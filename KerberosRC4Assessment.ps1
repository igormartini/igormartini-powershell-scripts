<#
.SYNOPSIS
    Consolidated Kerberos RC4 assessment for Active Directory.

.DESCRIPTION
    Correlates the same Kerberos telemetry used by Microsoft's official:
      - Get-KerbEncryptionUsage.ps1
      - List-AccountKeys.ps1

    IMPORTANT CORRELATION RULES:
      1) Event 4769 represents a TGS request.
         - Source/requestor = Properties[0]
         - Target service account = Properties[2]
         - Ticket encryption = Properties[5]
         - Session key encryption = Properties[20]
         - Available account keys = Properties[16]
         Microsoft's List-AccountKeys.ps1 assigns Properties[16] to the TARGET
         service account, not to the requestor.

      2) Event 4768 represents an AS request.
         - Source account = Properties[0]
         - Target = Properties[3] (normally krbtgt)
         - Ticket encryption = Properties[7]
         - Session key encryption = Properties[22]
         - Available account keys = Properties[16]
         Microsoft's List-AccountKeys.ps1 assigns Properties[16] to the SOURCE
         account for 4768.

      3) RC4 in a 4769 service ticket is attributed to the TARGET service account.
         The requestor is retained as evidence/context but is NOT automatically
         classified as an RC4-dependent account.

      4) v1.7 additionally reads ClientAdvertizedEncryptionTypes from the event XML.
         For 4769, Advertized Etypes are stored as REQUESTER/CLIENT context on the
         TARGET service account row. v1.7 also preserves requester-to-advertised-
         etype correlation so a legacy client can be identified directly.
         Advertised Etypes do not independently prove RC4 usage and do not change
         the account severity model.

      5) KDCSVC System events 201-209 are collected as supplementary Microsoft
         enforcement-readiness evidence. They are reported separately and do not
         override Security 4768/4769 account attribution or severity.

    The script is read-only. It does not change AD, SPNs, GPOs, passwords, registry,
    or Kerberos policy.

.NOTES
	Author  : Igor Henrique Martini
    Website : https://igormartini.cloud
    Microsoft reference repository: https://github.com/microsoft/Kerberos-Crypto
#>

[CmdletBinding()]
param()

# ============================================================
# USER CONFIGURATION
# ============================================================
$SearchScope = 'AllKdcs'   # This | AllKdcs
$Days        = 30
$OutputPath  = Join-Path $PSScriptRoot 'KerberosRC4-Assessment'
# ============================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step([string]$Message) {
    Write-Host "[+] $Message" -ForegroundColor Cyan
}

function Convert-HtmlSafe {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Normalize-PrincipalName {
    param([AllowNull()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    $n = $Name.Trim()
    if ($n -match '@') { $n = $n.Split('@')[0] }
    if ($n -match '\\') { $n = $n.Split('\')[-1] }
    $n.Trim()
}

function Convert-EType {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }
    $s = ([string]$Value).Trim()
    if (-not $s) { return '' }

    # Event XML normally returns hex strings, Properties[] can return integers.
    $numeric = $null
    if ($s -match '^0x[0-9a-fA-F]+$') {
        try { $numeric = [Convert]::ToInt32($s.Substring(2),16) } catch {}
    } elseif ($s -match '^\d+$') {
        try { $numeric = [int]$s } catch {}
    }

    if ($null -ne $numeric) {
        switch ($numeric) {
            0x1  { return 'DES-CRC' }
            0x3  { return 'DES-MD5' }
            0x11 { return 'AES128-SHA96' }
            0x12 { return 'AES256-SHA96' }
            0x13 { return 'AES128-SHA256' }
            0x14 { return 'AES256-SHA384' }
            0x17 { return 'RC4' }
            0x18 { return 'RC4-EXP' }
            default { return ('0x{0:X}' -f $numeric) }
        }
    }

    switch -Regex ($s) {
        '^AES128-SHA96$' { 'AES128-SHA96'; break }
        '^AES256-SHA96$' { 'AES256-SHA96'; break }
        '^AES128-SHA256$' { 'AES128-SHA256'; break }
        '^AES256-SHA384$' { 'AES256-SHA384'; break }
        '^AES-SHA1$' { 'AES-SHA1'; break }
        '^RC4$|^RC4-HMAC$' { 'RC4'; break }
        '^RC4-HMAC-EXP$' { 'RC4-EXP'; break }
        default { $s }
    }
}

function Test-IsRC4([AllowNull()][object]$Value) {
    (Convert-EType $Value) -in @('RC4','RC4-EXP')
}

function Test-IsAES([AllowNull()][object]$Value) {
    (Convert-EType $Value) -in @('AES128-SHA96','AES256-SHA96','AES128-SHA256','AES256-SHA384','AES-SHA1')
}

function Split-AvailableKeys {
    param([AllowNull()][object]$Raw)

    if ($null -eq $Raw -or [string]::IsNullOrWhiteSpace([string]$Raw)) { return @() }

    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($token in (([string]$Raw) -split '[,;]')) {
        $t = $token.Trim()
        if (-not $t -or $t -eq 'N/A') { continue }

        # Same compatibility handling used by Microsoft's List-AccountKeys.ps1:
        # Windows Server 2022 and earlier can aggregate AES keys as AES-SHA1.
        if ($t -eq 'AES-SHA1') {
            $out.Add('AES128-SHA96')
            $out.Add('AES256-SHA96')
        } else {
            $v = Convert-EType $t
            if ($v -and $v -ne 'N/A') { $out.Add($v) }
        }
    }
    @($out | Sort-Object -Unique)
}

function Convert-SupportedEncryptionTypes {
    param([AllowNull()][object]$Raw)

    if ($null -eq $Raw -or "$Raw" -eq '') {
        return [pscustomobject]@{
            Raw=$null; Hex=''; RC4=$false; AES128=$false; AES256=$false
            Summary='Not explicitly configured'
        }
    }

    try { $n = [int64]$Raw } catch { $n = 0 }
    $types = [System.Collections.Generic.List[string]]::new()
    if (($n -band 0x1)  -ne 0) { $types.Add('DES-CBC-CRC') }
    if (($n -band 0x2)  -ne 0) { $types.Add('DES-CBC-MD5') }
    if (($n -band 0x4)  -ne 0) { $types.Add('RC4') }
    if (($n -band 0x8)  -ne 0) { $types.Add('AES128') }
    if (($n -band 0x10) -ne 0) { $types.Add('AES256') }

    [pscustomobject]@{
        Raw=$n
        Hex=('0x{0:X}' -f $n)
        RC4=(($n -band 0x4) -ne 0)
        AES128=(($n -band 0x8) -ne 0)
        AES256=(($n -band 0x10) -ne 0)
        Summary=if($types.Count){$types -join '; '}else{"Configured ($n), no common crypto bits decoded"}
    }
}


function Get-EventDataMap {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)

    $map = @{}
    try {
        [xml]$xml = $Event.ToXml()
        foreach ($d in @($xml.Event.EventData.Data)) {
            $name = [string]$d.Name
            if (-not [string]::IsNullOrWhiteSpace($name)) {
                $map[$name] = [string]$d.InnerText
            }
        }
    } catch {}
    $map
}

function Get-EventDataValue {
    param(
        [hashtable]$Map,
        [string[]]$Names
    )
    foreach ($name in $Names) {
        if ($Map.ContainsKey($name)) {
            $value = [string]$Map[$name]
            if (-not [string]::IsNullOrWhiteSpace($value) -and $value -ne '-') {
                return $value
            }
        }
    }
    return $null
}

function Split-AdvertizedEtypes {
    param([AllowNull()][object]$Raw)

    if ($null -eq $Raw -or [string]::IsNullOrWhiteSpace([string]$Raw)) { return @() }

    # Modern 4768/4769 XML normally stores ClientAdvertizedEncryptionTypes as
    # whitespace-separated names. Accept commas/semicolons/newlines as well.
    $tokens = ([string]$Raw) -split '[,\s;]+'
    $out = [System.Collections.Generic.List[string]]::new()

    foreach ($token in $tokens) {
        $t = $token.Trim()
        if (-not $t -or $t -eq '-' -or $t -eq 'N/A') { continue }

        switch -Regex ($t) {
            '^AES256-CTS-HMAC-SHA1-96$' { $out.Add('AES256-SHA96'); continue }
            '^AES128-CTS-HMAC-SHA1-96$' { $out.Add('AES128-SHA96'); continue }
            '^AES256-CTS-HMAC-SHA384-192$' { $out.Add('AES256-SHA384'); continue }
            '^AES128-CTS-HMAC-SHA256-128$' { $out.Add('AES128-SHA256'); continue }
            '^RC4-HMAC-NT$|^RC4-HMAC$' { $out.Add('RC4'); continue }
            '^RC4-HMAC-NT-EXP$|^RC4-HMAC-OLD-EXP$' { $out.Add('RC4-EXP'); continue }
            '^RC4-HMAC-OLD$|^RC4-MD4$' { $out.Add($t); continue }
            default {
                $v = Convert-EType $t
                if ($v) { $out.Add($v) }
            }
        }
    }

    @($out | Sort-Object -Unique)
}

function Add-AdvertizedEtypesEvidence {
    param($State,[AllowNull()][object]$Raw)

    if ($null -eq $State) { return }

    $types = @(Split-AdvertizedEtypes $Raw)
    if ($types.Count -eq 0) {
        $State.AdvertizedEtypesUnknownEvents++
        return
    }

    $State.AdvertizedEtypesEvents++
    $eventHasAES = $false

    foreach ($type in $types) {
        [void]$State.AdvertizedEtypes.Add($type)
        if (Test-IsAES $type) { $eventHasAES = $true }
    }

    if ($eventHasAES) {
        $State.ClientAESAdvertisedEvents++
    } else {
        $State.ClientNoAESAdvertisedEvents++
    }
}

function Get-ClientAESSupport {
    param($State)

    if ($null -eq $State -or $State.AdvertizedEtypesEvents -eq 0) { return 'Unknown' }

    if ($State.ClientAESAdvertisedEvents -gt 0 -and $State.ClientNoAESAdvertisedEvents -gt 0) {
        return 'Mixed'
    }

    if ($State.ClientAESAdvertisedEvents -gt 0) { return 'Yes' }
    return 'No'
}

function Add-RequesterAdvertizedEvidence {
    param($State,[AllowNull()][string]$Requester,[AllowNull()][object]$Raw)

    if ($null -eq $State) { return }
    $requesterName = Normalize-PrincipalName $Requester
    if ([string]::IsNullOrWhiteSpace($requesterName)) { $requesterName = '<unknown requester>' }

    $types = @(Split-AdvertizedEtypes $Raw)
    if ($types.Count -eq 0) { return }

    $key = $requesterName.ToLowerInvariant()
    if (-not $State.RequesterAdvertizedMap.ContainsKey($key)) {
        $State.RequesterAdvertizedMap[$key] = [pscustomobject]@{
            Name=$requesterName
            Types=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }
    }
    foreach ($type in $types) {
        [void]$State.RequesterAdvertizedMap[$key].Types.Add($type)
    }
}

function Format-RequesterAdvertizedEvidence {
    param($State)
    if ($null -eq $State -or $State.RequesterAdvertizedMap.Count -eq 0) { return '' }

    @(
        $State.RequesterAdvertizedMap.Values |
        Sort-Object Name |
        ForEach-Object {
            $types = @($_.Types | Sort-Object) -join ', '
            "$($_.Name): $types"
        }
    ) -join ' | '
}

function New-PrincipalState {
    param([string]$Name)
    [ordered]@{
        Name=$Name
        FirstSeen=$null
        LastSeen=$null
        EventCount=0

        # Account-key evidence (Microsoft List-AccountKeys semantics)
        AvailableKeys=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        KeyEvidenceEvents=0

        # Actual usage attributed to this account as TARGET service / AS account.
        TicketTypes=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        SessionKeyTypes=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        RC4TgsTargetCount=0
        RC4AsCount=0
        AESTicketCount=0
        AESSessionCount=0

        # Context only: requests made BY this principal. Does not drive service-account remediation.
        RequestedTicketTypes=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        RequestedSessionTypes=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        RC4RequestsMade=0

        # Client/requester capability observed in modern 4768/4769 event XML.
        AdvertizedEtypes=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        AdvertizedEtypesEvents=0
        AdvertizedEtypesUnknownEvents=0
        ClientAESAdvertisedEvents=0
        ClientNoAESAdvertisedEvents=0
        RequesterAdvertizedMap=@{}

        RequesterAddresses=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        RequestingPrincipals=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        TargetPrincipals=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        DomainControllers=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        EvidenceRecordIds=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }
}

function Get-OrCreateState {
    param([hashtable]$States,[string]$Name)
    $n = Normalize-PrincipalName $Name
    if (-not $n -or $n -eq '-') { return $null }
    $key = $n.ToLowerInvariant()
    if (-not $States.ContainsKey($key)) {
        $States[$key] = New-PrincipalState $n
    }
    $States[$key]
}

function Touch-State {
    param($State,[datetime]$Time,[string]$DC,[long]$RecordId)
    if ($null -eq $State) { return }
    $State.EventCount++
    if ($null -eq $State.FirstSeen -or $Time -lt $State.FirstSeen) { $State.FirstSeen=$Time }
    if ($null -eq $State.LastSeen -or $Time -gt $State.LastSeen) { $State.LastSeen=$Time }
    if ($DC) { [void]$State.DomainControllers.Add($DC) }
    [void]$State.EvidenceRecordIds.Add([string]$RecordId)
}

function Add-KeyEvidence {
    param($State,[object]$RawKeys)
    if ($null -eq $State) { return }
    $keys = Split-AvailableKeys $RawKeys
    if ($keys.Count -gt 0) {
        $State.KeyEvidenceEvents++
        foreach ($k in $keys) { [void]$State.AvailableKeys.Add($k) }
    }
}

function Add-TargetUsage {
    param($State,[object]$Ticket,[object]$Session,[ValidateSet('AS','TGS')][string]$Type)
    if ($null -eq $State) { return }

    $t = Convert-EType $Ticket
    $sk = Convert-EType $Session

    if ($t) {
        [void]$State.TicketTypes.Add($t)
        if (Test-IsRC4 $t) {
            if ($Type -eq 'TGS') { $State.RC4TgsTargetCount++ } else { $State.RC4AsCount++ }
        }
        if (Test-IsAES $t) { $State.AESTicketCount++ }
    }

    if ($sk) {
        [void]$State.SessionKeyTypes.Add($sk)
        if (Test-IsAES $sk) { $State.AESSessionCount++ }
    }
}

function Add-RequesterContext {
    param($State,[object]$Ticket,[object]$Session,[string]$Target,[string]$Ip)
    if ($null -eq $State) { return }
    $t = Convert-EType $Ticket
    $sk = Convert-EType $Session
    if ($t) { [void]$State.RequestedTicketTypes.Add($t) }
    if ($sk) { [void]$State.RequestedSessionTypes.Add($sk) }
    if ((Test-IsRC4 $t) -or (Test-IsRC4 $sk)) { $State.RC4RequestsMade++ }
    if ($Target) { [void]$State.TargetPrincipals.Add((Normalize-PrincipalName $Target)) }
    if ($Ip) { [void]$State.RequesterAddresses.Add($Ip) }
}

function Get-ADPrincipal {
    param([string]$Name)

    $escaped = $Name.Replace('\','\5c').Replace('*','\2a').Replace('(','\28').Replace(')','\29')
    try {
        Get-ADObject -LDAPFilter "(sAMAccountName=$escaped)" -Properties `
            sAMAccountName,userPrincipalName,objectClass,distinguishedName,msDS-SupportedEncryptionTypes,`
            servicePrincipalName,pwdLastSet,userAccountControl -ErrorAction Stop |
            Select-Object -First 1
    } catch { $null }
}

function Get-Classification {
    param(
        [bool]$RC4TgsObserved,
        [bool]$RC4AsObserved,
        [bool]$HasAESKeyEvidence,
        [bool]$HasRC4KeyEvidence,
        [bool]$ExplicitRC4,
        [bool]$ExplicitAES,
        [bool]$HasSPN,
        [string]$ObjectClass,
        [bool]$HasKeyTelemetry
    )

    # FINAL MODEL:
    # Actual RC4 usage has priority. For modern 4768/4769 telemetry, Available Keys
    # is used to distinguish "RC4 used but AES keys exist" from "RC4 used and AES
    # keys are not demonstrated". The AD msDS-SET attribute remains important
    # configuration evidence, but it does not override observed Available Keys.
    #
    # Microsoft notes that event-log msDS-SET/Available Keys are processed values
    # and that RC4 can be displayed regardless of actual RC4 usage.

    if ($RC4TgsObserved) {
        if ($HasKeyTelemetry -and $HasAESKeyEvidence) {
            return [pscustomobject]@{
                Severity='High'; NeedsAction=$true
                Finding='RC4 service ticket observed for the target account, while AES key capability is also present.'
                Recommendation='RC4 is actively being used even though AES keys are available. Investigate the target service account, SPN, client Advertized Etypes, Kerberos policy, and application compatibility. Validate AES end-to-end and confirm subsequent 4769 service tickets use AES before removing RC4.'
            }
        }

        if ($HasKeyTelemetry -and -not $HasAESKeyEvidence) {
            return [pscustomobject]@{
                Severity='Critical'; NeedsAction=$true
                Finding='RC4 service ticket observed and modern event telemetry does not demonstrate AES keys for the target account.'
                Recommendation='Treat this as an active RC4-only or missing-AES-key dependency. Validate application support, generate AES keys where appropriate (often by rotating/resetting the service-account password), configure AES support, test the service, and confirm subsequent 4769 tickets use AES.'
            }
        }

        return [pscustomobject]@{
            Severity='High'; NeedsAction=$true
            Finding='RC4 service ticket observed, but modern Available Keys telemetry is not available to determine whether AES keys exist.'
            Recommendation='Investigate the active RC4 dependency. Review the target account, SPN, client Advertized Etypes and Kerberos configuration. Obtain modern 4769 telemetry where possible to determine AES key availability before remediation.'
        }
    }

    if ($RC4AsObserved) {
        if ($HasKeyTelemetry -and -not $HasAESKeyEvidence) {
            return [pscustomobject]@{
                Severity='Critical'; NeedsAction=$true
                Finding='RC4 was observed during AS authentication and modern event telemetry does not demonstrate AES keys for this account.'
                Recommendation='Review the account and client Kerberos configuration. Generate AES keys where appropriate, update legacy dependencies, and confirm subsequent AS authentication uses AES.'
            }
        }

        return [pscustomobject]@{
            Severity='High'; NeedsAction=$true
            Finding='RC4 was observed during AS authentication for this account.'
            Recommendation='Review the account and client Kerberos configuration, verify AES support and client Advertized Etypes, update legacy dependencies, and confirm subsequent AS authentication uses AES.'
        }
    }

    if ($ObjectClass -ne 'computer' -and $HasSPN -and $ExplicitRC4) {
        return [pscustomobject]@{
            Severity='Medium'; NeedsAction=$true
            Finding='RC4 is explicitly allowed on a non-computer account that owns SPNs, but no RC4 service-ticket usage was observed.'
            Recommendation='Review whether RC4 is still required for this service account. Since no RC4 use was observed, validate AES operation first and remove explicit RC4 only after compatibility testing.'
        }
    }

    if ($ObjectClass -eq 'computer' -and $ExplicitRC4 -and $ExplicitAES) {
        return [pscustomobject]@{
            Severity='Informational'; NeedsAction=$false
            Finding='RC4 is present in the computer account configuration, but AES is enabled and no RC4 service-ticket usage was observed.'
            Recommendation='No immediate remediation is required based on observed usage. Continue monitoring; treat this as RC4 capability/configuration rather than an active dependency.'
        }
    }

    if ($ExplicitAES -and -not $ExplicitRC4) {
        return [pscustomobject]@{
            Severity='Healthy'; NeedsAction=$false
            Finding='The account is explicitly configured for AES and no RC4 usage was observed.'
            Recommendation='No remediation identified. Continue periodic Kerberos monitoring.'
        }
    }

    if ($HasAESKeyEvidence -and -not $RC4TgsObserved -and -not $RC4AsObserved) {
        return [pscustomobject]@{
            Severity='Informational'; NeedsAction=$false
            Finding='AES key capability was observed and no RC4 usage was attributed to this account.'
            Recommendation='No immediate remediation identified from the observed Kerberos activity. Continue monitoring.'
        }
    }

    return [pscustomobject]@{
        Severity='Review'; NeedsAction=$true
        Finding='The available telemetry is insufficient to classify this account confidently.'
        Recommendation='Review recent 4768/4769 evidence, Advertized Etypes, and the account encryption configuration manually.'
    }
}

Write-Step "Checking prerequisites"
Import-Module ActiveDirectory -ErrorAction Stop

$domain = Get-ADDomain
$forest = Get-ADForest
$since = (Get-Date).AddDays(-$Days)

if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$htmlPath = Join-Path $OutputPath "Kerberos_RC4_Assessment_$stamp.html"
$csvPath = Join-Path $OutputPath "Kerberos_RC4_Assessment_$stamp.csv"
$kdcCsvPath = Join-Path $OutputPath "Kerberos_RC4_KDCSVC_201-209_$stamp.csv"
$generatedAt = Get-Date
try { $runAs = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $runAs = "$env:USERDOMAIN\$env:USERNAME" }

if ($SearchScope -eq 'AllKdcs') {
    $dcs = @(Get-ADDomainController -Filter * | ForEach-Object {
        [pscustomobject]@{ HostName = [string](@($_.HostName)[0]) }
    })
} else {
    $dcs = @([pscustomobject]@{ HostName = "$env:COMPUTERNAME.$env:USERDNSDOMAIN" })
}

Write-Step "Domain: $($domain.DNSRoot)"
Write-Step "Collection window: $since to $(Get-Date)"
Write-Step "Domain controllers to query: $($dcs.Count)"

$states = @{}
$errors = [System.Collections.Generic.List[object]]::new()
$totalEvents = 0
$modernEvents = 0
$legacyEvents = 0
$kdcEvents = [System.Collections.Generic.List[object]]::new()

foreach ($dc in $dcs) {
    $dcName = [string]$dc.HostName
    Write-Step "Reading 4768/4769 from $dcName"

    try {
        $events = Get-WinEvent -ComputerName $dcName -FilterHashtable @{
            LogName='Security'; Id=4768,4769; StartTime=$since
        } -ErrorAction Stop
    } catch {
        $errors.Add([pscustomobject]@{DomainController=$dcName;Error=$_.Exception.Message})
        Write-Warning "Could not read $dcName : $($_.Exception.Message)"
        continue
    }

    foreach ($e in $events) {
        $totalEvents++
        $p = @($e.Properties)
        $eventData = Get-EventDataMap $e
        $advertizedEtypes = Get-EventDataValue $eventData @(
            'ClientAdvertizedEncryptionTypes',
            'ClientAdvertisedEncryptionTypes'
        )

        # Microsoft's scripts require the modern event metadata. We still process
        # usage from older events when enough fields exist, but account-key evidence
        # is only accepted when Properties[16] is present.
        if ($p.Count -ge 21) { $modernEvents++ } else { $legacyEvents++ }

        if ($e.Id -eq 4769) {
            if ($p.Count -lt 7) { continue }

            # EXACT official Get-KerbEncryptionUsage.ps1 positions.
            $source = [string]$p[0].Value
            $target = [string]$p[2].Value
            $ticket = $p[5].Value
            $ip = [string]$p[6].Value
            $session = if ($p.Count -gt 20) { $p[20].Value } else { $null }

            # EXACT official List-AccountKeys.ps1 key position.
            $keys = if ($p.Count -gt 16) { $p[16].Value } else { $null }

            # Target/service account: this is where TGS encryption and account keys belong.
            $targetState = Get-OrCreateState $states $target
            Touch-State $targetState $e.TimeCreated $dcName $e.RecordId
            Add-KeyEvidence $targetState $keys
            Add-TargetUsage $targetState $ticket $session 'TGS'
            Add-AdvertizedEtypesEvidence $targetState $advertizedEtypes
            Add-RequesterAdvertizedEvidence $targetState $source $advertizedEtypes
            if ($source) { [void]$targetState.RequestingPrincipals.Add((Normalize-PrincipalName $source)) }
            if ($ip) { [void]$targetState.RequesterAddresses.Add($ip) }

            # Source/requestor: context only for 4769. Do NOT attribute the TGS encryption
            # to the requestor as an account remediation finding.
            $sourceState = Get-OrCreateState $states $source
            Touch-State $sourceState $e.TimeCreated $dcName $e.RecordId
            Add-RequesterContext $sourceState $ticket $session $target $ip
        }
        elseif ($e.Id -eq 4768) {
            if ($p.Count -lt 10) { continue }

            # EXACT official Get-KerbEncryptionUsage.ps1 positions.
            $source = [string]$p[0].Value
            $target = [string]$p[3].Value
            $ticket = $p[7].Value
            $ip = [string]$p[9].Value
            $session = if ($p.Count -gt 22) { $p[22].Value } else { $null }

            # EXACT official List-AccountKeys.ps1 key position.
            # For 4768 Microsoft attributes Properties[16] to Properties[0] (source account).
            $keys = if ($p.Count -gt 16) { $p[16].Value } else { $null }

            $sourceState = Get-OrCreateState $states $source
            Touch-State $sourceState $e.TimeCreated $dcName $e.RecordId
            Add-KeyEvidence $sourceState $keys
            Add-TargetUsage $sourceState $ticket $session 'AS'
            Add-AdvertizedEtypesEvidence $sourceState $advertizedEtypes
            Add-RequesterContext $sourceState $ticket $session $target $ip
        }
    }
}

# Microsoft CVE-2026-20833 guidance recommends monitoring KDCSVC 201-209.
# These System-log events are supplementary enforcement-readiness evidence only.
foreach ($dc in $dcs) {
    $dcName = [string]$dc.HostName
    Write-Step "Reading KDCSVC 201-209 from $dcName"
    try {
        $systemEvents = @(Get-WinEvent -ComputerName $dcName -FilterHashtable @{
            LogName='System'; Id=201,202,203,204,205,206,207,208,209; StartTime=$since
        } -ErrorAction Stop)

        foreach ($ke in $systemEvents) {
            $provider = [string]$ke.ProviderName
            if ($provider -and $provider -notmatch '(?i)kdc') { continue }

            $msg = ''
            try { $msg = [string]$ke.Message } catch {}
            $msg = ($msg -replace '\r?\n',' ' -replace '\s+',' ').Trim()

            $kdcEvents.Add([pscustomobject]@{
                DomainController=$dcName
                EventId=$ke.Id
                Level=$ke.LevelDisplayName
                TimeCreated=$ke.TimeCreated
                RecordId=$ke.RecordId
                Provider=$provider
                Message=$msg
            })
        }
    } catch {
        # "No events were found" is a healthy/valid collection outcome, not a collection failure.
        if ($_.Exception.Message -notmatch '(?i)no events were found|nenhum evento') {
            $errors.Add([pscustomobject]@{DomainController=$dcName;Error=("KDCSVC collection: " + $_.Exception.Message)})
            Write-Warning "Could not read KDCSVC events from $dcName : $($_.Exception.Message)"
        }
    }
}

Write-Step "Collected $totalEvents Security events ($modernEvents modern-schema, $legacyEvents legacy-schema)"
Write-Step "Collected $($kdcEvents.Count) KDCSVC 201-209 events"
Write-Step "Observed $($states.Count) unique principals"
Write-Step "v1.7 enrichment: Advertized Etypes / Client AES Support collected from modern event XML when available"

$results = [System.Collections.Generic.List[object]]::new()

foreach ($entry in $states.GetEnumerator()) {
    $s = $entry.Value
    $ad = Get-ADPrincipal $s.Name

    # Keep only resolvable AD principals in the account-remediation table.
    # Unresolved requestor strings are not actionable account objects.
    if (-not $ad) { continue }

    $enc = Convert-SupportedEncryptionTypes $ad.'msDS-SupportedEncryptionTypes'
    $keys = @($s.AvailableKeys | Sort-Object)
    $hasAESKey = @($keys | Where-Object { Test-IsAES $_ }).Count -gt 0
    $hasRC4Key = @($keys | Where-Object { Test-IsRC4 $_ }).Count -gt 0
    $explicitAES = $enc.AES128 -or $enc.AES256

    $spns = @($ad.servicePrincipalName)
    $hasSPN = $spns.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace(($spns -join ''))

    $class = Get-Classification `
        -RC4TgsObserved ($s.RC4TgsTargetCount -gt 0) `
        -RC4AsObserved ($s.RC4AsCount -gt 0) `
        -HasAESKeyEvidence $hasAESKey `
        -HasRC4KeyEvidence $hasRC4Key `
        -ExplicitRC4 $enc.RC4 `
        -ExplicitAES $explicitAES `
        -HasSPN $hasSPN `
        -ObjectClass ([string]$ad.objectClass) `
        -HasKeyTelemetry ($s.KeyEvidenceEvents -gt 0)

    $pwdLastSet = $null
    if ($ad.pwdLastSet -and [int64]$ad.pwdLastSet -gt 0) {
        try { $pwdLastSet=[datetime]::FromFileTimeUtc([int64]$ad.pwdLastSet).ToLocalTime() } catch {}
    }

    $results.Add([pscustomobject]@{
        Severity=$class.Severity
        NeedsAction=$class.NeedsAction
        Account=$s.Name
        ObjectClass=[string]$ad.objectClass
        UPN=[string]$ad.userPrincipalName
        HasSPN=$hasSPN
        SPNs=$spns -join '; '
        PasswordLastSet=$pwdLastSet
        msDSSupportedEncryptionTypesHex=$enc.Hex
        msDSSupportedEncryptionTypes=$enc.Summary
        ExplicitRC4=$enc.RC4
        ExplicitAES=$explicitAES

        # Official List-AccountKeys perspective
        AvailableKeys=$keys -join '; '
        HasAESKey=$hasAESKey
        HasRC4Key=$hasRC4Key
        KeyEvidenceEvents=$s.KeyEvidenceEvents

        # Client/requester capability from modern event XML.
        # For a 4769 target row, these are the etypes advertised by clients that
        # requested tickets for this service during the collection window.
        AdvertizedEtypes=@($s.AdvertizedEtypes | Sort-Object) -join '; '
        ClientAESSupport=$(Get-ClientAESSupport $s)
        AdvertizedEtypesEvents=$s.AdvertizedEtypesEvents
        RequesterAdvertizedEtypes=$(Format-RequesterAdvertizedEvidence $s)
        ClientAESAdvertisedEvents=$s.ClientAESAdvertisedEvents
        ClientNoAESAdvertisedEvents=$s.ClientNoAESAdvertisedEvents

        # Official Get-KerbEncryptionUsage perspective attributed to THIS account
        TicketEncryptionObserved=@($s.TicketTypes | Sort-Object) -join '; '
        SessionKeyEncryptionObserved=@($s.SessionKeyTypes | Sort-Object) -join '; '
        RC4TgsTargetCount=$s.RC4TgsTargetCount
        RC4AsCount=$s.RC4AsCount

        # Context: what this account requested from other targets; not classification input for TGS dependency
        RequestedTicketEncryption=@($s.RequestedTicketTypes | Sort-Object) -join '; '
        RequestedSessionEncryption=@($s.RequestedSessionTypes | Sort-Object) -join '; '
        RC4RequestsMade=$s.RC4RequestsMade
        RequestedTargets=@($s.TargetPrincipals | Sort-Object) -join '; '

        RequestingPrincipals=@($s.RequestingPrincipals | Sort-Object) -join '; '
        RequesterAddresses=@($s.RequesterAddresses | Sort-Object) -join '; '
        DomainControllers=@($s.DomainControllers | Sort-Object) -join '; '
        EvidenceRecordIds=@($s.EvidenceRecordIds | Sort-Object) -join '; '
        FirstSeen=$s.FirstSeen
        LastSeen=$s.LastSeen
        Finding=$class.Finding
        Recommendation=$class.Recommendation
        DistinguishedName=[string]$ad.distinguishedName
    })
}

$rank=@{Critical=1;High=2;Medium=3;Review=4;Informational=5;Healthy=6}
$results=@($results | Sort-Object @{Expression={$rank[$_.Severity]}},Account)
$action=@($results | Where-Object NeedsAction)

$results | Export-Csv $csvPath -NoTypeInformation -Encoding UTF8
if ($kdcEvents.Count -gt 0) {
    $kdcEvents | Export-Csv $kdcCsvPath -NoTypeInformation -Encoding UTF8
} else {
    '"DomainController","EventId","Level","TimeCreated","RecordId","Provider","Message"' |
        Set-Content -Path $kdcCsvPath -Encoding UTF8
}

$critical=@($results|Where-Object Severity -eq Critical).Count
$high=@($results|Where-Object Severity -eq High).Count
$medium=@($results|Where-Object Severity -eq Medium).Count
$review=@($results|Where-Object Severity -eq Review).Count
$healthy=@($results|Where-Object Severity -eq Healthy).Count
$info=@($results|Where-Object Severity -eq Informational).Count
$actualRC4=@($results|Where-Object {$_.RC4TgsTargetCount -gt 0 -or $_.RC4AsCount -gt 0}).Count

$rows = foreach($r in $results) {
    $sev="sev-"+$r.Severity.ToLowerInvariant()
    $rc4=[bool]($r.RC4TgsTargetCount -gt 0 -or $r.RC4AsCount -gt 0)
    $spnDisplay = if($r.HasSPN){ Convert-HtmlSafe $r.SPNs }else{'—'}
    $requesterEtypes = if($r.RequesterAdvertizedEtypes){ Convert-HtmlSafe $r.RequesterAdvertizedEtypes }else{'—'}

    "<tr data-severity='$($r.Severity)' data-action='$($r.NeedsAction)' data-rc4='$rc4'>"+
    "<td><span class='badge $sev'>$(Convert-HtmlSafe $r.Severity)</span></td>"+
    "<td>$(if($r.NeedsAction){'<span class=''action yes''>YES</span>'}else{'<span class=''action no''>NO</span>'})</td>"+
    "<td><b>$(Convert-HtmlSafe $r.Account)</b><div class='sub'>$(Convert-HtmlSafe $r.UPN)</div></td>"+
    "<td>$(Convert-HtmlSafe $r.ObjectClass)</td>"+
    "<td class='spn'>$spnDisplay</td>"+
    "<td>$(Convert-HtmlSafe $r.msDSSupportedEncryptionTypesHex)<div class='sub'>$(Convert-HtmlSafe $r.msDSSupportedEncryptionTypes)</div></td>"+
    "<td>$(Convert-HtmlSafe $r.AvailableKeys)</td>"+
    "<td>$(Convert-HtmlSafe $r.AdvertizedEtypes)</td>"+
    "<td>$(Convert-HtmlSafe $r.ClientAESSupport)</td>"+
    "<td class='requester-map'>$requesterEtypes</td>"+
    "<td>$(Convert-HtmlSafe $r.TicketEncryptionObserved)</td>"+
    "<td>$(Convert-HtmlSafe $r.SessionKeyEncryptionObserved)</td>"+
    "<td class='num'>$($r.RC4TgsTargetCount)</td>"+
    "<td>$(Convert-HtmlSafe $r.RequestingPrincipals)</td>"+
    "<td>$(Convert-HtmlSafe $r.LastSeen)</td>"+
    "<td class='finding'>$(Convert-HtmlSafe $r.Finding)</td>"+
    "<td class='recommendation'>$(Convert-HtmlSafe $r.Recommendation)</td>"+
    "</tr>"
}

$errorRows = if($errors.Count){
    ($errors|ForEach-Object{"<tr><td>$(Convert-HtmlSafe $_.DomainController)</td><td>$(Convert-HtmlSafe $_.Error)</td></tr>"}) -join "`n"
}else{"<tr><td colspan='2'>No collection errors.</td></tr>"}

$kdcRows = if($kdcEvents.Count){
    ($kdcEvents | Sort-Object TimeCreated -Descending | ForEach-Object {
        $m = $_.Message
        if($m.Length -gt 900){ $m=$m.Substring(0,900)+'…' }
        "<tr><td><b>$($_.EventId)</b></td><td>$(Convert-HtmlSafe $_.Level)</td><td>$(Convert-HtmlSafe $_.DomainController)</td><td>$(Convert-HtmlSafe $_.TimeCreated)</td><td>$(Convert-HtmlSafe $m)</td></tr>"
    }) -join "`n"
}else{
    "<tr><td colspan='5'>No KDCSVC 201-209 events were observed in the selected collection window.</td></tr>"
}

$html=@"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kerberos RC4 Assessment</title>
<style>
:root{
 --bg:#f3f6fa;--panel:#fff;--border:#d9e1ea;--text:#172033;--muted:#68758a;
 --blue:#0f4c78;--blue2:#1e73b7;--critical:#d92d20;--high:#e55b13;--medium:#e7a008;
 --info:#2878c8;--healthy:#169b62;--review:#6554c0
}
*{box-sizing:border-box}
body{margin:0;font-family:"Segoe UI",Arial,sans-serif;background:var(--bg);color:var(--text);font-size:13px}
.wrap{width:100%;max-width:none;margin:0;padding:24px}
.hero{background:linear-gradient(110deg,#103b60,#2378b8);color:#fff;border-radius:18px;padding:26px 30px;display:flex;justify-content:space-between;gap:30px;box-shadow:0 1px 2px rgba(16,24,40,.08)}
.hero h1{margin:0 0 8px;font-size:28px;font-weight:700}.hero p{margin:3px 0;color:#e7f1fa;max-width:980px;line-height:1.45}
.meta{text-align:right;min-width:250px;font-size:12px;line-height:1.5;color:#e7f1fa}.meta b{color:#fff}
.cards{display:grid;grid-template-columns:repeat(7,minmax(145px,1fr));gap:14px;margin:18px 0}
.card{background:#fff;border:1px solid var(--border);border-radius:14px;padding:16px 18px;border-left:5px solid #3b82f6;box-shadow:0 1px 2px rgba(16,24,40,.04)}
.card .l{color:var(--muted);font-size:12px}.card .n{font-size:28px;font-weight:700;margin-top:6px}.c-action{border-left-color:#f59e0b}.c-rc4{border-left-color:#ef4444}.c-critical{border-left-color:var(--critical)}.c-high{border-left-color:var(--high)}.c-medium{border-left-color:var(--medium)}.c-good{border-left-color:var(--healthy)}
.note{background:#fff;border:1px solid var(--border);border-left:5px solid var(--blue2);padding:14px 16px;margin:0 0 16px;border-radius:10px;line-height:1.45}
.controls{background:#fff;border:1px solid var(--border);border-radius:14px;padding:13px 16px;display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin-bottom:16px}
input{min-width:360px;flex:1;border:1px solid #c9d3df;border-radius:8px;padding:9px 11px;background:#fff}
button{border:1px solid #c9d3df;background:#fff;border-radius:8px;padding:8px 12px;cursor:pointer;color:#344054}button:hover{background:#f4f7fa}
.tablewrap{width:100%;overflow-x:auto;overflow-y:visible;background:#fff;border:1px solid var(--border);border-radius:14px;box-shadow:0 1px 2px rgba(16,24,40,.04)}
table{border-collapse:collapse;width:100%;table-layout:auto;font-size:12px}th{position:sticky;top:0;z-index:2;background:#f7f9fc;text-align:left;padding:11px;border-bottom:1px solid var(--border);white-space:nowrap;color:#344054}
td{vertical-align:top;padding:10px 11px;border-bottom:1px solid #edf0f4;line-height:1.4}.sub{color:var(--muted);font-size:10.5px;margin-top:3px}.num{text-align:center;font-weight:700}
.spn{white-space:normal;overflow-wrap:anywhere;line-height:1.35;min-width:150px;max-width:280px}
.requester-map{white-space:normal;overflow-wrap:anywhere;line-height:1.35;min-width:170px;max-width:320px}
.finding{white-space:normal;overflow-wrap:anywhere;min-width:190px}
.recommendation{white-space:normal;overflow-wrap:anywhere;min-width:240px}
.badge{display:inline-block;padding:4px 9px;border-radius:999px;font-weight:700;font-size:11px;border:1px solid}
.sev-critical{background:#fee4e2;border-color:#f97066;color:#b42318}.sev-high{background:#fff0e6;border-color:#fb923c;color:#b54708}.sev-medium{background:#fff7d6;border-color:#f5c242;color:#7a4d00}.sev-review{background:#eeeafd;border-color:#a99cf5;color:#42307d}.sev-informational{background:#eaf3ff;border-color:#84b9f4;color:#175cd3}.sev-healthy{background:#e7f8ef;border-color:#6fd3a4;color:#067647}
.action{font-weight:700}.action.yes{color:#b54708}.action.no{color:#667085}
.section{margin-top:24px}.section h2{font-size:18px;margin:0 0 10px}.smalltable{min-width:0}.kdc-table{min-width:0}
footer{color:var(--muted);font-size:11px;margin-top:18px;line-height:1.5}
#main th{white-space:normal;overflow-wrap:normal;word-break:normal;hyphens:none}
#main td{white-space:normal;overflow-wrap:anywhere;word-break:normal}

/* Never split compact labels or single-word headers */
#main th:nth-child(1),
#main th:nth-child(2),
#main th:nth-child(4),
#main th:nth-child(9),
#main th:nth-child(13),
#main td:nth-child(1),
#main td:nth-child(2),
#main td:nth-child(4),
#main td:nth-child(9),
#main td:nth-child(13){
  white-space:nowrap;
  overflow-wrap:normal;
  word-break:normal;
}

/* Keep status badges intact */
.badge,
.action{
  white-space:nowrap !important;
  word-break:normal !important;
  overflow-wrap:normal !important;
}
#main th:nth-child(1),#main td:nth-child(1){width:78px;min-width:78px}
#main th:nth-child(2),#main td:nth-child(2){width:68px;min-width:68px}
#main th:nth-child(3),#main td:nth-child(3){min-width:125px}
#main th:nth-child(4),#main td:nth-child(4){width:72px;min-width:72px}
#main th:nth-child(5),#main td:nth-child(5){min-width:150px;max-width:280px}
#main th:nth-child(6),#main td:nth-child(6){min-width:115px}
#main th:nth-child(7),#main td:nth-child(7){min-width:110px}
#main th:nth-child(8),#main td:nth-child(8){min-width:120px}
#main th:nth-child(9),#main td:nth-child(9){width:96px;min-width:96px}
#main th:nth-child(10),#main td:nth-child(10){min-width:170px;max-width:320px}
#main th:nth-child(11),#main td:nth-child(11){min-width:110px}
#main th:nth-child(12),#main td:nth-child(12){min-width:110px}
#main th:nth-child(13),#main td:nth-child(13){width:64px;min-width:64px}
#main th:nth-child(14),#main td:nth-child(14){min-width:125px}
#main th:nth-child(15),#main td:nth-child(15){min-width:110px}
#main th:nth-child(16),#main td:nth-child(16){min-width:190px}
#main th:nth-child(17),#main td:nth-child(17){min-width:240px}
@media (min-width:2200px){.wrap{padding:24px 32px}table{font-size:12.5px}th,td{padding:10px 12px}.spn{max-width:360px}.requester-map{max-width:420px}}
@media (max-width:1920px){.wrap{padding:18px}table{font-size:11px}th,td{padding:7px 8px}.cards{gap:10px}.hero{padding:22px 24px}.hero h1{font-size:25px}.spn{min-width:135px;max-width:240px}.requester-map{min-width:150px;max-width:260px}.finding{min-width:170px}.recommendation{min-width:220px}}
@media (max-width:1400px){table{font-size:10px}th,td{padding:6px}.cards{grid-template-columns:repeat(4,minmax(135px,1fr))}.requester-map{max-width:220px}.spn{max-width:210px}.recommendation{min-width:200px}.finding{min-width:155px}}
@media (max-width:1100px){.cards{grid-template-columns:repeat(2,1fr)}.hero{flex-direction:column}.meta{text-align:left}.wrap{padding:14px}.tablewrap{overflow-x:auto}#main{min-width:1800px}}
</style>
</head>
<body>
<div class="wrap">
<div class="hero">
 <div>
  <h1>Kerberos RC4 Assessment</h1>
  <p>Consolidated Active Directory assessment of Kerberos encryption usage, available account keys, client-advertised encryption types, SPN ownership, and service-account configuration.</p>
  <p><b>Domain:</b> $(Convert-HtmlSafe $domain.DNSRoot) &nbsp; | &nbsp; <b>Forest:</b> $(Convert-HtmlSafe $forest.Name) &nbsp; | &nbsp; <b>Window:</b> $(Convert-HtmlSafe $since) to $(Convert-HtmlSafe $generatedAt)</p>
 </div>
 <div class="meta">
  <b>Generated</b><br>$(Convert-HtmlSafe $generatedAt)<br><br>
  <b>Run as</b><br>$(Convert-HtmlSafe $runAs)<br><br>
  <b>Scope</b><br>$(Convert-HtmlSafe $SearchScope)
 </div>
</div>

<div class="cards">
 <div class="card"><div class="l">Kerberos principals assessed</div><div class="n">$($results.Count)</div></div>
 <div class="card c-action"><div class="l">Needs action</div><div class="n">$($action.Count)</div></div>
 <div class="card c-rc4"><div class="l">Observed RC4 usage</div><div class="n">$actualRC4</div></div>
 <div class="card c-critical"><div class="l">Critical</div><div class="n">$critical</div></div>
 <div class="card c-high"><div class="l">High</div><div class="n">$high</div></div>
 <div class="card c-medium"><div class="l">Medium</div><div class="n">$medium</div></div>
 <div class="card c-good"><div class="l">Healthy / Informational</div><div class="n">$($healthy+$info)</div></div>
</div>

<div class="note">
<b>Assessment model:</b> Security Events <b>4768/4769</b> provide observed Kerberos usage. <b>Available Keys</b> follows Microsoft List-AccountKeys account attribution. <b>Ticket/Session encryption</b> follows Get-KerbEncryptionUsage semantics. Active Directory adds <b>msDS-SupportedEncryptionTypes</b> and the actual <b>Service Principal Names</b>. Client-advertised encryption types are preserved per requester for investigation. <b>KDCSVC 201-209</b> are collected separately as CVE-2026-20833 enforcement-readiness evidence and do not independently change account severity.
</div>

<div class="controls">
 <input id="q" type="search" placeholder="Search account, SPN, requester, encryption, finding or recommendation...">
 <button onclick="setFilter('ALL')">All</button>
 <button onclick="setFilter('ACTION')">Needs action</button>
 <button onclick="setFilter('RC4')">Observed RC4</button>
 <button onclick="setFilter('Critical')">Critical</button>
 <button onclick="setFilter('High')">High</button>
 <button onclick="setFilter('Medium')">Medium</button>
 <button onclick="setFilter('INFO')">Healthy / Informational</button>
</div>

<div class="tablewrap"><table id="main">
<thead><tr>
<th>Severity</th><th>Action</th><th>Account</th><th>Type</th><th>Service Principal Names</th>
<th>msDS-SupportedEncryptionTypes</th><th>Available Keys</th><th>Advertised Etypes</th><th>Client AES Support</th>
<th>Requester → Advertised Etypes</th><th>Observed Ticket Encryption</th><th>Observed Session Encryption</th>
<th>RC4 TGS</th><th>Requesting Principals</th><th>Last Seen</th><th>Finding</th><th>Recommendation</th>
</tr></thead><tbody>
$($rows -join "`n")
</tbody></table></div>

<div class="section">
<h2>Classification logic</h2>
<div class="tablewrap"><table class="smalltable">
<thead><tr><th>Observed / configured condition</th><th>Priority</th><th>Operational meaning</th></tr></thead>
<tbody>
<tr><td>RC4 TGS attributed to target + modern Available Keys telemetry does not demonstrate AES keys</td><td><span class='badge sev-critical'>Critical</span></td><td>Active RC4 dependency with missing/undemonstrated AES key capability; validate and restore AES capability before removing RC4.</td></tr>
<tr><td>RC4 TGS attributed to target + AES keys present</td><td><span class='badge sev-high'>High</span></td><td>RC4 is actively selected even though AES capability exists; investigate service configuration, SPN, requester and application path.</td></tr>
<tr><td>RC4 AS authentication observed</td><td><span class='badge sev-high'>High</span></td><td>Active RC4 authentication evidence requiring investigation.</td></tr>
<tr><td>Non-computer SPN account explicitly allows RC4, no RC4 TGS observed</td><td><span class='badge sev-medium'>Medium</span></td><td>Potential service dependency; validate AES before removing explicit RC4 support.</td></tr>
<tr><td>Computer supports RC4 + AES, only AES observed</td><td><span class='badge sev-informational'>Informational</span></td><td>Capability/configuration only; no active RC4 dependency observed.</td></tr>
<tr><td>Explicit AES-only configuration, no RC4 observed</td><td><span class='badge sev-healthy'>Healthy</span></td><td>No RC4 remediation identified from the observed evidence.</td></tr>
</tbody></table></div>
</div>

<div class="section">
<h2>KDCSVC 201-209 — enforcement readiness</h2>
<div class="note">Microsoft's CVE-2026-20833 deployment guidance recommends monitoring KDCSVC Events 201-209 in the <b>System</b> log. These events are shown as supplementary evidence because they describe audit/enforcement compatibility conditions and are not a substitute for 4768/4769 usage attribution.</div>
<div class="tablewrap"><table class="kdc-table">
<thead><tr><th>Event ID</th><th>Level</th><th>Domain Controller</th><th>Time</th><th>Event summary</th></tr></thead>
<tbody>$kdcRows</tbody></table></div>
</div>

<div class="section"><h2>Collection health</h2>
<p>Security events read: <b>$totalEvents</b> &nbsp; | &nbsp; Modern-schema: <b>$modernEvents</b> &nbsp; | &nbsp; Legacy-schema: <b>$legacyEvents</b> &nbsp; | &nbsp; KDCSVC 201-209: <b>$($kdcEvents.Count)</b></p>
<div class="tablewrap"><table class="smalltable"><thead><tr><th>Domain Controller</th><th>Error</th></tr></thead><tbody>$errorRows</tbody></table></div>
</div>

<footer>
Generated by <b>Invoke-KerberosRC4Assessment v1.7.2 Production Final</b>. Read-only assessment. No Active Directory, SPN, GPO, password, registry, or Kerberos-policy changes are performed.<br>
Correlation model is based on Microsoft Kerberos Security Event telemetry and the Microsoft Kerberos-Crypto Get-KerbEncryptionUsage.ps1 / List-AccountKeys.ps1 assessment approach. KDCSVC 201-209 are supplementary evidence for CVE-2026-20833 readiness.
</footer>
</div>
<script>
let currentFilter='ACTION';
const q=document.getElementById('q');
q.addEventListener('input',apply);
window.addEventListener('DOMContentLoaded',apply);
function setFilter(f){currentFilter=f;apply()}
function apply(){
 const term=q.value.toLowerCase();
 document.querySelectorAll('#main tbody tr').forEach(r=>{
  let ok=r.innerText.toLowerCase().includes(term);
  if(['Critical','High','Medium'].includes(currentFilter)) ok=ok&&r.dataset.severity===currentFilter;
  else if(currentFilter==='RC4') ok=ok&&r.dataset.rc4==='True';
  else if(currentFilter==='ACTION') ok=ok&&r.dataset.action==='True';
  else if(currentFilter==='INFO') ok=ok&&(r.dataset.severity==='Healthy'||r.dataset.severity==='Informational');
  r.style.display=ok?'':'none';
 });
}
</script>
</body></html>
"@

$html | Set-Content $htmlPath -Encoding UTF8

Write-Host ""
Write-Host "=== Kerberos RC4 Assessment v1.7.2 Production Final ===" -ForegroundColor White
Write-Host "Security events read         : $totalEvents"
Write-Host "Modern-schema events         : $modernEvents"
Write-Host "Legacy-schema events         : $legacyEvents"
Write-Host "KDCSVC 201-209 events        : $($kdcEvents.Count)"
Write-Host "Accounts in report           : $($results.Count)"
Write-Host "Accounts needing action      : $($action.Count)"
Write-Host "Attributed RC4 usage         : $actualRC4"
Write-Host "Critical                     : $critical"
Write-Host "High                         : $high"
Write-Host "Medium                       : $medium"
Write-Host "Healthy / Informational      : $($healthy+$info)"
Write-Host "Collection errors            : $($errors.Count)"
Write-Host ""
Write-Host "HTML   : $htmlPath" -ForegroundColor Green
Write-Host "CSV    : $csvPath" -ForegroundColor Green
Write-Host "KDCSVC : $kdcCsvPath" -ForegroundColor Green