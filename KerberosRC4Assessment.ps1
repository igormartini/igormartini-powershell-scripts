<#
.SYNOPSIS
    Collects and consolidates Kerberos RC4 usage evidence across all selected Domain Controllers.

.DESCRIPTION
    This single-file assessment extends the Microsoft Kerberos-Crypto approach by collecting
    Security Events 4768 and 4769 from mixed-generation Domain Controllers, including legacy
    and enhanced event schemas. It correlates event telemetry with Active Directory attributes
    and generates a concise HTML report, a CSV export, and a separate KDCSVC 201-209 readiness CSV.

.NOTES
    Author  : Igor Henrique Martini
    Website : https://igormartini.cloud
    Version: 5.2.1 Final
    Target execution platform: Windows 10 or Windows 11 with Windows PowerShell 5.1
    Supported Domain Controller event sources: Windows Server 2008 R2 through Windows Server 2025+

.DISCLAIMER
    Severity labels are an operational prioritization model created for this tool. They are not
    official Microsoft severity ratings. Validate all remediation actions in a controlled environment
    before making production changes.

.ASSESSMENT WORKFLOW
    1. Collect Security Events 4768 and 4769.
    2. Collect KDCSVC Events 201 through 209.
    3. Read Active Directory account attributes.
    4. Normalize and correlate evidence across all selected Domain Controllers.
    5. Generate the consolidated HTML report.
    6. Generate the consolidated CSV report.
    7. Generate the KDCSVC readiness CSV report.

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

# Writes a standardized progress message to the console.
function Write-Step([string]$Message) {
    Write-Host "[+] $Message" -ForegroundColor Cyan
}

# Escapes text before inserting it into HTML.
function Convert-HtmlSafe {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

# Implements the Normalize-PrincipalName helper used by the Kerberos assessment workflow.#

# Renders delimited values as one complete HTML record per line.
function Convert-ToHtmlRecordLines {
    param(
        [AllowNull()][string]$Value,
        [string]$Separator = ';'
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return '&mdash;'
    }

    $items = @(
        $Value -split [regex]::Escape($Separator) |
        ForEach-Object { $_.Trim() } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )

    if ($items.Count -eq 0) {
        return '&mdash;'
    }

    return (
        $items |
        ForEach-Object {
            "<div class='record-line'>$(Convert-HtmlSafe $_)</div>"
        }
    ) -join ''
}


# Normalizes principal names for cross-DC correlation.

# Renders semicolon-separated encryption values as stacked visual tags.
function Convert-ToHtmlEncryptionTags {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return '&mdash;'
    }

    $items = @(
        $Value -split ';' |
        ForEach-Object { $_.Trim() } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )

    if ($items.Count -eq 0) {
        return '&mdash;'
    }

    return (
        $items |
        ForEach-Object {
            $safe = Convert-HtmlSafe $_
            $class = if ($_ -match '^RC4') {
                'crypto-tag crypto-rc4'
            }
            elseif ($_ -match '^AES') {
                'crypto-tag crypto-aes'
            }
            elseif ($_ -match '^DES') {
                'crypto-tag crypto-des'
            }
            else {
                'crypto-tag'
            }

            "<div class='crypto-line'><span class='$class'>$safe</span></div>"
        }
    ) -join ''
}

# Renders requester-to-etype mappings as requester blocks with one etype per line.
function Convert-ToHtmlRequesterEtypeMap {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return '&mdash;'
    }

    $records = @(
        $Value -split '\s+\|\s+' |
        ForEach-Object { $_.Trim() } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )

    $html = foreach ($record in $records) {
        $parts = $record -split ':', 2
        $requester = Convert-HtmlSafe $parts[0].Trim()
        $etypeText = if ($parts.Count -gt 1) { $parts[1].Trim().Replace(',', ';') } else { '' }

        "<div class='requester-block'><div class='requester-name'>$requester</div>$(Convert-ToHtmlEncryptionTags $etypeText)</div>"
    }

    return $html -join ''
}


function Normalize-PrincipalName {
    param([AllowNull()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    $n = $Name.Trim()
    if ($n -match '@') { $n = $n.Split('@')[0] }
    if ($n -match '\\') { $n = $n.Split('\')[-1] }
    $n.Trim()
}

# Implements the Convert-EType helper.
function Convert-EType {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }
    $s = ([string]$Value).Trim()
    if (-not $s) { return '' }

    # 0xFFFFFFFF is logged when no Kerberos ticket was issued, typically in
    # authentication-failure events. It is a result state, not an encryption type.
    if ($s -match '^(?i)0xFFFFFFFF$' -or $s -eq '-1' -or $s -eq '4294967295') {
        return 'No Ticket Issued'
    }

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
            -1   { return 'No Ticket Issued' }
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

# Implements the Test-IsRC4 helper.
function Test-IsRC4([AllowNull()][object]$Value) {
    (Convert-EType $Value) -in @('RC4','RC4-EXP')
}

# Implements the Test-IsAES helper.
function Test-IsAES([AllowNull()][object]$Value) {
    (Convert-EType $Value) -in @('AES128-SHA96','AES256-SHA96','AES128-SHA256','AES256-SHA384','AES-SHA1')
}

# Implements the Split-AvailableKeys helper.
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

# Implements the Convert-SupportedEncryptionTypes helper.
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


# Implements the Split-AdvertizedEtypes helper.
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

# Implements the Add-AdvertizedEtypesEvidence helper.
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

# Implements the Get-ClientAESSupport helper.
function Get-ClientAESSupport {
    param($State)

    if ($null -eq $State -or $State.AdvertizedEtypesEvents -eq 0) { return 'Unknown' }

    if ($State.ClientAESAdvertisedEvents -gt 0 -and $State.ClientNoAESAdvertisedEvents -gt 0) {
        return 'Mixed'
    }

    if ($State.ClientAESAdvertisedEvents -gt 0) { return 'Yes' }
    return 'No'
}

# Implements the Add-RequesterAdvertizedEvidence helper.
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

# Implements the Format-RequesterAdvertizedEvidence helper.
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


# Implements the Add-CountMapValue helper.
function Add-CountMapValue {
    param([hashtable]$Map,[string]$Key,[int]$Increment=1)
    if ($null -eq $Map -or [string]::IsNullOrWhiteSpace($Key)) { return }
    if (-not $Map.ContainsKey($Key)) { $Map[$Key] = 0 }
    $Map[$Key] = [int]$Map[$Key] + $Increment
}

# Implements the Add-SetMapValue helper.
function Add-SetMapValue {
    param([hashtable]$Map,[string]$Key,[string]$Value)
    if ($null -eq $Map -or [string]::IsNullOrWhiteSpace($Key) -or [string]::IsNullOrWhiteSpace($Value)) { return }
    if (-not $Map.ContainsKey($Key)) {
        $Map[$Key] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }
    [void]$Map[$Key].Add($Value)
}

# Formats correlation counters for display.
function Format-CountMap {
    param([hashtable]$Map)
    if ($null -eq $Map -or $Map.Count -eq 0) { return '' }
    @(
        $Map.GetEnumerator() |
        Sort-Object Name |
        ForEach-Object { "$($_.Name): $($_.Value)" }
    ) -join ' | '
}

# Formats correlation sets for display.
function Format-SetMap {
    param([hashtable]$Map)
    if ($null -eq $Map -or $Map.Count -eq 0) { return '' }
    @(
        $Map.GetEnumerator() |
        Sort-Object Name |
        ForEach-Object {
            $values = @($_.Value | Sort-Object) -join ', '
            "$($_.Name): $values"
        }
    ) -join ' | '
}

# Implements the New-PrincipalState helper.
function New-PrincipalState {
    param([string]$Name)
    [pscustomobject][ordered]@{
        Name=$Name
        FirstSeen=$null
        LastSeen=$null
        EventCount=0
        ModernSchemaEvents=0
        LegacySchemaEvents=0
        CollectorModes=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        RemotePSVersions=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        # Account-key evidence (Microsoft List-AccountKeys semantics).
        # The union is retained for reporting, while per-event counters are used
        # to prevent a false RC4-only conclusion when evidence conflicts.
        AvailableKeys=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        KeyEvidenceEvents=0
        RC4OnlyKeyEvidenceEvents=0
        AESKeyEvidenceEvents=0
        OtherKeyEvidenceEvents=0
        KeyEvidenceByDC=@{}
        KeyEvidenceRecordIdsByDC=@{}

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

        # Per-DC evidence origin retained for auditability.
        EventCountByDC=@{}
        RC4TgsCountByDC=@{}
        RC4AsCountByDC=@{}
        AESTicketCountByDC=@{}
        AESSessionCountByDC=@{}
        TicketTypesByDC=@{}
        SessionTypesByDC=@{}
    }
}

# Implements the Get-OrCreateState helper.
function Get-OrCreateState {
    param([hashtable]$States,[string]$Name)
    $n = Normalize-PrincipalName $Name
    if (-not $n -or $n -eq '-') { return $null }
    $key = $n.ToLowerInvariant()
    if (-not $States.ContainsKey($key)) {
        # Suppress assignment output. Without [void], PowerShell emits the newly
        # assigned state and then emits it again on the return line below,
        # causing the caller to receive Object[] instead of one state object.
        [void]($States[$key] = New-PrincipalState $n)
    }
    return $States[$key]
}

# Implements the Touch-State helper.
function Touch-State {
    param($State,[datetime]$Time,[string]$DC,[long]$RecordId)
    if ($null -eq $State) { return }
    $State.EventCount++
    if ($null -eq $State.FirstSeen -or $Time -lt $State.FirstSeen) { $State.FirstSeen=$Time }
    if ($null -eq $State.LastSeen -or $Time -gt $State.LastSeen) { $State.LastSeen=$Time }
    if ($DC) {
        [void]$State.DomainControllers.Add($DC)
        Add-CountMapValue $State.EventCountByDC $DC 1
    }
    [void]$State.EvidenceRecordIds.Add([string]$RecordId)
}

# Tracks collector details for a principal.
function Add-CollectorEvidence {
    param(
        $State,
        [AllowNull()][string]$CollectorMode,
        [AllowNull()][string]$RemotePSVersion
    )

    if ($null -eq $State) { return }

    if (-not [string]::IsNullOrWhiteSpace($CollectorMode)) {
        [void]$State.CollectorModes.Add($CollectorMode)
    }

    if (-not [string]::IsNullOrWhiteSpace($RemotePSVersion)) {
        [void]$State.RemotePSVersions.Add($RemotePSVersion)
    }
}

# Tracks legacy or enhanced event-schema evidence.
function Add-SchemaEvidence {
    param($State,[bool]$IsModern)
    if ($null -eq $State) { return }
    if ($IsModern) { $State.ModernSchemaEvents++ } else { $State.LegacySchemaEvents++ }
}

# Determines whether evidence is legacy, modern, or hybrid.
function Get-AssessmentMode {
    param($State)
    if ($null -eq $State) { return 'Unknown' }
    if ($State.ModernSchemaEvents -gt 0 -and $State.LegacySchemaEvents -gt 0) { return 'Hybrid' }
    if ($State.ModernSchemaEvents -gt 0) { return 'Modern' }
    if ($State.LegacySchemaEvents -gt 0) { return 'Legacy' }
    return 'Unknown'
}

# Implements the Add-KeyEvidence helper.
function Add-KeyEvidence {
    param(
        $State,
        [object]$RawKeys,
        [string]$DC,
        [long]$RecordId
    )

    if ($null -eq $State) { return }

    $keys = @(Split-AvailableKeys $RawKeys)
    if ($keys.Count -eq 0) { return }

    $State.KeyEvidenceEvents++

    $eventHasAES = @($keys | Where-Object { Test-IsAES $_ }).Count -gt 0
    $eventHasRC4 = @($keys | Where-Object { Test-IsRC4 $_ }).Count -gt 0

    if ($eventHasAES) {
        $State.AESKeyEvidenceEvents++
    }
    elseif ($eventHasRC4) {
        $State.RC4OnlyKeyEvidenceEvents++
    }
    else {
        $State.OtherKeyEvidenceEvents++
    }

    foreach ($key in $keys) {
        [void]$State.AvailableKeys.Add($key)
        if ($DC) { Add-SetMapValue $State.KeyEvidenceByDC $DC $key }
    }

    if ($DC) {
        Add-SetMapValue $State.KeyEvidenceRecordIdsByDC $DC ([string]$RecordId)
    }
}

# Implements the Add-TargetUsage helper.
function Add-TargetUsage {
    param(
        $State,
        [object]$Ticket,
        [object]$Session,
        [ValidateSet('AS','TGS')][string]$Type,
        [string]$DC
    )
    if ($null -eq $State) { return }

    $t = Convert-EType $Ticket
    $sk = Convert-EType $Session

    if ($t) {
        [void]$State.TicketTypes.Add($t)
        if ($DC) { Add-SetMapValue $State.TicketTypesByDC $DC $t }

        if (Test-IsRC4 $t) {
            if ($Type -eq 'TGS') {
                $State.RC4TgsTargetCount++
                if ($DC) { Add-CountMapValue $State.RC4TgsCountByDC $DC 1 }
            }
            else {
                $State.RC4AsCount++
                if ($DC) { Add-CountMapValue $State.RC4AsCountByDC $DC 1 }
            }
        }

        if (Test-IsAES $t) {
            $State.AESTicketCount++
            if ($DC) { Add-CountMapValue $State.AESTicketCountByDC $DC 1 }
        }
    }

    if ($sk) {
        [void]$State.SessionKeyTypes.Add($sk)
        if ($DC) { Add-SetMapValue $State.SessionTypesByDC $DC $sk }
        if (Test-IsAES $sk) {
            $State.AESSessionCount++
            if ($DC) { Add-CountMapValue $State.AESSessionCountByDC $DC 1 }
        }
    }
}

# Implements the Add-RequesterContext helper.
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

# Implements the Get-ADPrincipal helper.
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

# Builds a contextual remediation recommendation from the observed evidence.
function Get-ContextualRecommendation {
    param(
        [bool]$RC4TgsObserved,
        [bool]$RC4AsObserved,
        [bool]$HasAESKeyEvidence,
        [bool]$ExplicitRC4,
        [bool]$ExplicitAES,
        [bool]$ZeroEncryptionTypes,
        [ValidateSet('User','Service','Computer')]
        [string]$AccountType
    )

    $actions = New-Object 'System.Collections.Generic.List[string]'
    $hasConfiguredOrObservedAES = $HasAESKeyEvidence -or $ExplicitAES

    if ($RC4TgsObserved -and $RC4AsObserved) {
        $actions.Add('Investigate both the RC4 authentication requests and RC4 service-ticket activity associated with this principal.')
    }
    elseif ($RC4TgsObserved) {
        $actions.Add('Identify the service and requesting principals responsible for the RC4 service tickets.')
    }
    elseif ($RC4AsObserved) {
        $actions.Add('Identify the client, device, or account generating RC4 authentication requests.')
    }

    if (-not $hasConfiguredOrObservedAES) {
        $actions.Add('Reset the account password through the approved change process to generate AES keys, then verify that the account has usable AES key material.')
    }
    elseif ($RC4TgsObserved -and $AccountType -eq 'Service') {
        $actions.Add('Verify that the service account has valid AES keys; reset its password if the required AES keys are missing or stale.')
    }

    if ($ZeroEncryptionTypes) {
        $actions.Add('Review the zero-valued msDS-SupportedEncryptionTypes configuration and explicitly configure the required AES encryption types after compatibility validation.')
    }
    elseif ($ExplicitRC4) {
        $actions.Add('Review msDS-SupportedEncryptionTypes and retain the required AES types; remove the RC4 bit only after compatibility testing succeeds.')
    }

    switch ($AccountType) {
        'Service' {
            $actions.Add('Validate that the application, service, and every dependent client support AES before changing the production configuration.')
        }
        'Computer' {
            $actions.Add('Verify the operating system, machine-account configuration, and Kerberos policy of the device, then confirm that machine authentication negotiates AES.')
        }
        'User' {
            $actions.Add('Verify the client configuration and any applications using this identity, then confirm that subsequent Kerberos authentications negotiate AES.')
        }
    }

    if ($RC4TgsObserved -and $RC4AsObserved) {
        $actions.Add('Re-audit Events 4768 and 4769 and confirm that both authentication requests and service tickets use AES before removing the remaining RC4 dependency.')
    }
    elseif ($RC4TgsObserved) {
        $actions.Add('Request new service tickets and confirm in Event 4769 that AES is negotiated before removing RC4 support.')
    }
    elseif ($RC4AsObserved) {
        $actions.Add('Repeat authentication and confirm in Event 4768 that AES is negotiated before removing RC4 support.')
    }

    ($actions | Select-Object -Unique) -join ' '
}

# Assigns severity, finding, and a contextual recommendation.
function Get-Classification {
    param(
        [bool]$RC4TgsObserved,
        [bool]$RC4AsObserved,
        [bool]$AESTicketObserved,
        [bool]$AESSessionObserved,
        [bool]$HasAESKeyEvidence,
        [bool]$ExplicitRC4,
        [bool]$ExplicitAES,
        [bool]$ZeroEncryptionTypes,
        [ValidateSet('User','Service','Computer')]
        [string]$AccountType
    )

    $observedRC4 = $RC4TgsObserved -or $RC4AsObserved
    $hasAESEvidence = $AESTicketObserved -or $AESSessionObserved -or $HasAESKeyEvidence -or $ExplicitAES

    if ($observedRC4) {
        $finding = if ($RC4TgsObserved -and $RC4AsObserved) {
            'Events 4768 and 4769: RC4 observed.'
        }
        elseif ($RC4TgsObserved) {
            'Event 4769: RC4 service ticket observed.'
        }
        else {
            'Event 4768: RC4 authentication activity observed.'
        }

        if ($ZeroEncryptionTypes) {
            $finding += ' AD attribute: msDS-SupportedEncryptionTypes is configured as 0 (Unset).'
        }

        return [pscustomobject]@{
            Severity='High'
            NeedsAction=$true
            Finding=$finding
            Recommendation=Get-ContextualRecommendation `
                -RC4TgsObserved $RC4TgsObserved `
                -RC4AsObserved $RC4AsObserved `
                -HasAESKeyEvidence $HasAESKeyEvidence `
                -ExplicitRC4 $ExplicitRC4 `
                -ExplicitAES $ExplicitAES `
                -ZeroEncryptionTypes $ZeroEncryptionTypes `
                -AccountType $AccountType
        }
    }

    if ($ExplicitRC4) {
        $typeGuidance = switch ($AccountType) {
            'Service' {
                'Validate the service and all dependent applications with AES before changing the account configuration.'
            }
            'Computer' {
                'Verify the operating system and machine-account Kerberos configuration, then confirm that device authentication uses AES.'
            }
            default {
                'Verify the client and application configuration, then confirm that future Kerberos authentications use AES.'
            }
        }

        return [pscustomobject]@{
            Severity='Medium'
            NeedsAction=$true
            Finding='AD attribute: msDS-SupportedEncryptionTypes allows RC4; no RC4 activity was observed in the selected window.'
            Recommendation=("RC4 is permitted but was not observed during the assessment window. Review whether RC4 is still required. {0} After successful compatibility validation, remove the RC4 bit from msDS-SupportedEncryptionTypes while retaining the required AES types, then monitor Events 4768/4769 for authentication failures or renewed RC4 activity." -f $typeGuidance)
        }
    }

    if ($hasAESEvidence) {
        return [pscustomobject]@{
            Severity='Healthy'
            NeedsAction=$false
            Finding='Events or account evidence show AES capability or usage; no RC4 activity was observed in the selected window.'
            Recommendation='No RC4 remediation is currently required. Continue periodic monitoring to confirm that Kerberos authentication remains on AES and that RC4 is not reintroduced.'
        }
    }

    return [pscustomobject]@{
        Severity='Informational'
        NeedsAction=$false
        Finding='No RC4 activity was observed, but the available event and account evidence is insufficient for a stronger conclusion.'
        Recommendation='Continue monitoring Events 4768/4769. Review Available Keys, msDS-SupportedEncryptionTypes, password age, application compatibility, and client behavior before making an encryption-policy change.'
    }
}

Write-Step "Checking prerequisites"
Import-Module ActiveDirectory -ErrorAction Stop

$domain = Get-ADDomain
$forest = Get-ADForest
$collectionEnd = Get-Date
$since = $collectionEnd.AddDays(-$Days)

if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

$stamp = $collectionEnd.ToString('yyyyMMdd_HHmmss')
$htmlPath = Join-Path $OutputPath "Kerberos_RC4_Assessment_$stamp.html"
$csvPath = Join-Path $OutputPath "Kerberos_RC4_Assessment_$stamp.csv"
$kdcCsvPath = Join-Path $OutputPath "Kerberos_RC4_KDCSVC_201-209_$stamp.csv"
$generatedAt = $collectionEnd
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

    [long]$receivedCount = 0
    [long]$processedCount = 0
    $collectionWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $lastProgressUpdate = [datetime]::MinValue

    try {
        # OPTIMIZED WINRM STREAMING + NAMED-FIELD COLLECTION
        # ------------------------------------
        # Get-WinEvent runs locally on the DC, but only a flat DTO containing the
        # exact fields used by the v1.7 analysis engine is serialized over WinRM.
        # Events are processed locally as they arrive; no large local or remote
        # event array is created and no preliminary count/second log scan occurs.
        Invoke-Command -ComputerName $dcName -ArgumentList $since,$collectionEnd -ErrorAction Stop -ScriptBlock {
            param(
                [datetime]$StartTime,
                [datetime]$EndTime
            )

            # ------------------------------------------------------------
            # LEGACY COLLECTOR - Windows PowerShell 2.0 / Server 2008 R2
            # ------------------------------------------------------------
            # PowerShell 2.0 does not reliably support the modern
            # EventLogPropertySelector path or FilterHashtable behavior used by
            # newer systems. Use one XPath query and parse XML locally on the DC.
            # Only the normalized compact DTO crosses WinRM.
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                $utcStart = $StartTime.ToUniversalTime().ToString(
                    'yyyy-MM-ddTHH:mm:ss.fffZ',
                    [System.Globalization.CultureInfo]::InvariantCulture
                )
                $utcEnd = $EndTime.ToUniversalTime().ToString(
                    'yyyy-MM-ddTHH:mm:ss.fffZ',
                    [System.Globalization.CultureInfo]::InvariantCulture
                )

                $legacyXPath = "*[System[((EventID=4768) or (EventID=4769)) and TimeCreated[@SystemTime>='$utcStart' and @SystemTime<='$utcEnd']]]"

                Get-WinEvent `
                    -LogName Security `
                    -FilterXPath $legacyXPath `
                    -ErrorAction Stop |
                    ForEach-Object {
                        $id = [int]$_.Id
                        $eventData = @{}

                        try {
                            [xml]$eventXml = $_.ToXml()

                            foreach ($dataNode in $eventXml.Event.EventData.Data) {
                                $fieldName = [string]$dataNode.Name

                                if (-not [string]::IsNullOrEmpty($fieldName)) {
                                    $eventData[$fieldName] = [string]$dataNode.'#text'
                                }
                            }

                            $source = [string]$eventData['TargetUserName']
                            $target = [string]$eventData['ServiceName']
                            $ticket = $eventData['TicketEncryptionType']
                            $ip = [string]$eventData['IpAddress']

                            $isValid = (
                                -not [string]::IsNullOrEmpty($source) -and
                                -not [string]::IsNullOrEmpty($target) -and
                                $null -ne $ticket
                            )

                            New-Object PSObject -Property @{
                                Id               = $id
                                TimeCreated      = [datetime]$_.TimeCreated
                                RecordId         = [long]$_.RecordId
                                IsModern         = $false
                                IsValid          = [bool]$isValid
                                Source           = $source
                                Target           = $target
                                Ticket           = $ticket
                                Ip               = $ip
                                Keys             = $null
                                Session          = $null
                                AdvertizedEtypes = $null
                                CollectorMode    = 'LegacyXPathXml'
                                RemotePSVersion  = [string]$PSVersionTable.PSVersion
                            }
                        }
                        catch {
                            New-Object PSObject -Property @{
                                Id               = $id
                                TimeCreated      = [datetime]$_.TimeCreated
                                RecordId         = [long]$_.RecordId
                                IsModern         = $false
                                IsValid          = $false
                                Source           = $null
                                Target           = $null
                                Ticket           = $null
                                Ip               = $null
                                Keys             = $null
                                Session          = $null
                                AdvertizedEtypes = $null
                                CollectorMode    = 'LegacyXPathXml'
                                RemotePSVersion  = [string]$PSVersionTable.PSVersion
                            }
                        }
                    }

                return
            }

            # ------------------------------------------------------------
            # MODERN COLLECTOR - PowerShell 3.0+
            # ------------------------------------------------------------

            # Resolve the required EventData fields by NAME rather than by Properties[]
            # position. This prevents schema/layout differences from shifting fields such
            # as TicketEncryptionType, SessionKeyEncryptionType and Available Keys.
            # The selector is created once per DC and GetPropertyValues() returns only
            # these values; ToXml() is never called.
            $fieldNames = [string[]]@(
                'TargetUserName',
                'ServiceName',
                'TicketEncryptionType',
                'IpAddress',
                'AccountAvailableKeys',
                'ServiceAvailableKeys',
                'SessionKeyEncryptionType',
                'ClientAdvertizedEncryptionTypes',
                'ClientAdvertisedEncryptionTypes'
            )

            $fieldXpaths = [string[]]@(
                $fieldNames | ForEach-Object { "Event/EventData/Data[@Name='$_']" }
            )

            # New-Object keeps this remote block compatible with Windows PowerShell 2.0
            # on Windows Server 2008 R2. The modern ::new() syntax is not used here.
            $fieldSelector = New-Object `
                System.Diagnostics.Eventing.Reader.EventLogPropertySelector `
                -ArgumentList (,$fieldXpaths)

# Implements the Test-RemoteBlank helper.
            function Test-RemoteBlank {
                param([object]$Value)
                if ($null -eq $Value) { return $true }
                return (([string]$Value).Trim().Length -eq 0)
            }

# Implements the Get-SelectedFieldValue helper.
            function Get-SelectedFieldValue {
                param(
                    [object[]]$Values,
                    [int]$Index
                )

                if ($null -eq $Values -or $Index -lt 0 -or $Index -ge $Values.Count) {
                    return $null
                }

                $value = $Values[$Index]
                if ($null -eq $value) { return $null }

                $text = [string]$value
                if ((Test-RemoteBlank $text) -or $text -eq '-') { return $null }
                return $value
            }

            Get-WinEvent -FilterHashtable @{
                LogName='Security'
                Id=4768,4769
                StartTime=$StartTime
                EndTime=$EndTime
            } -ErrorAction Stop | ForEach-Object {
                $id = [int]$_.Id
                $values = @()

                $selectorSucceeded = $false
                try {
                    $values = @($_.GetPropertyValues($fieldSelector))
                    $selectorSucceeded = $true
                }
                catch {
                    $selectorSucceeded = $false
                }

                if ($selectorSucceeded) {
                    $source  = Get-SelectedFieldValue $values 0 # TargetUserName
                    $target  = Get-SelectedFieldValue $values 1 # ServiceName
                    $ticket  = Get-SelectedFieldValue $values 2 # TicketEncryptionType
                    $ip      = Get-SelectedFieldValue $values 3 # IpAddress
                    $acctKey = Get-SelectedFieldValue $values 4 # AccountAvailableKeys
                    $svcKey  = Get-SelectedFieldValue $values 5 # ServiceAvailableKeys
                    $session = Get-SelectedFieldValue $values 6 # SessionKeyEncryptionType
                    $adv1    = Get-SelectedFieldValue $values 7 # Microsoft spelling: Advertized
                    $adv2    = Get-SelectedFieldValue $values 8 # Alternate spelling: Advertised
                }
                else {
                    # Compatibility fallback for older KDC/PowerShell combinations.
                    # XML is parsed locally on the DC and only the compact DTO crosses WinRM.
                    $eventData = @{}
                    try {
                        [xml]$eventXml = $_.ToXml()
                        foreach ($dataNode in $eventXml.Event.EventData.Data) {
                            $fieldName = [string]$dataNode.Name
                            if (-not (Test-RemoteBlank $fieldName)) {
                                $eventData[$fieldName] = [string]$dataNode.'#text'
                            }
                        }
                    }
                    catch {
                        New-Object PSObject -Property @{
                            Id=$id; TimeCreated=[datetime]$_.TimeCreated; RecordId=[long]$_.RecordId
                            IsModern=$false; IsValid=$false; Source=$null; Target=$null
                            Ticket=$null; Ip=$null; Keys=$null; Session=$null
                            AdvertizedEtypes=$null
                            CollectorMode='ModernXmlFallback'
                            RemotePSVersion=[string]$PSVersionTable.PSVersion
                        }
                        return
                    }

                    $source  = $eventData['TargetUserName']
                    $target  = $eventData['ServiceName']
                    $ticket  = $eventData['TicketEncryptionType']
                    $ip      = $eventData['IpAddress']
                    $acctKey = $eventData['AccountAvailableKeys']
                    $svcKey  = $eventData['ServiceAvailableKeys']
                    $session = $eventData['SessionKeyEncryptionType']
                    $adv1    = $eventData['ClientAdvertizedEncryptionTypes']
                    $adv2    = $eventData['ClientAdvertisedEncryptionTypes']
                }

                $advertizedEtypes = if ($null -ne $adv1 -and -not (Test-RemoteBlank $adv1)) { $adv1 } else { $adv2 }

                # Microsoft attribution is preserved:
                # 4769 -> ServiceAvailableKeys belongs to the TARGET service account.
                # 4768 -> AccountAvailableKeys belongs to the SOURCE account.
                $keys = if ($id -eq 4769) { $svcKey } else { $acctKey }

                # Validate the minimum named fields required for attribution. Missing
                # optional modern fields do not invalidate the event.
                $isValid = -not (Test-RemoteBlank $source) -and
                           -not (Test-RemoteBlank $target) -and
                           $null -ne $ticket

                $isModern = ($null -ne $acctKey -or $null -ne $svcKey -or
                             $null -ne $session -or $null -ne $advertizedEtypes)

                New-Object PSObject -Property @{
                    Id               = $id
                    TimeCreated      = [datetime]$_.TimeCreated
                    RecordId         = [long]$_.RecordId
                    IsModern         = [bool]$isModern
                    IsValid          = [bool]$isValid
                    Source           = if ($null -ne $source) { [string]$source } else { $null }
                    Target           = if ($null -ne $target) { [string]$target } else { $null }
                    Ticket           = $ticket
                    Ip               = if ($null -ne $ip) { [string]$ip } else { $null }
                    Keys             = $keys
                    Session          = $session
                    AdvertizedEtypes = $advertizedEtypes
                    CollectorMode = if($selectorSucceeded){'ModernNamedField'}else{'ModernXmlFallback'}
                    RemotePSVersion = [string]$PSVersionTable.PSVersion
                }
            }
        } | ForEach-Object {
            $dto = $_
            $receivedCount++
            $totalEvents++

            if ([bool]$dto.IsModern) { $modernEvents++ } else { $legacyEvents++ }

            if ([bool]$dto.IsValid) {
                if ([int]$dto.Id -eq 4769) {
                    # Target/service account: TGS encryption and Available Keys are
                    # attributed exactly as in Microsoft's reference scripts.
                    $targetState = Get-OrCreateState $states ([string]$dto.Target)
                    if ($null -ne $targetState) {
                        Touch-State $targetState ([datetime]$dto.TimeCreated) $dcName ([long]$dto.RecordId)
                        Add-SchemaEvidence $targetState ([bool]$dto.IsModern)
                        Add-CollectorEvidence $targetState ([string]$dto.CollectorMode) ([string]$dto.RemotePSVersion)
                        Add-KeyEvidence $targetState $dto.Keys $dcName ([long]$dto.RecordId)
                        Add-TargetUsage $targetState $dto.Ticket $dto.Session 'TGS' $dcName
                        Add-AdvertizedEtypesEvidence $targetState $dto.AdvertizedEtypes
                        Add-RequesterAdvertizedEvidence $targetState ([string]$dto.Source) $dto.AdvertizedEtypes

                        $normalizedSource = Normalize-PrincipalName ([string]$dto.Source)
                        if ($normalizedSource) {
                            [void]$targetState.RequestingPrincipals.Add($normalizedSource)
                        }
                        if (-not [string]::IsNullOrWhiteSpace([string]$dto.Ip)) {
                            [void]$targetState.RequesterAddresses.Add([string]$dto.Ip)
                        }
                    }

                    # Requestor context only; this does not attribute the target's
                    # TGS encryption to the requesting account.
                    $sourceState = Get-OrCreateState $states ([string]$dto.Source)
                    if ($null -ne $sourceState) {
                        Touch-State $sourceState ([datetime]$dto.TimeCreated) $dcName ([long]$dto.RecordId)
                        Add-SchemaEvidence $sourceState ([bool]$dto.IsModern)
                        Add-CollectorEvidence $sourceState ([string]$dto.CollectorMode) ([string]$dto.RemotePSVersion)
                        Add-RequesterContext $sourceState $dto.Ticket $dto.Session ([string]$dto.Target) ([string]$dto.Ip)
                    }
                }
                elseif ([int]$dto.Id -eq 4768) {
                    # For 4768, Microsoft attributes Properties[16] Available Keys
                    # to the source account.
                    $sourceState = Get-OrCreateState $states ([string]$dto.Source)
                    if ($null -ne $sourceState) {
                        Touch-State $sourceState ([datetime]$dto.TimeCreated) $dcName ([long]$dto.RecordId)
                        Add-SchemaEvidence $sourceState ([bool]$dto.IsModern)
                        Add-CollectorEvidence $sourceState ([string]$dto.CollectorMode) ([string]$dto.RemotePSVersion)
                        Add-KeyEvidence $sourceState $dto.Keys $dcName ([long]$dto.RecordId)
                        Add-TargetUsage $sourceState $dto.Ticket $dto.Session 'AS' $dcName
                        Add-AdvertizedEtypesEvidence $sourceState $dto.AdvertizedEtypes
                        Add-RequesterContext $sourceState $dto.Ticket $dto.Session ([string]$dto.Target) ([string]$dto.Ip)
                    }
                }
            }

            $processedCount++
            $now = Get-Date
            if (($processedCount % 500 -eq 0) -or (($now - $lastProgressUpdate).TotalSeconds -ge 1)) {
                $elapsedSeconds = [math]::Max($collectionWatch.Elapsed.TotalSeconds, 0.001)
                $rate = [math]::Round($processedCount / $elapsedSeconds, 1)
                $status = ('Received and processed {0:N0} events | Elapsed {1:hh\:mm\:ss} | {2:N1} events/sec' -f `
                    $processedCount, $collectionWatch.Elapsed, $rate)

                Write-Progress -Id 10 `
                    -Activity "Collecting and processing Kerberos events from $dcName" `
                    -Status $status `
                    -PercentComplete -1 `
                    -SecondsRemaining -1

                $lastProgressUpdate = $now
            }
        }

        $collectionWatch.Stop()
        Write-Progress -Id 10 -Activity "Collecting and processing Kerberos events from $dcName" -Completed
        Write-Host ('    Complete: {0:N0} events received and processed in {1:hh\:mm\:ss}' -f `
            $processedCount, $collectionWatch.Elapsed) -ForegroundColor DarkGray
    }
    catch {
        $collectionWatch.Stop()
        Write-Progress -Id 10 -Activity "Collecting and processing Kerberos events from $dcName" -Completed
        $errors.Add([pscustomobject]@{DomainController=$dcName;Error=$_.Exception.Message})
        Write-Warning "Could not read $dcName : $($_.Exception.Message)"
        continue
    }
}

# Microsoft CVE-2026-20833 guidance recommends monitoring KDCSVC 201-209.
# These System-log events are supplementary enforcement-readiness evidence only.
foreach ($dc in $dcs) {
    $dcName = [string]$dc.HostName
    Write-Step "Reading KDCSVC 201-209 from $dcName"
    try {
        $systemEvents = @(Invoke-Command -ComputerName $dcName -ArgumentList $since,$collectionEnd -ErrorAction Stop -ScriptBlock {
            param(
                [datetime]$StartTime,
                [datetime]$EndTime
            )

            Get-WinEvent -FilterHashtable @{
                LogName='System'
                Id=201,202,203,204,205,206,207,208,209
                StartTime=$StartTime
                EndTime=$EndTime
            } -ErrorAction Stop | ForEach-Object {
                $message = ''
                try { $message = [string]$_.Message } catch {}

                New-Object PSObject -Property @{
                    Id               = [int]$_.Id
                    TimeCreated      = [datetime]$_.TimeCreated
                    RecordId         = [long]$_.RecordId
                    ProviderName     = [string]$_.ProviderName
                    LevelDisplayName = [string]$_.LevelDisplayName
                    Message          = $message
                }
            }
        })

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
Write-Step "Automatic compatibility: Legacy, Modern, and Hybrid evidence detected from event fields"

$results = [System.Collections.Generic.List[object]]::new()

foreach ($entry in $states.GetEnumerator()) {
    $s = $entry.Value
    $ad = Get-ADPrincipal $s.Name

    # Keep only resolvable AD principals in the account-remediation table.
    # Unresolved requestor strings are not actionable account objects.
    if (-not $ad) { continue }

    $enc = Convert-SupportedEncryptionTypes $ad.'msDS-SupportedEncryptionTypes'
    $isKrbtgt = (
        [string]::Equals([string]$s.Name,'krbtgt',[System.StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals([string]$ad.sAMAccountName,'krbtgt',[System.StringComparison]::OrdinalIgnoreCase)
    )

    # Exclude the built-in krbtgt account from every report output.
    if ($isKrbtgt) { continue }

    $status = if (([int64]$ad.userAccountControl -band 0x2) -ne 0) {
        'Disabled'
    }
    else {
        'Enabled'
    }

    $assessmentMode = Get-AssessmentMode $s
    $keys = @($s.AvailableKeys | Sort-Object)
    $hasAESKey = @($keys | Where-Object { Test-IsAES $_ }).Count -gt 0
    $hasRC4Key = @($keys | Where-Object { Test-IsRC4 $_ }).Count -gt 0
    $explicitAES = $enc.AES128 -or $enc.AES256

    $keyEvidenceConflict = (
        $s.AESKeyEvidenceEvents -gt 0 -and
        $s.RC4OnlyKeyEvidenceEvents -gt 0
    )

    $conclusiveRC4OnlyKeyEvidence = (
        $s.KeyEvidenceEvents -gt 0 -and
        $s.RC4OnlyKeyEvidenceEvents -gt 0 -and
        $s.AESKeyEvidenceEvents -eq 0 -and
        $s.OtherKeyEvidenceEvents -eq 0 -and
        $hasRC4Key -and
        -not $hasAESKey
    )

    $spns = @($ad.servicePrincipalName)
    $hasSPN = $spns.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace(($spns -join ''))
    $zeroEncryptionTypes = (
        $null -ne $ad.'msDS-SupportedEncryptionTypes' -and
        [int64]$ad.'msDS-SupportedEncryptionTypes' -eq 0
    )
    $accountType = if ([string]$ad.objectClass -eq 'computer') {
        'Computer'
    }
    elseif ($hasSPN) {
        'Service'
    }
    else {
        'User'
    }

    $class = Get-Classification `
        -RC4TgsObserved ($s.RC4TgsTargetCount -gt 0) `
        -RC4AsObserved ($s.RC4AsCount -gt 0) `
        -AESTicketObserved ($s.AESTicketCount -gt 0) `
        -AESSessionObserved ($s.AESSessionCount -gt 0) `
        -HasAESKeyEvidence $hasAESKey `
        -ExplicitRC4 $enc.RC4 `
        -ExplicitAES $explicitAES `
        -ZeroEncryptionTypes $zeroEncryptionTypes `
        -AccountType $accountType

    $pwdLastSet = $null
    if ($ad.pwdLastSet -and [int64]$ad.pwdLastSet -gt 0) {
        try { $pwdLastSet=[datetime]::FromFileTimeUtc([int64]$ad.pwdLastSet).ToLocalTime() } catch {}
    }

    $results.Add([pscustomobject]@{
        Severity=$class.Severity
        NeedsAction=$class.NeedsAction
        Status=$status
        Account=$s.Name
        AccountType=$accountType
        RC4Seen=if(($s.RC4TgsTargetCount -gt 0) -or ($s.RC4AsCount -gt 0)){'Yes'}else{'No'}
        SamAccountName=[string]$ad.sAMAccountName
        UserPrincipalName=[string]$ad.userPrincipalName
        ObjectClass=[string]$ad.objectClass
        UPN=[string]$ad.userPrincipalName
        HasSPN=$hasSPN
        SPNs=$spns -join '; '
        ServicePrincipalNames=$spns -join '; '
        PasswordLastSet=$pwdLastSet
        msDSSupportedEncryptionTypesHex=$enc.Hex
        msDSSupportedEncryptionTypes=$enc.Summary
        EncryptionFlags=$enc.Summary
        ExplicitRC4=$enc.RC4
        ExplicitAES=$explicitAES

        # Official List-AccountKeys perspective
        AvailableKeys=$keys -join '; '
        HasAESKey=$hasAESKey
        HasRC4Key=$hasRC4Key
        KeyEvidenceEvents=$s.KeyEvidenceEvents
        RC4OnlyKeyEvidenceEvents=$s.RC4OnlyKeyEvidenceEvents
        AESKeyEvidenceEvents=$s.AESKeyEvidenceEvents
        OtherKeyEvidenceEvents=$s.OtherKeyEvidenceEvents
        ConclusiveRC4OnlyKeyEvidence=$conclusiveRC4OnlyKeyEvidence
        ConflictingKeyEvidence=$keyEvidenceConflict

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
        ObservedTicketEncryption=@($s.TicketTypes | Sort-Object) -join '; '
        SessionKeyEncryptionObserved=@($s.SessionKeyTypes | Sort-Object) -join '; '
        ObservedSessionEncryption=@($s.SessionKeyTypes | Sort-Object) -join '; '
        RC4TgsTargetCount=$s.RC4TgsTargetCount
        RC4AsCount=$s.RC4AsCount
        AESTicketCount=$s.AESTicketCount
        AESSessionCount=$s.AESSessionCount

        # Context: what this account requested from other targets; not classification input for TGS dependency
        RequestedTicketEncryption=@($s.RequestedTicketTypes | Sort-Object) -join '; '
        RequestedSessionEncryption=@($s.RequestedSessionTypes | Sort-Object) -join '; '
        RC4RequestsMade=$s.RC4RequestsMade
        RequestedTargets=@($s.TargetPrincipals | Sort-Object) -join '; '

        RequestingPrincipals=@($s.RequestingPrincipals | Sort-Object) -join '; '
        RequesterAddresses=@($s.RequesterAddresses | Sort-Object) -join '; '
        LastSeen=$s.LastSeen
        EvidenceFinding=$class.Finding
        Recommendation=$class.Recommendation
        DistinguishedName=[string]$ad.distinguishedName
    })
}

$rank=@{High=1;Medium=2;Healthy=3;Informational=4}
$results=@($results | Sort-Object @{Expression={$rank[$_.Severity]}},Status,Account)

# Dashboard remediation metrics represent currently enabled objects only.
$activeResults=@($results | Where-Object Status -eq 'Enabled')
$action=@($activeResults | Where-Object NeedsAction)
$disabledResults=@($results | Where-Object Status -eq 'Disabled')
$disabledRecentRC4=@($disabledResults | Where-Object {
    $_.RC4TgsTargetCount -gt 0 -or $_.RC4AsCount -gt 0
})

$results |
    Select-Object `
        Severity,
        Status,
        Account,
        AccountType,
        RC4Seen,
        ServicePrincipalNames,
        AvailableKeys,
        msDSSupportedEncryptionTypes,
        AdvertizedEtypes,
        RequesterAdvertizedEtypes,
        ObservedTicketEncryption,
        ObservedSessionEncryption,
        RC4TgsTargetCount,
        RC4AsCount,
        RequestingPrincipals,
        LastSeen,
        EvidenceFinding,
        Recommendation |
    Export-Csv $csvPath -NoTypeInformation -Encoding UTF8

if ($kdcEvents.Count -gt 0) {
    $kdcEvents | Export-Csv $kdcCsvPath -NoTypeInformation -Encoding UTF8
} else {
    '"DomainController","EventId","Level","TimeCreated","RecordId","Provider","Message"' |
        Set-Content -Path $kdcCsvPath -Encoding UTF8
}

$high=@($activeResults|Where-Object Severity -eq High).Count
$medium=@($activeResults|Where-Object Severity -eq Medium).Count
$healthy=@($activeResults|Where-Object Severity -eq Healthy).Count
$info=@($activeResults|Where-Object Severity -eq Informational).Count
$actualRC4=@($activeResults|Where-Object {$_.RC4TgsTargetCount -gt 0 -or $_.RC4AsCount -gt 0}).Count

$rows = foreach($r in $results) {
    $sev="sev-"+$r.Severity.ToLowerInvariant()
    $rc4=[bool]($r.RC4TgsTargetCount -gt 0 -or $r.RC4AsCount -gt 0)
    $spnDisplay = Convert-ToHtmlRecordLines -Value $r.SPNs -Separator ';'
    $availableKeysDisplay = Convert-ToHtmlEncryptionTags -Value $r.AvailableKeys
    $supportedEncryptionDisplay = Convert-ToHtmlEncryptionTags -Value $r.msDSSupportedEncryptionTypes
    $advertizedEtypesDisplay = Convert-ToHtmlEncryptionTags -Value $r.AdvertizedEtypes
    $requesterEtypes = Convert-ToHtmlRequesterEtypeMap -Value $r.RequesterAdvertizedEtypes
    $ticketEncryptionDisplay = Convert-ToHtmlEncryptionTags -Value $r.TicketEncryptionObserved
    $sessionEncryptionDisplay = Convert-ToHtmlEncryptionTags -Value $r.SessionKeyEncryptionObserved
    $requestingPrincipalsDisplay = Convert-ToHtmlRecordLines -Value $r.RequestingPrincipals -Separator ';'

    "<tr data-severity='$($r.Severity)' data-status='$($r.Status)' data-rc4='$rc4'>"+
    "<td><span class='badge $sev'>$(Convert-HtmlSafe $r.Severity)</span></td>"+
    "<td><span class='status-badge status-$($r.Status.ToLowerInvariant())'>$(Convert-HtmlSafe $r.Status)</span></td>"+
    "<td class='account-cell'><b>$(Convert-HtmlSafe $r.Account)</b><div class='sub'>$(Convert-HtmlSafe $r.UPN)</div></td>"+
    "<td>$(Convert-HtmlSafe $r.AccountType)</td>"+
    "<td class='num'>$(Convert-HtmlSafe $r.RC4Seen)</td>"+
    "<td class='spn'>$spnDisplay</td>"+
    "<td>$availableKeysDisplay</td>"+
    "<td><b class='nowrap-value'>$(Convert-HtmlSafe $r.msDSSupportedEncryptionTypesHex)</b><div class='sub'>$supportedEncryptionDisplay</div></td>"+
    "<td>$advertizedEtypesDisplay</td>"+
    "<td class='requester-map'>$requesterEtypes</td>"+
    "<td>$ticketEncryptionDisplay</td>"+
    "<td>$sessionEncryptionDisplay</td>"+
    "<td class='num'>$($r.RC4TgsTargetCount)</td>"+
    "<td class='num'>$($r.RC4AsCount)</td>"+
    "<td>$requestingPrincipalsDisplay</td>"+
    "<td class='nowrap-value'>$(Convert-HtmlSafe $r.LastSeen)</td>"+
    "<td class='finding'>$(Convert-HtmlSafe $r.EvidenceFinding)</td>"+
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
 --info:#2878c8;--healthy:#169b62;--disabled:#667085
}
*{box-sizing:border-box}
body{margin:0;font-family:"Segoe UI",Arial,sans-serif;background:var(--bg);color:var(--text);font-size:13px}
.wrap{width:100%;max-width:none;margin:0;padding:24px}
.hero{background:linear-gradient(110deg,#103b60,#2378b8);color:#fff;border-radius:18px;padding:26px 30px;display:flex;justify-content:space-between;gap:30px;box-shadow:0 1px 2px rgba(16,24,40,.08)}
.hero h1{margin:0 0 8px;font-size:28px;font-weight:700}.hero p{margin:3px 0;color:#e7f1fa;max-width:980px;line-height:1.45}
.meta{text-align:right;min-width:250px;font-size:12px;line-height:1.5;color:#e7f1fa}.meta b{color:#fff}
.cards{display:grid;grid-template-columns:repeat(8,minmax(135px,1fr));gap:14px;margin:18px 0}
.card{background:#fff;border:1px solid var(--border);border-radius:14px;padding:16px 18px;border-left:5px solid #3b82f6;box-shadow:0 1px 2px rgba(16,24,40,.04)}
.card .l{color:var(--muted);font-size:12px}.card .n{font-size:28px;font-weight:700;margin-top:6px}.c-action{border-left-color:#f59e0b}.c-rc4{border-left-color:#ef4444}.c-critical{border-left-color:var(--critical)}.c-high{border-left-color:var(--high)}.c-medium{border-left-color:var(--medium)}.c-disabled{border-left-color:var(--disabled)}.c-good{border-left-color:var(--healthy)}
.note{background:#fff;border:1px solid var(--border);border-left:5px solid var(--blue2);padding:14px 16px;margin:0 0 16px;border-radius:10px;line-height:1.45}
.controls{background:#fff;border:1px solid var(--border);border-radius:14px;padding:13px 16px;display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin-bottom:16px}
input{min-width:360px;flex:1;border:1px solid #c9d3df;border-radius:8px;padding:9px 11px;background:#fff}
button{border:1px solid #c9d3df;background:#fff;border-radius:8px;padding:8px 12px;cursor:pointer;color:#344054}button:hover{background:#f4f7fa}
button.active-filter{background:#e8f1fa;border-color:#1e73b7;color:#0f4c78;font-weight:700}
.table-scroll-shell{width:100%}
.table-scroll-top{width:100%;overflow-x:auto;overflow-y:hidden;height:18px;margin-bottom:6px}
.table-scroll-top-inner{height:1px}
.tablewrap{width:100%;overflow-x:auto;overflow-y:visible;background:#fff;border:1px solid var(--border);border-radius:14px;box-shadow:0 1px 2px rgba(16,24,40,.04)}
table{border-collapse:collapse;width:100%;table-layout:auto;font-size:12px}th{position:sticky;top:0;z-index:2;background:#f7f9fc;text-align:left;padding:11px;border-bottom:1px solid var(--border);white-space:nowrap;color:#344054}
td{vertical-align:top;padding:10px 11px;border-bottom:1px solid #edf0f4;line-height:1.4}.sub{color:var(--muted);font-size:10.5px;margin-top:3px}.num{text-align:center;font-weight:700}
.account-cell,.account-cell b,.account-cell .sub{white-space:nowrap!important;word-break:normal!important;overflow-wrap:normal!important}
.record-line{white-space:nowrap!important;word-break:normal!important;overflow-wrap:normal!important;display:block;margin:0 0 3px 0}
.record-line:last-child{margin-bottom:0}
.crypto-line{display:block;margin:0 0 4px 0;white-space:nowrap}
.crypto-line:last-child{margin-bottom:0}
.crypto-tag{display:inline-block;padding:3px 8px;border-radius:999px;border:1px solid #c9d3df;background:#f8fafc;color:#344054;font-weight:600;white-space:nowrap}
.crypto-aes{background:#e7f8ef;border-color:#6fd3a4;color:#067647}
.crypto-rc4{background:#fff0e6;border-color:#fb923c;color:#b54708}
.crypto-des{background:#fee4e2;border-color:#f97066;color:#b42318}
.requester-block{margin:0 0 8px 0}
.requester-block:last-child{margin-bottom:0}
.requester-name{font-weight:700;white-space:nowrap;margin-bottom:4px}
.nowrap-value{white-space:nowrap!important;word-break:normal!important;overflow-wrap:normal!important}
.spn{white-space:normal;overflow-wrap:normal;word-break:normal;line-height:1.35;min-width:220px;max-width:none}
.requester-map{white-space:normal;overflow-wrap:normal;word-break:normal;line-height:1.35;min-width:220px;max-width:none}
.finding{white-space:normal;overflow-wrap:anywhere;min-width:190px}
.recommendation{white-space:normal;overflow-wrap:anywhere;min-width:240px}
.badge,.status-badge{display:inline-block;padding:4px 10px;border-radius:999px;font-weight:700;font-size:11px;border:1px solid}
.status-badge{white-space:nowrap!important;word-break:normal!important;overflow-wrap:normal!important;min-width:90px;text-align:center}
.sev-high{background:#fff0e6;border-color:#fb923c;color:#b54708}.sev-medium{background:#fff7d6;border-color:#f5c242;color:#7a4d00}.sev-informational{background:#eaf3ff;border-color:#84b9f4;color:#175cd3}.sev-healthy{background:#e7f8ef;border-color:#6fd3a4;color:#067647}
.status-enabled{background:#e7f8ef;border-color:#6fd3a4;color:#067647}.status-disabled{background:#f2f4f7;border-color:#98a2b3;color:#475467}
.section{margin-top:24px}.section h2{font-size:18px;margin:0 0 10px}.smalltable{min-width:0}.kdc-table{min-width:0}
footer{color:var(--muted);font-size:11px;margin-top:18px;line-height:1.5}
#main th{white-space:normal;overflow-wrap:normal;word-break:normal;hyphens:none}
#main td{white-space:normal;overflow-wrap:anywhere;word-break:normal}

/* Keep compact status labels intact */
.badge,.action{white-space:nowrap !important;word-break:normal !important;overflow-wrap:normal !important}
#main th,#main td{min-width:105px}
#main th:nth-child(1),#main td:nth-child(1){min-width:82px}
#main th:nth-child(2),#main td:nth-child(2){min-width:100px;text-align:center}
#main th:nth-child(3),#main td:nth-child(3){min-width:190px;white-space:nowrap}
#main th:nth-child(4),#main td:nth-child(4){min-width:135px}
#main th:nth-child(6),#main td:nth-child(6){min-width:260px;max-width:none}
#main th:nth-last-child(2),#main td:nth-last-child(2){min-width:260px}
#main th:nth-last-child(1),#main td:nth-last-child(1){min-width:300px}
@media (min-width:2200px){.wrap{padding:24px 32px}table{font-size:12.5px}th,td{padding:10px 12px}.spn{max-width:360px}.requester-map{max-width:420px}}
@media (max-width:1920px){.wrap{padding:18px}table{font-size:11px}th,td{padding:7px 8px}.cards{gap:10px}.hero{padding:22px 24px}.hero h1{font-size:25px}.spn{min-width:135px;max-width:240px}.requester-map{min-width:150px;max-width:260px}.finding{min-width:170px}.recommendation{min-width:220px}}
@media (max-width:1400px){table{font-size:10px}th,td{padding:6px}.cards{grid-template-columns:repeat(4,minmax(135px,1fr))}.requester-map{max-width:220px}.spn{max-width:210px}.recommendation{min-width:200px}.finding{min-width:155px}}
@media (max-width:1100px){.cards{grid-template-columns:repeat(2,1fr)}.hero{flex-direction:column}.meta{text-align:left}.wrap{padding:14px}.tablewrap{overflow-x:auto}#main{min-width:2050px}}
</style>
</head>
<body>
<div class="wrap">
<div class="hero">
 <div>
  <h1>Kerberos RC4 Assessment</h1>
  <p>Consolidated Kerberos encryption assessment based on Microsoft event telemetry collected across all selected Domain Controllers.</p>
  <p><b>Domain:</b> $(Convert-HtmlSafe $domain.DNSRoot) &nbsp; | &nbsp; <b>Forest:</b> $(Convert-HtmlSafe $forest.Name) &nbsp; | &nbsp; <b>Window:</b> $(Convert-HtmlSafe $since) to $(Convert-HtmlSafe $generatedAt)</p>
 </div>
 <div class="meta">
  <b>Generated</b><br>$(Convert-HtmlSafe $generatedAt)<br><br>
  <b>Run as</b><br>$(Convert-HtmlSafe $runAs)<br><br>
  <b>Scope</b><br>$(Convert-HtmlSafe $SearchScope)
 </div>
</div>

<div class="cards">
 <div class="card"><div class="l">Enabled accounts evaluated</div><div class="n">$($activeResults.Count)</div></div>
 <div class="card c-action"><div class="l">Enabled accounts requiring action</div><div class="n">$($action.Count)</div></div>
 <div class="card c-rc4"><div class="l">Enabled accounts with RC4 observed</div><div class="n">$actualRC4</div></div>
 <div class="card c-high"><div class="l">High</div><div class="n">$high</div></div>
 <div class="card c-medium"><div class="l">Medium</div><div class="n">$medium</div></div>
 <div class="card c-good"><div class="l">Healthy</div><div class="n">$healthy</div></div>
 <div class="card"><div class="l">Informational</div><div class="n">$info</div></div>
 <div class="card c-disabled"><div class="l">Disabled accounts collected</div><div class="n">$($disabledResults.Count)</div></div>
</div>

<div class="note">
<b>Assessment model:</b> Collection and account attribution follow the same Kerberos event semantics used by Microsoft's <b>Get-KerbEncryptionUsage.ps1</b> and <b>List-AccountKeys.ps1</b>. Events <b>4768/4769</b> are collected from every selected Domain Controller and consolidated into one row per AD principal. Legacy DCs contribute the fields available in their event schema; enhanced DCs also contribute Available Keys, session encryption, and client-advertised encryption types. Active Directory adds <b>msDS-SupportedEncryptionTypes</b> and <b>Service Principal Names</b>. Disabled accounts are collected but hidden by default; use the status filters to display them. The built-in <b>krbtgt</b> account is excluded from all outputs. Severity is an operational prioritization model, not an official Microsoft severity rating.
</div>

<div class="controls">
 <input id="q" type="search" placeholder="Search account, SPN, requester, encryption, evidence or recommendation...">
 <span class="sub"><b>Status:</b></span>
 <button data-filter-group="status" data-filter-value="Enabled" onclick="setStatusFilter('Enabled')">Enabled</button>
 <button data-filter-group="status" data-filter-value="Disabled" onclick="setStatusFilter('Disabled')">Disabled</button>
 <button data-filter-group="status" data-filter-value="ALL" onclick="setStatusFilter('ALL')">All</button>
 <span class="sub"><b>Severity:</b></span>
 <button data-filter-group="severity" data-filter-value="ALL" onclick="setSeverityFilter('ALL')">All severities</button>
 <button data-filter-group="severity" data-filter-value="High" onclick="setSeverityFilter('High')">High</button>
 <button data-filter-group="severity" data-filter-value="Medium" onclick="setSeverityFilter('Medium')">Medium</button>
 <button data-filter-group="severity" data-filter-value="Healthy" onclick="setSeverityFilter('Healthy')">Healthy</button>
 <button data-filter-group="severity" data-filter-value="Informational" onclick="setSeverityFilter('Informational')">Informational</button>
 <button data-filter-group="severity" data-filter-value="RC4" onclick="setSeverityFilter('RC4')">RC4 observed</button>
</div>

<div class="table-scroll-shell">
<div id="mainScrollTop" class="table-scroll-top"><div id="mainScrollTopInner" class="table-scroll-top-inner"></div></div>
<div id="mainScrollBottom" class="tablewrap"><table id="main">
<thead><tr>
<th>Severity</th><th>Status</th><th>Account</th><th>Type</th><th>RC4 Seen</th>
<th>Service Principal Names</th><th>Available Keys</th><th>msDS-SupportedEncryptionTypes</th>
<th>Advertised Etypes</th><th>Requester &rarr; Advertised Etypes</th>
<th>Observed Ticket Encryption</th><th>Observed Session Encryption</th>
<th>RC4 TGS</th><th>RC4 AS</th><th>Requesting Principals</th><th>Last Seen</th>
<th>Evidence / Finding</th><th>Recommendation</th>
</tr></thead><tbody>
$($rows -join "`n")
</tbody></table></div>
</div>

<div class="section">
<h2>Classification legend</h2>
<div class="note"><b>Important:</b> The underlying telemetry comes from Microsoft Kerberos Security Events and Active Directory attributes. The severity labels below are this tool's simplified operational prioritization model.</div>
<div class="tablewrap"><table class="smalltable">
<thead><tr><th>Priority</th><th>Rule</th><th>Operational meaning</th></tr></thead>
<tbody>
<tr><td><span class='badge sev-high'>High</span></td><td><b>RC4 observed in Event 4768 or 4769.</b></td><td>An active RC4 dependency was observed and requires investigation.</td></tr>
<tr><td><span class='badge sev-medium'>Medium</span></td><td><b>msDS-SupportedEncryptionTypes allows RC4, but no RC4 activity was observed.</b></td><td>Review whether RC4 can be removed after compatibility testing.</td></tr>
<tr><td><span class='badge sev-healthy'>Healthy</span></td><td><b>AES capability or usage was observed and no RC4 activity was found.</b></td><td>No current RC4 remediation is identified from the selected window.</td></tr>
<tr><td><span class='badge sev-informational'>Informational</span></td><td><b>No RC4 observed, but available evidence is insufficient for another classification.</b></td><td>Continue monitoring or gather enhanced telemetry.</td></tr>
</tbody></table></div>
</div>

<div class="section">
<h2>KDCSVC 201-209 &mdash; enforcement readiness</h2>
<div class="note">Microsoft's CVE-2026-20833 deployment guidance recommends monitoring KDCSVC Events 201-209 in the <b>System</b> log. These events are shown as supplementary evidence because they describe audit/enforcement compatibility conditions and are not a substitute for 4768/4769 usage attribution.</div>
<div class="tablewrap"><table class="kdc-table">
<thead><tr><th>Event ID</th><th>Level</th><th>Domain Controller</th><th>Time</th><th>Event summary</th></tr></thead>
<tbody>$kdcRows</tbody></table></div>
</div>

<div class="section"><h2>Collection health</h2>
<p>Compatibility is detected from event fields, allowing mixed forests with legacy and enhanced KDC schemas. Security events read: <b>$totalEvents</b> &nbsp; | &nbsp; Modern-schema: <b>$modernEvents</b> &nbsp; | &nbsp; Legacy-schema: <b>$legacyEvents</b> &nbsp; | &nbsp; KDCSVC 201-209: <b>$($kdcEvents.Count)</b></p>
<div class="tablewrap"><table class="smalltable"><thead><tr><th>Domain Controller</th><th>Error</th></tr></thead><tbody>$errorRows</tbody></table></div>
</div>

<footer>
Evidence correlation is based on Microsoft Kerberos Security Event telemetry and the Microsoft Kerberos-Crypto Get-KerbEncryptionUsage.ps1 / List-AccountKeys.ps1 approach. Severity labels are this tool's simplified operational prioritization model, not official Microsoft severity ratings. Recommendations are generated from the observed Kerberos evidence, Active Directory configuration, AES-key evidence, and account type; validate every change against application-specific compatibility and organizational change-control requirements. KDCSVC 201-209 are supplementary evidence for CVE-2026-20833 readiness.
</footer>
</div>
<script>
let currentStatusFilter='Enabled';
let currentSeverityFilter='ALL';
let q=null;

window.addEventListener('DOMContentLoaded',()=>{
 q=document.getElementById('q');
 if(q){
  q.addEventListener('input',apply);
 }
 apply();
 initializeHorizontalScrollbars();
 updateFilterButtons();
});

// Initializes synchronized horizontal scrollbars.
function initializeHorizontalScrollbars(){
 const top=document.getElementById('mainScrollTop');
 const topInner=document.getElementById('mainScrollTopInner');
 const bottom=document.getElementById('mainScrollBottom');
 const table=document.getElementById('main');

 if(!top||!topInner||!bottom||!table){return;}

 const updateWidth=()=>{
  topInner.style.width=table.scrollWidth+'px';
 };

 let syncing=false;

 top.addEventListener('scroll',()=>{
  if(syncing){return;}
  syncing=true;
  bottom.scrollLeft=top.scrollLeft;
  syncing=false;
 });

 bottom.addEventListener('scroll',()=>{
  if(syncing){return;}
  syncing=true;
  top.scrollLeft=bottom.scrollLeft;
  syncing=false;
 });

 updateWidth();
 window.addEventListener('resize',updateWidth);
}

// Applies the selected account-status filter.
function setStatusFilter(value){
 currentStatusFilter=value;
 apply();
 updateFilterButtons();
}

// Applies the selected severity filter.
function setSeverityFilter(value){
 currentSeverityFilter=value;
 apply();
 updateFilterButtons();
}

// Highlights the currently selected status and severity filters.
function updateFilterButtons(){
 document.querySelectorAll('button[data-filter-group]').forEach(button=>{
  const group=button.dataset.filterGroup;
  const value=button.dataset.filterValue;
  const active=
   (group==='status'&&value===currentStatusFilter)||
   (group==='severity'&&value===currentSeverityFilter);
  button.classList.toggle('active-filter',active);
 });
}

// Applies search, status, and severity filters to the result table.
function apply(){
 const term=q ? q.value.toLowerCase() : '';

 document.querySelectorAll('#main tbody tr').forEach(r=>{
  let ok=r.innerText.toLowerCase().includes(term);

  if(currentStatusFilter!=='ALL'){
   ok=ok&&r.dataset.status===currentStatusFilter;
  }

  if(currentSeverityFilter==='RC4'){
   ok=ok&&r.dataset.rc4==='True';
  }
  else if(currentSeverityFilter!=='ALL'){
   ok=ok&&r.dataset.severity===currentSeverityFilter;
  }

  r.style.display=ok?'':'none';
 });
}
</script>
</body></html>
"@

$html | Set-Content $htmlPath -Encoding UTF8

Write-Host ""
Write-Host "=== Kerberos RC4 Assessment v5.2.1 Final ===" -ForegroundColor White
Write-Host "Security events read         : $totalEvents"
Write-Host "Modern-schema events         : $modernEvents"
Write-Host "Legacy-schema events         : $legacyEvents"
Write-Host "KDCSVC 201-209 events        : $($kdcEvents.Count)"
Write-Host "Accounts in report           : $($results.Count)"
Write-Host "Enabled accounts needing action : $($action.Count)"
Write-Host "Enabled accounts with RC4       : $actualRC4"
Write-Host "Disabled accounts                : $($disabledResults.Count)"
Write-Host "Disabled with recent RC4         : $($disabledRecentRC4.Count)"
Write-Host "High                         : $high"
Write-Host "Medium                       : $medium"
Write-Host "Healthy / Informational      : $($healthy+$info)"
Write-Host "Collection errors            : $($errors.Count)"
Write-Host ""
Write-Host "HTML   : $htmlPath" -ForegroundColor Green
Write-Host "CSV    : $csvPath" -ForegroundColor Green
Write-Host "KDCSVC : $kdcCsvPath" -ForegroundColor Green
