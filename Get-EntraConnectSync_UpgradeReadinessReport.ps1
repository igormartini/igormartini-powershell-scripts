<#
.SYNOPSIS
    Microsoft Entra Connect Sync Upgrade Readiness Health Check

.DESCRIPTION
    Generates a focused executive HTML report for Microsoft Entra Connect Sync upgrade readiness.

.NOTES
	Author  : Igor Henrique Martini
    Website : https://igormartini.cloud
    Version: 6.1
    Run as Administrator on the Microsoft Entra Connect Sync server.
    Read-only by default. Does not change synchronization settings.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop\EntraConnect_Upgrade_Readiness_Report.html",
    [version]$MinimumRequiredVersion = [version]"2.5.79.0",
    [int]$RecentEventHours = 168,
    [int]$MaxEvents = 15
)

$ErrorActionPreference = "SilentlyContinue"

function ConvertTo-SafeHtml {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    return [System.Web.HttpUtility]::HtmlEncode([string]$Value)
}

function New-Section {
    param([string]$Title, [string]$Content)
@"
<section class="card">
  <h2>$Title</h2>
  $Content
</section>
"@
}

function ConvertTo-HtmlTable {
    param([array]$Data, [string[]]$Columns)
    if (-not $Data -or $Data.Count -eq 0) { return "<p class='muted'>No data found.</p>" }
    $html = "<table><thead><tr>"
    foreach ($col in $Columns) { $html += "<th>$(ConvertTo-SafeHtml $col)</th>" }
    $html += "</tr></thead><tbody>"
    foreach ($row in $Data) {
        $html += "<tr>"
        foreach ($col in $Columns) {
            $value = $row.$col
            $class = ""
            if ($col -match "Status|Compliant|Result|State|Connectivity|Enabled|Value") {
                if ($value -match "PASS|Compliant|Running|Enabled|Healthy|OK|Detected|Success|True|Yes") { $class = " class='ok'" }
                elseif ($value -match "WARN|Attention|Not configured|Review|Unknown|Disabled|Not Found|No|None|Not detected") { $class = " class='warntext'" }
                elseif ($value -match "FAIL|Not compliant|Stopped|Error|Critical|Missing|Failed|False") { $class = " class='failtext'" }
            }
            $html += "<td$class>$(ConvertTo-SafeHtml $value)</td>"
        }
        $html += "</tr>"
    }
    $html += "</tbody></table>"
    return $html
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function Try-ImportADSyncModule {
    $candidatePaths = @(
        "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync\ADSync.psd1",
        "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync.psd1"
    )
    foreach ($p in $candidatePaths) {
        if (Test-Path $p) {
            try { Import-Module $p -ErrorAction Stop; return $true } catch {}
        }
    }
    try { Import-Module ADSync -ErrorAction Stop; return $true } catch { return $false }
}

function Get-EntraConnectVersion {
    $exe = "C:\Program Files\Microsoft Azure AD Sync\Bin\miiserver.exe"
    if (Test-Path $exe) {
        $v = (Get-Item $exe).VersionInfo.ProductVersion
        if ($v) { return $v }
    }
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($path in $uninstallPaths) {
        $app = Get-ItemProperty $path | Where-Object { $_.DisplayName -match "Microsoft Entra Connect Sync|Azure AD Connect|Microsoft Azure AD Sync" } | Select-Object -First 1
        if ($app.DisplayVersion) { return $app.DisplayVersion }
    }
    return "Not detected"
}

function Get-DotNetInfo {
    $release = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name Release
    if (-not $release) {
        return [pscustomobject]@{ Component = ".NET Framework"; Version = "Not detected"; Release = ""; Required = "4.7.2 or later"; Status = "FAIL - Missing" }
    }
    $version = switch ($release) {
        { $_ -ge 533320 } { "4.8.1 or later"; break }
        { $_ -ge 528040 } { "4.8"; break }
        { $_ -ge 461808 } { "4.7.2"; break }
        { $_ -ge 461308 } { "4.7.1"; break }
        { $_ -ge 460798 } { "4.7"; break }
        default { "Older than 4.7" }
    }
    [pscustomobject]@{ Component = ".NET Framework"; Version = $version; Release = $release; Required = "4.7.2 or later"; Status = if ($release -ge 461808) { "PASS - Compliant" } else { "FAIL - Not compliant" } }
}

function Get-ADSyncToolsTls12RegValue {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$true, Position=0)][string]$RegPath, [Parameter(Mandatory=$true, Position=1)][string]$RegName)
    $regItem = Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction Ignore
    $output = "" | Select-Object Path, Name, Value
    $output.Path = $RegPath
    $output.Name = $RegName
    if ($null -eq $regItem) { $output.Value = "Not Found" } else { $output.Value = $regItem.$RegName }
    return $output
}

function Get-Tls12Info {
    $regSettings = @()
    $regKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
    $regSettings += Get-ADSyncToolsTls12RegValue $regKey 'SystemDefaultTlsVersions'
    $regSettings += Get-ADSyncToolsTls12RegValue $regKey 'SchUseStrongCrypto'
    $regKey = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
    $regSettings += Get-ADSyncToolsTls12RegValue $regKey 'SystemDefaultTlsVersions'
    $regSettings += Get-ADSyncToolsTls12RegValue $regKey 'SchUseStrongCrypto'
    $regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
    $regSettings += Get-ADSyncToolsTls12RegValue $regKey 'Enabled'
    $regSettings += Get-ADSyncToolsTls12RegValue $regKey 'DisabledByDefault'
    $regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
    $regSettings += Get-ADSyncToolsTls12RegValue $regKey 'Enabled'
    $regSettings += Get-ADSyncToolsTls12RegValue $regKey 'DisabledByDefault'
    $regSettings | ForEach-Object {
        $expected = switch -Regex ($_.Name) {
            "SystemDefaultTlsVersions" { "1"; break }
            "SchUseStrongCrypto" { "1"; break }
            "Enabled" { "1"; break }
            "DisabledByDefault" { "0"; break }
            default { "" }
        }
        $status = if ($_.Value -eq "Not Found") { "WARN - Not Found" } elseif ([string]$_.Value -eq $expected) { "PASS - Expected value" } else { "WARN - Review value" }
        [pscustomobject]@{ Path = $_.Path; Name = $_.Name; Value = $_.Value; ExpectedValue = $expected; Status = $status }
    }
}

function Get-TlsOverallStatus {
    param([array]$TlsRows)
    if (-not $TlsRows) { return "Unknown" }
    if ($TlsRows | Where-Object { $_.Status -match "FAIL" }) { return "Fail" }
    if ($TlsRows | Where-Object { $_.Status -match "WARN" }) { return "Review" }
    return "OK"
}

function New-SqlConnection {
    param([string]$DataSource, [string]$Database = "master")
    Add-Type -AssemblyName System.Data
    $connectionString = "Data Source=$DataSource;Initial Catalog=$Database;Integrated Security=True;Connection Timeout=5;TrustServerCertificate=True"
    return New-Object System.Data.SqlClient.SqlConnection $connectionString
}
function Invoke-SqlScalar {
    param([string]$DataSource, [string]$Database = "master", [string]$Query)
    try { $connection = New-SqlConnection -DataSource $DataSource -Database $Database; $command = $connection.CreateCommand(); $command.CommandText = $Query; $connection.Open(); $result = $command.ExecuteScalar(); $connection.Close(); return $result } catch { return $null }
}
function Test-SqlConnection {
    param([string]$DataSource, [string]$Database = "master")
    try { $connection = New-SqlConnection -DataSource $DataSource -Database $Database; $connection.Open(); $connection.Close(); return $true } catch { return $false }
}

function Get-ADSyncDatabaseConfiguration {
    $candidateDataSources = New-Object System.Collections.Generic.List[string]
    $registryRoots = @("HKLM:\SOFTWARE\Microsoft\Azure AD Connect", "HKLM:\SOFTWARE\Microsoft\ADSync", "HKLM:\SOFTWARE\Microsoft\Microsoft Azure AD Sync", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Azure AD Connect", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\ADSync", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft Azure AD Sync")
    foreach ($root in $registryRoots) {
        if (Test-Path $root) {
            $keys = @()
            try { $keys += Get-Item -Path $root } catch {}
            try { $keys += Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue } catch {}
            foreach ($key in $keys) {
                try {
                    $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
                    foreach ($prop in $props.PSObject.Properties) {
                        $text = [string]$prop.Value
                        if ($prop.Name -match "SQL|Database|DB|Instance|Server|DataSource|Data Source|ConnectionString|Connection|Catalog" -and $text) {
                            foreach ($m in [regex]::Matches($text, "(Data Source|Server)\s*=\s*([^;]+)", "IgnoreCase")) { $ds = $m.Groups[2].Value.Trim(); if (-not $candidateDataSources.Contains($ds)) { [void]$candidateDataSources.Add($ds) } }
                            if ($prop.Name -match "Server|SqlServer|DataSource" -and $text -notmatch ";") { if (-not $candidateDataSources.Contains($text)) { [void]$candidateDataSources.Add($text) } }
                        }
                    }
                } catch {}
            }
        }
    }
    $configFiles = @("C:\Program Files\Microsoft Azure AD Sync\Bin\miiserver.exe.config", "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync.exe.config", "C:\Program Files\Microsoft Azure AD Sync\UIShell\miisclient.exe.config", "C:\ProgramData\AADConnect\ADSyncConfig.json")
    foreach ($file in $configFiles) {
        if (Test-Path $file) {
            try { $content = Get-Content -Path $file -Raw -ErrorAction SilentlyContinue; foreach ($m in [regex]::Matches($content, "(Data Source|Server)\s*=\s*([^;`"]+)", "IgnoreCase")) { $ds = $m.Groups[2].Value.Trim(); if (-not $candidateDataSources.Contains($ds)) { [void]$candidateDataSources.Add($ds) } } } catch {}
        }
    }
    $sqlServices = Get-CimInstance Win32_Service | Where-Object { $_.Name -match "MSSQL|SQLAgent|SQLBrowser|MSSQLFDLauncher" -or $_.DisplayName -match "SQL Server" } | Select-Object Name, DisplayName, State, StartName, PathName
    foreach ($svc in $sqlServices) {
        if ($svc.Name -match "^MSSQL\$(.+)$") { $instance = $Matches[1]; foreach ($ds in @("$env:COMPUTERNAME\$instance", ".\$instance")) { if (-not $candidateDataSources.Contains($ds)) { [void]$candidateDataSources.Add($ds) } } }
        elseif ($svc.Name -eq "MSSQLSERVER") { foreach ($ds in @($env:COMPUTERNAME, ".")) { if (-not $candidateDataSources.Contains($ds)) { [void]$candidateDataSources.Add($ds) } } }
    }
    $sqlLocalDbExe = (Get-Command "SqlLocalDB.exe" -ErrorAction SilentlyContinue).Source
    if (-not $sqlLocalDbExe) {
        $possible = @("$env:ProgramFiles\Microsoft SQL Server\160\Tools\Binn\SqlLocalDB.exe", "$env:ProgramFiles\Microsoft SQL Server\150\Tools\Binn\SqlLocalDB.exe", "$env:ProgramFiles\Microsoft SQL Server\140\Tools\Binn\SqlLocalDB.exe", "$env:ProgramFiles\Microsoft SQL Server\130\Tools\Binn\SqlLocalDB.exe", "${env:ProgramFiles(x86)}\Microsoft SQL Server\160\Tools\Binn\SqlLocalDB.exe", "${env:ProgramFiles(x86)}\Microsoft SQL Server\150\Tools\Binn\SqlLocalDB.exe", "${env:ProgramFiles(x86)}\Microsoft SQL Server\140\Tools\Binn\SqlLocalDB.exe", "${env:ProgramFiles(x86)}\Microsoft SQL Server\130\Tools\Binn\SqlLocalDB.exe")
        $sqlLocalDbExe = $possible | Where-Object { Test-Path $_ } | Select-Object -First 1
    }
    if ($sqlLocalDbExe) { try { $localDbInstances = & $sqlLocalDbExe info 2>$null; foreach ($inst in $localDbInstances) { $ds = "(localdb)\$inst"; if (-not $candidateDataSources.Contains($ds)) { [void]$candidateDataSources.Add($ds) } } } catch {} }
    foreach ($c in @("(localdb)\ADSync", ".\ADSYNC", "$env:COMPUTERNAME\ADSYNC")) { if (-not $candidateDataSources.Contains($c)) { [void]$candidateDataSources.Add($c) } }
    $adSyncService = Get-CimInstance Win32_Service | Where-Object { $_.Name -eq "ADSync" } | Select-Object Name, DisplayName, State, StartName, PathName
    $detected = $null
    foreach ($ds in $candidateDataSources) {
        $canConnectMaster = Test-SqlConnection -DataSource $ds -Database "master"
        $canConnectADSync = Test-SqlConnection -DataSource $ds -Database "ADSync"
        $sqlVersion = $null
        if ($canConnectMaster) { $sqlVersion = Invoke-SqlScalar -DataSource $ds -Database "master" -Query "SELECT @@VERSION" }
        $dbExists = $false
        if ($canConnectMaster) { $dbName = Invoke-SqlScalar -DataSource $ds -Database "master" -Query "SELECT name FROM sys.databases WHERE name = 'ADSync'"; if ($dbName -eq "ADSync") { $dbExists = $true } } elseif ($canConnectADSync) { $dbExists = $true }
        $type = if ($ds -match "localdb") { "SQL LocalDB local instance" } elseif ($ds -match "\\ADSYNC|\.\\") { "SQL Server Express local instance" } elseif ($ds -match "\\") { "SQL Server named instance" } elseif ($ds -eq "." -or $ds -eq $env:COMPUTERNAME) { "SQL Server local default instance" } else { "SQL Server remote/custom instance" }
        if (-not $detected -and ($canConnectADSync -or $dbExists)) { $detected = [pscustomobject]@{ DatabaseType = $type; Server = $ds; Instance = if ($ds -match "localdb\)\\(.+)$") { $Matches[1] } elseif ($ds -match "\\(.+)$") { $Matches[1] } else { "Default" }; DatabaseName = "ADSync"; SqlVersion = if ($sqlVersion) { ($sqlVersion -replace "`r|`n"," ") } else { "Unknown" }; Connectivity = "Success"; ADSyncServiceAccount = if ($adSyncService) { $adSyncService.StartName } else { "Unknown" } } }
    }
    if (-not $detected) { $detected = [pscustomobject]@{ DatabaseType = "Unknown / not confirmed"; Server = "Unknown"; Instance = "Unknown"; DatabaseName = "ADSync (expected default, not confirmed)"; SqlVersion = "Unknown"; Connectivity = "Failed or insufficient permissions"; ADSyncServiceAccount = if ($adSyncService) { $adSyncService.StartName } else { "Unknown" } } }
    return $detected
}

function Get-DiskInfo {
    Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, @{n="SizeGB";e={[math]::Round($_.Size/1GB,2)}}, @{n="FreeGB";e={[math]::Round($_.FreeSpace/1GB,2)}}, @{n="FreePct";e={[math]::Round(($_.FreeSpace/$_.Size)*100,2)}}, @{n="Status";e={ if (($_.FreeSpace/$_.Size)*100 -ge 20) { "PASS" } elseif (($_.FreeSpace/$_.Size)*100 -ge 10) { "WARN" } else { "FAIL" } }}
}

function Get-ADSyncServiceAccounts {
    $targetNames = @("ADSync", "ADSyncUpdater", "AzureADConnectHealthSyncMonitor", "AzureADConnectHealthSyncInsights", "MSSQL`$ADSYNC", "SQLAgent`$ADSYNC")
    Get-CimInstance Win32_Service | Where-Object { $targetNames -contains $_.Name -or $_.DisplayName -match "Microsoft Azure AD Sync|Azure AD Connect|Microsoft Entra|ADSync|SQL Server.*ADSYNC" } | Select-Object @{n="Component";e={$_.DisplayName}}, @{n="ServiceName";e={$_.Name}}, @{n="ServiceAccount";e={$_.StartName}}, @{n="State";e={$_.State}}
}



function Get-ADSyncConnectorConfigurationRaw {
    try {
        $raw = Get-ADSyncConnector |
            Select-Object Name, Type, ConnectivityParameters |
            Format-List |
            Out-String -Width 50000

        if (-not $raw -or -not $raw.Trim()) {
            return ""
        }

        $outputBlocks = @()

        $blocks = [regex]::Split($raw, "(?m)(?=^\s*Name\s+:)") |
            Where-Object { $_ -match "^\s*Name\s*:" }

        foreach ($block in $blocks) {
            $name = ""
            $type = ""
            $params = ""

            $nameMatch = [regex]::Match($block, "(?m)^\s*Name\s*:\s*(.+?)\s*$")
            if ($nameMatch.Success) { $name = $nameMatch.Groups[1].Value.Trim() }

            $typeMatch = [regex]::Match($block, "(?m)^\s*Type\s*:\s*(.+?)\s*$")
            if ($typeMatch.Success) { $type = $typeMatch.Groups[1].Value.Trim() }

            $paramMatch = [regex]::Match($block, "(?ms)^\s*ConnectivityParameters\s*:\s*(?<params>.*)$")
            if ($paramMatch.Success) {
                $params = ($paramMatch.Groups["params"].Value -replace "`r"," " -replace "`n"," " -replace "\s+"," ").Trim()
            }

            $userName = ""
            $applicationManagedBy = ""
            $certificateManagedBy = ""
            $forestLoginUser = ""
            $forestLoginDomain = ""

            function Get-ParamValueFromText {
                param(
                    [string]$Text,
                    [string]$Key
                )

                if (-not $Text) { return "" }

                $escapedKey = [regex]::Escape($Key)
                $match = [regex]::Match(
                    $Text,
                    "(?i)$escapedKey\s*:\s*(?<value>.*?)(?=,\s*[\w-]+\s*:|\.\.\.|\}|$)"
                )

                if ($match.Success) {
                    return ($match.Groups["value"].Value.Trim() -replace "\s*\}\s*$","").Trim()
                }

                return ""
            }

            if ($type -match "Extensible2|AAD") {
                $userName = Get-ParamValueFromText -Text $params -Key "UserName"
                $applicationManagedBy = Get-ParamValueFromText -Text $params -Key "ApplicationManagedBy"
                $certificateManagedBy = Get-ParamValueFromText -Text $params -Key "CertificateManagedBy"

                $lines = @()
                $lines += "Name                   : $name"
                $lines += "Type                   : $type"
                $lines += "ConnectivityParameters :"
                if ($userName) { $lines += "  UserName             : $userName" }
                if ($applicationManagedBy) { $lines += "  ApplicationManagedBy : $applicationManagedBy" }
                if ($certificateManagedBy) { $lines += "  CertificateManagedBy : $certificateManagedBy" }

                $outputBlocks += ($lines -join "`r`n")
            }
            elseif ($type -match "^AD$|AD") {
                $forestLoginUser = Get-ParamValueFromText -Text $params -Key "forest-login-user"
                $forestLoginDomain = Get-ParamValueFromText -Text $params -Key "forest-login-domain"

                $lines = @()
                $lines += "Name                   : $name"
                $lines += "Type                   : $type"
                $lines += "ConnectivityParameters :"
                if ($forestLoginUser) { $lines += "  forest-login-user    : $forestLoginUser" }
                if ($forestLoginDomain) { $lines += "  forest-login-domain  : $forestLoginDomain" }

                $outputBlocks += ($lines -join "`r`n")
            }
        }

        return ($outputBlocks -join "`r`n`r`n").Trim()
    }
    catch {
        return ""
    }
}


function Get-ADSyncRecentEvents {
    param([int]$Hours,[int]$Max)
    $start = (Get-Date).AddHours(-1 * $Hours)
    Get-WinEvent -FilterHashtable @{ LogName="Application"; StartTime=$start; Level=1,2,3 } | Where-Object { $_.ProviderName -match "ADSync|Directory Synchronization|Azure AD Connect|Microsoft Entra" -or $_.Message -match "ADSync|Azure AD Connect|Entra Connect|Directory Synchronization" } | Sort-Object TimeCreated -Descending | Select-Object -First $Max TimeCreated, ProviderName, Id, LevelDisplayName, @{n="Message";e={($_.Message -replace "`r|`n"," ") }}
}

function Search-ObjectForFeatureValue {
    param(
        [object]$Object,
        [string[]]$Patterns,
        [int]$Depth = 0
    )

    if (-not $Object -or $Depth -gt 6) { return $null }
    if ($Object -is [string]) { return $null }

    if ($Object -is [System.Collections.IEnumerable] -and -not ($Object -is [string])) {
        foreach ($item in $Object) {
            $found = Search-ObjectForFeatureValue -Object $item -Patterns $Patterns -Depth ($Depth + 1)
            if ($null -ne $found) { return $found }
        }
        return $null
    }

    try {
        foreach ($prop in $Object.PSObject.Properties) {
            if ($prop.Name -match "Password|Secret|Credential|Key" -and $prop.Name -notmatch "PasswordWriteback|PasswordHash|PasswordSync|PasswordReset") {
                continue
            }

            foreach ($pattern in $Patterns) {
                if ($prop.Name -match $pattern) {
                    if ($null -ne $prop.Value -and [string]$prop.Value -ne "") {
                        return $prop.Value
                    }
                }
            }

            if ($prop.Value -and $prop.Value -isnot [string]) {
                $found = Search-ObjectForFeatureValue -Object $prop.Value -Patterns $Patterns -Depth ($Depth + 1)
                if ($null -ne $found) { return $found }
            }
        }
    } catch {}

    return $null
}

function Convert-DetectedFeatureValue {
    param([object]$Value)

    if ($null -eq $Value) { return $null }

    $text = [string]$Value
    if ($text -match "True|Enabled|Enable|1") { return "Enabled" }
    if ($text -match "False|Disabled|Disable|0") { return "Disabled" }
    return $text
}

function Get-AuthenticationAndSyncFeatures {
    param(
        [object]$Scheduler,
        [array]$Services
    )

    $rows = @()

    $companyFeature = $null
    $globalSettings = $null

    try {
        if (Get-Command Get-ADSyncAADCompanyFeature -ErrorAction SilentlyContinue) {
            $companyFeature = Get-ADSyncAADCompanyFeature
        }
    } catch {}

    try {
        if (Get-Command Get-ADSyncGlobalSettings -ErrorAction SilentlyContinue) {
            $globalSettings = Get-ADSyncGlobalSettings
        }
    } catch {}

    $allFeatureSources = @($companyFeature, $globalSettings) | Where-Object { $_ }

    function Get-FeatureFromSources {
        param([string[]]$Patterns)
        foreach ($source in $allFeatureSources) {
            $value = Search-ObjectForFeatureValue -Object $source -Patterns $Patterns
            if ($null -ne $value) { return Convert-DetectedFeatureValue $value }
        }
        return $null
    }

    $phs = Get-FeatureFromSources -Patterns @("PasswordHash.*Sync|Password.*Hash|HashSync|PasswordSync")
    if ($phs) {
        $rows += [pscustomobject]@{ Feature="Password Hash Synchronization"; Value=$phs; Source="ADSync company feature/global settings" }
    }

    $pwdWriteback = Get-FeatureFromSources -Patterns @("PasswordWriteback|Password.*Writeback|PasswordReset.*Writeback|OnPremises.*Password.*Reset|Writeback.*Password")
    if ($pwdWriteback) {
        $rows += [pscustomobject]@{ Feature="Password Writeback"; Value=$pwdWriteback; Source="ADSync company feature/global settings" }
    }

    $groupWriteback = Get-FeatureFromSources -Patterns @("GroupWriteback|Group.*Writeback|UnifiedGroupWriteback")
    if ($groupWriteback) {
        $rows += [pscustomobject]@{ Feature="Group Writeback"; Value=$groupWriteback; Source="ADSync company feature/global settings" }
    }

    $deviceWriteback = Get-FeatureFromSources -Patterns @("DeviceWriteback|Device.*Writeback")
    if ($deviceWriteback) {
        $rows += [pscustomobject]@{ Feature="Device Writeback"; Value=$deviceWriteback; Source="ADSync company feature/global settings" }
    }

    $seamlessSso = Get-FeatureFromSources -Patterns @("Seamless|DesktopSso|Desktop.*Sso|SSO")
    if ($seamlessSso) {
        $rows += [pscustomobject]@{ Feature="Seamless SSO"; Value=$seamlessSso; Source="ADSync company feature/global settings" }
    }

    $ptaService = Get-CimInstance Win32_Service | Where-Object {
        $_.Name -match "AzureADConnectAuthenticationAgent|PassThrough|PTA" -or
        $_.DisplayName -match "Authentication Agent|Pass-through Authentication|Pass Through Authentication"
    } | Select-Object -First 1

    if ($ptaService) {
        $rows += [pscustomobject]@{ Feature="Pass-through Authentication"; Value="Detected"; Source="Local Authentication Agent service" }
    }

    $adfsService = Get-CimInstance Win32_Service | Where-Object {
        $_.Name -match "adfssrv" -or $_.DisplayName -match "Active Directory Federation Services"
    } | Select-Object -First 1

    if ($adfsService) {
        $rows += [pscustomobject]@{ Feature="Federation / AD FS"; Value="Detected locally"; Source="Local AD FS service" }
    }

    $stagingProp = $null
    if ($Scheduler) {
        $stagingProp = $Scheduler.PSObject.Properties | Where-Object { $_.Name -match "Staging" } | Select-Object -First 1
    }

    if ($stagingProp -and $null -ne $stagingProp.Value -and [string]$stagingProp.Value -ne "") {
        $rows += [pscustomobject]@{ Feature="Staging Mode"; Value=(Convert-DetectedFeatureValue $stagingProp.Value); Source="Get-ADSyncScheduler" }
    }

    if ($phs -eq "Enabled") {
        $rows = @([pscustomobject]@{ Feature="Authentication Method"; Value="Password Hash Synchronization"; Source="Derived from detected features" }) + $rows
    }
    elseif ($ptaService) {
        $rows = @([pscustomobject]@{ Feature="Authentication Method"; Value="Pass-through Authentication detected"; Source="Derived from local service detection" }) + $rows
    }
    elseif ($adfsService) {
        $rows = @([pscustomobject]@{ Feature="Authentication Method"; Value="Federation / AD FS detected locally"; Source="Derived from local service detection" }) + $rows
    }

    return $rows
}

function Get-CustomADSyncRules {
    param([array]$Rules)

    $custom = @()

    foreach ($r in $Rules) {
        $isCustom = $false
        $reason = ""

        $precedence = $null
        try { $precedence = [int]$r.Precedence } catch {}

        $hasImmutableTagProp = ($r.PSObject.Properties.Name -contains "ImmutableTag")
        $immutableTag = if ($hasImmutableTagProp) { [string]$r.ImmutableTag } else { "" }

        $hasIsDefaultProp = ($r.PSObject.Properties.Name -contains "IsDefault")
        $isDefault = if ($hasIsDefaultProp) { [string]$r.IsDefault } else { "" }

        if ($hasIsDefaultProp -and $isDefault -match "False") {
            $isCustom = $true
            $reason = "IsDefault = False"
        }
        elseif ($hasImmutableTagProp -and [string]::IsNullOrWhiteSpace($immutableTag)) {
            $isCustom = $true
            $reason = "Empty ImmutableTag"
        }
        elseif ($hasImmutableTagProp -and $immutableTag -notmatch "^Microsoft\.") {
            $isCustom = $true
            $reason = "Non-Microsoft ImmutableTag"
        }
        elseif ($precedence -ne $null -and $precedence -le 99) {
            $isCustom = $true
            $reason = "Precedence <= 99"
        }

        if ($isCustom) {
            $custom += [pscustomobject]@{
                Precedence = $r.Precedence
                Name = $r.Name
                Direction = $r.Direction
                Connector = $r.Connector
                Enabled = $r.Enabled
                SourceObjectType = $r.SourceObjectType
                TargetObjectType = $r.TargetObjectType
                ImmutableTag = $immutableTag
                DetectionReason = $reason
            }
        }
    }

    return $custom | Sort-Object Precedence
}

$adSyncModuleLoaded = Try-ImportADSyncModule
$os = Get-CimInstance Win32_OperatingSystem
$installedVersion = Get-EntraConnectVersion
$versionCompliant = $false
try { $versionCompliant = ([version]$installedVersion -ge $MinimumRequiredVersion) } catch {}
$dotNet = Get-DotNetInfo
$tls = Get-Tls12Info
$tlsOverall = Get-TlsOverallStatus -TlsRows $tls
$disk = Get-DiskInfo
$serviceAccounts = Get-ADSyncServiceAccounts
$db = Get-ADSyncDatabaseConfiguration
$scheduler = $null
if ($adSyncModuleLoaded) { try { $scheduler = Get-ADSyncScheduler } catch {} }
$schedulerRows = @()
if ($scheduler) { foreach ($p in $scheduler.PSObject.Properties) { $schedulerRows += [pscustomobject]@{ Setting = $p.Name; Value = if ($null -eq $p.Value) { "" } else { $p.Value } } } }
$connectors = @(); $connectorRows = @()
if ($adSyncModuleLoaded) { try { $connectors = Get-ADSyncConnector } catch {}; foreach ($c in $connectors) { $connectorRows += [pscustomobject]@{ Name = $c.Name; Type = $c.Type; Version = $c.Version; Identifier = $c.Identifier } } }
$connectorConfigurationRaw = Get-ADSyncConnectorConfigurationRaw

$features = Get-AuthenticationAndSyncFeatures -Scheduler $scheduler -Services $serviceAccounts
$rules = @()
if ($adSyncModuleLoaded) { try { $rules = Get-ADSyncRule } catch {} }
$customRules = @(Get-CustomADSyncRules -Rules $rules)
$events = Get-ADSyncRecentEvents -Hours $RecentEventHours -Max $MaxEvents

# Executive score
$score = 100
if (-not $versionCompliant) { $score -= 35 }
if ($dotNet.Status -notmatch "PASS") { $score -= 10 }
if ($tlsOverall -eq "Fail") { $score -= 15 } elseif ($tlsOverall -eq "Review") { $score -= 5 }
if (($serviceAccounts | Where-Object { $_.ServiceName -eq "ADSync" -and $_.State -ne "Running" }).Count -gt 0) { $score -= 20 }
if (($events | Where-Object { $_.LevelDisplayName -match "Critical|Error" }).Count -gt 0) { $score -= 15 }
if (($disk | Where-Object { $_.Status -eq "FAIL" }).Count -gt 0) { $score -= 10 }
if (-not $adSyncModuleLoaded) { $score -= 10 }
if ($score -lt 0) { $score = 0 }
$readiness = if ($score -ge 90) { "READY" } elseif ($score -ge 70) { "READY WITH ATTENTION" } else { "NOT READY" }
$readinessClass = if ($score -ge 90) { "pass" } elseif ($score -ge 70) { "warn" } else { "fail" }
$authMethod = ($features | Where-Object { $_.Feature -eq "Authentication Method" } | Select-Object -First 1).Value
$phsValue = ($features | Where-Object { $_.Feature -eq "Password Hash Synchronization" } | Select-Object -First 1).Value
$ptaValue = ($features | Where-Object { $_.Feature -eq "Pass-through Authentication" } | Select-Object -First 1).Value
$pwdWritebackValue = ($features | Where-Object { $_.Feature -eq "Password Writeback" } | Select-Object -First 1).Value
$stagingModeValue = ($features | Where-Object { $_.Feature -eq "Staging Mode" } | Select-Object -First 1).Value
if (-not $authMethod) { $authMethod = "Not detected" }
$executiveSummary = @(
    [pscustomobject]@{ Item="Upgrade Readiness"; Value="$score% - $readiness" },
    [pscustomobject]@{ Item="Server"; Value=$env:COMPUTERNAME },
    [pscustomobject]@{ Item="Operating System"; Value="$($os.Caption) $($os.Version)" },
    [pscustomobject]@{ Item="Installed Entra Connect Sync Version"; Value=$installedVersion },
    [pscustomobject]@{ Item="Minimum Required Version"; Value="$MinimumRequiredVersion or later" },
    [pscustomobject]@{ Item="Version Compliance"; Value= if ($versionCompliant) { "PASS - Compliant" } else { "FAIL - Upgrade required" } },
    [pscustomobject]@{ Item=".NET Framework"; Value="$($dotNet.Version) / $($dotNet.Status)" },
    [pscustomobject]@{ Item="TLS 1.2"; Value=$tlsOverall },
    [pscustomobject]@{ Item="Database Type"; Value=$db.DatabaseType },
    [pscustomobject]@{ Item="Database Connectivity"; Value=$db.Connectivity },
    [pscustomobject]@{ Item="Authentication Method"; Value=$authMethod },
    [pscustomobject]@{ Item="Password Hash Sync"; Value=$phsValue },
    [pscustomobject]@{ Item="Pass-through Authentication"; Value=$ptaValue },
    [pscustomobject]@{ Item="Password Writeback"; Value=$pwdWritebackValue },
    [pscustomobject]@{ Item="Staging Mode"; Value=$stagingModeValue },
    [pscustomobject]@{ Item="Connectors Detected"; Value=$connectorRows.Count },
    [pscustomobject]@{ Item="Connector Configuration Output"; Value= if ($connectorConfigurationRaw) { "Captured" } else { "No data" } },
    [pscustomobject]@{ Item="Custom Sync Rules Detected"; Value=@($customRules).Count },
    [pscustomobject]@{ Item="Recent Warning/Error Events"; Value=$events.Count }
) | Where-Object { $_.Item -eq "Custom Sync Rules Detected" -or ($null -ne $_.Value -and [string]$_.Value -ne "") }

$style = @"
<style>
body { margin:0; font-family: Segoe UI, Arial, sans-serif; background:#f5f7fb; color:#102033; }
header { background:linear-gradient(135deg,#061a33,#0b3d75); color:#fff; padding:28px 40px; }
header h1 { margin:0; font-size:28px; }
header p { margin:8px 0 0 0; color:#cfe8ff; }
.container { padding:24px 40px; }
.hero { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:16px; }
.metric { background:#fff; border-radius:14px; padding:16px; box-shadow:0 2px 9px rgba(0,0,0,.08); border-left:6px solid #0b65c2; }
.label { font-size:12px; color:#667085; text-transform:uppercase; letter-spacing:.04em; }
.value { font-size:22px; font-weight:700; margin-top:6px; }
.card { background:#fff; border-radius:14px; padding:20px; margin:16px 0; box-shadow:0 2px 9px rgba(0,0,0,.08); }
h2 { margin:0 0 14px 0; color:#072b55; padding-bottom:8px; border-bottom:2px solid #e5edf7; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th { background:#082f5f; color:#fff; text-align:left; padding:8px; }
td { border-bottom:1px solid #e5edf7; padding:8px; vertical-align:top; }
tr:nth-child(even) td { background:#f9fbfe; }
.badge { display:inline-block; padding:4px 10px; border-radius:999px; font-size:12px; font-weight:700; color:#fff; }
.pass { background:#238636; }
.warn { background:#bf8700; }
.fail { background:#d1242f; }
.ok { color:#238636; font-weight:600; }
.warntext { color:#9a6700; font-weight:600; }
.failtext { color:#d1242f; font-weight:600; }
.muted { color:#667085; }
.important { border-left:6px solid #d1242f; background:#fff4f4; padding:14px; border-radius:10px; margin-bottom:16px; }
.note { border-left:6px solid #0969da; background:#f0f7ff; padding:14px; border-radius:10px; margin-bottom:16px; }
pre { background:#0B1F3A; color:#F8FAFC; padding:14px; border-radius:8px; border:1px solid #D0D5DD; overflow:auto; white-space:pre-wrap; word-break:break-word; font-family:Consolas, Monaco, monospace; font-size:13px; line-height:1.45; } footer { padding:18px 40px; color:#667085; font-size:12px; }
</style>
"@
$dashboard = @"
<div class="hero">
  <div class="metric"><div class="label">Readiness</div><div class="value"><span class="badge $readinessClass">$score%</span> $readiness</div></div>
  <div class="metric"><div class="label">Installed Version</div><div class="value">$(ConvertTo-SafeHtml $installedVersion)</div></div>
  <div class="metric"><div class="label">Minimum Required</div><div class="value">$MinimumRequiredVersion+</div></div>
  <div class="metric"><div class="label">Authentication</div><div class="value">$(ConvertTo-SafeHtml $authMethod)</div></div>
</div>
<div class="important">
<strong>Important:</strong> Microsoft requires Microsoft Entra Connect Sync version <strong>$MinimumRequiredVersion or later</strong> before <strong>September 30, 2026</strong> to continue synchronizing identities.
</div>
"@
$customRulesContent = if ($customRules -and $customRules.Count -gt 0) {
@"
<p class="note"><strong>Detection criteria:</strong> Custom synchronization rules are identified only when ImmutableTag is null or empty.</p>
$(ConvertTo-HtmlTable -Data $customRules -Columns @("Precedence","Name","Direction","Connector","Enabled","SourceObjectType","TargetObjectType","ImmutableTag"))
"@
} else { "<p class='ok'>No customer-created synchronization rules were detected. Only Microsoft default rules appear to be configured.</p>" }
$sections = ""
$sections += New-Section "Executive Summary" (ConvertTo-HtmlTable -Data $executiveSummary -Columns @("Item","Value"))
$sections += New-Section "Compatibility" (ConvertTo-HtmlTable -Data @(
    [pscustomobject]@{ Component="Entra Connect Sync Version"; Current=$installedVersion; Required="$MinimumRequiredVersion or later"; Status= if ($versionCompliant) { "PASS - Compliant" } else { "FAIL - Upgrade required" } },
    [pscustomobject]@{ Component="Windows Server"; Current="$($os.Caption) $($os.Version)"; Required="Supported OS for installed Entra Connect version"; Status="INFO - Validate with Microsoft support matrix" },
    [pscustomobject]@{ Component="ADSync PowerShell Module"; Current= if ($adSyncModuleLoaded) { "Loaded" } else { "Not loaded" }; Required="Available on Entra Connect server"; Status= if ($adSyncModuleLoaded) { "PASS" } else { "WARN" } }
) -Columns @("Component","Current","Required","Status"))
$sections += New-Section "Authentication & Synchronization Features" (@"
<p class="muted">Only features detected locally with confidence are shown in this section.</p>
$(ConvertTo-HtmlTable -Data $features -Columns @("Feature","Value","Source"))
"@)
$sections += New-Section "TLS Version" (@"
<p class="muted">TLS validation uses the same registry paths and values from the Microsoft ADSyncTools TLS 1.2 check.</p>
$(ConvertTo-HtmlTable -Data $tls -Columns @("Path","Name","Value","ExpectedValue","Status"))
"@)
$sections += New-Section ".NET Framework Version" (ConvertTo-HtmlTable -Data @($dotNet) -Columns @("Component","Version","Release","Required","Status"))
$sections += New-Section "Disk Space" (ConvertTo-HtmlTable -Data $disk -Columns @("DeviceID","SizeGB","FreeGB","FreePct","Status"))
$sections += New-Section "Synchronization Scheduler" (ConvertTo-HtmlTable -Data $schedulerRows -Columns @("Setting","Value"))
$sections += New-Section "Service Accounts" (@"
<p class="muted">Windows service accounts configured for Entra Connect Sync, Health agents, and local SQL components.</p>
$(ConvertTo-HtmlTable -Data $serviceAccounts -Columns @("Component","ServiceName","ServiceAccount","State"))
"@)
$sections += New-Section "Database Configuration" (@"
<p class="muted">Shows the confirmed ADSync database connection when the current user has permission to connect using Windows authentication.</p>
$(ConvertTo-HtmlTable -Data @($db) -Columns @("DatabaseType","Server","Instance","DatabaseName","SqlVersion","Connectivity","ADSyncServiceAccount"))
"@)
$sections += New-Section "Connectors" (ConvertTo-HtmlTable -Data $connectorRows -Columns @("Name","Type","Version","Identifier"))


if ($connectorConfigurationRaw) {
    $connectorConfigurationHtml = [System.Web.HttpUtility]::HtmlEncode($connectorConfigurationRaw)

    $sections += New-Section "Connector Configuration" @"
<p class="muted">
The following information is collected directly from the Microsoft Entra Connect Sync connector configuration.
Sensitive fields such as passwords, secrets, keys, credentials, and tokens are automatically masked.
</p>

<pre>$connectorConfigurationHtml</pre>
"@
}


$customRulesContent = ""
if ($customRules -and $customRules.Count -gt 0) {
    $customRulesContent = @"
<p class="note"><strong>Detection criteria:</strong> Custom synchronization rules are identified only when ImmutableTag is null or empty.</p>
$(ConvertTo-HtmlTable -Data $customRules -Columns @("Precedence","Name","Direction","Connector","Enabled","SourceObjectType","TargetObjectType","ImmutableTag"))
"@
    $sections += New-Section "Custom Synchronization Rules" $customRulesContent
}
$sections += New-Section "Recent ADSync Warnings and Errors" (@"
<p class="muted">Showing the latest $MaxEvents Warning, Error, or Critical events related to ADSync from the last $RecentEventHours hours.</p>
$(ConvertTo-HtmlTable -Data $events -Columns @("TimeCreated","ProviderName","Id","LevelDisplayName","Message"))
"@)
$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Microsoft Entra Connect Sync Upgrade Readiness Report</title>
$style
</head>
<body>
<header>
  <h1>Microsoft Entra Connect Sync Upgrade Readiness Report</h1>
  <p>Generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") by $env:USERNAME on $env:COMPUTERNAME</p>
</header>
<div class="container">
$dashboard
$sections
</div>
<footer>
Read-only assessment report. Validate all results before making production changes.
</footer>
</body>
</html>
"@
$html | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "Report generated: $OutputPath" -ForegroundColor Green
