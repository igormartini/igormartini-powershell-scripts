<#
.SYNOPSIS
	Exports a lifecycle-focused Microsoft Entra application report.

.DESCRIPTION
	Collects App Registrations and Enterprise Applications, then correlates owners, assignments,
	credentials, API permissions, and recent sign-in activity into a CSV and HTML report.

	The report is designed for application lifecycle reviews, workload identity governance,
	and cleanup/remediation planning.

.NOTES
	Author  : Igor Henrique Martini
    Website : https://igormartini.cloud
	Sign-in data is limited by Microsoft Entra sign-in log retention.
	The script uses delegated Microsoft Graph authentication.
	Default sign-in lookback is 30 days. Increasing the value only helps if the tenant
		retains sign-in logs for longer than 30 days or exports them elsewhere.

#>

# Required Microsoft Graph PowerShell modules. Missing modules are installed for the current user.
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Applications"
)

function Import-RequiredGraphModules {
    param(
        [Parameter(Mandatory=$true)][string[]]$ModuleNames
    )

    foreach ($module in $ModuleNames) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Host "Installing $module..." -ForegroundColor Yellow
            Install-Module $module -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
        }

        Import-Module $module -ErrorAction Stop
    }
}

# Runtime settings.
$SignInLookbackDays = 30
$BatchSize = 20
$BatchDelaySeconds = 1

# Output folder
$ReportOutputFolder = Join-Path -Path (Get-Location) -ChildPath "EntraAppAuditOutput"

# Timestamped file names
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$CsvFileName  = "entra_application_lifecycle_assessment_$ts.csv"
$HtmlFileName = "entra_application_lifecycle_assessment_$ts.html"
$LogFileName  = "entra_apps_audit_$ts.log"

# Logging helper.
function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR")][string]$Level = "INFO",
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )
    $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = ("[{0}] [{1}] {2}" -f $now, $Level, $Message)
    Write-Host $line -ForegroundColor $Color
    if ($script:LogPath) {
        Add-Content -Path $script:LogPath -Value $line -Encoding UTF8
    }
}

# Helper functions.
function Set-Tls12 { try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { } }
function New-OutputFolder([string]$Path) { if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path | Out-Null } }
function HtmlEncode([string]$s) { if ($null -eq $s) { return "" }; return [System.Web.HttpUtility]::HtmlEncode($s) }
function Join-StringSafe([object]$val, [string]$sep=", ", [string]$default="") {
    if ($null -eq $val) { return $default }
    if ($val -is [System.Array]) { if ($val.Count -eq 0) { return $default }; return ($val -join $sep) }
    return [string]$val
}
function Join-OrDefault { param($Value,[string]$Separator=", ",[string]$Default=""); return (Join-StringSafe $Value $Separator $Default) }
function To-DateTimeOrNull([object]$value) { if ($null -eq $value) { return $null }; try { return [DateTime]::Parse($value.ToString()) } catch { return $null } }
function Parse-GraphBatch { param($BatchResponse); $map=@{}; if ($null -eq $BatchResponse.responses) { return $map }; foreach ($r in $BatchResponse.responses) { $map[$r.id]=$r }; return $map }


# Formats application and service principal credentials.
function Format-CredList {
    param(
        [System.Array] $Creds,
        [string] $Type,
        [datetime] $Today
    )
    if ($null -eq $Creds -or $Creds.Count -eq 0) { return "" }

    $items = @()
    foreach ($c in $Creds) {
        $name = $c.displayName
        if (-not $name) { $name = $Type }

        $kid = $c.keyId
        $end = $c.endDateTime
        $endDt = To-DateTimeOrNull $end
        $expired = ($endDt -and $endDt.Date -lt $Today.Date)

        $endText = ""
        if ($endDt) { $endText = $endDt.ToString("yyyy-MM-dd HH:mm:ss") }
        elseif ($end) { $endText = [string]$end }

        $label = "{0} | End: {1} | KeyId: {2}" -f $name, $endText, $kid
        if ($expired) { $label = "[EXPIRED] " + $label }
        $items += $label
    }

    return ($items -join [Environment]::NewLine)
}

# Initialize output and logging.
Set-Tls12
New-OutputFolder -Path $ReportOutputFolder
$script:LogPath = Join-Path $ReportOutputFolder $LogFileName
Write-Log -Message ("Log file: {0}" -f $script:LogPath) -Color Cyan

# Load Microsoft Graph modules.
Write-Log -Message "Loading Microsoft Graph PowerShell modules..." -Color Cyan
Import-RequiredGraphModules -ModuleNames $RequiredModules
Write-Log -Message "Microsoft Graph modules successfully loaded." -Color Green

# Connect to Microsoft Graph.
Write-Log -Message "Connecting to Microsoft Graph (Interactive)..." -Color Cyan

$GraphScopes = @(
  "Application.Read.All",
  "Directory.Read.All",
  "AuditLog.Read.All"
)

try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }

try {
    Connect-MgGraph -Audience "organizations" -Scopes $GraphScopes -ContextScope Process -NoWelcome -ErrorAction Stop | Out-Null
}
catch {
    Write-Log -Message ("Interactive auth failed: {0}" -f $_.Exception.Message) -Level "ERROR" -Color Red
    throw
}

$ctx = Get-MgContext
Write-Log -Message ("Connected to Microsoft Graph as {0}" -f $ctx.Account) -Color Green

# Collect App Registrations.
Write-Log -Message "Collecting App Registrations (/applications)..." -Color Cyan
$AppRegistrations = Get-MgApplication -All -Property `
    "id,appId,displayName,createdDateTime,requiredResourceAccess,passwordCredentials,keyCredentials" `
    -ConsistencyLevel eventual
Write-Log -Message ("App Registrations collected: {0}" -f $AppRegistrations.Count) -Color Green

# Collect Enterprise Applications / Service Principals.
Write-Log -Message "Collecting Enterprise Applications (/servicePrincipals)..." -Color Cyan
$EnterpriseApps = Get-MgServicePrincipal -All -Property `
    "id,appId,displayName,createdDateTime,appOwnerOrganizationId,servicePrincipalType,keyCredentials,passwordCredentials" `
    -ConsistencyLevel eventual
Write-Log -Message ("Enterprise Applications collected: {0}" -f $EnterpriseApps.Count) -Color Green

# Index service principals.
$spById=@{}
foreach ($sp in $EnterpriseApps) { if ($sp.Id -and -not $spById.ContainsKey($sp.Id)) { $spById[$sp.Id]=$sp } }

# Map AppId to ServicePrincipalId.
$ServicePrincipalIdByAppId = @{}
foreach ($sp in $EnterpriseApps) {
    if ($sp.appId -and -not $ServicePrincipalIdByAppId.ContainsKey($sp.appId)) { $ServicePrincipalIdByAppId[$sp.appId] = $sp.id }
}

# Resolve API permission names.
Write-Log -Message "Resolving API permission names..." -Color Cyan
$ResourceServicePrincipalCache = @{}
function Get-ResourceSp([string]$resourceAppId) {
    if ([string]::IsNullOrWhiteSpace($resourceAppId)) { return $null }
    if ($ResourceServicePrincipalCache.ContainsKey($resourceAppId)) { return $ResourceServicePrincipalCache[$resourceAppId] }
    try {
        $sp = Get-MgServicePrincipal -Filter "appId eq '$resourceAppId'" -Property "id,appId,displayName,appRoles,oauth2PermissionScopes" -ConsistencyLevel eventual
        $resolved = $null
        if ($sp -is [System.Array]) { if ($sp.Count -gt 0) { $resolved = $sp[0] } } else { $resolved = $sp }
        $ResourceServicePrincipalCache[$resourceAppId] = $resolved
        return $resolved
    } catch { $ResourceServicePrincipalCache[$resourceAppId] = $null; return $null }
}
function Resolve-RequiredResourceAccess($requiredResourceAccess) {
    if ($null -eq $requiredResourceAccess) { return "" }
    $lines = @()

    foreach ($rra in $requiredResourceAccess) {
        $resourceAppId = $rra.resourceAppId
        $resourceSp = Get-ResourceSp -resourceAppId $resourceAppId
        $resourceName = if ($resourceSp -and $resourceSp.displayName) { $resourceSp.displayName } else { $resourceAppId }

        foreach ($ra in $rra.resourceAccess) {
            $id = $ra.id
            $type = $ra.type   # Role => Application, Scope => Delegated
            $permissionType = if ($type -eq "Role") { "Application" } else { "Delegated" }
            $permissionName = [string]$id

            if ($resourceSp) {
                if ($type -eq "Role") {
                    foreach ($role in $resourceSp.appRoles) {
                        if ($role.id -eq $id) { $permissionName = [string]$role.value; break }
                    }
                } else {
                    foreach ($scope in $resourceSp.oauth2PermissionScopes) {
                        if ($scope.id -eq $id) { $permissionName = [string]$scope.value; break }
                    }
                }
            }

            $lines += ("{0} | {1} | {2}" -f $resourceName, $permissionType, $permissionName)
        }
    }

    if ($lines.Count -eq 0) { return "" }
    return ($lines | Sort-Object -Unique) -join [Environment]::NewLine
}
# Collect application and service principal owners.
Write-Log -Message "Collecting owners..." -Color Cyan
$AppOwnersByAppObjectId = @{}
$EnterpriseAppOwnersByServicePrincipalId = @{}

$appOwnerReqs=@(); $rid=1
foreach ($app in $AppRegistrations) { $appOwnerReqs += @{ id="$rid"; method="GET"; url="/applications/$($app.Id)/owners?`$select=id,displayName,userPrincipalName" }; $rid++ }
for ($i=0; $i -lt $appOwnerReqs.Count; $i += $BatchSize) {
    $chunk = $appOwnerReqs[$i..([Math]::Min($i+$BatchSize-1, $appOwnerReqs.Count-1))]
    $body=@{requests=$chunk}
    try {
        $resp = Invoke-MgGraphRequest -Method POST -Uri "/v1.0/`$batch" -Body ($body | ConvertTo-Json -Depth 10)
        $map = Parse-GraphBatch $resp
        foreach ($req in $chunk) {
            $r = $map[$req.id]
            $m=[regex]::Match($req.url, "/applications/([^/]+)/owners")
            $appObjId = if ($m.Success) { $m.Groups[1].Value } else { $null }
            if (-not $appObjId) { continue }
            if ($r.status -eq 200 -and $r.body.value) {
                $owners=@()
                foreach ($o in $r.body.value) { if ($o.userPrincipalName) { $owners += $o.userPrincipalName } elseif ($o.displayName) { $owners += $o.displayName } }
                $AppOwnersByAppObjectId[$appObjId]=($owners -join "; ")
            } else { $AppOwnersByAppObjectId[$appObjId]="" }
        }
    } catch { foreach ($req in $chunk) { $m=[regex]::Match($req.url, "/applications/([^/]+)/owners"); $appObjId = if ($m.Success) { $m.Groups[1].Value } else { $null }; if ($appObjId) { $AppOwnersByAppObjectId[$appObjId]="" } } }
    Start-Sleep -Seconds $BatchDelaySeconds
}

$spOwnerReqs=@(); $rid=1
foreach ($sp in $EnterpriseApps) { $spOwnerReqs += @{ id="$rid"; method="GET"; url="/servicePrincipals/$($sp.Id)/owners?`$select=id,displayName,userPrincipalName" }; $rid++ }
for ($i=0; $i -lt $spOwnerReqs.Count; $i += $BatchSize) {
    $chunk = $spOwnerReqs[$i..([Math]::Min($i+$BatchSize-1, $spOwnerReqs.Count-1))]
    $body=@{requests=$chunk}
    try {
        $resp = Invoke-MgGraphRequest -Method POST -Uri "/v1.0/`$batch" -Body ($body | ConvertTo-Json -Depth 10)
        $map = Parse-GraphBatch $resp
        foreach ($req in $chunk) {
            $r = $map[$req.id]
            $m=[regex]::Match($req.url, "/servicePrincipals/([^/]+)/owners")
            $spid = if ($m.Success) { $m.Groups[1].Value } else { $null }
            if (-not $spid) { continue }
            if ($r.status -eq 200 -and $r.body.value) {
                $owners=@()
                foreach ($o in $r.body.value) { if ($o.userPrincipalName) { $owners += $o.userPrincipalName } elseif ($o.displayName) { $owners += $o.displayName } }
                $EnterpriseAppOwnersByServicePrincipalId[$spid]=($owners -join "; ")
            } else { $EnterpriseAppOwnersByServicePrincipalId[$spid]="" }
        }
    } catch { foreach ($req in $chunk) { $m=[regex]::Match($req.url, "/servicePrincipals/([^/]+)/owners"); $spid = if ($m.Success) { $m.Groups[1].Value } else { $null }; if ($spid) { $EnterpriseAppOwnersByServicePrincipalId[$spid]="" } } }
    Start-Sleep -Seconds $BatchDelaySeconds
}
Write-Log -Message "Owners collected." -Color Green

# Collect assigned users and groups.
Write-Log -Message "Collecting assigned users/groups..." -Color Cyan
$AssignedPrincipalsByServicePrincipalId=@{}
$assignReqs=@(); $rid=1
foreach ($sp in $EnterpriseApps) { $assignReqs += @{ id="$rid"; method="GET"; url="/servicePrincipals/$($sp.Id)/appRoleAssignedTo?`$select=principalDisplayName,principalType" }; $rid++ }
for ($i=0; $i -lt $assignReqs.Count; $i += $BatchSize) {
    $chunk = $assignReqs[$i..([Math]::Min($i+$BatchSize-1, $assignReqs.Count-1))]
    $body=@{requests=$chunk}
    try {
        $resp=Invoke-MgGraphRequest -Method POST -Uri "/v1.0/`$batch" -Body ($body | ConvertTo-Json -Depth 10)
        $map=Parse-GraphBatch $resp
        foreach ($req in $chunk) {
            $r=$map[$req.id]
            $m=[regex]::Match($req.url, "/servicePrincipals/([^/]+)/appRoleAssignedTo")
            $spid = if ($m.Success) { $m.Groups[1].Value } else { $null }
            if (-not $spid) { continue }
            if ($r.status -eq 200 -and $r.body.value) {
                $names=@()
                foreach ($a in $r.body.value) { if ($a.principalType -eq "User" -or $a.principalType -eq "Group") { if ($a.principalDisplayName) { $names += $a.principalDisplayName } } }
                $AssignedPrincipalsByServicePrincipalId[$spid]=($names -join "; ")
            } else { $AssignedPrincipalsByServicePrincipalId[$spid]="" }
        }
    } catch { foreach ($req in $chunk) { $m=[regex]::Match($req.url, "/servicePrincipals/([^/]+)/appRoleAssignedTo"); $spid = if ($m.Success) { $m.Groups[1].Value } else { $null }; if ($spid) { $AssignedPrincipalsByServicePrincipalId[$spid]="" } } }
    Start-Sleep -Seconds $BatchDelaySeconds
}
Write-Log -Message "Assignments collected." -Color Green

# Prepare service principals for sign-in correlation.
$allSpIds = @($EnterpriseApps | Where-Object { $_.Id } | ForEach-Object { $_.Id } | Sort-Object -Unique)

# Collect latest sign-in activity from Microsoft Graph beta audit logs.
# The script scans sign-in event types first and maps the latest event locally by SPId, resource SPId, and AppId.
Write-Log -Message "Collecting latest sign-in activity..." -Color Cyan

$sinceUtc = (Get-Date).ToUniversalTime().AddDays(-1 * $SignInLookbackDays).ToString("o")

$SignInEventTypesToCollect = @(
    "servicePrincipal",
    "managedIdentity",
    "interactiveUser",
    "nonInteractiveUser"
)

$MaxSignInPagesPerEventType = 50

$LastSignInByServicePrincipalId = @{}
$LastSignInByAppId = @{}

function Get-SignInValue {
    param(
        [object]$SignIn,
        [string]$PropertyName
    )

    if ($null -eq $SignIn) { return $null }

    if ($SignIn -is [System.Collections.IDictionary]) {
        if ($SignIn.Contains($PropertyName)) { return $SignIn[$PropertyName] }
        return $null
    }

    if ($SignIn.PSObject.Properties.Name -contains $PropertyName) {
        return $SignIn.$PropertyName
    }

    return $null
}

function Get-SignInStatusText {
    param([object]$SignIn)

    $status = Get-SignInValue -SignIn $SignIn -PropertyName "status"
    if ($null -eq $status) { return "" }

    $errorCode = $null
    $failureReason = $null

    if ($status -is [System.Collections.IDictionary]) {
        if ($status.Contains("errorCode")) { $errorCode = $status["errorCode"] }
        if ($status.Contains("failureReason")) { $failureReason = $status["failureReason"] }
    } else {
        if ($status.PSObject.Properties.Name -contains "errorCode") { $errorCode = $status.errorCode }
        if ($status.PSObject.Properties.Name -contains "failureReason") { $failureReason = $status.failureReason }
    }

    if ($null -eq $errorCode) { return "" }
    if ([string]$errorCode -eq "0") { return "0 - Success" }
    if ($failureReason) { return ("{0} - {1}" -f $errorCode, $failureReason) }
    return [string]$errorCode
}

function Convert-SignInToReportObject {
    param([object]$SignIn)

    $eventTypes = Get-SignInValue -SignIn $SignIn -PropertyName "signInEventTypes"
    $eventTypesText = Join-OrDefault $eventTypes ", " ""

    $user = Get-SignInValue -SignIn $SignIn -PropertyName "userPrincipalName"
    if (-not $user) { $user = Get-SignInValue -SignIn $SignIn -PropertyName "userDisplayName" }

    [pscustomobject]@{
        createdDateTime = Get-SignInValue -SignIn $SignIn -PropertyName "createdDateTime"
        signInEventTypes = $eventTypes
        signInEventTypesText = $eventTypesText
        servicePrincipalId = Get-SignInValue -SignIn $SignIn -PropertyName "servicePrincipalId"
        servicePrincipalName = Get-SignInValue -SignIn $SignIn -PropertyName "servicePrincipalName"
        appId = Get-SignInValue -SignIn $SignIn -PropertyName "appId"
        appDisplayName = Get-SignInValue -SignIn $SignIn -PropertyName "appDisplayName"
        resourceServicePrincipalId = Get-SignInValue -SignIn $SignIn -PropertyName "resourceServicePrincipalId"
        resourceDisplayName = Get-SignInValue -SignIn $SignIn -PropertyName "resourceDisplayName"
        userPrincipalName = $user
        ipAddress = Get-SignInValue -SignIn $SignIn -PropertyName "ipAddress"
        status = Get-SignInValue -SignIn $SignIn -PropertyName "status"
        statusText = Get-SignInStatusText -SignIn $SignIn
        id = Get-SignInValue -SignIn $SignIn -PropertyName "id"
        correlationId = Get-SignInValue -SignIn $SignIn -PropertyName "correlationId"
    }
}

function Set-LatestSignIn {
    param(
        [hashtable]$Map,
        [string]$Key,
        [object]$SignInObject
    )

    if ([string]::IsNullOrWhiteSpace($Key) -or $null -eq $SignInObject) { return }

    $newDate = To-DateTimeOrNull $SignInObject.createdDateTime
    if ($null -eq $newDate) { return }

    if (-not $Map.ContainsKey($Key) -or $null -eq $Map[$Key]) {
        $Map[$Key] = $SignInObject
        return
    }

    $oldDate = To-DateTimeOrNull $Map[$Key].createdDateTime
    if ($null -eq $oldDate -or $newDate -gt $oldDate) {
        $Map[$Key] = $SignInObject
    }
}

function Invoke-GraphGetWithRetry {
    param(
        [Parameter(Mandatory=$true)][string]$Uri,
        [int]$MaxRetries = 5
    )

    $attempt = 0
    while ($true) {
        try {
            return Invoke-MgGraphRequest -Method GET -Uri $Uri -ErrorAction Stop
        }
        catch {
            $attempt++
            $message = $_.Exception.Message

            if ($attempt -gt $MaxRetries) {
                Write-Log -Message ("Graph request failed after {0} retries. Error: {1}" -f $MaxRetries, $message) -Level "WARN" -Color Yellow
                return $null
            }

            $sleepSeconds = [Math]::Min(60, [Math]::Pow(2, $attempt))
            Write-Log -Message ("Graph request retry {0}/{1} in {2}s." -f $attempt, $MaxRetries, $sleepSeconds) -Level "WARN" -Color Yellow
            Start-Sleep -Seconds $sleepSeconds
        }
    }
}

foreach ($eventType in $SignInEventTypesToCollect) {

    Write-Log -Message ("Scanning sign-in event type: {0}" -f $eventType) -Color Cyan

    $filter = "createdDateTime ge $sinceUtc and signInEventTypes/any(t:t eq '$eventType')"
    $encodedFilter = [uri]::EscapeDataString($filter)
    $uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$encodedFilter&`$orderby=createdDateTime desc&`$top=1000"

    $page = 0
    $recordsForType = 0

    while ($uri) {
        $page++
        if ($MaxSignInPagesPerEventType -gt 0 -and $page -gt $MaxSignInPagesPerEventType) {
            Write-Log -Message ("Page limit reached for sign-in event type {0}." -f $eventType) -Level "WARN" -Color Yellow
            break
        }

        $resp = Invoke-GraphGetWithRetry -Uri $uri
        if ($null -eq $resp) { break }

        $values = @()
        if ($resp.value) { $values = @($resp.value) }

        foreach ($s in $values) {
            $recordsForType++
            $signInObj = Convert-SignInToReportObject -SignIn $s

            # Main mappings.
            Set-LatestSignIn -Map $LastSignInByServicePrincipalId -Key $signInObj.servicePrincipalId -SignInObject $signInObj
            Set-LatestSignIn -Map $LastSignInByServicePrincipalId -Key $signInObj.resourceServicePrincipalId -SignInObject $signInObj
            Set-LatestSignIn -Map $LastSignInByAppId -Key $signInObj.appId -SignInObject $signInObj
        }

        $next = $null
        if ($resp.'@odata.nextLink') { $next = $resp.'@odata.nextLink' }
        elseif ($resp.AdditionalProperties -and $resp.AdditionalProperties['@odata.nextLink']) { $next = $resp.AdditionalProperties['@odata.nextLink'] }

        $uri = $next
    }

    Write-Log -Message ("Completed {0}: {1} records" -f $eventType, $recordsForType) -Color Green
}

Write-Log -Message ("Last sign-in collection completed. Mapped apps: {0}" -f ($LastSignInByServicePrincipalId.Count + $LastSignInByAppId.Count)) -Color Green

# Build one merged row per application.
Write-Log -Message "Building report rows..." -Color Cyan
$today = (Get-Date).Date

$appByAppId=@{}; foreach ($a in $AppRegistrations) { if ($a.appId -and -not $appByAppId.ContainsKey($a.appId)) { $appByAppId[$a.appId]=$a } }

$merged=@{}
function Get-MergeKey($spid, $appid) { if ($spid) { return "SP:" + $spid }; if ($appid) { return "APP:" + $appid }; return [Guid]::NewGuid().ToString() }

# Seed rows from Service Principals.
foreach ($sp in $EnterpriseApps) {
    $key = Get-MergeKey $sp.Id $sp.AppId
    if (-not $merged.ContainsKey($key)) {
        $spCreated = ""
        if (($sp.PSObject.Properties.Name -contains "createdDateTime") -and $sp.createdDateTime) { $spCreated = [string]$sp.createdDateTime }

        $merged[$key] = [ordered]@{
            DisplayName = $sp.DisplayName
            AppId = $sp.AppId

            AppOrigin = ""
            ApplicationObjectId = ""
            ServicePrincipalId = $sp.Id

            APP_CreatedDateTime = ""
            APP_ApiPermissionsRequested = ""
            APP_Owners = ""
            APP_Secrets = ""
            APP_Certificates = ""

            SP_CreatedDateTime = $spCreated
            SP_AppOwnerOrganizationId = $sp.appOwnerOrganizationId
            SP_ServicePrincipalType = $sp.servicePrincipalType
            SP_Owners = ""
            SP_AssignedUsersGroups = ""
            SP_SpSecrets = ""
            SP_SpCertificates = ""

            LastSignInDateTime = ""
            LastSignInEventTypes = ""
            LastSignInUser = ""
            LastSignInIP = ""
            LastSignInStatus = ""
        }
    }
}

# Merge App Registration data.
foreach ($app in $AppRegistrations) {
    $appid = $app.appId
    $spid = $null
    if ($appid -and $ServicePrincipalIdByAppId.ContainsKey($appid)) { $spid = $ServicePrincipalIdByAppId[$appid] }
    $key = Get-MergeKey $spid $appid

    if (-not $merged.ContainsKey($key)) {
        $merged[$key] = [ordered]@{
            DisplayName = $app.DisplayName
            AppId = $appid

            AppOrigin = ""
            ApplicationObjectId = $app.Id
            ServicePrincipalId = ""

            APP_CreatedDateTime = [string]$app.createdDateTime
            APP_ApiPermissionsRequested = ""
            APP_Owners = ""
            APP_Secrets = ""
            APP_Certificates = ""

            SP_CreatedDateTime = ""
            SP_AppOwnerOrganizationId = ""
            SP_ServicePrincipalType = ""
            SP_Owners = ""
            SP_AssignedUsersGroups = ""
            SP_SpSecrets = ""
            SP_SpCertificates = ""

            LastSignInDateTime = ""
            LastSignInEventTypes = ""
            LastSignInUser = ""
            LastSignInIP = ""
            LastSignInStatus = ""
        }
    }

    $row = $merged[$key]
    if ($app.DisplayName) { $row["DisplayName"] = $app.DisplayName }
    $row["ApplicationObjectId"] = $app.Id

    $row["APP_CreatedDateTime"] = [string]$app.createdDateTime

    $row["APP_ApiPermissionsRequested"] = Resolve-RequiredResourceAccess $app.requiredResourceAccess

    $pwCreds=@(); if ($app.passwordCredentials) { $pwCreds=@($app.passwordCredentials) }
    $keyCreds=@(); if ($app.keyCredentials) { $keyCreds=@($app.keyCredentials) }
    if ($pwCreds -and $pwCreds.Count -gt 0) { $row["APP_Secrets"] = Format-CredList -Creds $pwCreds -Type "Secret" -Today $today } else { $row["APP_Secrets"] = "" }
    if ($keyCreds -and $keyCreds.Count -gt 0) { $row["APP_Certificates"] = Format-CredList -Creds $keyCreds -Type "Certificate" -Today $today } else { $row["APP_Certificates"] = "" }

    if ($spid) { $row["ServicePrincipalId"] = $spid }
}

# Add owners, assignments, credentials, and latest sign-in data.
foreach ($key in $merged.Keys) {
    $row = $merged[$key]
    $spid = $row["ServicePrincipalId"]
    $appObjId = $row["ApplicationObjectId"]

    if ($appObjId -and $spid) { $row["AppOrigin"] = "AppRegistration + EnterpriseApp" }
    elseif ($appObjId) { $row["AppOrigin"] = "AppRegistrationOnly" }
    elseif ($spid) { $row["AppOrigin"] = "EnterpriseAppOnly" }
    else { $row["AppOrigin"] = "Unknown" }

    if ($appObjId -and $AppOwnersByAppObjectId.ContainsKey($appObjId)) { $row["APP_Owners"] = $AppOwnersByAppObjectId[$appObjId] }
    if ($spid -and $EnterpriseAppOwnersByServicePrincipalId.ContainsKey($spid)) { $row["SP_Owners"] = $EnterpriseAppOwnersByServicePrincipalId[$spid] }

    if ($spid -and $spById.ContainsKey($spid)) {
        $spObj = $spById[$spid]
        if ((-not $row["SP_CreatedDateTime"] -or $row["SP_CreatedDateTime"] -eq "") -and (($spObj.PSObject.Properties.Name -contains "createdDateTime") -and $spObj.createdDateTime)) { $row["SP_CreatedDateTime"] = [string]$spObj.createdDateTime }

        $spPw=@(); if ($spObj.passwordCredentials) { $spPw=@($spObj.passwordCredentials) }
        $spKeys=@(); if ($spObj.keyCredentials) { $spKeys=@($spObj.keyCredentials) }
        if ($spPw -and $spPw.Count -gt 0) { $row["SP_SpSecrets"] = Format-CredList -Creds $spPw -Type "SP Secret" -Today $today } else { if ($row["SP_SpSecrets"] -eq $null) { $row["SP_SpSecrets"] = "" } }
        if ($spKeys -and $spKeys.Count -gt 0) { $row["SP_SpCertificates"] = Format-CredList -Creds $spKeys -Type "SP Certificate" -Today $today } else { if ($row["SP_SpCertificates"] -eq $null) { $row["SP_SpCertificates"] = "" } }
    }

    if ($spid -and $AssignedPrincipalsByServicePrincipalId.ContainsKey($spid)) { $row["SP_AssignedUsersGroups"] = $AssignedPrincipalsByServicePrincipalId[$spid] }

    $last = $null
    if ($spid -and $LastSignInByServicePrincipalId.ContainsKey($spid) -and $LastSignInByServicePrincipalId[$spid]) {
        $last = $LastSignInByServicePrincipalId[$spid]
    }
    elseif ($row["AppId"] -and $LastSignInByAppId.ContainsKey($row["AppId"]) -and $LastSignInByAppId[$row["AppId"]]) {
        $last = $LastSignInByAppId[$row["AppId"]]
    }

    if ($last) {
        $row["LastSignInDateTime"] = $last.createdDateTime
        if ($last.PSObject.Properties.Name -contains "signInEventTypesText") { $row["LastSignInEventTypes"] = $last.signInEventTypesText }
        else { $row["LastSignInEventTypes"] = Join-OrDefault $last.signInEventTypes ", " "" }
        $row["LastSignInUser"] = $last.userPrincipalName
        $row["LastSignInIP"] = $last.ipAddress
        if ($last.PSObject.Properties.Name -contains "statusText") { $row["LastSignInStatus"] = $last.statusText }
        elseif ($last.status -and $last.status.errorCode -ne $null) { $row["LastSignInStatus"] = ("{0} - {1}" -f $last.status.errorCode, $last.status.failureReason) }
    }
}

$MergedRows=@(); foreach ($k in ($merged.Keys | Sort-Object)) { $MergedRows += [pscustomobject]$merged[$k] }

# Build final report view.

Write-Log -Message "Building final report..." -Color Cyan

$reportList = @()
foreach ($r in $MergedRows) {
    $createdParts = @()
    if ($r.APP_CreatedDateTime) { $createdParts += ("[APP] " + $r.APP_CreatedDateTime) }
    if ($r.SP_CreatedDateTime)  { $createdParts += ("[SP] " + $r.SP_CreatedDateTime) }
    $createdMerged = ($createdParts -join " ; ")
    $ownerParts = @()
    if ($r.APP_Owners) { $ownerParts += ("[APP] " + $r.APP_Owners) }
    if ($r.SP_Owners)  { $ownerParts += ("[SP] " + $r.SP_Owners) }
    $ownersMerged = ($ownerParts -join " ; ")
    $appPublisherType = "Unknown"
    if ($r.ApplicationObjectId) {
        $appPublisherType = "Internal / Custom"
    } elseif ($r.SP_AppOwnerOrganizationId) {
        $appPublisherType = "External / Gallery / First-Party"
    }
    $appIdentityType = "Unknown"
    $spType = ""
    if ($r.PSObject.Properties.Name -contains "SP_ServicePrincipalType") { $spType = [string]$r.SP_ServicePrincipalType }
    elseif ($r.PSObject.Properties.Name -contains "ServicePrincipalType") { $spType = [string]$r.ServicePrincipalType }

    if ($spType -eq "ManagedIdentity") { $appIdentityType = "ManagedIdentity" }
    elseif ($spType -eq "Legacy") { $appIdentityType = "Legacy" }
    elseif (($r.PSObject.Properties.Name -contains "LastSignInEventTypes") -and ($r.LastSignInEventTypes -match "managedIdentity")) { $appIdentityType = "ManagedIdentity" }
    elseif (($r.PSObject.Properties.Name -contains "LastSignInEventTypes") -and ($r.LastSignInEventTypes -match "servicePrincipal")) { $appIdentityType = "AppOnly (Service Principal)" }
    elseif (($r.PSObject.Properties.Name -contains "LastSignInEventTypes") -and ($r.LastSignInEventTypes -match "interactiveUser")) { $appIdentityType = "UserInteractive" }
    elseif (($r.PSObject.Properties.Name -contains "LastSignInEventTypes") -and ($r.LastSignInEventTypes -match "nonInteractiveUser")) { $appIdentityType = "UserNonInteractive" }

    $row = [ordered]@{
        DisplayName = $r.DisplayName
        AppOrigin   = $r.AppOrigin
        AppPublisherType = $appPublisherType
        AppIdentityType  = $appIdentityType
        AppId       = $r.AppId
        ApplicationObjectId = $r.ApplicationObjectId
        ServicePrincipalId  = $r.ServicePrincipalId

        CreatedDateTime = $createdMerged
        Owners          = $ownersMerged
        AssignedUsersGroups  = $r.SP_AssignedUsersGroups

        ApiPermissionsRequested = $r.APP_ApiPermissionsRequested
        Secrets              = $r.APP_Secrets
        Certificates         = $r.APP_Certificates

        ServicePrincipalSecrets      = $r.SP_SpSecrets
        ServicePrincipalCertificates = $r.SP_SpCertificates

        LastSignInDateTime   = $r.LastSignInDateTime
        LastSignInEventTypes = $r.LastSignInEventTypes
        LastSignInUser       = $r.LastSignInUser
        LastSignInIP         = $r.LastSignInIP
        LastSignInStatus     = $r.LastSignInStatus
    }

    $reportList += [pscustomobject]$row
}

Write-Log -Message ("Final rows: {0}" -f $reportList.Count) -Color Green

# Export CSV and HTML.

$csvPath = Join-Path $ReportOutputFolder $CsvFileName
$reportList | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath
Write-Log -Message ("CSV written: {0}" -f $csvPath) -Color Green

$htmlPath = Join-Path $ReportOutputFolder $HtmlFileName

$headers = @(
  "DisplayName","AppOrigin","AppPublisherType","AppIdentityType","AppId","ApplicationObjectId","ServicePrincipalId",
  "CreatedDateTime","Owners","AssignedUsersGroups",
  "ApiPermissionsRequested","Secrets","Certificates",
  "ServicePrincipalSecrets","ServicePrincipalCertificates",
  "LastSignInDateTime","LastSignInEventTypes","LastSignInUser","LastSignInIP","LastSignInStatus"
)

$totalApps       = @($reportList).Count
$withLastSignIn  = @($reportList | Where-Object { $_.LastSignInDateTime }).Count
$withoutOwner    = @($reportList | Where-Object { -not $_.Owners }).Count
$internalApps    = @($reportList | Where-Object { $_.AppPublisherType -eq "Internal / Custom" }).Count
$externalApps    = @($reportList | Where-Object { $_.AppPublisherType -eq "External / Gallery / First-Party" }).Count
$expiredCredentialApps = @($reportList | Where-Object {
    $_.Secrets -match "\[EXPIRED\]" -or
    $_.Certificates -match "\[EXPIRED\]" -or
    $_.ServicePrincipalSecrets -match "\[EXPIRED\]" -or
    $_.ServicePrincipalCertificates -match "\[EXPIRED\]"
}).Count

function Convert-ToCellHtml {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    $s = [string]$Value
    if (-not $s) { return "" }

    $lines = @($s -split "(`r`n|`n| ; )" | Where-Object { $_ -and $_.Trim() -ne "" })
    if ($lines.Count -le 1) { return HtmlEncode $s }

    $items = @()
    foreach ($line in $lines) {
        $items += "<div class='list-item'>" + (HtmlEncode ($line.Trim())) + "</div>"
    }
    return ($items -join "")
}

function Convert-ToCredentialHtml {
    param([string]$Value)
    if (-not $Value) { return "" }

    $lines = @($Value -split "(`r`n|`n| ; |; )" | Where-Object { $_ -and $_.Trim() -ne "" })
    $items = @()
    foreach ($line in $lines) {
        $encoded = HtmlEncode ($line.Trim())
        $encoded = $encoded.Replace("[EXPIRED] ","<span class='badge badge-danger'>EXPIRED</span> ")
        $items += "<div class='list-item'>" + $encoded + "</div>"
    }
    return ($items -join "")
}

function New-BadgeHtml {
    param(
        [string]$Text,
        [string]$Type = "neutral"
    )
    if (-not $Text) { return "" }
    return "<span class='badge badge-$Type'>" + (HtmlEncode $Text) + "</span>"
}

$rowsHtml = New-Object System.Text.StringBuilder
foreach ($r in $reportList) {

    $hasLast = if ($r.LastSignInDateTime) { "1" } else { "0" }
    $isCustom = if ($r.AppPublisherType -eq "Internal / Custom") { "1" } else { "0" }
    $hasExpiredCredential = if (
        $r.Secrets -match "\[EXPIRED\]" -or
        $r.Certificates -match "\[EXPIRED\]" -or
        $r.ServicePrincipalSecrets -match "\[EXPIRED\]" -or
        $r.ServicePrincipalCertificates -match "\[EXPIRED\]"
    ) { "1" } else { "0" }
    [void]$rowsHtml.AppendLine("<tr data-haslast='" + $hasLast + "' data-custom='" + $isCustom + "' data-expired='" + $hasExpiredCredential + "'>")

    foreach ($h in $headers) {
        $cell = ""
        $cls = ""

        switch ($h) {
            "AppOrigin" {
                if ($r.$h -eq "AppRegistration + EnterpriseApp") { $cell = New-BadgeHtml $r.$h "success" }
                elseif ($r.$h -eq "AppRegistrationOnly") { $cell = New-BadgeHtml $r.$h "warning" }
                elseif ($r.$h -eq "EnterpriseAppOnly") { $cell = New-BadgeHtml $r.$h "info" }
                else { $cell = New-BadgeHtml $r.$h "neutral" }
            }
            "AppPublisherType" {
                if ($r.$h -eq "Internal / Custom") { $cell = New-BadgeHtml $r.$h "success" }
                elseif ($r.$h -match "External") { $cell = New-BadgeHtml $r.$h "warning" }
                else { $cell = New-BadgeHtml $r.$h "neutral" }
            }
            "AppIdentityType" {
                if ($r.$h -match "ManagedIdentity") { $cell = New-BadgeHtml $r.$h "info" }
                elseif ($r.$h -match "AppOnly") { $cell = New-BadgeHtml $r.$h "success" }
                elseif ($r.$h -match "User") { $cell = New-BadgeHtml $r.$h "warning" }
                else { $cell = New-BadgeHtml $r.$h "neutral" }
            }
            "Secrets" { $cell = Convert-ToCredentialHtml $r.$h; $cls = "wide" }
            "Certificates" { $cell = Convert-ToCredentialHtml $r.$h; $cls = "wide" }
            "ServicePrincipalSecrets" { $cell = Convert-ToCredentialHtml $r.$h; $cls = "wide" }
            "ServicePrincipalCertificates" { $cell = Convert-ToCredentialHtml $r.$h; $cls = "wide" }
            "ApiPermissionsRequested" { $cell = Convert-ToCellHtml $r.$h; $cls = "wide" }
            "LastSignInDateTime" {
                if ($r.$h) { $cell = New-BadgeHtml $r.$h "success" }
                else { $cell = New-BadgeHtml "No data" "neutral" }
            }
            default { $cell = HtmlEncode ([string]$r.$h) }
        }

        if ($cls) { [void]$rowsHtml.AppendLine("<td class='" + $cls + "'>" + $cell + "</td>") }
        else { [void]$rowsHtml.AppendLine("<td>" + $cell + "</td>") }
    }

    [void]$rowsHtml.AppendLine("</tr>")
}

$tableHeader = "<tr>" + (($headers | ForEach-Object { "<th>" + (HtmlEncode $_) + "</th>" }) -join "") + "</tr>"

$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Entra Application Lifecycle Assessment</title>
<style>
:root {
  --bg: #f5f7fb;
  --card: #ffffff;
  --text: #172033;
  --muted: #667085;
  --line: #e6eaf2;
  --blue: #0f3b63;
  --blue2: #185abd;
  --success-bg: #e8f5ee;
  --success-text: #146c43;
  --warning-bg: #fff4de;
  --warning-text: #9a5b00;
  --danger-bg: #fdecec;
  --danger-text: #b42318;
  --info-bg: #eaf2ff;
  --info-text: #175cd3;
  --neutral-bg: #eef2f7;
  --neutral-text: #475467;
}
* { box-sizing: border-box; }
body { margin: 0; font-family: 'Segoe UI', Arial, sans-serif; background: var(--bg); color: var(--text); }
.page { padding: 24px; }
.hero {
  background: linear-gradient(135deg, #0f2f4f 0%, #124b7a 55%, #1f6fb2 100%);
  color: white;
  border-radius: 18px;
  padding: 26px 30px;
  display: flex;
  justify-content: space-between;
  gap: 20px;
  box-shadow: 0 12px 30px rgba(15, 47, 79, .18);
}
.hero h1 { margin: 0 0 8px 0; font-size: 26px; font-weight: 700; letter-spacing: -.02em; }
.hero p { margin: 0; color: rgba(255,255,255,.82); font-size: 13px; line-height: 1.5; max-width: 820px; }
.hero-meta { text-align: right; min-width: 230px; font-size: 12px; color: rgba(255,255,255,.78); }
.hero-meta strong { color: white; font-size: 14px; }
.cards { display: grid; grid-template-columns: repeat(6, minmax(140px, 1fr)); gap: 14px; margin: 18px 0; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 16px; padding: 16px; box-shadow: 0 6px 18px rgba(16,24,40,.06); }
.card span { display: block; color: var(--muted); font-size: 12px; margin-bottom: 8px; }
.card strong { font-size: 25px; line-height: 1; }
.card.danger { border-left: 5px solid #d92d20; }
.card.warning { border-left: 5px solid #f79009; }
.card.success { border-left: 5px solid #12b76a; }
.card.info { border-left: 5px solid #2e90fa; }
.toolbar { background: var(--card); border: 1px solid var(--line); border-radius: 16px; padding: 14px 16px; margin: 18px 0; display: flex; align-items: center; gap: 14px; }
.toolbar label { font-size: 13px; color: #344054; }
.note { font-size: 12px; color: var(--muted); margin-left: auto; }
.table-wrap { background: var(--card); border: 1px solid var(--line); border-radius: 16px; overflow: auto; box-shadow: 0 6px 18px rgba(16,24,40,.06); max-height: 72vh; }
table { border-collapse: separate; border-spacing: 0; width: 100%; min-width: 2600px; }
th, td { border-bottom: 1px solid var(--line); padding: 10px 12px; font-size: 12px; vertical-align: top; }
th { position: sticky; top: 0; z-index: 3; background: #f8fafc; color: #344054; text-align: left; font-weight: 700; white-space: nowrap; }
tr:hover td { background: #fbfdff; }
td { color: #1d2939; max-width: 280px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
td.wide { max-width: 720px; white-space: normal; line-height: 1.45; }
.list-item { display: block; white-space: nowrap; margin: 0 0 4px 0; }
.badge { display: inline-flex; align-items: center; border-radius: 999px; padding: 3px 9px; font-size: 11px; font-weight: 700; line-height: 1.4; white-space: nowrap; }
.badge-success { background: var(--success-bg); color: var(--success-text); }
.badge-warning { background: var(--warning-bg); color: var(--warning-text); }
.badge-danger { background: var(--danger-bg); color: var(--danger-text); }
.badge-info { background: var(--info-bg); color: var(--info-text); }
.badge-neutral { background: var(--neutral-bg); color: var(--neutral-text); }
.footer { margin-top: 12px; color: var(--muted); font-size: 12px; }
@media (max-width: 1200px) { .cards { grid-template-columns: repeat(2, 1fr); } .hero { flex-direction: column; } .hero-meta { text-align: left; } }
</style>
</head>
<body>
<div class="page">
  <section class="hero">
    <div>
      <h1>Entra Application Lifecycle Assessment</h1>
      <p>Unified inventory for App Registrations and Enterprise Applications, including owners, credentials, API permissions, assignments and latest sign-in activity available in Microsoft Graph sign-in logs.</p>
    </div>
    <div class="hero-meta">
      <strong>Generated</strong><br />
      $(Get-Date)<br /><br />
      Signed-in account<br />
      $($ctx.Account)
    </div>
  </section>

  <section class="cards">
    <div class="card info"><span>Total apps</span><strong>$totalApps</strong></div>
    <div class="card success"><span>With last sign-in</span><strong>$withLastSignIn</strong></div>
    <div class="card warning"><span>Without owner</span><strong>$withoutOwner</strong></div>
    <div class="card danger"><span>Expired credentials</span><strong>$expiredCredentialApps</strong></div>
    <div class="card success"><span>Internal/custom</span><strong>$internalApps</strong></div>
    <div class="card warning"><span>External/gallery</span><strong>$externalApps</strong></div>
  </section>

  <section class="toolbar">
    <label><input id="chkHasLast" type="checkbox" /> Only apps with Last sign-in</label>
    <label><input id="chkExpired" type="checkbox" /> Only apps with expired secret/cert</label>
    <label><input id="chkCustomOnly" type="checkbox" /> Only user-created apps</label>
    <span class="note">Default view shows all applications. Use the filters to focus on active, expired, or user-created apps.</span>
  </section>

  <section class="table-wrap">
    <table id="tbl">
      <thead>
        $tableHeader
      </thead>
      <tbody>
        $($rowsHtml.ToString())
      </tbody>
    </table>
  </section>

  <div class="footer">
    CSV: $csvPath<br />
    HTML: $htmlPath<br />
    Log: $script:LogPath
  </div>
</div>

<script>
(function(){
  var chkLast=document.getElementById('chkHasLast');
  var chkExpired=document.getElementById('chkExpired');
  var chkCustomOnly=document.getElementById('chkCustomOnly');
  var tbl=document.getElementById('tbl');
  function apply(){
    var onlyLast=chkLast.checked;
    var onlyExpired=chkExpired.checked;
    var onlyCustom=chkCustomOnly.checked;
    var rows=tbl.querySelectorAll('tbody tr');
    for(var i=0;i<rows.length;i++){
      var ok = true;
      if(onlyLast){ ok = ok && rows[i].getAttribute('data-haslast')==='1'; }
      if(onlyExpired){ ok = ok && rows[i].getAttribute('data-expired')==='1'; }
      if(onlyCustom){ ok = ok && rows[i].getAttribute('data-custom')==='1'; }
      rows[i].style.display = ok ? '' : 'none';
    }
  }
  chkLast.addEventListener('change', apply);
  chkExpired.addEventListener('change', apply);
  chkCustomOnly.addEventListener('change', apply);
})();
</script>
</body>
</html>
"@

Set-Content -Path $htmlPath -Value $html -Encoding UTF8
Write-Log -Message ("HTML written: {0}" -f $htmlPath) -Color Green

Write-Log -Message "Done." -Color Green
Write-Host ""
Write-Host ("OUTPUT FOLDER: {0}" -f $ReportOutputFolder) -ForegroundColor Cyan
Write-Host ("LOG FILE     : {0}" -f $script:LogPath) -ForegroundColor Cyan
Write-Host ("CSV          : {0}" -f $csvPath) -ForegroundColor Cyan
Write-Host ("HTML         : {0}" -f $htmlPath) -ForegroundColor Cyan
