<#
.SYNOPSIS
    Microsoft Entra ID SMS/Voice authentication assessment.

.DESCRIPTION
    Read-only assessment focused on:
      - SMS Authentication Methods Policy
      - Voice Authentication Methods Policy
      - Registration Campaign configuration and targets
      - Interactive sign-ins where SMS or Voice was used
      - Users with a registered phone authentication method and their SMS/Voice sign-in counts

.NOTES
    Author  : Igor Henrique Martini
    Website : https://igormartini.cloud
    Version : 2.2.2

    Required module:
      Microsoft.Graph.Authentication

    Required delegated Microsoft Graph permissions:
      Policy.Read.AuthenticationMethod
      Group.Read.All
      AuditLog.Read.All

    Recommended Entra role:
      Global Reader
#>

[CmdletBinding()]
param()

# ============================================================
# USER CONFIGURATION
# ============================================================
$LookbackDays    = 30
$SignInChunkDays = 7
$OutputFolder    = if ($PSScriptRoot) { Join-Path $PSScriptRoot 'Output' } else { Join-Path (Get-Location).Path 'Output' }
$OpenHtmlReport  = $true
# ============================================================

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ScriptVersion = '2.2.2'

# ============================================================
# INITIALIZATION
# ============================================================

if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw @"
Microsoft.Graph.Authentication is required.

Install it with:
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
"@
}

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

function Write-Step {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Cyan
}

function Get-PropertyValue {
    param(
        $Object,
        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $Object) { return $null }

    if ($Object -is [System.Collections.IDictionary]) {
        try {
            if ($Object.ContainsKey($Name)) { return $Object[$Name] }
        }
        catch {}

        try {
            if ($Object.Contains($Name)) { return $Object[$Name] }
        }
        catch {}
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }

    return $null
}

function Convert-ToBoolean {
    param($Value)

    if ($Value -eq $true) { return $true }
    if ($null -eq $Value) { return $false }
    return ([string]$Value).ToLowerInvariant() -eq 'true'
}

function Convert-HtmlSafe {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Format-UtcDate {
    param($Value)

    if (-not $Value) { return '' }

    try {
        return ([datetime]$Value).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
    }
    catch {
        return [string]$Value
    }
}

function Invoke-GraphGet {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [int]$MaxAttempts = 6
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject -ErrorAction Stop
        }
        catch {
            $status = $null

            try { $status = [int]$_.Exception.Response.StatusCode } catch {}
            if ($null -eq $status) {
                try { $status = [int]$_.Exception.Response.StatusCode.value__ } catch {}
            }

            $retryable = ($status -eq 429 -or ($status -ge 500 -and $status -lt 600))

            if ($retryable -and $attempt -lt $MaxAttempts) {
                $delay = [math]::Min(30, [math]::Pow(2, $attempt))
                Start-Sleep -Seconds $delay
                continue
            }

            throw
        }
    }
}

function Get-AllGraphItems {
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri

    while ($next) {
        $response = Invoke-GraphGet -Uri $next

        foreach ($item in @(Get-PropertyValue $response 'value')) {
            if ($null -ne $item) { $items.Add($item) }
        }

        $next = [string](Get-PropertyValue $response '@odata.nextLink')
    }

    return $items.ToArray()
}

# ============================================================
# MICROSOFT GRAPH CONNECTION
# ============================================================

$Scopes = @(
    'Policy.Read.AuthenticationMethod',
    'Group.Read.All',
    'AuditLog.Read.All'
)

Write-Step 'Connecting to Microsoft Graph'
Connect-MgGraph -Scopes $Scopes -NoWelcome | Out-Null

$MgContext = Get-MgContext
if (-not $MgContext) { throw 'Microsoft Graph connection was not established.' }

$TenantId = [string]$MgContext.TenantId
$RunAs = [string]$MgContext.Account

# ============================================================
# DIRECTORY / TARGET HELPERS
# ============================================================

$GroupNameCache = @{}
$RegistrationById = @{}
$RegistrationByUpn = @{}

function Resolve-GroupName {
    param([string]$GroupId)

    if (-not $GroupId) { return '' }
    if ($GroupId -eq 'all_users') { return 'All Users' }

    if ($GroupNameCache.ContainsKey($GroupId)) {
        return $GroupNameCache[$GroupId]
    }

    $displayName = $null

    try {
        $group = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId"
        $displayName = [string](Get-PropertyValue $group 'displayName')
    }
    catch {}

    if (-not $displayName) { $displayName = $GroupId }

    $GroupNameCache[$GroupId] = $displayName
    return $displayName
}

function Resolve-TargetName {
    param(
        [string]$TargetType,
        [string]$Id
    )

    if (-not $Id) { return '' }
    if ($Id -eq 'all_users') { return 'All Users' }

    if ($TargetType -eq 'group') {
        return Resolve-GroupName -GroupId $Id
    }

    if ($TargetType -eq 'user') {
        if (-not $RegistrationById.ContainsKey($Id)) {
            try {
                $registration = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails/$Id"

                if ($registration) {
                    $RegistrationById[$Id] = $registration
                    $registrationUpn = [string](Get-PropertyValue $registration 'userPrincipalName')

                    if ($registrationUpn) {
                        $RegistrationByUpn[$registrationUpn.ToLowerInvariant()] = $registration
                    }
                }
            }
            catch {}
        }

        if ($RegistrationById.ContainsKey($Id)) {
            $u = $RegistrationById[$Id]
            $upn = [string](Get-PropertyValue $u 'userPrincipalName')
            $name = [string](Get-PropertyValue $u 'userDisplayName')

            if ($name -and $upn) { return "$name ($upn)" }
            if ($upn) { return $upn }
            if ($name) { return $name }
        }
    }

    return $Id
}

function Get-PolicyScope {
    param($Configuration)

    $result = [ordered]@{
        IsAllUsers     = $false
        IncludedGroups = @()
        ExcludedGroups = @()
        IncludedUsers  = @()
        ExcludedUsers  = @()
    }

    if ($null -eq $Configuration) {
        return [PSCustomObject]$result
    }

    foreach ($target in @(Get-PropertyValue $Configuration 'includeTargets')) {
        if ($null -eq $target) { continue }

        $type = [string](Get-PropertyValue $target 'targetType')
        $id   = [string](Get-PropertyValue $target 'id')

        if ($type -eq 'group') {
            if ($id -eq 'all_users') {
                $result.IsAllUsers = $true
            }
            else {
                $result.IncludedGroups += [PSCustomObject]@{ Id=$id; DisplayName=(Resolve-GroupName $id) }
            }
        }
        elseif ($type -eq 'user') {
            $result.IncludedUsers += $id
        }
    }

    foreach ($target in @(Get-PropertyValue $Configuration 'excludeTargets')) {
        if ($null -eq $target) { continue }

        $type = [string](Get-PropertyValue $target 'targetType')
        $id   = [string](Get-PropertyValue $target 'id')

        if ($type -eq 'group') {
            $result.ExcludedGroups += [PSCustomObject]@{ Id=$id; DisplayName=(Resolve-GroupName $id) }
        }
        elseif ($type -eq 'user') {
            $result.ExcludedUsers += $id
        }
    }

    return [PSCustomObject]$result
}

function Test-IsPhoneMethod {
    param([string]$Method)

    if (-not $Method) { return $false }
    return ($Method -match '(?i)^(mobilePhone|alternateMobilePhone|officePhone|sms|voice.*)$')
}

# Returns true for a durable non-phone authentication method that can serve
# as an MFA alternative. Email, password, phone methods, and Temporary Access
# Pass are intentionally excluded.
function Test-IsAlternativeMfaMethod {
    param([string]$Method)

    if (-not $Method) { return $false }
    if (Test-IsPhoneMethod -Method $Method) { return $false }

    $normalized = $Method.Trim()

    if ($normalized -match '(?i)^(email|password|temporaryAccessPass|tap)$') {
        return $false
    }

    return (
        $normalized -match '(?i)microsoftAuthenticator' -or
        $normalized -match '(?i)softwareOneTimePasscode' -or
        $normalized -match '(?i)hardwareOneTimePasscode' -or
        $normalized -match '(?i)softwareOath' -or
        $normalized -match '(?i)hardwareOath' -or
        $normalized -match '(?i)fido2' -or
        $normalized -match '(?i)passkey' -or
        $normalized -match '(?i)windowsHelloForBusiness' -or
        $normalized -match '(?i)platformCredential' -or
        $normalized -match '(?i)certificateBasedAuthentication' -or
        $normalized -match '(?i)^cba$'
    )
}

function Get-SmsVoiceKind {
    param([string]$Method)

    if (-not $Method) { return $null }

    if ($Method -match '(?i)(^|\b)SMS($|\b)|text[\s-]*message') {
        return 'SMS'
    }

    if ($Method -match '(?i)(^|\b)Voice($|\b)|phone[\s-]*call') {
        return 'Voice'
    }

    return $null
}

# ============================================================
# 1. AUTHENTICATION METHODS POLICY + REGISTRATION CAMPAIGN
# ============================================================

Write-Step 'Reading SMS, Voice, and Registration Campaign configuration'

$AuthPolicy = $null
$AuthPolicyBeta = $null
$AuthPolicyBetaReadSucceeded = $false
$AuthPolicyBetaReadError = ''
$SmsPolicy = $null
$VoicePolicy = $null

try {
    $AuthPolicy = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
}
catch {
    throw "Unable to read Authentication Methods Policy: $($_.Exception.Message)"
}

try {
    $AuthPolicyBeta = Invoke-GraphGet -Uri 'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy'
    $AuthPolicyBetaReadSucceeded = $true
}
catch {
    $AuthPolicyBetaReadError = $_.Exception.Message
    Write-Warning "Could not read optOutSettings.passkeyDynamicMigration from Graph beta: $AuthPolicyBetaReadError"
}

try {
    $SmsPolicy = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/sms'
}
catch {
    throw "Unable to read SMS Authentication Methods Policy: $($_.Exception.Message)"
}

try {
    $VoicePolicy = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/voice'
}
catch {
    throw "Unable to read Voice Authentication Methods Policy: $($_.Exception.Message)"
}

$SmsState   = [string](Get-PropertyValue $SmsPolicy 'state')
$VoiceState = [string](Get-PropertyValue $VoicePolicy 'state')

if (-not $SmsState) { $SmsState = 'unknown' }
if (-not $VoiceState) { $VoiceState = 'unknown' }

$SmsScope   = Get-PolicyScope -Configuration $SmsPolicy
$VoiceScope = Get-PolicyScope -Configuration $VoicePolicy

$RegistrationEnforcement = Get-PropertyValue $AuthPolicy 'registrationEnforcement'
$RegistrationCampaign = Get-PropertyValue $RegistrationEnforcement 'authenticationMethodsRegistrationCampaign'

$CampaignStateRaw = [string](Get-PropertyValue $RegistrationCampaign 'state')
if (-not $CampaignStateRaw) { $CampaignStateRaw = 'unknown' }

$CampaignMode = switch ($CampaignStateRaw) {
    'default'  { 'Microsoft managed' }
    'enabled'  { 'Enabled' }
    'disabled' { 'Disabled' }
    default    { $CampaignStateRaw }
}

$CampaignSnoozeDays = Get-PropertyValue $RegistrationCampaign 'snoozeDurationInDays'
$CampaignSnoozeDisplay = if ($null -eq $CampaignSnoozeDays -or [string]$CampaignSnoozeDays -eq '') {
    'Not returned'
}
else {
    "$CampaignSnoozeDays day(s)"
}

$CampaignEnforceAfterSnoozesRaw = Get-PropertyValue $RegistrationCampaign 'enforceRegistrationAfterAllowedSnoozes'
$CampaignEnforceAfterSnoozesDisplay = if ($null -eq $CampaignEnforceAfterSnoozesRaw) {
    'Not returned'
}
elseif (Convert-ToBoolean $CampaignEnforceAfterSnoozesRaw) {
    'Yes'
}
else {
    'No'
}

$OptOutSettings = if ($AuthPolicyBeta) { Get-PropertyValue $AuthPolicyBeta 'optOutSettings' } else { $null }
$PasskeyDynamicMigrationRaw = Get-PropertyValue $OptOutSettings 'passkeyDynamicMigration'

if (-not $AuthPolicyBetaReadSucceeded) {
    $PasskeyDynamicMigrationStatus = 'Unknown'
    $PasskeyDynamicMigrationDisplay = 'Unknown (Graph read failed)'
    $PasskeyDynamicMigrationValue = 'Unknown'
    $PasskeyDynamicMigrationRawDisplay = 'Unavailable'
}
elseif ($null -eq $PasskeyDynamicMigrationRaw) {
    # Microsoft activates the temporary opt-out only when this property is
    # explicitly set to true. If the GET succeeds and the property is absent,
    # the tenant is not opted out.
    $PasskeyDynamicMigrationStatus = 'Not active'
    $PasskeyDynamicMigrationDisplay = 'Not active'
    $PasskeyDynamicMigrationValue = 'Property absent - effective opt-out: No'
    $PasskeyDynamicMigrationRawDisplay = 'Property absent'
}
elseif (Convert-ToBoolean $PasskeyDynamicMigrationRaw) {
    $PasskeyDynamicMigrationStatus = 'Active'
    $PasskeyDynamicMigrationDisplay = 'Active'
    $PasskeyDynamicMigrationValue = 'True'
    $PasskeyDynamicMigrationRawDisplay = 'True'
}
else {
    $PasskeyDynamicMigrationStatus = 'Not active'
    $PasskeyDynamicMigrationDisplay = 'Not active'
    $PasskeyDynamicMigrationValue = 'False'
    $PasskeyDynamicMigrationRawDisplay = 'False'
}

$PasskeyOptOutGraphQuery = 'GET /beta/policies/authenticationMethodsPolicy -> optOutSettings.passkeyDynamicMigration'

# ============================================================
# 2. REGISTERED AUTHENTICATION METHODS
# ============================================================

Write-Step 'Reading registered authentication methods'

$RegistrationMap = @{}
$PhoneRegistrationMethods = @('mobilePhone','alternateMobilePhone','officePhone')
$RegistrationFilterSucceeded = $true

try {
    foreach ($phoneMethod in $PhoneRegistrationMethods) {
        $filter = [uri]::EscapeDataString("methodsRegistered/any(x:x eq '$phoneMethod')")
        $uri = "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?`$filter=$filter"

        foreach ($registration in @(Get-AllGraphItems -Uri $uri)) {
            $id = [string](Get-PropertyValue $registration 'id')
            $upn = [string](Get-PropertyValue $registration 'userPrincipalName')
            $key = if ($id) { $id } elseif ($upn) { $upn.ToLowerInvariant() } else { continue }
            $RegistrationMap[$key] = $registration
        }
    }
}
catch {
    $RegistrationFilterSucceeded = $false
    Write-Warning "Filtered userRegistrationDetails query failed. Falling back to the full registration report. $($_.Exception.Message)"
}

if (-not $RegistrationFilterSucceeded) {
    $RegistrationMap = @{}

    foreach ($registration in @(Get-AllGraphItems -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails')) {
        $methods = @(@(Get-PropertyValue $registration 'methodsRegistered') | Where-Object { $_ } | ForEach-Object { [string]$_ })
        $hasPhone = @($methods | Where-Object { Test-IsPhoneMethod -Method $_ }).Count -gt 0
        if (-not $hasPhone) { continue }

        $id = [string](Get-PropertyValue $registration 'id')
        $upn = [string](Get-PropertyValue $registration 'userPrincipalName')
        $key = if ($id) { $id } elseif ($upn) { $upn.ToLowerInvariant() } else { continue }
        $RegistrationMap[$key] = $registration
    }
}

$RegistrationDetails = @($RegistrationMap.Values)

foreach ($registration in $RegistrationDetails) {
    $id = [string](Get-PropertyValue $registration 'id')
    $upn = [string](Get-PropertyValue $registration 'userPrincipalName')
    if ($id) { $RegistrationById[$id] = $registration }
    if ($upn) { $RegistrationByUpn[$upn.ToLowerInvariant()] = $registration }
}

$PhoneRegisteredUsers = @(
    foreach ($registration in $RegistrationDetails) {
        $methods = @(@(Get-PropertyValue $registration 'methodsRegistered') | Where-Object { $_ } | ForEach-Object { [string]$_ } | Select-Object -Unique)
        $phoneMethods = @($methods | Where-Object { Test-IsPhoneMethod -Method $_ })

        if ($phoneMethods.Count -gt 0) {
            $alternativeMethods = @($methods | Where-Object { Test-IsAlternativeMfaMethod -Method $_ } | Select-Object -Unique)
            $hasAlternativeMfa = ($alternativeMethods.Count -gt 0)
            $phoneDependent = (-not $hasAlternativeMfa)

            [PSCustomObject]@{
                Id                     = [string](Get-PropertyValue $registration 'id')
                UserPrincipalName      = [string](Get-PropertyValue $registration 'userPrincipalName')
                DisplayName            = [string](Get-PropertyValue $registration 'userDisplayName')
                UserType               = [string](Get-PropertyValue $registration 'userType')
                IsAdmin                = Convert-ToBoolean (Get-PropertyValue $registration 'isAdmin')
                PhoneMethods           = ($phoneMethods -join '; ')
                RegisteredMethods      = ($methods -join '; ')
                AlternativeMfa         = if ($hasAlternativeMfa) { 'Yes' } else { 'No' }
                AlternativeMfaMethods  = ($alternativeMethods -join '; ')
                PhoneDependent         = if ($phoneDependent) { 'Yes' } else { 'No' }
                IsMfaCapable           = Convert-ToBoolean (Get-PropertyValue $registration 'isMfaCapable')
                IsPasswordlessCapable  = Convert-ToBoolean (Get-PropertyValue $registration 'isPasswordlessCapable')
                UserPreferredMethod    = [string](Get-PropertyValue $registration 'userPreferredMethodForSecondaryAuthentication')
                SystemPreferredMethods = (@(Get-PropertyValue $registration 'systemPreferredAuthenticationMethods') -join '; ')
            }
        }
    }
)

$PhoneUserIds = @{}
$PhoneUserUpns = @{}

foreach ($user in $PhoneRegisteredUsers) {
    if ($user.Id) { $PhoneUserIds[$user.Id] = $true }
    if ($user.UserPrincipalName) { $PhoneUserUpns[$user.UserPrincipalName.ToLowerInvariant()] = $true }
}

# ============================================================
# 3. POLICY TARGETS
# ============================================================

$PolicyTargets = New-Object System.Collections.Generic.List[object]

function Add-PolicyTargets {
    param(
        [string]$PolicyName,
        $Configuration
    )

    foreach ($target in @(Get-PropertyValue $Configuration 'includeTargets')) {
        if ($null -eq $target) { continue }
        $type = [string](Get-PropertyValue $target 'targetType')
        $id = [string](Get-PropertyValue $target 'id')

        $PolicyTargets.Add([PSCustomObject]@{
            Policy      = $PolicyName
            Assignment  = 'Include'
            TargetType  = if ($id -eq 'all_users') { 'AllUsers' } else { $type }
            Target      = Resolve-TargetName -TargetType $type -Id $id
            Id          = $id
        })
    }

    foreach ($target in @(Get-PropertyValue $Configuration 'excludeTargets')) {
        if ($null -eq $target) { continue }
        $type = [string](Get-PropertyValue $target 'targetType')
        $id = [string](Get-PropertyValue $target 'id')

        $PolicyTargets.Add([PSCustomObject]@{
            Policy      = $PolicyName
            Assignment  = 'Exclude'
            TargetType  = $type
            Target      = Resolve-TargetName -TargetType $type -Id $id
            Id          = $id
        })
    }
}

Add-PolicyTargets -PolicyName 'SMS' -Configuration $SmsPolicy
Add-PolicyTargets -PolicyName 'Voice' -Configuration $VoicePolicy

$CampaignTargets = New-Object System.Collections.Generic.List[object]

foreach ($target in @(Get-PropertyValue $RegistrationCampaign 'includeTargets')) {
    if ($null -eq $target) { continue }

    $type = [string](Get-PropertyValue $target 'targetType')
    $id = [string](Get-PropertyValue $target 'id')
    $method = [string](Get-PropertyValue $target 'targetedAuthenticationMethod')

    $CampaignTargets.Add([PSCustomObject]@{
        Assignment           = 'Include'
        TargetType           = $type
        Target               = Resolve-TargetName -TargetType $type -Id $id
        AuthenticationMethod = $method
        Id                   = $id
    })
}

foreach ($target in @(Get-PropertyValue $RegistrationCampaign 'excludeTargets')) {
    if ($null -eq $target) { continue }

    $type = [string](Get-PropertyValue $target 'targetType')
    $id = [string](Get-PropertyValue $target 'id')

    $CampaignTargets.Add([PSCustomObject]@{
        Assignment           = 'Exclude'
        TargetType           = $type
        Target               = Resolve-TargetName -TargetType $type -Id $id
        AuthenticationMethod = ''
        Id                   = $id
    })
}

$CampaignIncludes = @($CampaignTargets | Where-Object { $_.Assignment -eq 'Include' })
$CampaignExcludes = @($CampaignTargets | Where-Object { $_.Assignment -eq 'Exclude' })
$NonDefaultIncludes = @($CampaignIncludes | Where-Object { $_.Id -ne 'all_users' })

$CampaignCustomTargeting = if (
    $CampaignExcludes.Count -gt 0 -or
    $CampaignIncludes.Count -gt 1 -or
    $NonDefaultIncludes.Count -gt 0
) {
    'Yes'
}
else {
    'No'
}

# ============================================================
# 4. INTERACTIVE SMS / VOICE SIGN-INS
# ============================================================

Write-Step "Reading interactive SMS/Voice sign-ins from the last $LookbackDays days"

$MatchingEvents = New-Object System.Collections.Generic.List[object]
$UsageByUser = @{}
$SeenUsageKeys = @{}

$EndUtc = [datetime]::UtcNow
$StartUtc = $EndUtc.AddDays(-$LookbackDays)
$Cursor = $StartUtc
$Chunk = 0
$EstimatedChunks = [math]::Max(1, [math]::Ceiling(($EndUtc - $StartUtc).TotalDays / $SignInChunkDays))

while ($Cursor -lt $EndUtc) {
    $Chunk++
    $ChunkEnd = $Cursor.AddDays($SignInChunkDays)
    if ($ChunkEnd -gt $EndUtc) { $ChunkEnd = $EndUtc }

    $Percent = [math]::Min(100, [math]::Round(($Chunk / $EstimatedChunks) * 100))

    Write-Progress `
        -Activity 'Collecting interactive Entra sign-ins' `
        -Status "$($Cursor.ToString('yyyy-MM-dd')) to $($ChunkEnd.ToString('yyyy-MM-dd'))" `
        -PercentComplete $Percent

    # GET /auditLogs/signIns returns interactive user sign-ins by default.
    # Keep the query simple for maximum compatibility: date/time filter + paging only.
    $filter = "createdDateTime ge $($Cursor.ToString('yyyy-MM-ddTHH:mm:ssZ')) and createdDateTime lt $($ChunkEnd.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    $encodedFilter = [uri]::EscapeDataString($filter)
    $next = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$encodedFilter&`$top=1000"

    while ($next) {
        $response = Invoke-GraphGet -Uri $next

        foreach ($signIn in @(Get-PropertyValue $response 'value')) {
            if ($null -eq $signIn) { continue }

            $userId = [string](Get-PropertyValue $signIn 'userId')
            $upn = [string](Get-PropertyValue $signIn 'userPrincipalName')

            # Historical SMS/Voice usage is collected independently from the
            # user's current phone-registration state. Correlation happens later.
            $status = Get-PropertyValue $signIn 'status'
            $errorCode = [string](Get-PropertyValue $status 'errorCode')
            $parentSuccess = ($errorCode -eq '0')
            $signInId = [string](Get-PropertyValue $signIn 'id')
            $createdDateTime = Get-PropertyValue $signIn 'createdDateTime'
            $details = @(Get-PropertyValue $signIn 'authenticationDetails')

            foreach ($detail in $details) {
                if ($null -eq $detail) { continue }

                $method = [string](Get-PropertyValue $detail 'authenticationMethod')
                $kind = Get-SmsVoiceKind -Method $method
                if (-not $kind) { continue }

                $stepSucceededRaw = Get-PropertyValue $detail 'succeeded'
                $stepSucceeded = Convert-ToBoolean $stepSucceededRaw
                $stepResult = [string](Get-PropertyValue $detail 'authenticationStepResultDetail')

                # Count as actual SMS/Voice usage when the authentication step itself
                # succeeded. If Graph omits the step flag, a successful parent sign-in
                # is accepted as fallback evidence.
                $countAsUsage = $stepSucceeded -or ($parentSuccess -and $null -eq $stepSucceededRaw)

                $parentStatus = if ($parentSuccess) { 'Success' } elseif ($errorCode -eq '50140') { 'Interrupted (KMSI)' } else { 'Not successful' }

                $MatchingEvents.Add([PSCustomObject]@{
                    Time                    = Format-UtcDate $createdDateTime
                    UserPrincipalName       = $upn
                    EventType               = 'Interactive'
                    Method                  = $method
                    MethodKind              = $kind
                    StepSucceeded           = if ($null -eq $stepSucceededRaw) { '' } else { [string]$stepSucceededRaw }
                    StepResult              = $stepResult
                    ParentSignInStatus      = $parentStatus
                    ErrorCode               = $errorCode
                    Application             = [string](Get-PropertyValue $signIn 'appDisplayName')
                    IPAddress               = [string](Get-PropertyValue $signIn 'ipAddress')
                    CountedAsUsage          = $countAsUsage
                })

                if (-not $countAsUsage) { continue }

                $userKey = if ($userId) { $userId } elseif ($upn) { $upn.ToLowerInvariant() } else { continue }

                if (-not $UsageByUser.ContainsKey($userKey)) {
                    $UsageByUser[$userKey] = [ordered]@{
                        SmsSignIns   = 0
                        VoiceSignIns = 0
                    }
                }

                # Count a sign-in once per method, even if Graph exposes more than one
                # authenticationDetails row for the same method.
                $dedupeKey = "$userKey|$kind|$signInId"
                if (-not $SeenUsageKeys.ContainsKey($dedupeKey)) {
                    $SeenUsageKeys[$dedupeKey] = $true

                    if ($kind -eq 'SMS') {
                        $UsageByUser[$userKey].SmsSignIns++
                    }
                    else {
                        $UsageByUser[$userKey].VoiceSignIns++
                    }
                }
            }
        }

        $next = [string](Get-PropertyValue $response '@odata.nextLink')
    }

    $Cursor = $ChunkEnd
}

Write-Progress -Activity 'Collecting interactive Entra sign-ins' -Completed

# ============================================================
# 5. CONSOLIDATED REGISTERED USERS
# ============================================================

$RegisteredUsers = @(
    foreach ($user in $PhoneRegisteredUsers) {
        $key = if ($user.Id) { $user.Id } else { $user.UserPrincipalName.ToLowerInvariant() }
        $usage = if ($UsageByUser.ContainsKey($key)) { $UsageByUser[$key] } else { $null }

        $smsCount = if ($usage) { [int]$usage.SmsSignIns } else { 0 }
        $voiceCount = if ($usage) { [int]$usage.VoiceSignIns } else { 0 }

        [PSCustomObject]@{
            UserPrincipalName      = $user.UserPrincipalName
            DisplayName            = $user.DisplayName
            UserType               = $user.UserType
            IsAdmin                = $user.IsAdmin
            PhoneMethods           = $user.PhoneMethods
            RegisteredMethods      = $user.RegisteredMethods
            AlternativeMfa         = $user.AlternativeMfa
            AlternativeMfaMethods  = $user.AlternativeMfaMethods
            PhoneDependent         = $user.PhoneDependent
            IsMfaCapable           = $user.IsMfaCapable
            IsPasswordlessCapable  = $user.IsPasswordlessCapable
            UserPreferredMethod    = $user.UserPreferredMethod
            SystemPreferredMethods = $user.SystemPreferredMethods
            SmsSignIns             = $smsCount
            VoiceSignIns           = $voiceCount
            TotalSignIns           = ($smsCount + $voiceCount)
        }
    }
)
$RegisteredUsers = @($RegisteredUsers | Sort-Object @{ Expression='TotalSignIns'; Descending=$true }, UserPrincipalName)

# ============================================================
# 6. CSV EXPORTS
# ============================================================

$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$HtmlPath = Join-Path $OutputFolder "Entra_SMS_Voice_Assessment_$Timestamp.html"
$PolicyCsvPath = Join-Path $OutputFolder "SmsVoice_PolicyTargets_$Timestamp.csv"
$CampaignCsvPath = Join-Path $OutputFolder "RegistrationCampaign_Targets_$Timestamp.csv"
$EventsCsvPath = Join-Path $OutputFolder "SmsVoice_MatchingSignInEvents_$Timestamp.csv"
$UsersCsvPath = Join-Path $OutputFolder "SmsVoice_RegisteredUsers_$Timestamp.csv"

if ($PolicyTargets.Count -gt 0) {
    $PolicyTargets | Export-Csv -Path $PolicyCsvPath -NoTypeInformation -Encoding UTF8
}
else {
    'Policy,Assignment,TargetType,Target,Id' | Set-Content -Path $PolicyCsvPath -Encoding UTF8
}

if ($CampaignTargets.Count -gt 0) {
    $CampaignTargets | Export-Csv -Path $CampaignCsvPath -NoTypeInformation -Encoding UTF8
}
else {
    'Assignment,TargetType,Target,AuthenticationMethod,Id' | Set-Content -Path $CampaignCsvPath -Encoding UTF8
}

if ($MatchingEvents.Count -gt 0) {
    $MatchingEvents | Sort-Object Time -Descending | Export-Csv -Path $EventsCsvPath -NoTypeInformation -Encoding UTF8
}
else {
    'Time,UserPrincipalName,EventType,Method,MethodKind,StepSucceeded,StepResult,ParentSignInStatus,ErrorCode,Application,IPAddress,CountedAsUsage' |
        Set-Content -Path $EventsCsvPath -Encoding UTF8
}

$RegisteredUsers | Export-Csv -Path $UsersCsvPath -NoTypeInformation -Encoding UTF8

# ============================================================
# 7. HTML PREPARATION
# ============================================================

function Join-DisplayValues {
    param([object[]]$Values)

    $items = @($Values | Where-Object { $_ } | ForEach-Object { [string]$_ })
    if ($items.Count -eq 0) { return '&mdash;' }
    return (($items | ForEach-Object { Convert-HtmlSafe $_ }) -join '<br>')
}

$SmsIncludedGroups = Join-DisplayValues @($SmsScope.IncludedGroups | ForEach-Object { $_.DisplayName })
$SmsExcludedGroups = Join-DisplayValues @($SmsScope.ExcludedGroups | ForEach-Object { $_.DisplayName })
$SmsIncludedUsers  = Join-DisplayValues @($SmsScope.IncludedUsers | ForEach-Object { Resolve-TargetName -TargetType 'user' -Id $_ })
$SmsExcludedUsers  = Join-DisplayValues @($SmsScope.ExcludedUsers | ForEach-Object { Resolve-TargetName -TargetType 'user' -Id $_ })

$VoiceIncludedGroups = Join-DisplayValues @($VoiceScope.IncludedGroups | ForEach-Object { $_.DisplayName })
$VoiceExcludedGroups = Join-DisplayValues @($VoiceScope.ExcludedGroups | ForEach-Object { $_.DisplayName })
$VoiceIncludedUsers  = Join-DisplayValues @($VoiceScope.IncludedUsers | ForEach-Object { Resolve-TargetName -TargetType 'user' -Id $_ })
$VoiceExcludedUsers  = Join-DisplayValues @($VoiceScope.ExcludedUsers | ForEach-Object { Resolve-TargetName -TargetType 'user' -Id $_ })

$PolicyRowsHtml = @"
<tr>
 <td><b>SMS</b></td>
 <td><span class='status-badge status-$($SmsState.ToLowerInvariant())'>$(Convert-HtmlSafe $SmsState)</span></td>
 <td>$(if ($SmsScope.IsAllUsers) { 'Yes' } else { 'No' })</td>
 <td>$SmsIncludedGroups</td>
 <td>$SmsIncludedUsers</td>
 <td>$SmsExcludedGroups</td>
 <td>$SmsExcludedUsers</td>
</tr>
<tr>
 <td><b>Voice</b></td>
 <td><span class='status-badge status-$($VoiceState.ToLowerInvariant())'>$(Convert-HtmlSafe $VoiceState)</span></td>
 <td>$(if ($VoiceScope.IsAllUsers) { 'Yes' } else { 'No' })</td>
 <td>$VoiceIncludedGroups</td>
 <td>$VoiceIncludedUsers</td>
 <td>$VoiceExcludedGroups</td>
 <td>$VoiceExcludedUsers</td>
</tr>
"@

$PolicyTargetRowsHtml = if ($PolicyTargets.Count -gt 0) {
    ($PolicyTargets | ForEach-Object {
        "<tr><td><b>$(Convert-HtmlSafe $_.Policy)</b></td><td>$(Convert-HtmlSafe $_.Assignment)</td><td>$(Convert-HtmlSafe $_.TargetType)</td><td>$(Convert-HtmlSafe $_.Target)</td></tr>"
    }) -join "`n"
}
else {
    "<tr><td colspan='4'>No configured SMS/Voice policy targets were returned.</td></tr>"
}

$CampaignTargetRowsHtml = if ($CampaignTargets.Count -gt 0) {
    ($CampaignTargets | ForEach-Object {
        $method = if ($_.AuthenticationMethod) { Convert-HtmlSafe $_.AuthenticationMethod } else { '&mdash;' }
        "<tr><td>$(Convert-HtmlSafe $_.Assignment)</td><td>$(Convert-HtmlSafe $_.TargetType)</td><td>$(Convert-HtmlSafe $_.Target)</td><td>$method</td></tr>"
    }) -join "`n"
}
else {
    "<tr><td colspan='4'>No Registration Campaign targets were returned.</td></tr>"
}

$MatchingEventRowsHtml = if ($MatchingEvents.Count -gt 0) {
    $eventGroups = @(
        $MatchingEvents |
            Group-Object UserPrincipalName |
            Sort-Object Name
    )

    ($eventGroups | ForEach-Object {
        $group = $_
        $events = @($group.Group | Sort-Object Time -Descending)
        $smsCount = @($events | Where-Object { $_.MethodKind -eq 'SMS' -and $_.CountedAsUsage }).Count
        $voiceCount = @($events | Where-Object { $_.MethodKind -eq 'Voice' -and $_.CountedAsUsage }).Count
        $countedCount = @($events | Where-Object { $_.CountedAsUsage }).Count
        $lastEvent = $events | Select-Object -First 1

        $detailsRows = ($events | ForEach-Object {
            $counted = if ($_.CountedAsUsage) { 'Yes' } else { 'No' }

            "<tr>" +
            "<td class='nowrap-value'>$(Convert-HtmlSafe $_.Time)</td>" +
            "<td>$(Convert-HtmlSafe $_.Method)</td>" +
            "<td>$(Convert-HtmlSafe $_.StepSucceeded)</td>" +
            "<td>$(Convert-HtmlSafe $_.StepResult)</td>" +
            "<td>$(Convert-HtmlSafe $_.ParentSignInStatus)</td>" +
            "<td>$(Convert-HtmlSafe $_.ErrorCode)</td>" +
            "<td>$(Convert-HtmlSafe $_.Application)</td>" +
            "<td>$(Convert-HtmlSafe $_.IPAddress)</td>" +
            "<td><b>$counted</b></td>" +
            "</tr>"
        }) -join "`n"

        $detailTable = @"
<details class='event-details'>
<summary>Show $($events.Count) sign-in event(s)</summary>
<div class='nested-tablewrap'>
<table class='nested-table'>
<thead><tr>
<th>Time</th><th>Method</th><th>Step succeeded</th><th>Step result</th><th>Parent sign-in</th><th>Error code</th><th>Application</th><th>IP</th><th>Counted</th>
</tr></thead>
<tbody>
$detailsRows
</tbody>
</table>
</div>
</details>
"@

        $groupUpn = [string]$group.Name
        $currentlyRegistered = if ($groupUpn -and $PhoneUserUpns.ContainsKey($groupUpn.ToLowerInvariant())) { 'Yes' } else { 'No' }

        "<tr>" +
        "<td class='account-cell'><b>$(Convert-HtmlSafe $group.Name)</b></td>" +
        "<td><span class='capability-badge capability-$($currentlyRegistered.ToLowerInvariant())'>$currentlyRegistered</span></td>" +
        "<td class='num'>$smsCount</td>" +
        "<td class='num'>$voiceCount</td>" +
        "<td class='num'><b>$countedCount</b></td>" +
        "<td class='nowrap-value'>$(Convert-HtmlSafe $lastEvent.Time)</td>" +
        "<td>$detailTable</td>" +
        "</tr>"
    }) -join "`n"
}
else {
    "<tr><td colspan='7'>No interactive SMS/Voice sign-in events were found in the selected period.</td></tr>"
}

$RegisteredUserRowsHtml = if ($RegisteredUsers.Count -gt 0) {
    ($RegisteredUsers | ForEach-Object {
        $admin = if ($_.IsAdmin) { 'Yes' } else { 'No' }
        $mfaCapable = if ($_.IsMfaCapable) { 'Yes' } else { 'No' }
        $passwordlessCapable = if ($_.IsPasswordlessCapable) { 'Yes' } else { 'No' }

        "<tr>" +
        "<td class='account-cell'><b>$(Convert-HtmlSafe $_.UserPrincipalName)</b><div class='sub'>$(Convert-HtmlSafe $_.DisplayName)</div></td>" +
        "<td class='num'>$($_.SmsSignIns)</td>" +
        "<td class='num'>$($_.VoiceSignIns)</td>" +
        "<td class='num'><b>$($_.TotalSignIns)</b></td>" +
        "<td><span class='dependency-badge dependency-$($_.PhoneDependent.ToLowerInvariant())'>$(Convert-HtmlSafe $_.PhoneDependent)</span></td>" +
        "<td><span class='alternative-badge alternative-$($_.AlternativeMfa.ToLowerInvariant())'>$(Convert-HtmlSafe $_.AlternativeMfa)</span><div class='sub'>$(Convert-HtmlSafe $_.AlternativeMfaMethods)</div></td>" +
        "<td>$(Convert-HtmlSafe $_.RegisteredMethods)</td>" +
        "<td><span class='capability-badge capability-$($mfaCapable.ToLowerInvariant())'>$mfaCapable</span></td>" +
        "<td><span class='capability-badge capability-$($passwordlessCapable.ToLowerInvariant())'>$passwordlessCapable</span></td>" +
        "<td>$(Convert-HtmlSafe $_.UserPreferredMethod)</td>" +
        "<td>$(Convert-HtmlSafe $_.SystemPreferredMethods)</td>" +
        "<td>$admin</td>" +
        "</tr>"
    }) -join "`n"
}
else {
    "<tr><td colspan='12'>No users with a registered phone authentication method were returned.</td></tr>"
}

$GeneratedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$SmsCardClass = if ($SmsState -eq 'enabled') { 'c-good' } else { 'c-disabled' }
$VoiceCardClass = if ($VoiceState -eq 'enabled') { 'c-good' } else { 'c-disabled' }
$CampaignCardClass = if ($CampaignStateRaw -eq 'enabled') { 'c-good' } elseif ($CampaignStateRaw -eq 'disabled') { 'c-disabled' } else { '' }

# ============================================================
# 8. HTML REPORT
# Template intentionally follows the visual model used by
# KerberosRC4Assessment.ps1: hero, cards, controls, and bordered tables.
# ============================================================

$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Microsoft Entra SMS &amp; Voice Assessment</title>
<style>
:root{
 --bg:#f3f6fa;--panel:#fff;--border:#d9e1ea;--text:#172033;--muted:#68758a;
 --blue:#0f4c78;--blue2:#1e73b7;--healthy:#169b62;--disabled:#667085;--warning:#e7a008
}
*{box-sizing:border-box}
body{margin:0;font-family:"Segoe UI",Arial,sans-serif;background:var(--bg);color:var(--text);font-size:13px}
.wrap{width:100%;max-width:none;margin:0;padding:24px}
.hero{background:linear-gradient(110deg,#103b60,#2378b8);color:#fff;border-radius:18px;padding:26px 30px;display:flex;justify-content:space-between;gap:30px;box-shadow:0 1px 2px rgba(16,24,40,.08)}
.hero h1{margin:0 0 8px;font-size:28px;font-weight:700}.hero p{margin:3px 0;color:#e7f1fa;max-width:980px;line-height:1.45}
.meta{text-align:right;min-width:250px;font-size:12px;line-height:1.5;color:#e7f1fa}.meta b{color:#fff}
.cards{display:grid;grid-template-columns:repeat(3,minmax(180px,1fr));gap:14px;margin:18px 0}
.card{background:#fff;border:1px solid var(--border);border-radius:14px;padding:16px 18px;border-left:5px solid #3b82f6;box-shadow:0 1px 2px rgba(16,24,40,.04)}
.card .l{color:var(--muted);font-size:12px}.card .n{font-size:24px;font-weight:700;margin-top:6px}.card .s{color:var(--muted);font-size:11px;margin-top:6px}
.c-good{border-left-color:var(--healthy)}.c-disabled{border-left-color:var(--disabled)}
.section{margin-top:24px}.section h2{font-size:18px;margin:0 0 10px}
.controls{background:#fff;border:1px solid var(--border);border-radius:14px;padding:13px 16px;display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin-bottom:16px}
input{min-width:360px;flex:1;border:1px solid #c9d3df;border-radius:8px;padding:9px 11px;background:#fff}
.tablewrap{width:100%;overflow-x:auto;overflow-y:visible;background:#fff;border:1px solid var(--border);border-radius:14px;box-shadow:0 1px 2px rgba(16,24,40,.04)}
table{border-collapse:collapse;width:100%;table-layout:auto;font-size:12px}th{position:sticky;top:0;z-index:2;background:#f7f9fc;text-align:left;padding:11px;border-bottom:1px solid var(--border);white-space:nowrap;color:#344054}
td{vertical-align:top;padding:10px 11px;border-bottom:1px solid #edf0f4;line-height:1.4}.sub{color:var(--muted);font-size:10.5px;margin-top:3px}.num{text-align:center;font-weight:700}
.account-cell,.account-cell b,.account-cell .sub{white-space:nowrap!important;word-break:normal!important;overflow-wrap:normal!important}.nowrap-value{white-space:nowrap!important}.mono{font-family:Consolas,"Courier New",monospace;font-size:11px}
.status-badge{display:inline-block;padding:4px 10px;border-radius:999px;font-weight:700;font-size:11px;border:1px solid;white-space:nowrap;min-width:82px;text-align:center}
.status-enabled{background:#e7f8ef;border-color:#6fd3a4;color:#067647}.status-disabled{background:#f2f4f7;border-color:#98a2b3;color:#475467}.status-unknown{background:#fff7d6;border-color:#f5c242;color:#7a4d00}
details{margin-top:12px;background:#fff;border:1px solid var(--border);border-radius:14px;padding:0;overflow:hidden;box-shadow:0 1px 2px rgba(16,24,40,.04)}
summary{cursor:pointer;font-weight:700;padding:13px 16px;background:#f7f9fc;border-bottom:1px solid var(--border)}
details .tablewrap{border:0;border-radius:0;box-shadow:none}
.event-details{margin:0;border:0;border-radius:8px;box-shadow:none;background:transparent}
.event-details summary{padding:7px 10px;border:1px solid #d9e1ea;border-radius:8px;background:#f7f9fc;font-size:11px;color:#0f4c78}
.event-details[open] summary{border-radius:8px 8px 0 0}
.nested-tablewrap{overflow-x:auto;border:1px solid #d9e1ea;border-top:0;border-radius:0 0 8px 8px;background:#fff}
.nested-table{font-size:11px;min-width:1100px}
.nested-table th{position:static;background:#fbfcfe;padding:8px}
.nested-table td{padding:8px}
.dependency-badge,.alternative-badge,.capability-badge{display:inline-block;padding:4px 10px;border-radius:999px;font-weight:700;font-size:11px;border:1px solid;white-space:nowrap}
.dependency-yes{background:#fff0e6;border-color:#fb923c;color:#b54708}
.dependency-no{background:#e7f8ef;border-color:#6fd3a4;color:#067647}
.alternative-yes,.capability-yes{background:#e7f8ef;border-color:#6fd3a4;color:#067647}
.alternative-no,.capability-no{background:#f2f4f7;border-color:#98a2b3;color:#475467}
.api-query{margin-top:10px;padding:10px 12px;border:1px solid var(--border);border-radius:10px;background:#f8fafc;color:#475467;font-family:Consolas,"Courier New",monospace;font-size:11px;overflow-wrap:anywhere}
footer{color:var(--muted);font-size:11px;margin-top:18px;line-height:1.5}
@media(max-width:1100px){.cards{grid-template-columns:1fr}.hero{flex-direction:column}.meta{text-align:left}.wrap{padding:14px}.tablewrap{overflow-x:auto}}
</style>
</head>
<body>
<div class="wrap">

<div class="hero">
 <div>
  <h1>Microsoft Entra SMS &amp; Voice Assessment</h1>
  <p>Authentication Methods Policy, Registration Campaign, interactive SMS/Voice activity, authentication readiness, and phone dependency.</p>
  <p><b>Tenant:</b> $(Convert-HtmlSafe $TenantId) &nbsp; | &nbsp; <b>Lookback:</b> $LookbackDays days</p>
 </div>
 <div class="meta">
  <b>Generated</b><br>$(Convert-HtmlSafe $GeneratedAt)<br><br>
  <b>Run as</b><br>$(Convert-HtmlSafe $RunAs)<br><br>
  <b>Version</b><br>$ScriptVersion
 </div>
</div>

<div class="cards">
 <div class="card $SmsCardClass"><div class="l">SMS Policy</div><div class="n">$(Convert-HtmlSafe $SmsState)</div></div>
 <div class="card $VoiceCardClass"><div class="l">Voice Policy</div><div class="n">$(Convert-HtmlSafe $VoiceState)</div></div>
 <div class="card $CampaignCardClass"><div class="l">Registration Campaign</div><div class="n">$(Convert-HtmlSafe $CampaignMode)</div><div class="s">Custom targeting: $CampaignCustomTargeting &nbsp; | &nbsp; Snooze: $(Convert-HtmlSafe $CampaignSnoozeDisplay) &nbsp; | &nbsp; Passkey opt-out: $(Convert-HtmlSafe $PasskeyDynamicMigrationDisplay)</div></div>
</div>

<div class="section">
<h2>Authentication Methods Policy</h2>
<div class="tablewrap">
<table>
<thead><tr><th>Method</th><th>State</th><th>All users</th><th>Included groups</th><th>Included users</th><th>Excluded groups</th><th>Excluded users</th></tr></thead>
<tbody>
$PolicyRowsHtml
</tbody>
</table>
</div>

<details open>
<summary>Show configured SMS/Voice policy targets</summary>
<div class="tablewrap">
<table>
<thead><tr><th>Policy</th><th>Assignment</th><th>Target type</th><th>Target</th></tr></thead>
<tbody>
$PolicyTargetRowsHtml
</tbody>
</table>
</div>
</details>
</div>

<div class="section">
<h2>Registration Campaign</h2>
<div class="tablewrap">
<table>
<thead><tr><th>Mode</th><th>Custom targeting</th><th>Snooze duration</th><th>Enforce after allowed snoozes</th><th>Passkey migration opt-out</th></tr></thead>
<tbody><tr>
<td><b>$(Convert-HtmlSafe $CampaignMode)</b></td>
<td>$(Convert-HtmlSafe $CampaignCustomTargeting)</td>
<td>$(Convert-HtmlSafe $CampaignSnoozeDisplay)</td>
<td>$(Convert-HtmlSafe $CampaignEnforceAfterSnoozesDisplay)</td>
<td><b>$(Convert-HtmlSafe $PasskeyDynamicMigrationStatus)</b><div class='sub'>Raw property: $(Convert-HtmlSafe $PasskeyDynamicMigrationRawDisplay)</div></td>
</tr></tbody>
</table>
</div>

<div class="api-query"><b>Graph query:</b> $(Convert-HtmlSafe $PasskeyOptOutGraphQuery) &nbsp; | &nbsp; <b>Result:</b> $(Convert-HtmlSafe $PasskeyDynamicMigrationValue)</div>

<details open>
<summary>Show Registration Campaign targets and options</summary>
<div class="tablewrap">
<table>
<thead><tr><th>Assignment</th><th>Target type</th><th>Target</th><th>Targeted authentication method</th></tr></thead>
<tbody>
$CampaignTargetRowsHtml
</tbody>
</table>
</div>
</details>
</div>

<div class="section">
<h2>Actual SMS/Voice usage</h2>
<details open>
<summary>Show SMS/Voice matching sign-in events</summary>
<div class="tablewrap">
<table>
<thead><tr><th>User</th><th>Phone registered now</th><th>SMS sign-ins</th><th>Voice sign-ins</th><th>Total counted</th><th>Last event</th><th>Sign-in details</th></tr></thead>
<tbody>
$MatchingEventRowsHtml
</tbody>
</table>
</div>
</details>
</div>

<div class="section">
<h2>Users with Phone Authentication Registered</h2>
<div class="controls">
 <input id="q" type="search" placeholder="Search user or registered method...">
</div>
<div class="tablewrap">
<table id="users">
<thead><tr><th>User</th><th>SMS sign-ins</th><th>Voice sign-ins</th><th>Total</th><th>Phone dependent</th><th>Alternative MFA</th><th>Registered methods</th><th>MFA capable</th><th>Passwordless capable</th><th>User preferred</th><th>System preferred</th><th>Admin</th></tr></thead>
<tbody>
$RegisteredUserRowsHtml
</tbody>
</table>
</div>
</div>

<footer>Generated by Invoke-EntraSmsVoiceAssessment.ps1 v$ScriptVersion. Read-only assessment.</footer>
</div>

<script>
const q=document.getElementById('q');
if(q){
 q.addEventListener('input',()=>{
  const term=(q.value||'').toLowerCase();
  document.querySelectorAll('#users tbody tr').forEach(r=>{
   r.style.display=r.innerText.toLowerCase().includes(term)?'':'none';
  });
 });
}
</script>
</body>
</html>
"@

$html | Set-Content -Path $HtmlPath -Encoding UTF8

Write-Host ''
Write-Host '=== Microsoft Entra SMS & Voice Assessment ===' -ForegroundColor White
Write-Host "SMS policy              : $SmsState"
Write-Host "Voice policy            : $VoiceState"
Write-Host "Registration Campaign   : $CampaignMode"
Write-Host "Custom targeting        : $CampaignCustomTargeting"
Write-Host "Passkey migration opt-out: $PasskeyDynamicMigrationDisplay"
Write-Host "Phone-registered users  : $($RegisteredUsers.Count)"
Write-Host "Matching sign-in events : $($MatchingEvents.Count)"
Write-Host ''
Write-Host "HTML                     : $HtmlPath" -ForegroundColor Green
Write-Host "Registered users CSV     : $UsersCsvPath" -ForegroundColor Green
Write-Host "Matching events CSV      : $EventsCsvPath" -ForegroundColor Green
Write-Host "Policy targets CSV       : $PolicyCsvPath" -ForegroundColor Green
Write-Host "Campaign targets CSV     : $CampaignCsvPath" -ForegroundColor Green

if ($OpenHtmlReport) {
    Start-Process $HtmlPath
}
