# Import required modules
Import-Module ActiveDirectory
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Users

# Output files
$DateStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$CsvPath  = ".\Hybrid_LastKnownActivity_Report_$DateStamp.csv"
$HtmlPath = ".\Hybrid_LastKnownActivity_Report_$DateStamp.html"

# Execution info
$GeneratedAt = Get-Date -Format "dd-MMM-yyyy HH:mm:ss"
$ExecutedBy  = "$env:USERDOMAIN\$env:USERNAME"
$Computer    = $env:COMPUTERNAME

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All" -NoWelcome

# Get Domain Controllers
$DomainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName

function Convert-ADFileTime {
    param($Value)

    if (!$Value -or $Value -eq 0) {
        return $null
    }

    [DateTime]::FromFileTime($Value)
}

function Format-Date {
    param($Date)

    if (!$Date) {
        return "N/A"
    }

    ([datetime]$Date).ToString("dd-MMM-yyyy HH:mm")
}

function Get-ActivityStatus {
    param($Date)

    if (!$Date) {
        return "No Activity"
    }

    $Days = ((Get-Date) - ([datetime]$Date)).Days

    if ($Days -le 30) {
        return "Active"
    }
    elseif ($Days -le 90) {
        return "Stale"
    }
    else {
        return "Inactive"
    }
}

function Get-MostRecentLastLogon {
    param([string]$SamAccountName)

    $LastLogons = foreach ($DC in $DomainControllers) {
        try {
            $User = Get-ADUser -Server $DC -Identity $SamAccountName -Properties LastLogon
            Convert-ADFileTime $User.LastLogon
        }
        catch {
            $null
        }
    }

    $LastLogons |
        Where-Object { $_ } |
        Sort-Object -Descending |
        Select-Object -First 1
}

# Retrieve Entra ID users
$EntraUsers = Get-MgUser -All -Property "UserPrincipalName,SignInActivity"

# Create Entra lookup table for performance
$EntraLookup = @{}

foreach ($User in $EntraUsers) {
    if ($User.UserPrincipalName) {
        $EntraLookup[$User.UserPrincipalName.ToLower()] = $User
    }
}

# Retrieve enabled AD users
$ADUsers = Get-ADUser -Filter 'Enabled -eq $true' -Properties UserPrincipalName

# Build report
$Report = foreach ($ADUser in $ADUsers) {

    $UPN = $ADUser.UserPrincipalName
    $CloudUser = $null

    if ($UPN) {
        $CloudUser = $EntraLookup[$UPN.ToLower()]
    }

    $ADLastLogon = Get-MostRecentLastLogon -SamAccountName $ADUser.SamAccountName

    $EntraLastSuccessful = $null

    if ($CloudUser -and $CloudUser.SignInActivity) {
        $EntraLastSuccessful = $CloudUser.SignInActivity.LastSuccessfulSignInDateTime
    }

    $LastKnownActivity =
        @(
            $ADLastLogon
            $EntraLastSuccessful
        ) |
        Where-Object { $_ } |
        Sort-Object -Descending |
        Select-Object -First 1

    $Status = Get-ActivityStatus $LastKnownActivity

    [PSCustomObject]@{
        DisplayName                  = $ADUser.Name
        UserPrincipalName             = $UPN
        AD_LastLogon_AllDCs           = $ADLastLogon
        Entra_LastSuccessfulSignIn    = $EntraLastSuccessful
        LastKnownActivity             = $LastKnownActivity
        ActivityStatus                = $Status
    }
}

# Export CSV
$Report |
    Export-Csv $CsvPath -NoTypeInformation -Encoding UTF8

# Summary
$TotalUsers = $Report.Count
$Active     = ($Report | Where-Object ActivityStatus -eq "Active").Count
$Stale      = ($Report | Where-Object ActivityStatus -eq "Stale").Count
$Inactive   = ($Report | Where-Object ActivityStatus -eq "Inactive").Count
$NoActivity = ($Report | Where-Object ActivityStatus -eq "No Activity").Count

# HTML rows
$Rows = foreach ($Item in $Report | Sort-Object LastKnownActivity -Descending) {

    $StatusClass = switch ($Item.ActivityStatus) {
        "Active"      { "status-active" }
        "Stale"       { "status-stale" }
        "Inactive"    { "status-inactive" }
        "No Activity" { "status-none" }
    }

@"
<tr>
    <td>$($Item.DisplayName)</td>
    <td>$($Item.UserPrincipalName)</td>
    <td>$(Format-Date $Item.AD_LastLogon_AllDCs)</td>
    <td>$(Format-Date $Item.Entra_LastSuccessfulSignIn)</td>
    <td><b>$(Format-Date $Item.LastKnownActivity)</b></td>
    <td><span class="$StatusClass">$($Item.ActivityStatus)</span></td>
</tr>
"@
}

# HTML report
$Html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Hybrid Last Known Activity Report</title>

<style>
body {
    margin: 0;
    background: #f4f6f8;
    font-family: Segoe UI, Arial, sans-serif;
    color: #1f2937;
}

.header {
    background: linear-gradient(135deg, #1f2937, #2563eb);
    color: white;
    padding: 28px 40px;
}

.header h1 {
    margin: 0;
    font-size: 26px;
}

.header p {
    margin: 8px 0 0;
    color: #dbeafe;
}

.container {
    padding: 30px 40px;
}

.cards {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 16px;
    margin-bottom: 25px;
}

.card {
    background: white;
    border-radius: 12px;
    padding: 18px;
    box-shadow: 0 2px 8px rgba(0,0,0,.08);
}

.card-title {
    font-size: 12px;
    color: #6b7280;
    text-transform: uppercase;
}

.card-value {
    font-size: 28px;
    font-weight: 700;
    margin-top: 8px;
}

table {
    width: 100%;
    border-collapse: collapse;
    background: white;
    border-radius: 12px;
    overflow: hidden;
    box-shadow: 0 2px 8px rgba(0,0,0,.08);
}

th {
    background: #111827;
    color: white;
    text-align: left;
    padding: 12px;
    font-size: 13px;
}

td {
    padding: 11px 12px;
    border-bottom: 1px solid #e5e7eb;
    font-size: 13px;
}

tr:hover {
    background: #f9fafb;
}

.status-active,
.status-stale,
.status-inactive,
.status-none {
    padding: 5px 10px;
    border-radius: 999px;
    font-weight: 600;
    font-size: 12px;
}

.status-active {
    background: #dcfce7;
    color: #166534;
}

.status-stale {
    background: #fef3c7;
    color: #92400e;
}

.status-inactive {
    background: #fee2e2;
    color: #991b1b;
}

.status-none {
    background: #e5e7eb;
    color: #374151;
}

.footer {
    margin-top: 30px;
    font-size: 12px;
    color: #6b7280;
    border-top: 1px solid #d1d5db;
    padding-top: 15px;
}

.note {
    margin-bottom: 20px;
    background: #eff6ff;
    border-left: 4px solid #2563eb;
    padding: 14px 16px;
    border-radius: 8px;
    font-size: 14px;
}
</style>
</head>

<body>

<div class="header">
    <h1>Hybrid Last Known Activity Report</h1>
    <p>Active Directory + Microsoft Entra ID user activity overview</p>
</div>

<div class="container">

    <div class="cards">
        <div class="card">
            <div class="card-title">Total Users</div>
            <div class="card-value">$TotalUsers</div>
        </div>

        <div class="card">
            <div class="card-title">Active</div>
            <div class="card-value">$Active</div>
        </div>

        <div class="card">
            <div class="card-title">Stale</div>
            <div class="card-value">$Stale</div>
        </div>

        <div class="card">
            <div class="card-title">Inactive</div>
            <div class="card-value">$Inactive</div>
        </div>

        <div class="card">
            <div class="card-title">No Activity</div>
            <div class="card-value">$NoActivity</div>
        </div>
    </div>

    <div class="note">
        <b>Report logic:</b> Last Known Activity is calculated using the most recent value between
        Active Directory <b>lastLogon</b> across all Domain Controllers and Microsoft Entra ID
        <b>lastSuccessfulSignInDateTime</b>.
    </div>

    <table>
        <thead>
            <tr>
                <th>Display Name</th>
                <th>User Principal Name</th>
                <th>AD LastLogon Across All DCs</th>
                <th>Entra Last Successful Sign-In</th>
                <th>Last Known Activity</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            $($Rows -join "`n")
        </tbody>
    </table>

    <div class="footer">
        Generated on: <b>$GeneratedAt</b><br>
        Executed by: <b>$ExecutedBy</b><br>
        Computer: <b>$Computer</b><br>
        Domain Controllers scanned: <b>$($DomainControllers.Count)</b><br>
        CSV output: <b>$CsvPath</b>
    </div>

</div>

</body>
</html>
"@

$Html | Out-File $HtmlPath -Encoding UTF8

Write-Host "CSV generated : $CsvPath" -ForegroundColor Green
Write-Host "HTML generated: $HtmlPath" -ForegroundColor Green