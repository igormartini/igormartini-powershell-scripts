<#
.SYNOPSIS
    Generates a hybrid user activity report using Active Directory
    and Microsoft Entra ID sign-in information.

.DESCRIPTION
    This script retrieves the most recent Active Directory lastLogon
    value across all Domain Controllers and compares it with Microsoft
    Entra ID lastSuccessfulSignInDateTime.

    The report generates:
    - CSV output
    - Executive HTML report
    - Status filter
    - Clickable column sorting
    - Progress bar during execution

.NOTES
    Author  : Igor Henrique Martini
    Website : https://igormartini.cloud

    Required Modules:
        ActiveDirectory
        Microsoft.Graph.Authentication
        Microsoft.Graph.Users

    Required Graph Permissions:
        User.Read.All
        AuditLog.Read.All

    Authentication:
        Interactive Microsoft Graph authentication.
        No App Registration required.
#>

# Import required PowerShell modules
Import-Module ActiveDirectory
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Users

# Generate output file names
$DateStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$CsvPath  = ".\Hybrid_LastKnownActivity_Report_$DateStamp.csv"
$HtmlPath = ".\Hybrid_LastKnownActivity_Report_$DateStamp.html"

# Capture execution metadata
$GeneratedAt = Get-Date -Format "dd-MMM-yyyy HH:mm:ss"
$ExecutedBy  = "$env:USERDOMAIN\$env:USERNAME"
$Computer    = $env:COMPUTERNAME

# Connect to Microsoft Graph using interactive authentication
Write-Progress -Id 1 -Activity "Microsoft Graph" -Status "Connecting to Microsoft Graph..." -PercentComplete 10

Connect-MgGraph `
    -Scopes "User.Read.All","AuditLog.Read.All" `
    -NoWelcome

Write-Progress -Id 1 -Activity "Microsoft Graph" -Status "Connected successfully." -PercentComplete 100
Start-Sleep -Milliseconds 400
Write-Progress -Id 1 -Activity "Microsoft Graph" -Completed

# Retrieve all Domain Controllers from the current domain
Write-Progress -Id 2 -Activity "Active Directory" -Status "Retrieving Domain Controllers..." -PercentComplete 10

$DomainControllers = Get-ADDomainController -Filter * |
    Select-Object -ExpandProperty HostName

$DomainControllerList = ($DomainControllers | Sort-Object) -join ", "

Write-Progress -Id 2 -Activity "Active Directory" -Status "Domain Controllers retrieved." -PercentComplete 100
Start-Sleep -Milliseconds 400
Write-Progress -Id 2 -Activity "Active Directory" -Completed

# Converts Active Directory FileTime values to DateTime
function Convert-ADFileTime {
    param($Value)

    if ($null -eq $Value -or $Value -eq 0) {
        return $null
    }

    return [DateTime]::FromFileTime([Int64]$Value)
}

# Formats dates consistently across the report
function Format-Date {
    param($Date)

    if ($null -eq $Date -or $Date -eq "") {
        return "N/A"
    }

    return ([datetime]$Date).ToString("dd-MMM-yyyy HH:mm")
}

# Determines the activity status based on the age of Last Known Activity
function Get-ActivityStatus {
    param($Date)

    if ($null -eq $Date -or $Date -eq "") {
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

# Retrieves the most recent lastLogon value across all Domain Controllers
function Get-MostRecentLastLogon {
    param(
        [string]$SamAccountName,
        [int]$UserIndex,
        [int]$TotalUsers
    )

    $Logons = @()
    $DcIndex = 0

    foreach ($DC in $DomainControllers) {

        $DcIndex++

        $OverallPercent = [int](($UserIndex / $TotalUsers) * 100)
        $DcPercent      = [int](($DcIndex / $DomainControllers.Count) * 100)

        Write-Progress `
            -Id 3 `
            -Activity "Scanning Active Directory lastLogon across all Domain Controllers" `
            -Status "User $UserIndex of $TotalUsers - $SamAccountName" `
            -PercentComplete $OverallPercent

        Write-Progress `
            -Id 4 `
            -ParentId 3 `
            -Activity "Current Domain Controller" `
            -Status "Scanning $DC ($DcIndex of $($DomainControllers.Count))" `
            -PercentComplete $DcPercent

        try {
            $User = Get-ADUser `
                -Server $DC `
                -Identity $SamAccountName `
                -Properties LastLogon

            $ConvertedDate = Convert-ADFileTime $User.LastLogon

            if ($null -ne $ConvertedDate) {
                $Logons += $ConvertedDate
            }
        }
        catch {
            continue
        }
    }

    Write-Progress -Id 4 -ParentId 3 -Activity "Current Domain Controller" -Completed

    if ($Logons.Count -gt 0) {
        return $Logons |
            Sort-Object -Descending |
            Select-Object -First 1
    }

    return $null
}

# Retrieve Microsoft Entra ID users and sign-in activity
Write-Progress `
    -Id 5 `
    -Activity "Microsoft Entra ID" `
    -Status "Retrieving users and sign-in activity..." `
    -PercentComplete 25

$EntraUsers = Get-MgUser `
    -All `
    -Property "UserPrincipalName,SignInActivity"

Write-Progress `
    -Id 5 `
    -Activity "Microsoft Entra ID" `
    -Status "Users and sign-in activity retrieved." `
    -PercentComplete 100

Start-Sleep -Milliseconds 400
Write-Progress -Id 5 -Activity "Microsoft Entra ID" -Completed

# Build a lookup table to improve performance when matching AD and Entra ID users
$EntraLookup = @{}

foreach ($User in $EntraUsers) {
    if ($User.UserPrincipalName) {
        $EntraLookup[$User.UserPrincipalName.ToLower()] = $User
    }
}

# Retrieve all enabled Active Directory users
Write-Progress `
    -Id 6 `
    -Activity "Active Directory" `
    -Status "Retrieving enabled AD users..." `
    -PercentComplete 40

$ADUsers = Get-ADUser `
    -Filter 'Enabled -eq $true' `
    -Properties UserPrincipalName

Write-Progress `
    -Id 6 `
    -Activity "Active Directory" `
    -Status "Enabled AD users retrieved." `
    -PercentComplete 100

Start-Sleep -Milliseconds 400
Write-Progress -Id 6 -Activity "Active Directory" -Completed

# Build the activity correlation dataset by combining AD and Entra ID information
$Report = @()
$UserIndex = 0
$TotalADUsers = $ADUsers.Count

foreach ($ADUser in $ADUsers) {

    $UserIndex++

    $UPN = $ADUser.UserPrincipalName
    $CloudUser = $null

    # Match the AD user with the corresponding Entra ID user by UPN
    if ($UPN) {
        $CloudUser = $EntraLookup[$UPN.ToLower()]
    }

    # Retrieve the most recent AD lastLogon across all Domain Controllers
    $ADLastLogon = Get-MostRecentLastLogon `
        -SamAccountName $ADUser.SamAccountName `
        -UserIndex $UserIndex `
        -TotalUsers $TotalADUsers

    # Retrieve the last successful Microsoft Entra ID sign-in
    $EntraLastSuccessful = $null

    if ($CloudUser -and $CloudUser.SignInActivity) {
        $EntraLastSuccessful = $CloudUser.SignInActivity.LastSuccessfulSignInDateTime
    }

    # Determine the most recent activity source
    #
    # Note:
    # lastNonInteractiveSignInDateTime is intentionally excluded because it
    # may include unsuccessful non-interactive authentication attempts.
    $ActivityDates = @()

    if ($ADLastLogon) {
        $ActivityDates += [datetime]$ADLastLogon
    }

    if ($EntraLastSuccessful) {
        $ActivityDates += [datetime]$EntraLastSuccessful
    }

    $LastKnownActivity = $null

    if ($ActivityDates.Count -gt 0) {
        $LastKnownActivity = $ActivityDates |
            Sort-Object -Descending |
            Select-Object -First 1
    }

    $Report += [PSCustomObject]@{
        DisplayName               = $ADUser.Name
        UserPrincipalName          = $UPN
        AD_LastLogon_AllDCs        = $ADLastLogon
        Entra_LastSuccessfulSignIn = $EntraLastSuccessful
        LastKnownActivity          = $LastKnownActivity
        ActivityStatus             = Get-ActivityStatus $LastKnownActivity
    }
}

Write-Progress -Id 3 -Activity "Scanning Active Directory lastLogon across all Domain Controllers" -Completed

# Export detailed results to CSV
$Report | Export-Csv $CsvPath -NoTypeInformation -Encoding UTF8

# Calculate executive summary metrics
$TotalUsers = $Report.Count
$Active     = ($Report | Where-Object { $_.ActivityStatus -eq "Active" }).Count
$Stale      = ($Report | Where-Object { $_.ActivityStatus -eq "Stale" }).Count
$Inactive   = ($Report | Where-Object { $_.ActivityStatus -eq "Inactive" }).Count
$NoActivity = ($Report | Where-Object { $_.ActivityStatus -eq "No Activity" }).Count

# Generate HTML table rows
$Rows = @()

foreach ($Item in ($Report | Sort-Object LastKnownActivity -Descending)) {

    switch ($Item.ActivityStatus) {
        "Active"      { $StatusClass = "status-active" }
        "Stale"       { $StatusClass = "status-stale" }
        "Inactive"    { $StatusClass = "status-inactive" }
        "No Activity" { $StatusClass = "status-none" }
        default       { $StatusClass = "status-none" }
    }

    $Rows += @"
<tr data-status="$($Item.ActivityStatus)">
<td>$($Item.DisplayName)</td>
<td>$($Item.UserPrincipalName)</td>
<td>$(Format-Date $Item.AD_LastLogon_AllDCs)</td>
<td>$(Format-Date $Item.Entra_LastSuccessfulSignIn)</td>
<td><b>$(Format-Date $Item.LastKnownActivity)</b></td>
<td><span class="$StatusClass">$($Item.ActivityStatus)</span></td>
</tr>
"@
}

# Build the executive HTML report
$Html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Hybrid Last Known Activity Report</title>

<style>
body { margin:0; background:#f4f6f8; font-family:Segoe UI,Arial,sans-serif; color:#1f2937; }
.header { background:linear-gradient(135deg,#1f2937,#2563eb); color:white; padding:28px 40px; }
.header h1 { margin:0; font-size:26px; }
.header p { margin:8px 0 0; color:#dbeafe; }
.container { padding:30px 40px; }
.cards { display:grid; grid-template-columns:repeat(5,1fr); gap:16px; margin-bottom:25px; }
.card { background:white; border-radius:12px; padding:18px; box-shadow:0 2px 8px rgba(0,0,0,.08); }
.card-title { font-size:12px; color:#6b7280; text-transform:uppercase; }
.card-value { font-size:28px; font-weight:700; margin-top:8px; }
.note { margin-bottom:16px; background:#eff6ff; border-left:4px solid #2563eb; padding:14px 16px; border-radius:8px; font-size:14px; }
.legend { margin-bottom:16px; background:white; border-radius:8px; padding:12px 15px; box-shadow:0 2px 8px rgba(0,0,0,.08); font-size:13px; }
.legend-title { font-weight:700; margin-bottom:8px; }
.legend-grid { display:grid; grid-template-columns:1fr 1fr; gap:8px 18px; }
.toolbar { margin-bottom:16px; background:white; border-radius:8px; padding:12px 15px; box-shadow:0 2px 8px rgba(0,0,0,.08); font-size:13px; }
.toolbar select { padding:6px 10px; border:1px solid #d1d5db; border-radius:6px; margin-left:8px; }
table { width:100%; border-collapse:collapse; background:white; border-radius:12px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,.08); }
th { background:#111827; color:white; text-align:left; padding:12px; font-size:13px; cursor:pointer; user-select:none; }
th:hover { background:#1f2937; }
td { padding:11px 12px; border-bottom:1px solid #e5e7eb; font-size:13px; }
tr:hover { background:#f9fafb; }
.status-active,.status-stale,.status-inactive,.status-none { padding:5px 10px; border-radius:999px; font-weight:600; font-size:12px; white-space:nowrap; }
.status-active { background:#dcfce7; color:#166534; }
.status-stale { background:#fef3c7; color:#92400e; }
.status-inactive { background:#fee2e2; color:#991b1b; }
.status-none { background:#e5e7eb; color:#374151; }
.footer { margin-top:30px; font-size:12px; color:#6b7280; border-top:1px solid #d1d5db; padding-top:15px; line-height:1.6; }
</style>
</head>

<body>

<div class="header">
    <h1>Hybrid Last Known Activity Report</h1>
    <p>Active Directory + Microsoft Entra ID user activity overview</p>
</div>

<div class="container">

    <div class="cards">
        <div class="card"><div class="card-title">Total Users</div><div class="card-value">$TotalUsers</div></div>
        <div class="card"><div class="card-title">Active</div><div class="card-value">$Active</div></div>
        <div class="card"><div class="card-title">Stale</div><div class="card-value">$Stale</div></div>
        <div class="card"><div class="card-title">Inactive</div><div class="card-value">$Inactive</div></div>
        <div class="card"><div class="card-title">No Activity</div><div class="card-value">$NoActivity</div></div>
    </div>

    <div class="note">
        <b>Report logic:</b> Last Known Activity is calculated using the most recent value between
        Active Directory <b>lastLogon</b> across all Domain Controllers and Microsoft Entra ID
        <b>lastSuccessfulSignInDateTime</b>. Non-interactive sign-in activity is not used in this
        calculation because it may include unsuccessful authentication attempts.
    </div>

    <div class="legend">
        <div class="legend-title">Status Legend</div>
        <div class="legend-grid">
            <div><span class="status-active">Active</span> Activity detected within the last 30 days.</div>
            <div><span class="status-inactive">Inactive</span> No activity detected for more than 90 days.</div>
            <div><span class="status-stale">Stale</span> Activity detected between 31 and 90 days ago.</div>
            <div><span class="status-none">No Activity</span> No AD or Entra ID activity found.</div>
        </div>
    </div>

    <div class="toolbar">
        <b>Filter by Status:</b>
        <select id="statusFilter" onchange="filterStatus()">
            <option value="All">All</option>
            <option value="Active">Active</option>
            <option value="Stale">Stale</option>
            <option value="Inactive">Inactive</option>
            <option value="No Activity">No Activity</option>
        </select>
    </div>

    <table id="activityTable">
        <thead>
            <tr>
                <th onclick="sortTable(0)">Display Name</th>
                <th onclick="sortTable(1)">User Principal Name</th>
                <th onclick="sortTable(2)">AD LastLogon Across All DCs</th>
                <th onclick="sortTable(3)">Entra Last Successful Sign-In</th>
                <th onclick="sortTable(4)">Last Known Activity</th>
                <th onclick="sortTable(5)">Status</th>
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
        Domain Controllers scanned: <b>$DomainControllerList</b><br>
        CSV output: <b>$CsvPath</b>
    </div>

</div>

<script>
var sortDirection = {};

function filterStatus() {
    var selected = document.getElementById("statusFilter").value;
    var rows = document.querySelectorAll("#activityTable tbody tr");

    rows.forEach(function(row) {
        var status = row.getAttribute("data-status");

        if (selected === "All" || status === selected) {
            row.style.display = "";
        } else {
            row.style.display = "none";
        }
    });
}

function sortTable(columnIndex) {
    var table = document.getElementById("activityTable");
    var tbody = table.tBodies[0];
    var rows = Array.prototype.slice.call(tbody.rows);

    sortDirection[columnIndex] = !sortDirection[columnIndex];

    rows.sort(function(a, b) {
        var aText = a.cells[columnIndex].innerText.trim();
        var bText = b.cells[columnIndex].innerText.trim();

        var statusOrder = {
            "Active": 1,
            "Stale": 2,
            "Inactive": 3,
            "No Activity": 4
        };

        if (columnIndex === 5) {
            aText = statusOrder[aText] || 99;
            bText = statusOrder[bText] || 99;
        }

        var aDate = Date.parse(aText);
        var bDate = Date.parse(bText);

        if (!isNaN(aDate) && !isNaN(bDate)) {
            aText = aDate;
            bText = bDate;
        }

        if (aText < bText) {
            return sortDirection[columnIndex] ? -1 : 1;
        }

        if (aText > bText) {
            return sortDirection[columnIndex] ? 1 : -1;
        }

        return 0;
    });

    rows.forEach(function(row) {
        tbody.appendChild(row);
    });
}
</script>

</body>
</html>
"@

# Save HTML report
$Html | Out-File $HtmlPath -Encoding UTF8

# Display generated file locations
Write-Host "CSV generated : $CsvPath" -ForegroundColor Green
Write-Host "HTML generated: $HtmlPath" -ForegroundColor Green
