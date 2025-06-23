<#
.SYNOPSIS
    Audits Active Directory users and service accounts across one or more domains,
    with per-OU or domain-level summaries and CSV export.

.DESCRIPTION
    This script connects to one or more Active Directory domains and retrieves a unified view
    of user and service account metadata. It calculates totals and classifies accounts by:
        - Activity (Active, Inactive, Never Logged In)
        - Managed Service Accounts (MSA)
        - Group Managed Service Accounts (gMSA)
        - PasswordNeverExpires flag
        - Naming pattern matches (optional)

    You can:
        - Target specific domains or scan the full forest
        - Provide wildcard-based name patterns to flag service accounts
        - Choose per-OU or summary reporting view
        - Automatically export results to a timestamped CSV

.PARAMETER SpecificDomains
    Optional. An array of fully qualified domain names to audit (e.g., "corp.domain.local").
    If omitted, the script audits all domains in the current forest.

.PARAMETER UserServiceAccountNamesLike
    Optional. Wildcard patterns (e.g., "*svc*", "*_bot") to match account names that represent
    service accounts. Used to classify matching users under ServiceAccountsPatternMatched.

.PARAMETER Mode
    Required. Selects output format:
        - 'UserPerOU': detailed counts per Organizational Unit (OU)
        - 'Summary': consolidated view per domain

.EXAMPLE
    .\Audit-ADUsers.ps1 -SpecificDomains "corp.domain.local" -UserServiceAccountNamesLike "*svc*","*_bot" -Mode UserPerOU

    This command:
        - Targets only corp.domain.local
        - Scans for accounts whose Name matches "*svc*" or "*_bot"
        - Classifies and counts users by OU
        - Outputs results to .\ADReports\UserAudit_UserPerOU_<timestamp>.csv

.EXAMPLE
    .\Audit-ADUsers.ps1

    This default call:
        - Targets all domains in the forest
        - Skips name-based pattern matching
        - Defaults to UserPerOU mode
        - Outputs results to .\ADReports\UserAudit_UserPerOU_<timestamp>.csv

.NOTES
    Script Requirements:
        - PowerShell 5.1 or later
        - RSAT: Active Directory module installed (ActiveDirectory)
        - Appropriate permissions to query each domain

    Culture is temporarily forced to en-US during execution to ensure consistent timestamp parsing.
#>


param (
    [string[]]$UserServiceAccountNamesLike = @(),
    [string[]]$SpecificDomains,
    [ValidateSet("UserPerOU", "Summary")]
    [string]$Mode = "UserPerOU"
)

function Initialize-Prerequisites {
    $requiredPSVersion = [Version]"5.1"
    $moduleName = "ActiveDirectory"

    if ($PSVersionTable.PSVersion -lt $requiredPSVersion) {
        Write-Error "PowerShell $requiredPSVersion or higher is required. Current version: $($PSVersionTable.PSVersion)"
        exit
    }

    try {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            Write-Error "Required module '$moduleName' not found. Please install RSAT: Active Directory Tools."
            exit
        }
        Import-Module $moduleName -ErrorAction Stop
    } catch {
        Write-Error "Failed to import '$moduleName'. Ensure it's installed and accessible. $_"
        exit
    }

    # Culture preservation
    $script:OriginalCulture = [System.Globalization.CultureInfo]::CurrentCulture
    $script:OriginalUICulture = [System.Globalization.CultureInfo]::CurrentUICulture

    [System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'

    Write-Host "Prerequisites validated. Environment initialized." -ForegroundColor Green
}

Initialize-Prerequisites

# Create output directory if needed
$outputPath = ".\ADReports"
if (-not (Test-Path $outputPath)) { New-Item -Path $outputPath -ItemType Directory | Out-Null }

# =====================
# Helper Functions
# =====================

function Get-OUFromDN {
    param ([string]$dn)
    ($dn -split '(?<!\\),')[1..($dn.Count - 1)] -join ','
}

function Test-ManagedServiceAccount {
    param ([string]$SamAccountName, [string[]]$MSASet)
    return $MSASet -contains $SamAccountName
}

function Test-GroupManagedServiceAccount {
    param ([string]$SamAccountName, [string[]]$GMSASet)
    return $GMSASet -contains $SamAccountName
}

function Test-NonExpiringUser {
    param ([string]$SamAccountName, [string[]]$NoExpireSet)
    return $NoExpireSet -contains $SamAccountName
}

function Test-PatternMatchedUser {
    param ([string]$SamAccountName, [string[]]$PatternSet)
    return $PatternSet -contains $SamAccountName
}

function Get-UsersAsServiceAccount {
    param (
        [string[]]$NamePatterns,
        [string]$Domain
    )

    if (-not $NamePatterns -or $NamePatterns.Count -eq 0) {
        return @()  # nothing to do
    }

    $subs = @()
    foreach ($pattern in $NamePatterns) {
        Write-Host "[$Domain] Searching for users like '$pattern'..." -ForegroundColor Yellow
        try {
            $usersFound = Get-ADUser -Server $Domain -Filter "Name -like '$($pattern.Trim())'" `
                -Properties Name, SamAccountName, DistinguishedName, Enabled, LastLogonTimestamp, PasswordNeverExpires, ServicePrincipalName |
                Select-Object Name, SamAccountName, DistinguishedName, Enabled,
                              @{Name="LastLogonDate";Expression={[DateTime]::FromFileTime($_.LastLogonTimestamp)}},
                              PasswordNeverExpires,
                              @{Name="ServicePrincipalNames";Expression={($_.ServicePrincipalName -join ";")}}

            $subs += $usersFound
        } catch {
            Write-Warning "[$Domain] Error searching pattern '$pattern': $_"
        }
    }
    return $subs
}

# =====================
# Main Logic
# =====================

$logonThreshold = (Get-Date).AddDays(-180)
$summary = @()

$domainsToAudit = if ($SpecificDomains) {
    $SpecificDomains
} else {
    [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Domains | ForEach-Object { $_.Name }
}

foreach ($domain in $domainsToAudit) {
    Write-Host "Auditing domain: $domain" -ForegroundColor Cyan

    try {
        # Preload reference data
        $MSASet = Get-ADServiceAccount -Server $domain -Filter { ObjectClass -eq 'msDS-ManagedServiceAccount' } |
                  Select-Object -ExpandProperty SamAccountName
        $GMSASet = Get-ADServiceAccount -Server $domain -Filter { ObjectClass -eq 'msDS-GroupManagedServiceAccount' } |
                   Select-Object -ExpandProperty SamAccountName
        $NoExpireSet = Get-ADUser -Server $domain -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } |
                       Select-Object -ExpandProperty SamAccountName

        # Get pattern-matched service accounts
        $PatternMatches = Get-UsersAsServiceAccount -NamePatterns $UserServiceAccountNamesLike -Domain $domain
        $PatternSet = $PatternMatches.SamAccountName | Sort-Object -Unique

        # Get users
        $userAccounts = Get-ADUser -Server $domain -Filter { Enabled -eq $true } `
            -Properties SamAccountName, DistinguishedName, LastLogonTimestamp

        $msaObjects  = @(Get-ADServiceAccount -Server $domain -Filter { ObjectClass -eq 'msDS-ManagedServiceAccount' })
        $gmsaObjects = @(Get-ADServiceAccount -Server $domain -Filter { ObjectClass -eq 'msDS-GroupManagedServiceAccount' })

        $serviceAccounts = $msaObjects + $gmsaObjects | ForEach-Object {
            [PSCustomObject]@{
                SamAccountName     = $_.SamAccountName
                DistinguishedName  = $_.DistinguishedName
                LastLogonTimestamp = $_.LastLogonTimestamp
            }
        }

        $users = $userAccounts + $serviceAccounts

        foreach ($user in $users) {
            $sam = $user.SamAccountName
            $ou  = Get-OUFromDN $user.DistinguishedName

            $entry = $summary | Where-Object { $_.Domain -eq $domain -and $_.OU -eq $ou }
            if (-not $entry) {
                $entry = [PSCustomObject]@{
                    Domain                              = $domain
                    OU                                  = $ou
                    TotalUsers                          = 0
                    ActiveUsers                         = 0
                    InactiveUsers                       = 0
                    NeverLoggedInUsers                  = 0
                    ServiceAccountsManaged              = 0
                    ServiceAccountsGroupManaged         = 0
                    ServiceAccountsPasswordNeverExpires = 0
                    ServiceAccountsPatternMatched       = 0
                }
                $summary += $entry
            }

            $entry.TotalUsers++
            if ($user.LastLogonTimestamp) {
                if ($user.LastLogonTimestamp -ge $logonThreshold.ToFileTime()) {
                    $entry.ActiveUsers++
                } else {
                    $entry.InactiveUsers++
                }
            } else {
                $entry.NeverLoggedInUsers++
            }

            if (Test-ManagedServiceAccount      $sam $MSASet)      { $entry.ServiceAccountsManaged++ }
            elseif (Test-GroupManagedServiceAccount $sam $GMSASet)     { $entry.ServiceAccountsGroupManaged++ }
            if (Test-NonExpiringUser            $sam $NoExpireSet) { $entry.ServiceAccountsPasswordNeverExpires++ }
            if (Test-PatternMatchedUser         $sam $PatternSet)  { $entry.ServiceAccountsPatternMatched++ }
        }
    } catch {
        Write-Warning "Failed processing domain $domain : $_"
    }
}

# =====================
# Report Output
# =====================

# Create unique filename with timestamp
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$fileName = "UserAudit_${Mode}_$timestamp.csv"
$fullExportPath = Join-Path -Path $outputPath -ChildPath $fileName

switch ($Mode) {

    "UserPerOU" {
        Write-Host "OU Summary Report" -ForegroundColor Green
        $summary | Sort-Object Domain, OU | Format-Table -AutoSize
        $summary | Sort-Object Domain, OU | Export-Csv -Path $fullExportPath -NoTypeInformation -Encoding UTF8
    }
    "Summary" {
        $summaryGrouped = $summary |
            Group-Object Domain |
            ForEach-Object {
                [PSCustomObject]@{
                    Domain                              = $_.Name
                    TotalUsers                          = ($_.Group | Measure-Object TotalUsers -Sum).Sum
                    ActiveUsers                         = ($_.Group | Measure-Object ActiveUsers -Sum).Sum
                    InactiveUsers                       = ($_.Group | Measure-Object InactiveUsers -Sum).Sum
                    NeverLoggedInUsers                  = ($_.Group | Measure-Object NeverLoggedInUsers -Sum).Sum
                    ServiceAccountsManaged              = ($_.Group | Measure-Object ServiceAccountsManaged -Sum).Sum
                    ServiceAccountsGroupManaged         = ($_.Group | Measure-Object ServiceAccountsGroupManaged -Sum).Sum
                    ServiceAccountsPasswordNeverExpires = ($_.Group | Measure-Object ServiceAccountsPasswordNeverExpires -Sum).Sum
                    ServiceAccountsPatternMatched       = ($_.Group | Measure-Object ServiceAccountsPatternMatched -Sum).Sum
                }
            }
        
        $summaryGrouped | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
        Write-Host "Domain Summary Report" -ForegroundColor Green
        $summaryGrouped | Sort-Object Domain | Format-Table -AutoSize
        $summaryGrouped | Export-Csv -Path $fullExportPath -NoTypeInformation -Encoding UTF8
    }
}

Write-Host "Results have been saved into $outputPath. Please send all the files within the directory to your Rubrik Sales representative." -ForegroundColor Green

# Reset Culture settings back to original value
[System.Threading.Thread]::CurrentThread.CurrentCulture = $OriginalCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $OriginalUICulture
