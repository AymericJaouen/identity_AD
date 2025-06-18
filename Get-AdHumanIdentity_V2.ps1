<#
.SYNOPSIS
    Active Directory Domain User and Service Account Audit Script

.DESCRIPTION
    This script audits one or more Active Directory domains in a Forest to:
    - Identify enabled user accounts
    - Analyze user logon activity (active, inactive, never logged in)
    - Optionally filter and export service accounts by naming patterns
    - Summarize results by OU or by Domain
    - Provide per-domain statistics on service accounts and password policies

.PARAMETER UserServiceAccountNamesLike
    Optional. An array of wildcard patterns to identify potential service accounts (e.g. "*svc*", "*_sa").

.PARAMETER SpecificDomains
    Optional. An array of AD domain names to target. If omitted, all domains in the current forest will be scanned.

.PARAMETER Mode
    Required. Defines the report output style.
        - "UserPerOU": Shows total, active, inactive, and never-logged-in users per OU
        - "Summary"  : Shows a per-domain summary only (aggregate user stats)

.OUTPUT
    CSV files saved to the "ADReports" directory containing:
        - OU-level or domain-level user logon summaries
        - Matched service account exports
        - Per-domain service account policy summary (MSAs, gMSAs, non-expiring users)

.EXAMPLE
    .\Audit-AD.ps1 -Mode Summary

    Runs a forest-wide scan and produces a summary of user login stats and service account stats per domain.

.EXAMPLE
    .\Audit-AD.ps1 -SpecificDomains @("contoso.com", "fabrikam.com") -UserServiceAccountNamesLike @("*svc*", "*sys*") -Mode UserPerOU

    Scans only the specified domains, exports user login activity per OU, and finds service accounts matching the provided patterns.

.NOTES
    Author: Aymeric ✨  
    Created: 18/06/2025
    Requires: ActiveDirectory module (RSAT)
#>

param (
    [string[]]$UserServiceAccountNamesLike,
    [string[]]$SpecificDomains,
    [ValidateSet("UserPerOU", "Summary")]
    [string]$Mode = "UserPerOU"
)

# Save the current culture so it can be restored later
$CurrentCulture = [System.Globalization.CultureInfo]::CurrentCulture

# Ensure output culture is consistent
[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
[System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'

$date = Get-Date
$fileDate = $date.ToString("yyyy-MM-dd_HHmm")
$logonThreshold = (Get-Date).AddDays(-180).ToFileTime()
$summary = @()

# Create output directory if needed
$outputPath = ".\ADReports"
if (-not (Test-Path $outputPath)) { New-Item -Path $outputPath -ItemType Directory | Out-Null }

# Helper: Extract OU from DN
function Get-OUFromDN($dn) {
    ($dn -split '(?<!\\),')[1..($dn.Count - 1)] -join ','
}

# Function: Export filtered users matching naming patterns
function Get-UsersAsServiceAccount {
    param (
        [string[]]$NamePatterns,
        [string]$Domain,
        [string]$OutputFile
    )
    $subs = @()
    foreach ($pattern in $NamePatterns) {
        Write-Host "[$Domain] Searching for users like '$pattern'..." -ForegroundColor Yellow
        try {
            $usersFound = Get-ADUser -Server $Domain -Filter "Name -like '$($pattern.Trim())'" `
                -Properties Name, DistinguishedName, Enabled, LastLogonTimestamp, PasswordNeverExpires, ServicePrincipalName |
                Select-Object Name, DistinguishedName, Enabled, @{Name="LastLogonDate";Expression={[DateTime]::FromFileTime($_.LastLogonTimestamp)}}, PasswordNeverExpires, @{Name="ServicePrincipalNames";Expression={ $_.ServicePrincipalName -join ";" }}

            $subs += $usersFound
        } catch {
            Write-Warning "[$Domain] Error searching pattern '$pattern': $_"
        }
    }
    if ($subs.Count -gt 0) {
        $subs | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
        Write-Host "[$Domain] Exported $($subs.Count) service accounts to: $OutputFile" -ForegroundColor Green
    } else {
        Write-Host "[$Domain] No service accounts matched." -ForegroundColor Cyan
    }
}

# Collect domains
if ($SpecificDomains) {
    $domainsToScan = $SpecificDomains
} else {
    $domainsToScan = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Domains | ForEach-Object { $_.Name }
}

# Loop over each domain
foreach ($domainName in $domainsToScan) {
    Write-Host "`n🔎 Processing domain: $domainName" -ForegroundColor Cyan

    # Export service accounts if patterns are given
    if ($UserServiceAccountNamesLike) {
        $svcOutFile = Join-Path $outputPath "svc_accounts_$($domainName.Replace('.', '_'))_$fileDate.csv"
        Get-UsersAsServiceAccount -NamePatterns $UserServiceAccountNamesLike -Domain $domainName -OutputFile $svcOutFile
    }

    try {
        $users = Get-ADUser -Server $domainName -Filter {Enabled -eq $true} -Properties LastLogonTimestamp, DistinguishedName

        foreach ($user in $users) {
            $ou = Get-OUFromDN $user.DistinguishedName
            $entry = $summary | Where-Object { $_.Domain -eq $domainName -and $_.OU -eq $ou }
            if (-not $entry) {
                $entry = [PSCustomObject]@{
                    Domain             = $domainName
                    OU                 = $ou
                    TotalUsers         = 0
                    ActiveUsers        = 0
                    InactiveUsers      = 0
                    NeverLoggedInUsers = 0
                }
                $summary += $entry
            }
            $entry.TotalUsers++
            if ($user.LastLogonTimestamp) {
                if ($user.LastLogonTimestamp -ge $logonThreshold) {
                    $entry.ActiveUsers++
                } else {
                    $entry.InactiveUsers++
                }
            } else {
                $entry.NeverLoggedInUsers++
            }
        }
    } catch {
        Write-Warning "⚠️ Failed to process domain '$domainName': $_"
    }
}

# Final output for Users and OU
switch ($Mode) {
    "UserPerOU" {
        $summary | Sort-Object Domain, OU | Format-Table -AutoSize
        $summaryPath = Join-Path $outputPath "OU_UserLogonBreakdown_$fileDate.csv"
        $summary | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8
        Write-Host "`n✅ Exported OU breakdown to: $summaryPath" -ForegroundColor Green
    }
    
    "Summary" {
        $domainSummaries = $summary |
            Group-Object Domain |
            ForEach-Object {
                [PSCustomObject]@{
                    Domain             = $_.Name
                    TotalUsers         = ($_.Group | Measure-Object -Property TotalUsers -Sum).Sum
                    ActiveUsers        = ($_.Group | Measure-Object -Property ActiveUsers -Sum).Sum
                    InactiveUsers      = ($_.Group | Measure-Object -Property InactiveUsers -Sum).Sum
                    NeverLoggedInUsers = ($_.Group | Measure-Object -Property NeverLoggedInUsers -Sum).Sum
                }
            }

        $domainSummaries | Sort-Object Domain | Format-Table -AutoSize

        $summaryPath = Join-Path $outputPath "DomainLevelSummary_$fileDate.csv"
        $domainSummaries | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8
        Write-Host "`n✅ Exported domain-level summary to: $summaryPath" -ForegroundColor Green
    }

}

# -- Service Account Summary (Per-Domain) --   
Write-Host "`n📊 Now collecting service account statistics per domain..." -ForegroundColor Cyan

$domainAccountSummaries = @()

foreach ($domain in $domainsToScan) {
    Write-Host "`n📦 Processing service accounts for: $domain" -ForegroundColor Yellow
    try {
        $managedAccounts = Get-ADServiceAccount -Server $domain -Filter * |
            Where-Object { $_.ObjectClass -eq "msDS-ManagedServiceAccount" }

        $groupManagedAccounts = Get-ADServiceAccount -Server $domain -Filter * |
            Where-Object { $_.ObjectClass -eq "msDS-GroupManagedServiceAccount" }

        $nonExpiringUsers = Get-ADUser -Server $domain -Filter { PasswordNeverExpires -eq $true }

        $summary = [PSCustomObject]@{
            Domain                        = $domain
            ManagedServiceAccounts        = ($managedAccounts | Measure-Object).Count
            GroupManagedServiceAccounts   = ($groupManagedAccounts | Measure-Object).Count
            UsersWithPasswordNeverExpires = ($nonExpiringUsers | Measure-Object).Count
        }

        $domainAccountSummaries += $summary
    }
    catch {
        Write-Warning "⚠️ Failed to query service account data for domain '$domain': $_"
    }
}

$domainAccountSummaries | Sort-Object Domain | Format-Table -AutoSize

# 💾 Export per-domain summary
$servicePerDomainPath = Join-Path $outputPath "ServiceAccountSummary_PerDomain_$fileDate.csv"
$domainAccountSummaries | Export-Csv -Path $servicePerDomainPath -NoTypeInformation -Encoding UTF8
Write-Host "`n✅ Exported per-domain service account summary to: $servicePerDomainPath" -ForegroundColor Green

Write-Host
Write-Host "Results have been saved into $outputPath. Please send all the files within the directory to your Rubrik Sales representative." -ForegroundColor Green

# Reset Culture settings back to original value
[System.Threading.Thread]::CurrentThread.CurrentCulture = $CurrentCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $CurrentCulture