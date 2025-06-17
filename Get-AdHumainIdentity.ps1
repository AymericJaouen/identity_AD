# requires -Version 7.0
# requires -Modules ActiveDirectory

<#
.SYNOPSIS
Gets all human identity in the specified Active Directory Domain.

.DESCRIPTION
The "Get-AdHumainIdentity.ps1" script collects xxxxxxx

There are options to refine the search of the identities. See the parameters section for more details.

A summary of the information found by this script will be sent to console.
One or more CSV files will be saved to the same directory where the script ran with the detailed information.
Please copy/paste the console output and send it along with the CSV files to the person that asked you to run
this script.

.PARAMETER UserServiceAccountNamesLike
A comma separated list of Service Account naming convention to gather data from.

.NOTES
Written by Aymeric Jaouen for community usage
GitHub: aymeric.jaouen
Date: 16/06/2025
Updated by xxxx: 17/05/2025 -  Added support for Parameters for "name like identity"
                            -  Added support for ManagedServiceAccount
    

.EXAMPLE
./Get-AdHumainIdentity.ps1
Runs the script against the default domain the user has access to

.EXAMPLE
./Get-AdHumainIdentity.ps1 -UserServiceAccountNameLike "svc-,service"
Runs the script and check user used as service account with specific naming convention

.LINK
https://build.rubrik.com
https://github.com/rubrikinc
#>

param (
 # Option to add User names used as service account.
  [Parameter(ParameterSetName='UserServiceAccountNamesLike', Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string]$UserServiceAccountNamesLike = ''
)

# Save the current culture so it can be restored later
$CurrentCulture = [System.Globalization.CultureInfo]::CurrentCulture

# Set the culture to en-US; this is to ensure that output to CSV is formatted properly
[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
[System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'

$date = Get-Date
$date_string = $($date.ToString("yyyy-MM-dd_HHmmss"))

$output_log = "output_ad_humain_identity_$date_string.log"

if (Test-Path "./$output_log") {
  Remove-Item -Path "./$output_log"
}

Write-Host "Arguments passed to $($MyInvocation.MyCommand.Name):" -ForeGroundColor Green
$PSBoundParameters | Format-Table

# Import-Module -ActiveDirectory

try{

# Filenames of the CSVs to output
$fileDate = $date.ToString("yyyy-MM-dd_HHmm")
$outputUserAsServiceAccount = "ad_user_as_service_account_info-$($fileDate).csv"
$outputUserPerOU = "ad_user_per_OU_info-$($fileDate).csv"
$outputSummary = "Summary_all_users_info-$($fileDate).csv"

}
catch {
  Write-Error "Unable to create OutPut file."
  Write-Error "Error: $_"
}

#Inactive user at the today's date - 180 days (6 months)
$logondate = (Get-Date).AddDays(-180).ToFileTime()

# Get all enabled users with LastLogonTimestamp attribute
$EnabledUsers = Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonTimestamp

# Count active users (logged in within last 6 months)
$ActiveUsers = $EnabledUsers | Where-Object { $_.LastLogonTimestamp -and $_.LastLogonTimestamp -ge $logondate }
$TotalActive = ($ActiveUsers  | Measure-Object).Count

# Count inactive users (no login in 6+ months)
$InactiveUsers = $EnabledUsers | Where-Object { $_.LastLogonTimestamp -and $_.LastLogonTimestamp -lt $logondate }
$TotalInactive = $InactiveUsers.Count

# Count users with no LastLogonTimestamp (never logged in).  New accounts and service accounts that don't use interactive login
$NeverLoggedInUsers = $EnabledUsers | Where-Object { -not $_.LastLogonTimestamp }
$TotalNeverLoggedIn = $NeverLoggedInUsers.Count

# Total enabled users
$TotalEnabled = $EnabledUsers.Count

#---------------------------------------------------------#
# ManagedService Account
$ManagedServiceAccount = Get-ADServiceAccount -Filter * | Where-Object {$_.objectClass -eq "msDS-ManagedServiceAccount"}
$TotalManagedService = ($ManagedServiceAccount | Measure-Object).Count

# GroupManagedService Account
$GroupManagedService = Get-ADServiceAccount -Filter * | Where-Object {$_.objectClass -eq "msDS-GroupManagedServiceAccount"} 
$TotalGroupManagedService = ($GroupManagedService | Measure-Object).Count

# Users with Password never expires that might be used as Service Account
$UserPasswordNotExpired = Get-ADUser -Filter {PasswordNeverExpires -eq $true}
#$TotalUserPasswordNotExpired = $UserPasswordNotExpired.Count
$TotalUserPasswordNotExpired = ($UserPasswordNotExpired | Measure-Object).Count

# Users per OU
Get-ADOrganizationalUnit -Filter * | ForEach-Object { Get-ADUser -Filter * -SearchBase $_.DistinguishedName | Measure-Object | Select-Object Name, Count } |
Export-csv -Path $outputUserPerOU -NoTypeInformation

#Get User with names starting with svc
$UserWithSpecificName = Get-ADUser -Filter 'Name -like "svc*"'
$TotalUserWithSpecificName = ($UserWithSpecificName | Measure-Object).Count

switch ($PSCmdlet.ParameterSetName) {
  'UserServiceAccountNamesLike' {
    Write-Host "Finding specified Non humain Identity with naming convention(s)..." -ForegroundColor Green
    $subs = @()
    foreach ($UserServiceAccountNameLike in $UserServiceAccountNamesLike.split(',')) {
    Write-Host "Getting non-human information for: $($UserServiceAccountNameLike.Trim())..."
    try {
        # Get-ADUser directly, without Format-Table, and select desired properties
        $usersFound = Get-ADUser -Filter "Name -like '$($UserServiceAccountNameLike.Trim())'" -Properties Name, DistinguishedName, Enabled, LastLogonTimestamp, PasswordNeverExpires, ServicePrincipalName |
                      Select-Object Name, DistinguishedName, Enabled, LastLogonTimestamp, PasswordNeverExpires, ServicePrincipalName

        # Add the found users to the $subs array
        $subs += $usersFound
    } catch {
        Write-Error "Unable to get information for users like: $($UserServiceAccountNameLike.Trim())"
        Write-Error "Error: $_"
        Continue
    }
  }
  if ($subs.Count -gt 0) {
      $subs | Export-Csv -Path $outputUserAsServiceAccount -NoTypeInformation  -Encoding UTF8
      Write-Host "Non humain Identity information saved to: $outputUserAsServiceAccount" -ForegroundColor Green
    } else {
      Write-Host "No Non humain Identity found with the specified naming convention(s)." -ForegroundColor Yellow
    }
  }
} 

# Display summary
Write-Host "Total Enabled Users: $TotalEnabled"
Write-Host "Active Users (Last 6 Months): $TotalActive"
Write-Host "Inactive Users (No Login in 6+ Months): $TotalInactive"
Write-Host "Users with No Recorded Login: $TotalNeverLoggedIn"
Write-Host "Managed Service Account: $TotalManagedService"
Write-Host "Grouped Managed Service Account: $TotalGroupManagedService"
Write-Host "User with Password never Expires: $TotalUserPasswordNotExpired"
Write-Host "User with Specific Name starting with svc : $TotalUserWithSpecificName"

# File summary
"Total Enabled Users: $TotalEnabled" | Add-Content $outputSummary
"Active Users (Last 6 Months): $TotalActive"  | Add-Content $outputSummary
"Inactive Users (No Login in 6+ Months): $TotalInactive" | Add-Content $outputSummary
"Users with No Recorded Login: $TotalNeverLoggedIn" | Add-Content $outputSummary
"Managed Service Account: $TotalManagedService" | Add-Content $outputSummary
"Grouped Managed Service Account: $TotalGroupManagedService" | Add-Content $outputSummary
"User with Password never Expires: $TotalUserPasswordNotExpired" | Add-Content $outputSummary
"User with Specific Name starting with svc : $TotalUserWithSpecificName" | Add-Content $outputSummary

Write-Host
Write-Host "Results have been saved into $outputSummary. Please send all the files within the directory to your Rubrik Sales representative." -ForegroundColor Green

# Reset Culture settings back to original value
[System.Threading.Thread]::CurrentThread.CurrentCulture = $CurrentCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $CurrentCulture
