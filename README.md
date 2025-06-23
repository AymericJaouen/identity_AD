# Get-AdHumanIdentity

A PowerShell script to audit Active Directory human and service accounts across single or multiple domains.  
It classifies users by activity and account type, detects naming-based service accounts, and exports organized CSV reports by Organizational Unit (OU) or domain.

---

## ✨ Features

- ✅ Audit one or more domains using `-SpecificDomains`
- ✅ Detect:
  - Managed Service Accounts (MSAs)
  - Group Managed Service Accounts (gMSAs)
  - Users with PasswordNeverExpires
  - Accounts matching naming patterns (e.g. `*svc*`, `*_bot`)
- ✅ Classify accounts by last logon status:
  - Active (last login in past 180 days)
  - Inactive
  - Never logged in
- ✅ Output grouped by:
  - Organizational Unit (`UserPerOU` mode)
  - Domain summary (`Summary` mode)
- ✅ Automatically exports CSV to `.ADReports\` with timestamped filenames
- ✅ Automatically creates output folder if it doesn’t exist
- ✅ Script initializes PowerShell language settings to `en-US` for consistent timestamp parsing

---

## 📦 Version 1.0.0 – June 2025

### 🆕 New in this version

- Integrated human and service account auditing into a single engine
- Added support for MSAs and gMSAs via `Get-ADServiceAccount`
- Includes pattern-based name filtering with `Get-UsersAsServiceAccount`
- Smart fallback: skips pattern matching if no wildcards supplied
- Export folder auto-creation with timestamped filenames
- Last logon classification using `LastLogonTimestamp` properly converted via `[DateTime]::FromFileTime()`
- Fully structured script header and embedded documentation
- Built-in prerequisite checks (PowerShell version, AD module)

---

## ⚙️ Usage Examples

### 1. Scan all domains, default OU-level report (no service patterns):

```powershell
.\Get-AdHumanIdentity.ps1

2. Target a single domain, match service accounts by naming convention:
.\Get-AdHumanIdentity.ps1 `
    -SpecificDomains "corp.domain.local" `
    -UserServiceAccountNamesLike "*svc*","*_bot","sql_*" `
    -Mode UserPerOU

3. View a concise domain summary:
.\Get-AdHumanIdentity.ps1 -Mode Summary

📁 Output
CSV file saved to .\ADReports\, with filenames like:
Get-AdHumanIdentity_UserPerOU_20250623_1758.csv
Get-AdHumanIdentity_Summary_20250623_1815.csv
Includes columns:
Domain, OU, TotalUsers, ActiveUsers, InactiveUsers, NeverLoggedInUsers, ServiceAccountsManaged, GroupManaged, PasswordNeverExpires, PatternMatched

🧪 Requirements
PowerShell 5.1+
Active Directory module (ActiveDirectory) from RSAT
Permissions to query user and service account objects in all target domains

🛠 Known Limitations
Results based on LastLogonTimestamp, which may be up to 14 days out of sync across DCs
Multi-forest environments are not supported in this version