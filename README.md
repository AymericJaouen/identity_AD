# AD User and Service Account Audit Script – Release Notes

## Version 1.0.0 – June 2025

### 🎯 Overview
This PowerShell script audits Active Directory users and service accounts across one or more domains. It provides detailed per-OU or domain-level summaries and classifies accounts into specific categories for better visibility and reporting.

### ✨ Features

- **Multi-domain support** via `-SpecificDomains`
- **Dual reporting modes**: `UserPerOU` or `Summary`
- **Categorization** of service accounts:
  - Managed Service Accounts (MSA)
  - Group Managed Service Accounts (gMSA)
  - PasswordNeverExpires accounts
  - Pattern-matching by name (e.g. `*svc*`)
- **Pattern-based scanning** using the `Get-UsersAsServiceAccount` helper
- **Accurate last logon tracking** (active/inactive/never used)
- **CSV export with timestamped filenames**
- **Automatic report folder creation**
- **Localization enforcement** (CultureInfo set to `en-US`)
- **PowerShell and module validation** on launch

### 🛠 Fixes & Improvements

- Resolved issues where service accounts were omitted from `$TotalUsers`
- Ensured `SamAccountName` is reliably captured by explicitly requesting it
- Eliminated `.ToFileTime()` misuse on integer timestamps
- Added fault-tolerant merging of AD objects using array coercion
- Skipped pattern matching when no patterns are provided
- Structured script for modularity and readability

### 🚀 Requirements

- PowerShell 5.1+
- ActiveDirectory module (`RSAT: Active Directory Tools` installed)
- Domain connectivity

### 🧪 Example Usage

```powershell
.\Get-AdHumanIdentity.ps1 `
    -SpecificDomains "corp.domain.local","emea.domain.local" `
    -UserServiceAccountNamesLike "*svc*","*_bot","backup*" `
    -Mode "Summary"
