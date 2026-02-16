# Entra Security Toolkit

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive PowerShell toolkit for **Microsoft Entra ID** (Azure AD) and **Microsoft 365** security assessment, auditing, and hardening. Supports both cloud-only and hybrid Active Directory environments.

## 🎯 What This Toolkit Does

| Module | Description |
|--------|-------------|
| **Conditional Access Analyzer** | Identify gaps, redundancies, and risky configurations in CA policies |
| **Privileged Role Auditor** | Audit PIM status, standing access, stale admins, and role assignments |
| **App Registration Scanner** | Find overpermissioned apps, expired credentials, and risky API permissions |
| **Sign-in Risk Detector** | Analyze sign-in patterns, risky sign-ins, and authentication anomalies |
| **Security Baseline Checker** | Validate against Microsoft security defaults and CIS benchmarks |
| **Hybrid Sync Health** | Monitor Azure AD Connect health, sync errors, and password hash sync status |

## 🚀 Quick Start

### Prerequisites

- PowerShell 5.1+ (PowerShell 7+ recommended)
- Microsoft Graph PowerShell SDK
- Appropriate Entra ID permissions (see [Required Permissions](#required-permissions))

### Installation

```powershell
# Clone the repository
git clone https://github.com/nickjlucker/entra-security-toolkit.git
cd entra-security-toolkit

# Import the module
Import-Module ./src/EntraSecurityToolkit.psd1

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Directory.Read.All", "Policy.Read.All", "AuditLog.Read.All"
```

### Run Your First Assessment

```powershell
# Full security assessment
Invoke-EntraSecurityAssessment -OutputPath "./reports"

# Individual modules
Get-ConditionalAccessGaps
Get-PrivilegedRoleAudit
Get-RiskyAppRegistrations
Get-HybridSyncHealth
```

## 📋 Required Permissions

### Microsoft Graph API Permissions

| Permission | Type | Purpose |
|------------|------|---------|
| `Directory.Read.All` | Application | Read directory data, users, groups |
| `Policy.Read.All` | Application | Read Conditional Access policies |
| `RoleManagement.Read.All` | Application | Read role assignments and PIM |
| `Application.Read.All` | Application | Read app registrations |
| `AuditLog.Read.All` | Application | Read sign-in and audit logs |
| `SecurityEvents.Read.All` | Application | Read security alerts |

### For Hybrid Environments

Additional permissions for Azure AD Connect health monitoring:
- `AdministrativeUnit.Read.All`
- On-premises AD read access (for sync validation)

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║           ENTRA SECURITY ASSESSMENT REPORT                   ║
║           Generated: 2026-02-16 00:45:00 UTC                 ║
╠══════════════════════════════════════════════════════════════╣
║  CONDITIONAL ACCESS                                          ║
║  ├─ Policies Analyzed: 24                                    ║
║  ├─ Coverage Gaps: 3 (HIGH)                                  ║
║  ├─ Redundant Policies: 2 (MEDIUM)                           ║
║  └─ Legacy Auth Blocked: ✓                                   ║
║                                                              ║
║  PRIVILEGED ACCESS                                           ║
║  ├─ Global Admins: 4 (Target: ≤5 ✓)                         ║
║  ├─ PIM Enabled: 3/4 (75%)                                   ║
║  ├─ Stale Admins (90+ days): 1 (HIGH)                        ║
║  └─ Standing Access: 2 accounts                              ║
║                                                              ║
║  APP REGISTRATIONS                                           ║
║  ├─ Total Apps: 156                                          ║
║  ├─ High-Risk Permissions: 8 (CRITICAL)                      ║
║  ├─ Expired Credentials: 12 (MEDIUM)                         ║
║  └─ Multi-tenant Apps: 23                                    ║
╚══════════════════════════════════════════════════════════════╝
```

## 🏗️ Project Structure

```
entra-security-toolkit/
├── src/
│   ├── EntraSecurityToolkit.psd1    # Module manifest
│   ├── EntraSecurityToolkit.psm1    # Root module
│   ├── Public/                       # Exported functions
│   │   ├── ConditionalAccess/
│   │   ├── PrivilegedAccess/
│   │   ├── AppRegistrations/
│   │   ├── SignInAnalysis/
│   │   ├── SecurityBaseline/
│   │   └── HybridSync/
│   ├── Private/                      # Internal functions
│   └── Classes/                      # PowerShell classes
├── docs/                             # Documentation
├── examples/                         # Usage examples
├── tests/                            # Pester tests
└── .github/                          # GitHub Actions, templates
```

## 🛡️ Security Checks Performed

### Conditional Access
- [ ] MFA enforcement gaps
- [ ] Legacy authentication blocking
- [ ] Device compliance requirements
- [ ] Location-based access controls
- [ ] Session timeout configurations
- [ ] Break-glass account exclusions
- [ ] Policy conflict detection

### Privileged Access
- [ ] Global Admin count and justification
- [ ] PIM activation requirements
- [ ] Standing vs just-in-time access
- [ ] Admin account MFA status
- [ ] Stale privileged accounts
- [ ] Role assignment scope creep
- [ ] Emergency access accounts

### Application Security
- [ ] Overpermissioned applications
- [ ] Apps with Mail.ReadWrite, Files.ReadWrite.All
- [ ] Expired secrets and certificates
- [ ] Apps consented by end users
- [ ] Multi-tenant application risks
- [ ] Service principal credentials

### Hybrid Identity
- [ ] Azure AD Connect sync health
- [ ] Password hash sync status
- [ ] Pass-through auth agent health
- [ ] Sync errors and conflicts
- [ ] On-prem to cloud privilege escalation paths

## 📖 Documentation

- [Getting Started Guide](docs/getting-started.md)
- [Configuration Options](docs/configuration.md)
- [Assessment Modules](docs/modules.md)
- [Remediation Playbooks](docs/remediation.md)
- [Contributing Guide](CONTRIBUTING.md)

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) before submitting PRs.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This toolkit is provided as-is for security assessment purposes. Always test in a non-production environment first. The authors are not responsible for any unintended consequences of running these scripts.

---

**Built with ❤️ for the identity security community**
