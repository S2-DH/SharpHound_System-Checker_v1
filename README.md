# 🔍 SharpHound Checker v1.0

**Comprehensive diagnostic suite for BloodHound Enterprise / SharpHound deployments**

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue)
![Version](https://img.shields.io/badge/version-1.0-green)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)

---

## 📋 **Overview**

SharpHound Checker is a powerful diagnostic toolkit designed for BloodHound Enterprise Technical Account Managers (TAMs), security engineers, and administrators to quickly validate, troubleshoot, and optimize SharpHound/SHDelegator deployments.

### **Key Features**

- ✅ **Two Execution Modes**: Standard (4 sections, ~10-20s) and Verbose (11 sections, ~1-2min)
- ✅ **Modular Architecture**: Run complete suite or individual test scripts
- ✅ **9 Customizable Parameters**: Customize behavior with optional parameters
- ✅ **Professional Output**: Self-contained reports and complete transcripts
- ✅ **Zero Dependencies**: Pure PowerShell - no modules required
- ✅ **Timeout Protection**: Won't hang on network issues or offline DCs

---

## 🚀 **Quick Start**

### **Basic Usage**

```powershell
# Standard diagnostics (4 core sections, ~10-20 seconds)
.\SharpHound-Checker-v1-MASTER.ps1

# Verbose mode (11 sections with performance metrics, ~1-2 minutes)
.\SharpHound-Checker-v1-MASTER.ps1 -Verbose

# Show help
.\SharpHound-Checker-v1-MASTER.ps1 -Help
Get-Help .\SharpHound-Checker-v1-MASTER.ps1 -Full
```

### **Advanced Usage**

```powershell
# Test with custom tenant
.\SharpHound-Checker-v1-MASTER.ps1 -TenantUrl "https://company.bloodhoundenterprise.io"

# Test connectivity to specific DC
.\SharpHound-Checker-v1-MASTER.ps1 -DomainController "DC01.contoso.com"

# Verbose mode, skip network tests (useful for offline scenarios)
.\SharpHound-Checker-v1-MASTER.ps1 -Verbose -SkipNetworkTests

# Custom paths for non-standard deployments
.\SharpHound-Checker-v1-MASTER.ps1 -SettingsPath "C:\Custom\settings.json"
```

---

## 📊 **What It Checks**

See **[CHECKS.md](CHECKS.md)** for detailed breakdown of all diagnostic sections.

### **Standard Mode (4 Sections)**

| Section | What It Checks | Time |
|---------|---------------|------|
| **1. Service Detection** | Service status, account type (gMSA/user), binary location | ~2s |
| **2. System Requirements** | .NET version, PowerShell version, ports, permissions, memory | ~5s |
| **5. Configuration Files** | settings.json, auth.json, tenant configuration | ~2s |
| **6. API & Connectivity** | API authentication, DC connectivity, network ports | ~8s |

**Total Runtime**: ~10-20 seconds

### **Verbose Mode (11 Sections)**

All Standard Mode sections **PLUS** 7 additional sections for deep diagnostics and performance analysis.

**Total Runtime**: ~1-2 minutes

---

## 📁 **Output Files**

Every run generates two files:

**1. Report File** (`*_Report_*.txt`)
- Self-contained summary
- Test results with status (PASS/FAIL/WARN)
- Key findings and recommendations

**2. Transcript File** (`*_Transcript_*.txt`)
- Complete PowerShell console output
- Full command history
- Raw data for troubleshooting

---

## 🛠️ **Parameters**

| Parameter | Description |
|-----------|-------------|
| `-Verbose` | Enable verbose mode (11 sections) |
| `-Help` or `-h` or `-?` | Display help information |
| `-TenantUrl` | Custom BHE tenant URL |
| `-DomainController` | Specific DC to test |
| `-ServiceName` | Custom service name |
| `-SettingsPath` | Custom settings.json path |
| `-AuthPath` | Custom auth.json path |
| `-LogArchivePath` | Custom log archive path |
| `-SkipNetworkTests` | Skip network port tests |
| `-SkipApiTest` | Skip API authentication test |

See **[CHECKS.md](CHECKS.md)** for complete parameter reference with examples.

---

## 📋 **Requirements**

- Windows Server 2016+ or Windows 10+
- PowerShell 5.1+
- BloodHound Enterprise / SharpHound installed
- Administrator privileges recommended

---

## 🎯 **Use Cases**

**Customer Onboarding**: Validate deployment in first 24 hours  
**Troubleshooting**: Diagnose collection failures and configuration issues  
**Health Checks**: Monthly performance reviews and trend analysis  
**Pre/Post Upgrade**: Verify system status before and after updates  

---

## 🐛 **Troubleshooting**

**Script hangs?** → Use `-SkipNetworkTests` (network timeout issue)  
**Service not found?** → Use `-ServiceName "YourServiceName"`  
**Access denied?** → Run PowerShell as Administrator  
**Can't find config files?** → Use `-SettingsPath` and `-AuthPath`  

---

## 📝 **License**

MIT License - see [LICENSE](LICENSE) file

---

## 🔗 **Links**

- **BloodHound Enterprise**: https://bloodhound.specterops.io/
- **Support**: https://support.bloodhoundenterprise.io/
- **Report Issues**: [GitHub Issues](../../issues)

---

## 👥 **Authors**

Created by SpecterOps BloodHound team for TAMs and the community.

---

**⭐ If this tool helps you, please star the repository!**

**Version**: 1.0 | **Status**: Production Ready | **Last Updated**: February 2026
