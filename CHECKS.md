# 📋 SharpHound Checker - Complete Reference

**Detailed breakdown of all diagnostic sections, parameters, and help options**

---

## 📊 **STANDARD MODE** (4 Sections, ~10-20 seconds)

### **SECTION 1: SERVICE DETECTION & STATUS**
- ✅ Service name detection (auto-detects: SHDelegator, SharpHound, BloodHoundEnterprise, SharpHoundDelegator)
- ✅ Service state (Running, Stopped, etc.)
- ✅ Service account type (gMSA, User Account, Local Service)
- ✅ Service account name
- ✅ Binary path and executable location
- ✅ Service install date (3 methods: Registry, WMI, File Creation)
- ✅ Service status validation (PASS/FAIL)

### **SECTION 2: SYSTEM REQUIREMENTS VALIDATION**

**Software Requirements:**
- ✅ Operating System name and version
- ✅ OS version validation (requires Windows Server 2019+ or Windows 10+)
- ✅ .NET Framework version
- ✅ .NET Framework validation (requires 4.7.2+)
- ✅ PowerShell version
- ✅ PowerShell validation (requires 5.1+)

**Hardware Requirements:**
- ✅ OS Architecture (32-bit vs 64-bit)
- ✅ Available memory (RAM)
- ✅ Memory validation (requires 2048 MB minimum)

**Network Requirements:**
- ✅ BHE Tenant connectivity (port 443)
- ✅ Domain Controller LDAPS (port 636) and LDAP (port 389) connectivity
- ✅ Sample computer SMB (port 445) connectivity
- ✅ Sample computer RPC (port 135) connectivity
- ✅ Network timeout protection (10-second timeout on DC detection, 3-second timeout on port tests)

**Overall Status:**
- ✅ PASS: All requirements met
- ✅ WARN: Minimum requirements met with warnings
- ✅ FAIL: Critical requirements not met

### **SECTION 5: BLOODHOUND CONFIGURATION FILES**

**settings.json Analysis:**
- ✅ File location detection (auto-searches standard paths)
- ✅ File existence validation
- ✅ JSON parsing validation
- ✅ Tenant URL extraction
- ✅ Domain configuration (domains array)
- ✅ OU configuration (collection OUs)
- ✅ Named pipe configuration (if present)
- ✅ Job schedule interval
- ✅ Job schedule display (next run time, frequency)

**auth.json Analysis:**
- ✅ File location detection
- ✅ File existence validation
- ✅ JSON parsing validation
- ✅ Token ID presence
- ✅ Token expiration date (if parseable)
- ✅ Token age calculation
- ✅ Token ID display (first 8 characters for security)

**Configuration Validation:**
- ✅ Both files present check
- ✅ Tenant URL consistency check
- ✅ Overall configuration status (PASS/FAIL/WARN)

### **SECTION 6: API AUTHENTICATION & DC CONNECTIVITY**

**API Authentication Test:**
- ✅ Tenant URL extraction from settings.json
- ✅ Token ID and token key extraction from auth.json
- ✅ HMAC signature generation (SHA256-based)
- ✅ API request construction with proper headers
- ✅ API call to `/api/v2/collectors` endpoint
- ✅ HTTP status code validation (200 = success)
- ✅ Response parsing (collector count, version info)
- ✅ Authentication result (PASS/FAIL)

**Domain Controller Connectivity:**
- ✅ Current domain detection
- ✅ PDC Emulator identification
- ✅ DC reachability test (ping/network)
- ✅ LDAPS port test (636)
- ✅ LDAP port test (389)
- ✅ DNS resolution validation
- ✅ DC connectivity status (PASS/WARN/FAIL)

---

## 🔍 **VERBOSE MODE** (11 Sections, ~1-2 minutes)

**Includes ALL Standard Mode sections (1, 2, 5, 6) PLUS:**

### **SECTION 3: PROXY CONFIGURATION & CONNECTIVITY**

**System Proxy Settings:**
- ✅ WinHTTP proxy configuration
- ✅ Internet Explorer proxy settings
- ✅ System-wide proxy detection
- ✅ Proxy server address
- ✅ Proxy bypass list
- ✅ Proxy authentication type

**Proxy Connectivity Tests:**
- ✅ Direct connection test (no proxy)
- ✅ Proxy connection test (if configured)
- ✅ BHE tenant accessibility through proxy
- ✅ Proxy authentication validation
- ✅ Proxy status (CONFIGURED/NOT_CONFIGURED/FAILING)

### **SECTION 4: ANTIVIRUS STATUS & EXCLUSIONS**

**Antivirus Detection:**
- ✅ Windows Defender status
- ✅ Windows Defender real-time protection status
- ✅ Third-party antivirus detection (via WMI)
- ✅ Antivirus product name and version
- ✅ Antivirus state (enabled/disabled)

**Windows Defender Exclusions:**
- ✅ Path exclusions list
- ✅ Process exclusions list
- ✅ Extension exclusions list
- ✅ SharpHound/SHDelegator-specific exclusion check
- ✅ Recommended exclusions display

**PowerShell Execution Policy:**
- ✅ Current execution policy (LocalMachine)
- ✅ Current execution policy (CurrentUser)
- ✅ Execution policy validation (RemoteSigned or Unrestricted recommended)

**PowerShell Constraints:**
- ✅ Constrained language mode check
- ✅ AppLocker policy detection
- ✅ PowerShell restrictions that may impact collection

### **SECTION 7: EVENT LOG ANALYSIS** (4 Categories)

**Category 1: Running Job Schedules (Event ID 9001):**
- ✅ Last 20 job schedule events
- ✅ Event timestamp
- ✅ Event level (Info/Warn/Error)
- ✅ Event message
- ✅ Event properties (Duration, Objects, Status, Target, Method, etc.)
- ✅ Sample events captured to report (first 5)

**Category 2: Service Start/Stop Events (Event ID 0):**
- ✅ Service start events
- ✅ Service stop events
- ✅ Event timestamps
- ✅ Event details and properties
- ✅ Sample events captured to report (first 3)

**Category 3: Other Events (Various Event IDs):**
- ✅ Error events (Level 2)
- ✅ Warning events (Level 3)
- ✅ Event ID identification
- ✅ Error categorization
- ✅ Sample events captured to report (first 3)

**Category 4: gMSA Authentication Events (Security Log):**
- ✅ Requires Administrator privileges
- ✅ Event ID 4624: Successful logon
- ✅ Event ID 4625: Failed logon
- ✅ Event ID 4768: Kerberos TGT request
- ✅ Event ID 4771: Kerberos pre-authentication failed
- ✅ Success/failure count summary
- ✅ Last 10 authentication events
- ✅ Sample events captured to report (first 5)

**Event Log Summary:**
- ✅ Total events analyzed count
- ✅ Error count
- ✅ Warning count
- ✅ Events by category breakdown

### **SECTION 8: WER CRASH ANALYSIS**

**Windows Error Reporting (WER) Analysis:**
- ✅ Searches last 30 days of crash reports
- ✅ Crash report locations checked:
  - `%LOCALAPPDATA%\CrashDumps`
  - `C:\ProgramData\Microsoft\Windows\WER\ReportQueue`
  - `C:\ProgramData\Microsoft\Windows\WER\ReportArchive`
- ✅ SHDelegator/SharpHound specific crashes
- ✅ Crash timestamp
- ✅ Crash type (AppCrash, AppHang, etc.)
- ✅ Exception code extraction
- ✅ Faulting module identification
- ✅ Faulting module offset
- ✅ Crash location (ReportQueue vs ReportArchive)

**Crash Categorization:**
- ✅ ACCESS VIOLATIONS (0xC0000005)
- ✅ .NET RUNTIME ERRORS (0xE0434352)
- ✅ CLR EXCEPTIONS (0x80131623)
- ✅ APPLICATION HANGS
- ✅ OTHER CRASHES

**Crash Report Output:**
- ✅ Total crashes found
- ✅ Crashes by category
- ✅ Last 10 crashes with full details
- ✅ Last WER file information (if no crashes)

### **SECTION 9: SERVICE.ZIP LOG ANALYSIS**

**Service Log Analysis (Last 10 Files):**
- ✅ Archive path detection (auto-searches standard locations)
- ✅ service.zip file enumeration
- ✅ service.log extraction from each archive
- ✅ Log line count
- ✅ Error detection (ERROR, FATAL, EXCEPTION keywords)
- ✅ Warning detection (WARN, WARNING keywords)
- ✅ Error message extraction with timestamps
- ✅ Warning message extraction with timestamps

**Per-File Analysis:**
- ✅ File name and size
- ✅ File creation timestamp
- ✅ Total log lines
- ✅ Error count
- ✅ Warning count
- ✅ First 5 errors with details
- ✅ First 3 warnings with details
- ✅ "... and X more" indicators

**Summary Output:**
- ✅ Total service.zip files analyzed
- ✅ Total errors across all files
- ✅ Total warnings across all files
- ✅ Files with issues highlighted

### **SECTION 10: DATE.ZIP COLLECTION ANALYSIS**

**Collection Archive Analysis (Last 10 Files):**
- ✅ Archive path detection
- ✅ Date-stamped .zip file enumeration
- ✅ ZIP contents inspection (debug output shows all files)
- ✅ run.log extraction and analysis
- ✅ compstatus.csv extraction and analysis
- ✅ Flexible file pattern matching (handles various naming conventions)

**run.log Analysis:**
- ✅ Total log lines
- ✅ Error line detection
- ✅ Warning line detection
- ✅ First 3 errors with timestamps
- ✅ First 3 warnings with timestamps

**compstatus.csv Analysis:**
- ✅ Total computers in collection
- ✅ Successful collection count
- ✅ Failed collection count
- ✅ Success rate percentage
- ✅ Failed computer details by category

**Failed Computer Categorization:**
- ✅ NETWORK ERRORS (network path not found, no route, timeout)
- ✅ ACCESS DENIED (permissions, authentication failures)
- ✅ TIMEOUT ERRORS (collection timeouts)
- ✅ SMB/RPC ERRORS (file sharing, remote procedure call issues)
- ✅ AUTHENTICATION ERRORS (Kerberos, NTLM failures)
- ✅ MEMORY/RESOURCE ERRORS (out of memory, resource exhaustion)
- ✅ OTHER ERRORS (uncategorized failures)

**Failed Computer Details:**
- ✅ Computer name
- ✅ Error message
- ✅ Last contact time (relative: "2d ago", "5h ago")
- ✅ First 3 computers per category
- ✅ "... and X more" for additional failures

**Summary Output:**
- ✅ Total collection archives analyzed
- ✅ Total computers across all collections
- ✅ Total successful collections
- ✅ Total failed collections
- ✅ Overall success rate
- ✅ Unique failed computers count

### **SECTION 11: PERFORMANCE METRICS & TRENDS**

**Requirements:**
- ✅ Minimum 5 collection archives
- ✅ Minimum 3 archives with extractable metrics
- ✅ Pre-check validation (section skipped if insufficient data)

**Collection Duration Trends:**
- ✅ Average collection duration (seconds and minutes)
- ✅ Minimum collection duration
- ✅ Maximum collection duration
- ✅ Trend analysis (IMPROVING = getting faster, DEGRADING = getting slower, STABLE)
- ✅ Trend calculation (compares first half vs second half of dataset)

**Objects Collected Trends:**
- ✅ Average objects per collection
- ✅ Minimum objects collected
- ✅ Maximum objects collected
- ✅ Trend analysis (INCREASING = more AD objects, DECREASING = fewer, STABLE)

**Success Rate Trends:**
- ✅ Total collections analyzed
- ✅ Successful collection count
- ✅ Failed collection count
- ✅ Success rate percentage
- ✅ Color-coded status (Green ≥90%, Yellow ≥75%, Red <75%)

**Informative Messages:**
- ✅ Processed files count (e.g., "Processed: 14 run.log files, 12 with metrics")
- ✅ Insufficient data explanation (need 5+ archives, 3+ with metrics)
- ✅ Reasons for insufficient data (log format mismatch, incomplete logs, etc.)

**Data Extraction:**
- ✅ Searches for duration patterns in run.log
- ✅ Searches for objects collected patterns
- ✅ Detects collection success/failure
- ✅ Handles various log formats

---

## 🆘 **HELP OPTIONS**

### **Command-Line Help**

```powershell
# Show quick help
.\SharpHound-Checker-v1-MASTER.ps1 -Help
.\SharpHound-Checker-v1-MASTER.ps1 -h
.\SharpHound-Checker-v1-MASTER.ps1 -?

# Show detailed help with all parameters
Get-Help .\SharpHound-Checker-v1-MASTER.ps1 -Full

# Show examples only
Get-Help .\SharpHound-Checker-v1-MASTER.ps1 -Examples

# Show parameter details
Get-Help .\SharpHound-Checker-v1-MASTER.ps1 -Parameter TenantUrl
Get-Help .\SharpHound-Checker-v1-MASTER.ps1 -Parameter Verbose
```

### **Built-in Help Content**

The script includes comprehensive help documentation with:
- ✅ Synopsis (one-line description)
- ✅ Detailed description of both modes
- ✅ Parameter descriptions and data types
- ✅ Usage examples (7 examples covering common scenarios)
- ✅ Notes (version, author, requirements)
- ✅ Links to documentation

---

## ⚙️ **PARAMETERS / VARIABLES**

### **1. -Verbose** (Switch Parameter)
**Type:** Switch  
**Required:** No  
**Default:** False (Standard mode)

**Description:**  
Enables verbose mode with 11 comprehensive diagnostic sections instead of 4 standard sections.

**Example:**
```powershell
.\SharpHound-Checker-v1-MASTER.ps1 -Verbose
```

**Effect:**
- Runs all 4 standard sections (1, 2, 5, 6)
- PLUS runs 7 additional sections (3, 4, 7, 8, 9, 10, 11)
- Runtime increases from ~10-20s to ~1-2 minutes
- Report includes performance metrics and historical analysis

---

### **2. -Help** (Switch Parameter)
**Type:** Switch  
**Aliases:** -h, -?  
**Required:** No  
**Default:** False

**Description:**  
Displays comprehensive help information and exits without running diagnostics.

**Examples:**
```powershell
.\SharpHound-Checker-v1-MASTER.ps1 -Help
.\SharpHound-Checker-v1-MASTER.ps1 -h
.\SharpHound-Checker-v1-MASTER.ps1 -?
```

**Effect:**
- Displays full help documentation
- Shows all parameters and their descriptions
- Shows usage examples
- Exits immediately (does not run any diagnostics)

---

### **3. -TenantUrl** (String Parameter)
**Type:** String  
**Required:** No  
**Default:** Extracted from settings.json

**Description:**  
Override the BHE tenant URL for testing. Useful for testing connectivity to a different tenant or validating a tenant URL before updating settings.json.

**Example:**
```powershell
.\SharpHound-Checker-v1-MASTER.ps1 -TenantUrl "https://company.bloodhoundenterprise.io"
```

**Effect:**
- Overrides tenant URL from settings.json
- Tests connectivity to specified tenant
- Tests API authentication against specified tenant
- Does NOT modify settings.json file

**Use Cases:**
- Testing connectivity to new tenant before migration
- Validating tenant URL format
- Troubleshooting tenant-specific connectivity issues

---

### **4. -DomainController** (String Parameter)
**Type:** String  
**Required:** No  
**Default:** Auto-detected (PDC Emulator)

**Description:**  
Specify a custom domain controller FQDN to test connectivity instead of using the auto-detected PDC.

**Example:**
```powershell
.\SharpHound-Checker-v1-MASTER.ps1 -DomainController "DC02.contoso.com"
```

**Effect:**
- Overrides automatic PDC detection
- Tests LDAPS/LDAP connectivity to specified DC
- Useful for testing specific DC performance or availability

**Use Cases:**
- Testing connectivity to a specific DC
- Troubleshooting DC-specific collection issues
- Validating backup DC availability

---

### **5. -ServiceName** (String Parameter)
**Type:** String (ValidateSet)  
**Required:** No  
**Default:** Auto-detect  
**Valid Values:** SHDelegator, SharpHound, BloodHoundEnterprise, SharpHoundDelegator

**Description:**  
Specify the exact service name if auto-detection fails or if using a custom service name.

**Example:**
```powershell
.\SharpHound-Checker-v1-MASTER.ps1 -ServiceName "SharpHound"
```

**Effect:**
- Skips auto-detection
- Uses specified service name directly
- Useful for non-standard deployments

**Use Cases:**
- Custom service naming
- Auto-detection failing
- Multiple SharpHound services installed

---

### **6. -SettingsPath** (String Parameter)
**Type:** String (File Path)  
**Required:** No  
**Default:** Auto-detect in standard locations

**Description:**  
Specify a custom path to settings.json file for non-standard installations.

**Example:**
```powershell
.\SharpHound-Checker-v1-MASTER.ps1 -SettingsPath "C:\Custom\Path\settings.json"
```

**Effect:**
- Skips auto-detection of settings.json
- Uses specified file path
- Validates file existence and JSON format

**Auto-Detection Paths:**
- `C:\Users\<username>\AppData\Roaming\BloodHoundEnterprise\settings.json`
- `C:\Users\<username>\AppData\Local\BloodHoundEnterprise\settings.json`
- `C:\ProgramData\BloodHoundEnterprise\settings.json`

**Use Cases:**
- Non-standard installation paths
- Multiple BloodHound instances
- Custom deployment configurations

---

### **7. -AuthPath** (String Parameter)
**Type:** String (File Path)  
**Required:** No  
**Default:** Auto-detect in standard locations

**Description:**  
Specify a custom path to auth.json file for non-standard installations.

**Example:**
```powershell
.\SharpHound-Checker-v1-MASTER.ps1 -AuthPath "C:\Custom\Path\auth.json"
```

**Effect:**
- Skips auto-detection of auth.json
- Uses specified file path
- Validates file existence and JSON format

**Auto-Detection Paths:**
- `C:\Users\<username>\AppData\Roaming\BloodHoundEnterprise\auth.json`
- `C:\Users\<username>\AppData\Local\BloodHoundEnterprise\auth.json`
- `C:\ProgramData\BloodHoundEnterprise\auth.json`

**Use Cases:**
- Non-standard installation paths
- Multiple API tokens
- Custom deployment configurations

---

### **8. -LogArchivePath** (String Parameter)
**Type:** String (Directory Path)  
**Required:** No  
**Default:** Auto-detect in standard locations

**Description:**  
Specify a custom path to the log archive directory containing service.zip and date.zip files.

**Example:**
```powershell
.\SharpHound-Checker-v1-MASTER.ps1 -LogArchivePath "C:\Custom\Logs\log_archive"
```

**Effect:**
- Skips auto-detection of log archive directory
- Uses specified directory path
- Affects Sections 9, 10, and 11 (verbose mode only)

**Auto-Detection Paths:**
- `C:\Users\<username>\AppData\Roaming\BloodHoundEnterprise\log_archive`
- `C:\Users\<username>\AppData\Local\BloodHoundEnterprise\log_archive`
- `C:\ProgramData\BloodHoundEnterprise\log_archive`

**Use Cases:**
- Non-standard log locations
- Custom archive paths
- Network-based log storage

---

### **9. -SkipNetworkTests** (Switch Parameter)
**Type:** Switch  
**Required:** No  
**Default:** False

**Description:**  
Skip all network connectivity tests. Useful when running diagnostics in offline or isolated environments, or when network tests are causing timeouts.

**Example:**
```powershell
.\SharpHound-Checker-v1-MASTER.ps1 -SkipNetworkTests
```

**Effect:**
- Skips BHE Tenant port 443 test
- Skips DC LDAPS/LDAP tests
- Skips sample computer SMB/RPC tests
- Skips domain controller detection (which can timeout)
- All other diagnostics still run normally

**Use Cases:**
- DC is powered off or unreachable
- Running in isolated network
- Network timeout issues
- Offline troubleshooting
- Testing non-network components only

---

### **10. -SkipApiTest** (Switch Parameter)
**Type:** Switch  
**Required:** No  
**Default:** False

**Description:**  
Skip the API authentication test in Section 6. Useful when API credentials are not available or when testing other components.

**Example:**
```powershell
.\SharpHound-Checker-v1-MASTER.ps1 -SkipApiTest
```

**Effect:**
- Skips API authentication call to BHE tenant
- Skips HMAC signature generation
- Skips collector enumeration
- All other Section 6 tests still run (DC connectivity)

**Use Cases:**
- API token not configured
- Testing pre-deployment configuration
- Troubleshooting non-API issues
- Offline validation

---

## 📝 **PARAMETER COMBINATION EXAMPLES**

### **Example 1: Full Verbose with Custom Paths**
```powershell
.\SharpHound-Checker-v1-MASTER.ps1 -Verbose `
    -SettingsPath "D:\BHE\settings.json" `
    -AuthPath "D:\BHE\auth.json" `
    -LogArchivePath "D:\BHE\logs"
```

### **Example 2: Quick Check (Skip Network & API)**
```powershell
.\SharpHound-Checker-v1-MASTER.ps1 -SkipNetworkTests -SkipApiTest
```

### **Example 3: Test Specific Tenant and DC**
```powershell
.\SharpHound-Checker-v1-MASTER.ps1 `
    -TenantUrl "https://test.bloodhoundenterprise.io" `
    -DomainController "DC01.test.local"
```

### **Example 4: Offline Diagnostics**
```powershell
.\SharpHound-Checker-v1-MASTER.ps1 -Verbose -SkipNetworkTests -SkipApiTest
```

### **Example 5: Custom Service Name**
```powershell
.\SharpHound-Checker-v1-MASTER.ps1 -ServiceName "BloodHoundEnterprise"
```

---

## 🎯 **QUICK REFERENCE**

| What You Want | Command |
|---------------|---------|
| **Quick health check** | `.\SharpHound-Checker-v1-MASTER.ps1` |
| **Full diagnostics** | `.\SharpHound-Checker-v1-MASTER.ps1 -Verbose` |
| **Show help** | `.\SharpHound-Checker-v1-MASTER.ps1 -Help` |
| **Skip network tests** | `.\SharpHound-Checker-v1-MASTER.ps1 -SkipNetworkTests` |
| **Custom tenant** | `.\SharpHound-Checker-v1-MASTER.ps1 -TenantUrl "https://..."` |
| **Offline mode** | `.\SharpHound-Checker-v1-MASTER.ps1 -SkipNetworkTests -SkipApiTest` |
| **Custom paths** | `.\SharpHound-Checker-v1-MASTER.ps1 -SettingsPath "..." -AuthPath "..."` |

---

**Version**: 1.0  
**Last Updated**: February 2026  
**For more info**: See [README.md](README.md)
