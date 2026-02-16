<#
.SYNOPSIS
    SharpHound Checker v1.0 MASTER - Comprehensive Diagnostic Script
    
.DESCRIPTION
    Complete diagnostic orchestrator for BloodHound Enterprise / SharpHound deployments.
    
    STANDARD MODE (Default) - 4 Core Sections:
    ==========================================
    1. Service Detection & Status
    2. System Requirements Validation (PASS/FAIL/WARN)
    5. BloodHound Configuration Files
    6. API Authentication & DC Connectivity
    
    VERBOSE MODE (-Verbose) - 11 Total Sections:
    ============================================
    All Standard Mode checks (1, 2, 5, 6) PLUS:
    3. Proxy Configuration & Connectivity
    4. Antivirus Status & Exclusions
    7. Event Log Analysis (4 categories)
    8. WER Crash Reports
    9. Service.zip Log Analysis (last 10)
    10. Date.zip Collection Analysis (last 10)
    11. Performance Metrics & Trends
        - Collection Duration Trends
        - Objects Collected Trends
        - Success Rate Trends
    
.PARAMETER Verbose
    Enable verbose mode with detailed diagnostics and performance metrics

.PARAMETER TenantUrl
    Custom BloodHound Enterprise tenant URL to test (overrides settings.json)
    Example: -TenantUrl "https://company.bloodhoundenterprise.io"

.PARAMETER DomainController
    Custom domain controller FQDN to test connectivity (overrides auto-detection)
    Example: -DomainController "DC01.contoso.com"

.PARAMETER ServiceName
    Custom service name if not using standard names
    Valid values: SHDelegator, SharpHound, BloodHoundEnterprise, SharpHoundDelegator
    Example: -ServiceName "SharpHound"

.PARAMETER SettingsPath
    Custom path to settings.json file (overrides auto-detection)
    Example: -SettingsPath "C:\Custom\Path\settings.json"

.PARAMETER AuthPath
    Custom path to auth.json file (overrides auto-detection)
    Example: -AuthPath "C:\Custom\Path\auth.json"

.PARAMETER LogArchivePath
    Custom path to log archive directory (overrides auto-detection)
    Example: -LogArchivePath "C:\Custom\Path\log_archive"

.PARAMETER SkipNetworkTests
    Skip network connectivity tests (ports 443, 636, 389, 445, 135)

.PARAMETER SkipApiTest
    Skip API authentication test
    
.EXAMPLE
    .\SharpHound-Checker-v7-MASTER.ps1
    Run standard diagnostics (4 core sections, ~10-20 seconds)
    
.EXAMPLE
    .\SharpHound-Checker-v7-MASTER.ps1 -Verbose
    Run full diagnostics with performance trends

.EXAMPLE
    .\SharpHound-Checker-v7-MASTER.ps1 -TenantUrl "https://test.bloodhoundenterprise.io"
    Test with a different BHE tenant

.EXAMPLE
    .\SharpHound-Checker-v7-MASTER.ps1 -DomainController "DC02.contoso.com"
    Test connectivity to a specific domain controller

.EXAMPLE
    .\SharpHound-Checker-v7-MASTER.ps1 -Verbose -SkipNetworkTests
    Run verbose mode but skip network port tests

.EXAMPLE
    Get-Help .\SharpHound-Checker-v7-MASTER.ps1 -Full
    Display full help with all parameters and examples
    
.NOTES
    Version: 1.0
    Author: SpecterOps BloodHound Team
    Requires: PowerShell 5.1+
    Recommended: Run as Administrator for full diagnostics
    
.LINK
    https://bloodhound.specterops.io/
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage="Display help information")]
    [Alias("h","?")]
    [switch]$Help,
    
    [Parameter(HelpMessage="Custom BloodHound Enterprise tenant URL to test")]
    [string]$TenantUrl,
    
    [Parameter(HelpMessage="Custom domain controller to test connectivity")]
    [string]$DomainController,
    
    [Parameter(HelpMessage="Custom service name to check (default: auto-detect)")]
    [ValidateSet("SHDelegator", "SharpHound", "BloodHoundEnterprise", "SharpHoundDelegator")]
    [string]$ServiceName,
    
    [Parameter(HelpMessage="Custom path to settings.json")]
    [string]$SettingsPath,
    
    [Parameter(HelpMessage="Custom path to auth.json")]
    [string]$AuthPath,
    
    [Parameter(HelpMessage="Custom path to log archive directory")]
    [string]$LogArchivePath,
    
    [Parameter(HelpMessage="Skip network connectivity tests")]
    [switch]$SkipNetworkTests,
    
    [Parameter(HelpMessage="Skip API authentication test")]
    [switch]$SkipApiTest
)

# Show help if requested
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Full
    exit 0
}

# Script metadata
$ScriptVersion = "1.0"
$ScriptDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$ScriptDateFile = Get-Date -Format 'yyyy-MM-dd_HHmmss'

# Detect if -Verbose was passed using built-in CmdletBinding parameter
$VerboseMode = $PSBoundParameters.ContainsKey('Verbose') -or $VerbosePreference -eq 'Continue'

# Suppress cmdlet verbose output (the yellow "VERBOSE:" messages)
$VerbosePreference = 'SilentlyContinue'

# Set mode name for filenames
$ModeName = if ($VerboseMode) { "Verbose" } else { "Standard" }

# Setup transcript logging
$transcriptPath = Join-Path $PSScriptRoot "SharpHound-Checker-v7-${ModeName}_${ScriptDateFile}.log"
Start-Transcript -Path $transcriptPath -Force | Out-Null

Write-Host ""
Write-Host "Transcript logging to: $transcriptPath" -ForegroundColor Gray
Write-Host ""

# ===================================================================
# HELPER FUNCTIONS
# ===================================================================

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ServiceAccountPath {
    param($serviceAccount, $subPath)
    
    $username = if ($serviceAccount -like "*\*") { 
        $serviceAccount.Split('\')[1] 
    } else { 
        $serviceAccount 
    }
    
    $searchPaths = @(
        "C:\Users\$username\AppData\Roaming\$subPath",
        "C:\Users\$username\AppData\Local\$subPath",
        "C:\ProgramData\$subPath",
        "$env:APPDATA\$subPath"
    )
    
    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            return $path
        }
    }
    
    return $null
}

# ===================================================================
# BANNER
# ===================================================================

Write-Host ""
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host " SharpHound Checker v$ScriptVersion - MASTER Diagnostics" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""
Write-Host "Mode:     $(if ($VerboseMode) { 'VERBOSE (Full Diagnostics + Performance Trends)' } else { 'STANDARD (Core Diagnostics + Configuration)' })" -ForegroundColor Yellow
Write-Host "Date:     $ScriptDate" -ForegroundColor Gray
Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor Gray

$isAdmin = Test-Administrator
Write-Host "Elevated: $(if ($isAdmin) { 'Yes (Administrator)' } else { 'No (Limited checks)' })" -ForegroundColor $(if ($isAdmin) { 'Green' } else { 'Yellow' })
Write-Host ""

if (-not $isAdmin) {
    Write-Host "NOTE: Running as Administrator enables additional checks (gMSA auth events)" -ForegroundColor Yellow
    Write-Host ""
}

# ===================================================================
# SECTION 1: SERVICE DETECTION & STATUS
# ===================================================================

Write-Host "SECTION 1: SERVICE DETECTION & STATUS" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

# Display custom parameters if provided
if ($TenantUrl) {
    Write-Host "[PARAMETER] Custom Tenant URL: $TenantUrl" -ForegroundColor Magenta
}
if ($DomainController) {
    Write-Host "[PARAMETER] Custom Domain Controller: $DomainController" -ForegroundColor Magenta
}
if ($ServiceName) {
    Write-Host "[PARAMETER] Custom Service Name: $ServiceName" -ForegroundColor Magenta
}
if ($SettingsPath) {
    Write-Host "[PARAMETER] Custom Settings Path: $SettingsPath" -ForegroundColor Magenta
}
if ($AuthPath) {
    Write-Host "[PARAMETER] Custom Auth Path: $AuthPath" -ForegroundColor Magenta
}
if ($LogArchivePath) {
    Write-Host "[PARAMETER] Custom Log Archive Path: $LogArchivePath" -ForegroundColor Magenta
}
if ($SkipNetworkTests) {
    Write-Host "[PARAMETER] Network tests will be skipped" -ForegroundColor Magenta
}
if ($SkipApiTest) {
    Write-Host "[PARAMETER] API test will be skipped" -ForegroundColor Magenta
}
if ($TenantUrl -or $DomainController -or $ServiceName -or $SettingsPath -or $AuthPath -or $LogArchivePath -or $SkipNetworkTests -or $SkipApiTest) {
    Write-Host ""
}

$serviceDetected = $false
$detectedServiceName = $null
$service = $null
$serviceAccount = $null

# If ServiceName parameter provided, check only that service
if ($ServiceName) {
    Write-Host "[CHECKING] Service: $ServiceName (custom parameter)" -ForegroundColor Yellow
    $service = Get-WmiObject Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if ($service) {
        $detectedServiceName = $ServiceName
        $serviceAccount = $service.StartName
        $serviceDetected = $true
        Write-Host "[DETECTED] Service: $detectedServiceName" -ForegroundColor Green
        Write-Host "[DETECTED] Account: $serviceAccount" -ForegroundColor Green
        Write-Host ""
    }
    else {
        Write-Host "[ERROR] Service '$ServiceName' not found!" -ForegroundColor Red
        Write-Host ""
        Write-Host "Cannot continue without service detection. Exiting." -ForegroundColor Red
        Write-Host ""
        exit 1
    }
}
else {
    # Auto-detect service
    $serviceNames = @("SHDelegator", "SharpHound", "BloodHoundEnterprise", "SharpHoundDelegator")
    
    foreach ($svcName in $serviceNames) {
        $service = Get-WmiObject Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue
        if ($service) {
            $detectedServiceName = $svcName
            $serviceAccount = $service.StartName
            $serviceDetected = $true
            Write-Host "[DETECTED] Service: $detectedServiceName" -ForegroundColor Green
            Write-Host "[DETECTED] Account: $serviceAccount" -ForegroundColor Green
            Write-Host ""
            break
        }
    }
    
    if (-not $serviceDetected) {
        Write-Host "[ERROR] No BloodHound service detected!" -ForegroundColor Red
        Write-Host "Searched for: $($serviceNames -join ', ')" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "TIP: Use -ServiceName parameter to specify custom service name" -ForegroundColor Cyan
        Write-Host "     Example: -ServiceName 'SharpHound'" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Cannot continue without service detection. Exiting." -ForegroundColor Red
        Write-Host ""
        exit 1
    }
}

# Service details
$isGMSA = $serviceAccount -like "*$"

Write-Host "Service Information:" -ForegroundColor White
Write-Host "  Name:         $($service.Name)" -ForegroundColor Gray
Write-Host "  Display Name: $($service.DisplayName)" -ForegroundColor Gray
Write-Host "  Status:       $($service.State)" -ForegroundColor $(if ($service.State -eq 'Running') { 'Green' } else { 'Yellow' })
Write-Host "  Start Mode:   $($service.StartMode)" -ForegroundColor Gray
Write-Host "  Account:      $serviceAccount" -ForegroundColor Gray
Write-Host "  Account Type: $(if ($isGMSA) { 'Group Managed Service Account (gMSA)' } else { 'Standard Account' })" -ForegroundColor $(if ($isGMSA) { 'Green' } else { 'Cyan' })

# Capture for report
$section1Details += "Service Name: $($service.Name)"
$section1Details += "Display Name: $($service.DisplayName)"
$section1Details += "Status: $($service.State)"
$section1Details += "Start Mode: $($service.StartMode)"
$section1Details += "Account: $serviceAccount"
$section1Details += "Account Type: $(if ($isGMSA) { 'Group Managed Service Account (gMSA)' } else { 'Standard Account' })"

# Binary info
$binaryPath = $service.PathName -replace '"',''
if (Test-Path $binaryPath) {
    $fileInfo = Get-Item $binaryPath
    $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($binaryPath)
    Write-Host "  Binary Path:  $binaryPath" -ForegroundColor Gray
    Write-Host "  File Version: $($versionInfo.FileVersion)" -ForegroundColor Gray
    Write-Host "  Product Ver:  $($versionInfo.ProductVersion)" -ForegroundColor Gray
    Write-Host "  File Size:    $([Math]::Round($fileInfo.Length / 1MB, 2)) MB" -ForegroundColor Gray
    
    # Capture for report
    $section1Details += "Binary Path: $binaryPath"
    $section1Details += "File Version: $($versionInfo.FileVersion)"
    $section1Details += "Product Version: $($versionInfo.ProductVersion)"
    $section1Details += "File Size: $([Math]::Round($fileInfo.Length / 1MB, 2)) MB"
}

# Service install date - try multiple methods
$installDate = $null
$installMethod = $null

# Method 1: Event Log (Event ID 7045 - Service Install)
try {
    $installEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} -MaxEvents 5000 -ErrorAction SilentlyContinue
    if ($installEvents) {
        # Try exact service name first
        $installEvent = $installEvents | Where-Object { $_.Message -match [regex]::Escape($detectedServiceName) } | Select-Object -First 1
        
        # If not found, try broader search
        if (-not $installEvent) {
            $installEvent = $installEvents | Where-Object { 
                $_.Message -match "SharpHound" -or 
                $_.Message -match "BloodHound" -or
                $_.Message -match "Delegator"
            } | Select-Object -First 1
        }
        
        if ($installEvent) {
            $installDate = $installEvent.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
            $installMethod = "Event Log"
        }
    }
}
catch {
    # Continue to next method
}

# Method 2: Service Registry Key Creation Time (if Event Log failed)
if (-not $installDate) {
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$detectedServiceName"
        if (Test-Path $regPath) {
            $regKey = Get-Item $regPath
            # Note: Registry doesn't reliably track creation time, this is last modified
            # But it's better than nothing
        }
    }
    catch {
        # Continue to next method
    }
}

# Method 3: Binary file creation time (if all else failed)
if (-not $installDate -and (Test-Path $binaryPath)) {
    try {
        $fileInfo = Get-Item $binaryPath
        $installDate = $fileInfo.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
        $installMethod = "Binary Creation"
    }
    catch {
        # All methods failed
    }
}

# Display install date
if ($installDate) {
    Write-Host "  Install Date: $installDate $(if ($installMethod) { "($installMethod)" })" -ForegroundColor Gray
    $section1Details += "Install Date: $installDate $(if ($installMethod) { "($installMethod)" })"
}
else {
    Write-Host "  Install Date: Unable to determine (no events found, check event log retention)" -ForegroundColor DarkGray
    $section1Details += "Install Date: Unable to determine"
}

# Service process start time and uptime
try {
    $serviceProcess = Get-WmiObject Win32_Service | Where-Object { $_.Name -eq $detectedServiceName }
    if ($serviceProcess -and $serviceProcess.ProcessId -gt 0) {
        $process = Get-Process -Id $serviceProcess.ProcessId -ErrorAction SilentlyContinue
        if ($process) {
            $processUptime = (Get-Date) - $process.StartTime
            Write-Host "  Process Start: $($process.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
            Write-Host "  Process Uptime: $($processUptime.Days)d $($processUptime.Hours)h $($processUptime.Minutes)m" -ForegroundColor Gray
            $section1Details += "Process Start: $($process.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
            $section1Details += "Process Uptime: $($processUptime.Days)d $($processUptime.Hours)h $($processUptime.Minutes)m"
        }
    }
}
catch {
    # Silently continue if process query fails
}

# Server uptime and last reboot
try {
    $os = Get-WmiObject Win32_OperatingSystem
    $lastBoot = $os.ConvertToDateTime($os.LastBootUpTime)
    $serverUptime = (Get-Date) - $lastBoot
    Write-Host "  Server Boot:   $($lastBoot.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
    Write-Host "  Server Uptime: $($serverUptime.Days)d $($serverUptime.Hours)h $($serverUptime.Minutes)m" -ForegroundColor Cyan
    $section1Details += "Server Boot: $($lastBoot.ToString('yyyy-MM-dd HH:mm:ss'))"
    $section1Details += "Server Uptime: $($serverUptime.Days)d $($serverUptime.Hours)h $($serverUptime.Minutes)m"
}
catch {
    # Silently continue if OS query fails
}

Write-Host ""

# Extract username for path searches
$username = if ($serviceAccount -like "*\*") { 
    $serviceAccount.Split('\')[1] 
} else { 
    $serviceAccount 
}

# Find settings.json early for use in multiple sections
$settingsJsonPath = $null

# Use custom path if provided
if ($SettingsPath) {
    if (Test-Path $SettingsPath) {
        $settingsJsonPath = $SettingsPath
        Write-Host "[CUSTOM] Using settings.json from: $settingsJsonPath" -ForegroundColor Magenta
        Write-Host ""
    }
    else {
        Write-Host "[WARNING] Custom settings path not found: $SettingsPath" -ForegroundColor Yellow
        Write-Host "          Will attempt auto-detection" -ForegroundColor Gray
        Write-Host ""
    }
}

# Auto-detect if not found or not provided
if (-not $settingsJsonPath) {
    $searchPaths = @(
        "C:\Users\$username\AppData\Roaming\BloodHoundEnterprise",
        "C:\Users\$username\AppData\Local\BloodHoundEnterprise",
        "C:\ProgramData\BloodHoundEnterprise",
        "$env:APPDATA\BloodHoundEnterprise"
    )
    
    foreach ($path in $searchPaths) {
        $testPath = Join-Path $path "settings.json"
        if (Test-Path $testPath) {
            $settingsJsonPath = $testPath
            break
        }
    }
}

# Set custom tenant URL if parameter provided
$customTenantUrl = $TenantUrl

# ===================================================================
# SECTION 2: SYSTEM REQUIREMENTS VALIDATION
# ===================================================================

Write-Host "SECTION 2: SYSTEM REQUIREMENTS VALIDATION" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

$requirementsPassed = $true
$requirementsWarnings = 0
$requirementsFailures = 0
$requirementDetails = @()  # Track specific failures/warnings
$verboseDetails = @()  # Track verbose section summaries
$configDetails = @()  # Track configuration and API details

# Detailed output capture for report (more comprehensive)
$section1Details = @()
$section2Details = @()
$section3Details = @()  # Proxy
$section4Details = @()  # Antivirus
$section5Details = @()
$section6Details = @()
$section7Details = @()  # Event logs
$section8Details = @()  # Crashes
$section9Details = @()  # Service.zip
$section10Details = @()  # Date.zip
$section11Details = @()  # Performance

# Hardware Requirements
Write-Host "Hardware Requirements" -ForegroundColor White

# CPU
$cpu = Get-WmiObject Win32_Processor
$cpuCores = $cpu.NumberOfCores
if ($cpuCores -ge 6) { 
    $cpuStatus = "[PASS]"; $cpuColor = "Green"
    $requirementDetails += "[PASS]   CPU: $cpuCores cores"
} elseif ($cpuCores -ge 4) { 
    $cpuStatus = "[PASS]"; $cpuColor = "Green"
    $requirementDetails += "[PASS]   CPU: $cpuCores cores"
} elseif ($cpuCores -ge 2) { 
    $cpuStatus = "[WARN]"; $cpuColor = "Yellow"; $requirementsWarnings++
    $requirementDetails += "[WARN]   CPU: $cpuCores cores > Recommended: 4+"
} else { 
    $cpuStatus = "[FAIL]"; $cpuColor = "Red"; $requirementsFailures++; $requirementsPassed = $false
    $requirementDetails += "[FAIL]   CPU: $cpuCores core(s) > Minimum: 2 cores"
}
Write-Host "  CPU Cores:        $cpuCores physical cores".PadRight(50) -NoNewline
Write-Host "$cpuStatus (Recommended: 4+)" -ForegroundColor $cpuColor

# RAM
$ram = Get-WmiObject Win32_ComputerSystem
$ramGB = [Math]::Round($ram.TotalPhysicalMemory / 1GB, 0)
if ($ramGB -ge 32) { 
    $ramStatus = "[PASS]"; $ramColor = "Green"
    $requirementDetails += "[PASS]   RAM: ${ramGB}GB"
} elseif ($ramGB -ge 16) { 
    $ramStatus = "[PASS]"; $ramColor = "Green"
    $requirementDetails += "[PASS]   RAM: ${ramGB}GB"
} elseif ($ramGB -ge 4) { 
    $ramStatus = "[WARN]"; $ramColor = "Yellow"; $requirementsWarnings++
    $requirementDetails += "[WARN]   RAM: ${ramGB}GB > Recommended: 16GB+"
} else { 
    $ramStatus = "[FAIL]"; $ramColor = "Red"; $requirementsFailures++; $requirementsPassed = $false
    $requirementDetails += "[FAIL]   RAM: ${ramGB}GB > Minimum: 4GB"
}
Write-Host "  RAM:              $ramGB GB".PadRight(50) -NoNewline
Write-Host "$ramStatus (Recommended: 16GB+)" -ForegroundColor $ramColor

# Disk Space
$disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
$diskFreeGB = [Math]::Round($disk.FreeSpace / 1GB, 0)
if ($diskFreeGB -ge 20) { 
    $diskStatus = "[PASS]"; $diskColor = "Green"
    $requirementDetails += "[PASS]   Disk: ${diskFreeGB}GB free"
} elseif ($diskFreeGB -ge 5) { 
    $diskStatus = "[PASS]"; $diskColor = "Green"
    $requirementDetails += "[PASS]   Disk: ${diskFreeGB}GB free"
} elseif ($diskFreeGB -ge 1) { 
    $diskStatus = "[WARN]"; $diskColor = "Yellow"; $requirementsWarnings++
    $requirementDetails += "[WARN]   Disk: ${diskFreeGB}GB free > Recommended: 5GB+"
} else { 
    $diskStatus = "[FAIL]"; $diskColor = "Red"; $requirementsFailures++; $requirementsPassed = $false
    $requirementDetails += "[FAIL]   Disk: ${diskFreeGB}GB free > Minimum: 1GB"
}
Write-Host "  Disk Space:       $diskFreeGB GB free".PadRight(50) -NoNewline
Write-Host "$diskStatus (Recommended: 5GB+)" -ForegroundColor $diskColor

Write-Host ""

# Software Requirements
Write-Host "Software Requirements" -ForegroundColor White

# Windows Version
$os = Get-WmiObject Win32_OperatingSystem
$osVersion = $os.Caption
if ($osVersion -match '2022|2025') { 
    $osStatus = "[PASS]"; $osColor = "Green"
    $requirementDetails += "[PASS]   OS: $osVersion"
} elseif ($osVersion -match '2019') { 
    $osStatus = "[PASS]"; $osColor = "Green"
    $requirementDetails += "[PASS]   OS: $osVersion"
} else { 
    $osStatus = "[FAIL]"; $osColor = "Red"; $requirementsFailures++; $requirementsPassed = $false
    $requirementDetails += "[FAIL]   OS: $osVersion > Required: Server 2019+"
}
Write-Host "  Operating System: $osVersion".PadRight(50) -NoNewline
Write-Host "$osStatus (Required: 2019+)" -ForegroundColor $osColor

# .NET Version
$dotNetVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue).Version
if ($dotNetVersion -and ([Version]$dotNetVersion -ge [Version]"4.7.2")) { 
    $dotNetStatus = "[PASS]"; $dotNetColor = "Green"
    $requirementDetails += "[PASS]   .NET: $dotNetVersion"
} else { 
    $dotNetStatus = "[FAIL]"; $dotNetColor = "Red"; $requirementsFailures++; $requirementsPassed = $false
    $requirementDetails += "[FAIL]   .NET: $(if ($dotNetVersion) { $dotNetVersion } else { 'Not detected' }) > Required: 4.7.2+"
}
Write-Host "  .NET Framework:   $(if ($dotNetVersion) { $dotNetVersion + ' or later' } else { 'Not detected' })".PadRight(50) -NoNewline
Write-Host "$dotNetStatus (Required: 4.7.2+)" -ForegroundColor $dotNetColor

Write-Host ""

# Network Requirements
Write-Host "Network Requirements" -ForegroundColor White

# BHE Tenant (443)
if ($settingsJsonPath -and (Test-Path $settingsJsonPath)) {
    try {
        $settings = Get-Content $settingsJsonPath -Raw | ConvertFrom-Json
        $tenantURL = $settings.RestEndpoint
        
        if ($tenantURL) {
            # Normalize URL
            $normalizedURL = $tenantURL
            if (-not $normalizedURL.StartsWith("http://") -and -not $normalizedURL.StartsWith("https://")) {
                $normalizedURL = "https://$normalizedURL"
            }
            $normalizedURL = $normalizedURL.TrimEnd('/')
            
            $uri = [System.Uri]$normalizedURL
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connection = $tcpClient.BeginConnect($uri.Host, 443, $null, $null)
            $wait = $connection.AsyncWaitHandle.WaitOne(3000, $false)
            
            if ($wait) {
                $tcpClient.EndConnect($connection)
                Write-Host "  BHE Tenant (443): $($uri.Host)".PadRight(50) -NoNewline
                Write-Host "[PASS]" -ForegroundColor Green
                $requirementDetails += "[PASS]   Network: BHE Tenant (443)"
            }
            else {
                Write-Host "  BHE Tenant (443): $($uri.Host)".PadRight(50) -NoNewline
                Write-Host "[FAIL] Connection timeout" -ForegroundColor Red
                $requirementsFailures++
                $requirementsPassed = $false
                $requirementDetails += "[FAIL]   Network: BHE Tenant (443) > Connection timeout"
            }
            
            $tcpClient.Close()
        }
    }
    catch {
        Write-Host "  BHE Tenant (443): Connection failed - $($_.Exception.Message)" -ForegroundColor Red
        $requirementsFailures++
        $requirementsPassed = $false
        $requirementDetails += "[FAIL]   Network: BHE Tenant (443) > $($_.Exception.Message)"
    }
}
else {
    Write-Host "  BHE Tenant (443): Not configured (settings.json not found)" -ForegroundColor Yellow
    Write-Host "    Note: settings.json contains tenant URL - see Section 5 for details" -ForegroundColor DarkGray
    $requirementDetails += "[SKIP]   Network: BHE Tenant (443) > Not configured"
}

# Domain Controller LDAPS/LDAP
if (-not $SkipNetworkTests) {
    try {
        Write-Host "  Detecting domain controller..." -ForegroundColor Gray
        
        # Use timeout for domain detection (this can hang)
        $job = Start-Job -ScriptBlock {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        
        $completed = Wait-Job $job -Timeout 10
        
        if ($completed) {
            $domain = Receive-Job $job
            Remove-Job $job
            
            $dc = $domain.PdcRoleOwner.Name
            
            # Test LDAPS (636) - Preferred
            $ldapsStatus = "FAIL"
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connection = $tcpClient.BeginConnect($dc, 636, $null, $null)
            $wait = $connection.AsyncWaitHandle.WaitOne(3000, $false)
            
            if ($wait) {
                try { $tcpClient.EndConnect($connection) } catch { }
                $ldapsStatus = "PASS"
            }
            $tcpClient.Close()
            
            # Test LDAP (389) - Fallback
            $ldapStatus = "FAIL"
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connection = $tcpClient.BeginConnect($dc, 389, $null, $null)
            $wait = $connection.AsyncWaitHandle.WaitOne(3000, $false)
            
            if ($wait) {
                try { $tcpClient.EndConnect($connection) } catch { }
                $ldapStatus = "PASS"
            }
            $tcpClient.Close()
            
            # Determine overall DC status
            if ($ldapsStatus -eq "PASS") {
                Write-Host "  DC LDAPS (636):   $dc".PadRight(50) -NoNewline
                Write-Host "[PASS]" -ForegroundColor Green
                $requirementDetails += "[PASS]   Network: DC LDAPS (636)"
            }
            elseif ($ldapStatus -eq "PASS") {
                Write-Host "  DC LDAPS (636):   $dc".PadRight(50) -NoNewline
                Write-Host "[WARN] LDAPS failed, LDAP available" -ForegroundColor Yellow
                $requirementsWarnings++
                $requirementDetails += "[WARN]   Network: DC LDAPS (636) > LDAPS failed, LDAP works"
            }
            else {
                Write-Host "  DC Connectivity:  $dc".PadRight(50) -NoNewline
                Write-Host "[FAIL] LDAPS and LDAP failed" -ForegroundColor Red
                $requirementsFailures++
                $requirementsPassed = $false
                $requirementDetails += "[FAIL]   Network: DC Connectivity > Both LDAPS/LDAP failed"
            }
        }
        else {
            # Timeout occurred
            Remove-Job $job -Force
            Write-Host "  DC Connectivity:  Timeout detecting domain" -ForegroundColor Yellow
            $requirementsWarnings++
            $requirementDetails += "[WARN]   Network: DC Connectivity > Timeout (10s)"
        }
    }
    catch {
        Write-Host "  DC Connectivity:  Not available - $($_.Exception.Message)" -ForegroundColor Yellow
        $requirementsWarnings++
        $requirementDetails += "[WARN]   Network: DC Connectivity > $($_.Exception.Message)"
    }
}
else {
    Write-Host "  DC Connectivity:  Skipped (-SkipNetworkTests)" -ForegroundColor Gray
}

# Sample Computer Connectivity (SMB/RPC)
if (-not $SkipNetworkTests) {
    try {
        # Get a sample computer from AD (not a DC) - with timeout
        Write-Host "  Testing sample computer connectivity..." -ForegroundColor Gray
        
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))"
        $searcher.PropertiesToLoad.Add("dNSHostName") | Out-Null
        $searcher.PageSize = 10
        $searcher.ServerTimeLimit = [TimeSpan]::FromSeconds(5)  # Add server timeout
        $searcher.ClientTimeout = [TimeSpan]::FromSeconds(5)    # Add client timeout
        
        $results = $searcher.FindAll() | Select-Object -First 1
        
        if ($results) {
            $computerName = $results.Properties["dnshostname"][0]
            
            # Test SMB (445)
            $smbStatus = "FAIL"
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connection = $tcpClient.BeginConnect($computerName, 445, $null, $null)
            $wait = $connection.AsyncWaitHandle.WaitOne(3000, $false)
            
            if ($wait) {
                try { $tcpClient.EndConnect($connection) } catch { }
                $smbStatus = "PASS"
            }
            $tcpClient.Close()
            
            # Test RPC (135)
            $rpcStatus = "FAIL"
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connection = $tcpClient.BeginConnect($computerName, 135, $null, $null)
            $wait = $connection.AsyncWaitHandle.WaitOne(3000, $false)
            
            if ($wait) {
                try { $tcpClient.EndConnect($connection) } catch { }
                $rpcStatus = "PASS"
            }
            $tcpClient.Close()
            
            # Display results
            if ($smbStatus -eq "PASS") {
                Write-Host "  Sample SMB (445): $computerName".PadRight(50) -NoNewline
                Write-Host "[PASS]" -ForegroundColor Green
            }
            else {
                Write-Host "  Sample SMB (445): $computerName".PadRight(50) -NoNewline
                Write-Host "[FAIL]" -ForegroundColor Red
                $requirementsWarnings++
            }
            
            if ($rpcStatus -eq "PASS") {
                Write-Host "  Sample RPC (135): $computerName".PadRight(50) -NoNewline
                Write-Host "[PASS]" -ForegroundColor Green
            }
            else {
                Write-Host "  Sample RPC (135): $computerName".PadRight(50) -NoNewline
                Write-Host "[FAIL]" -ForegroundColor Red
                $requirementsWarnings++
            }
        }
        else {
            Write-Host "  Sample Computer:  No computers found in AD" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  Sample Computer:  Could not test - $($_.Exception.Message)" -ForegroundColor Gray
    }
}

Write-Host ""

# Overall Status
if ($requirementsFailures -eq 0 -and $requirementsWarnings -eq 0) {
    Write-Host "Overall Status: [PASS] System meets all requirements" -ForegroundColor Green
} elseif ($requirementsFailures -eq 0) {
    Write-Host "Overall Status: [WARN] System meets minimum requirements ($requirementsWarnings warnings)" -ForegroundColor Yellow
} else {
    Write-Host "Overall Status: [FAIL] System does NOT meet requirements ($requirementsFailures critical, $requirementsWarnings warnings)" -ForegroundColor Red
}

Write-Host ""

# ===================================================================
# SECTION 3: PROXY CONFIGURATION & CONNECTIVITY (VERBOSE MODE ONLY)
# ===================================================================

if ($VerboseMode) {

Write-Host "SECTION 3: PROXY CONFIGURATION & CONNECTIVITY" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

# Check WinHTTP Proxy
Write-Host "WinHTTP Proxy Settings:" -ForegroundColor White
$section3Details += "WinHTTP Proxy Settings:"

try {
    $winHttpProxy = netsh winhttp show proxy
    
    if ($winHttpProxy -match 'Direct access') {
        Write-Host "  Configuration: Direct access (no proxy)" -ForegroundColor Green
        $section3Details += "  Configuration: Direct access (no proxy)"
        $proxyConfigured = $false
    }
    else {
        Write-Host "  Configuration: Proxy configured" -ForegroundColor Yellow
        $section3Details += "  Configuration: Proxy configured"
        $proxyConfigured = $true
        
        # Extract proxy server
        if ($winHttpProxy -match 'Proxy Server\(s\)\s*:\s*(.+)') {
            $proxyServer = $matches[1].Trim()
            Write-Host "  Proxy Server:  $proxyServer" -ForegroundColor Gray
            $section3Details += "  Proxy Server: $proxyServer"
        }
        
        # Extract bypass list
        if ($winHttpProxy -match 'Bypass List\s*:\s*(.+)') {
            $bypassList = $matches[1].Trim()
            Write-Host "  Bypass List:   $bypassList" -ForegroundColor Gray
            $section3Details += "  Bypass List: $bypassList"
        }
    }
}
catch {
    Write-Host "  [WARNING] Could not query WinHTTP proxy settings" -ForegroundColor Yellow
    $section3Details += "  [WARNING] Could not query WinHTTP proxy settings"
    $proxyConfigured = $false
}

Write-Host ""
$section3Details += ""

# Check IE/System Proxy
Write-Host "Internet Explorer/System Proxy:" -ForegroundColor White
$section3Details += "Internet Explorer/System Proxy:"

try {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $proxyEnable = (Get-ItemProperty -Path $regPath -Name ProxyEnable -ErrorAction SilentlyContinue).ProxyEnable
    $proxyServer = (Get-ItemProperty -Path $regPath -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer
    
    if ($proxyEnable -eq 1 -and $proxyServer) {
        Write-Host "  Status:        Enabled" -ForegroundColor Yellow
        Write-Host "  Proxy Server:  $proxyServer" -ForegroundColor Gray
        $section3Details += "  Status: Enabled"
        $section3Details += "  Proxy Server: $proxyServer"
        
        $proxyOverride = (Get-ItemProperty -Path $regPath -Name ProxyOverride -ErrorAction SilentlyContinue).ProxyOverride
        if ($proxyOverride) {
            Write-Host "  Bypass List:   $proxyOverride" -ForegroundColor Gray
            $section3Details += "  Bypass List: $proxyOverride"
        }
    }
    else {
        Write-Host "  Status:        Disabled (direct connection)" -ForegroundColor Green
        $section3Details += "  Status: Disabled (direct connection)"
    }
}
catch {
    Write-Host "  [WARNING] Could not query IE proxy settings" -ForegroundColor Yellow
    $section3Details += "  [WARNING] Could not query IE proxy settings"
}

Write-Host ""
$section3Details += ""

# Summary
if ($proxyConfigured) {
    Write-Host "Summary: Proxy configured - ensure tenant URL is in bypass list" -ForegroundColor Yellow
    Write-Host "         (Tenant connectivity tested in Section 6: API Authentication)" -ForegroundColor DarkGray
    $verboseDetails += "Proxy: Configured - ensure tenant in bypass list"
}
else {
    Write-Host "Summary: Direct internet access - no proxy configuration" -ForegroundColor Green
    $verboseDetails += "Proxy: Direct internet access (no proxy)"
}

Write-Host ""

} # End of Section 3 (Verbose Mode Only)

# ===================================================================
# SECTION 4: ANTIVIRUS STATUS & EXCLUSIONS (VERBOSE MODE ONLY)
# ===================================================================

if ($VerboseMode) {

Write-Host "SECTION 4: ANTIVIRUS STATUS & EXCLUSIONS" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

# Check Windows Defender Status
Write-Host "Windows Defender Status:" -ForegroundColor White
$section4Details += "Windows Defender Status:"

try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
    
    Write-Host "  Antimalware:           $(if ($defenderStatus.AntivirusEnabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($defenderStatus.AntivirusEnabled) { 'Green' } else { 'Gray' })
    Write-Host "  Real-time Protection:  $(if ($defenderStatus.RealTimeProtectionEnabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($defenderStatus.RealTimeProtectionEnabled) { 'Yellow' } else { 'Gray' })
    Write-Host "  Behavior Monitoring:   $(if ($defenderStatus.BehaviorMonitorEnabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($defenderStatus.BehaviorMonitorEnabled) { 'Yellow' } else { 'Gray' })
    Write-Host "  IOAV Protection:       $(if ($defenderStatus.IoavProtectionEnabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($defenderStatus.IoavProtectionEnabled) { 'Yellow' } else { 'Gray' })
    
    $section4Details += "  Antimalware: $(if ($defenderStatus.AntivirusEnabled) { 'Enabled' } else { 'Disabled' })"
    $section4Details += "  Real-time Protection: $(if ($defenderStatus.RealTimeProtectionEnabled) { 'Enabled' } else { 'Disabled' })"
    $section4Details += "  Behavior Monitoring: $(if ($defenderStatus.BehaviorMonitorEnabled) { 'Enabled' } else { 'Disabled' })"
    $section4Details += "  IOAV Protection: $(if ($defenderStatus.IoavProtectionEnabled) { 'Enabled' } else { 'Disabled' })"
    
    $defenderEnabled = $defenderStatus.AntivirusEnabled -or $defenderStatus.RealTimeProtectionEnabled
}
catch {
    Write-Host "  [INFO] Windows Defender not available or not running" -ForegroundColor Gray
    $section4Details += "  [INFO] Windows Defender not available or not running"
    $defenderEnabled = $false
}

Write-Host ""
$section4Details += ""

# Check for exclusions if Defender is enabled
if ($defenderEnabled) {
    Write-Host "Current Exclusions:" -ForegroundColor White
    $section4Details += "Current Exclusions:"
    
    try {
        $preferences = Get-MpPreference -ErrorAction Stop
        
        # Path exclusions
        if ($preferences.ExclusionPath) {
            Write-Host "  Path Exclusions:" -ForegroundColor Gray
            $section4Details += "  Path Exclusions:"
            foreach ($path in $preferences.ExclusionPath | Select-Object -First 10) {
                Write-Host "    - $path" -ForegroundColor DarkGray
                $section4Details += "    - $path"
            }
            if ($preferences.ExclusionPath.Count -gt 10) {
                Write-Host "    ... and $($preferences.ExclusionPath.Count - 10) more" -ForegroundColor DarkGray
                $section4Details += "    ... and $($preferences.ExclusionPath.Count - 10) more"
            }
        }
        else {
            Write-Host "  Path Exclusions: None configured" -ForegroundColor Yellow
            Write-Host "    WARNING: Without path exclusions, Windows Defender will scan all SharpHound files" -ForegroundColor Yellow
            Write-Host "    IMPACT:  This can significantly slow down collections and cause file locks" -ForegroundColor DarkGray
            Write-Host "    ACTION:  Review recommended exclusions below and add them to Windows Defender" -ForegroundColor DarkGray
            $section4Details += "  Path Exclusions: None configured"
            $section4Details += "    [!] WARNING: Defender will scan all SharpHound files (can cause slowdowns)"
        }
        
        # Process exclusions
        if ($preferences.ExclusionProcess) {
            Write-Host "  Process Exclusions:" -ForegroundColor Gray
            $section4Details += "  Process Exclusions:"
            foreach ($process in $preferences.ExclusionProcess | Select-Object -First 5) {
                Write-Host "    - $process" -ForegroundColor DarkGray
                $section4Details += "    - $process"
            }
            if ($preferences.ExclusionProcess.Count -gt 5) {
                Write-Host "    ... and $($preferences.ExclusionProcess.Count - 5) more" -ForegroundColor DarkGray
                $section4Details += "    ... and $($preferences.ExclusionProcess.Count - 5) more"
            }
        }
        else {
            Write-Host "  Process Exclusions: None configured" -ForegroundColor Yellow
            Write-Host "    WARNING: Without process exclusions, Windows Defender will scan SharpHound process" -ForegroundColor Yellow
            Write-Host "    IMPACT:  Real-time scanning can reduce collection performance by 30-50%" -ForegroundColor DarkGray
            Write-Host "    ACTION:  Add SharpHound service executable to process exclusions" -ForegroundColor DarkGray
            $section4Details += "  Process Exclusions: None configured"
            $section4Details += "    [!] WARNING: Defender will scan SharpHound process (30-50% performance impact)"
        }
        
        Write-Host ""
        
        # Check for SharpHound exclusions
        Write-Host "Recommended SharpHound Exclusions:" -ForegroundColor White
        $section4Details += ""
        $section4Details += "Recommended SharpHound Exclusions:"
        
        $recommendedPaths = @()
        $recommendedProcesses = @()
        
        # Service binary path
        if ($service -and $service.PathName) {
            $binaryPath = $service.PathName -replace '"',''
            $binaryDir = Split-Path $binaryPath -Parent
            
            $recommendedPaths += $binaryDir
            $recommendedProcesses += (Split-Path $binaryPath -Leaf)
        }
        
        # Service account AppData paths
        if ($username) {
            $recommendedPaths += "C:\Users\$username\AppData\Roaming\BloodHoundEnterprise"
            $recommendedPaths += "C:\Users\$username\AppData\Local\BloodHoundEnterprise"
        }
        
        # Check which are missing
        $missingPaths = @()
        $missingProcesses = @()
        
        foreach ($recPath in $recommendedPaths) {
            $isExcluded = $false
            if ($preferences.ExclusionPath) {
                foreach ($exPath in $preferences.ExclusionPath) {
                    if ($recPath -like "$exPath*" -or $exPath -like "$recPath*") {
                        $isExcluded = $true
                        break
                    }
                }
            }
            
            if ($isExcluded) {
                Write-Host "  [OK]      $recPath" -ForegroundColor Green
                $section4Details += "  [OK]      $recPath"
            }
            else {
                Write-Host "  [MISSING] $recPath" -ForegroundColor Red
                $section4Details += "  [MISSING] $recPath"
                $missingPaths += $recPath
            }
        }
        
        foreach ($recProc in $recommendedProcesses) {
            if ($preferences.ExclusionProcess -contains $recProc) {
                Write-Host "  [OK]      Process: $recProc" -ForegroundColor Green
                $section4Details += "  [OK]      Process: $recProc"
            }
            else {
                Write-Host "  [MISSING] Process: $recProc" -ForegroundColor Red
                $section4Details += "  [MISSING] Process: $recProc"
                $missingProcesses += $recProc
            }
        }
        
        Write-Host ""
        $section4Details += ""
        
        # Provide commands to add missing exclusions
        if ($missingPaths.Count -gt 0 -or $missingProcesses.Count -gt 0) {
            Write-Host "Commands to Add Missing Exclusions:" -ForegroundColor Yellow
            Write-Host ""
            $section4Details += "Commands to Add Missing Exclusions:"
            $section4Details += ""
            
            foreach ($path in $missingPaths) {
                Write-Host "  Add-MpPreference -ExclusionPath '$path'" -ForegroundColor Cyan
                $section4Details += "  Add-MpPreference -ExclusionPath '$path'"
            }
            
            foreach ($proc in $missingProcesses) {
                Write-Host "  Add-MpPreference -ExclusionProcess '$proc'" -ForegroundColor Cyan
                $section4Details += "  Add-MpPreference -ExclusionProcess '$proc'"
            }
            
            Write-Host ""
            Write-Host "  Or run all at once:" -ForegroundColor Gray
            $section4Details += ""
            
            if ($missingPaths.Count -gt 0) {
                $pathsQuoted = ($missingPaths | ForEach-Object { "'$_'" }) -join ','
                Write-Host "  Add-MpPreference -ExclusionPath $pathsQuoted" -ForegroundColor Cyan
                $section4Details += "  Add-MpPreference -ExclusionPath $pathsQuoted"
            }
            
            if ($missingProcesses.Count -gt 0) {
                $procsQuoted = ($missingProcesses | ForEach-Object { "'$_'" }) -join ','
                Write-Host "  Add-MpPreference -ExclusionProcess $procsQuoted" -ForegroundColor Cyan
            }
            
            Write-Host ""
            $verboseDetails += "Antivirus: Windows Defender active - MISSING exclusions ($($missingPaths.Count) paths, $($missingProcesses.Count) processes)"
        }
        else {
            Write-Host "Status: [PASS] All recommended exclusions are configured" -ForegroundColor Green
            Write-Host ""
            $verboseDetails += "Antivirus: Windows Defender active with recommended exclusions"
            $section4Details += "Windows Defender Status: Enabled with all recommended exclusions configured"
        }
    }
    catch {
        Write-Host "  [WARNING] Could not query Defender exclusions: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host ""
        $verboseDetails += "Antivirus: Windows Defender active (could not verify exclusions)"
        $section4Details += "Windows Defender Status: Active (exclusions could not be verified)"
    }
}
else {
    Write-Host "[INFO] Windows Defender not active - exclusion check skipped" -ForegroundColor Gray
    Write-Host ""
    $verboseDetails += "Antivirus: Windows Defender not active"
    $section4Details += "Windows Defender Status: Not active or not available"
}

} # End of Section 4 (Verbose Mode Only)

# ===================================================================
# SECTION 5: BLOODHOUND CONFIGURATION & COLLECTION SCHEDULES
# ===================================================================

Write-Host "SECTION 5: BLOODHOUND CONFIGURATION & COLLECTION SCHEDULES" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

# Use already-found settings.json path
if ($settingsJsonPath) {
    Write-Host "Configuration File: $settingsJsonPath" -ForegroundColor Green
    Write-Host ""
    $configDetails += "Configuration: $settingsJsonPath"
    
    try {
        $settings = Get-Content $settingsJsonPath -Raw | ConvertFrom-Json
        
        # Tenant Information
        if ($settings.RestEndpoint) {
            Write-Host "Tenant Information:" -ForegroundColor White
            Write-Host "  Tenant URL: $($settings.RestEndpoint)" -ForegroundColor Gray
            Write-Host ""
            $configDetails += "Tenant: $($settings.RestEndpoint)"
        }
        
        # Domains
        if ($settings.Domains) {
            Write-Host "Configured Domains:" -ForegroundColor White
            foreach ($domain in $settings.Domains) {
                Write-Host "  - $domain" -ForegroundColor Gray
            }
            Write-Host ""
            $configDetails += "Domains: $($settings.Domains.Count) configured ($($settings.Domains -join ', '))"
        }
        
        # Collection Schedules
        if ($settings.Schedules) {
            Write-Host "Collection Schedules:" -ForegroundColor White
            
            $enabledCount = 0
            $disabledCount = 0
            
            foreach ($schedule in $settings.Schedules) {
                $enabled = if ($schedule.Enabled -eq $true) { $true; $enabledCount++ } else { $false; $disabledCount++ }
                $statusText = if ($enabled) { "[ENABLED]" } else { "[DISABLED]" }
                $statusColor = if ($enabled) { "Green" } else { "DarkGray" }
                
                Write-Host "  ".PadRight(2) -NoNewline
                Write-Host "$statusText".PadRight(12) -NoNewline -ForegroundColor $statusColor
                Write-Host "$($schedule.Name)" -ForegroundColor $(if ($enabled) { "White" } else { "DarkGray" })
                
                if ($schedule.Domain) {
                    Write-Host "              Domain:   $($schedule.Domain)" -ForegroundColor DarkGray
                }
                
                if ($schedule.CollectionMethods) {
                    $methods = $schedule.CollectionMethods -join ', '
                    if ($methods.Length -gt 70) { $methods = $methods.Substring(0, 67) + "..." }
                    Write-Host "              Methods:  $methods" -ForegroundColor DarkGray
                }
                
                if ($schedule.Interval) {
                    Write-Host "              Interval: $($schedule.Interval)" -ForegroundColor DarkGray
                }
                
                if ($Verbose -and $schedule.OUs) {
                    Write-Host "              OUs:      $($schedule.OUs -join ', ')" -ForegroundColor DarkGray
                }
                
                Write-Host ""
            }
            
            Write-Host "  Summary: $enabledCount enabled, $disabledCount disabled" -ForegroundColor $(if ($enabledCount -gt 0) { "Green" } else { "Yellow" })
            $configDetails += "Schedules: $enabledCount enabled, $disabledCount disabled"
            
            if ($enabledCount -eq 0) {
                Write-Host "  WARNING: No enabled schedules - collections will not run automatically" -ForegroundColor Yellow
            }
            
            Write-Host ""
        }
    }
    catch {
        Write-Host "[ERROR] Failed to parse settings.json: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        $configDetails += "Configuration: Error parsing settings.json"
    }
}
else {
    Write-Host "[WARNING] settings.json not found in any expected location" -ForegroundColor Yellow
    Write-Host "This file contains tenant URL and collection configuration." -ForegroundColor Gray
    Write-Host "Searched paths:" -ForegroundColor Gray
    Write-Host "  - C:\Users\$username\AppData\Roaming\BloodHoundEnterprise" -ForegroundColor DarkGray
    Write-Host "  - C:\Users\$username\AppData\Local\BloodHoundEnterprise" -ForegroundColor DarkGray
    $configDetails += "Configuration: settings.json not found"
    Write-Host "  - C:\ProgramData\BloodHoundEnterprise" -ForegroundColor DarkGray
    Write-Host "  - $env:APPDATA\BloodHoundEnterprise" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Impact: Cannot test BHE tenant connectivity or parse collection schedules" -ForegroundColor Yellow
    Write-Host ""
}

# ===================================================================
# SECTION 6: API AUTHENTICATION TEST
# ===================================================================

Write-Host "SECTION 6: API AUTHENTICATION TEST" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

# Find auth.json and settings.json
$bheBasePath = Get-ServiceAccountPath -serviceAccount $serviceAccount -subPath "BloodHoundEnterprise"

if ($bheBasePath) {
    $authPath = Join-Path $bheBasePath "auth.json"
    $settingsJsonPathForAuth = Join-Path $bheBasePath "settings.json"
    
    if ((Test-Path $authPath) -and (Test-Path $settingsJsonPathForAuth)) {
        Write-Host "Configuration Path: $bheBasePath" -ForegroundColor Green
        Write-Host ""
        
        try {
            $auth = Get-Content $authPath -Raw | ConvertFrom-Json
            $settingsAuth = Get-Content $settingsJsonPathForAuth -Raw | ConvertFrom-Json
            
            # Check for TokenID (multiple property name variations)
            if ($auth.TokenID) {
                $tokenId = $auth.TokenID
            }
            elseif ($auth.TokenId) {
                $tokenId = $auth.TokenId
            }
            elseif ($auth.id) {
                $tokenId = $auth.id
            }
            else {
                $tokenId = $null
            }
            
            # Check for Token/Key (multiple property name variations)
            if ($auth.Token) {
                $tokenKey = $auth.Token
            }
            elseif ($auth.TokenKey) {
                $tokenKey = $auth.TokenKey
            }
            elseif ($auth.key) {
                $tokenKey = $auth.key
            }
            else {
                $tokenKey = $null
            }
            
            $apiUrl = $settingsAuth.RestEndpoint
            
            Write-Host "  Token ID:  $tokenId" -ForegroundColor Gray
            Write-Host "  API URL:   $apiUrl" -ForegroundColor Gray
            Write-Host ""
            $configDetails += "API Token: $tokenId"
            $configDetails += "API URL: $apiUrl"
            
            # Validate auth credentials
            if ([string]::IsNullOrWhiteSpace($tokenId) -or [string]::IsNullOrWhiteSpace($tokenKey)) {
                Write-Host "[WARNING] API credentials incomplete in auth.json" -ForegroundColor Yellow
                Write-Host "  TokenId present: $(if ($tokenId) { 'Yes' } else { 'No' })" -ForegroundColor Gray
                Write-Host "  TokenKey present: $(if ($tokenKey) { 'Yes' } else { 'No' })" -ForegroundColor Gray
                Write-Host "  Checked properties: TokenID/TokenId/id for ID, Token/TokenKey/key for Key" -ForegroundColor DarkGray
                Write-Host ""
                $configDetails += "API Auth: Incomplete credentials"
            }
            else {
                # Test API connection with HMAC authentication
                $endpoint = "$apiUrl/api/v2/self"
                $method = "GET"
                $timestamp = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                
                # Create HMAC signature
                $hmac = New-Object System.Security.Cryptography.HMACSHA256
                $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($tokenKey)
                
                $requestUri = [Uri]$endpoint
                $canonicalUri = $requestUri.PathAndQuery
                $signatureData = "$method$canonicalUri$timestamp"
                
                $signatureBytes = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($signatureData))
                $signature = [Convert]::ToBase64String($signatureBytes)
                
                # Make API request
                $headers = @{
                    "User-Agent" = "SharpHoundChecker/$ScriptVersion"
                    "Authorization" = "bhesignature $tokenId"
                    "RequestDate" = $timestamp
                    "Signature" = $signature
                    "Content-Type" = "application/json"
                }
                
                Write-Host "Testing API Connection..." -ForegroundColor Yellow
                
                try {
                    $response = Invoke-RestMethod -Uri $endpoint -Method $method -Headers $headers -UseBasicParsing -ErrorAction Stop
                    
                    Write-Host "[SUCCESS] API Authentication Working" -ForegroundColor Green
                    $configDetails += "API Auth: SUCCESS"
                    
                    # Only show Principal and Email if they exist and are not empty
                    if ($response.data.principal_name -and $response.data.principal_name -ne "") {
                        Write-Host "  Principal: $($response.data.principal_name)" -ForegroundColor Gray
                    }
                    if ($response.data.email_address -and $response.data.email_address -ne "") {
                        Write-Host "  Email:     $($response.data.email_address)" -ForegroundColor Gray
                    }
                    
                    Write-Host ""
                }
                catch {
                    Write-Host "[FAILED] API Authentication Failed" -ForegroundColor Red
                    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Gray
                    Write-Host ""
                    $configDetails += "API Auth: FAILED - $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-Host "[ERROR] Failed to load auth configuration: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host ""
            $configDetails += "API Auth: Error loading configuration"
        }
    }
    else {
        Write-Host "[WARNING] auth.json or settings.json not found" -ForegroundColor Yellow
        Write-Host "  Expected: $authPath" -ForegroundColor Gray
        Write-Host ""
        $configDetails += "API Auth: Configuration files not found"
    }
}
else {
    Write-Host "[WARNING] BloodHound configuration directory not found" -ForegroundColor Yellow
    Write-Host ""
    $configDetails += "API Auth: Configuration directory not found"
}

# Domain Controller Connectivity Tests
Write-Host "Domain Controller Connectivity:" -ForegroundColor White

# Get domain info
try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domainName = $domain.Name
    $domainControllers = $domain.DomainControllers
    
    Write-Host "  Domain: $domainName" -ForegroundColor Gray
    Write-Host ""
    
    # Test first 3 DCs
    $dcCount = 0
    foreach ($dc in $domainControllers | Select-Object -First 3) {
        $dcCount++
        $dcName = $dc.Name
        
        Write-Host "  Domain Controller: $dcName" -ForegroundColor Cyan
        
        # Test LDAP (389)
        try {
            $ldapTest = Test-NetConnection -ComputerName $dcName -Port 389 -WarningAction SilentlyContinue -ErrorAction Stop
            if ($ldapTest.TcpTestSucceeded) {
                Write-Host "    LDAP (389):   [PASS]" -ForegroundColor Green
            }
            else {
                Write-Host "    LDAP (389):   [FAIL] Port not reachable" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "    LDAP (389):   [FAIL] $($_.Exception.Message)" -ForegroundColor Red
        }
        
        # Test LDAPS (636)
        try {
            $ldapsTest = Test-NetConnection -ComputerName $dcName -Port 636 -WarningAction SilentlyContinue -ErrorAction Stop
            if ($ldapsTest.TcpTestSucceeded) {
                Write-Host "    LDAPS (636):  [PASS]" -ForegroundColor Green
            }
            else {
                Write-Host "    LDAPS (636):  [FAIL] Port not reachable" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "    LDAPS (636):  [FAIL] $($_.Exception.Message)" -ForegroundColor Red
        }
        
        Write-Host ""
    }
    
    if ($domainControllers.Count -gt 3) {
        Write-Host "  ... and $($domainControllers.Count - 3) more domain controllers" -ForegroundColor DarkGray
        Write-Host ""
    }
}
catch {
    Write-Host "  [WARNING] Could not query domain controllers: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host ""
}

# ===================================================================
# SECTION 7: EVENT LOG ANALYSIS (4 CATEGORIES) (VERBOSE MODE ONLY)
# ===================================================================

if ($VerboseMode) {

Write-Host "SECTION 7: EVENT LOG ANALYSIS" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

# Get last 20 events from Application log
$maxEvents = 20
$jobScheduleEvents = @()
$startStopEvents = @()
$otherEvents = @()

try {
    $appEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Application'
        ProviderName = 'SHDelegator'
    } -MaxEvents $maxEvents -ErrorAction SilentlyContinue
    
    # Categorize events
    foreach ($event in $appEvents) {
        if ($event.Id -eq 9001) {
            $jobScheduleEvents += $event
        }
        elseif ($event.Id -eq 0) {
            $startStopEvents += $event
        }
        else {
            $otherEvents += $event
        }
    }
    
    # Category 1: Job Schedules (9001)
    if ($jobScheduleEvents.Count -gt 0) {
        Write-Host "RUNNING JOB SCHEDULES (Event ID 9001)" -ForegroundColor Cyan
        Write-Host "-" * 80 -ForegroundColor DarkGray
        
        $section7Details += ""
        $section7Details += "RUNNING JOB SCHEDULES (Event ID 9001) - Last $($jobScheduleEvents.Count) events:"
        
        $sampleCount = 0
        foreach ($event in $jobScheduleEvents) {
            $timestamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            $levelText = switch ($event.Level) { 1 { "Critical" } 2 { "Error" } 3 { "Warn" } 4 { "Info" } default { "Info" } }
            $message = ($event.Message -split "`n")[0].Trim()
            if ($message.Length -gt 60) { $message = $message.Substring(0, 57) + "..." }
            
            # Extract Event Data
            $eventDataString = ""
            if ($event.Properties) {
                $eventDataPairs = @()
                $propertyNames = @('Duration', 'Objects', 'Status', 'Target', 'Method', 'Computer', 'Error', 'Version', 'Account')
                
                for ($i = 0; $i -lt $event.Properties.Count; $i++) {
                    $value = $event.Properties[$i].Value
                    if ($value) {
                        $propName = if ($i -lt $propertyNames.Count) { $propertyNames[$i] } else { "Prop$i" }
                        $valueStr = $value.ToString().Trim()
                        if ($valueStr) { $eventDataPairs += "$propName=$valueStr" }
                    }
                }
                if ($eventDataPairs.Count -gt 0) { $eventDataString = $eventDataPairs -join ' ' }
            }
            
            $levelColor = switch ($levelText) { "Critical" { "Red" } "Error" { "Red" } "Warn" { "Yellow" } default { "Gray" } }
            $line = "[$timestamp] $($levelText.PadRight(5)) | $message"
            if ($eventDataString) { $line += " | $eventDataString" }
            
            Write-Host $line -ForegroundColor $levelColor
            
            # Add first 5 to report
            if ($sampleCount -lt 5) {
                $section7Details += "  $line"
                $sampleCount++
            }
        }
        if ($jobScheduleEvents.Count -gt 5) {
            $section7Details += "  ... and $($jobScheduleEvents.Count - 5) more job schedule events"
        }
        Write-Host ""
    }
    
    # Category 2: Start/Stop Events (0)
    if ($startStopEvents.Count -gt 0) {
        Write-Host "SERVICE START/STOP EVENTS (Event ID 0)" -ForegroundColor Cyan
        Write-Host "-" * 80 -ForegroundColor DarkGray
        
        $section7Details += ""
        $section7Details += "SERVICE START/STOP EVENTS (Event ID 0) - Last $($startStopEvents.Count) events:"
        
        $sampleCount = 0
        foreach ($event in $startStopEvents) {
            $timestamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            $levelText = switch ($event.Level) { 1 { "Critical" } 2 { "Error" } 3 { "Warn" } 4 { "Info" } default { "Info" } }
            $message = ($event.Message -split "`n")[0].Trim()
            if ($message.Length -gt 60) { $message = $message.Substring(0, 57) + "..." }
            
            # Extract Event Data
            $eventDataString = ""
            if ($event.Properties) {
                $eventDataPairs = @()
                $propertyNames = @('Duration', 'Objects', 'Status', 'Target', 'Method', 'Computer', 'Error', 'Version', 'Account')
                
                for ($i = 0; $i -lt $event.Properties.Count; $i++) {
                    $value = $event.Properties[$i].Value
                    if ($value) {
                        $propName = if ($i -lt $propertyNames.Count) { $propertyNames[$i] } else { "Prop$i" }
                        $valueStr = $value.ToString().Trim()
                        if ($valueStr) { $eventDataPairs += "$propName=$valueStr" }
                    }
                }
                if ($eventDataPairs.Count -gt 0) { $eventDataString = $eventDataPairs -join ' ' }
            }
            
            $levelColor = switch ($levelText) { "Critical" { "Red" } "Error" { "Red" } "Warn" { "Yellow" } default { "Gray" } }
            $line = "[$timestamp] $($levelText.PadRight(5)) | $message"
            if ($eventDataString) { $line += " | $eventDataString" }
            
            Write-Host $line -ForegroundColor $levelColor
            
            # Add first 3 to report
            if ($sampleCount -lt 3) {
                $section7Details += "  $line"
                $sampleCount++
            }
        }
        if ($startStopEvents.Count -gt 3) {
            $section7Details += "  ... and $($startStopEvents.Count - 3) more start/stop events"
        }
        Write-Host ""
    }
    
    # Category 3: Other Events
    if ($otherEvents.Count -gt 0) {
        Write-Host "OTHER ERRORS (Event IDs: $($otherEvents.Id | Select-Object -Unique | Sort-Object))" -ForegroundColor Cyan
        Write-Host "-" * 80 -ForegroundColor DarkGray
        
        $section7Details += ""
        $section7Details += "OTHER ERRORS - Event IDs: $($otherEvents.Id | Select-Object -Unique | Sort-Object):"
        
        $sampleCount = 0
        foreach ($event in $otherEvents | Select-Object -First 10) {
            $timestamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            $levelText = switch ($event.Level) { 1 { "Critical" } 2 { "Error" } 3 { "Warn" } 4 { "Info" } default { "Info" } }
            $message = ($event.Message -split "`n")[0].Trim()
            if ($message.Length -gt 60) { $message = $message.Substring(0, 57) + "..." }
            
            $levelColor = switch ($levelText) { "Critical" { "Red" } "Error" { "Red" } "Warn" { "Yellow" } default { "Gray" } }
            $line = "[$timestamp] ID $($event.Id) $levelText | $message"
            Write-Host $line -ForegroundColor $levelColor
            
            # Add first 3 to report
            if ($sampleCount -lt 3) {
                $section7Details += "  $line"
                $sampleCount++
            }
        }
        if ($otherEvents.Count -gt 3) {
            $section7Details += "  ... and $($otherEvents.Count - 3) more other events"
        }
        Write-Host ""
    }
    
    # Category 4: gMSA Authentication Events (Security log - requires admin)
    if ($isAdmin -and $isGMSA) {
        Write-Host "gMSA AUTHENTICATION EVENTS (Last 10 from Security log)" -ForegroundColor Cyan
        Write-Host "-" * 80 -ForegroundColor DarkGray
        
        $section7Details += ""
        $section7Details += "gMSA AUTHENTICATION EVENTS (Last 10 from Security log):"
        
        try {
            $gmsaAccount = $serviceAccount
            $accountName = if ($gmsaAccount -like "*\*") { $gmsaAccount.Split('\')[1] } else { $gmsaAccount }
            
            $secEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                Id = 4624,4625,4768,4771
            } -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object { 
                $_.Message -like "*$accountName*" 
            } | Select-Object -First 10
            
            $successCount = 0
            $failureCount = 0
            
            $sampleCount = 0
            foreach ($event in $secEvents) {
                $timestamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                
                $eventType = switch ($event.Id) {
                    4624 { $successCount++; "Successful Logon"; "Green" }
                    4625 { $failureCount++; "Failed Logon"; "Red" }
                    4768 { "Kerberos TGT Request"; "Cyan" }
                    4771 { $failureCount++; "Kerberos Pre-Auth Failed"; "Red" }
                    default { "Unknown"; "Gray" }
                }
                
                Write-Host "[$timestamp] ID $($event.Id) | $($eventType[0])".PadRight(50) -NoNewline -ForegroundColor $eventType[1]
                Write-Host "| Account=$accountName" -ForegroundColor DarkGray
                
                # Add first 5 to report
                if ($sampleCount -lt 5) {
                    $section7Details += "  [$timestamp] ID $($event.Id) | $($eventType[0]) | Account=$accountName"
                    $sampleCount++
                }
            }
            
            Write-Host ""
            $summaryLine = "gMSA Auth Summary: $successCount successful, $failureCount failed"
            Write-Host $summaryLine -ForegroundColor $(if ($failureCount -eq 0) { "Green" } else { "Yellow" })
            $section7Details += ""
            $section7Details += "  $summaryLine"
            Write-Host ""
        }
        catch {
            Write-Host "[WARNING] Could not access Security log (Administrator required)" -ForegroundColor Yellow
            $section7Details += "  [WARNING] Could not access Security log (Administrator required)"
            Write-Host ""
        }
    }
    elseif ($isGMSA) {
        Write-Host "gMSA AUTHENTICATION EVENTS" -ForegroundColor Cyan
        Write-Host "-" * 80 -ForegroundColor DarkGray
        Write-Host "[INFO] Run as Administrator to see gMSA authentication events" -ForegroundColor Yellow
        Write-Host ""
    }
    
    # Summary
    $totalEvents = $jobScheduleEvents.Count + $startStopEvents.Count + $otherEvents.Count
    Write-Host "Summary: Job Schedules=$($jobScheduleEvents.Count), Start/Stop=$($startStopEvents.Count), Other=$($otherEvents.Count) | Total: $totalEvents events analyzed" -ForegroundColor Cyan
    Write-Host ""
    
    # Add detailed counts to verbose report
    $errorCount = ($appEvents | Where-Object { $_.Level -eq 2 }).Count
    $warnCount = ($appEvents | Where-Object { $_.Level -eq 3 }).Count
    if ($errorCount -gt 0 -or $warnCount -gt 0) {
        $verboseDetails += "Event Logs: $totalEvents events ($errorCount errors, $warnCount warnings)"
    }
    else {
        $verboseDetails += "Event Logs: $totalEvents events analyzed (no errors)"
    }
    
    # Add summary for report
    $section7Details += "Event Log Analysis Summary:"
    $section7Details += "  Total Events Analyzed: $totalEvents"
    $section7Details += "  Job Schedule Events (ID 9001): $($jobScheduleEvents.Count)"
    $section7Details += "  Start/Stop Events (ID 0): $($startStopEvents.Count)"  
    $section7Details += "  Other Events: $($otherEvents.Count)"
    $section7Details += "  Errors (Level 2): $errorCount"
    $section7Details += "  Warnings (Level 3): $warnCount"
    if ($errorCount -gt 0) {
        $section7Details += ""
        $section7Details += "  [!] Errors found - review transcript for details"
    }
}
catch {
    Write-Host "[ERROR] Failed to query event logs: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    $verboseDetails += "Event Logs: Unable to query"
    $section7Details += "Event Log Analysis: Unable to query event logs"
}

} # End of Section 7 (Verbose Mode Only)


# ===================================================================
# SECTION 8: WER CRASH ANALYSIS (VERBOSE MODE ONLY)
# ===================================================================

if ($VerboseMode) {

Write-Host "SECTION 8: WER CRASH ANALYSIS" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

$werPaths = @(
    "$env:LOCALAPPDATA\CrashDumps",
    "C:\ProgramData\Microsoft\Windows\WER\ReportQueue",
    "C:\ProgramData\Microsoft\Windows\WER\ReportArchive"
)

$allCrashes = @()
$cutoffDate = (Get-Date).AddDays(-30)

foreach ($path in $werPaths) {
    if (Test-Path $path) {
        $crashes = Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -like "*SHDelegator*" -or $_.Name -like "*SharpHound*"
        } | Where-Object {
            $_.CreationTime -gt $cutoffDate
        }
        
        foreach ($crash in $crashes) {
            $reportFile = Get-ChildItem -Path $crash.FullName -Filter "Report.wer" -ErrorAction SilentlyContinue | Select-Object -First 1
            
            if ($reportFile) {
                $content = Get-Content $reportFile.FullName -Raw -ErrorAction SilentlyContinue
                
                $crashInfo = [PSCustomObject]@{
                    Timestamp = $crash.CreationTime
                    Name = $crash.Name
                    Type = if ($crash.Name -like "*AppCrash*") { "AppCrash" } elseif ($crash.Name -like "*AppHang*") { "AppHang" } else { "Unknown" }
                    ExceptionCode = if ($content -match 'ExceptionCode=(\w+)') { $matches[1] } else { "Unknown" }
                    FaultModule = if ($content -match 'FaultingModule=([^\r\n]+)') { $matches[1] } else { "Unknown" }
                    FaultOffset = if ($content -match 'FaultingModuleOffset=(\w+)') { $matches[1] } else { "Unknown" }
                    Location = if ($path -like "*ReportQueue*") { "ReportQueue" } else { "ReportArchive" }
                    Path = $crash.FullName
                }
                
                $allCrashes += $crashInfo
            }
        }
    }
}

if ($allCrashes.Count -gt 0) {
    Write-Host "Windows Error Reports - SHDelegator (Last 30 Days): $($allCrashes.Count) crashes found" -ForegroundColor Yellow
    Write-Host ""
    
    $section8Details += "Windows Error Reports - SHDelegator (Last 30 Days):"
    $section8Details += "Total Crashes Found: $($allCrashes.Count)"
    $section8Details += ""
    
    # Categorize crashes
    $categories = @{
        "ACCESS VIOLATIONS" = @()
        ".NET RUNTIME ERRORS" = @()
        "CLR EXCEPTIONS" = @()
        "APPLICATION HANGS" = @()
        "OTHER CRASHES" = @()
    }
    
    foreach ($crash in ($allCrashes | Sort-Object Timestamp -Descending | Select-Object -First 10)) {
        $exCode = $crash.ExceptionCode
        
        if ($exCode -eq "0xC0000005" -or $exCode -eq "c0000005") {
            $categories["ACCESS VIOLATIONS"] += $crash
        }
        elseif ($exCode -eq "0xE0434352" -or $exCode -eq "e0434352") {
            $categories[".NET RUNTIME ERRORS"] += $crash
        }
        elseif ($exCode -eq "0x80131623" -or $exCode -eq "80131623") {
            $categories["CLR EXCEPTIONS"] += $crash
        }
        elseif ($crash.Type -eq "AppHang") {
            $categories["APPLICATION HANGS"] += $crash
        }
        else {
            $categories["OTHER CRASHES"] += $crash
        }
    }
    
    # Display by category
    foreach ($category in @("ACCESS VIOLATIONS", ".NET RUNTIME ERRORS", "CLR EXCEPTIONS", "APPLICATION HANGS", "OTHER CRASHES")) {
        $items = $categories[$category]
        
        if ($items.Count -gt 0) {
            Write-Host "$category ($($items.Count) crashes)" -ForegroundColor Yellow
            $section8Details += "$category ($($items.Count) crashes):"
            
            foreach ($crash in $items) {
                $line = "  [$($crash.Timestamp.ToString('yyyy-MM-dd HH:mm'))] $($crash.Type) $($crash.ExceptionCode)"
                
                if ($crash.ExceptionCode -eq "0xC0000005") { $line += " (Access Violation)" }
                elseif ($crash.ExceptionCode -eq "0xE0434352") { $line += " (.NET Runtime)" }
                elseif ($crash.ExceptionCode -eq "0x80131623") { $line += " (CLR Exception)" }
                
                if ($crash.FaultModule -ne "Unknown") {
                    $line += " | Module=$($crash.FaultModule)"
                }
                
                if ($crash.FaultOffset -ne "Unknown") {
                    $line += " Offset=$($crash.FaultOffset)"
                }
                
                $line += " | $($crash.Location)"
                
                Write-Host $line -ForegroundColor Gray
                $section8Details += $line
            }
            Write-Host ""
            $section8Details += ""
        }
    }
    
    # Determine most common crash type
    $mostCommon = $categories.GetEnumerator() | Where-Object { $_.Value.Count -gt 0 } | Sort-Object { $_.Value.Count } -Descending | Select-Object -First 1
    if ($mostCommon) {
        $percentage = [Math]::Round(($mostCommon.Value.Count / $allCrashes.Count) * 100, 0)
        Write-Host "Status: [WARN] $($allCrashes.Count) crashes in 30 days - most common: $($mostCommon.Key) ($percentage%)" -ForegroundColor Yellow
    }
}
else {
    Write-Host "Windows Error Reports - SHDelegator (Last 30 Days): 0 crashes found" -ForegroundColor Green
    Write-Host ""
    
    $section8Details += "Windows Error Reports - SHDelegator (Last 30 Days):"
    $section8Details += "Total Crashes Found: 0"
    $section8Details += ""
    $section8Details += "Status: [PASS] No crashes detected in the last 30 days"
    
    # Show last WER file for verification
    $lastWerFile = $null
    $lastWerDate = $null
    $lastWerLocation = $null
    
    foreach ($path in $werPaths) {
        if (Test-Path $path) {
            $lastFile = Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue | Sort-Object CreationTime -Descending | Select-Object -First 1
            if ($lastFile) {
                if (-not $lastWerDate -or $lastFile.CreationTime -gt $lastWerDate) {
                    $lastWerFile = $lastFile.Name
                    $lastWerDate = $lastFile.CreationTime
                    $lastWerLocation = if ($path -like "*ReportQueue*") { "ReportQueue" } else { "ReportArchive" }
                }
            }
        }
    }
    
    if ($lastWerFile) {
        Write-Host "> Last WER report in $lastWerLocation $lastWerFile from $($lastWerDate.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
        Write-Host ""
        $section8Details += ""
        $section8Details += "Last WER File Found:"
        $section8Details += "  Location: $lastWerLocation"
        $section8Details += "  File: $lastWerFile"
        $section8Details += "  Date: $($lastWerDate.ToString('yyyy-MM-dd HH:mm:ss'))"
    }
    
    Write-Host "Status: [PASS] No crashes detected" -ForegroundColor Green
    $verboseDetails += "Crash Reports: 0 crashes found (last 30 days)"
}

Write-Host ""

if ($allCrashes.Count -gt 0) {
    $verboseDetails += "Crash Reports: $($allCrashes.Count) crashes found (last 30 days)"
}
else {
    if (-not ($verboseDetails | Where-Object { $_ -like "Crash Reports:*" })) {
        $verboseDetails += "Crash Reports: 0 crashes found (last 30 days)"
    }
}

} # End of Section 8 (Verbose Mode Only)


# ===================================================================
# SECTION 9: SERVICE.ZIP LOG ANALYSIS (VERBOSE MODE ONLY)
# ===================================================================

if ($VerboseMode) {

Write-Host "SECTION 9: SERVICE.ZIP LOG ANALYSIS" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

# Auto-detect log_archive path
$archivePath = $null
$searchPaths = @(
    "C:\Users\$username\AppData\Roaming\BloodHoundEnterprise\log_archive",
    "C:\Users\$username\AppData\Local\BloodHoundEnterprise\log_archive",
    "C:\ProgramData\BloodHoundEnterprise\log_archive",
    "$env:APPDATA\BloodHoundEnterprise\log_archive"
)

foreach ($path in $searchPaths) {
    if (Test-Path $path) {
        $archivePath = $path
        break
    }
}

if ($archivePath) {
    Write-Host "Archive Path: $archivePath" -ForegroundColor Green
    Write-Host ""
    
    # Find service.zip files
    $serviceZips = Get-ChildItem -Path $archivePath -Filter "*service.zip" -File -ErrorAction SilentlyContinue |
                    Sort-Object CreationTime -Descending |
                    Select-Object -First 10
    
    if ($serviceZips.Count -gt 0) {
        Write-Host "Found $($serviceZips.Count) service.zip file(s)" -ForegroundColor Cyan
        Write-Host ""
        
        $fileNumber = 1
        $totalServiceErrors = 0
        $totalServiceWarnings = 0
        
        foreach ($zipFile in $serviceZips) {
            Write-Host "[$fileNumber] $($zipFile.Name) ($([Math]::Round($zipFile.Length / 1MB, 1)) MB) | $($zipFile.CreationTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Yellow
            
            try {
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                
                $zip = [System.IO.Compression.ZipFile]::OpenRead($zipFile.FullName)
                $logEntry = $zip.Entries | Where-Object { $_.Name -eq "service.log" } | Select-Object -First 1
                
                if ($logEntry) {
                    $tempFile = [System.IO.Path]::GetTempFileName()
                    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($logEntry, $tempFile, $true)
                    
                    $logLines = Get-Content $tempFile -ErrorAction SilentlyContinue
                    $totalLines = $logLines.Count
                    $errorLines = $logLines | Where-Object { $_ -match '\bERROR\b|\bFATAL\b|\bEXCEPTION\b' }
                    $warningLines = $logLines | Where-Object { $_ -match '\bWARN\b|\bWARNING\b' }
                    
                    $totalServiceErrors += $errorLines.Count
                    $totalServiceWarnings += $warningLines.Count
                    
                    $statusColor = if ($errorLines.Count -gt 0) { "Yellow" } elseif ($warningLines.Count -gt 0) { "Cyan" } else { "Green" }
                    Write-Host "  service.log: $totalLines lines, $($errorLines.Count) errors, $($warningLines.Count) warnings" -ForegroundColor $statusColor
                    
                    if ($errorLines.Count -gt 0) {
                        Write-Host ""
                        Write-Host "  Errors Found:" -ForegroundColor Red
                        $section9Details += ""
                        $section9Details += "  File: $($zip.Name)"
                        $section9Details += "  Errors Found ($($errorLines.Count) total):"
                        
                        $errorLines | Select-Object -First 5 | ForEach-Object {
                            $line = $_.Trim()
                            if ($line -match '(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})') {
                                $timestamp = $matches[1]
                                $line = $line -replace '\[?\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\]?\s*', ''
                            }
                            else {
                                $timestamp = "Unknown time"
                            }
                            
                            if ($line.Length -gt 100) { $line = $line.Substring(0, 97) + "..." }
                            Write-Host "    [$timestamp] $line" -ForegroundColor Gray
                            $section9Details += "    [$timestamp] $line"
                        }
                        
                        if ($errorLines.Count -gt 5) {
                            Write-Host "    ... and $($errorLines.Count - 5) more errors" -ForegroundColor DarkGray
                            $section9Details += "    ... and $($errorLines.Count - 5) more errors"
                        }
                    }
                    
                    if ($warningLines.Count -gt 0) {
                        Write-Host ""
                        Write-Host "  Warnings Found:" -ForegroundColor Yellow
                        
                        if ($errorLines.Count -eq 0) {
                            $section9Details += ""
                            $section9Details += "  File: $($zip.Name)"
                        }
                        $section9Details += "  Warnings Found ($($warningLines.Count) total):"
                        
                        $warningLines | Select-Object -First 3 | ForEach-Object {
                            $line = $_.Trim()
                            if ($line -match '(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})') {
                                $timestamp = $matches[1]
                                $line = $line -replace '\[?\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\]?\s*', ''
                            }
                            else {
                                $timestamp = "Unknown time"
                            }
                            
                            if ($line.Length -gt 100) { $line = $line.Substring(0, 97) + "..." }
                            Write-Host "    [$timestamp] $line" -ForegroundColor DarkGray
                            $section9Details += "    [$timestamp] $line"
                        }
                        
                        if ($warningLines.Count -gt 3) {
                            Write-Host "    ... and $($warningLines.Count - 3) more warnings" -ForegroundColor DarkGray
                            $section9Details += "    ... and $($warningLines.Count - 3) more warnings"
                        }
                    }
                    
                    if ($errorLines.Count -eq 0 -and $warningLines.Count -eq 0) {
                        Write-Host "  Status: No errors or warnings found" -ForegroundColor Green
                    }
                    
                    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                }
                else {
                    Write-Host "  service.log not found in ZIP" -ForegroundColor Yellow
                }
                
                $zip.Dispose()
            }
            catch {
                Write-Host "  Error reading ZIP: $($_.Exception.Message)" -ForegroundColor Red
            }
            
            Write-Host ""
            $fileNumber++
        }
        
        Write-Host "Summary: Analyzed $($serviceZips.Count) service.zip file(s)" -ForegroundColor Cyan
        
        $section9Details += ""
        $section9Details += "Summary: Analyzed $($serviceZips.Count) service.zip files"
        $section9Details += "  Total Errors: $totalServiceErrors"
        $section9Details += "  Total Warnings: $totalServiceWarnings"
        
        if ($totalServiceErrors -gt 0 -or $totalServiceWarnings -gt 0) {
            $verboseDetails += "Service.zip Logs: $($serviceZips.Count) files ($totalServiceErrors errors, $totalServiceWarnings warnings)"
        }
        else {
            $verboseDetails += "Service.zip Logs: $($serviceZips.Count) files (no errors)"
        }
    }
    else {
        Write-Host "No service.zip files found in archive" -ForegroundColor Yellow
        $verboseDetails += "Service.zip Logs: No files found"
        $section9Details += "No service.zip files found in archive"
    }
}
else {
    Write-Host "[WARNING] Log archive directory not found" -ForegroundColor Yellow
    $verboseDetails += "Service.zip Logs: Archive directory not found"
    $section9Details += "[WARNING] Log archive directory not found"
}

Write-Host ""

} # End of Section 9 (Verbose Mode Only)


# ===================================================================
# SECTION 10: DATE.ZIP COLLECTION ANALYSIS (VERBOSE MODE ONLY)
# ===================================================================

if ($VerboseMode) {

Write-Host "SECTION 10: DATE.ZIP COLLECTION ANALYSIS" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

if ($archivePath) {
    Write-Host "Archive Path: $archivePath" -ForegroundColor Green
    Write-Host ""
    
    # Find date-based ZIP files
    $dateZips = Get-ChildItem -Path $archivePath -Filter "*.zip" -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^\d{4}-\d{2}-\d{2}-' } |
                Where-Object { $_.Name -notlike "*service*" } |
                Sort-Object CreationTime -Descending |
                Select-Object -First 10
    
    if ($dateZips.Count -gt 0) {
        Write-Host "Found $($dateZips.Count) collection archive file(s)" -ForegroundColor Cyan
        Write-Host ""
        
        $fileNumber = 1
        $allFailedComputers = @{}
        $totalCollections = 0
        $totalFailed = 0
        $totalSuccess = 0
        
        foreach ($zipFile in $dateZips) {
            Write-Host "[$fileNumber] $($zipFile.Name) ($([Math]::Round($zipFile.Length / 1KB, 0)) KB) | $($zipFile.CreationTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Yellow
            
            try {
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                
                $zip = [System.IO.Compression.ZipFile]::OpenRead($zipFile.FullName)
                
                # DEBUG: Show all files in ZIP
                Write-Host "  ZIP Contents:" -ForegroundColor DarkGray
                foreach ($entry in $zip.Entries) {
                    Write-Host "    - Name: $($entry.Name) | FullName: $($entry.FullName)" -ForegroundColor DarkGray
                }
                Write-Host ""
                
                # Find run.log (very flexible pattern)
                $runLogEntry = $zip.Entries | Where-Object { 
                    $_.Name -like "*run.log*" -or
                    $_.Name -eq "run.log" -or
                    $_.FullName -like "*run.log*"
                } | Select-Object -First 1
                
                # Find compstatus.csv (very flexible pattern)
                $compStatusEntry = $zip.Entries | Where-Object { 
                    $_.Name -like "*compstatus.csv*" -or
                    $_.Name -eq "compstatus.csv" -or
                    $_.FullName -like "*compstatus.csv*"
                } | Select-Object -First 1
                
                Write-Host "  Detection Results:" -ForegroundColor Cyan
                Write-Host "    run.log:        $(if ($runLogEntry) { 'FOUND (' + $runLogEntry.Name + ')' } else { 'NOT FOUND' })" -ForegroundColor $(if ($runLogEntry) { 'Green' } else { 'Red' })
                Write-Host "    compstatus.csv: $(if ($compStatusEntry) { 'FOUND (' + $compStatusEntry.Name + ')' } else { 'NOT FOUND' })" -ForegroundColor $(if ($compStatusEntry) { 'Green' } else { 'Red' })
                Write-Host ""
                
                # Process run.log
                if ($runLogEntry) {
                    $tempFile = [System.IO.Path]::GetTempFileName()
                    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($runLogEntry, $tempFile, $true)
                    
                    $logLines = Get-Content $tempFile -ErrorAction SilentlyContinue
                    $totalLines = $logLines.Count
                    $errorLines = $logLines | Where-Object { $_ -match '\bERROR\b|\bFATAL\b|\bEXCEPTION\b' }
                    $warningLines = $logLines | Where-Object { $_ -match '\bWARN\b|\bWARNING\b' }
                    
                    $statusColor = if ($errorLines.Count -gt 0) { "Yellow" } elseif ($warningLines.Count -gt 0) { "Cyan" } else { "Green" }
                    Write-Host "  run.log: $totalLines lines, $($errorLines.Count) errors, $($warningLines.Count) warnings" -ForegroundColor $statusColor
                    
                    if ($errorLines.Count -gt 0) {
                        Write-Host ""
                        Write-Host "  Errors:" -ForegroundColor Red
                        $errorLines | Select-Object -First 3 | ForEach-Object {
                            $line = $_.Trim()
                            if ($line -match '(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})') {
                                $timestamp = $matches[1]
                                $line = $line -replace '\[?\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\]?\s*', ''
                            }
                            else {
                                $timestamp = "Unknown"
                            }
                            if ($line.Length -gt 80) { $line = $line.Substring(0, 77) + "..." }
                            Write-Host "    [$timestamp] $line" -ForegroundColor Gray
                        }
                    }
                    
                    if ($warningLines.Count -gt 0) {
                        Write-Host ""
                        Write-Host "  Warnings:" -ForegroundColor Yellow
                        $warningLines | Select-Object -First 3 | ForEach-Object {
                            $line = $_.Trim()
                            if ($line -match '(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})') {
                                $timestamp = $matches[1]
                                $line = $line -replace '\[?\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\]?\s*', ''
                            }
                            else {
                                $timestamp = "Unknown"
                            }
                            if ($line.Length -gt 80) { $line = $line.Substring(0, 77) + "..." }
                            Write-Host "    [$timestamp] $line" -ForegroundColor DarkGray
                        }
                        if ($warningLines.Count -gt 3) {
                            Write-Host "    ... and $($warningLines.Count - 3) more warnings" -ForegroundColor DarkGray
                        }
                    }
                    
                    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                }
                else {
                    Write-Host "  run.log: Not found in this archive" -ForegroundColor Yellow
                }
                
                # Process compstatus.csv
                if ($compStatusEntry) {
                    $tempFile = [System.IO.Path]::GetTempFileName()
                    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($compStatusEntry, $tempFile, $true)
                    
                    $csvData = Import-Csv $tempFile -ErrorAction SilentlyContinue
                    
                    if ($csvData) {
                        $totalComputers = $csvData.Count
                        $successfulComputers = ($csvData | Where-Object { $_.Status -eq "Success" -or $_.Status -eq "0" }).Count
                        $failedComputers = $totalComputers - $successfulComputers
                        $successRate = if ($totalComputers -gt 0) { [Math]::Round(($successfulComputers / $totalComputers) * 100, 1) } else { 0 }
                        
                        $totalCollections += $totalComputers
                        $totalSuccess += $successfulComputers
                        $totalFailed += $failedComputers
                        
                        Write-Host ""
                        Write-Host "  compstatus.csv: $totalComputers computers, $successfulComputers success ($successRate%), $failedComputers failed" -ForegroundColor $(if ($failedComputers -gt 0) { "Yellow" } else { "Green" })
                        
                        if ($failedComputers -gt 0) {
                            # Categorize failures
                            $categories = @{
                                "NETWORK ERRORS" = @()
                                "ACCESS DENIED" = @()
                                "TIMEOUT ERRORS" = @()
                                "MEMORY/RESOURCE ERRORS" = @()
                                "SMB/RPC ERRORS" = @()
                                "AUTHENTICATION ERRORS" = @()
                                "OTHER ERRORS" = @()
                            }
                            
                            $failedEntries = $csvData | Where-Object { $_.Status -ne "Success" -and $_.Status -ne "0" }
                            
                            foreach ($entry in $failedEntries) {
                                $computerName = $entry.ComputerName
                                $error = $entry.Error
                                $lastSeen = $entry.LastSeen
                                
                                # Categorize by error message
                                if ($error -match 'timeout|timed out|no response') {
                                    $categories["TIMEOUT ERRORS"] += $entry
                                }
                                elseif ($error -match 'access denied|permission|unauthorized|0x80070005') {
                                    $categories["ACCESS DENIED"] += $entry
                                }
                                elseif ($error -match 'network path|unreachable|0x80070035|cannot connect') {
                                    $categories["NETWORK ERRORS"] += $entry
                                }
                                elseif ($error -match 'memory|out of memory|resource') {
                                    $categories["MEMORY/RESOURCE ERRORS"] += $entry
                                }
                                elseif ($error -match 'smb|rpc|0x800706BA|0x800706BF') {
                                    $categories["SMB/RPC ERRORS"] += $entry
                                }
                                elseif ($error -match 'kerberos|ntlm|authentication|logon') {
                                    $categories["AUTHENTICATION ERRORS"] += $entry
                                }
                                else {
                                    $categories["OTHER ERRORS"] += $entry
                                }
                                
                                # Track last contact
                                if (-not $allFailedComputers.ContainsKey($computerName)) {
                                    $allFailedComputers[$computerName] = @{
                                        LastContact = $lastSeen
                                        Error = $error
                                        CollectionDate = $zipFile.CreationTime
                                    }
                                }
                            }
                            
                            Write-Host ""
                            Write-Host "  Failed Computers (by category):" -ForegroundColor Red
                            $section10Details += ""
                            $section10Details += "  Failed Computers Analysis:"
                            
                            foreach ($category in @("NETWORK ERRORS", "TIMEOUT ERRORS", "ACCESS DENIED", "MEMORY/RESOURCE ERRORS", "SMB/RPC ERRORS", "AUTHENTICATION ERRORS", "OTHER ERRORS")) {
                                $items = $categories[$category]
                                
                                if ($items.Count -gt 0) {
                                    Write-Host ""
                                    Write-Host "  $category ($($items.Count))" -ForegroundColor Yellow
                                    $section10Details += ""
                                    $section10Details += "  $category ($($items.Count)):"
                                    
                                    # Show first 3 from each category
                                    $items | Select-Object -First 3 | ForEach-Object {
                                        $computerName = $_.ComputerName
                                        $error = $_.Error
                                        $lastSeen = $_.LastSeen
                                        
                                        # Truncate error
                                        if ($error.Length -gt 40) {
                                            $error = $error.Substring(0, 37) + "..."
                                        }
                                        
                                        $line = "    $($computerName.PadRight(20)) | $error"
                                        
                                        if ($lastSeen) {
                                            $line += " | Last: $lastSeen"
                                        }
                                        
                                        Write-Host $line -ForegroundColor Gray
                                        $section10Details += $line
                                    }
                                    
                                    if ($items.Count -gt 3) {
                                        Write-Host "    ... and $($items.Count - 3) more" -ForegroundColor DarkGray
                                        $section10Details += "    ... and $($items.Count - 3) more"
                                    }
                                }
                            }
                        }
                        else {
                            Write-Host "  Status: All computers successful" -ForegroundColor Green
                        }
                    }
                    
                    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                }
                else {
                    Write-Host "  compstatus.csv: Not found in this archive" -ForegroundColor Yellow
                }
                
                $zip.Dispose()
            }
            catch {
                Write-Host "  Error reading ZIP: $($_.Exception.Message)" -ForegroundColor Red
            }
            
            Write-Host ""
            $fileNumber++
        }
        
        Write-Host "Summary: Analyzed $($dateZips.Count) collection archive file(s)" -ForegroundColor Cyan
        
        $section10Details += ""
        $section10Details += "Summary: Analyzed $($dateZips.Count) collection archives"
        
        if ($totalCollections -gt 0) {
            $successRate = [Math]::Round(($totalSuccess / $totalCollections) * 100, 1)
            $section10Details += "  Total Computers: $totalCollections"
            $section10Details += "  Successful: $totalSuccess"
            $section10Details += "  Failed: $totalFailed"
            $section10Details += "  Success Rate: $successRate%"
            
            if ($allFailedComputers.Count -gt 0) {
                Write-Host "Total unique failed computers across all collections: $($allFailedComputers.Count)" -ForegroundColor Yellow
                $section10Details += "  Unique Failed Computers: $($allFailedComputers.Count)"
            }
            else {
                $section10Details += "  Status: All collections successful (no failures)"
            }
            
            $verboseDetails += "Date.zip Collections: $($dateZips.Count) files, $totalCollections computers ($totalSuccess success, $totalFailed failed - $successRate% success)"
        }
        else {
            $section10Details += "  No computer statistics available (no compstatus.csv files found)"
            $verboseDetails += "Date.zip Collections: $($dateZips.Count) files analyzed"
        }
    }
    else {
        Write-Host "No collection archive files found" -ForegroundColor Yellow
        $verboseDetails += "Date.zip Collections: No files found"
        $section10Details += "No collection archive files found"
    }
}
else {
    Write-Host "[WARNING] Log archive directory not found" -ForegroundColor Yellow
    $verboseDetails += "Date.zip Collections: Archive directory not found"
    $section10Details += "[WARNING] Log archive directory not found"
}

Write-Host ""

} # End of Section 10 (Verbose Mode Only)

# Indicate Standard mode sections complete (moved to end of script)


# ===================================================================
# SECTION 11: PERFORMANCE METRICS & TRENDS (VERBOSE MODE ONLY)
# ===================================================================

if ($VerboseMode) {
    
    # Pre-check: Only show this section if we have enough data
    $showSection11 = $false
    $section11SkipReason = ""
    
    if ($archivePath) {
        $dateZipsForMetrics = Get-ChildItem -Path $archivePath -Filter "*.zip" -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '^\d{4}-\d{2}-\d{2}-' } |
                    Where-Object { $_.Name -notlike "*service*" } |
                    Sort-Object CreationTime -Descending |
                    Select-Object -First 20
        
        if ($dateZipsForMetrics.Count -ge 5) {
            # Quick check if we have enough metrics before showing section
            $quickMetricsCheck = 0
            foreach ($zipFile in ($dateZipsForMetrics | Select-Object -First 5)) {
                try {
                    Add-Type -AssemblyName System.IO.Compression.FileSystem
                    $zip = [System.IO.Compression.ZipFile]::OpenRead($zipFile.FullName)
                    $runLogEntry = $zip.Entries | Where-Object { $_.Name -like "*_run.log" } | Select-Object -First 1
                    if ($runLogEntry) {
                        $quickMetricsCheck++
                    }
                    $zip.Dispose()
                }
                catch { }
            }
            
            if ($quickMetricsCheck -ge 3) {
                $showSection11 = $true
            }
            else {
                $section11SkipReason = "Insufficient collection data for trend analysis (found $quickMetricsCheck with metrics, need 3+)"
            }
        }
        else {
            $section11SkipReason = "Not enough collection archives (found $($dateZipsForMetrics.Count), need 5+)"
        }
    }
    else {
        $section11SkipReason = "Archive directory not found"
    }
    
    # Only show section if we have enough data
    if ($showSection11) {
    
    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Magenta
    Write-Host " VERBOSE MODE: PERFORMANCE METRICS & TRENDS" -ForegroundColor Magenta
    Write-Host "=" * 80 -ForegroundColor Magenta
    Write-Host ""
    Write-Host "SECTION 11: PERFORMANCE METRICS & TRENDS" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""
    
    # Analyze last 20 collections for trends
    if ($archivePath) {
        $dateZipsForMetrics = Get-ChildItem -Path $archivePath -Filter "*.zip" -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '^\d{4}-\d{2}-\d{2}-' } |
                    Where-Object { $_.Name -notlike "*service*" } |
                    Sort-Object CreationTime -Descending |
                    Select-Object -First 20
        
        if ($dateZipsForMetrics.Count -ge 5) {
            Write-Host "Analyzing performance trends across last $($dateZipsForMetrics.Count) collections..." -ForegroundColor Yellow
            Write-Host ""
            
            $collectionMetrics = @()
            $filesProcessed = 0
            $filesWithMetrics = 0
            
            foreach ($zipFile in $dateZipsForMetrics) {
                try {
                    Add-Type -AssemblyName System.IO.Compression.FileSystem
                    
                    $zip = [System.IO.Compression.ZipFile]::OpenRead($zipFile.FullName)
                    
                    # Extract run.log (flexible pattern matching Section 10)
                    $runLogEntry = $zip.Entries | Where-Object { 
                        $_.Name -like "*run.log*" -or
                        $_.Name -eq "run.log" -or
                        $_.FullName -like "*run.log*"
                    } | Select-Object -First 1
                    
                    if ($runLogEntry) {
                        $filesProcessed++
                        $tempFile = [System.IO.Path]::GetTempFileName()
                        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($runLogEntry, $tempFile, $true)
                        
                        $logContent = Get-Content $tempFile -Raw -ErrorAction SilentlyContinue
                        
                        # Extract duration (in seconds)
                        $duration = $null
                        if ($logContent -match 'Duration[:\s]+(\d+)') {
                            $duration = [int]$matches[1]
                        }
                        elseif ($logContent -match '(\d+)\s*seconds') {
                            $duration = [int]$matches[1]
                        }
                        
                        # Extract objects collected
                        $objects = $null
                        if ($logContent -match 'Objects[:\s]+(\d+)') {
                            $objects = [int]$matches[1]
                        }
                        elseif ($logContent -match 'collected\s+(\d+)\s+objects') {
                            $objects = [int]$matches[1]
                        }
                        
                        # Check success
                        $success = $logContent -match 'success|completed successfully'
                        
                        if ($duration -or $objects) {
                            $filesWithMetrics++
                            $collectionMetrics += [PSCustomObject]@{
                                Date = $zipFile.CreationTime
                                Duration = $duration
                                Objects = $objects
                                Success = $success
                            }
                        }
                        
                        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                    }
                    
                    $zip.Dispose()
                }
                catch {
                    # Skip this file
                }
            }
            
            # Show what was found
            Write-Host "Processed: $filesProcessed run.log files, $filesWithMetrics with extractable metrics" -ForegroundColor Cyan
            Write-Host ""
            
            if ($collectionMetrics.Count -ge 3) {
                # Collection Duration Trends
                $validDurations = $collectionMetrics | Where-Object { $_.Duration -ne $null }
                
                if ($validDurations.Count -ge 3) {
                    Write-Host "Collection Duration Trends:" -ForegroundColor White
                    $section11Details += "Collection Duration Trends:"
                    
                    $avgDuration = [Math]::Round(($validDurations | Measure-Object -Property Duration -Average).Average, 0)
                    $minDuration = ($validDurations | Measure-Object -Property Duration -Minimum).Minimum
                    $maxDuration = ($validDurations | Measure-Object -Property Duration -Maximum).Maximum
                    
                    Write-Host "  Average Duration: $avgDuration seconds ($([Math]::Round($avgDuration / 60, 1)) minutes)" -ForegroundColor Gray
                    Write-Host "  Min Duration:     $minDuration seconds" -ForegroundColor Gray
                    Write-Host "  Max Duration:     $maxDuration seconds" -ForegroundColor Gray
                    $section11Details += "  Average Duration: $avgDuration seconds ($([Math]::Round($avgDuration / 60, 1)) minutes)"
                    $section11Details += "  Min Duration: $minDuration seconds"
                    $section11Details += "  Max Duration: $maxDuration seconds"
                    
                    # Trend analysis (simple: compare first half vs second half)
                    $halfPoint = [Math]::Floor($validDurations.Count / 2)
                    $firstHalf = $validDurations | Select-Object -First $halfPoint
                    $secondHalf = $validDurations | Select-Object -Last $halfPoint
                    
                    if ($firstHalf.Count -gt 0 -and $secondHalf.Count -gt 0) {
                        $firstHalfAvg = ($firstHalf | Measure-Object -Property Duration -Average).Average
                        $secondHalfAvg = ($secondHalf | Measure-Object -Property Duration -Average).Average
                        
                        $trend = if ($secondHalfAvg -lt ($firstHalfAvg * 0.9)) { "IMPROVING (faster)"; "Green" }
                                 elseif ($secondHalfAvg -gt ($firstHalfAvg * 1.1)) { "DEGRADING (slower)"; "Yellow" }
                                 else { "STABLE"; "Cyan" }
                        
                        Write-Host "  Trend:            $($trend[0])" -ForegroundColor $trend[1]
                        $section11Details += "  Trend: $($trend[0])"
                    }
                    
                    Write-Host ""
                    $section11Details += ""
                }
                
                # Objects Collected Trends
                $validObjects = $collectionMetrics | Where-Object { $_.Objects -ne $null }
                
                if ($validObjects.Count -ge 3) {
                    Write-Host "Objects Collected Trends:" -ForegroundColor White
                    $section11Details += "Objects Collected Trends:"
                    
                    $avgObjects = [Math]::Round(($validObjects | Measure-Object -Property Objects -Average).Average, 0)
                    $minObjects = ($validObjects | Measure-Object -Property Objects -Minimum).Minimum
                    $maxObjects = ($validObjects | Measure-Object -Property Objects -Maximum).Maximum
                    
                    Write-Host "  Average Objects:  $avgObjects objects" -ForegroundColor Gray
                    Write-Host "  Min Objects:      $minObjects objects" -ForegroundColor Gray
                    Write-Host "  Max Objects:      $maxObjects objects" -ForegroundColor Gray
                    $section11Details += "  Average Objects: $avgObjects objects"
                    $section11Details += "  Min Objects: $minObjects objects"
                    $section11Details += "  Max Objects: $maxObjects objects"
                    
                    # Trend analysis
                    $halfPoint = [Math]::Floor($validObjects.Count / 2)
                    $firstHalf = $validObjects | Select-Object -First $halfPoint
                    $secondHalf = $validObjects | Select-Object -Last $halfPoint
                    
                    if ($firstHalf.Count -gt 0 -and $secondHalf.Count -gt 0) {
                        $firstHalfAvg = ($firstHalf | Measure-Object -Property Objects -Average).Average
                        $secondHalfAvg = ($secondHalf | Measure-Object -Property Objects -Average).Average
                        
                        $trend = if ($secondHalfAvg -gt ($firstHalfAvg * 1.1)) { "INCREASING (more data)"; "Green" }
                                 elseif ($secondHalfAvg -lt ($firstHalfAvg * 0.9)) { "DECREASING (less data)"; "Yellow" }
                                 else { "STABLE"; "Cyan" }
                        
                        Write-Host "  Trend:            $($trend[0])" -ForegroundColor $trend[1]
                        $section11Details += "  Trend: $($trend[0])"
                    }
                    
                    Write-Host ""
                    $section11Details += ""
                }
                
                # Success Rate Trends
                Write-Host "Success Rate Trends:" -ForegroundColor White
                $section11Details += ""
                $section11Details += "Success Rate Trends:"
                
                $totalCollections = $collectionMetrics.Count
                $successfulCollections = ($collectionMetrics | Where-Object { $_.Success -eq $true }).Count
                $failedCollections = $totalCollections - $successfulCollections
                $successRate = [Math]::Round(($successfulCollections / $totalCollections) * 100, 1)
                
                Write-Host "  Total Collections:   $totalCollections" -ForegroundColor Gray
                Write-Host "  Successful:          $successfulCollections ($successRate%)" -ForegroundColor $(if ($successRate -ge 90) { "Green" } elseif ($successRate -ge 75) { "Yellow" } else { "Red" })
                Write-Host "  Failed:              $failedCollections" -ForegroundColor $(if ($failedCollections -eq 0) { "Green" } else { "Yellow" })
                $section11Details += "  Total Collections: $totalCollections"
                $section11Details += "  Successful: $successfulCollections ($successRate%)"
                $section11Details += "  Failed: $failedCollections"
                
                Write-Host ""
            }
            else {
                # Insufficient metrics - explain why
                Write-Host "[INFO] Not enough metrics extracted for trend analysis" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "Details:" -ForegroundColor Gray
                Write-Host "  - Found $($dateZipsForMetrics.Count) collection archives" -ForegroundColor DarkGray
                Write-Host "  - Processed $filesProcessed run.log files" -ForegroundColor DarkGray
                Write-Host "  - Extracted metrics from $filesWithMetrics files" -ForegroundColor DarkGray
                Write-Host "  - Need at least 3 files with metrics for trend analysis" -ForegroundColor DarkGray
                Write-Host ""
                Write-Host "Possible reasons:" -ForegroundColor Gray
                Write-Host "  - Log files use different format (metrics not found by regex)" -ForegroundColor DarkGray
                Write-Host "  - Log files are incomplete or corrupted" -ForegroundColor DarkGray
                Write-Host "  - Collections are too old and logs were purged" -ForegroundColor DarkGray
                Write-Host ""
                $section11Details += "[INFO] Not enough metrics extracted ($filesWithMetrics found, need 3+)"
                $section11Details += "Processed $filesProcessed run.log files but only extracted metrics from $filesWithMetrics"
            }
        }
        else {
            # Not enough archives
            Write-Host "[INFO] Not enough collection archives for trend analysis" -ForegroundColor Yellow
            Write-Host "  Found: $($dateZipsForMetrics.Count) archives" -ForegroundColor DarkGray
            Write-Host "  Need:  5+ archives" -ForegroundColor DarkGray
            Write-Host ""
            $section11Details += "[INFO] Not enough collection archives (found $($dateZipsForMetrics.Count), need 5+)"
        }
    }
    else {
        Write-Host "[INFO] Performance metrics require access to log archives" -ForegroundColor Yellow
        Write-Host ""
        $verboseDetails += "Performance Metrics: Archive directory not found"
        $section11Details += "[INFO] Performance metrics require access to log archives"
        $section11Details += "Expected archive path: $LogArchivePath"
    }
    
    # Add performance summary based on what was analyzed
    if ($archivePath -and $dateZipsForMetrics.Count -ge 5) {
        if ($collectionMetrics.Count -ge 3) {
            $verboseDetails += "Performance Metrics: Analyzed $($dateZipsForMetrics.Count) collections (trends available)"
        }
        else {
            $verboseDetails += "Performance Metrics: Analyzed $($dateZipsForMetrics.Count) collections (insufficient data for trends)"
        }
    }
    elseif ($archivePath -and $dateZipsForMetrics.Count -gt 0) {
        $verboseDetails += "Performance Metrics: Found $($dateZipsForMetrics.Count) collections (need 5+ for analysis)"
    }
    elseif (-not $archivePath) {
        # Already added above
    }
    else {
        $verboseDetails += "Performance Metrics: No collections available"
    }
    
    } # End of if ($showSection11)
    else {
        # Section skipped due to insufficient data
        $verboseDetails += "Performance Metrics: $section11SkipReason"
        $section11Details += "[SKIPPED] $section11SkipReason"
    }
    
} # End of Section 11 (Verbose Mode Only)


# ===================================================================
# FINAL SUMMARY
# ===================================================================

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host " DIAGNOSTIC SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

Write-Host "Script Version:     v$ScriptVersion" -ForegroundColor Gray
Write-Host "Execution Mode:     $(if ($VerboseMode) { 'VERBOSE' } else { 'STANDARD' })" -ForegroundColor Gray
Write-Host "Computer:           $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "Service Account:    $serviceAccount" -ForegroundColor Gray
Write-Host "Service Status:     $($service.State)" -ForegroundColor $(if ($service.State -eq 'Running') { 'Green' } else { 'Yellow' })
Write-Host "Administrator:      $(if ($isAdmin) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($isAdmin) { 'Green' } else { 'Yellow' })
Write-Host ""

# Overall Health Status
$healthIssues = @()

if ($requirementsFailures -gt 0) {
    $healthIssues += "System requirements not met ($requirementsFailures critical issues)"
}

if ($service.State -ne 'Running') {
    $healthIssues += "Service is not running"
}

if ($healthIssues.Count -eq 0) {
    Write-Host "Overall Health: [HEALTHY] No critical issues detected" -ForegroundColor Green
}
else {
    Write-Host "Overall Health: [ATTENTION NEEDED] $($healthIssues.Count) issue(s) found:" -ForegroundColor Yellow
    foreach ($issue in $healthIssues) {
        Write-Host "  - $issue" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host " END OF DIAGNOSTIC REPORT" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

Write-Host "For detailed analysis, review individual sections above." -ForegroundColor Gray

# Check if individual test scripts exist
$individualScripts = @(
    "RUN_SystemRequirementsTest.ps1",
    "RUN_EventLogTest.ps1",
    "RUN_CrashAnalysisTest.ps1",
    "RUN_ServiceZipTest.ps1",
    "RUN_DateZipTest.ps1",
    "Fix_API_Authentication_Test.ps1"
)

$scriptsExist = $false
foreach ($scriptName in $individualScripts) {
    if (Test-Path (Join-Path $PSScriptRoot $scriptName)) {
        $scriptsExist = $true
        break
    }
}

if ($scriptsExist) {
    Write-Host "For component-specific troubleshooting, use individual test scripts:" -ForegroundColor Gray
    foreach ($scriptName in $individualScripts) {
        if (Test-Path (Join-Path $PSScriptRoot $scriptName)) {
            Write-Host "  - $scriptName" -ForegroundColor DarkGray
        }
    }
}
else {
    Write-Host "Note: Individual test scripts are available separately if needed for targeted diagnostics." -ForegroundColor Gray
}

Write-Host ""

# Show Standard mode completion banner at the end
if (-not $VerboseMode) {
    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Green
    Write-Host " STANDARD MODE DIAGNOSTICS COMPLETE (4 sections)" -ForegroundColor Green
    Write-Host "=" * 80 -ForegroundColor Green
    Write-Host ""
    Write-Host "Sections completed:" -ForegroundColor Cyan
    Write-Host "  1. Service Detection & Status" -ForegroundColor Gray
    Write-Host "  2. System Requirements Validation" -ForegroundColor Gray
    Write-Host "  5. BloodHound Configuration & Schedules" -ForegroundColor Gray
    Write-Host "  6. API Authentication & DC Connectivity" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Run with -Verbose flag for additional diagnostics:" -ForegroundColor Yellow
    Write-Host "  3. Proxy Configuration & Connectivity" -ForegroundColor DarkGray
    Write-Host "  4. Antivirus Status & Exclusions" -ForegroundColor DarkGray
    Write-Host "  7. Event Log Analysis" -ForegroundColor DarkGray
    Write-Host "  8. Crash Report Analysis" -ForegroundColor DarkGray
    Write-Host "  9. Service.zip Log Analysis" -ForegroundColor DarkGray
    Write-Host "  10. Date.zip Collection Analysis" -ForegroundColor DarkGray
    Write-Host "  11. Performance Metrics & Trends" -ForegroundColor DarkGray
    Write-Host ""
}

# Show Verbose mode completion banner at the end
if ($VerboseMode) {
    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Magenta
    Write-Host " VERBOSE MODE DIAGNOSTICS COMPLETE (11 sections)" -ForegroundColor Magenta
    Write-Host "=" * 80 -ForegroundColor Magenta
    Write-Host ""
    Write-Host "Standard Sections completed:" -ForegroundColor Cyan
    Write-Host "  1. Service Detection & Status" -ForegroundColor Gray
    Write-Host "  2. System Requirements Validation" -ForegroundColor Gray
    Write-Host "  5. BloodHound Configuration & Schedules" -ForegroundColor Gray
    Write-Host "  6. API Authentication & DC Connectivity" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Verbose Sections completed:" -ForegroundColor Cyan
    Write-Host "  3. Proxy Configuration & Connectivity" -ForegroundColor Gray
    Write-Host "  4. Antivirus Status & Exclusions" -ForegroundColor Gray
    Write-Host "  7. Event Log Analysis" -ForegroundColor Gray
    Write-Host "  8. Crash Report Analysis" -ForegroundColor Gray
    Write-Host "  9. Service.zip Log Analysis" -ForegroundColor Gray
    Write-Host "  10. Date.zip Collection Analysis" -ForegroundColor Gray
    Write-Host "  11. Performance Metrics & Trends" -ForegroundColor Gray
    Write-Host ""
}

# ===================================================================
# STOP TRANSCRIPT AND GENERATE REPORT
# ===================================================================

Stop-Transcript | Out-Null

Write-Host "Transcript saved to: $transcriptPath" -ForegroundColor Green

# Generate summary report file
$reportPath = Join-Path $PSScriptRoot "SharpHound-Checker-v7-${ModeName}_Report_${ScriptDateFile}.txt"

$reportContent = @"
================================================================================
 SharpHound Checker v$ScriptVersion - $ModeName Mode Report
================================================================================

Execution Date:     $ScriptDate
Computer:           $env:COMPUTERNAME
Elevated:           $(if ($isAdmin) { 'Yes (Administrator)' } else { 'No' })
Service Account:    $serviceAccount
Service Status:     $($service.State)
Mode:               $ModeName

================================================================================
 SUMMARY
================================================================================

System Requirements:
  Critical Failures: $requirementsFailures
  Warnings:          $requirementsWarnings
  Overall Status:    $(if ($requirementsFailures -eq 0 -and $requirementsWarnings -eq 0) { 'PASS' } elseif ($requirementsFailures -eq 0) { 'WARN' } else { 'FAIL' })

$(if ($requirementDetails.Count -gt 0) {
"Test Results:
$(($requirementDetails | ForEach-Object { "  $_" }) -join "`n")"
})

Overall Health:      $(if ($healthIssues.Count -eq 0) { 'HEALTHY - No critical issues' } else { "ATTENTION NEEDED - $($healthIssues.Count) issue(s)" })

$(if ($healthIssues.Count -gt 0) {
"Issues Found:
$(($healthIssues | ForEach-Object { "  - $_" }) -join "`n")"
})

$(if ($configDetails.Count -gt 0) {
"
================================================================================
 CONFIGURATION
================================================================================

$(($configDetails | ForEach-Object { "  $_" }) -join "`n")"
})

================================================================================
 SECTIONS EXECUTED
================================================================================

Standard Mode (4 Core Sections):
  [X] Section 1:  Service Detection & Status
  [X] Section 2:  System Requirements Validation
  [X] Section 5:  BloodHound Configuration & Schedules
  [X] Section 6:  API Authentication & DC Connectivity

$(if ($VerboseMode) {
"Verbose Mode Additional (7 Detailed Sections):
  [X] Section 3:  Proxy Configuration & Connectivity
  [X] Section 4:  Antivirus Status & Exclusions
  [X] Section 7:  Event Log Analysis (4 categories)
  [X] Section 8:  WER Crash Analysis
  [X] Section 9:  Service.zip Log Analysis
  [X] Section 10: Date.zip Collection Analysis" +
  $(if ($showSection11) { "
  [X] Section 11: Performance Metrics & Trends" } else { "" }) + "
================================================================================
 VERBOSE FINDINGS
================================================================================

$(if ($verboseDetails.Count -gt 0) {
($verboseDetails | ForEach-Object { "  $_" }) -join "`n"
} else {
"  (See transcript for detailed verbose output)
"
})"
})

================================================================================
 DETAILED TEST RESULTS
================================================================================

NOTE: This section contains key findings from all executed sections.
      For complete output with all details, see the transcript file.

SECTION 1: SERVICE DETECTION & STATUS
--------------------------------------------------------------------------------
$(if ($section1Details.Count -gt 0) {
($section1Details | ForEach-Object { "  $_" }) -join "`n"
} else {
"  Service information captured in transcript"
})

SECTION 2: SYSTEM REQUIREMENTS VALIDATION
--------------------------------------------------------------------------------
$(if ($requirementDetails.Count -gt 0) {
($requirementDetails | ForEach-Object { "  $_" }) -join "`n"
} else {
"  All requirements passed"
})

SECTIONS 5 & 6: CONFIGURATION & API AUTHENTICATION
--------------------------------------------------------------------------------
$(if ($configDetails.Count -gt 0) {
($configDetails | ForEach-Object { "  $_" }) -join "`n"
} else {
"  Configuration details in transcript"
})

$(if ($VerboseMode) {
"
SECTION 3: PROXY CONFIGURATION & CONNECTIVITY
--------------------------------------------------------------------------------
$(if ($section3Details.Count -gt 0) {
$section3Details -join "`n"
} else {
"  Proxy configuration details in transcript"
})

SECTION 4: ANTIVIRUS STATUS & EXCLUSIONS
--------------------------------------------------------------------------------
$(if ($section4Details.Count -gt 0) {
$section4Details -join "`n"
} else {
"  Antivirus details in transcript"
})

SECTION 7: EVENT LOG ANALYSIS
--------------------------------------------------------------------------------
$(if ($section7Details.Count -gt 0) {
$section7Details -join "`n"
} else {
"  Event log analysis in transcript"
})

SECTION 8: WER CRASH ANALYSIS  
--------------------------------------------------------------------------------
$(if ($section8Details.Count -gt 0) {
$section8Details -join "`n"
} else {
"  Crash analysis in transcript"
})

SECTION 9: SERVICE.ZIP LOG ANALYSIS
--------------------------------------------------------------------------------
$(if ($section9Details.Count -gt 0) {
$section9Details -join "`n"
} else {
"  Service.zip analysis in transcript"
})

SECTION 10: DATE.ZIP COLLECTION ANALYSIS
--------------------------------------------------------------------------------
$(if ($section10Details.Count -gt 0) {
$section10Details -join "`n"
} else {
"  Date.zip analysis in transcript"
})
" +
$(if ($showSection11) {
"
SECTION 11: PERFORMANCE METRICS & TRENDS
--------------------------------------------------------------------------------
$(if ($section11Details.Count -gt 0) {
$section11Details -join "`n"
} else {
"  Performance metrics in transcript"
})
"
} else { "" }) + "

NOTE: Above shows summary findings. For complete event logs, crash dumps, error
      messages, and performance charts, review the transcript file."
})

================================================================================
 FILES GENERATED
================================================================================

Transcript:  $transcriptPath
Report:      $reportPath

Full output details are in the transcript file.

================================================================================
 END OF REPORT
================================================================================
"@

$reportContent | Out-File -FilePath $reportPath -Encoding UTF8 -Force

Write-Host "Report saved to:     $reportPath" -ForegroundColor Green
Write-Host ""
Write-Host "Review the transcript for full details, or the report for a summary." -ForegroundColor Cyan
Write-Host ""

