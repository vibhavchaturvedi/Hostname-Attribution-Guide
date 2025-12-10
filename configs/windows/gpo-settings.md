# Windows Group Policy Settings for DNS Monitoring

## Overview

This document provides Group Policy settings required for comprehensive DNS and network monitoring on Windows endpoints.

## Windows Event Forwarding (WEF) Source Configuration

### GPO Path
```
Computer Configuration → Administrative Templates → 
Windows Components → Event Forwarding → 
Configure target Subscription Manager
```

### Setting Value
```
Server=http://YOUR-WEC-SERVER:5985/wsman/SubscriptionManager/WEC,Refresh=60
```

Replace `YOUR-WEC-SERVER` with your Windows Event Collector hostname.

## Enable Windows Filtering Platform Auditing

### GPO Path
```
Computer Configuration → Windows Settings → Security Settings → 
Advanced Audit Policy Configuration → Object Access
```

### Settings
- **Audit Filtering Platform Connection**: Success, Failure
- **Audit Filtering Platform Packet Drop**: Success, Failure

## Enable DNS Client Logging

### GPO Path
```
Computer Configuration → Administrative Templates → 
Network → DNS Client
```

### Enable via Registry (if GPO not available)
```
HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters
EnableLogging = 1 (DWORD)
```

## Disable Browser DNS over HTTPS (DoH)

### Google Chrome

**GPO Path**: Use Chrome ADMX templates

**Registry Alternative**:
```
HKLM\SOFTWARE\Policies\Google\Chrome
DnsOverHttpsMode = "off" (REG_SZ)
```

### Microsoft Edge

**GPO Path**: Use Edge ADMX templates

**Registry Alternative**:
```
HKLM\SOFTWARE\Policies\Microsoft\Edge
DnsOverHttpsMode = "off" (REG_SZ)
```

### Mozilla Firefox

**GPO Path**: Use Firefox ADMX templates or deploy policies.json

**Registry Alternative**:
```
HKLM\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS
Enabled = 0 (DWORD)
Locked = 1 (DWORD)
```

## Sysmon Deployment via GPO

### Startup Script Method

1. Place Sysmon files in SYSVOL share:
   - `\\domain\SYSVOL\domain\scripts\sysmon\sysmon64.exe`
   - `\\domain\SYSVOL\domain\scripts\sysmon\sysmonconfig.xml`

2. Create startup script:
```batch
@echo off
set SYSMON_PATH=\\%USERDNSDOMAIN%\SYSVOL\%USERDNSDOMAIN%\scripts\sysmon

:: Check if Sysmon is installed
sc query sysmon64 >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Installing Sysmon...
    "%SYSMON_PATH%\sysmon64.exe" -accepteula -i "%SYSMON_PATH%\sysmonconfig.xml"
) else (
    echo Updating Sysmon configuration...
    "%SYSMON_PATH%\sysmon64.exe" -c "%SYSMON_PATH%\sysmonconfig.xml"
)
```

3. Assign script via GPO:
```
Computer Configuration → Windows Settings → Scripts → Startup
```

## NTP Configuration

Ensure consistent time synchronization for log correlation.

### GPO Path
```
Computer Configuration → Administrative Templates → 
System → Windows Time Service → Time Providers
```

### Settings
- **Configure Windows NTP Client**: Enabled
- **NtpServer**: `time.windows.com,0x9` or your internal NTP server

## Firewall Logging

### GPO Path
```
Computer Configuration → Windows Settings → Security Settings → 
Windows Defender Firewall with Advanced Security → 
Windows Defender Firewall Properties
```

### For Each Profile (Domain, Private, Public)
1. Click **Customize** under Logging
2. Set:
   - Log dropped packets: **Yes**
   - Log successful connections: **Yes**
   - Size limit: **32767 KB**
   - Path: `%systemroot%\system32\LogFiles\Firewall\pfirewall.log`

## Verification Commands

After GPO application, verify settings:

```powershell
# Check WEF subscription
wecutil gr DNSandNetwork

# Check audit policy
auditpol /get /subcategory:"Filtering Platform Connection"

# Check Sysmon
sysmon -c

# Check DNS logging
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"

# Check NTP
w32tm /query /status
```

## Troubleshooting

### WEF Not Working
```powershell
# On source computer
winrm quickconfig

# Check connectivity
Test-NetConnection -ComputerName WEC-SERVER -Port 5985
```

### Sysmon Not Logging
```powershell
# Check service
Get-Service Sysmon64

# Check driver
fltmc filters | findstr /i sysmon

# Re-install if needed
sysmon -u force
sysmon -i sysmonconfig.xml
```
