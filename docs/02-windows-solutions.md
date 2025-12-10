# Windows Solutions for Hostname Attribution

## Overview

Windows provides multiple mechanisms for DNS and network connection logging, each with different trade-offs between visibility, performance impact, and deployment complexity.

## Recommended Stack

```
┌────────────────────────────────────────────────────────────────┐
│                    RECOMMENDED WINDOWS STACK                    │
├────────────────────────────────────────────────────────────────┤
│ Primary:    Sysmon Event ID 22 (DNS + process correlation)     │
│ Secondary:  WFP Auditing Event ID 5156 (connection + process)  │
│ Infra:      DNS Server logging on Domain Controllers           │
│ Collection: Windows Event Forwarding to central collector      │
│ IR Tool:    netsh trace / ETW for incident response            │
└────────────────────────────────────────────────────────────────┘
```

## 1. Sysmon DNS Logging (Event ID 22) — Primary Solution

Sysmon provides the **best process-to-DNS correlation** on Windows. Event ID 22 captures DNS queries with full process context.

### Installation

```cmd
# Download Sysmon from Microsoft Sysinternals
# https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

# Install with DNS logging configuration
sysmon.exe -accepteula -i sysmon-dns.xml

# Update existing installation
sysmon.exe -c sysmon-dns.xml

# Check current configuration
sysmon.exe -c
```

### Configuration File

See [configs/windows/sysmon-dns.xml](../configs/windows/sysmon-dns.xml) for the complete configuration.

### Event ID 22 Fields

| Field | Description |
|-------|-------------|
| ProcessGuid | Unique process identifier (correlates with Event ID 1) |
| ProcessId | Process ID at query time |
| QueryName | Domain name queried |
| QueryStatus | 0=Success, non-zero=error code |
| QueryResults | Resolved IP addresses (semicolon-separated) |
| Image | Full path to executable making query |
| User | User account running the process |
| UtcTime | Timestamp in UTC |

### Query Sysmon DNS Events

**PowerShell**:
```powershell
# Basic query - last 100 DNS events
Get-WinEvent -FilterHashTable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    ID=22
} -MaxEvents 100 | 
Select-Object TimeCreated, 
    @{N='Process';E={$_.Properties[4].Value}},
    @{N='QueryName';E={$_.Properties[5].Value}},
    @{N='QueryResults';E={$_.Properties[7].Value}}

# Search for specific domain
Get-WinEvent -FilterHashTable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    ID=22
} | Where-Object {$_.Properties[5].Value -like "*suspicious*"} |
Select-Object TimeCreated, @{N='Process';E={$_.Properties[4].Value}}, @{N='QueryName';E={$_.Properties[5].Value}}

# Export to CSV for analysis
Get-WinEvent -FilterHashTable @{LogName='Microsoft-Windows-Sysmon/Operational';ID=22} |
Select-Object TimeCreated, 
    @{N='ProcessId';E={$_.Properties[3].Value}},
    @{N='Image';E={$_.Properties[4].Value}},
    @{N='QueryName';E={$_.Properties[5].Value}},
    @{N='QueryResults';E={$_.Properties[7].Value}},
    @{N='User';E={$_.Properties[9].Value}} |
Export-Csv -Path dns_queries.csv -NoTypeInformation
```

**Event Viewer Filter (XML)**:
```xml
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
      *[System[(EventID=22)]] and
      *[EventData[Data[@Name='QueryName'] and (contains(Data, 'suspicious'))]]
    </Select>
  </Query>
</QueryList>
```

### Limitations

- Does NOT capture queries from `nslookup.exe` (uses different API)
- Does NOT capture applications using DNS over HTTPS (DoH)
- Does NOT capture queries made before Sysmon driver loads

---

## 2. Windows Filtering Platform (WFP) Auditing — Secondary Solution

WFP auditing provides **process-to-network-connection correlation** at the firewall level.

### Enable via Command Line

```cmd
# Enable connection logging (success and failure)
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable

# Enable packet drop logging
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable

# Verify settings
auditpol /get /subcategory:"Filtering Platform Connection"
```

### Enable via Group Policy

```
Path: Computer Configuration → Windows Settings → Security Settings → 
      Advanced Audit Policy Configuration → Object Access

Settings:
- Audit Filtering Platform Connection: Success, Failure
- Audit Filtering Platform Packet Drop: Success, Failure
```

### Key Event IDs (Security Log)

| Event ID | Description |
|----------|-------------|
| 5156 | WFP permitted a connection |
| 5157 | WFP blocked a connection |
| 5158 | WFP permitted a bind to local port |
| 5159 | WFP blocked a bind |

### Event 5156 Fields

| Field | Description |
|-------|-------------|
| Application | Full path to executable |
| ProcessId | Process ID |
| Direction | Inbound or Outbound |
| SourceAddress | Source IP address |
| SourcePort | Source port |
| DestAddress | Destination IP address |
| DestPort | Destination port |
| Protocol | 6=TCP, 17=UDP |
| LayerName | WFP layer that processed |

### Query WFP Events

```powershell
# Recent outbound connections
Get-WinEvent -FilterHashTable @{
    LogName='Security'
    ID=5156
} -MaxEvents 100 | 
Where-Object {$_.Properties[2].Value -eq '%%14593'} |  # Outbound
Select-Object TimeCreated,
    @{N='Application';E={$_.Properties[1].Value}},
    @{N='DestIP';E={$_.Properties[5].Value}},
    @{N='DestPort';E={$_.Properties[6].Value}}

# Connections to specific port (443)
Get-WinEvent -FilterHashTable @{LogName='Security';ID=5156} |
Where-Object {$_.Properties[6].Value -eq '443'} |
Select-Object TimeCreated, 
    @{N='App';E={$_.Properties[1].Value}},
    @{N='Dest';E={$_.Properties[5].Value}}
```

### Performance Considerations

> **Warning**: WFP auditing generates **high event volume**. On busy servers, this can produce 10,000+ events per minute.

**Mitigation Strategies**:
1. Filter by destination port or IP range in SIEM
2. Use Windows Event Forwarding with XPath filters
3. Consider enabling only during investigations

---

## 3. DNS Client Service Logging

The DNS Client service handles name resolution for Windows applications.

### Event Log Location

```
Applications and Services Logs\Microsoft\Windows\DNS-Client\Operational
```

### Enable Logging

```powershell
# Enable DNS Client Operational log
wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true

# Set maximum log size (in bytes)
wevtutil sl Microsoft-Windows-DNS-Client/Operational /ms:52428800
```

### Key Event IDs

| Event ID | Description |
|----------|-------------|
| 3006 | DNS query initiated |
| 3008 | DNS query completed (contains results) |
| 3020 | DNS response received |

### Limitations

- Does NOT include process information
- Lower detail than Sysmon Event ID 22
- Use Sysmon for process attribution

---

## 4. DNS Server Logging (Domain Controllers)

For environments with internal DNS servers on Domain Controllers.

### Enable via PowerShell

```powershell
# Enable comprehensive DNS debug logging
Set-DnsServerDiagnostics -All $true

# Enable logging to file
Set-DnsServerDiagnostics -EnableLoggingToFile $true -LogFilePath "D:\DNSLogs\"

# Selective logging (reduced volume)
Set-DnsServerDiagnostics -Queries $true -Answers $true -Notifications $false

# Query current settings
Get-DnsServerDiagnostics
```

### DNS Debug Log Format

```
12/9/2025 10:15:30 AM 0BE4 PACKET  00000000033D47F0 UDP Rcv 192.168.1.100 0001 Q [0001   D   NOERROR] A      (7)example(3)com(0)
```

### Analytical Logging (Event Log)

```powershell
# Enable DNS Server Analytical log
wevtutil sl "Microsoft-Windows-DNSServer/Analytical" /e:true

# View analytical events
Get-WinEvent -LogName "Microsoft-Windows-DNSServer/Analytical" -MaxEvents 50
```

---

## 5. ETW DNS Tracing (Incident Response)

Event Tracing for Windows provides real-time DNS activity capture.

### Start DNS Trace

```cmd
# Start trace session
logman start dns_trace -p Microsoft-Windows-DNS-Client -o C:\Traces\dns.etl -ets

# Let it run during investigation...

# Stop trace
logman stop dns_trace -ets

# Convert to readable format
netsh trace convert input="C:\Traces\dns.etl" output="C:\Traces\dns.xml"
```

### PowerShell ETW Collection

```powershell
# Using NetEventPacketCapture module
New-NetEventSession -Name "DNSCapture" -LocalFilePath "C:\Traces\dns.etl"
Add-NetEventProvider -Name "Microsoft-Windows-DNS-Client" -SessionName "DNSCapture"
Start-NetEventSession -Name "DNSCapture"

# ... capture period ...

Stop-NetEventSession -Name "DNSCapture"
Remove-NetEventSession -Name "DNSCapture"
```

---

## 6. Windows Firewall Logging

Basic firewall logging captures connection metadata but lacks process attribution.

### Enable via netsh

```cmd
# Enable logging for all profiles
netsh advfirewall set allprofiles logging allowedconnections enable
netsh advfirewall set allprofiles logging droppedconnections enable

# Set log location and size
netsh advfirewall set allprofiles logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set allprofiles logging maxfilesize 32767

# Verify settings
netsh advfirewall show allprofiles
```

### Log Format

```
#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path
2025-12-09 10:15:30 ALLOW TCP 192.168.1.105 93.184.216.34 51234 443 60 S 12345678 0 64240 - - - SEND
```

### Log Location

```
%windir%\system32\logfiles\firewall\pfirewall.log
```

> **Note**: Basic firewall logs do NOT include process information. Use WFP auditing (above) for process attribution.

---

## 7. Windows Event Forwarding (WEF)

Centralize endpoint DNS and network events for enterprise-wide visibility.

### Configure Collector Server

```powershell
# On collector, configure WinRM
winrm quickconfig

# Create subscription (use XML file)
wecutil cs configs/windows/wef-subscription.xml

# Enable subscription
wecutil ss DNSandNetwork /e:true

# Check subscription status
wecutil gs DNSandNetwork
```

### Configure Source Computers (GPO)

```
Path: Computer Configuration → Administrative Templates → 
      Windows Components → Event Forwarding → 
      Configure target Subscription Manager

Value: Server=http://WEC-SERVER:5985/wsman/SubscriptionManager/WEC,Refresh=60
```

### Subscription XML

See [configs/windows/wef-subscription.xml](../configs/windows/wef-subscription.xml) for the complete configuration.

---

## 8. Disable Browser DoH (Critical)

To maintain endpoint DNS visibility, disable DoH in browsers via Group Policy.

### Chrome

```
Registry Path: HKLM\SOFTWARE\Policies\Google\Chrome
Value Name: DnsOverHttpsMode
Value Type: REG_SZ
Value Data: off
```

### Edge

```
Registry Path: HKLM\SOFTWARE\Policies\Microsoft\Edge
Value Name: DnsOverHttpsMode
Value Type: REG_SZ
Value Data: off
```

### Firefox

```
Registry Path: HKLM\SOFTWARE\Policies\Mozilla\Firefox
Value Name: DNSOverHTTPS
Value Type: REG_DWORD
Value Data: 0
```

### PowerShell Deployment

```powershell
# Disable DoH for Chrome
New-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DnsOverHttpsMode" -Value "off"

# Disable DoH for Edge
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DnsOverHttpsMode" -Value "off"
```

---

## Quick Reference: Event ID Summary

| Event ID | Log | Source | Provides |
|----------|-----|--------|----------|
| 22 | Sysmon | Endpoint | DNS + Process + User |
| 5156 | Security | Endpoint | Connection + Process |
| 5157 | Security | Endpoint | Blocked Connection + Process |
| 3008 | DNS-Client/Operational | Endpoint | DNS (no process) |
| - | DNS Debug Log | Server | Client IP + Query |

## Deployment Checklist

- [ ] Deploy Sysmon with DNS logging configuration
- [ ] Enable WFP auditing for network connections
- [ ] Configure Windows Event Forwarding
- [ ] Disable browser DoH via Group Policy
- [ ] Verify NTP synchronization
- [ ] Set appropriate log retention (minimum 90 days)
- [ ] Create SIEM correlation rules
