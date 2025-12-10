# macOS Solutions for Hostname Attribution

## Overview

macOS presents unique challenges due to System Integrity Protection (SIP), Transparency Consent and Control (TCC), and the shift from kernel extensions to the Network Extension framework. This guide covers available monitoring approaches.

## Recommended Stack

```
┌────────────────────────────────────────────────────────────────┐
│                     RECOMMENDED macOS STACK                     │
├────────────────────────────────────────────────────────────────┤
│ Primary:    osquery with Fleet (scheduled + live queries)       │
│ Real-time:  Network Extension-based tool (e.g., LuLu)          │
│ Firewall:   pf with logging enabled                             │
│ Logging:    Unified logging for mDNSResponder                   │
│ Collection: osquery → Fleet → SIEM                              │
└────────────────────────────────────────────────────────────────┘
```

---

## 1. Unified Logging System — Built-in Solution

macOS uses a unified logging system accessed via the `log` command. DNS resolution is handled by mDNSResponder.

### Stream DNS Events in Real-Time

```bash
# mDNSResponder (system DNS resolver)
log stream --predicate 'process == "mDNSResponder"' --info

# Filter for DNS queries specifically
log stream --predicate 'process == "mDNSResponder" AND eventMessage CONTAINS "Query"' --info

# Network-related events
log stream --predicate 'subsystem == "com.apple.network"'

# Network extensions (VPN, content filters)
log stream --predicate 'subsystem == "com.apple.networkextension"'

# All DNS-related activity
log stream --predicate 'subsystem == "com.apple.mDNSResponder"' --level debug
```

### Historical DNS Query Search

```bash
# Query last 10 minutes
log show --last 10m --predicate 'subsystem == "com.apple.mDNSResponder"'

# Search for specific domain
log show --last 8h --predicate 'eventMessage CONTAINS[cd] "malicious.com"'

# Filter by time range
log show --start "2025-12-09 09:00:00" --end "2025-12-09 17:00:00" \
    --predicate 'process == "mDNSResponder"'

# JSON output for parsing
log show --style json --last 10m --predicate 'subsystem == "com.apple.mDNSResponder"'

# Export to file
log show --last 24h --predicate 'subsystem == "com.apple.mDNSResponder"' \
    --style syslog > dns_queries.log
```

### Relevant Subsystems

| Subsystem | Purpose |
|-----------|---------|
| com.apple.mDNSResponder | DNS resolution |
| com.apple.network | General networking |
| com.apple.networkextension | VPN, content filters |
| com.apple.SystemConfiguration | Network configuration |
| com.apple.URLConnection | URL loading |

### Enable Private Data Logging

By default, DNS hostnames may be hashed for privacy. Enable private data logging for full visibility:

```bash
# Enable (requires root)
sudo log config --mode "private_data:on"

# Verify setting
log config --status

# Disable when done (production systems)
sudo log config --mode "private_data:off"
```

> **Privacy Note**: Private data logging captures sensitive information. Use only during investigations and disable afterward.

### Limitations

- Process attribution is LIMITED in unified logs
- High volume makes continuous monitoring challenging
- Logs are stored in compressed tracev3 format
- Log retention is managed by the system

---

## 2. osquery Integration — Primary Recommendation

osquery provides **cross-platform SQL-based** endpoint visibility with excellent process-to-network correlation.

### Installation

```bash
# Homebrew
brew install osquery

# Package installer from osquery.io
curl -L https://pkg.osquery.io/darwin/osquery-5.x.x.pkg -o osquery.pkg
sudo installer -pkg osquery.pkg -target /

# Verify installation
osqueryi --version
```

### Key Network Tables

| Table | Description |
|-------|-------------|
| process_open_sockets | Active network connections per process |
| listening_ports | Ports in LISTEN state |
| dns_resolvers | System DNS configuration |
| routes | Routing table |
| interface_addresses | Network interface configuration |

### Interactive Queries

```sql
-- List processes with network connections
SELECT 
    p.name AS process_name,
    p.path AS process_path,
    p.pid,
    p.uid,
    u.username,
    pos.local_address,
    pos.local_port,
    pos.remote_address,
    pos.remote_port,
    pos.protocol,
    pos.state
FROM processes p
JOIN process_open_sockets pos USING (pid)
LEFT JOIN users u ON p.uid = u.uid
WHERE pos.remote_port != 0
ORDER BY p.name;

-- Find connections to specific IP
SELECT 
    p.name,
    p.path,
    pos.remote_address,
    pos.remote_port
FROM processes p
JOIN process_open_sockets pos USING (pid)
WHERE pos.remote_address = '93.184.216.34';

-- Find listening services
SELECT 
    p.name,
    p.path,
    lp.port,
    lp.address,
    lp.protocol
FROM processes p
JOIN listening_ports lp USING (pid)
WHERE lp.address IN ('0.0.0.0', '::');

-- DNS resolver configuration
SELECT * FROM dns_resolvers;

-- Find processes connecting to external IPs
SELECT DISTINCT
    p.name,
    p.path,
    pos.remote_address,
    pos.remote_port
FROM processes p
JOIN process_open_sockets pos USING (pid)
WHERE pos.remote_address NOT LIKE '127.%'
  AND pos.remote_address NOT LIKE '10.%'
  AND pos.remote_address NOT LIKE '192.168.%'
  AND pos.remote_address NOT LIKE '172.1%'
  AND pos.remote_address NOT LIKE '172.2%'
  AND pos.remote_address NOT LIKE '172.3%'
  AND pos.remote_port != 0;
```

### Scheduled Query Configuration

```json
{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "utc": true
  },
  "schedule": {
    "network_connections": {
      "query": "SELECT p.name, p.path, p.pid, pos.remote_address, pos.remote_port, pos.local_address, pos.local_port, pos.protocol, pos.state FROM processes p JOIN process_open_sockets pos USING (pid) WHERE pos.remote_port > 0;",
      "interval": 300,
      "description": "Active network connections"
    },
    "listening_ports": {
      "query": "SELECT p.name, p.path, lp.port, lp.address, lp.protocol FROM processes p JOIN listening_ports lp USING (pid);",
      "interval": 600,
      "description": "Listening ports with process info"
    },
    "dns_resolvers": {
      "query": "SELECT * FROM dns_resolvers;",
      "interval": 3600,
      "description": "DNS resolver configuration"
    },
    "process_events": {
      "query": "SELECT * FROM process_events;",
      "interval": 60,
      "description": "Process execution events"
    }
  },
  "packs": {
    "incident-response": "/opt/osquery/packs/incident-response.conf"
  }
}
```

### Deploy as Service

```bash
# Copy configuration
sudo cp osquery.conf /var/osquery/osquery.conf

# Enable launch daemon
sudo cp /var/osquery/com.facebook.osqueryd.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.facebook.osqueryd.plist

# Verify running
sudo launchctl list | grep osquery
```

---

## 3. pf Firewall Logging

macOS includes the pf (packet filter) firewall from BSD.

### Enable and Configure pf

```bash
# Check if pf is enabled
sudo pfctl -s info

# Enable pf
sudo pfctl -e

# Load configuration
sudo pfctl -f /etc/pf.conf
```

### pf Configuration with Logging

Create or modify `/etc/pf.conf`:

```
# /etc/pf.conf - macOS packet filter configuration

# Options
set skip on lo0

# Create logging interface
set loginterface pflog0

# Block rules (logged)
block log all

# Allow established connections
pass in quick on en0 proto tcp from any to any flags S/SA keep state
pass out quick on en0 proto tcp from any to any flags S/SA keep state

# Log all outbound TCP connections
pass out log (all) on en0 proto tcp from any to any

# Log all DNS queries
pass out log on en0 proto udp from any to any port 53

# Log all HTTPS connections
pass out log on en0 proto tcp from any to any port 443
```

### Create pflog Interface

```bash
# Create the logging interface
sudo ifconfig pflog0 create

# Verify interface exists
ifconfig pflog0
```

### View pf Logs

```bash
# Real-time log viewing
sudo tcpdump -n -e -ttt -i pflog0

# Filter for specific protocol
sudo tcpdump -n -e -i pflog0 tcp

# Filter for specific port
sudo tcpdump -n -e -i pflog0 port 443

# Log to file
sudo tcpdump -n -e -i pflog0 -w /var/log/pf.pcap
```

### Limitations

- pf logging does NOT include process attribution
- Requires manual interface creation
- May conflict with application firewalls (Little Snitch, LuLu)

---

## 4. lsof Network Monitoring

lsof provides point-in-time network connection snapshots with process information.

### Basic Usage

```bash
# All network connections
sudo lsof -i -n -P

# Filter by protocol
sudo lsof -i TCP -n -P
sudo lsof -i UDP -n -P

# Filter by port
sudo lsof -i :443 -n -P
sudo lsof -i :53 -n -P

# Filter by state
sudo lsof -i -n -P | grep ESTABLISHED
sudo lsof -i -n -P | grep LISTEN

# Filter by process
sudo lsof -c Safari -i -n -P
sudo lsof -c Chrome -i -n -P
```

### Output Fields

| Field | Description |
|-------|-------------|
| COMMAND | Process name |
| PID | Process ID |
| USER | Username |
| FD | File descriptor |
| TYPE | IPv4 or IPv6 |
| NODE | Protocol (TCP/UDP) |
| NAME | Connection details |

### Continuous Monitoring Script

```bash
#!/bin/bash
# /opt/scripts/network-monitor.sh

LOG_FILE="/var/log/network_connections.log"

while true; do
    echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" >> "$LOG_FILE"
    lsof -i -n -P | grep ESTABLISHED >> "$LOG_FILE"
    sleep 60
done
```

### Snapshot Script for Incident Response

```bash
#!/bin/bash
# network-snapshot.sh - Capture current network state

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="/tmp/network_snapshot_$TIMESTAMP"
mkdir -p "$OUTPUT_DIR"

echo "Capturing network snapshot..."

# Network connections with processes
sudo lsof -i -n -P > "$OUTPUT_DIR/lsof_connections.txt"

# Listening ports
sudo lsof -i -n -P | grep LISTEN > "$OUTPUT_DIR/listening_ports.txt"

# Routing table
netstat -rn > "$OUTPUT_DIR/routing_table.txt"

# DNS configuration
scutil --dns > "$OUTPUT_DIR/dns_config.txt"

# Interface configuration
ifconfig -a > "$OUTPUT_DIR/interfaces.txt"

# ARP table
arp -a > "$OUTPUT_DIR/arp_table.txt"

echo "Snapshot saved to: $OUTPUT_DIR"
tar -czf "$OUTPUT_DIR.tar.gz" -C /tmp "network_snapshot_$TIMESTAMP"
echo "Archive: $OUTPUT_DIR.tar.gz"
```

---

## 5. nettop Real-Time Monitoring

nettop provides real-time network activity per process.

### Interactive Mode

```bash
# Default view
nettop

# Per-process summary
nettop -P

# Delta mode (changes only)
nettop -d

# JSON output
nettop -J
```

### Navigation

| Key | Action |
|-----|--------|
| p | Sort by packets |
| b | Sort by bytes |
| c | Collapse/expand |
| q | Quit |

### Filter by Process

```bash
# Monitor specific process
nettop -p "Safari"
nettop -p "curl"

# Multiple processes
nettop -p "Safari" -p "Chrome"
```

---

## 6. macOS-Specific Challenges

### System Integrity Protection (SIP)

SIP restricts kernel-level monitoring and prevents modification of system processes.

```bash
# Check SIP status
csrutil status

# SIP affects:
# - Kernel extension loading
# - System process monitoring
# - Certain file system locations
```

**Impact**: Traditional kernel-level monitoring tools may not work. Use Network Extensions and osquery instead.

### Transparency, Consent, and Control (TCC)

Monitoring tools need explicit permissions.

**Required Permissions**:
- Full Disk Access (for log files)
- Network monitoring (for packet capture)

**Grant via**: System Preferences → Security & Privacy → Privacy → Full Disk Access

```bash
# Check TCC database (requires FDA)
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
    "SELECT client, service FROM access WHERE allowed=1;"
```

### Encrypted DNS (DoH/DoT)

macOS supports encrypted DNS system-wide.

**Check Current DNS Configuration**:
```bash
scutil --dns

# Shows:
# - DNS servers
# - Search domains
# - Encrypted DNS status
```

**MDM Configuration Profile** to disable DoH:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>Cleartext</string>
            </dict>
        </dict>
    </array>
    <key>PayloadType</key>
    <string>Configuration</string>
</dict>
</plist>
```

### Apple Private Relay

iCloud Private Relay routes Safari and certain system traffic through Apple's proxy network.

**Impacts**:
- Source IP is hidden from destinations
- Traffic appears to originate from Apple IPs
- DNS queries go through Apple's servers

**Disable via**:
- System Preferences → Apple ID → iCloud → Private Relay
- MDM profile

**Block at Network Level**:
```bash
# Block Private Relay domains
# Add to DNS blocklist:
mask.icloud.com
mask-h2.icloud.com
```

---

## 7. Network Extension Framework

Modern macOS uses Network Extensions instead of kernel extensions for network monitoring.

### Available Extension Types

| Type | Use Case |
|------|----------|
| Content Filter | URL/content filtering |
| DNS Proxy | Custom DNS handling |
| Packet Tunnel | VPN functionality |
| App Proxy | Application-level proxy |

### Third-Party Tools Using Network Extensions

- **LuLu**: Open-source application firewall
- **Little Snitch**: Commercial network monitor
- **Charles Proxy**: HTTP debugging proxy

### LuLu Configuration (Example)

```bash
# Install via Homebrew
brew install --cask lulu

# LuLu logs location
/var/log/lulu.log

# Query rules
lulu --rules
```

---

## Log Collection Configuration

### Filebeat for macOS

```yaml
# /etc/filebeat/filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/osquery/osqueryd.results.log
  fields:
    log_type: osquery
  json.keys_under_root: true
  json.add_error_key: true

- type: log
  enabled: true
  paths:
    - /var/log/network_connections.log
  fields:
    log_type: network_monitor

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "macos-network-%{+yyyy.MM.dd}"
```

### Export Unified Logs

```bash
#!/bin/bash
# Export unified logs for SIEM ingestion

OUTPUT_DIR="/var/log/unified_export"
mkdir -p "$OUTPUT_DIR"

# Export last 24 hours of DNS logs
log show --last 24h \
    --predicate 'subsystem == "com.apple.mDNSResponder"' \
    --style json > "$OUTPUT_DIR/dns_$(date +%Y%m%d).json"

# Compress and rotate
gzip "$OUTPUT_DIR/dns_$(date +%Y%m%d).json"
find "$OUTPUT_DIR" -name "*.gz" -mtime +7 -delete
```

---

## Deployment Checklist

- [ ] Install and configure osquery with scheduled queries
- [ ] Enable pf firewall logging
- [ ] Deploy network monitoring script (lsof-based)
- [ ] Configure TCC permissions for monitoring tools
- [ ] Disable Private Relay via MDM (if applicable)
- [ ] Set up log collection to SIEM
- [ ] Create detection rules for macOS-specific IOCs
- [ ] Document Network Extension tool configurations
