# Network Infrastructure Challenges and Solutions

## Overview

Network infrastructure creates multiple barriers to hostname attribution. This guide covers NAT translation, DHCP correlation, proxy attribution, encrypted DNS visibility, and flow analysis.

---

## 1. NAT Translation and IP Masquerading

### The Problem

```
Internal Host → NAT Gateway → Internet
192.168.1.105   →   203.0.113.50   → malicious.com

External view: 203.0.113.50 contacted malicious.com
Challenge: Which of 10,000 internal hosts behind NAT initiated this?
```

### Solution: NAT Session Logging

#### Cisco IOS

```
! Enable NAT logging
ip nat log translations syslog

! Set logging level
logging trap informational

! Send to syslog server
logging host 10.1.1.100

! Log format includes:
! - Inside local address:port
! - Inside global address:port  
! - Outside global address:port
! - Protocol
! - Timestamp
```

#### Linux (iptables/netfilter)

```bash
# Log NAT translations
iptables -t nat -A POSTROUTING -j LOG --log-prefix "NAT: " --log-level info

# Or use conntrack for detailed tracking
conntrack -E -o timestamp >> /var/log/nat_translations.log
```

#### Required Log Fields

| Field | Purpose |
|-------|---------|
| Timestamp | Correlation timing |
| Inside Local IP:Port | Original source |
| Inside Global IP:Port | Post-NAT source |
| Outside Global IP:Port | Destination |
| Protocol | TCP/UDP |

### Correlation Workflow

```
Step 1: Alert received
    "203.0.113.50 contacted malicious.com at 10:15:30 UTC"

Step 2: Search NAT logs (±5 seconds)
    NAT Log: 10:15:30 | 192.168.1.100:54321 → 203.0.113.50:54321 → malicious.com:443

Step 3: Identify internal host
    Result: Internal host 192.168.1.100 is the source
```

---

## 2. DHCP Lease Correlation

### The Problem

DHCP leases expire and reassign. An IP at 10:00 AM may belong to a different host at 10:05 AM.

### Solution: DHCP Server Logging

#### ISC DHCP (Linux)

**Configuration** (`/etc/dhcp/dhcpd.conf`):
```
# Enable logging
log-facility local7;

# Log to separate file (rsyslog)
# /etc/rsyslog.d/dhcpd.conf:
# local7.* /var/log/dhcpd.log
```

**Lease File Format** (`/var/lib/dhcp/dhcpd.leases`):
```
lease 192.168.1.100 {
  starts 2 2025/12/09 10:00:00;
  ends 2 2025/12/10 10:00:00;
  cltt 2 2025/12/09 10:00:00;
  binding state active;
  hardware ethernet 00:11:22:33:44:55;
  uid "\001\000\021\"3DU";
  client-hostname "workstation-47";
}
```

#### Windows DHCP Server

**Enable Audit Logging**:
```powershell
# Enable DHCP audit logging
Set-DhcpServerAuditLog -Enable $true -Path "D:\DHCPLogs"

# Query leases
Get-DhcpServerv4Lease -ComputerName "dhcp-server" -ScopeId 192.168.1.0

# Search by MAC address
Get-DhcpServerv4Lease -ClientId "00-11-22-33-44-55"

# Export lease history
Get-DhcpServerv4Lease -ScopeId 192.168.1.0 | 
    Export-Csv -Path "dhcp_leases.csv" -NoTypeInformation
```

**DHCP Event IDs** (Event Viewer):
| Event ID | Description |
|----------|-------------|
| 10 | New lease |
| 11 | Lease renewed |
| 12 | Lease released |
| 13 | Lease expired |
| 14 | Lease deleted |

#### Kea DHCP

```json
{
  "Dhcp4": {
    "hooks-libraries": [
      {
        "library": "/usr/lib/kea/hooks/libdhcp_lease_cmds.so"
      }
    ],
    "loggers": [
      {
        "name": "kea-dhcp4",
        "output_options": [
          {
            "output": "/var/log/kea-dhcp4.log"
          }
        ],
        "severity": "INFO"
      }
    ]
  }
}
```

### Key Correlation Fields

| Field | Purpose |
|-------|---------|
| Timestamp | When lease was active |
| IP Address | Assigned IP |
| MAC Address | Physical identifier |
| Client Hostname | Device name |
| Lease Duration | Validity period |

---

## 3. Proxy Server Attribution

### Forward Proxy Logging

Proxies act as intermediaries, obscuring the original client IP from destinations.

#### X-Forwarded-For Header

```
X-Forwarded-For: <client>, <proxy1>, <proxy2>
```

> **Security Warning**: X-Forwarded-For is user-controllable. Only trust IPs added by your infrastructure.

#### Squid Proxy Configuration

```
# /etc/squid/squid.conf

# Log format with client IP
logformat combined %>a %ui %un [%tl] "%rm %ru HTTP/%rv" %>Hs %<st "%{Referer}>h" "%{User-Agent}>h"

# Access log
access_log /var/log/squid/access.log combined

# Enable X-Forwarded-For
forwarded_for on
follow_x_forwarded_for allow localhost
```

#### nginx Proxy Logging

```nginx
http {
    # Trust internal proxies
    set_real_ip_from 10.0.0.0/8;
    set_real_ip_from 192.168.0.0/16;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    
    # Log format with original client IP
    log_format main '$remote_addr - $http_x_forwarded_for - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
    
    access_log /var/log/nginx/access.log main;
}
```

---

## 4. DNS Over HTTPS (DoH) and DNS Over TLS (DoT)

### The Problem

Encrypted DNS bypasses traditional DNS logging infrastructure.

```
Traditional DNS (Port 53):
┌────────┐     UDP/53      ┌────────────┐
│ Client │ ──────────────► │ DNS Server │ ← Logged
└────────┘                 └────────────┘

DNS over HTTPS (DoH):
┌────────┐    HTTPS/443    ┌────────────┐
│ Client │ ──────────────► │ DoH Server │ ← Invisible
└────────┘     (Encrypted) └────────────┘
```

### Detection and Mitigation Strategies

#### 1. Block Known DoH Endpoints

```bash
# Common DoH providers
# Block or monitor connections to:
dns.google          # 8.8.8.8, 8.8.4.4
cloudflare-dns.com  # 1.1.1.1, 1.0.0.1
dns.quad9.net       # 9.9.9.9
doh.opendns.com     # 208.67.222.222
```

**Firewall Rule Example (iptables)**:
```bash
# Block DoH to common providers (use cautiously)
iptables -A OUTPUT -d 8.8.8.8 -p tcp --dport 443 -j LOG --log-prefix "DOH_BLOCKED: "
iptables -A OUTPUT -d 8.8.8.8 -p tcp --dport 443 -j DROP
```

#### 2. Block DoT Port 853

```bash
# Block DNS over TLS
iptables -A OUTPUT -p tcp --dport 853 -j LOG --log-prefix "DOT_BLOCKED: "
iptables -A OUTPUT -p tcp --dport 853 -j DROP
```

#### 3. Browser Canary Domain

Browsers check for `use-application-dns.net`. If it returns NXDOMAIN, DoH is disabled.

**BIND Configuration**:
```
zone "use-application-dns.net" {
    type master;
    file "/etc/bind/zones/disable-doh.zone";
};
```

**Zone File** (`disable-doh.zone`):
```
$TTL 3600
@   IN  SOA ns1.example.com. admin.example.com. (
        2025120901  ; Serial
        3600        ; Refresh
        600         ; Retry
        604800      ; Expire
        3600 )      ; Minimum TTL
@   IN  NS  ns1.example.com.
; Return NXDOMAIN by having no A record
```

#### 4. Enterprise Browser Policies

**Chrome (Windows Registry)**:
```
HKLM\SOFTWARE\Policies\Google\Chrome
DnsOverHttpsMode = "off"
```

**Firefox (policies.json)**:
```json
{
  "policies": {
    "DNSOverHTTPS": {
      "Enabled": false
    }
  }
}
```

**Edge (Windows Registry)**:
```
HKLM\SOFTWARE\Policies\Microsoft\Edge
DnsOverHttpsMode = "off"
```

---

## 5. Centralized DNS Server Logging

### BIND Query Logging

**Configuration** (`/etc/named.conf`):
```
logging {
    channel query_log {
        file "/var/log/bind/query.log" versions 10 size 100M;
        print-time yes;
        print-category yes;
        print-severity yes;
        severity info;
    };
    
    channel security_log {
        file "/var/log/bind/security.log" versions 5 size 50M;
        print-time yes;
        severity info;
    };
    
    category queries { query_log; };
    category security { security_log; };
};
```

**Log Format**:
```
09-Dec-2025 10:15:30.178 queries: info: client @0x7f3438 192.168.1.100#54387 (example.com): query: example.com IN A +ED (10.1.1.1)
```

### DNStap for High-Performance Logging

DNStap uses Protocol Buffers for efficient logging—500:1 compression vs text.

**BIND DNStap Configuration**:
```
options {
    dnstap { client; auth; resolver; forwarder; };
    dnstap-output unix "/var/run/named/dnstap.sock";
    dnstap-identity "dns-server-01";
    dnstap-version "BIND 9.16";
};
```

**Unbound DNStap Configuration**:
```yaml
dnstap:
    dnstap-enable: yes
    dnstap-socket-path: "/var/run/unbound/dnstap.sock"
    dnstap-send-identity: yes
    dnstap-send-version: yes
    dnstap-log-client-query-messages: yes
    dnstap-log-client-response-messages: yes
```

**DNStap Receiver**:
```bash
# Install fstrm tools
apt install fstrm-bin

# Capture to file
fstrm_capture -t protobuf:dnstap.Dnstap -u /var/run/dnstap.sock -w output.fstrm

# Convert to text
dnstap-read output.fstrm
```

### DNS Response Policy Zones (RPZ)

RPZ enables blocking and logging of malicious domain queries.

**BIND RPZ Configuration**:
```
options {
    response-policy {
        zone "rpz.blocklist" log yes;
    };
};

zone "rpz.blocklist" {
    type master;
    file "/var/named/rpz/blocklist.zone";
    allow-query { none; };
    allow-transfer { none; };
};
```

**RPZ Zone File**:
```
$TTL 60
@ IN SOA rpz.local. admin.rpz.local. (
    2025120901 ; Serial
    1h         ; Refresh
    15m        ; Retry
    1w         ; Expire
    1h )       ; Minimum
@ IN NS localhost.

; Block - return NXDOMAIN
malicious-c2.com        CNAME .
*.malicious-c2.com      CNAME .

; Redirect to sinkhole
bad-domain.com          A     10.0.0.100
*.bad-domain.com        A     10.0.0.100

; Log only (passthrough)
suspicious.com          CNAME rpz-passthru.
```

**RPZ Actions**:
| Syntax | Effect |
|--------|--------|
| `CNAME .` | NXDOMAIN |
| `CNAME *.` | NODATA |
| `CNAME rpz-drop.` | Drop query silently |
| `CNAME rpz-passthru.` | Allow through |
| `A 10.0.0.100` | Redirect to sinkhole |

---

## 6. Network Flow Analysis

### NetFlow/IPFIX Configuration

#### Cisco IOS

```
! Enable NetFlow v9
ip flow-export version 9
ip flow-export destination 10.1.1.100 2055
ip flow-export source Loopback0
ip flow-cache timeout active 1
ip flow-cache timeout inactive 15

! Apply to interfaces
interface GigabitEthernet0/0
    ip flow ingress
    ip flow egress
```

#### Linux (softflowd)

```bash
# Install
apt install softflowd

# Configure
softflowd -i eth0 -n 10.1.1.100:2055 -v 9 -t maxlife=300

# Verify
softflowctl statistics
```

### Key Flow Fields

| Field | Purpose |
|-------|---------|
| Source/Dest IP | Connection endpoints |
| Source/Dest Port | Service identification |
| Protocol | TCP/UDP/ICMP |
| Bytes/Packets | Volume metrics |
| Start/End Time | Duration |
| TCP Flags | Connection state |

### Flow Collector Analysis (nfdump)

```bash
# Basic query
nfdump -R /flow/data -s srcip

# Filter by destination
nfdump -R /flow/data 'dst ip 93.184.216.34'

# Time-based query
nfdump -R /flow/data -t 2025/12/09.10:00:00-2025/12/09.11:00:00

# Top talkers
nfdump -R /flow/data -s ip/bytes -n 20

# Suspicious ports
nfdump -R /flow/data 'dst port in [4444,5555,6666,31337]'
```

---

## 7. VPN Split Tunneling

### The Problem

Split-tunnel VPNs route only corporate traffic through the tunnel. Internet traffic goes directly, bypassing security monitoring.

```
Corporate Resources:  VPN Tunnel → Monitored
Internet Traffic:     Direct → NOT Monitored
Malware C2:          Direct → NOT Monitored ← RISK
```

### Solutions

#### 1. Full-Tunnel VPN

Route all traffic through corporate network.

**OpenVPN Configuration**:
```
# Server config - push default route
push "redirect-gateway def1"
push "dhcp-option DNS 10.1.1.53"
```

#### 2. Always-On VPN

Mandatory VPN connection with lockdown mode.

#### 3. Endpoint Telemetry

Deploy EDR/osquery that monitors regardless of VPN state.

---

## 8. IPv6 Considerations

### Privacy Extensions

IPv6 privacy extensions generate temporary, random addresses.

**Check Status**:
```bash
# Linux
ip -6 addr show | grep temporary
sysctl net.ipv6.conf.all.use_tempaddr

# Windows
netsh interface ipv6 show privacy
```

**Disable (for attribution)**:
```bash
# Linux
sysctl -w net.ipv6.conf.all.use_tempaddr=0

# Windows
netsh interface ipv6 set privacy state=disabled
```

### Dual-Stack Monitoring

Ensure monitoring covers both IPv4 and IPv6:
- DNS logs for AAAA queries
- Firewall rules for IPv6
- Flow collection for IPv6
- EDR telemetry for IPv6 connections

---

## Quick Reference: Network Log Sources

| Source | Provides | Limitations |
|--------|----------|-------------|
| NAT Logs | IP translation mapping | No process info |
| DHCP Logs | IP-to-MAC-to-hostname | Temporal gaps |
| Proxy Logs | URL, user (if auth) | No endpoint process |
| DNS Server | Query + client IP | No process info |
| NetFlow | Traffic metadata | No payload, no DNS |
| Firewall | Connection + action | Limited process info |
