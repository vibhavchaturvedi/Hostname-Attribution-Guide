# Linux Solutions for Hostname Attribution

## Overview

Linux provides powerful kernel-level visibility through auditd, eBPF, and netfilter. The choice of tooling depends on kernel version, performance requirements, and operational maturity.

## Recommended Stack

```
┌────────────────────────────────────────────────────────────────┐
│                     RECOMMENDED LINUX STACK                     │
├────────────────────────────────────────────────────────────────┤
│ Primary:    eBPF (tcpconnect, tcplife, gethostlatency)         │
│ Compliance: auditd rules for connect/bind/listen syscalls      │
│ Firewall:   nftables with NFLOG to ulogd2                      │
│ NSM:        Zeek for full protocol analysis                    │
│ Collection: Filebeat → Kafka → SIEM                            │
└────────────────────────────────────────────────────────────────┘
```

---

## 1. eBPF-Based Solutions — Primary Recommendation

eBPF provides **high-performance, low-overhead** network monitoring with full process context.

### Kernel Requirements

| Feature | Minimum Kernel | Recommended |
|---------|----------------|-------------|
| Basic eBPF | 4.1 | 4.9+ |
| BTF Support | 5.2 | 5.5+ |
| CO-RE (Portable) | 5.5 | 5.8+ |

### Installation

**RHEL/CentOS/Rocky**:
```bash
# Enable EPEL if needed
dnf install epel-release

# Install BCC tools
dnf install bcc-tools bcc-devel

# For bpftrace
dnf install bpftrace
```

**Ubuntu/Debian**:
```bash
apt update
apt install bpfcc-tools linux-headers-$(uname -r) bpftrace
```

**Verify Installation**:
```bash
# Check kernel version
uname -r

# Verify BPF support
ls /sys/kernel/btf/vmlinux  # Should exist for BTF support

# Test basic functionality
/usr/share/bcc/tools/execsnoop
```

### tcpconnect — Trace Outbound TCP Connections

```bash
# Basic usage - shows all new TCP connections
/usr/share/bcc/tools/tcpconnect

# Output format:
# PID    COMM         IP SADDR            DADDR            DPORT
# 12345  curl         4  192.168.1.100    93.184.216.34    443
# 23456  python3      4  192.168.1.100    151.101.1.69     443

# With timestamps
tcpconnect -t

# Filter by PID
tcpconnect -p 1234

# Filter by UID
tcpconnect -U 1000

# Include DNS name resolution (if available)
tcpconnect -d

# Output to file with rotation
tcpconnect -t >> /var/log/tcpconnect.log &
```

### tcplife — Track TCP Session Lifecycle

```bash
/usr/share/bcc/tools/tcplife

# Output includes duration and bytes transferred:
# PID   COMM    LADDR        LPORT  RADDR        RPORT  TX_KB  RX_KB  MS
# 1234  curl    10.0.0.1     54321  93.184.216   443    0      15     234

# With timestamps
tcplife -t

# Filter by port
tcplife -L 443  # Local port
tcplife -D 443  # Remote port
```

### gethostlatency — DNS Resolution Monitoring

Traces DNS lookups via getaddrinfo()/gethostbyname() with process attribution.

```bash
/usr/share/bcc/tools/gethostlatency

# Output:
# TIME     PID    COMM           LAT(ms) HOST
# 10:15:30 1234   curl            12.50   api.example.com
# 10:15:31 5678   python3          8.23   malicious-domain.com
```

### bpftrace One-Liners

```bash
# Trace TCP connect calls by process
bpftrace -e 'kprobe:tcp_v4_connect { printf("%s (pid %d) connecting\n", comm, pid); }'

# Count connections by process name
bpftrace -e 'kprobe:tcp_v4_connect { @[comm] = count(); }'

# Trace DNS lookups
bpftrace -e 'uprobe:/lib/x86_64-linux-gnu/libc.so.6:getaddrinfo { printf("%s looking up %s\n", comm, str(arg0)); }'

# Connection duration histogram
bpftrace -e 'kprobe:tcp_v4_connect { @start[tid] = nsecs; } kretprobe:tcp_v4_connect /@start[tid]/ { @us = hist((nsecs - @start[tid]) / 1000); delete(@start[tid]); }'
```

### Production Deployment Script

See [scripts/linux/ebpf-monitor.sh](../scripts/linux/ebpf-monitor.sh) for a production-ready monitoring script.

---

## 2. auditd Network Syscall Monitoring — Compliance Solution

The Linux audit subsystem provides comprehensive syscall monitoring with process attribution, suitable for compliance requirements.

### Installation

```bash
# RHEL/CentOS
dnf install audit

# Ubuntu/Debian
apt install auditd audispd-plugins

# Enable and start
systemctl enable auditd
systemctl start auditd
```

### Audit Rules Configuration

Create `/etc/audit/rules.d/network.rules`:

```bash
# Network socket monitoring

# Monitor socket creation (IPv4=2, IPv6=10)
-a always,exit -F arch=b64 -S socket -F a0=2 -k socket_ipv4
-a always,exit -F arch=b64 -S socket -F a0=10 -k socket_ipv6
-a always,exit -F arch=b32 -S socket -F a0=2 -k socket_ipv4
-a always,exit -F arch=b32 -S socket -F a0=10 -k socket_ipv6

# Monitor outbound connections
-a always,exit -F arch=b64 -S connect -k outbound_connection
-a always,exit -F arch=b32 -S connect -k outbound_connection

# Monitor listening sockets (backdoor detection)
-a always,exit -F arch=b64 -S bind -k bind_socket
-a always,exit -F arch=b64 -S listen -k listen_socket
-a always,exit -F arch=b64 -S accept -k accept_connection
-a always,exit -F arch=b64 -S accept4 -k accept_connection

# Optional: Exclude high-volume system processes
-a always,exit -F arch=b64 -S connect -F exe!=/usr/lib/systemd/systemd -k outbound_connection
```

### Load Rules

```bash
# Reload rules
augenrules --load

# Verify rules loaded
auditctl -l

# Check audit status
auditctl -s
```

### Understanding Audit Log Fields

| Field | Description |
|-------|-------------|
| `saddr` | Socket address (hex-encoded) |
| `pid` | Process ID |
| `ppid` | Parent process ID |
| `exe` | Full path to executable |
| `auid` | Audit UID (original login user) |
| `uid/gid` | Effective user/group |
| `comm` | Command name |
| `key` | Rule key for filtering |

### Decoding saddr Field

```
saddr=02000050C0A80165...
       ^^ ^^^^ ^^^^^^^^
       |  |    IP address (hex, network byte order)
       |  Port (hex, big-endian): 0050 = 80
       Address family: 02 = AF_INET (IPv4)

# Python decoder:
import socket, struct
saddr = "02000050C0A80165"
family = int(saddr[0:2], 16)  # 2 = AF_INET
port = int(saddr[2:6], 16)    # 80
ip = socket.inet_ntoa(bytes.fromhex(saddr[6:14]))  # 192.168.1.101
```

### Query Audit Logs

```bash
# Search for connect syscalls
ausearch -sc connect -i

# Search by key
ausearch -k outbound_connection -i

# Search by executable
ausearch -x /usr/bin/curl -i

# Time-based search
ausearch -ts recent -k socket_ipv4

# Export to file
ausearch -k outbound_connection -i > /tmp/connections.txt

# Generate report
aureport -x --summary  # Executable summary
aureport -n --summary  # Anomaly summary
```

### Performance Considerations

> **Warning**: Auditing connect() syscalls generates significant volume on busy systems.

**Mitigation Strategies**:
```bash
# Exclude specific users (e.g., service accounts)
-a always,exit -F arch=b64 -S connect -F auid>=1000 -k user_outbound

# Exclude specific executables
-a always,exit -F arch=b64 -S connect -F exe!=/usr/bin/prometheus -k outbound

# Rate limiting (auditd.conf)
# /etc/audit/auditd.conf
freq = 50
```

---

## 3. systemd-resolved Logging

For systems using systemd-resolved for DNS.

### Enable Debug Logging

```bash
# Temporary (runtime)
resolvectl log-level debug

# Monitor in real-time
journalctl -u systemd-resolved -f

# Reset to normal
resolvectl log-level info
```

### Query DNS Statistics

```bash
# Current status
resolvectl status

# Cache statistics
resolvectl statistics

# Flush cache
resolvectl flush-caches

# Query specific domain
resolvectl query example.com
```

### Limitations

- systemd-resolved logs **do NOT include process attribution**
- The resolver only sees the query, not which process made it
- Use eBPF tools (gethostlatency) for process-level DNS attribution

---

## 4. iptables/nftables Logging

Log network connections at the firewall layer.

### iptables LOG Target

```bash
# Log new outbound connections
iptables -A OUTPUT -m state --state NEW -j LOG \
    --log-prefix "OUTBOUND_NEW: " --log-level 4

# Rate-limited logging (prevent log flooding)
iptables -A OUTPUT -m state --state NEW -m limit --limit 100/sec \
    --limit-burst 200 -j LOG --log-prefix "OUTBOUND: "

# Log specific ports (e.g., DNS, HTTP, HTTPS)
iptables -A OUTPUT -p udp --dport 53 -m state --state NEW \
    -j LOG --log-prefix "DNS_QUERY: "
iptables -A OUTPUT -p tcp --dport 80 -m state --state NEW \
    -j LOG --log-prefix "HTTP: "
iptables -A OUTPUT -p tcp --dport 443 -m state --state NEW \
    -j LOG --log-prefix "HTTPS: "

# Log and continue (non-terminating)
iptables -A OUTPUT -m state --state NEW -j LOG --log-prefix "OUT: "
iptables -A OUTPUT -m state --state NEW -j ACCEPT
```

### nftables Logging

```bash
# Add logging rule
nft add rule inet filter output ct state new log prefix \"OUTBOUND: \" accept

# Example nftables configuration
cat << 'EOF' > /etc/nftables.conf
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif lo accept
        ct state new log prefix "INPUT_NEW: " group 32
    }

    chain output {
        type filter hook output priority 0; policy accept;
        ct state new log prefix "OUTPUT_NEW: " group 32
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }
}
EOF

# Apply configuration
nft -f /etc/nftables.conf
```

### NFLOG with ulogd2 (Structured Logging)

```bash
# Install ulogd2
dnf install ulogd  # RHEL/CentOS
apt install ulogd2  # Ubuntu/Debian

# iptables rule to send to userspace
iptables -A OUTPUT -m state --state NEW -j NFLOG --nflog-group 32 --nflog-prefix "OUT"

# ulogd2 configuration (/etc/ulogd.conf)
[global]
logfile="/var/log/ulogd.log"

[log1]
group=32

[emu1]
file="/var/log/nflog/connections.log"
sync=1

stack=log1:NFLOG,base1:BASE,ip2str1:IP2STR,print1:PRINTPKT,emu1:LOGEMU

# Enable JSON output
[json1]
file="/var/log/nflog/connections.json"
sync=1

stack=log1:NFLOG,base1:BASE,ip2str1:IP2STR,json1:JSON
```

> **Note**: iptables/nftables logging does NOT include process attribution. Use auditd or eBPF for process context.

---

## 5. conntrack — Connection Tracking

Linux kernel connection tracking provides NAT translation visibility.

### Real-Time Connection Monitoring

```bash
# List all tracked connections
conntrack -L

# Real-time event stream
conntrack -E

# With timestamps
conntrack -E -o timestamp

# Filter by destination port
conntrack -L --dport 443

# Filter by source IP
conntrack -L --src 192.168.1.100

# Show NAT translations
conntrack -L --src-nat
conntrack -L --dst-nat

# Export to file
conntrack -L -o extended > /tmp/connections.txt
```

### Enable Connection Timestamps

```bash
# Enable timestamps (required for forensics)
echo 1 > /proc/sys/net/netfilter/nf_conntrack_timestamp

# Make persistent
echo "net.netfilter.nf_conntrack_timestamp = 1" >> /etc/sysctl.conf
sysctl -p
```

### Log Conntrack Events

```bash
# Real-time logging script
#!/bin/bash
conntrack -E -o timestamp 2>&1 | while read line; do
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $line" >> /var/log/conntrack.log
done
```

---

## 6. /proc/net Analysis

Snapshot-based network connection analysis.

### Current TCP Connections

```bash
# View established TCP connections
cat /proc/net/tcp
cat /proc/net/tcp6

# Decoded view with ss
ss -tnp

# Filter established connections to specific port
ss -tnp | grep ':443'

# Include process information
ss -tnp | awk 'NR>1 {print $6}'
```

### Script for Continuous Monitoring

```bash
#!/bin/bash
# /opt/scripts/connection-monitor.sh

while true; do
    echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" >> /var/log/connections.log
    ss -tnp >> /var/log/connections.log
    sleep 60
done
```

---

## 7. osquery for Linux

Cross-platform SQL-based endpoint visibility.

### Installation

```bash
# Add repository (Ubuntu/Debian)
export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys $OSQUERY_KEY
add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'
apt update
apt install osquery

# RHEL/CentOS
curl -L https://pkg.osquery.io/rpm/GPG | tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery
dnf install https://pkg.osquery.io/rpm/osquery-5.x.x.rpm
```

### Key Network Tables

```sql
-- Active network connections with process info
SELECT 
    p.name AS process_name,
    p.path AS process_path,
    p.pid,
    pos.local_address,
    pos.local_port,
    pos.remote_address,
    pos.remote_port,
    pos.protocol,
    pos.state
FROM processes p
JOIN process_open_sockets pos USING (pid)
WHERE pos.remote_port != 0
ORDER BY p.name;

-- Listening ports
SELECT 
    p.name,
    p.path,
    lp.port,
    lp.address,
    lp.protocol
FROM processes p
JOIN listening_ports lp USING (pid)
WHERE lp.address IN ('0.0.0.0', '::');

-- DNS resolvers
SELECT * FROM dns_resolvers;

-- Network interfaces
SELECT * FROM interface_addresses;
```

### Scheduled Query Configuration

See [configs/linux/osquery.conf](../configs/linux/osquery.conf) for production configuration.

---

## Log Collection Configuration

### rsyslog for Kernel Messages

```bash
# /etc/rsyslog.d/10-iptables.conf
:msg, contains, "OUTBOUND" /var/log/firewall/outbound.log
:msg, contains, "DNS_QUERY" /var/log/firewall/dns.log

# Stop processing (optional)
& stop
```

### Filebeat Configuration

```yaml
# /etc/filebeat/filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/audit/audit.log
  fields:
    log_type: audit
  processors:
    - add_fields:
        target: ''
        fields:
          log_source: auditd

- type: log
  enabled: true
  paths:
    - /var/log/nflog/*.log
  fields:
    log_type: netfilter

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "linux-network-%{+yyyy.MM.dd}"
```

---

## Deployment Checklist

- [ ] Deploy eBPF tools (tcpconnect, gethostlatency)
- [ ] Configure auditd network rules
- [ ] Enable nftables/iptables logging with rate limiting
- [ ] Enable conntrack timestamps
- [ ] Configure log collection (Filebeat/rsyslog)
- [ ] Verify NTP synchronization
- [ ] Test log flow to SIEM
- [ ] Create correlation rules
