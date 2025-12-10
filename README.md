# Hostname Attribution for Malicious Network Connections

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

> A comprehensive technical guide for identifying which hostname initiated malicious IP or domain connections in enterprise environments.

## 🎯 The Problem

When your security team receives an alert that "192.168.1.105 contacted malicious-c2-server.com," the immediate question is: **which machine is 192.168.1.105, and which process initiated that connection?**

This seemingly simple question requires navigating layers of:
- NAT translation and IP masquerading
- DHCP lease dynamics
- Proxy configurations
- Encrypted DNS (DoH/DoT)
- OS-specific logging limitations

This repository provides **production-ready configurations, detection rules, and architectural patterns** to solve hostname attribution across Windows, Linux, and macOS environments at enterprise scale.

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Core Concepts](docs/01-core-concepts.md) | Understanding the fundamental challenges |
| [Windows Solutions](docs/02-windows-solutions.md) | Sysmon, WFP, ETW, DNS logging |
| [Linux Solutions](docs/03-linux-solutions.md) | auditd, eBPF, conntrack, nftables |
| [macOS Solutions](docs/04-macos-solutions.md) | Unified logging, osquery, pf |
| [Network Infrastructure](docs/05-network-infrastructure.md) | NAT, DHCP, proxy, flow analysis |
| [Architectural Patterns](docs/06-architecture.md) | Reference designs and patterns |
| [Detection Engineering](docs/07-detection-engineering.md) | Rules for DGA, tunneling, beaconing |
| [Enterprise Challenges](docs/08-enterprise-challenges.md) | Containers, cloud, BYOD |

## 🚀 Quick Start

### Phase 1: Centralized DNS Logging (Day 1)

```bash
# BIND DNS Server - Enable query logging
cat >> /etc/named.conf << 'EOF'
logging {
    channel query_log {
        file "/var/log/bind/query.log" versions 5 size 50M;
        print-time yes;
        severity info;
    };
    category queries { query_log; };
};
EOF
rndc reload
```

### Phase 2: Endpoint DNS Logging (Day 2-3)

**Windows (Sysmon)**:
```cmd
sysmon.exe -accepteula -i configs/windows/sysmon-dns.xml
```

**Linux (auditd)**:
```bash
sudo cp configs/linux/audit-network.rules /etc/audit/rules.d/
sudo augenrules --load
```

**macOS (osquery)**:
```bash
brew install osquery
sudo cp configs/macos/osquery.conf /var/osquery/osquery.conf
sudo osqueryctl start
```

### Phase 3: Detection Rules (Day 4-5)

Import the [Sigma rules](detection-rules/sigma/) into your SIEM or use the platform-specific versions in [KQL](detection-rules/kql/) or [Splunk SPL](detection-rules/splunk/).

## 📁 Repository Structure

```
hostname-attribution-guide/
├── README.md                    # This file
├── LICENSE                      # MIT License
├── CONTRIBUTING.md              # Contribution guidelines
├── docs/                        # Detailed documentation
│   ├── 01-core-concepts.md
│   ├── 02-windows-solutions.md
│   ├── 03-linux-solutions.md
│   ├── 04-macos-solutions.md
│   ├── 05-network-infrastructure.md
│   ├── 06-architecture.md
│   ├── 07-detection-engineering.md
│   └── 08-enterprise-challenges.md
├── configs/                     # Production-ready configurations
│   ├── windows/
│   │   ├── sysmon-dns.xml
│   │   ├── wef-subscription.xml
│   │   └── gpo-settings.md
│   ├── linux/
│   │   ├── audit-network.rules
│   │   ├── nftables-logging.conf
│   │   └── rsyslog-dns.conf
│   ├── macos/
│   │   └── osquery.conf
│   └── network/
│       ├── bind-logging.conf
│       ├── rpz-blocklist.zone
│       └── dnstap.conf
├── detection-rules/             # Detection content
│   ├── sigma/
│   ├── kql/
│   └── splunk/
├── scripts/                     # Utility scripts
│   ├── windows/
│   ├── linux/
│   └── macos/
├── diagrams/                    # Architecture diagrams
└── examples/                    # Example log formats and queries
```

## 🔧 Tool Comparison

| Capability | Windows (Sysmon) | Linux (eBPF) | macOS (osquery) | Network (Zeek) |
|------------|:----------------:|:------------:|:---------------:|:--------------:|
| DNS Query Logging | ✅ | ✅ | ✅ | ✅ |
| Process Attribution | ✅ | ✅ | ✅ | ❌ |
| Network Connections | ✅ | ✅ | ✅ | ✅ |
| User Context | ✅ | ✅ | ✅ | ❌ |
| Performance Impact | Low-Med | Very Low | Low | Medium |
| DoH/DoT Visibility | ❌ | ❌ | ❌ | ❌ |

## 📊 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         DATA SOURCES                                 │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐   │
│  │   DNS   │  │Firewall │  │  Proxy  │  │   EDR   │  │  Cloud  │   │
│  │ Servers │  │  /IDS   │  │         │  │ Agents  │  │  VPCs   │   │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘   │
└───────┼────────────┼────────────┼────────────┼────────────┼─────────┘
        │            │            │            │            │
        ▼            ▼            ▼            ▼            ▼
┌─────────────────────────────────────────────────────────────────────┐
│              COLLECTION LAYER (Filebeat / Fluent Bit)                │
└──────────────────────────────┬──────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    TRANSPORT LAYER (Kafka)                           │
└──────────────────────────────┬──────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    SIEM / ANALYTICS PLATFORM                         │
│              Correlation │ Detection │ Visualization                 │
└─────────────────────────────────────────────────────────────────────┘
```

## ✅ Best Practices Checklist

- [ ] Deploy centralized DNS logging as the foundation
- [ ] Use dnstap over text logging for high-performance environments
- [ ] Implement DNS sinkholing with RPZ for threat blocking
- [ ] Deploy Sysmon (Windows), eBPF (Linux), osquery (macOS) for endpoint visibility
- [ ] Synchronize time via NTP/Chrony before deploying logging
- [ ] Disable browser DoH via policy to maintain DNS visibility
- [ ] Log NAT translations with timestamps for correlation
- [ ] Integrate DHCP lease data with asset inventory
- [ ] Implement tiered storage (hot/warm/cold) for retention

## 📋 Compliance Retention Requirements

| Standard | Minimum Retention |
|----------|-------------------|
| PCI-DSS | 1 year |
| HIPAA | 6 years |
| SOX | 7 years |
| GDPR | As short as necessary |

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- The security community for continuous research and tool development
- Open-source projects: Sysmon, osquery, Zeek, Sigma
- Detection engineering practitioners sharing their expertise

---

**Note**: This guide focuses on technical implementations. Always ensure compliance with your organization's policies and applicable regulations when implementing monitoring solutions.
