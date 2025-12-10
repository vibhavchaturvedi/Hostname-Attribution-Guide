# Reference Architecture for Hostname Attribution

## Overview

This document provides reference architectures for implementing hostname attribution at various scales and maturity levels.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                             DATA SOURCES                                 │
│                                                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │   DNS    │ │ Firewall │ │  Proxy   │ │   EDR    │ │  Cloud   │      │
│  │ Servers  │ │   /IDS   │ │          │ │  Agents  │ │   VPCs   │      │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘      │
│       │            │            │            │            │             │
└───────┼────────────┼────────────┼────────────┼────────────┼─────────────┘
        │            │            │            │            │
        ▼            ▼            ▼            ▼            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    COLLECTION LAYER                                      │
│                                                                          │
│   ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐        │
│   │  Filebeat  │  │  Fluent    │  │   Syslog   │  │   Custom   │        │
│   │            │  │    Bit     │  │  Forwarder │  │   Agents   │        │
│   └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘        │
│         │               │               │               │               │
│         └───────────────┴───────────────┴───────────────┘               │
│                                   │                                      │
└───────────────────────────────────┼──────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     TRANSPORT LAYER                                      │
│                                                                          │
│                    ┌─────────────────────┐                              │
│                    │       Kafka         │                              │
│                    │                     │                              │
│                    │  Topics:            │                              │
│                    │  - dns-events       │                              │
│                    │  - network-flow     │                              │
│                    │  - edr-telemetry    │                              │
│                    │  - dhcp-events      │                              │
│                    └──────────┬──────────┘                              │
│                               │                                          │
└───────────────────────────────┼──────────────────────────────────────────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                 │
              ▼                 ▼                 ▼
┌────────────────────┐ ┌─────────────────┐ ┌─────────────────────┐
│  Stream Processing │ │ Batch Analytics │ │  Real-time SIEM     │
│                    │ │                 │ │                     │
│  - Enrichment      │ │  - ML Models    │ │  - Correlation      │
│  - Normalization   │ │  - Historical   │ │  - Detection Rules  │
│  - Correlation     │ │    Analysis     │ │  - Alerting         │
└─────────┬──────────┘ └────────┬────────┘ └──────────┬──────────┘
          │                     │                     │
          └─────────────────────┴─────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        STORAGE LAYER                                     │
│                                                                          │
│    ┌─────────────────────────────────────────────────────────────┐      │
│    │                     Elasticsearch                            │      │
│    │                                                              │      │
│    │   Hot (7d)  →  Warm (30d)  →  Cold (90d)  →  Frozen (365d)  │      │
│    │   SSD          HDD            Archive        Searchable      │      │
│    │   Full Index   Reduced        Snapshots      Snapshots       │      │
│    └─────────────────────────────────────────────────────────────┘      │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     VISUALIZATION & RESPONSE                             │
│                                                                          │
│   ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐        │
│   │ Dashboards │  │    SOAR    │  │  Ticketing │  │  Alerting  │        │
│   │  (Kibana)  │  │ Playbooks  │  │   System   │  │   (Email,  │        │
│   │            │  │            │  │            │  │   Slack)   │        │
│   └────────────┘  └────────────┘  └────────────┘  └────────────┘        │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Maturity Levels

### Level 1: Foundational (Small Organizations)

**Components**:
- Centralized DNS server with logging
- Basic firewall logging
- DHCP server logging
- Manual correlation

**Architecture**:
```
DNS Server ──┐
             ├──► Syslog Server ──► Manual Analysis
Firewall ────┤
             │
DHCP ────────┘
```

**Implementation Time**: 1-2 weeks
**Annual Cost**: $0-5K (open source)

### Level 2: Integrated (Medium Organizations)

**Components**:
- DNS logging (BIND/Windows)
- Endpoint logging (Sysmon/auditd)
- SIEM with correlation rules
- Automated DHCP lookups

**Architecture**:
```
┌─────────────┐     ┌─────────────┐
│ DNS Server  │────►│   SIEM      │
└─────────────┘     │             │
┌─────────────┐     │ - Graylog   │
│  Endpoints  │────►│ - ELK       │
│  (Sysmon)   │     │ - Wazuh     │
└─────────────┘     │             │
┌─────────────┐     │ Correlation │
│  Firewall   │────►│ Rules       │
└─────────────┘     └─────────────┘
```

**Implementation Time**: 4-8 weeks
**Annual Cost**: $10K-50K

### Level 3: Advanced (Large Organizations)

**Components**:
- DNStap high-performance logging
- EDR integration
- Network flow analysis
- ML-based anomaly detection
- SOAR automation

**Architecture**: See High-Level Architecture above

**Implementation Time**: 3-6 months
**Annual Cost**: $100K-500K

### Level 4: Enterprise (Global Organizations)

**Components**:
- Multi-region deployment
- Real-time streaming analytics
- Threat intelligence integration
- Zero Trust network segmentation
- Full packet capture capability

**Implementation Time**: 6-12 months
**Annual Cost**: $500K+

---

## Component Specifications

### DNS Logging Tier

| Scale | Solution | Throughput | Storage/Day |
|-------|----------|------------|-------------|
| Small | BIND text logs | 10K qps | 2GB |
| Medium | BIND + Filebeat | 50K qps | 10GB |
| Large | DNStap + Kafka | 500K qps | 50GB |
| Enterprise | Passive DNS sensors | 1M+ qps | 200GB+ |

### Endpoint Telemetry Tier

| Platform | Agent | Events/Day/Host |
|----------|-------|-----------------|
| Windows | Sysmon | 50K-500K |
| Linux | auditd + eBPF | 10K-100K |
| macOS | osquery | 5K-50K |

### SIEM Sizing

```
Daily Ingestion = (Endpoints × Events/Host) + DNS + Flow + Other

Example (1000 endpoints):
- Endpoints: 1000 × 100K = 100M events
- DNS: 10M queries
- Flow: 50M records
- Other: 10M events
Total: ~170M events/day ≈ 500GB raw, 50GB indexed
```

---

## Data Flow Patterns

### Pattern 1: Push-Based Collection

```
Endpoint → Agent → Collector → SIEM

Pros:
- Real-time visibility
- Guaranteed delivery (with buffering)
- Agent-side filtering

Cons:
- Agent deployment overhead
- Agent resource consumption
```

### Pattern 2: Pull-Based Collection

```
Endpoint ← Collector (polls periodically)

Pros:
- No agent required
- Centralized control

Cons:
- Not real-time
- May miss transient connections
- Scale limitations
```

### Pattern 3: Hybrid Collection

```
Critical Events → Push (real-time)
Bulk Data → Pull (scheduled)

Optimal for:
- Large environments
- Mixed endpoint types
- Cost optimization
```

---

## Correlation Engine Design

### Rule-Based Correlation

```yaml
# DNS to Connection Correlation
rule:
  name: dns_connection_correlation
  description: Link DNS query to subsequent connection
  
  trigger:
    event_type: dns_query
    conditions:
      - response_code: NOERROR
      - answer_type: A
  
  action:
    - create_lookup:
        key: "{client_ip}:{resolved_ip}"
        value:
          hostname: "{query_name}"
          ttl: "{answer_ttl}"
          timestamp: "{event_time}"
    
    - schedule_correlation:
        within: "{answer_ttl} seconds"
        match:
          event_type: network_connection
          dest_ip: "{resolved_ip}"
        enrich_with:
          dns_query: "{query_name}"
```

### Enrichment Pipeline

```
Raw Event
    │
    ▼
┌─────────────────────┐
│ GeoIP Enrichment    │
│ - Country           │
│ - ASN               │
│ - Organization      │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Threat Intel Lookup │
│ - Known malicious   │
│ - Risk score        │
│ - Category          │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Asset Enrichment    │
│ - Hostname          │
│ - Owner             │
│ - Criticality       │
└─────────┬───────────┘
          │
          ▼
Enriched Event
```

---

## Storage Strategy

### Index Lifecycle Management (ILM)

```json
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_primary_shard_size": "50gb",
            "max_age": "1d"
          },
          "set_priority": {
            "priority": 100
          }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "shrink": {
            "number_of_shards": 1
          },
          "forcemerge": {
            "max_num_segments": 1
          },
          "set_priority": {
            "priority": 50
          }
        }
      },
      "cold": {
        "min_age": "30d",
        "actions": {
          "searchable_snapshot": {
            "snapshot_repository": "cold-snapshots"
          }
        }
      },
      "frozen": {
        "min_age": "90d",
        "actions": {
          "searchable_snapshot": {
            "snapshot_repository": "frozen-snapshots"
          }
        }
      },
      "delete": {
        "min_age": "365d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
```

### Retention Requirements

| Data Type | Hot | Warm | Cold | Archive |
|-----------|-----|------|------|---------|
| DNS Queries | 7d | 30d | 90d | 365d |
| Connections | 7d | 30d | 90d | 365d |
| Process Events | 7d | 14d | 30d | 90d |
| Flow Data | 3d | 14d | 30d | 90d |
| Alerts | 30d | 90d | 365d | 7y |

---

## High Availability Design

### Active-Active Deployment

```
                    ┌─────────────┐
                    │   Load      │
                    │  Balancer   │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
        ┌─────────┐  ┌─────────┐  ┌─────────┐
        │ SIEM-1  │  │ SIEM-2  │  │ SIEM-3  │
        │ (Zone A)│  │ (Zone B)│  │ (Zone C)│
        └────┬────┘  └────┬────┘  └────┬────┘
             │            │            │
             └────────────┼────────────┘
                          │
                          ▼
                ┌─────────────────┐
                │ Shared Storage  │
                │   (Replicated)  │
                └─────────────────┘
```

### Disaster Recovery

- **RPO** (Recovery Point Objective): 15 minutes
- **RTO** (Recovery Time Objective): 4 hours

**Backup Strategy**:
1. Continuous replication to DR site
2. Hourly snapshots
3. Daily off-site backups
4. Monthly archive to cold storage

---

## Security Considerations

### Data Protection

```
┌─────────────────────────────────────────────────────┐
│                 Security Controls                    │
├─────────────────────────────────────────────────────┤
│ Transport:  TLS 1.3 for all log transmission        │
│ At Rest:    AES-256 encryption                      │
│ Access:     RBAC with least privilege               │
│ Audit:      All access logged and monitored         │
│ Retention:  Automated purging per policy            │
└─────────────────────────────────────────────────────┘
```

### Access Control Model

| Role | DNS Logs | Connection Logs | Process Logs | Alerts |
|------|----------|-----------------|--------------|--------|
| Analyst L1 | Read | Read | - | Read |
| Analyst L2 | Read | Read | Read | Read/Write |
| Analyst L3 | Read | Read | Read | Full |
| Admin | Full | Full | Full | Full |

---

## Monitoring the Monitoring

### Key Metrics

| Metric | Warning | Critical |
|--------|---------|----------|
| Ingestion Rate | -20% | -50% |
| Processing Latency | >30s | >5min |
| Storage Utilization | 80% | 90% |
| Query Response Time | >10s | >60s |
| Agent Health | <95% | <90% |

### Health Dashboard

```
┌────────────────────────────────────────────────────┐
│              System Health Dashboard                │
├────────────────────────────────────────────────────┤
│                                                     │
│  Ingestion Rate    [████████████░░] 85K eps        │
│  Processing Lag    [██░░░░░░░░░░░░] 2.3s           │
│  Storage Used      [██████████░░░░] 73%            │
│  Active Agents     [█████████████░] 98.5%          │
│  Query Latency     [███░░░░░░░░░░░] 1.2s           │
│                                                     │
│  ⚠ Warning: 15 agents not reporting (>5 min)       │
│                                                     │
└────────────────────────────────────────────────────┘
```
