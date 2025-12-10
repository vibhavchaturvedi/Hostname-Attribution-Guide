# Detection Engineering for Hostname Attribution

## Overview

This document provides detection rules and techniques for identifying malicious network activity and attributing it to specific hosts and processes.

---

## 1. Domain Generation Algorithm (DGA) Detection

DGA domains are algorithmically generated and used by malware for C2 communication.

### Characteristics

- High entropy domain names
- Random-appearing character sequences
- Often registered recently
- May use uncommon TLDs

### Sigma Rule

```yaml
title: Potential DGA Domain Query
id: 8f3c0a1d-5e7b-4c2f-9a8d-6b3e2f1c4d5a
status: experimental
description: Detects DNS queries to potential DGA domains based on entropy and length
author: Security Team
date: 2025/12/09
logsource:
    category: dns
    product: any
detection:
    selection:
        dns.question.type: 'A'
    filter_legitimate:
        dns.question.name|endswith:
            - '.amazonaws.com'
            - '.cloudfront.net'
            - '.akamaiedge.net'
            - '.microsoft.com'
            - '.windows.com'
            - '.google.com'
            - '.googleapis.com'
    filter_short:
        dns.question.name|re: '^.{1,15}\.[a-z]{2,6}$'
    condition: selection and not filter_legitimate and not filter_short
fields:
    - dns.question.name
    - source.ip
    - dns.answers.data
falsepositives:
    - CDN domains
    - Legitimate services with random subdomains
level: medium
```

### KQL (Microsoft Sentinel)

```kusto
// DGA Detection - High Entropy Domains
let EntropyThreshold = 3.5;
let MinDomainLength = 15;
let WhitelistedTLDs = dynamic(['.microsoft.com', '.windows.com', '.azure.com']);

DnsEvents
| where TimeGenerated > ago(24h)
| extend DomainParts = split(Name, '.')
| extend SecondLevelDomain = tostring(DomainParts[-2])
| where strlen(SecondLevelDomain) >= MinDomainLength
| extend Entropy = -sum(
    array_slice(range(0, 25), 0, 25) 
    | mv-expand c = pack_array('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z')
    | extend freq = countof(tolower(SecondLevelDomain), tostring(c)) * 1.0 / strlen(SecondLevelDomain)
    | where freq > 0
    | extend e = freq * log2(freq)
    | summarize sum(e)
)
| where Entropy > EntropyThreshold
| where not(Name has_any (WhitelistedTLDs))
| summarize 
    QueryCount = count(),
    UniqueClients = dcount(ClientIP),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Name
| where QueryCount < 10  // DGA domains typically have low query counts
| project Name, QueryCount, UniqueClients, FirstSeen, LastSeen
| order by QueryCount desc
```

### Splunk SPL

```spl
index=dns earliest=-24h
| rex field=query "^(?<subdomain>[^.]+)\.(?<domain>[^.]+)\.(?<tld>[^.]+)$"
| eval domain_length = len(domain)
| where domain_length > 15
| eval char_array = split(lower(domain), "")
| mvexpand char_array
| stats count by query, char_array, domain_length, src_ip
| eventstats sum(count) as total_chars by query
| eval freq = count / total_chars
| eval entropy_component = if(freq > 0, freq * log(freq) / log(2), 0)
| stats sum(entropy_component) as neg_entropy, values(src_ip) as clients by query, domain_length
| eval entropy = -neg_entropy
| where entropy > 3.5
| table query, entropy, domain_length, clients
| sort - entropy
```

---

## 2. DNS Tunneling Detection

DNS tunneling uses DNS queries to exfiltrate data or establish C2 channels.

### Indicators

- Long subdomain labels (>30 characters)
- High volume of TXT/NULL queries
- Consistent query patterns
- Encoded data in subdomains

### Sigma Rule

```yaml
title: Potential DNS Tunneling Activity
id: 2a1b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: Detects potential DNS tunneling based on query characteristics
logsource:
    category: dns
detection:
    selection_long_subdomain:
        dns.question.name|re: '^[a-zA-Z0-9]{30,}\.'
    selection_txt_queries:
        dns.question.type:
            - 'TXT'
            - 'NULL'
            - 'CNAME'
    condition: selection_long_subdomain or selection_txt_queries
fields:
    - dns.question.name
    - dns.question.type
    - source.ip
    - dns.answers.data
falsepositives:
    - DKIM records
    - SPF lookups
    - Legitimate services using long subdomains
level: medium
```

### KQL Detection

```kusto
// DNS Tunneling Detection
DnsEvents
| where TimeGenerated > ago(24h)
| extend DomainParts = split(Name, '.')
| extend SubdomainLength = strlen(tostring(DomainParts[0]))
| extend QueryType = QueryType
// Long subdomain detection
| where SubdomainLength > 30 
   or QueryType in ('TXT', 'NULL', 'CNAME')
| summarize 
    QueryCount = count(),
    AvgSubdomainLength = avg(SubdomainLength),
    MaxSubdomainLength = max(SubdomainLength),
    UniqueSubdomains = dcount(tostring(DomainParts[0])),
    TXTCount = countif(QueryType == 'TXT')
    by ClientIP, tostring(DomainParts[-2]), tostring(DomainParts[-1]), bin(TimeGenerated, 1h)
| where QueryCount > 50 or UniqueSubdomains > 20 or TXTCount > 10
| extend BaseDomain = strcat(DomainParts_2, '.', DomainParts_1)
| project TimeGenerated, ClientIP, BaseDomain, QueryCount, UniqueSubdomains, AvgSubdomainLength, TXTCount
```

### Splunk SPL

```spl
index=dns earliest=-24h
| rex field=query "^(?<subdomain>[^.]+)\.(?<rest>.+)$"
| eval subdomain_length = len(subdomain)
| where subdomain_length > 30 OR query_type IN ("TXT", "NULL", "CNAME")
| stats 
    count as query_count,
    avg(subdomain_length) as avg_length,
    dc(subdomain) as unique_subdomains,
    sum(if(query_type="TXT", 1, 0)) as txt_count
    by src_ip, rest, _time span=1h
| where query_count > 50 OR unique_subdomains > 20 OR txt_count > 10
| table _time, src_ip, rest, query_count, unique_subdomains, avg_length, txt_count
| sort - query_count
```

---

## 3. Beaconing Detection

Beaconing indicates regular, periodic communication typical of malware C2.

### Characteristics

- Consistent time intervals between connections
- Low jitter (standard deviation)
- Persistent over extended periods
- Often during non-business hours

### KQL Detection

```kusto
// C2 Beaconing Detection
let TimeWindow = 24h;
let MinConnections = 50;
let MaxJitterPercent = 25;

NetworkConnectionEvents  // Or use DnsEvents
| where TimeGenerated > ago(TimeWindow)
| sort by DeviceName, RemoteIP, TimeGenerated asc
| extend PrevTime = prev(TimeGenerated, 1)
| extend PrevDevice = prev(DeviceName, 1)
| extend PrevRemoteIP = prev(RemoteIP, 1)
| where DeviceName == PrevDevice and RemoteIP == PrevRemoteIP
| extend TimeDeltaSeconds = datetime_diff('second', TimeGenerated, PrevTime)
| where TimeDeltaSeconds > 0 and TimeDeltaSeconds < 3600  // Max 1 hour intervals
| summarize 
    ConnectionCount = count(),
    AvgInterval = avg(TimeDeltaSeconds),
    StdDevInterval = stdev(TimeDeltaSeconds),
    MinInterval = min(TimeDeltaSeconds),
    MaxInterval = max(TimeDeltaSeconds),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by DeviceName, RemoteIP
| where ConnectionCount >= MinConnections
| extend JitterPercent = (StdDevInterval / AvgInterval) * 100
| where JitterPercent < MaxJitterPercent
| extend DurationHours = datetime_diff('hour', LastSeen, FirstSeen)
| where DurationHours >= 4  // Active for at least 4 hours
| extend BeaconScore = 100 - JitterPercent
| where BeaconScore > 75
| project DeviceName, RemoteIP, ConnectionCount, AvgInterval, JitterPercent, BeaconScore, FirstSeen, LastSeen
| order by BeaconScore desc
```

### Splunk SPL

```spl
index=network earliest=-24h
| sort 0 src_ip, dest_ip, _time
| streamstats current=f last(_time) as prev_time by src_ip, dest_ip
| eval time_delta = _time - prev_time
| where time_delta > 0 AND time_delta < 3600
| stats 
    count as connection_count,
    avg(time_delta) as avg_interval,
    stdev(time_delta) as stdev_interval,
    min(_time) as first_seen,
    max(_time) as last_seen
    by src_ip, dest_ip
| where connection_count >= 50
| eval jitter_percent = (stdev_interval / avg_interval) * 100
| where jitter_percent < 25
| eval beacon_score = 100 - jitter_percent
| where beacon_score > 75
| eval duration_hours = (last_seen - first_seen) / 3600
| where duration_hours >= 4
| table src_ip, dest_ip, connection_count, avg_interval, jitter_percent, beacon_score, first_seen, last_seen
| sort - beacon_score
```

---

## 4. First-Seen Domain Detection

Detect queries to domains not previously observed in the environment.

### KQL Detection

```kusto
// First-Seen Domain Detection
let LookbackDays = 30;
let HistoricalDomains = 
    DnsEvents
    | where TimeGenerated between (ago(LookbackDays) .. ago(1h))
    | distinct Name;

DnsEvents
| where TimeGenerated > ago(1h)
| where Name !in (HistoricalDomains)
// Filter out common new domains
| where not(Name has_any ('.microsoft.com', '.windows.com', '.google.com'))
| summarize 
    QueryCount = count(),
    UniqueClients = dcount(ClientIP),
    Clients = make_set(ClientIP, 10)
    by Name
| where UniqueClients <= 3  // Suspicious if only few hosts query it
| project Name, QueryCount, UniqueClients, Clients
| order by QueryCount desc
```

---

## 5. DNS Sinkhole Hit Detection

Detect hosts attempting to contact known malicious domains (blocked by sinkhole).

### Sigma Rule

```yaml
title: DNS Sinkhole Hit - Malicious Domain Attempt
id: 3b4c5d6e-7f8a-9b0c-1d2e-3f4a5b6c7d8e
status: stable
description: Detects when a host queries a domain that resolves to a sinkhole IP
logsource:
    category: dns
detection:
    selection:
        dns.answers.data:
            - '127.0.0.1'      # Common sinkhole
            - '0.0.0.0'        # Common sinkhole
            - '10.0.0.100'     # Example internal sinkhole
            - '192.0.2.1'      # Documentation range sinkhole
    condition: selection
fields:
    - dns.question.name
    - source.ip
    - dns.answers.data
level: high
```

### KQL Detection

```kusto
// Sinkhole Hit Detection
let SinkholeIPs = dynamic(['127.0.0.1', '0.0.0.0', '10.0.0.100', '192.0.2.1']);

DnsEvents
| where TimeGenerated > ago(24h)
| where IPAddresses has_any (SinkholeIPs)
| summarize 
    HitCount = count(),
    UniqueQueries = dcount(Name),
    Domains = make_set(Name, 50),
    FirstHit = min(TimeGenerated),
    LastHit = max(TimeGenerated)
    by ClientIP
| where HitCount >= 1
| project ClientIP, HitCount, UniqueQueries, Domains, FirstHit, LastHit
| order by HitCount desc
```

---

## 6. Process-Based Detection (Endpoint)

Detect suspicious processes making network connections.

### Sysmon + KQL

```kusto
// Suspicious Process DNS Queries
let SuspiciousProcesses = dynamic(['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'regsvr32.exe']);
let SuspiciousTLDs = dynamic(['.tk', '.xyz', '.top', '.pw', '.cc', '.su']);

SysmonDnsQuery  // Event ID 22
| where TimeGenerated > ago(24h)
| extend ProcessName = tostring(split(Image, '\\')[-1])
| where ProcessName in~ (SuspiciousProcesses)
   or QueryName has_any (SuspiciousTLDs)
| project TimeGenerated, Computer, User, ProcessName, Image, QueryName, QueryResults
| order by TimeGenerated desc
```

### Sigma Rule - PowerShell DNS Query

```yaml
title: PowerShell DNS Query to Suspicious TLD
id: 4c5d6e7f-8a9b-0c1d-2e3f-4a5b6c7d8e9f
status: experimental
description: Detects PowerShell making DNS queries to suspicious TLDs
logsource:
    product: windows
    category: dns_query
detection:
    selection_process:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_tld:
        QueryName|endswith:
            - '.tk'
            - '.xyz'
            - '.top'
            - '.pw'
            - '.su'
    condition: selection_process and selection_tld
fields:
    - Image
    - QueryName
    - User
    - Computer
level: high
```

---

## 7. Rare User-Agent Detection

Detect unusual or malicious user-agents in proxy logs.

### Splunk SPL

```spl
index=proxy earliest=-7d
| stats count as total by http_user_agent
| sort + total
| head 100
| eval rarity = "rare"
| join type=left http_user_agent [
    search index=proxy earliest=-1d
    | stats count as recent_count, dc(src_ip) as unique_clients by http_user_agent
]
| where recent_count > 0
| table http_user_agent, total, recent_count, unique_clients, rarity
| sort - recent_count
```

---

## 8. Data Exfiltration Detection

Detect large outbound data transfers that may indicate exfiltration.

### KQL Detection

```kusto
// Large Outbound Transfer Detection
let ThresholdMB = 100;
let TimeWindow = 1h;

NetworkConnectionEvents
| where TimeGenerated > ago(24h)
| where Direction == "Outbound"
| where not(RemoteIP startswith "10." or RemoteIP startswith "192.168." or RemoteIP startswith "172.16.")
| summarize 
    TotalBytesSent = sum(BytesSent),
    ConnectionCount = count(),
    UniqueDestinations = dcount(RemoteIP),
    Destinations = make_set(RemoteIP, 10)
    by DeviceName, bin(TimeGenerated, TimeWindow)
| extend TotalMBSent = TotalBytesSent / (1024 * 1024)
| where TotalMBSent > ThresholdMB
| project TimeGenerated, DeviceName, TotalMBSent, ConnectionCount, UniqueDestinations, Destinations
| order by TotalMBSent desc
```

---

## 9. Correlation Rules

### DNS Query to Connection Correlation

```yaml
# Pseudocode for SIEM correlation
rule: dns_to_connection_correlation

trigger:
  event: dns_query
  conditions:
    - response_code == 'NOERROR'
    - answer_type == 'A'

actions:
  - create_enrichment:
      key: "{source_ip}_{resolved_ip}"
      data:
        query_name: "{query_name}"
        timestamp: "{event_time}"
        ttl: "{answer_ttl}"
      expire_after: "{ttl} + 60 seconds"
  
  - when:
      event: network_connection
      conditions:
        - dest_ip matches "{resolved_ip}"
        - timestamp within ttl window
      then:
        enrich_event:
          dns_query: "{query_name}"
          attribution: "complete"
```

### Multi-Stage Attack Detection

```kusto
// Detect reconnaissance followed by C2
let ReconWindow = 1h;
let C2Window = 24h;

// Stage 1: Reconnaissance (multiple failed DNS queries)
let ReconHosts = 
    DnsEvents
    | where TimeGenerated > ago(ReconWindow)
    | where ResponseCode != 0  // Failed queries
    | summarize FailedQueries = count() by ClientIP
    | where FailedQueries > 20;

// Stage 2: C2 Communication (successful connection to new domain)
DnsEvents
| where TimeGenerated > ago(C2Window)
| where ResponseCode == 0
| where ClientIP in (ReconHosts)
| summarize 
    SuccessfulQueries = count(),
    Domains = make_set(Name, 20)
    by ClientIP
| join kind=inner ReconHosts on ClientIP
| project ClientIP, FailedQueries, SuccessfulQueries, Domains
```

---

## Detection Rule Checklist

- [ ] DGA domain detection
- [ ] DNS tunneling detection
- [ ] C2 beaconing detection
- [ ] First-seen domain alerting
- [ ] Sinkhole hit monitoring
- [ ] Suspicious process DNS queries
- [ ] Rare user-agent detection
- [ ] Data exfiltration thresholds
- [ ] DNS-to-connection correlation
- [ ] Multi-stage attack patterns

---

## Tuning and False Positive Reduction

### Whitelist Management

```yaml
# whitelist.yaml
dns_domains:
  - '*.microsoft.com'
  - '*.windows.com'
  - '*.azure.com'
  - '*.googleapis.com'
  - '*.gstatic.com'

processes:
  - 'C:\Windows\System32\svchost.exe'
  - 'C:\Program Files\Mozilla Firefox\firefox.exe'

user_agents:
  - 'Mozilla/5.0*'
  - 'Chrome/*'
```

### Threshold Tuning

| Detection | Starting Threshold | Tune Based On |
|-----------|-------------------|---------------|
| DGA Entropy | 3.5 | FP rate |
| Beaconing Jitter | 25% | Environment baseline |
| Data Exfil | 100MB/hour | Normal transfer patterns |
| Query Volume | 1000/hour | User behavior |
