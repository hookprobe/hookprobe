# Qsecbit: Unified Cyber Resilience Engine

<p align="center">
  <strong>The Future of Cybersecurity</strong><br>
  <em>Single Source of Truth · AI-Powered Detection · Real-Time Mitigation</em>
</p>

**Pillar 3 of HookProbe: Quantified Cyber Resilience**

**Version**: 6.0 "Unified" | **License**: Proprietary | **Author**: Andrei Toma

---

![Future City](../../assets/qsecbit-catcher.png)

---

## 📋 Table of Contents

- [Overview](#overview)
- [v6.0 Unified Engine](#v60-unified-engine)
- [Architecture](#architecture)
- [OSI Layer Detection (L2-L7)](#osi-layer-detection-l2-l7)
- [AI/ML Pattern Recognition](#aiml-pattern-recognition)
- [Automated Response Orchestrator](#automated-response-orchestrator)
- [Real-Time Mitigation Workflow](#real-time-mitigation-workflow)
- [XDP/eBPF DDoS Mitigation](#xdpebpf-ddos-mitigation)
- [Energy Monitoring & Anomaly Detection](#energy-monitoring--anomaly-detection)
- [NIC Compatibility Matrix](#nic-compatibility-matrix)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Performance](#performance)
- [Troubleshooting](#troubleshooting)

---

## 🎯 Overview

Traditional security asks: *"Are we under attack?"* (binary yes/no)
**Qsecbit asks**: *"How fast can we return to equilibrium?"* (quantified resilience 0.0-1.0)

**Qsecbit (Quantum Security Bit)** is the **single source of truth** for cyber protection, providing unified threat detection, classification, and automated response across all OSI layers (L2-L7).

### What's New in v6.0 "Unified"

**Qsecbit v6.0** transforms from a resilience metric into a **complete unified threat detection and response engine**:

| Capability | v5.0 | v6.0 |
|-----------|------|------|
| **Threat Detection** | Statistical drift | **27 attack types across L2-L7** |
| **ML Classification** | Single attack probability | **Multi-class classifier with 50+ features** |
| **Response** | Manual/XDP blocking | **Automated orchestration with policy engine** |
| **Attack Chains** | Not supported | **Multi-stage correlation scoring** |
| **MITRE ATT&CK** | Not mapped | **Full technique mapping** |
| **Energy Integration** | Anomaly score | **Spike-triggered mitigation** |

### Key Features

- **Single Source of Truth**: One unified engine for all threat detection, classification, and response
- **OSI Layer Detection (L2-L7)**: 27 attack types from ARP Spoofing to HTTP Flood
- **AI/ML Pattern Recognition**: Real-time classification with 50+ network features
- **Automated Response**: Policy-driven mitigation via XDP, firewall, and rate limiting
- **Attack Chain Correlation**: Detect multi-stage attacks (reconnaissance → exploitation → pivot)
- **Energy-Based Anomaly Detection**: Power consumption spikes trigger automated response
- **MITRE ATT&CK Mapping**: Industry-standard threat intelligence integration
- **Deployment-Adaptive Weights**: Optimized for Guardian, Fortress, Nexus, MSSP

### Supported Attack Types

| OSI Layer | Attacks Detected |
|-----------|------------------|
| **L2 (Data Link)** | ARP Spoofing, MAC Flooding, VLAN Hopping, Evil Twin, Rogue DHCP |
| **L3 (Network)** | IP Spoofing, ICMP Flood, Smurf Attack, Routing Attack, Fragmentation |
| **L4 (Transport)** | SYN Flood, Port Scan, TCP Reset, Session Hijack, UDP Flood |
| **L5 (Session)** | SSL Strip, TLS Downgrade, Cert Pinning Bypass, Auth Bypass |
| **L7 (Application)** | SQL Injection, XSS, DNS Tunneling, HTTP Flood, Malware C2, Command Injection, Path Traversal |

### Qsecbit v6.0 Unified Formula

The unified Qsecbit score combines layer-weighted threat scores with behavioral analysis:

```
Q = Σ(ωᵢ × Lᵢ) + β×Energy + γ×Behavioral + δ×ChainCorrelation
```

Where:
- **Lᵢ**: Layer score for L2, L3, L4, L5, L7 (0.0-1.0)
- **ωᵢ**: Deployment-specific layer weight
- **Energy**: Power consumption anomaly score
- **Behavioral**: ML-detected behavioral anomalies
- **ChainCorrelation**: Multi-stage attack correlation bonus

**Deployment-Specific Weights**:

| Deployment | L2 | L3 | L4 | L5 | L7 | Energy | Behavioral | Chain |
|-----------|-----|-----|-----|-----|-----|--------|------------|-------|
| **Guardian** | 0.25 | 0.20 | 0.15 | 0.15 | 0.15 | 0.05 | 0.03 | 0.02 |
| **Fortress** | 0.15 | 0.25 | 0.25 | 0.10 | 0.15 | 0.05 | 0.03 | 0.02 |
| **Nexus** | 0.10 | 0.15 | 0.15 | 0.15 | 0.30 | 0.05 | 0.05 | 0.05 |
| **MSSP** | 0.15 | 0.20 | 0.20 | 0.15 | 0.20 | 0.05 | 0.03 | 0.02 |

**RAG Classification**:
- **GREEN** (< 0.45): Normal operation - monitoring mode
- **AMBER** (0.45-0.70): Warning state - automated response initiated
- **RED** (> 0.70): Critical - full mitigation engaged

---

## 🚀 v6.0 Unified Engine

### The Single Source of Truth

Qsecbit v6.0 introduces the **UnifiedThreatEngine** - a complete detection-to-mitigation pipeline:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     QSECBIT v6.0 UNIFIED ENGINE                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐       │
│  │   L2    │  │   L3    │  │   L4    │  │   L5    │  │   L7    │       │
│  │Detector │  │Detector │  │Detector │  │Detector │  │Detector │       │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘       │
│       │            │            │            │            │             │
│       └────────────┴────────────┴────────────┴────────────┘             │
│                              │                                          │
│                              ▼                                          │
│                    ┌─────────────────┐                                  │
│                    │  ThreatEvent    │  Canonical threat format         │
│                    │  Aggregator     │  with MITRE ATT&CK mapping       │
│                    └────────┬────────┘                                  │
│                             │                                           │
│                             ▼                                           │
│       ┌─────────────────────────────────────────────┐                   │
│       │         ML ATTACK CLASSIFIER                │                   │
│       │  ┌──────────────┐  ┌──────────────────────┐ │                   │
│       │  │   Feature    │  │  Random Forest /     │ │                   │
│       │  │  Extractor   │→│  Rule-Based Fallback │ │                   │
│       │  │  (50+ feat)  │  │                      │ │                   │
│       │  └──────────────┘  └──────────────────────┘ │                   │
│       └─────────────────────┬───────────────────────┘                   │
│                             │                                           │
│                             ▼                                           │
│       ┌─────────────────────────────────────────────┐                   │
│       │         UNIFIED SCORE CALCULATOR            │                   │
│       │  Q = Σ(ωᵢ × Lᵢ) + Energy + Behavior + Chain │                   │
│       │  + Convergence Rate + Trend Analysis        │                   │
│       └─────────────────────┬───────────────────────┘                   │
│                             │                                           │
│                             ▼                                           │
│       ┌─────────────────────────────────────────────┐                   │
│       │       RESPONSE ORCHESTRATOR                 │                   │
│       │  ┌──────┐  ┌──────────┐  ┌─────────────┐   │                   │
│       │  │ XDP  │  │ Firewall │  │ Rate Limit  │   │                   │
│       │  │Block │  │  Rules   │  │   (tc/iptables) │                   │
│       │  └──────┘  └──────────┘  └─────────────┘   │                   │
│       └─────────────────────────────────────────────┘                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Quick Start (v6.0 API)

```python
#!/usr/bin/env python3
from core.qsecbit import (
    Qsecbit, QsecbitConfig,
    UnifiedThreatEngine, UnifiedEngineConfig, DeploymentType
)
import numpy as np

# Option 1: Via existing Qsecbit instance (backward compatible)
baseline_mu = np.array([0.1, 0.2, 0.15, 0.33])
baseline_cov = np.eye(4) * 0.02
quantum_anchor = 6.144

qsecbit = Qsecbit(baseline_mu, baseline_cov, quantum_anchor)

# Run unified detection with single method call
score = qsecbit.detect_threats(deployment_type='guardian')

print(f"Unified Score: {score.score:.4f} ({score.rag_status})")
for threat in score.threats:
    print(f"  [{threat.severity.name}] {threat.attack_type.name}")
    print(f"    {threat.description}")

# Option 2: Direct UnifiedThreatEngine (full control)
config = UnifiedEngineConfig(deployment_type=DeploymentType.FORTRESS)
engine = UnifiedThreatEngine(config=config)

score = engine.detect()
stats = engine.get_statistics()
```

### Legacy Mode (v5.0 Compatibility)

Existing v5.0 code continues to work unchanged:

```python
# v5.0 legacy API still fully supported
sample = qsecbit.calculate(
    x_t=np.array([0.25, 0.42, 0.35, 0.45]),
    p_attack=0.72,
    c_t=np.array([0.76, 0.71, 0.73])
)
print(f"Legacy Score: {sample.score:.4f}")
```

---

## 🏗️ Architecture

### v6.0 Modular Design

**Qsecbit v6.0** features a **comprehensive, modular architecture** with specialized detectors for each OSI layer:

```
qsecbit/
├── __init__.py              # Package exports (v5.0 + v6.0 unified)
├── qsecbit.py               # Core orchestrator + v6.0 unified integration
├── threat_types.py          # Unified data model (ThreatEvent, AttackType)
├── unified_engine.py        # Main v6.0 unified engine orchestrator
├── energy_monitor.py        # RAPL + per-PID power tracking
├── xdp_manager.py           # XDP/eBPF DDoS mitigation
├── nic_detector.py          # NIC capability detection
│
├── detectors/               # OSI Layer-Specific Detectors
│   ├── __init__.py
│   ├── base.py              # Abstract base detector class
│   ├── l2_detector.py       # L2 Data Link: ARP, MAC, VLAN, Evil Twin
│   ├── l3_detector.py       # L3 Network: IP Spoofing, ICMP, Smurf
│   ├── l4_detector.py       # L4 Transport: SYN Flood, Port Scan
│   ├── l5_detector.py       # L5 Session: SSL Strip, TLS Downgrade
│   └── l7_detector.py       # L7 Application: SQLi, XSS, DNS Tunnel
│
├── ml/                      # Machine Learning Classification
│   ├── __init__.py
│   └── classifier.py        # Attack classifier with feature extraction
│
├── response/                # Automated Response Orchestration
│   ├── __init__.py
│   └── orchestrator.py      # XDP/firewall/rate-limit orchestrator
│
└── README.md                # This documentation
```

**Modular Components**:

| Module | Purpose | Key Classes |
|--------|---------|-------------|
| `qsecbit.py` | **Main orchestrator** - v5.0 resilience + v6.0 unified detection | `Qsecbit`, `QsecbitConfig`, `QsecbitSample` |
| `threat_types.py` | **Unified data model** - All attack types, severities, responses | `AttackType`, `ThreatEvent`, `QsecbitUnifiedScore` |
| `unified_engine.py` | **v6.0 unified engine** - Orchestrates all detectors | `UnifiedThreatEngine`, `UnifiedEngineConfig` |
| `detectors/*.py` | **Layer detectors** - OSI L2-L7 threat detection | `L2DataLinkDetector`, `L3NetworkDetector`, etc. |
| `ml/classifier.py` | **ML classification** - Feature extraction + attack classification | `AttackClassifier`, `FeatureExtractor` |
| `response/orchestrator.py` | **Response automation** - XDP, firewall, rate limiting | `ResponseOrchestrator`, `ResponsePolicy` |
| `energy_monitor.py` | Energy consumption monitoring with anomaly detection | `EnergyMonitor`, `SystemEnergySnapshot` |
| `xdp_manager.py` | XDP/eBPF program lifecycle and DDoS mitigation | `XDPManager`, `XDPStats` |

**Design Philosophy**:
- **Single Source of Truth**: One unified engine for all detection and response
- **OSI Layer Separation**: Each layer has dedicated detection logic
- **ML-First Classification**: Pattern recognition before signature matching
- **Automated Response**: Policy-driven mitigation without manual intervention
- **Backward Compatible**: v5.0 API continues to work unchanged

### Deployment Models

**Edge Deployment** (Single-Tenant):
```
┌─────────────────────────────────────────────┐
│   Intel N100 / Raspberry Pi SBC            │
│   ┌──────────────┐    ┌─────────────────┐  │
│   │  Qsecbit     │───→│  ClickHouse     │  │
│   │  + XDP       │    │  (0-90 days)    │  │
│   │  + Energy    │    │                 │  │
│   └──────────────┘    └─────────────────┘  │
│        ↓                                    │
│   ┌──────────────┐                          │
│   │ XDP Layer 1  │  Kernel-level DDoS      │
│   │ (NIC Driver) │  mitigation             │
│   └──────────────┘                          │
└─────────────────────────────────────────────┘
```

**Cloud Backend** (Multi-Tenant MSSP):
```
┌──────────────────────────────────────────────┐
│  Proxmox / Ubuntu Server / Debian            │
│  ┌──────────────┐    ┌──────────────────┐   │
│  │  Qsecbit     │───→│  Apache Doris    │   │
│  │  (N-Pods)    │    │  (1000+ tenants) │   │
│  │              │    │  (365+ days)     │   │
│  └──────────────┘    └──────────────────┘   │
│                                              │
│  Multi-tenant isolation via tenant_id        │
└──────────────────────────────────────────────┘
```

### Qsecbit as a Resilience Metric

**Qsecbit is fundamentally a resilience metric**, not just a threat detector. It measures:

1. **Attack-Defense Equilibrium**: The smallest unit where AI-driven attack and defense balance
2. **Convergence Rate**: How quickly the system returns to GREEN status after threats
3. **System Stability**: Trend analysis (IMPROVING, STABLE, DEGRADING)
4. **Adaptive Capacity**: Energy consumption patterns indicating system stress

**Key Insight**: Qsecbit doesn't just detect attacks - it **quantifies how well your system absorbs and recovers from threats**. A high convergence rate indicates robust resilience; a degrading trend signals declining defensive capacity before catastrophic failure.

---

## 🔍 OSI Layer Detection (L2-L7)

### Layer 2 - Data Link Detection

**Detector**: `L2DataLinkDetector`

| Attack Type | Detection Method | Confidence | Evidence |
|------------|------------------|------------|----------|
| **ARP Spoofing** | MAC address change for known IP; gateway protection | 85-95% | MAC history, is_gateway flag |
| **MAC Flooding** | FDB table size monitoring (bridge fdb) | 60-80% | fdb_count, overflow_ratio |
| **VLAN Hopping** | 802.1Q-in-Q double tagging via Suricata | 75% | Suricata alerts |
| **Evil Twin** | Same SSID with different BSSID via WiFi scan | 90% | known_bssid, rogue_bssid |
| **Rogue DHCP** | Multiple DHCP servers via Zeek dhcp.log | 85% | all_servers, new_servers |

**Example Detection**:
```python
from core.qsecbit.detectors import L2DataLinkDetector

detector = L2DataLinkDetector()
threats = detector.detect()

for threat in threats:
    if threat.attack_type.name == 'ARP_SPOOFING':
        print(f"ARP Spoofing: {threat.source_ip} MAC changed to {threat.source_mac}")
        if threat.evidence.get('is_gateway'):
            print("  ⚠️ CRITICAL: Gateway MAC compromised!")
```

### Layer 3 - Network Detection

**Detector**: `L3NetworkDetector`

| Attack Type | Detection Method | Confidence | Evidence |
|------------|------------------|------------|----------|
| **IP Spoofing** | Martian packets in kernel logs | 70-85% | spoofed_ip, interface |
| **ICMP Flood** | `/proc/net/snmp` InEchos rate spike | 70-85% | icmp_rate, baseline_rate |
| **Smurf Attack** | Broadcast ICMP echo requests | 80% | broadcast_count, source_ip |
| **Routing Attack** | Suricata BGP/OSPF anomalies | 75% | Suricata alert signature |
| **Fragmentation** | Overlapping/malformed fragments | 80% | Suricata frag alerts |

### Layer 4 - Transport Detection

**Detector**: `L4TransportDetector`

| Attack Type | Detection Method | Confidence | Evidence |
|------------|------------------|------------|----------|
| **SYN Flood** | SYN_RECV state count via `ss -s` | 70-85% | syn_recv_count, threshold |
| **Port Scan** | Zeek conn.log analysis (50+ ports) | 75-90% | ports_scanned, scan_duration |
| **TCP Reset** | Suricata RST anomaly detection | 75% | Suricata RST alerts |
| **Session Hijack** | Sequence number prediction alerts | 80% | flow_id, Suricata signature |
| **UDP Flood** | `/proc/net/snmp` InDatagrams spike | 70-85% | udp_rate, baseline_rate |

### Layer 5 - Session Detection

**Detector**: `L5SessionDetector`

| Attack Type | Detection Method | Confidence | Evidence |
|------------|------------------|------------|----------|
| **SSL Strip** | HTTP downgrade detection via Zeek | 80% | Zeek ssl.log, downgrade_url |
| **TLS Downgrade** | Weak TLS version detection (SSLv2/3, TLS1.0) | 85% | tls_version, cipher_suite |
| **Cert Pinning Bypass** | Certificate chain anomalies | 75% | cert_issuer, expected_issuer |
| **Auth Bypass** | Brute force tracking (10+ failures) | 80% | failed_attempts, source_ip |

### Layer 7 - Application Detection

**Detector**: `L7ApplicationDetector`

| Attack Type | Detection Method | Confidence | Evidence |
|------------|------------------|------------|----------|
| **SQL Injection** | Pattern matching (`' OR 1=1`, `UNION SELECT`) | 85% | payload_snippet, url |
| **XSS** | Script tag/event handler detection | 85% | payload_snippet, url |
| **DNS Tunneling** | Shannon entropy analysis (>4.0 = suspicious) | 70-90% | entropy, query_length, subdomain |
| **HTTP Flood** | Request rate per source IP (>100/min) | 75% | request_rate, threshold |
| **Malware C2** | Known C2 domain/IP matching | 90% | matched_indicator, indicator_type |
| **Command Injection** | Shell metacharacter detection | 85% | payload_snippet |
| **Path Traversal** | `../` and path encoding detection | 85% | payload_snippet, url |

---

## 🧠 AI/ML Pattern Recognition

### Feature Extraction

The ML classifier extracts **50+ features** from network traffic for pattern recognition:

```python
@dataclass
class NetworkFeatures:
    # Packet characteristics (8 features)
    packet_count: int
    bytes_total: int
    avg_packet_size: float
    packet_rate: float
    byte_rate: float
    small_packets_ratio: float
    large_packets_ratio: float
    packet_size_variance: float

    # Protocol distribution (10 features)
    tcp_ratio: float
    udp_ratio: float
    icmp_ratio: float
    other_proto_ratio: float
    unique_protocols: int
    dns_ratio: float
    http_ratio: float
    https_ratio: float
    ssh_ratio: float
    ftp_ratio: float

    # TCP flags analysis (8 features)
    syn_ratio: float
    ack_ratio: float
    fin_ratio: float
    rst_ratio: float
    psh_ratio: float
    urg_ratio: float
    syn_ack_ratio: float
    incomplete_handshake_ratio: float

    # Connection patterns (9 features)
    unique_src_ips: int
    unique_dst_ips: int
    unique_src_ports: int
    unique_dst_ports: int
    avg_connection_duration: float
    connection_rate: float
    failed_connections_ratio: float
    port_scan_score: float
    ip_scan_score: float

    # DNS analysis (5 features)
    dns_query_count: int
    avg_dns_query_length: float
    dns_entropy: float
    dns_txt_ratio: float
    dns_mx_ratio: float

    # HTTP analysis (4 features)
    http_error_ratio: float
    avg_uri_length: float
    http_method_entropy: float
    suspicious_user_agent_ratio: float

    # SSL/TLS analysis (4 features)
    ssl_handshake_failures: float
    weak_cipher_ratio: float
    self_signed_cert_ratio: float
    expired_cert_ratio: float

    # ARP analysis (2 features)
    arp_request_ratio: float
    arp_reply_ratio: float
```

### Attack Classification Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                  ML ATTACK CLASSIFICATION                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Raw Traffic Data                                                │
│       │                                                          │
│       ▼                                                          │
│  ┌─────────────────────┐                                         │
│  │  Feature Extractor  │  Extract 50+ features from traffic      │
│  │  - Packet stats     │                                         │
│  │  - Protocol ratios  │                                         │
│  │  - TCP flags        │                                         │
│  │  - DNS entropy      │                                         │
│  └──────────┬──────────┘                                         │
│             │                                                    │
│             ▼                                                    │
│  ┌─────────────────────┐      ┌─────────────────────┐           │
│  │   ML Model Check    │──No──│   Rule-Based        │           │
│  │   (Model Loaded?)   │      │   Fallback          │           │
│  └──────────┬──────────┘      │   (Signatures)      │           │
│             │ Yes              └──────────┬──────────┘           │
│             ▼                             │                      │
│  ┌─────────────────────┐                 │                      │
│  │   Random Forest     │                 │                      │
│  │   Classifier        │                 │                      │
│  │   - Multi-class     │                 │                      │
│  │   - Probability     │                 │                      │
│  └──────────┬──────────┘                 │                      │
│             │                            │                      │
│             └────────────────────────────┘                      │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Classification Result                                   │    │
│  │  - attack_type: AttackType enum                         │    │
│  │  - confidence: 0.0-1.0                                  │    │
│  │  - features_used: List[str]                             │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Signature-Based Fallback

When ML model is unavailable, rule-based signatures provide detection:

```python
ATTACK_SIGNATURES = {
    AttackType.SYN_FLOOD: {
        'syn_ratio': (0.8, 'gt'),           # >80% SYN packets
        'incomplete_handshake_ratio': (0.5, 'gt'),
        'packet_rate': (1000, 'gt'),        # >1000 packets/sec
    },
    AttackType.PORT_SCAN: {
        'unique_dst_ports': (50, 'gt'),     # >50 unique ports
        'port_scan_score': (0.7, 'gt'),
    },
    AttackType.DNS_TUNNELING: {
        'dns_entropy': (4.0, 'gt'),         # High entropy
        'avg_dns_query_length': (50, 'gt'), # Long queries
        'dns_txt_ratio': (0.3, 'gt'),       # Many TXT records
    },
    AttackType.SQL_INJECTION: {
        'http_error_ratio': (0.3, 'gt'),    # Many errors
        'avg_uri_length': (200, 'gt'),      # Long URIs
    },
    # ... 27 attack types with signatures
}
```

### Training Custom Models

```python
from core.qsecbit.ml import AttackClassifier, FeatureExtractor

# Initialize classifier
classifier = AttackClassifier()

# Prepare training data (labeled traffic captures)
training_data = [...]  # List of NetworkFeatures
training_labels = [...]  # List of AttackType

# Train model
classifier.train(training_data, training_labels)

# Save for production use
classifier.save_model('/opt/hookprobe/models/attack_classifier.joblib')

# Load in production
classifier.load_model('/opt/hookprobe/models/attack_classifier.joblib')
```

---

## 🤖 Automated Response Orchestrator

### Response Policy Engine

The Response Orchestrator executes automated mitigation based on configurable policies:

```python
from core.qsecbit.response import ResponseOrchestrator, ResponsePolicy

policy = ResponsePolicy(
    # Enable/disable response types
    enable_xdp_blocking=True,       # Kernel-level IP blocking
    enable_firewall_rules=True,     # nftables/iptables rules
    enable_rate_limiting=True,      # tc/iptables rate limits
    enable_session_termination=False,  # Dangerous: kills connections
    enable_quarantine=False,        # Requires SDN integration

    # Automatic thresholds
    auto_block_severity=ThreatSeverity.HIGH,   # Auto-block HIGH+
    rate_limit_severity=ThreatSeverity.MEDIUM, # Rate limit MEDIUM+

    # Limits
    max_blocked_ips=10000,
    block_duration_minutes=60,
    rate_limit_duration_minutes=30,

    # Whitelist (never block)
    whitelist_ips={'192.168.1.1', '10.0.0.1'},
    whitelist_macs={'aa:bb:cc:dd:ee:ff'},
)

orchestrator = ResponseOrchestrator(
    xdp_manager=xdp_manager,
    policy=policy
)
```

### Response Actions

| Action | Description | Implementation |
|--------|-------------|----------------|
| **MONITOR** | Log and track (no active response) | Logging only |
| **ALERT** | Send notification | Callback + alerts.json |
| **RATE_LIMIT** | Throttle source traffic | tc/iptables rules |
| **BLOCK_IP** | Block source IP | XDP map → nftables → iptables |
| **BLOCK_MAC** | Block source MAC | ebtables |
| **TERMINATE_SESSION** | Kill active connections | conntrack -D |
| **QUARANTINE** | Isolate to VLAN | SDN/OpenFlow (future) |
| **CAPTIVE_PORTAL** | Redirect to portal | dnsmasq (future) |

### Default Response Map

```python
DEFAULT_RESPONSE_MAP = {
    # Critical threats → immediate block
    AttackType.ARP_SPOOFING: [ResponseAction.ALERT, ResponseAction.BLOCK_MAC],
    AttackType.EVIL_TWIN: [ResponseAction.ALERT],

    # Flood attacks → rate limit then block
    AttackType.SYN_FLOOD: [ResponseAction.ALERT, ResponseAction.RATE_LIMIT, ResponseAction.BLOCK_IP],
    AttackType.UDP_FLOOD: [ResponseAction.ALERT, ResponseAction.RATE_LIMIT, ResponseAction.BLOCK_IP],
    AttackType.ICMP_FLOOD: [ResponseAction.ALERT, ResponseAction.RATE_LIMIT],
    AttackType.HTTP_FLOOD: [ResponseAction.ALERT, ResponseAction.RATE_LIMIT, ResponseAction.BLOCK_IP],

    # Reconnaissance → monitor and alert
    AttackType.PORT_SCAN: [ResponseAction.ALERT, ResponseAction.MONITOR],

    # Application attacks → block source
    AttackType.SQL_INJECTION: [ResponseAction.ALERT, ResponseAction.BLOCK_IP],
    AttackType.XSS: [ResponseAction.ALERT, ResponseAction.BLOCK_IP],
    AttackType.COMMAND_INJECTION: [ResponseAction.ALERT, ResponseAction.BLOCK_IP],

    # Stealth attacks → alert only (investigation needed)
    AttackType.DNS_TUNNELING: [ResponseAction.ALERT],
    AttackType.MALWARE_C2: [ResponseAction.ALERT, ResponseAction.BLOCK_IP],
}
```

---

## ⚡ Real-Time Mitigation Workflow

### Detection-to-Mitigation Pipeline

```
┌─────────────────────────────────────────────────────────────────────────┐
│               REAL-TIME DETECTION-TO-MITIGATION PIPELINE                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. CONTINUOUS MONITORING (every 1-5 seconds)                            │
│     ┌──────────────────────────────────────────────────────────────┐    │
│     │  • ARP cache changes    • /proc/net/snmp stats               │    │
│     │  • Zeek/Suricata logs   • Energy consumption (RAPL)          │    │
│     │  • WiFi scan (periodic) • HTTP access logs                   │    │
│     └──────────────────────────────────────────────────────────────┘    │
│                                    │                                     │
│                                    ▼                                     │
│  2. THREAT DETECTION (per-layer)                                         │
│     ┌──────────────────────────────────────────────────────────────┐    │
│     │  L2: ARP Spoofing detected! Gateway MAC changed               │    │
│     │      → ThreatEvent(severity=CRITICAL, confidence=0.95)        │    │
│     │                                                               │    │
│     │  L4: SYN Flood detected! 50,000 SYN_RECV states              │    │
│     │      → ThreatEvent(severity=HIGH, confidence=0.85)            │    │
│     └──────────────────────────────────────────────────────────────┘    │
│                                    │                                     │
│                                    ▼                                     │
│  3. ML CLASSIFICATION (optional enrichment)                              │
│     ┌──────────────────────────────────────────────────────────────┐    │
│     │  Feature extraction → Model inference → Confidence boost      │    │
│     │  SYN Flood confidence: 0.85 → 0.92 (ML confirms pattern)     │    │
│     └──────────────────────────────────────────────────────────────┘    │
│                                    │                                     │
│                                    ▼                                     │
│  4. UNIFIED SCORE CALCULATION                                            │
│     ┌──────────────────────────────────────────────────────────────┐    │
│     │  Q = Σ(ωᵢ × Lᵢ) + Energy + Behavioral + Chain                │    │
│     │                                                               │    │
│     │  Layer Scores:  L2=0.85, L3=0.20, L4=0.75, L5=0.10, L7=0.15 │    │
│     │  Energy: 0.12  Behavioral: 0.08  Chain: 0.15                 │    │
│     │                                                               │    │
│     │  Unified Score: 0.72  →  RAG: RED                            │    │
│     └──────────────────────────────────────────────────────────────┘    │
│                                    │                                     │
│                                    ▼                                     │
│  5. AUTOMATED RESPONSE (policy-driven)                                   │
│     ┌──────────────────────────────────────────────────────────────┐    │
│     │  ARP_SPOOFING (CRITICAL):                                     │    │
│     │    → ALERT: Notification sent                                 │    │
│     │    → BLOCK_MAC: ebtables -A INPUT -s aa:bb:cc:dd:ee:ff -j DROP│    │
│     │                                                               │    │
│     │  SYN_FLOOD (HIGH):                                            │    │
│     │    → ALERT: Notification sent                                 │    │
│     │    → RATE_LIMIT: 1000 pps per source                         │    │
│     │    → BLOCK_IP: XDP map updated, 192.168.1.100 blocked        │    │
│     └──────────────────────────────────────────────────────────────┘    │
│                                    │                                     │
│                                    ▼                                     │
│  6. CONVERGENCE TRACKING                                                 │
│     ┌──────────────────────────────────────────────────────────────┐    │
│     │  Time to GREEN: 45 seconds                                    │    │
│     │  Trend: IMPROVING                                             │    │
│     │  Convergence Rate: 2.3 (good resilience)                     │    │
│     └──────────────────────────────────────────────────────────────┘    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Energy-Triggered Mitigation

Energy consumption spikes can trigger automated response even before network-based detection:

```python
# Energy spike detection flow
if energy_monitor.detect_anomalies(snapshot)['has_anomaly']:
    anomalies = energy_monitor.detect_anomalies(snapshot)

    if anomalies['nic_spike']:
        # NIC interrupt handlers consuming excessive power
        # → Likely DDoS attack overwhelming network stack
        print("⚠️ NIC power spike detected - possible DDoS")

        # Correlate with network metrics
        if xdp_stats.tcp_syn_flood > threshold:
            # Confirmed SYN Flood via energy + network correlation
            orchestrator.respond(ThreatEvent(
                attack_type=AttackType.SYN_FLOOD,
                severity=ThreatSeverity.HIGH,
                evidence={'energy_trigger': True, 'nic_watts': anomalies['nic_watts']}
            ))

    if anomalies['xdp_spike']:
        # XDP/eBPF processes consuming excessive power
        # → Possible XDP exploitation or overwhelming traffic
        print("⚠️ XDP power spike detected - investigating")
```

### Attack Chain Correlation

Multi-stage attacks are detected by correlating threats across time and layers:

```python
# Attack chain detection
ATTACK_CHAINS = {
    'reconnaissance_to_exploitation': [
        AttackType.PORT_SCAN,      # Stage 1: Reconnaissance
        AttackType.SYN_FLOOD,      # Stage 2: DoS distraction
        AttackType.SQL_INJECTION,  # Stage 3: Exploitation
    ],
    'lateral_movement': [
        AttackType.ARP_SPOOFING,   # Stage 1: MitM position
        AttackType.SESSION_HIJACK, # Stage 2: Steal session
        AttackType.COMMAND_INJECTION,  # Stage 3: Gain access
    ],
}

# If threats in last 5 minutes match a chain pattern:
# → Chain correlation score increases
# → Higher overall Qsecbit score
# → More aggressive response policy triggered
```

### Complete Integration Example

```python
#!/usr/bin/env python3
"""
Complete Qsecbit v6.0 Real-Time Mitigation Example
"""
import time
from core.qsecbit import (
    UnifiedThreatEngine, UnifiedEngineConfig, DeploymentType,
    XDPManager, EnergyMonitor
)
from core.qsecbit.response import ResponseOrchestrator, ResponsePolicy

# Initialize components
xdp_manager = XDPManager(auto_detect=True)
energy_monitor = EnergyMonitor(energy_monitoring_enabled=True)

# Configure response policy
policy = ResponsePolicy(
    enable_xdp_blocking=True,
    enable_firewall_rules=True,
    enable_rate_limiting=True,
    auto_block_severity=ThreatSeverity.HIGH,
)

# Create unified engine
config = UnifiedEngineConfig(deployment_type=DeploymentType.FORTRESS)
engine = UnifiedThreatEngine(
    xdp_manager=xdp_manager,
    energy_monitor=energy_monitor,
    config=config
)

# Enable automated response
engine.enable_response(policy)

# Main monitoring loop
print("Qsecbit v6.0 - Real-Time Threat Detection Active")
print("=" * 60)

while True:
    # Run unified detection (all layers + ML + response)
    score = engine.detect()

    # Display status
    print(f"\r[{score.timestamp}] Score: {score.score:.3f} ({score.rag_status}) "
          f"Threats: {len(score.threats)}", end='', flush=True)

    # Log significant events
    if score.rag_status in ['AMBER', 'RED']:
        print()  # Newline
        for threat in score.threats:
            print(f"  [{threat.severity.name}] {threat.attack_type.name}: "
                  f"{threat.description[:50]}...")

            # Response already executed automatically if enabled
            if threat.blocked:
                print(f"    ✓ Blocked at {threat.response_timestamp}")

    time.sleep(5)  # 5-second detection interval
```

---

## 🚀 XDP/eBPF DDoS Mitigation

### Overview

Qsecbit includes **kernel-level packet filtering** via XDP (eXpress Data Path) for ultra-low latency DDoS mitigation:

- **Packet filtering before network stack**: Sub-microsecond decisions
- **Rate limiting**: 1000 packets/sec per source IP
- **Dynamic IP blocking**: Real-time attacker blacklisting
- **Protocol flood detection**: TCP SYN, UDP, ICMP monitoring
- **Malformed packet filtering**: Automatic drop of invalid packets

### XDP Modes

XDP (eXpress Data Path) operates at different layers of the network stack, providing varying levels of performance:

| **Mode** | **Where it runs** | **Kernel bypass** | **Layer** | **Performance** | **Notes** |
|----------|------------------|-------------------|-----------|-----------------|-----------|
| **XDP-hw** | NIC hardware ASIC | Full | Layer 0 | Ultra-fast | Rare; requires programmable NICs (Mellanox SmartNIC, Intel IPU) |
| **XDP-drv** | NIC driver | Full | Layer 1 | Fastest practical | Native driver mode, requires driver support |
| **XDP-skb** | Generic SKB layer | Partial | Layer 1.5 | Moderate | Universal fallback, works on all NICs |

**Key Differences:**
- **XDP-hw**: Packet processing happens directly in NIC hardware before it reaches the CPU. Requires specialized NICs.
- **XDP-drv**: Packet processing happens in the NIC driver before the Linux kernel network stack. Requires XDP-capable driver.
- **XDP-skb**: Packet processing happens after the kernel allocates socket buffers (SKBs). Significantly slower but universal.

Qsecbit **automatically detects** your NIC capabilities and selects the optimal mode (preferring XDP-drv, falling back to XDP-skb).

### XDP Features

```python
# Automatic IP blocking at kernel level
qsecbit.xdp_manager.block_ip("192.168.1.100")

# Get real-time statistics
stats = qsecbit.xdp_manager.get_stats()
print(f"Total packets: {stats.total_packets}")
print(f"Dropped (rate-limited): {stats.dropped_rate_limit}")
print(f"TCP SYN floods: {stats.tcp_syn_flood}")
```

**Statistics Tracked**:
- Total packets processed
- Dropped packets (blocked IPs, rate-limited, malformed)
- TCP SYN flood attempts
- UDP flood attempts
- ICMP flood attempts

---

## ⚡ Energy Monitoring & Anomaly Detection

### Overview

**Qsecbit v5.0** includes a revolutionary **energy consumption-based early warning system** that detects threats by monitoring power consumption patterns at the per-process level. This provides an additional layer of defense against:

- **DDoS attacks**: Network flooding causes abnormal CPU/power spikes in NIC interrupt handlers
- **Cryptomining malware**: Distinctive high-power consumption patterns
- **0-day exploits**: Unusual process behavior detectable via power signatures
- **Kernel-level attacks**: XDP/eBPF process power anomalies

### How It Works

The energy monitoring system implements a **7-step algorithm**:

```
1. Initialize:
   - Read initial total CPU time (/proc/stat)
   - Read initial per-PID CPU times (/proc/[pid]/stat)
   - Read initial RAPL energy counter (/sys/class/powercap/intel-rapl/)

2. Sleep for Δt (e.g., 1 second)

3. Read again:
   - New total CPU time
   - New per-PID CPU times
   - New RAPL energy

4. Compute:
   - CPU time deltas (per-PID and total)
   - CPU usage share per PID (percentage)
   - Package wattage over interval (from RAPL delta)
   - Estimated PID wattage = (PID CPU share) × (package wattage)

5. Build time-series:
   - pid_power[t] = estimated_watts
   - Track NIC interrupt-handling PIDs (irq/, ksoftirqd, napi/)
   - Track XDP driver PIDs (xdp, bpf, ebpf)

6. Feed into anomaly detector:
   - EWMA (Exponentially Weighted Moving Average) for smoothing
   - Z-score spike detection (threshold: 2.5 sigma default)
   - Baseline deviation tracking (50%+ increase = alert)
   - Correlation with NIC/XDP process power spikes

7. Trigger alert when:
   - pid_power spikes > baseline × threshold
   - NIC interrupt-handling PIDs show correlated spikes
   - XDP driver CPU share increases disproportionately
   - Overall anomaly score contributes to qsecbit RAG status
```

### Key Features

- **RAPL Energy Counters**: Hardware-level power measurement (Intel CPUs)
- **Per-PID Power Estimation**: Accurate wattage tracking for every process
- **EWMA Smoothing**: Reduces false positives from transient spikes
- **Z-Score Detection**: Statistical anomaly detection (configurable threshold)
- **NIC Process Tracking**: Automatic detection of network-related processes
- **XDP Correlation**: Correlates XDP/eBPF process power with DDoS attacks
- **Integration with RAG**: Energy anomalies contribute 15% to qsecbit score

### Example Detection Scenarios

**Scenario 1: DDoS Attack via UDP Flood**
```
Normal State:
  - ksoftirqd/0: 2.5W
  - irq/eth0: 1.2W
  - Total NIC: 3.7W

During Attack:
  - ksoftirqd/0: 8.3W (Z-score: 4.2 → SPIKE)
  - irq/eth0: 5.1W (Z-score: 3.8 → SPIKE)
  - Total NIC: 13.4W (+262% → ALERT)
  - qsecbit energy_anomaly: 0.42 → RAG: AMBER
```

**Scenario 2: Cryptomining Malware**
```
Normal State:
  - Total package power: 15W

During Attack:
  - malicious_miner (PID 12345): 18W (Z-score: 6.5 → SPIKE)
  - Total package power: 33W (+120%)
  - qsecbit energy_anomaly: 0.65 → RAG: AMBER
```

**Scenario 3: XDP/eBPF Exploitation**
```
Normal State:
  - bpf_prog (XDP): 0.8W

During Attack:
  - bpf_prog (XDP): 4.2W (Z-score: 5.1 → SPIKE)
  - xdp_spike: True
  - qsecbit energy_anomaly: 0.51 → RAG: AMBER
```

### Network Direction-Aware Energy Efficiency (NEW v5.0)

**Qsecbit v5.0** introduces **network direction-aware energy efficiency analysis** to detect:
- **Compromised endpoints** sending spam/DDoS traffic (OUT spike on USER_ENDPOINT)
- **Servers under attack** (IN spike on PUBLIC_SERVER)
- **Data exfiltration** (abnormal OUT traffic pattern)
- **Cryptomining + network activity** correlation (high EPP + traffic anomalies)

**Key Metrics**:

| Metric | Description | Detection Use Case |
|--------|-------------|-------------------|
| **EPP** (Energy-Per-Packet) | Energy consumed per network packet (mJ/packet) | High EPP (>5 mJ) suggests inefficient processing or cryptomining |
| **OUT/IN Ratio** | Traffic direction ratio (packets_sent / packets_recv) | Role-based anomaly detection |
| **Packet Burst** | Packets in current interval | DDoS or data exfiltration detection |

**Deployment Roles**:

| Role | Expected Traffic Pattern | Anomaly Condition |
|------|-------------------------|-------------------|
| **PUBLIC_SERVER** | IN > OUT (ratio < 1) | OUT > IN suggests data exfiltration or C2 communication |
| **USER_ENDPOINT** | OUT > IN (ratio > 1) | IN > OUT suggests botnet command reception or reverse shell |

**Detection Examples**:

**Scenario 4: Compromised User Endpoint (Spam/DDoS)**
```
Normal State:
  - OUT/IN ratio: 1.8 (typical client behavior)
  - EPP: 2.1 mJ/packet
  - Packets: 320/sec

During Attack:
  - OUT/IN ratio: 8.5 (massive outbound traffic)
  - EPP: 6.2 mJ/packet (inefficient processing)
  - Packets: 4200/sec
  - Deployment Role: USER_ENDPOINT
  - Network Anomaly Score: 87/100 → CRITICAL
  - RAG: RED
```

**Scenario 5: Public Server Under DDoS**
```
Normal State:
  - OUT/IN ratio: 0.6 (typical server behavior)
  - EPP: 1.8 mJ/packet
  - Packets: 850/sec

During Attack:
  - OUT/IN ratio: 0.2 (flooded with inbound traffic)
  - EPP: 4.3 mJ/packet (CPU exhaustion)
  - Packets: 8900/sec
  - Deployment Role: PUBLIC_SERVER
  - Network Anomaly Score: 78/100 → CRITICAL
  - RAG: RED
```

**Scenario 6: Data Exfiltration from Server**
```
Normal State:
  - OUT/IN ratio: 0.6
  - EPP: 1.8 mJ/packet

During Exfiltration:
  - OUT/IN ratio: 2.4 (abnormal outbound spike)
  - EPP: 3.2 mJ/packet (compression/encryption overhead)
  - Deployment Role: PUBLIC_SERVER
  - Network Anomaly Score: 65/100 → WARNING
  - RAG: AMBER
```

**Configuration**:
```python
from qsecbit import EnergyMonitor, DeploymentRole

# Public server configuration
monitor = EnergyMonitor(
    network_interface="eth0",  # Auto-detect if None
    deployment_role=DeploymentRole.PUBLIC_SERVER,
    network_monitoring_enabled=True
)

# User endpoint configuration
monitor = EnergyMonitor(
    network_interface="wlan0",
    deployment_role=DeploymentRole.USER_ENDPOINT,
    network_monitoring_enabled=True
)
```

**Network Stats Output**:
```python
snapshot = monitor.capture_snapshot()

if snapshot.network_stats:
    net = snapshot.network_stats
    print(f"Interface: {net.interface}")
    print(f"EPP: {net.epp:.2f} mJ/packet")
    print(f"OUT/IN Ratio: {net.out_in_ratio:.2f}")
    print(f"Total Packets: {net.total_packets}")
    print(f"Anomaly Score: {net.anomaly_score:.1f}/100")
```

### Hardware Requirements

**Required**:
- **Intel CPU** with RAPL (Running Average Power Limit) support
  - **Supported**: Intel Core (6th gen+), Xeon (Skylake+), Atom (Goldmont+)
  - **Not Supported**: AMD CPUs (no RAPL), ARM CPUs (no RAPL)
  - **Partial Support**: Some AMD Ryzen CPUs via alternative power interfaces (not implemented)

**Automatic Fallback**:
- If RAPL is unavailable, energy monitoring uses CPU-time-based estimation only
- Less accurate but still functional for relative power comparisons

**Verification**:
```bash
# Check RAPL availability
ls /sys/class/powercap/intel-rapl/

# Expected output (if available):
# intel-rapl:0/       # Package-0 (CPU socket)
# intel-rapl:0:0/     # Core domain
# intel-rapl:0:1/     # Uncore domain
# ...

# Read current energy (microjoules)
cat /sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj
```

### Configuration

Enable energy monitoring via `QsecbitConfig`:

```python
config = QsecbitConfig(
    # Enable energy monitoring
    energy_monitoring_enabled=True,

    # Z-score threshold for spike detection (default: 2.5)
    # Lower = more sensitive, Higher = fewer false positives
    energy_spike_threshold=2.5,

    # EWMA smoothing factor (0-1, default: 0.3)
    # Lower = more smoothing, Higher = faster response
    energy_ewma_alpha=0.3,

    # Baseline window size (samples, default: 100)
    # Larger = more stable baseline, Smaller = faster adaptation
    energy_baseline_window=100
)
```

### Usage Example

```python
#!/usr/bin/env python3
import numpy as np
from qsecbit import Qsecbit, QsecbitConfig

# Enable energy monitoring
config = QsecbitConfig(
    energy_monitoring_enabled=True,
    energy_spike_threshold=2.5,
    energy_ewma_alpha=0.3
)

# Initialize qsecbit
baseline_mu = np.array([0.1, 0.2, 0.15, 0.33])
baseline_cov = np.eye(4) * 0.02
quantum_anchor = 6.144

qsecbit = Qsecbit(baseline_mu, baseline_cov, quantum_anchor, config)

# Output:
# ✓ Energy consumption monitoring enabled (RAPL + per-PID tracking)
#   - RAPL energy counters detected

# Analyze system state
sample = qsecbit.calculate(
    x_t=np.array([0.25, 0.42, 0.35, 0.45]),
    p_attack=0.72,
    c_t=np.array([0.76, 0.71, 0.73])
)

# Energy metadata automatically captured
print(f"Qsecbit Score: {sample.score:.4f}")
print(f"RAG Status: {sample.rag_status}")
print(f"Energy Anomaly: {sample.components.get('energy_anomaly', 0):.4f}")

if 'energy' in sample.metadata:
    energy = sample.metadata['energy']
    print(f"Package Power: {energy['package_watts']:.2f}W")
    print(f"NIC Processes: {energy['nic_processes_watts']:.2f}W")
    print(f"XDP Processes: {energy['xdp_processes_watts']:.2f}W")

    if energy['has_energy_anomaly']:
        print("⚠️  ENERGY ANOMALY DETECTED")
        if energy['nic_spike']:
            print("⚠️  NIC POWER SPIKE - Possible DDoS attack")
        if energy['xdp_spike']:
            print("⚠️  XDP POWER SPIKE - Possible kernel-level attack")

        # Top 5 processes with power spikes
        for spike in energy['energy_spike_pids']:
            print(f"  - PID {spike['pid']} ({spike['name']}): "
                  f"{spike['watts']:.2f}W (Z-score: {spike['z_score']:.2f})")
```

### Database Schema

Energy metrics are automatically saved to ClickHouse (edge) or Doris (cloud):

**Additional columns in `qsecbit_scores` table**:
```sql
-- Core energy component
energy_anomaly Float32,  -- Anomaly score (0-1)

-- Power measurements
package_watts Float32,  -- Total CPU package power
nic_processes_watts Float32,  -- Power from NIC-related processes
xdp_processes_watts Float32,  -- Power from XDP/eBPF processes

-- Anomaly flags
has_energy_anomaly UInt8,  -- 1 if anomaly detected
nic_spike UInt8,  -- 1 if NIC processes spiked
xdp_spike UInt8   -- 1 if XDP processes spiked
```

**Example Queries**:

```sql
-- Top energy anomalies in last 24 hours
SELECT
    timestamp,
    score AS qsecbit_score,
    energy_anomaly,
    package_watts,
    nic_processes_watts,
    has_energy_anomaly,
    nic_spike
FROM qsecbit_scores
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND has_energy_anomaly = 1
ORDER BY energy_anomaly DESC
LIMIT 10;

-- Correlation between NIC power and packet drops (XDP)
SELECT
    toStartOfHour(timestamp) AS hour,
    avg(nic_processes_watts) AS avg_nic_watts,
    avg(xdp_dropped_rate_limit) AS avg_drops,
    count(*) FILTER (WHERE nic_spike = 1) AS nic_spike_count
FROM qsecbit_scores
WHERE timestamp >= now() - INTERVAL 7 DAY
GROUP BY hour
ORDER BY hour DESC;

-- Energy baseline deviation trend
SELECT
    toDate(timestamp) AS day,
    avg(package_watts) AS avg_package_watts,
    max(package_watts) AS max_package_watts,
    stddevPop(package_watts) AS stddev_package_watts,
    countIf(has_energy_anomaly = 1) AS anomaly_count
FROM qsecbit_scores
WHERE timestamp >= now() - INTERVAL 30 DAY
GROUP BY day
ORDER BY day DESC;
```

### Benefits

**1. Early DDoS Detection**
- Detects attacks before traditional signatures
- Correlates NIC interrupt spikes with network floods
- Provides sub-second response time (integrated with qsecbit RAG)

**2. Cryptomining Detection**
- Identifies malicious miners by power consumption patterns
- Works even if process name is obfuscated
- Catches CPU-based and GPU-based miners

**3. 0-Day Attack Detection**
- Abnormal process behavior visible in power signatures
- Detects kernel exploits via system call patterns
- Catches privilege escalation attempts

**4. Resource Optimization**
- Identify power-hungry processes for optimization
- Track system efficiency over time
- Correlate power with performance metrics

**5. Forensics & Incident Response**
- Historical power consumption data for attack timeline reconstruction
- Per-PID power tracking for root cause analysis
- Integration with qsecbit RAG for automated response

### Limitations

**1. Intel CPU Required (for full functionality)**
- RAPL is Intel-specific technology
- AMD CPUs: No RAPL support (fallback to CPU-time estimation)
- ARM CPUs: No RAPL support (fallback to CPU-time estimation)

**2. Baseline Learning Period**
- Requires 100+ samples (default) to establish baseline
- First ~2 minutes may have false positives
- Adjust `energy_baseline_window` for faster/slower adaptation

**3. CPU-Intensive Operations**
- Reading `/proc/[pid]/stat` for all processes has overhead
- Recommended interval: 1-5 seconds (not sub-second)
- May increase CPU usage by 1-3%

**4. Process Lifetime**
- Short-lived processes may be missed between samples
- Long-lived processes have more accurate baselines
- Aggregate NIC/XDP metrics mitigate this

### Best Practices

1. **Baseline Establishment**: Run system under normal load for 5-10 minutes before relying on alerts
2. **Threshold Tuning**: Start with `energy_spike_threshold=2.5`, adjust based on false positive rate
3. **Sampling Interval**: 1-second intervals recommended for edge, 5-second for cloud backend
4. **Database Retention**: Energy metrics add ~200 bytes per sample, plan storage accordingly
5. **Alert Correlation**: Combine energy anomalies with XDP stats and qsecbit RAG for maximum accuracy

---

## 🖥️ NIC Compatibility Matrix

### XDP-Ready NIC Comparison

| **Platform** | **NIC Model** | **Driver** | **XDP-SKB** | **XDP-DRV** | **XDP-HW** | **Max Throughput** |
|-------------|---------------|------------|-------------|-------------|------------|-------------------|
| **Raspberry Pi 4/5** | Broadcom SoC | bcmgenet | ✅ | ❌ | ❌ | 1 Gbps |
| **Raspberry Pi** | Realtek USB | r8152 | ✅ | ❌ | ❌ | 1 Gbps |
| **Desktop** | Realtek PCIe | r8169 | ✅ | ❌ | ❌ | 2.5 Gbps |
| **Intel N100** | **I211** | **igb** | ✅ | ✅ | ❌ | **1 Gbps** |
| **Intel N100** | **I226** | **igc** | ✅ | ✅ | ❌ | **2.5 Gbps** |
| **Intel Server** | X520 (82599) | ixgbe | ✅ | ❌ | ❌ | 10 Gbps |
| **Intel Server** | **X710** | **i40e** | ✅ | ✅ | ❌ | **40 Gbps** |
| **Intel Server** | **E810** | **ice** | ✅ | ✅ | ❌ | **100 Gbps** |
| **Mellanox** | **ConnectX-3** | **mlx4_en** | ✅ | ❌ | ❌ | **40 Gbps** |
| **Mellanox** | **ConnectX-4/5/6/7** | **mlx5_core** | ✅ | ✅ | ✅ | **200 Gbps** |
| **Mellanox SmartNIC** | **BlueField-2/3** | **mlx5_core** | ✅ | ✅ | ✅ | **400 Gbps** |

**Legend**:
- ✅ **Supported**
- ❌ **Not supported**

**XDP-HW Note**: Hardware offload (XDP-hw) is extremely rare and only supported by:
- Mellanox ConnectX-5/6/7 (limited offload capabilities)
- Mellanox BlueField-2/3 SmartNICs (full programmable pipeline)
- Intel IPU (Infrastructure Processing Unit)
- Netronome Agilio SmartNICs

For 99% of deployments, **XDP-drv** is the fastest practical mode.

### Recommended Hardware

#### **Budget Edge Deployment** (< $300)
- **SBC**: Intel N100 (8GB RAM)
- **NIC**: Intel I226-V (built-in, 2.5Gbps)
- **XDP Mode**: XDP-DRV ✅
- **Performance**: 2.5 Gbps line rate filtering

#### **Mid-Range Edge** ($300-$1000)
- **SBC**: Raspberry Pi 5 (8GB) + Intel I226 USB adapter
- **Alternative**: Mini PC with Intel I211/I226
- **XDP Mode**: XDP-DRV ✅
- **Performance**: 1-2.5 Gbps

#### **High-Performance Cloud Backend** ($2000+)
- **Server**: Dell/HP with Intel X710 or Mellanox ConnectX-5
- **XDP Mode**: XDP-DRV ✅ + Hardware Offload
- **Performance**: 40-100 Gbps line rate

### Important Notes

⚠️ **Raspberry Pi Limitation**: Only supports XDP-SKB mode (software). For production DDoS mitigation, consider Intel N100 with I226 NIC for native XDP-DRV support.

✅ **Intel N100**: Best value for edge deployment. Built-in I226 NIC supports full XDP-DRV mode at 2.5 Gbps.

🏆 **Mellanox ConnectX**: Gold standard for enterprise. Full XDP-DRV, AF_XDP, and hardware offload.

---

## 📦 Installation

### System Requirements

**Minimum (Edge Deployment)**:
- OS: Ubuntu 22.04+, Debian 11+/12+, Raspberry Pi OS (Bookworm)
- CPU: 2 cores (ARM64 or x86_64)
- RAM: 4GB minimum, 8GB recommended
- Storage: 20GB (0-90 day retention)
- NIC: Any (XDP-SKB mode)

**Recommended (Edge with XDP-DRV)**:
- CPU: Intel N100 (4 cores, 3.4 GHz)
- RAM: 8-16GB
- NIC: Intel I226-V (2.5Gbps) or I211 (1Gbps)
- Storage: 50GB SSD

**Cloud Backend (MSSP)**:
- CPU: 16+ cores
- RAM: 64GB minimum (256GB for 1000+ tenants)
- Storage: 2TB+ NVMe SSD
- NIC: Intel X710 (40Gbps) or Mellanox ConnectX-5 (100Gbps)

### Software Dependencies

**Core Dependencies**:
```bash
pip install numpy>=1.24.0 scipy>=1.10.0
```

**Database Support**:
```bash
# ClickHouse (edge)
pip install clickhouse-driver>=0.2.6

# Apache Doris (cloud backend)
pip install pymysql>=1.1.0
```

**XDP/eBPF Support** (Ubuntu/Debian):
```bash
apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
apt-get install -y clang llvm
```

### Verify Installation

```python
#!/usr/bin/env python3
from qsecbit import Qsecbit, XDPManager, NICDetector

# Check BCC availability
try:
    from bcc import BPF
    print("✓ BCC/eBPF available")
except ImportError:
    print("✗ BCC not installed")

# Detect NIC capabilities
interface = NICDetector.get_primary_interface()
if interface:
    capability = NICDetector.detect_capability(interface)
    print(f"✓ Detected: {capability.vendor} {capability.model}")
    print(f"  XDP-DRV: {'✓' if capability.xdp_drv else '✗'}")
```

---

## 🔧 Usage

### Basic Usage (No XDP)

```python
#!/usr/bin/env python3
import numpy as np
from qsecbit import Qsecbit, QsecbitConfig

# Define baseline system profile
baseline_mu = np.array([0.1, 0.2, 0.15, 0.33])  # CPU, Memory, Network, Disk
baseline_cov = np.eye(4) * 0.02
quantum_anchor = 6.144  # Baseline entropy

# Initialize qsecbit
config = QsecbitConfig(
    alpha=0.30,  # System drift weight
    beta=0.30,   # Attack probability weight
    gamma=0.20,  # Classifier decay weight
    delta=0.20,  # Quantum drift weight
    amber_threshold=0.45,
    red_threshold=0.70
)

qsecbit = Qsecbit(baseline_mu, baseline_cov, quantum_anchor, config)

# Analyze current system state
current_telemetry = np.array([0.25, 0.42, 0.35, 0.45])
attack_probability = 0.72  # From ML model
classifier_confidence = np.array([0.76, 0.71, 0.73])

sample = qsecbit.calculate(
    x_t=current_telemetry,
    p_attack=attack_probability,
    c_t=classifier_confidence,
    dt=1.0
)

print(f"Qsecbit Score: {sample.score:.4f}")
print(f"RAG Status: {sample.rag_status}")
print(f"Components: {sample.components}")
```

### With XDP/eBPF Integration

```python
#!/usr/bin/env python3
import os
import numpy as np
from qsecbit import Qsecbit, QsecbitConfig

# Enable XDP for edge deployment
os.environ['XDP_ENABLED'] = 'true'
os.environ['DEPLOYMENT_TYPE'] = 'edge'
os.environ['CLICKHOUSE_ENABLED'] = 'true'
os.environ['CLICKHOUSE_HOST'] = '10.200.5.11'

# Initialize qsecbit (XDP auto-loads)
baseline_mu = np.array([0.1, 0.2, 0.15, 0.33])
baseline_cov = np.eye(4) * 0.02
quantum_anchor = 6.144

qsecbit = Qsecbit(baseline_mu, baseline_cov, quantum_anchor)

# Output:
# ✓ NIC Detected: Intel I226
#   - Interface: eth0
#   - Driver: igc
#   - XDP Mode: xdp-drv
#   - Max Throughput: 2.5Gbps
#   - Notes: Intel N100 typical NIC. Full XDP-DRV support.
# ✓ XDP program loaded on eth0 (xdp-drv)
# ✓ XDP/eBPF DDoS mitigation enabled
# ✓ ClickHouse integration enabled (edge deployment)

# Block attacker IPs dynamically
if qsecbit.xdp_manager:
    qsecbit.xdp_manager.block_ip("192.168.1.100")
    qsecbit.xdp_manager.block_ip("10.0.0.50")

    # Get XDP statistics
    stats = qsecbit.xdp_manager.get_stats()
    print(f"Total packets: {stats.total_packets}")
    print(f"Dropped (blocked): {stats.dropped_blocked}")
    print(f"Dropped (rate-limited): {stats.dropped_rate_limit}")

# Analyze threats (XDP stats automatically included)
sample = qsecbit.calculate(
    x_t=np.array([0.25, 0.42, 0.35, 0.45]),
    p_attack=0.72,
    c_t=np.array([0.76, 0.71, 0.73])
)

# Data automatically saved to ClickHouse with XDP metrics
```

### Cloud Backend (MSSP Multi-Tenant)

```python
#!/usr/bin/env python3
import os
from qsecbit import Qsecbit

# Configure for cloud backend
os.environ['DEPLOYMENT_TYPE'] = 'cloud-backend'
os.environ['TENANT_ID'] = 'customer-12345'
os.environ['DORIS_ENABLED'] = 'true'
os.environ['DORIS_HOST'] = '10.100.1.10'
os.environ['DORIS_PORT'] = '9030'
os.environ['DORIS_USER'] = 'root'
os.environ['DORIS_PASSWORD'] = 'secure_password'

# Initialize (no XDP in cloud)
qsecbit = Qsecbit(baseline_mu, baseline_cov, quantum_anchor)

# Output:
# ✓ Doris integration enabled (cloud backend, tenant: customer-12345)

# All data automatically isolated by tenant_id in Doris
sample = qsecbit.calculate(...)
# Data saved to Doris with automatic tenant_id filtering
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `DEPLOYMENT_TYPE` | `edge`, `cloud-backend` | `edge` | Deployment mode |
| `XDP_ENABLED` | `true`, `false` | `false` | Enable XDP/eBPF DDoS mitigation |
| `CLICKHOUSE_ENABLED` | `true`, `false` | `true` | Enable ClickHouse (edge) |
| `CLICKHOUSE_HOST` | IP address | `10.200.5.11` | ClickHouse server |
| `CLICKHOUSE_PORT` | Port | `9001` | ClickHouse native protocol port |
| `CLICKHOUSE_DB` | Database name | `security` | ClickHouse database |
| `DORIS_ENABLED` | `true`, `false` | `true` | Enable Doris (cloud) |
| `DORIS_HOST` | IP address | `10.100.1.10` | Doris frontend server |
| `DORIS_PORT` | Port | `9030` | Doris MySQL protocol port |
| `DORIS_DB` | Database name | `security` | Doris database |
| `TENANT_ID` | String | `default` | Multi-tenant identifier (cloud) |
| `POD_NAME` | String | `unknown` | Pod/container name |

### QsecbitConfig Parameters

```python
config = QsecbitConfig(
    # Component weights (must sum to 1.0)
    alpha=0.30,          # System drift weight (auto: 0.25 if energy enabled)
    beta=0.30,           # Attack probability weight (auto: 0.25 if energy enabled)
    gamma=0.20,          # Classifier decay weight
    delta=0.20,          # Quantum drift weight (auto: 0.15 if energy enabled)
    epsilon=0.0,         # Energy anomaly weight (auto: 0.15 if energy enabled)

    # RAG thresholds
    amber_threshold=0.45,  # Warning threshold
    red_threshold=0.70,    # Critical threshold

    # Normalization parameters
    lambda_crit=0.15,      # Classifier drift threshold
    q_crit=0.25,           # Quantum drift threshold
    drift_slope=3.5,       # Logistic function slope
    drift_center=2.0,      # Logistic function center

    # History management
    max_history_size=1000,      # Maximum samples to retain
    convergence_window=10,      # Samples for convergence analysis

    # Energy monitoring parameters (NEW)
    energy_monitoring_enabled=False,  # Enable energy-based anomaly detection
    energy_spike_threshold=2.5,       # Z-score threshold for spike detection
    energy_ewma_alpha=0.3,            # EWMA smoothing factor (0-1)
    energy_baseline_window=100        # Samples for baseline calculation
)
```

---

## 📊 API Reference

### Qsecbit Class

**Methods**:
- `calculate(x_t, p_attack, c_t, q_t=None, dt=1.0, metadata=None)` → `QsecbitSample`
- `convergence_rate(window=None)` → `float | None`
- `trend(window=20)` → `str`  # 'IMPROVING', 'STABLE', 'DEGRADING'
- `export_history(filepath)` → `None`
- `summary_stats()` → `Dict`

### XDPManager Class

**Methods**:
- `load_program(program_code=None)` → `bool`
- `unload_program()` → `bool`
- `get_stats()` → `XDPStats | None`
- `block_ip(ip_address)` → `bool`
- `unblock_ip(ip_address)` → `bool`

### NICDetector Class

**Static Methods**:
- `get_primary_interface()` → `str | None`
- `get_driver(interface)` → `str | None`
- `detect_capability(interface)` → `NICCapability`
- `select_xdp_mode(capability, prefer_drv=True)` → `XDPMode`

### EnergyMonitor Class (NEW)

**Methods**:
- `capture_snapshot()` → `SystemEnergySnapshot | None`
- `detect_anomalies(snapshot)` → `Dict[str, any]`
- `update_baselines()` → `None`

**Attributes**:
- `rapl_available: bool` - Whether RAPL energy counters are available
- `rapl_package_path: Path | None` - Path to RAPL energy counter
- `history: List[SystemEnergySnapshot]` - Energy snapshot history
- `pid_power_history: Dict[int, List[float]]` - Per-PID power time-series
- `pid_baseline_mean: Dict[int, float]` - Per-PID power baselines
- `pid_baseline_std: Dict[int, float]` - Per-PID power standard deviations

---

## ⚡ Performance

### XDP Performance Benchmarks

| **NIC** | **Mode** | **Throughput** | **CPU Usage** | **Latency** |
|---------|----------|----------------|---------------|-------------|
| Intel I226 | XDP-DRV | 2.5 Gbps | 5-10% | < 1 µs |
| Intel I226 | XDP-SKB | 1.5 Gbps | 15-20% | 2-5 µs |
| Raspberry Pi 4 | XDP-SKB | 800 Mbps | 25-30% | 5-10 µs |
| Intel X710 | XDP-DRV | 40 Gbps | < 2% | < 0.5 µs |
| Mellanox CX-5 | XDP-DRV | 100 Gbps | < 1% | < 0.2 µs |

### Database Performance

| **Database** | **Deployment** | **Write Speed** | **Query Speed** |
|--------------|----------------|-----------------|-----------------|
| ClickHouse | Edge (1 device) | 100k rows/sec | 0.1-0.5 sec |
| Doris | Cloud (1000 tenants) | 500k rows/sec | 2-5 sec |

---

## 🔍 Troubleshooting

### XDP Not Loading

**Problem**: `XDP/eBPF support disabled` message

**Solutions**:
```bash
# Check BCC installation
python3 -c "from bcc import BPF; print('BCC OK')"

# Install if missing (Ubuntu/Debian)
apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)

# Check kernel support
uname -r  # Should be 4.8+ for XDP
zgrep CONFIG_BPF /proc/config.gz  # Should show =y
```

### XDP-DRV Mode Not Available

**Problem**: Falls back to XDP-SKB even with compatible NIC

**Solutions**:
```bash
# Check driver version
ethtool -i eth0

# Update driver (Intel I226 example)
dnf update -y intel-igc-kmod

# Verify XDP support in driver
ip link set dev eth0 xdpdrv obj /dev/null  # Test command
```

### Database Connection Failures

**Problem**: `Failed to save to clickhouse/doris`

**Solutions**:
```bash
# ClickHouse (edge)
curl http://10.200.5.11:8123/ping
podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "SELECT 1"

# Doris (cloud)
mysql -h 10.100.1.10 -P 9030 -u root -p
```

### High CPU Usage with XDP-SKB

**Problem**: CPU usage > 30% with XDP enabled

**Solution**: Upgrade to NIC with XDP-DRV support (Intel I211/I226, X710, or Mellanox ConnectX).

---

## 📚 Additional Resources

- **Main Documentation**: `/home/user/hookprobe/README.md`
- **CLAUDE.md**: AI assistant guide
- **Backend Deployment**: `docs/installation/cloud-deployment.md`
- **ClickHouse Integration**: `docs/guides/clickhouse-quick-start.md`

---

## 📝 License

Proprietary License - See `LICENSE` file in this directory.

---

## 👤 Author

**Andrei Toma**
HookProbe Project
qsecbit@hookprobe.com

---

**Qsecbit v6.0 "Unified"** - Single Source of Truth for Cyber Protection

*One algorithm · All layers · Real-time mitigation*
