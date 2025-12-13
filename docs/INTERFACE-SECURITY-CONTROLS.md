# HookProbe Interface Security Controls Report

**Generated**: 2025-12-13
**Version**: 5.1

## Executive Summary

This document maps all security controls to their respective network interfaces in the HookProbe Guardian deployment.

**Key Finding**: Your understanding is **correct**:
- **WAN Interface (eth0/wlan0)**: Qsecbit, XDP/eBPF, Suricata, Zeek - packet inspection and threat detection
- **LAN Interface (br0)**: dnsXai - DNS query filtering for local clients

---

## Network Interface Architecture

```
                    INTERNET
                        │
          ┌─────────────┴─────────────┐
          │                           │
      ┌───┴───┐                 ┌─────┴─────┐
      │ eth0  │                 │  wlan0    │
      │ (WAN) │                 │(WAN WiFi) │
      │Primary│                 │ Fallback  │
      └───┬───┘                 └─────┬─────┘
          │                           │
          │   ┌───────────────────────┘
          │   │
    ┌─────┴───┴─────────────────────────────────┐
    │           SECURITY CONTROLS               │
    │  ┌─────────────────────────────────────┐  │
    │  │  XDP/eBPF (kernel-level filtering)  │  │
    │  │  Suricata IDS/IPS (packet capture)  │  │
    │  │  Zeek (network analysis)            │  │
    │  │  Qsecbit (threat scoring)           │  │
    │  └─────────────────────────────────────┘  │
    └───────────────────┬───────────────────────┘
                        │
                        │ NAT/Routing
                        │
    ┌───────────────────┴───────────────────────┐
    │               br0 (Bridge)                │
    │  ┌─────────────────────────────────────┐  │
    │  │  dnsmasq (DHCP: 192.168.4.2-30)     │  │
    │  │  dnsmasq (DNS: 192.168.4.1:53)      │  │
    │  │      ↓ forwards to                  │  │
    │  │  dnsXai (127.0.0.1:5353)            │  │
    │  └─────────────────────────────────────┘  │
    └───────────────────┬───────────────────────┘
                        │
                  ┌─────┴─────┐
                  │  wlan1    │
                  │  (WiFi AP)│
                  │ HookProbe │
                  │ -Guardian │
                  └─────┬─────┘
                        │
              ┌─────────┴─────────┐
              │   LAN Clients     │
              │  192.168.4.0/27   │
              └───────────────────┘
```

---

## Interface Definitions

| Interface | Role | IP Address | Description |
|-----------|------|------------|-------------|
| **eth0** | WAN Primary | DHCP | Ethernet uplink (highest priority) |
| **wlan0** | WAN Fallback | DHCP | WiFi upstream (hotel/café WiFi) |
| **wlan1** | LAN AP | N/A (bridged) | WiFi Access Point for clients |
| **br0** | LAN Bridge | 192.168.4.1/27 | Bridge interface, DHCP/DNS services |
| **lo** | Localhost | 127.0.0.1 | Internal services (dnsXai) |

---

## Security Controls by Interface

### 1. XDP/eBPF DDoS Mitigation

| Attribute | Value |
|-----------|-------|
| **File** | `core/qsecbit/xdp_manager.py:184-206` |
| **Interface** | Auto-detected primary (eth0 or wlan0) |
| **Direction** | Ingress (incoming packets) |
| **Layer** | Kernel (before network stack) |

**Interface Detection Logic** (`core/qsecbit/nic_detector.py:171-202`):
```python
# Gets default route interface
ip route show default → dev eth0/wlan0
```

**Verdict**: ✅ **WAN Interface** - Filters malicious traffic before it enters the system.

---

### 2. Suricata IDS/IPS

| Attribute | Value |
|-----------|-------|
| **Config** | `products/guardian/lib/config.py:196-200` |
| **Log Path** | `/var/log/suricata/eve.json` |
| **Interface** | Typically eth0/wlan0 (WAN) |
| **Mode** | IDS or IPS (configurable) |

**Note**: Suricata's interface is configured in `/etc/suricata/suricata.yaml` (system config, not in repo). Default captures on the primary WAN interface.

**Verdict**: ✅ **WAN Interface** - Inspects all incoming/outgoing WAN traffic.

---

### 3. Zeek Network Analysis

| Attribute | Value |
|-----------|-------|
| **Config** | `products/guardian/lib/config.py:202-204` |
| **Log Directory** | `/var/log/zeek/current/` |
| **Interface** | Typically eth0/wlan0 (WAN) |
| **Logs Used** | conn.log, http.log, ssl.log, dns.log, dhcp.log |

**Usage in Detectors** (`core/qsecbit/detectors/base.py:283-298`):
- L4 Detector: `conn.log` for port scans
- L5 Detector: `ssl.log` for TLS analysis, `http.log` for HTTP inspection
- L2 Detector: `dhcp.log` for rogue DHCP detection

**Verdict**: ✅ **WAN Interface** - Passive network analysis on WAN traffic.

---

### 4. Qsecbit Threat Scoring

| Attribute | Value |
|-----------|-------|
| **File** | `core/qsecbit/qsecbit.py` |
| **Interface** | Indirect (parses logs from Suricata/Zeek) |
| **Data Sources** | Suricata alerts, Zeek logs, /proc/net/*, ARP cache |

**Verdict**: ✅ **WAN Interface** (indirectly via Suricata/Zeek data)

---

### 5. Layer Threat Detectors (L2-L7)

| Detector | Primary Data Source | Interface |
|----------|---------------------|-----------|
| L2 DataLink | ARP cache, WiFi scans | System-wide |
| L3 Network | /proc/net/snmp, Suricata | WAN |
| L4 Transport | ss -s, Zeek conn.log, Suricata | WAN |
| L5 Session | Zeek ssl.log, http.log, Suricata | WAN |
| L7 Application | Zeek http.log, Suricata, ModSecurity | WAN |

**Verdict**: ✅ **WAN Interface** - All packet inspection occurs on WAN traffic.

---

### 6. dnsXai AI DNS Protection

| Attribute | Value |
|-----------|-------|
| **File** | `shared/dnsXai/engine.py:74-75` |
| **Listen Address** | `127.0.0.1:5353` |
| **Upstream DNS** | 1.1.1.1:53 (configurable) |
| **Interface Binding** | **NONE** - No packet capture |

**Traffic Flow**:
```
LAN Client (192.168.4.x)
    │
    │ DNS query to 192.168.4.1:53
    ▼
dnsmasq (br0 interface)
    │
    │ Forwards DOMAIN STRING to 127.0.0.1:5353
    ▼
dnsXai (localhost - NO interface binding)
    │
    │ ML classification + blocklist check
    │ (analyzes domain NAME only, not traffic)
    │
    ├─── BLOCKED → Return 0.0.0.0
    │
    └─── ALLOWED → Forward to upstream (1.1.1.1)
```

**Verdict**: ✅ **LAN Interface (br0)** - Filters DNS queries from local clients only.

---

### 6a. dnsXai ML/AI Component Details

**IMPORTANT**: The ML/AI in dnsXai does **NOT** inspect network traffic. It only analyzes domain name **strings**.

| ML Component | Location | Input Data |
|--------------|----------|------------|
| `DomainFeatureExtractor` | In-memory (localhost) | Domain name string |
| `DomainClassifier` | In-memory (localhost) | 20 text features |
| `CNAMEUncloaker` | DNS queries to upstream | DNS CNAME records |
| `FederatedLearning` | Mesh network | Model weights + domain hashes |

**What the ML Analyzes** (`shared/dnsXai/engine.py:200-264`):

| Feature | Source | Example |
|---------|--------|---------|
| `shannon_entropy` | String entropy | 3.42 |
| `ad_pattern_count` | Regex on string | 2 (found "ads", "track") |
| `subdomain_depth` | Count dots | 1 |
| `digit_ratio` | Characters | 0.0 |
| `has_uuid` | Regex pattern | False |
| ... 15 more | String analysis | ... |

**What the ML Does NOT See**:
- ❌ Raw packets
- ❌ HTTP headers or payload
- ❌ TLS handshake data
- ❌ IP addresses (except via DNS lookup)
- ❌ Any actual network traffic

**Interface Comparison**:

| Control | Binds to Interface | Sees Packets | ML Input |
|---------|-------------------|--------------|----------|
| Suricata | eth0/wlan0 (WAN) | Yes (pcap) | Packet signatures |
| Zeek | eth0/wlan0 (WAN) | Yes (pcap) | Connection metadata |
| **dnsXai** | **None** | **No** | **Domain name text** |

---

### 7. dnsmasq DHCP/DNS Server

| Attribute | Value |
|-----------|-------|
| **File** | `products/guardian/config/dnsmasq.conf:32-38` |
| **Listen Interface** | `br0` |
| **Excluded Interfaces** | eth0, wlan0, lo |

**Configuration**:
```conf
interface=br0
except-interface=eth0
except-interface=wlan0
except-interface=lo
```

**Verdict**: ✅ **LAN Interface (br0)** - DHCP/DNS only for local clients.

---

### 8. hostapd WiFi Access Point

| Attribute | Value |
|-----------|-------|
| **File** | `products/guardian/config/hostapd.conf:13-15` |
| **AP Interface** | `wlan1` |
| **Bridge** | `br0` |

**Configuration**:
```conf
interface=wlan1
bridge=br0
```

**Verdict**: ✅ **LAN Interface (wlan1 → br0)**

---

### 9. OpenFlow SDN Controller

| Attribute | Value |
|-----------|-------|
| **File** | `products/guardian/lib/openflow_controller.py` |
| **Listen** | `0.0.0.0:6653` |
| **Bridge** | `br-guardian` |

**Verdict**: ⚠️ **Internal Management** - Controls OVS bridge, not direct packet inspection.

---

## Summary Matrix

| Security Control | eth0 (WAN) | wlan0 (WAN) | wlan1 (AP) | br0 (LAN) | localhost |
|-----------------|:----------:|:-----------:|:----------:|:---------:|:---------:|
| **XDP/eBPF** | ✅ Primary | ✅ Fallback | ❌ | ❌ | ❌ |
| **Suricata** | ✅ Primary | ✅ Fallback | ❌ | ❌ | ❌ |
| **Zeek** | ✅ Primary | ✅ Fallback | ❌ | ❌ | ❌ |
| **Qsecbit** | ✅ (via logs) | ✅ (via logs) | ❌ | ❌ | ❌ |
| **Layer Detectors** | ✅ (via logs) | ✅ (via logs) | ❌ | ❌ | ❌ |
| **dnsXai** | ❌ | ❌ | ❌ | ✅ (via dnsmasq) | ✅ Listen |
| **dnsmasq** | ❌ Excluded | ❌ Excluded | ❌ | ✅ Listen | ❌ |
| **hostapd** | ❌ | ❌ | ✅ AP | ✅ Bridge | ❌ |

---

## Traffic Inspection Points

### WAN Traffic (Internet ↔ Guardian)

```
INTERNET → eth0/wlan0 → [XDP/eBPF] → [Suricata] → [Zeek] → NAT → br0 → LAN
                           ↓              ↓          ↓
                        DROP/PASS    eve.json    *.log
                                         ↓          ↓
                                    [Qsecbit Layer Detectors]
                                              ↓
                                    Threat Scoring (RAG)
```

### LAN Traffic (Clients → Guardian)

```
LAN Client → wlan1 → br0 → dnsmasq:53 → dnsXai:5353 → [ML/Blocklist] → Upstream DNS
                              ↓
                    DHCP lease assignment
```

---

## Key Configuration Files

| Purpose | File | Key Lines |
|---------|------|-----------|
| WAN interface config | `products/guardian/lib/config.py` | 169-180 |
| WAN interface detection | `core/qsecbit/nic_detector.py` | 171-202 |
| XDP attachment | `core/qsecbit/xdp_manager.py` | 184-206 |
| dnsmasq interface | `products/guardian/config/dnsmasq.conf` | 32-38 |
| hostapd interface | `products/guardian/config/hostapd.conf` | 13-15 |
| dnsXai listen | `shared/dnsXai/engine.py` | 74-75 |
| Offline mode interfaces | `products/guardian/lib/offline_mode_manager.py` | 57-60 |

---

## Recommendations

1. **Current Design is Correct**: WAN inspection + LAN DNS filtering is the proper architecture.

2. **No LAN Packet Inspection by Default**: Suricata/Zeek don't inspect br0 traffic. This is intentional for privacy (Guardian doesn't deep-inspect client traffic).

3. **If LAN Inspection Needed**: Configure Suricata to also listen on br0, but this increases CPU load significantly on Raspberry Pi.

4. **dnsXai Placement**: Correctly positioned to filter DNS without inspecting all LAN traffic.

---

*Report generated from codebase analysis. For Suricata/Zeek interface configuration, check system files `/etc/suricata/suricata.yaml` and `/etc/zeek/node.cfg`.*
