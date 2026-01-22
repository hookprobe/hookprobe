# HookProbe Interface Security Controls Report

**Generated**: 2025-12-13
**Version**: 5.2

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Chapter 1: Sentinel (IoT Validator)](#chapter-1-sentinel-iot-validator)
3. [Chapter 2: Guardian (Travel Companion)](#chapter-2-guardian-travel-companion)
4. [Chapter 3: Fortress (Edge Router)](#chapter-3-fortress-edge-router)
5. [Chapter 4: Nexus (ML/AI Server)](#chapter-4-nexus-mlai-server)
6. [Chapter 5: Cloud Federation](#chapter-5-cloud-federation)
7. [Cross-Tier Comparison](#cross-tier-comparison)

---

## Executive Summary

This document maps security controls to their network interfaces for each HookProbe product tier.

**Key Principle**: All tiers follow the same pattern:
- **WAN Interface**: Packet inspection, threat detection (Suricata, Zeek, XDP, Qsecbit)
- **LAN Interface**: DNS filtering (dnsXai), client services
- **Internal/Localhost**: Scoring engines, ML processing

| Tier | RAM | Primary Security Focus | Key Interfaces |
|------|-----|------------------------|----------------|
| **Sentinel** | 256MB | DSM validation | eth0 (WAN) |
| **Guardian** | 1.5GB | L2-L7 detection, WiFi AP | eth0/wlan0 (WAN), wlan1/br0 (LAN) |
| **Fortress** | 4GB | VLAN segmentation, SDN | eth0 (WAN), br-vlan-* (VLANs) |
| **Nexus** | 16GB+ | ML training, regional coordination | eth0 (WAN), internal mesh |
| **Cloud** | Auto | Multi-tenant aggregation | Cloud networking |

---

## Chapter 1: Sentinel (IoT Validator)

> **256MB RAM · $25 · IoT-scale protection**

### What Sentinel Does

Sentinel is the lightest HookProbe tier, designed for IoT gateways and constrained devices. It focuses on **validation** rather than full detection.

### Network Architecture

```
              INTERNET
                  │
            ┌─────┴─────┐
            │   eth0    │
            │   (WAN)   │
            └─────┬─────┘
                  │
    ┌─────────────┴─────────────┐
    │     SECURITY CONTROLS     │
    │  ┌─────────────────────┐  │
    │  │  Lightweight Qsecbit │  │
    │  │  (validation mode)   │  │
    │  │                      │  │
    │  │  DSM Microblock      │  │
    │  │  Verification        │  │
    │  └─────────────────────┘  │
    └─────────────────────────────┘
                  │
        (Optional downstream)
```

### Interface Definitions

| Interface | Role | Description |
|-----------|------|-------------|
| **eth0** | WAN | Single uplink to internet/upstream node |
| **lo** | Localhost | Internal DSM validation services |

### Security Controls

| Control | Interface | What It Does |
|---------|-----------|--------------|
| **DSM Validator** | eth0 → localhost | Validates microblocks from mesh (timestamp, sequence, signatures) |
| **Health Monitor** | localhost | Reports node health to mesh |
| **Partial BLS Signing** | localhost | Contributes partial signatures for consensus |
| **Threat Cache** | localhost | Maintains compact threat cache (100 entries) |

### What Sentinel Does NOT Have

- ❌ Suricata/Zeek (too heavy for 256MB)
- ❌ XDP/eBPF (simplified network stack)
- ❌ WiFi AP mode
- ❌ dnsXai (no DNS filtering)
- ❌ Full L2-L7 detection

### Summary

Sentinel is a **verification node**. It validates that threat intelligence from the mesh is legitimate, but doesn't do heavy packet inspection itself. Think of it as a witness that confirms what other nodes report.

---

## Chapter 2: Guardian (Travel Companion)

> **1.5GB RAM · $75 · Portable protection**

### What Guardian Does

Guardian is the portable security gateway for travelers. It creates a protected WiFi bubble anywhere you go - hotels, cafés, airports.

### Network Architecture

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

### Interface Definitions

| Interface | Role | IP Address | Description |
|-----------|------|------------|-------------|
| **eth0** | WAN Primary | DHCP | Ethernet uplink (highest priority) |
| **wlan0** | WAN Fallback | DHCP | WiFi upstream (hotel/café WiFi) |
| **wlan1** | LAN AP | N/A (bridged) | WiFi Access Point for your devices |
| **br0** | LAN Bridge | 192.168.4.1/27 | Bridge interface, DHCP/DNS services |
| **lo** | Localhost | 127.0.0.1 | Internal services (dnsXai, Qsecbit) |

### Security Controls by Interface

#### WAN Interface (eth0/wlan0) - Packet Inspection

| Control | What It Does | Layer |
|---------|--------------|-------|
| **XDP/eBPF** | Kernel-level DDoS mitigation, drops bad packets before they hit userspace | Kernel |
| **Suricata** | IDS/IPS, deep packet inspection, signature matching | L3-L7 |
| **Zeek** | Network analysis, connection logs, TLS inspection | L3-L7 |
| **Qsecbit** | Threat scoring from Suricata/Zeek logs, RAG status | Meta |

#### LAN Interface (br0) - Client Services

| Control | What It Does |
|---------|--------------|
| **dnsmasq** | DHCP server (assigns IPs), DNS server (forwards to dnsXai) |
| **dnsXai** | AI DNS filtering - blocks ads, trackers, malware domains |
| **hostapd** | Creates WiFi access point (HookProbe-Guardian) |

### dnsXai ML/AI Details

**IMPORTANT**: dnsXai does NOT inspect network traffic. It only analyzes domain name **strings**.

```
LAN Client asks for "ads.tracker.com"
    │
    ▼
dnsmasq receives DNS query
    │
    ▼
dnsXai receives domain STRING only
    │
    ├─── ML extracts 20 features from the text:
    │    - shannon_entropy: 3.42
    │    - ad_pattern_count: 2 ("ads", "track")
    │    - subdomain_depth: 2
    │    - etc.
    │
    ├─── BLOCKED → Return 0.0.0.0
    └─── ALLOWED → Forward to upstream DNS
```

### Advanced Detection Features

| Feature | Where It Lives | Interface |
|---------|----------------|-----------|
| TLS SNI Inspection | Zeek ssl.log → L5 Detector | WAN |
| JA3 Fingerprinting | Zeek (if enabled) | WAN |
| IP Reputation | Suricata feeds | WAN |
| Deep Packet Inspection | Suricata IPS | WAN |
| DNS ML Classification | dnsXai | Localhost (strings only) |

### Summary Matrix

| Control | eth0 (WAN) | wlan0 (WAN) | wlan1 (AP) | br0 (LAN) | localhost |
|---------|:----------:|:-----------:|:----------:|:---------:|:---------:|
| XDP/eBPF | ✅ | ✅ | ❌ | ❌ | ❌ |
| Suricata | ✅ | ✅ | ❌ | ❌ | ❌ |
| Zeek | ✅ | ✅ | ❌ | ❌ | ❌ |
| Qsecbit | ✅ (via logs) | ✅ (via logs) | ❌ | ❌ | ✅ |
| dnsXai | ❌ | ❌ | ❌ | ✅ | ✅ |
| dnsmasq | ❌ | ❌ | ❌ | ✅ | ❌ |
| hostapd | ❌ | ❌ | ✅ | ✅ | ❌ |

---

## Chapter 3: Fortress (Edge Router)

> **4GB RAM · $200 · Business-grade protection**

### What Fortress Does

Fortress is a permanent security appliance for home offices and small businesses. It adds **VLAN segmentation** and **SDN control** to isolate different network zones.

### Network Architecture

```
                    INTERNET
                        │
                  ┌─────┴─────┐
                  │   eth0    │
                  │   (WAN)   │
                  └─────┬─────┘
                        │
    ┌───────────────────┴───────────────────────┐
    │           SECURITY CONTROLS               │
    │  ┌─────────────────────────────────────┐  │
    │  │  XDP/eBPF (enhanced DDoS)           │  │
    │  │  Suricata IDS/IPS (full ruleset)    │  │
    │  │  Zeek (full logging)                │  │
    │  │  Qsecbit (local ML inference)       │  │
    │  │  OpenFlow SDN Controller            │  │
    │  └─────────────────────────────────────┘  │
    └───────────────────┬───────────────────────┘
                        │
              ┌─────────┴─────────┐
              │   OVS Bridge      │
              │   (br-fortress)   │
              └─────────┬─────────┘
                        │
        ┌───────────────┼───────────────┐
        │               │               │
  ┌─────┴─────┐   ┌─────┴─────┐   ┌─────┴─────┐
  │ VLAN 10   │   │ VLAN 20   │   │ VLAN 30   │
  │ Trusted   │   │ Guest     │   │ IoT       │
  │ Devices   │   │ Network   │   │ Isolated  │
  │           │   │           │   │           │
  │ Full      │   │ Limited   │   │ Heavily   │
  │ Access    │   │ Access    │   │ Restricted│
  └───────────┘   └───────────┘   └───────────┘
```

### Interface Definitions

| Interface | Role | Description |
|-----------|------|-------------|
| **eth0** | WAN | Primary internet uplink |
| **eth1** | LAN Trunk | VLAN trunk to switches |
| **br-fortress** | OVS Bridge | Software-defined bridge |
| **vlan10** | Trusted VLAN | Full network access |
| **vlan20** | Guest VLAN | Internet only, isolated |
| **vlan30** | IoT VLAN | Heavily restricted, no inter-VLAN |
| **lo** | Localhost | Internal services |

### Security Controls by Interface

#### WAN Interface (eth0) - Enhanced Inspection

| Control | Enhancement over Guardian |
|---------|---------------------------|
| **XDP/eBPF** | Full ruleset, hardware offload if supported |
| **Suricata** | Complete ruleset (not trimmed for Pi) |
| **Zeek** | Full logging, JA3 enabled by default |
| **Qsecbit** | Local ML inference for faster scoring |

#### VLAN Interfaces - Zone Isolation

| VLAN | Security Policy |
|------|-----------------|
| **VLAN 10 (Trusted)** | Full access, can reach other VLANs |
| **VLAN 20 (Guest)** | Internet only, no local network |
| **VLAN 30 (IoT)** | Internet only, rate limited, heavy logging |

#### OpenFlow SDN Controller

Fortress uses OpenFlow to dynamically control traffic:

```
Threat Detected (Qsecbit score > 0.7)
    │
    ▼
SDN Controller creates flow rule:
    "Block traffic from compromised IoT device"
    │
    ▼
OVS Bridge applies rule instantly
    │
    ▼
Device quarantined without affecting other VLANs
```

### Summary Matrix

| Control | eth0 (WAN) | VLANs | OVS Bridge | localhost |
|---------|:----------:|:-----:|:----------:|:---------:|
| XDP/eBPF | ✅ | ❌ | ❌ | ❌ |
| Suricata | ✅ | ✅ (mirror) | ❌ | ❌ |
| Zeek | ✅ | ✅ (mirror) | ❌ | ❌ |
| Qsecbit | ✅ | ✅ | ❌ | ✅ |
| dnsXai | ❌ | ✅ | ❌ | ✅ |
| OpenFlow | ❌ | ❌ | ✅ | ❌ |

---

## Chapter 4: Nexus (ML/AI Server)

> **16GB+ RAM · $2000+ · Regional intelligence hub**

### What Nexus Does

Nexus is the ML powerhouse. It **trains models**, **coordinates federated learning**, and serves as a **regional aggregation point** for threat intelligence.

### Network Architecture

```
                    INTERNET
                        │
                  ┌─────┴─────┐
                  │   eth0    │
                  │   (WAN)   │
                  └─────┬─────┘
                        │
    ┌───────────────────┴───────────────────────┐
    │           SECURITY CONTROLS               │
    │  ┌─────────────────────────────────────┐  │
    │  │  Full Security Stack                 │  │
    │  │  + GPU-accelerated ML Training       │  │
    │  │  + Federated Learning Coordinator    │  │
    │  │  + Regional Threat Aggregation       │  │
    │  │  + Adversarial Testing Engine        │  │
    │  └─────────────────────────────────────┘  │
    └───────────────────┬───────────────────────┘
                        │
              ┌─────────┴─────────┐
              │   Mesh Network    │
              │   (HTP Protocol)  │
              └─────────┬─────────┘
                        │
        ┌───────────────┼───────────────┐
        │               │               │
  ┌─────┴─────┐   ┌─────┴─────┐   ┌─────┴─────┐
  │ Guardian  │   │ Guardian  │   │ Fortress  │
  │ Node 1    │   │ Node 2    │   │ Node 3    │
  └───────────┘   └───────────┘   └───────────┘
```

### Interface Definitions

| Interface | Role | Description |
|-----------|------|-------------|
| **eth0** | WAN | Primary internet + mesh uplink |
| **eth1** | Management | Optional management network |
| **lo** | Localhost | ML training, model serving |

### Security Controls by Interface

#### WAN Interface (eth0)

Same as Fortress (full stack), but Nexus also:
- Receives threat intelligence from child nodes
- Distributes trained model weights
- Coordinates federated learning rounds

#### ML Processing (localhost)

| ML Component | What It Does |
|--------------|--------------|
| **Local Model Training** | Trains threat detection models on aggregated data |
| **Federated Coordinator** | Orchestrates model weight sharing without raw data |
| **Adversarial Engine** | Tests models against attack evasion techniques |
| **Pattern Correlation** | Finds cross-mesh attack patterns |

### Summary Matrix

| Control | eth0 (WAN) | Mesh Network | localhost |
|---------|:----------:|:------------:|:---------:|
| XDP/eBPF | ✅ | ❌ | ❌ |
| Suricata | ✅ | ❌ | ❌ |
| Zeek | ✅ | ❌ | ❌ |
| Qsecbit | ✅ | ✅ (aggregation) | ✅ |
| dnsXai | ✅ | ✅ (federated) | ✅ |
| ML Training | ❌ | ❌ | ✅ (GPU) |
| Federated Learning | ❌ | ✅ | ✅ |

---

## Chapter 5: Cloud Federation

> **Auto-scale · SaaS pricing · Global coordination**

### What Cloud Federation Does

The cloud platform aggregates intelligence from thousands of nodes without seeing raw customer data.

### Network Architecture

```
                    ┌─────────────────────────────────┐
                    │         CLOUD FEDERATION        │
                    │    (mesh.hookprobe.com)         │
                    │                                 │
                    │  ┌───────────────────────────┐  │
                    │  │    Django Web Portal      │  │
                    │  │    - Multi-tenant UI      │  │
                    │  │    - Customer dashboards  │  │
                    │  │    - Cortex visualization │  │
                    │  └───────────────────────────┘  │
                    │                                 │
                    │  ┌───────────────────────────┐  │
                    │  │    API Gateway            │  │
                    │  │    - REST/GraphQL APIs    │  │
                    │  │    - HTP Protocol Handler │  │
                    │  │    - Webhook dispatch     │  │
                    │  └───────────────────────────┘  │
                    │                                 │
                    │  ┌───────────────────────────┐  │
                    │  │    Intelligence Engine    │  │
                    │  │    - Cross-tenant dedup   │  │
                    │  │    - Global threat DB     │  │
                    │  │    - ML model serving     │  │
                    │  └───────────────────────────┘  │
                    └─────────────┬───────────────────┘
                                  │
                    ┌─────────────┼─────────────┐
                    │             │             │
              ┌─────┴─────┐ ┌─────┴─────┐ ┌─────┴─────┐
              │ Customer  │ │ Customer  │ │ Customer  │
              │ A Mesh    │ │ B Mesh    │ │ C Mesh    │
              │           │ │           │ │           │
              │ Guardian  │ │ Fortress  │ │ Nexus     │
              │ Nodes     │ │ Nodes     │ │ Nodes     │
              └───────────┘ └───────────┘ └───────────┘
```

### Interface Model

Cloud Federation uses **cloud networking** rather than physical interfaces:

| Component | Network | Description |
|-----------|---------|-------------|
| **Load Balancer** | Public | Incoming HTP connections |
| **API Gateway** | Public | REST/GraphQL API endpoints |
| **Web Portal** | Public | Customer dashboards |
| **Internal Services** | Private VPC | Database, cache, ML serving |

### Security Controls

#### Inbound (from customer nodes)

| Control | What It Does |
|---------|--------------|
| **HTP Validator** | Authenticates incoming node connections |
| **TER Verification** | Validates Telemetry Event Records |
| **Rate Limiting** | Prevents API abuse |

#### Intelligence Processing

| Control | What It Does |
|---------|--------------|
| **Cross-Tenant Dedup** | Identifies threats seen by multiple customers |
| **Global Threat DB** | Historical threat intelligence |
| **ML Model Serving** | Distributes trained models to nodes |
| **Consensus Finalization** | Global DSM checkpoint aggregation |

#### Outbound (to customer nodes)

| Control | What It Does |
|---------|--------------|
| **Threat Broadcast** | Distributes new IOCs to all nodes |
| **Model Updates** | Pushes updated ML weights |
| **Alert Dispatch** | Webhooks to customer SOCs |

### What Cloud Federation Does NOT Do

- ❌ Inspect customer traffic (privacy-preserving)
- ❌ Store raw packets
- ❌ Access customer networks directly

Cloud Federation only sees:
- Anonymized threat hashes (IOCs)
- Aggregated statistics
- Model weights (not training data)
- DSM microblock metadata

### Summary Matrix

| Control | Public Internet | Private VPC | Customer Mesh |
|---------|:---------------:|:-----------:|:-------------:|
| HTP Gateway | ✅ | ❌ | ✅ |
| REST API | ✅ | ❌ | ❌ |
| Intelligence Engine | ❌ | ✅ | ❌ |
| Threat Distribution | ✅ | ❌ | ✅ |
| ML Model Serving | ❌ | ✅ | ✅ |

---

## Cross-Tier Comparison

### Security Controls by Tier

| Control | Sentinel | Guardian | Fortress | Nexus |
|---------|:--------:|:--------:|:--------:|:-----:|
| **XDP/eBPF** | ❌ | ✅ | ✅ | ✅ |
| **Suricata** | ❌ | ✅ | ✅ | ✅ |
| **Zeek** | ❌ | ✅ | ✅ | ✅ |
| **Qsecbit** | Lite | ✅ | ✅ | ✅ |
| **dnsXai** | ❌ | ✅ | ✅ | ✅ |
| **DSM** | Validate | Participate | Coordinate | Aggregate |
| **VLAN/SDN** | ❌ | ❌ | ✅ | ❌ |
| **ML Training** | ❌ | ❌ | Inference | ✅ |
| **WiFi AP** | ❌ | ✅ | ✅ | ❌ |

### Interface Types by Tier

| Tier | WAN Interfaces | LAN Interfaces | Special |
|------|----------------|----------------|---------|
| **Sentinel** | eth0 | None | DSM validation |
| **Guardian** | eth0, wlan0 | wlan1, br0 | WiFi AP |
| **Fortress** | eth0 | VLAN 10/20/30 | OVS, SDN |
| **Nexus** | eth0 | Management | GPU, Mesh |

### Key Takeaways

1. **All tiers inspect WAN traffic** (except Sentinel which validates only)
2. **DNS filtering happens on LAN** (dnsXai receives strings, not packets)
3. **dnsXai ML analyzes text** (domain names), not network traffic
4. **Advanced detection (TLS, JA3) is on WAN** via Suricata/Zeek
5. **Higher tiers add capabilities** but don't change the basic pattern

---

*Report generated from codebase analysis v5.2. For system-level configs, check `/etc/suricata/suricata.yaml` and `/etc/zeek/node.cfg`.*
