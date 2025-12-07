# HookProbe Products

> **Federated Cybersecurity Mesh — From IoT to Cloud**

The products/ directory contains the five tiers of HookProbe deployment, from lightweight IoT validators to full cloud federation platforms.

```
products/
├── sentinel/   # DSM Validator (IoT, 512MB RAM)
├── guardian/   # Travel Companion (RPi, 3GB RAM)
├── fortress/   # Edge Router (Mini PC, 8GB RAM)
├── nexus/      # ML/AI Compute (Server, 64GB+ RAM)
└── mssp/       # Cloud Federation (mssp.hookprobe.com)
```

---

## Product Hierarchy

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          HOOKPROBE PRODUCT TIERS                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ┌──────────────────────────────────────────────────────────────────────────┐ │
│   │                              MSSP                                         │ │
│   │                    Cloud Federation Platform                              │ │
│   │         mssp.hookprobe.com · Scales horizontally · Global brain          │ │
│   └──────────────────────────────────────────────────────────────────────────┘ │
│                                      ▲                                          │
│                                      │ HTP                                      │
│   ┌──────────────────────────────────┴───────────────────────────────────────┐ │
│   │                              NEXUS                                        │ │
│   │               ML/AI Heavy Computation · 64GB+ RAM                         │ │
│   │         On-prem or Cloud · Federated Learning · Regional Hub             │ │
│   └──────────────────────────────────────────────────────────────────────────┘ │
│                                      ▲                                          │
│                                      │ HTP                                      │
│         ┌────────────────────────────┼────────────────────────────┐            │
│         ▼                            ▼                            ▼            │
│   ┌───────────┐              ┌───────────┐              ┌───────────┐          │
│   │ FORTRESS  │              │ GUARDIAN  │              │ SENTINEL  │          │
│   │Edge Router│              │  Travel   │              │ Validator │          │
│   │   8GB     │              │   3GB     │              │  512MB    │          │
│   │ Mini PC   │              │   RPi     │              │   IoT     │          │
│   └───────────┘              └───────────┘              └───────────┘          │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Comparison

| Feature | Sentinel | Guardian | Fortress | Nexus | MSSP |
|---------|----------|----------|----------|-------|------|
| **RAM** | 512MB | 3GB | 8GB | 64GB+ | Auto-scale |
| **Hardware** | IoT gateway | RPi 4/5 | Mini PC | Server | Cloud |
| **Use Case** | Validate | Travel | Home/Office | Regional | Global |
| **L2-L7 Detection** | - | ✓ | ✓ | ✓ | - |
| **WiFi Hotspot** | - | ✓ | ✓ | - | - |
| **VLAN Segmentation** | - | - | ✓ | - | - |
| **OpenFlow SDN** | - | - | ✓ | - | - |
| **Local AI** | - | - | ✓ | ✓ | - |
| **ML Training** | - | - | - | ✓ | ✓ |
| **Fleet Management** | - | - | - | Regional | Global |
| **Multi-Tenant** | - | - | - | - | ✓ |
| **Price** | $25 | $75 | $200 | $2000+ | SaaS |

---

## Sentinel — DSM Validator

> **"The Watchful Eye"** — Lightweight edge validator

**Location:** `products/sentinel/`

For IoT gateways, LTE devices, and constrained environments.

### Features
- DSM mesh validation
- Health monitoring (port 9090)
- MSSP connectivity
- Minimal footprint (~50MB)
- No container overhead

### Installation
```bash
sudo ./install.sh --tier sentinel
```

---

## Guardian — Travel Companion

> **"Protection on the Move"** — Portable security gateway

**Location:** `products/guardian/`

For travelers securing devices on hotel WiFi, airports, and public networks.

### Features
- Secure WiFi hotspot creation
- L2-L7 OSI threat detection
- Mobile network protection (evil twin, MITM)
- IDS/IPS (Suricata)
- Web dashboard
- HTP secure uplink

### Installation
```bash
sudo ./install.sh --tier guardian
```

### Web Interface
- **URL:** `http://192.168.4.1:8080`
- Security overview, connected devices, WiFi management

---

## Fortress — Edge Router

> **"Your Digital Stronghold"** — Full-featured edge with AI

**Location:** `products/fortress/`

For home/office permanent installations requiring advanced security.

### Features
- Everything in Guardian, plus:
- **VLAN segmentation** — Isolate IoT devices
- **OpenFlow SDN** — Advanced traffic control
- **Local AI inference** — On-device threat detection
- **n8n automation** — Workflow orchestration
- **Grafana dashboards** — Real-time metrics
- **Victoria Metrics** — Time-series database

### Installation
```bash
sudo ./install.sh --tier fortress \
  --enable-n8n \
  --enable-monitoring
```

---

## Nexus — ML/AI Compute

> **"The Regional Brain"** — Distributed ML/AI computation

**Location:** `products/nexus/`

For regional hubs performing heavy computation and federated learning.

### Features
- Aggregates Qsecbit scores from edge nodes
- Lightweight inference locally
- Adversarial AI (red-teams itself)
- Reports weakness vectors to MSSP
- Receives hardened models from MSSP
- Nexus-to-Nexus mesh communication
- GPU acceleration (NVIDIA)

### The Federated Learning Loop
```
Edge detects anomaly
    → Generates adversarial sample
    → Tests own defenses
    → Reports "weakness vector" to MSSP

MSSP aggregates weakness vectors
    → Trains hardened model
    → Pushes update to all Nexuses

Result: Network learns from attacks it hasn't seen yet
```

### Installation
```bash
sudo ./install.sh --tier nexus \
  --enable-gpu \
  --enable-ha
```

---

## MSSP — Cloud Federation

> **"The Central Brain"** — Global coordination platform

**Location:** `products/mssp/`

The cloud federation platform at mssp.hookprobe.com.

### Features
- Customer portal
- Fleet management (all tiers)
- Global threat model
- AI/ML training pipeline
- Multi-tenant architecture
- Privacy-preserving aggregation

### Components
| Directory | Purpose |
|-----------|---------|
| `web/` | Django web application |
| `device_registry.py` | Device registration & management |
| `geolocation.py` | Location services |

### Data Flow
```
Nexuses send:          MSSP provides:
├── Qsecbit scores     ├── Hardened models
├── Attack signatures  ├── Global threat intel
├── Neural fingerprints├── Fleet commands
└── Weakness vectors   └── Reputation updates

RAW DATA NEVER LEAVES THE EDGE
Only derived intelligence flows up
```

---

## Choosing Your Tier

```
Do you have >64GB RAM and need ML training?
├── YES → Nexus
└── NO
    └── Do you need VLAN segmentation or SDN?
        ├── YES → Fortress (8GB RAM)
        └── NO
            └── Do you need WiFi hotspot and L2-L7 detection?
                ├── YES → Guardian (3GB RAM)
                └── NO → Sentinel (512MB RAM)
```

---

## Upgrade Path

```
Sentinel → Guardian → Fortress → Nexus
   ↓          ↓           ↓          ↓
  Add      Add WiFi    Add VLAN    Add ML
 L2-L7     hotspot       SDN      training
```

Each tier builds on the previous, with seamless migration:
```bash
# Upgrade Guardian to Fortress
sudo ./install.sh --tier fortress --migrate
```

---

**HookProbe Products** — *Federated Cybersecurity for Every Scale*

MIT License
