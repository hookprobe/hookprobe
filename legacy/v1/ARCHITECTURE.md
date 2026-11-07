# HookProbe Architecture

> **Federated Cybersecurity Mesh: Privacy-Preserving Collective Defense**

**Full Documentation**: [docs/architecture/HOOKPROBE-ARCHITECTURE.md](docs/architecture/HOOKPROBE-ARCHITECTURE.md)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          HOOKPROBE FEDERATED MESH                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│                    ┌────────────────────────────────┐                          │
│                    │      HTP Mesh Protocol          │                          │
│                    │    (Trust Fabric + Qsecbit)     │                          │
│                    └────────────────┬────────────────┘                          │
│                                     │                                           │
│          ┌──────────────────────────┼──────────────────────────┐               │
│          │                          │                          │               │
│    ┌─────┴─────┐              ┌─────┴─────┐              ┌─────┴─────┐         │
│    │   NEXUS   │ ◄──HTP Mesh──►  NEXUS   │ ◄──HTP Mesh──►  NEXUS   │         │
│    │  Region A │              │ Region B │              │ Region C │         │
│    └─────┬─────┘              └─────┬─────┘              └─────┬─────┘         │
│          │                          │                          │               │
│    ┌─────┴─────┐              ┌─────┴─────┐              ┌─────┴─────┐         │
│    │ Guardian  │              │ Fortress  │              │ Guardian  │         │
│    │ Fortress  │              │ Guardian  │              │ Fortress  │         │
│    │ Sentinel  │              │ Sentinel  │              │ Sentinel  │         │
│    └───────────┘              └───────────┘              └───────────┘         │
│                                                                                 │
│    One node's detection → Everyone's protection (Herd Immunity)                │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Core Philosophy

**Traditional SOC**: One analyst watches 1000 networks (impossible)
**HookProbe Mesh**: 1000 nodes share intelligence instantly (unstoppable)

We flip the SOC model inside-out with a federated architecture where:
- **No raw data leaves** your network (privacy-preserving)
- **Collective defense** without exposing individual data
- **Self-evolving** threat detection via adversarial AI
- **Zero-trust mesh** where nodes prove integrity continuously

---

## Component Hierarchy

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│ TIER 1: CORE INTELLIGENCE (The Neuron)                                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ┌─────────────────────┐       ┌─────────────────────┐                        │
│   │         HTP         │       │       QSECBIT       │                        │
│   │  Transport Protocol │ ◄────► │   Security Metric   │                        │
│   └─────────────────────┘       └─────────────────────┘                        │
│           │                               │                                     │
│   • UDP 8144                      • Universal language                          │
│   • ChaCha20-Poly1305             • 0.0-1.0 resilience score                   │
│   • Kyber (post-quantum)          • Privacy-preserving                          │
│   • NAT/CGNAT traversal           • Federated aggregation                       │
│                                                                                 │
│   Location: /core/htp/            Location: /core/qsecbit/                      │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│ TIER 2: EDGE NODES (The Sensors)                                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ┌───────────────┐    ┌───────────────┐    ┌───────────────┐                  │
│   │   SENTINEL    │    │   GUARDIAN    │    │   FORTRESS    │                  │
│   │   Validator   │    │    Travel     │    │  Edge Router  │                  │
│   └───────────────┘    └───────────────┘    └───────────────┘                  │
│                                                                                 │
│   RAM: 256MB            RAM: 1.5GB           RAM: 4GB                           │
│   IoT gateways          RPi 4/5              Mini PC/Server                     │
│   LTE devices           Portable             Permanent install                  │
│                                                                                 │
│   • DSM validation      • L2-L7 detection    • VLAN segmentation               │
│   • Health monitoring   • Mobile protection  • OpenFlow SDN                    │
│   • Minimal footprint   • WiFi hotspot       • Local AI inference              │
│                         • Simple setup       • n8n automation                  │
│                                                                                 │
│   Location:             Location:            Location:                          │
│   /products/sentinel/   /products/guardian/  /products/fortress/               │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│ TIER 3: COMPUTE NODES (The Muscle)                                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐  │
│   │                              NEXUS                                       │  │
│   │                     ML/AI Heavy Computation                             │  │
│   └─────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│   RAM: 16GB+            GPU: NVIDIA recommended                                 │
│   Datacenter/Cloud      On-prem or hosted                                       │
│                                                                                 │
│   • Lightweight inference locally                                               │
│   • Aggregates edge Qsecbit scores                                              │
│   • Adversarial AI (red-teams itself)                                           │
│   • Reports weakness vectors to mesh                                            │
│   • Receives hardened models from mesh                                          │
│   • Nexus-to-Nexus mesh communication                                           │
│                                                                                 │
│   Location: /products/nexus/                                                    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘

```

---

## The Six Innovations

### 1. Federated Threat Intelligence (No Raw Data Leaves)

```
Traditional: Ship logs to SOC (expensive, privacy risk)
HookProbe:   Share only derived intelligence

┌─────────────┐                              ┌─────────────┐
│   Nexus A   │                              │    Mesh     │
│             │   ─── Qsecbit scores ───►    │             │
│  Raw logs   │   ─── Attack signatures ──►  │   Global    │
│  stay here  │   ─── Neural fingerprints ─► │   Threat    │
│             │                              │   Model     │
│             │   ◄── Hardened model ─────   │             │
└─────────────┘                              └─────────────┘

Node A's attack → Node B's immunity
Without exposing Node A's data
```

**What gets shared (not raw data):**
- Qsecbit scores (not raw telemetry)
- Attack signatures (hashed patterns, not payloads)
- Neural fingerprints (behavioral embeddings, ~256 bytes)

### 2. Adversarial AI Mesh (Self-Evolving Defense)

```
┌─────────────────────────────────────────────────────────────────┐
│                     ADVERSARIAL LEARNING LOOP                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌────────────┐      ┌────────────┐      ┌────────────┐       │
│   │   Nexus    │      │   Nexus    │      │   Nexus    │       │
│   │  Detects   │ ───► │  Generates │ ───► │   Tests    │       │
│   │  Anomaly   │      │ Adversarial│      │    Own     │       │
│   │            │      │   Sample   │      │  Defenses  │       │
│   └────────────┘      └────────────┘      └────────────┘       │
│                                                 │               │
│                                                 ▼               │
│                                        "Weakness Vector"        │
│                                                 │               │
│   ┌────────────────────────────────────────────┴──────────┐    │
│   │                        Mesh                            │    │
│   │    Aggregates weakness vectors from all Nexuses        │    │
│   │    Trains hardened model                               │    │
│   │    Pushes update to all Nexuses                        │    │
│   └────────────────────────────────────────────────────────┘    │
│                                                                 │
│   Result: Network learns from attacks it hasn't seen yet        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 3. HTP as Trust Fabric (Zero-Trust Mesh)

HTP isn't just transport—it's the identity and trust layer:

```
┌──────────────────────────────────────────────────────────────────┐
│                    PROOF OF SECURE FUNCTION (PoSF)               │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Neural weights evolve based on sensor data                     │
│   W(t+1) = W(t) - η × ∇L(W, TER)                                │
│                                                                  │
│   Each node proves its integrity by:                             │
│   • Cryptographic PoSF signatures                                │
│   • Reputation score based on:                                   │
│     - Uptime                                                     │
│     - False positive rate                                        │
│     - Contribution to collective intelligence                    │
│     - Response time to mesh directives                           │
│                                                                  │
│   Bad actors can't join the mesh                                 │
│   Compromised Nexuses get isolated automatically                 │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 4. Qsecbit as Universal Language

Single metric that works at every scale:

| Component | Produces | Consumes |
|-----------|----------|----------|
| **Guardian** | Local Qsecbit | Mitigation commands |
| **Fortress** | Local + network Qsecbit | WAF rules, IDS updates |
| **Nexus** | Aggregated Qsecbit | Global insights |

```python
# The Formula
Qsecbit = α·drift + β·p_attack + γ·decay + δ·q_drift + ε·energy_anomaly

# RAG Status
GREEN  (< 0.45):  Normal — learning baseline
AMBER  (0.45-0.70): Warning — auto-response triggered
RED    (> 0.70):  Critical — full mitigation deployed
```

Every decision traces back to Qsecbit: **Auditable, explainable AI**.

### 5. Decentralized Response Coordination (Herd Immunity)

```
┌──────────────────────────────────────────────────────────────────┐
│                    COORDINATED ATTACK RESPONSE                   │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   T+00s: Mesh detects pattern hitting Nexus A, B, C              │
│          │                                                       │
│          ▼                                                       │
│   T+05s: Mesh broadcasts: "Attack signature X detected"          │
│          │                                                       │
│          ├─────────────────────────────────────────────────┐     │
│          ▼                   ▼                   ▼         ▼     │
│        Nexus A            Nexus B            Nexus C    Nexus D  │
│       (already hit)      (already hit)      (already hit) (safe) │
│          │                   │                   │         │     │
│          ▼                   ▼                   ▼         ▼     │
│   T+10s: All Nexuses preemptively block signature X              │
│          │                                                       │
│          ▼                                                       │
│   T+15s: Nexus D protected BEFORE attack reaches it              │
│                                                                  │
│   Attacker's campaign fails before reaching 80% of targets       │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 6. Nexus-as-a-Service (Decentralized Marketplace)

Anyone can run a Nexus and contribute to the mesh:

| Operator | Use Case | Benefits |
|----------|----------|----------|
| Service Providers | Deploy for customers | Revenue, fleet control |
| Enterprises | Run their own | Data sovereignty, custom models |
| Researchers | Contribute capacity | Early threat intel, reputation |
| Home users | Spare hardware | Community protection |

Contributors earn:
- **Reputation**: Priority mesh access
- **Threat Intel**: See patterns before public disclosure
- **Revenue Share**: If running commercial

---

## Data Flow Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              DATA FLOW                                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ┌─────────┐     Raw        ┌─────────┐    Qsecbit    ┌─────────┐             │
│   │Guardian │ ──telemetry──► │ Nexus   │ ───scores───► │  Mesh   │             │
│   │Fortress │    (local)     │         │   (derived)   │         │             │
│   │Sentinel │                │         │               │         │             │
│   └─────────┘                └─────────┘               └─────────┘             │
│                                                              │                  │
│                                                              │                  │
│   ┌─────────┐    Hardened    ┌─────────┐    Global     ┌────┴────┐             │
│   │Guardian │ ◄───model────  │ Nexus   │ ◄──updates──  │  Mesh   │             │
│   │Fortress │    (updates)   │         │   (insights)  │         │             │
│   │Sentinel │                │         │               │         │             │
│   └─────────┘                └─────────┘               └─────────┘             │
│                                                                                 │
│   RAW DATA NEVER LEAVES THE EDGE                                               │
│   Only derived intelligence flows up                                            │
│   Only hardened models flow down                                                │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Protocol Stack

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            HOOKPROBE PROTOCOL STACK                             │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   Layer 6: Application                                                          │
│   ┌─────────────────────────────────────────────────────────────────────────┐  │
│   │  Mesh Portal  │  Fleet Mgmt  │  Node Portal  │  Threat Dashboard       │  │
│   └─────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│   Layer 5: Intelligence                                                         │
│   ┌─────────────────────────────────────────────────────────────────────────┐  │
│   │    Qsecbit    │   Neural Fingerprints   │   Federated Learning          │  │
│   └─────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│   Layer 4: Consensus                                                            │
│   ┌─────────────────────────────────────────────────────────────────────────┐  │
│   │    DSM (BLS Signatures)    │    PoSF Verification    │    Reputation    │  │
│   └─────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│   Layer 3: Identity                                                             │
│   ┌─────────────────────────────────────────────────────────────────────────┐  │
│   │    Neural Resonance (TER → Weight → PoSF)    │    Node Identity         │  │
│   └─────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│   Layer 2: Transport                                                            │
│   ┌─────────────────────────────────────────────────────────────────────────┐  │
│   │    HTP (UDP 8144)    │    ChaCha20-Poly1305    │    Kyber (Quantum)     │  │
│   └─────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│   Layer 1: Detection                                                            │
│   ┌─────────────────────────────────────────────────────────────────────────┐  │
│   │    XDP/eBPF    │    NAPSE (AI-Native IDS)    │    L2-L7 Monitors       │  │
│   └─────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
hookprobe/
├── core/                           # 🧠 Core Intelligence
│   ├── htp/                       # HookProbe Transport Protocol
│   │   ├── transport/             # UDP transport, NAT traversal
│   │   ├── crypto/                # ChaCha20, Kyber PQ crypto
│   │   ├── mesh/                  # Nexus-to-Nexus protocol
│   │   └── posf/                  # Proof of Secure Function
│   ├── qsecbit/                   # Quantified Security Metric
│   │   ├── engine/                # Score calculation
│   │   ├── federation/            # Privacy-preserving aggregation
│   │   └── signatures/            # Neural attack fingerprints
│   └── neuro/                     # Neural Resonance Protocol
│       ├── ter/                   # Telemetry Event Record
│       ├── weights/               # Neural weight evolution
│       └── identity/              # Cryptographic identity
│
├── products/                       # 📦 Product Tiers
│   ├── sentinel/                  # DSM Validator (IoT, 512MB)
│   ├── guardian/                  # Travel Companion (RPi, 3GB)
│   ├── fortress/                  # Edge Router (Mini PC, 8GB)
│   └── nexus/                     # ML/AI Compute (Server, 64GB+)
│
├── shared/                         # 🔧 Shared Infrastructure
│   ├── dsm/                       # Decentralized Security Mesh
│   │   ├── consensus/             # BLS signature aggregation
│   │   ├── gossip/                # P2P threat announcement
│   │   └── ledger/                # Microblock chain
│   └── response/                  # Automated threat response
│
├── deploy/                         # 🚀 Deployment
│   ├── install/                   # Installation scripts
│   └── containers/                # Podman/Docker configs
│
└── docs/                           # 📚 Documentation
    ├── architecture/              # This document
    └── protocols/                 # Protocol specifications
```

---

## Key Technical Innovations to Build

| Innovation | Description | Status |
|------------|-------------|--------|
| **HTP Mesh Protocol** | Nexus-to-Nexus direct communication | 🔨 Building |
| **Qsecbit Federation** | Aggregate without centralizing raw data | 🔨 Building |
| **Neural Signatures** | Compressed attack fingerprints (~256 bytes) | 📋 Planned |
| **Reputation System** | Score and trust Nexuses | 📋 Planned |
| **Predictive Blocking** | Block attacks before they reach you | 📋 Planned |

---

## Product Comparison

| Feature | Sentinel | Guardian | Fortress | Nexus |
|---------|----------|----------|----------|-------|
| **RAM** | 512MB | 3GB | 8GB | 64GB+ |
| **Role** | Validator | Edge | Edge+ | Compute |
| **L2-L7 Detection** | - | ✓ | ✓ | ✓ |
| **WiFi Hotspot** | - | ✓ | ✓ | - |
| **VLAN Segmentation** | - | - | ✓ | - |
| **Local AI** | - | - | ✓ | ✓ |
| **ML Training** | - | - | - | ✓ |
| **Fleet Management** | - | - | - | Regional |
| **Location** | IoT | Travel | Home/Office | Datacenter |

---

## Getting Started

```bash
# Choose your tier based on hardware:

# IoT/LTE devices (512MB RAM)
sudo ./install.sh --tier sentinel

# Raspberry Pi travel setup (3GB RAM)
sudo ./install.sh --tier guardian

# Mini PC/Server (8GB RAM)
sudo ./install.sh --tier fortress

# Datacenter/Cloud (64GB+ RAM)
sudo ./install.sh --tier nexus
```

---

## License

**MIT License** — Enterprise-grade security, democratized for everyone.

---

**HookProbe** — *Federated Cybersecurity Mesh*

*One node's detection → Everyone's protection*
