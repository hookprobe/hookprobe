<p align="center">
  <img src="assets/hookprobe-logo.svg" alt="HookProbe Logo" width="400"/>
</p>

<h1 align="center">The World's First Collective Defense Mesh</h1>

<p align="center">
  <strong>One node's detection is everyone's protection.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-5.0_Cortex-00e5ff?style=flat-square" alt="Version 5.1 Cortex"/>
  <img src="https://img.shields.io/badge/License-AGPL_v3.0_+_Commercial-blue?style=flat-square" alt="Dual License"/>
  <img src="https://img.shields.io/badge/Python-3.9+-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python 3.9+"/>
  <img src="https://img.shields.io/badge/Platform-Linux-FCC624?style=flat-square&logo=linux&logoColor=black" alt="Linux"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Crypto-Post--Quantum_(Kyber)-ff6b6b?style=flat-square" alt="Post-Quantum"/>
  <img src="https://img.shields.io/badge/AI-Qsecbit_Threat_Scoring-00ff88?style=flat-square" alt="AI Powered"/>
  <img src="https://img.shields.io/badge/Network-Zero_Trust_Mesh-ffaa00?style=flat-square" alt="Zero Trust"/>
</p>

<p align="center">
  <em>Post-quantum cryptography. AI-powered threat detection. Zero-trust mesh networking.</em>
</p>

---

## What is HookProbe?

HookProbe is an advanced, lightweight network security platform designed to bring intelligent protection to any environment — without the heavy operational overhead. It doesn’t replace SOC teams or security analysts; it empowers them by automating the repetitive, low-value noise that normally consumes time and attention.

This creates shared resilience, reduces response time, and strengthens your existing security stack.
HookProbe is built for organisations that need stronger security without adding complexity — a smart layer that supports your team, accelerates detection, and increases visibility across modern, distributed networks.

**The core principle:** When one HookProbe node detects a threat anywhere in the world, every node learns instantly. Collective intelligence replaces isolated guesswork. The mesh doesn't just defend - it evolves.

---

## Why HookProbe Exists

Enterprise security vendors build complex solutions that require dedicated teams to operate. Small organizations face two choices: expensive complexity or no protection at all.

HookProbe takes a different approach. We built software that handles the complexity internally so you can focus on what matters. Deploy in minutes. Operate with confidence. Achieve more with less.

| Traditional Security | HookProbe |
|---------------------|-----------|
| Requires security analysts | Self-operating |
| Manual threat investigation | Automated response |
| Isolated detection | Collective intelligence |
| Complex configuration | Simple deployment |
| Vendor lock-in | Open source foundation |

---

## Quick Start

```bash
# Deploy on any Linux system
curl -fsSL https://hookprobe.com/install.sh | bash

# Or clone and deploy manually
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe
./install.sh --tier guardian   # Home lab / prosumer
./install.sh --tier fortress   # Business network
./install.sh --tier nexus      # Multi-site coordination
```

**Deployment Tiers:**

| Tier | Memory | Use Case |
|------|--------|----------|
| Guardian | 1.5GB+ | Home lab, travel security, personal networks |
| Fortress | 4GB+ | Business networks, NIS2 compliance, IoT segmentation |
| Nexus | 16GB+ | Multi-site coordination, ML model training |

**[Installation Guide](docs/installation/INSTALLATION.md)** · **[Deployment Options](deploy/README.md)**

---

## How It Works

### Collective Defense Mesh

Every HookProbe installation joins a global mesh. When threats are detected, anonymized signatures propagate across the network in real-time.

```
Node A (Singapore)     Detects novel attack pattern
        │
        ▼
Mesh Intelligence      Validates and distributes signature
        │
        ├──────────────────────────────────────┐
        ▼                                      ▼
Node B (London)        Node C (New York)       Node D (Berlin)
Blocking in <30s       Blocking in <30s        Blocking in <30s
```

Traditional firewalls wait for vendor updates. HookProbe nodes protect each other continuously.

### Qsecbit Engine

Real-time threat scoring with automated response:

| Score Range | Status | System Response |
|-------------|--------|-----------------|
| < 0.45 | Normal | Baseline learning, passive monitoring |
| 0.45 - 0.70 | Elevated | Automated mitigation initiated |
| > 0.70 | Critical | Full defensive response activated |

The engine combines behavioral analysis, network anomaly detection, and collective threat intelligence to score risk in real-time.

### Network Segmentation

Automatic isolation of network segments prevents lateral movement:

```
┌─────────────────────────────────────────────────────────┐
│                    HookProbe Fortress                   │
├─────────────┬─────────────┬─────────────┬──────────────┤
│   VLAN 10   │   VLAN 20   │   VLAN 30   │   VLAN 99    │
│   Trusted   │     IoT     │    Guest    │  Quarantine  │
│             │             │             │              │
│ Workstations│   Cameras   │   Visitors  │  Suspicious  │
│   Servers   │   Sensors   │   Phones    │   Devices    │
├─────────────┴─────────────┴─────────────┴──────────────┤
│  Cross-segment traffic requires explicit authorization  │
└─────────────────────────────────────────────────────────┘
```

### DNS Protection (dnsXai)

ML-powered DNS filtering blocks threats at the source:

- Malware command and control domains
- Phishing infrastructure
- Advertising and tracking networks
- Data exfiltration tunnels

---

## Who Uses HookProbe

### Prosumers and Home Labs

Build a secure home network without becoming a security expert. HookProbe handles ad blocking, NAS protection, and remote access security automatically.

### Small and Medium Businesses

Meet NIS2 compliance requirements without hiring a security team. HookProbe provides automated incident reporting, continuous monitoring, and audit-ready documentation.

### Managed Service Providers

Deploy consistent security across client networks. Collective intelligence means every client benefits from threats detected at any client site.

---

## HookProbe Cortex - Neural Command Center

**See your mesh. Command your defense.**

Cortex is HookProbe's real-time 3D visualization - a digital twin of your entire defense network rendered on a globe. Watch attacks arrive from across the world and see them repelled in real-time.

```
┌─────────────────────────────────────────────────────────────────┐
│                     HOOKPROBE CORTEX                             │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                                                             ││
│  │           ⬡ Nexus (ML/AI)        Attack Arc →               ││
│  │              ↓                        ↓                     ││
│  │    ⬡ Guardian ←───── Mesh ─────→ ⬡ Fortress                 ││
│  │              ↓                        ↓                     ││
│  │         ⬡ Sentinel (IoT)      ← Repelled Arc                ││
│  │                                                             ││
│  │  [NODES: 1,247]  [ATTACKS: 89]  [REPELLED: 89]  [QSECBIT]  ││
│  └─────────────────────────────────────────────────────────────┘│
│         Real-time 3D globe with attack trajectories              │
└─────────────────────────────────────────────────────────────────┘
```

**Features:**
- Real-time attack visualization with animated arcs
- Node health monitoring via Qsecbit color coding
- Tier-based node representation (Sentinel → Guardian → Fortress → Nexus)
- Demo mode for showcasing without live data
- Premium visual effects: breathing nodes, particle impacts, ripple effects

**[Cortex Documentation](shared/cortex/README.md)** · **[Architecture](shared/cortex/ARCHITECTURE.md)**

---

## Architecture

```
hookprobe/
├── core/                    # Core Intelligence
│   ├── htp/                 # Transport Protocol (Post-Quantum)
│   ├── qsecbit/             # AI Threat Scoring Engine
│   └── neuro/               # Neural Resonance Authentication
│
├── shared/                  # Shared Modules
│   ├── dnsXai/              # AI DNS Protection
│   ├── mesh/                # Collective Defense Mesh
│   ├── dsm/                 # Decentralized Security Mesh
│   ├── response/            # Automated Threat Response
│   └── cortex/              # Neural Command Center (3D Globe)
│
├── products/                # Deployment Tiers
│   ├── guardian/            # Home / Prosumer (1.5GB)
│   ├── fortress/            # Business (4GB)
│   ├── nexus/               # ML Coordination (16GB+)
│   └── mssp/                # Cloud Platform
│
└── deploy/                  # Deployment Scripts
```

**[Full Architecture](ARCHITECTURE.md)** · **[Mesh Design](shared/mesh/ARCHITECTURE.md)** · **[Cortex](shared/cortex/README.md)**

---

## Technical Foundation

| Component | Technology | Purpose |
|-----------|------------|---------|
| Packet Processing | XDP/eBPF | Sub-microsecond filtering decisions |
| Cryptography | Kyber KEM | Post-quantum key exchange |
| Transport | HTP Protocol | NAT traversal, DDoS resistance |
| Intelligence | Federated ML | Privacy-preserving threat sharing |

**[Qsecbit Engine](core/qsecbit/README.md)** · **[HTP Protocol](docs/HTP_SECURITY_ENHANCEMENTS.md)** · **[dnsXai](shared/dnsXai/README.md)**

---

## NIS2 Compliance

For organizations subject to EU NIS2 Directive requirements:

- Automated incident detection and reporting (Article 23)
- Continuous risk assessment (Article 21)
- Supply chain security monitoring
- Audit trail and compliance documentation

**[GDPR Compliance](docs/GDPR.md)** · **[Security Policy](docs/SECURITY.md)**

---

## Licensing

HookProbe uses dual licensing to balance open collaboration with sustainable development.

**AGPL v3.0 (Open Source):**
- Deployment scripts
- Guardian product tier
- Mesh communication
- Threat response modules
- Documentation

**Commercial License (for SaaS/OEM):**
- Qsecbit AI algorithm
- Neural Resonance protocol
- dnsXai ML classifier
- MSSP platform

Personal use, internal business protection, and non-commercial research are free under both licenses.

**[Licensing Details](LICENSING.md)** · Contact: qsecbit@hookprobe.com

---

## Contributing

```bash
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe
make install-dev
make test
```

**[Contributing Guide](docs/CONTRIBUTING.md)** · **[GitHub Issues](https://github.com/hookprobe/hookprobe/issues)** · **[Discussions](https://github.com/hookprobe/hookprobe/discussions)**

---

## Documentation

| Topic | Link |
|-------|------|
| Installation | [Installation Guide](docs/installation/INSTALLATION.md) |
| Architecture | [System Architecture](ARCHITECTURE.md) |
| Development | [CLAUDE.md](CLAUDE.md) |
| Networking | [VPN Setup](docs/networking/VPN.md) |
| Compliance | [GDPR](docs/GDPR.md) |

---

<p align="center">
  <strong>HookProbe v5.0 "Cortex"</strong><br>
  The world's first collective defense mesh.<br>
  <em>One node's detection is everyone's protection.</em>
</p>

<p align="center">
  <a href="https://github.com/hookprobe/hookprobe">GitHub</a> ·
  <a href="docs/installation/INSTALLATION.md">Documentation</a> ·
  <a href="shared/cortex/README.md">Cortex</a> ·
  <a href="https://github.com/hookprobe/hookprobe/discussions">Community</a>
</p>
