<p align="center">
  <img src="assets/hookprobe-logo.svg" alt="HookProbe Logo" width="400"/>
</p>

<h1 align="center">The World's First Collective Defense Mesh</h1>

<p align="center">
  <strong>One node's detection is everyone's protection.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL%20v3.0-blue.svg" alt="License: AGPL v3.0"/></a>
  <a href="https://github.com/hookprobe/hookprobe/stargazers"><img src="https://img.shields.io/github/stars/hookprobe/hookprobe?style=social" alt="GitHub Stars"/></a>
  <a href="https://github.com/hookprobe/hookprobe/releases"><img src="https://img.shields.io/github/v/release/hookprobe/hookprobe" alt="Latest Release"/></a>
  <a href="https://github.com/hookprobe/hookprobe/actions"><img src="https://img.shields.io/github/actions/workflow/status/hookprobe/hookprobe/app-tests.yml" alt="Build Status"/></a>
</p>

<p align="center">
  <em>Post-quantum cryptography. AI-powered threat detection. Zero-trust mesh networking.</em>
</p>

---

## What is HookProbe?

HookProbe is the world's first **federated cybersecurity mesh** - a living network where every node protects every other node. No security analysts required. No threat hunters. No SOC team. Just intelligent software that turns the chaos of modern network threats into collective strength.

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

**[Cortex Documentation](visualization/globe/README.md)** · **[Architecture](visualization/globe/ARCHITECTURE.md)**

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
│   └── response/            # Automated Threat Response
│
├── products/                # Deployment Tiers
│   ├── guardian/            # Home / Prosumer (1.5GB)
│   ├── fortress/            # Business (4GB)
│   ├── nexus/               # ML Coordination (16GB+)
│   └── mssp/                # Cloud Platform
│
├── visualization/           # HookProbe Cortex
│   └── globe/               # 3D Neural Command Center
│
└── deploy/                  # Deployment Scripts
```

**[Full Architecture](ARCHITECTURE.md)** · **[Mesh Design](shared/mesh/ARCHITECTURE.md)** · **[Cortex](visualization/globe/README.md)**

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
  <strong>HookProbe v5.1 "Cortex"</strong><br>
  The world's first collective defense mesh.<br>
  <em>One node's detection is everyone's protection.</em>
</p>

<p align="center">
  <a href="https://github.com/hookprobe/hookprobe">GitHub</a> ·
  <a href="docs/installation/INSTALLATION.md">Documentation</a> ·
  <a href="visualization/globe/README.md">Cortex</a> ·
  <a href="https://github.com/hookprobe/hookprobe/discussions">Community</a>
</p>
