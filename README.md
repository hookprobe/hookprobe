<p align="center">
  <img src="assets/hookprobe-logo.svg" alt="HookProbe Logo" width="400"/>
</p>

<h1 align="center">Transparent Security That Empowers Everyone</h1>

<p align="center">
  <strong>See everything. Own your protection. Achieve more.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-5.0_Cortex-00e5ff?style=flat-square" alt="Version 5.0 Cortex"/>
  <img src="https://img.shields.io/badge/License-AGPL_v3.0_+_Commercial-blue?style=flat-square" alt="Dual License"/>
  <img src="https://img.shields.io/badge/Python-3.9+-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python 3.9+"/>
  <img src="https://img.shields.io/badge/Platform-Linux-FCC624?style=flat-square&logo=linux&logoColor=black" alt="Linux"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Open_Source-Auditable_Code-00ff88?style=flat-square" alt="Open Source"/>
  <img src="https://img.shields.io/badge/Privacy-Data_Never_Leaves_Edge-ff6b6b?style=flat-square" alt="Privacy First"/>
  <img src="https://img.shields.io/badge/Collective-Mesh_Intelligence-ffaa00?style=flat-square" alt="Collective Defense"/>
</p>

---

## The HookProbe Promise

**Transparency creates trust. Trust enables achievement.**

HookProbe is built on a simple belief: security technology should empower people, not create dependency. When you can see exactly how your protection works, audit every line of code, and understand every decision the system makes, you're free to focus on what matters - building, creating, and achieving more.

We reject the security industry's black-box approach. Our code is open. Our algorithms are documented. Our data handling is verifiable. When one HookProbe node anywhere in the world detects a threat, every node learns instantly - without anyone's private data ever leaving their control.

**This is security that works *for* you, not security that works *on* you.**

---

## Why Transparency Matters

| Black-Box Security | HookProbe (Transparent) |
|-------------------|-------------------------|
| "Trust us, we're protecting you" | Audit the code yourself |
| Your data sent to vendor clouds | Your data never leaves your edge |
| Opaque threat scoring | See exactly why decisions are made |
| Vendor lock-in | Open standards, your choice |
| Security creates dependency | Security enables independence |
| Complex interfaces hide complexity | Simple interfaces, documented complexity |

**The difference:** Black boxes ask for trust. Transparency earns it.

---

## How HookProbe Helps You Achieve More

### 1. Reclaim Your Time

Traditional security demands constant attention - alerts to investigate, logs to review, updates to manage. HookProbe handles this automatically so you can focus on your actual work.

- **Automated threat response** - No manual investigation needed
- **Self-learning baselines** - Adapts to your environment
- **Collective intelligence** - Benefits from global threat detection without effort

### 2. Protect Without Complexity

Enterprise security typically requires dedicated teams. HookProbe brings the same protection to anyone, regardless of technical background.

```bash
# That's it. You're protected.
./install.sh --tier guardian
```

### 3. Scale Without Cost

From a single Raspberry Pi to a global mesh of thousands of nodes - same technology, same transparency, scaling to your needs.

| Your Situation | Solution | Investment |
|----------------|----------|------------|
| Home network | Guardian | $75 hardware, $0 software |
| Small business | Fortress | $200 hardware, $0 software |
| Growing company | Nexus | $2000 hardware, $0 software |
| Enterprise/MSSP | Custom | Contact us |

### 4. Own Your Security Data

Every security decision, every threat detection, every response action - it's all yours. Export it. Analyze it. Verify it. No vendor has access unless you grant it.

---

## The Collective Defense Mesh

HookProbe's most powerful feature isn't code - it's community.

```
Node A (Singapore)     Detects zero-day attack
        │
        ▼
Mesh Intelligence      Validates pattern, creates signature
        │
        ├──────────────────────────────────────┐
        ▼                                      ▼
Node B (London)        Node C (New York)       Node D (Berlin)
Protected in <30s      Protected in <30s        Protected in <30s
```

**How it works:**
1. **Detection** - Any node detects a new threat pattern
2. **Validation** - Mesh consensus confirms it's legitimate
3. **Distribution** - Anonymized signature shared instantly
4. **Protection** - All nodes block the threat

**What we never share:**
- Your raw traffic data
- Your IP addresses
- Your internal network details
- Any personally identifiable information

**What we share:**
- Anonymized threat signatures
- Attack patterns (source removed)
- Model weight updates (federated learning)

This is collective defense that respects individual privacy.

---

## Technical Foundation (Fully Documented)

Every component is documented. Every algorithm is explained. Nothing is hidden.

### Qsecbit Engine - Transparent Threat Scoring

Traditional security: "This is bad" (trust us)
HookProbe: "This scores 0.72 because drift=0.25, attack_probability=0.85, decay=0.12"

```python
# The actual formula - no secrets
Qsecbit = α·drift + β·p_attack + γ·decay + δ·q_drift + ε·energy_anomaly

# You can verify every calculation
# See: core/qsecbit/qsecbit.py
```

| Score | Status | What Happens | Why |
|-------|--------|--------------|-----|
| < 0.45 | GREEN | Learning mode | System behavior normal |
| 0.45-0.70 | AMBER | Mitigation starts | Anomalies detected, investigating |
| > 0.70 | RED | Full defense | Confirmed threat, blocking |

### dnsXai - Explainable DNS Protection

Not just "blocked" - but *why* it was blocked:

```
Domain: suspicious-tracker.com
Decision: BLOCKED
Confidence: 92%
Reason: High entropy (4.2), matches tracking pattern, CNAME resolves to known tracker
Category: ADVERTISING_TRACKER
```

Every block is explainable. Every decision is auditable.

### HTP Protocol - Verifiable Security

Post-quantum cryptography you can inspect:
- **Kyber KEM** - NIST-approved, implementation viewable
- **ChaCha20-Poly1305** - Standard authenticated encryption
- **Entropy-based authentication** - Novel but documented

### XDP/eBPF - Kernel-Level, User-Auditable

DDoS mitigation at the kernel level, but you can see exactly what rules are applied:

```bash
# View active XDP rules
./hookprobe-ctl xdp show

# Understand every decision
./hookprobe-ctl xdp explain --ip 192.168.1.100
```

---

## Who Benefits from HookProbe

### Home Users & Prosumers

**Achieve:** Secure home network without becoming a security expert
**Transparency benefit:** Know exactly what's being blocked and why
**Time saved:** Set and forget - system learns your patterns

### Small & Medium Businesses

**Achieve:** Enterprise-grade protection without enterprise costs
**Transparency benefit:** Audit-ready logs, explainable decisions
**Time saved:** No dedicated security team needed

### Developers & Technical Users

**Achieve:** Security that integrates with your workflow
**Transparency benefit:** Full API access, source code available
**Time saved:** Automated responses, scriptable interfaces

### Managed Service Providers

**Achieve:** Offer premium security services at scale
**Transparency benefit:** Show clients exactly how they're protected
**Time saved:** Centralized management, automated operations

---

## HookProbe Cortex - See Your Mesh

Transparency isn't just about code - it's about visibility.

Cortex is a real-time 3D visualization of your entire defense network. Watch threats arrive from across the world and see them blocked in real-time.

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

**Not a dashboard about your security. A window into your security.**

[Cortex Documentation](shared/cortex/README.md)

---

## Quick Start

```bash
# Clone
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe

# Deploy (choose your tier)
./install.sh --tier guardian   # Home/prosumer (1.5GB RAM)
./install.sh --tier fortress   # Business (4GB RAM)
./install.sh --tier nexus      # Multi-site (16GB+ RAM)
```

**Time to protection:** ~5 minutes
**Ongoing maintenance:** Automatic

[Full Installation Guide](docs/installation/INSTALLATION.md)

---

## Our Commitment to Transparency

### Open Source Foundation

The majority of HookProbe is open source under AGPL v3.0:
- Deployment scripts and configuration
- Guardian product tier
- Mesh communication layer
- Threat response modules
- All documentation
- Cortex visualization

### Documented Innovations

Our proprietary components (Qsecbit algorithm, Neural Resonance protocol, dnsXai classifier) are clearly documented. You can understand *what* they do and *why* - the implementation is protected, but the purpose is transparent.

### Privacy by Architecture

We didn't add privacy as an afterthought. The architecture ensures:
- Raw data never leaves your edge
- Only anonymized signatures are shared
- You control what participates in the mesh
- Compliance (GDPR, NIS2) is built-in

### Community-Driven Development

- Public roadmap
- Open issue tracking
- Community contributions welcome
- Regular security audits

[Licensing Details](LICENSING.md) | [Contributing Guide](docs/CONTRIBUTING.md)

---

## Architecture Overview

```
hookprobe/
├── core/                    # Core Intelligence (documented)
│   ├── htp/                 # Transport Protocol (open source)
│   ├── qsecbit/             # AI Threat Scoring (documented, proprietary)
│   └── neuro/               # Neural Authentication (documented, proprietary)
│
├── shared/                  # Shared Modules
│   ├── dnsXai/              # AI DNS Protection (documented, proprietary)
│   ├── mesh/                # Collective Defense (open source)
│   ├── dsm/                 # Decentralized Security (documented, proprietary)
│   ├── response/            # Automated Response (open source)
│   └── cortex/              # 3D Visualization (open source)
│
├── products/                # Deployment Tiers (mostly open source)
│   ├── guardian/            # Home/Prosumer
│   ├── fortress/            # Business
│   ├── nexus/               # Enterprise
│   └── mssp/                # Service Provider (proprietary)
│
└── deploy/                  # Deployment Scripts (open source)
```

Every directory has documentation. Every module has a README.

---

## Resources

| Resource | Description |
|----------|-------------|
| [Installation Guide](docs/installation/INSTALLATION.md) | Get started in 5 minutes |
| [Architecture Overview](docs/architecture/HOOKPROBE-ARCHITECTURE.md) | Understand the system |
| [Qsecbit Documentation](core/qsecbit/README.md) | How threat scoring works |
| [Mesh Architecture](shared/mesh/ARCHITECTURE.md) | Collective defense explained |
| [Cortex Visualization](shared/cortex/README.md) | See your security |
| [API Reference](docs/components/README.md) | Integrate and extend |
| [GDPR Compliance](docs/GDPR.md) | Privacy documentation |
| [Security Policy](docs/SECURITY.md) | Report vulnerabilities |

---

## The HookProbe Difference

**We don't ask you to trust us. We give you the tools to verify.**

- Every threat decision is explainable
- Every line of defense code is auditable
- Every piece of your data stays under your control
- Every node in the mesh strengthens everyone

**This is what security looks like when transparency comes first.**

---

<p align="center">
  <strong>HookProbe v5.0 "Cortex"</strong><br>
  Transparent Security That Empowers Everyone<br>
  <em>See everything. Own your protection. Achieve more.</em>
</p>

<p align="center">
  <a href="https://github.com/hookprobe/hookprobe">GitHub</a> ·
  <a href="docs/installation/INSTALLATION.md">Get Started</a> ·
  <a href="shared/cortex/README.md">See Cortex</a> ·
  <a href="https://github.com/hookprobe/hookprobe/discussions">Community</a>
</p>
