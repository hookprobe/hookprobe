<p align="center">
  <img src="assets/hookprobe-logo.svg" alt="HookProbe Logo" width="400"/>
</p>

<h1 align="center">The Federated Network Security Platform</h1>

<p align="center">
  <strong>Affordable WiFi Security · Open-Source Firewall · Collective Defense Mesh</strong><br>
  <em>More than a firewall — it's a way of life.</em>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL%20v3.0-blue.svg" alt="License: AGPL v3.0"/></a>
  <a href="https://github.com/hookprobe/hookprobe/stargazers"><img src="https://img.shields.io/github/stars/hookprobe/hookprobe?style=social" alt="GitHub Stars"/></a>
  <a href="https://github.com/hookprobe/hookprobe/releases"><img src="https://img.shields.io/github/v/release/hookprobe/hookprobe" alt="Latest Release"/></a>
  <a href="https://github.com/hookprobe/hookprobe/actions"><img src="https://img.shields.io/github/actions/workflow/status/hookprobe/hookprobe/app-tests.yml" alt="Build Status"/></a>
</p>

<p align="center">
  <img src="assets/hookprobe-future-ram-cine.png" alt="Affordable WiFi Security Platform" width="600"/>
</p>

<p align="center">
  <strong>Off-the-Shelf Hardware · Enterprise Protection · NIS2 Compliance · Community Innovation</strong>
</p>

---

## 🎯 The Security Gap That Costs Billions

**The Reality:** The SMB security market is worth **$25 billion in 2024**, growing to **$70 billion by 2034**. Yet enterprise vendors ignore smaller customers — charging $10,000-$50,000/year for solutions that are overkill for most businesses.

**The NIS2 Mandate:** EU's NIS2 Directive now requires essential and important entities to implement cybersecurity measures. Small businesses face **mandatory compliance** with no affordable path forward.

**HookProbe Changes Everything:** Build enterprise-grade WiFi security using **off-the-shelf hardware** — a Raspberry Pi and USB WiFi adapters. Full office coverage for under $200.

| Challenge | Enterprise Vendors | HookProbe |
|-----------|-------------------|-----------|
| **Hardware** | Proprietary appliances | Raspberry Pi + USB WiFi |
| **Total Cost** | $10K-$50K/year | $75-$200 one-time |
| **Office WiFi** | Additional APs required | USB adapters = full coverage |
| **NIS2 Compliance** | Expensive add-ons | Built-in automation |
| **Threat Response** | Manual (hours) | AI-automated (<30 sec) |
| **Updates** | Vendor lock-in | Community-driven, open |
| **Defense Model** | Isolated silos | Collective mesh intelligence |

> ⭐ **Star this repo** — help bring professional security to every business, everywhere.

---

## 🚀 Quick Start — Deploy in Minutes

```bash
# One-line installation on Raspberry Pi / Mini PC
curl -fsSL https://hookprobe.com/install.sh | bash

# Or clone and run manually
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe
./install.sh --tier guardian  # Portable secure WiFi hotspot
./install.sh --tier fortress  # Full office WiFi security
```

**Off-the-Shelf Hardware — No Vendor Lock-in:**

| Product | Hardware | Cost | Best For |
|---------|----------|------|----------|
| **Guardian** | Raspberry Pi 5 + USB WiFi | ~$75 | Travel, home WiFi, portable protection |
| **Fortress** | Mini PC + USB WiFi adapters | ~$150 | Office WiFi, IoT segmentation, NIS2 compliance |
| **Nexus** | Any x86 server | Variable | Multi-site coordination, ML/AI training |

**The Innovation:** Add USB WiFi adapters for instant coverage expansion. One Raspberry Pi + 3 USB adapters = complete office WiFi security. No proprietary hardware. No recurring fees.

📖 **[Installation Guide →](docs/installation/INSTALLATION.md)** | **[Beginner's Guide →](docs/installation/BEGINNER-GUIDE.md)**

---

## 🔥 The Five Pillars of HookProbe

### 1. Collective Defense Mesh — One Detection Protects Everyone

This is what makes HookProbe **more than a firewall**. When any node detects a threat, the entire mesh learns instantly:

```
Your Office (London):    Detects ransomware C2 callback
        ↓
HookProbe Mesh:          Anonymized threat signature shared globally
        ↓
Partner Office (Berlin): Protected BEFORE attack reaches them
        ↓
Remote Worker (Paris):   Already blocking — zero-day neutralized
```

**The Power of Many:** Individual firewalls are isolated. HookProbe creates a **federated security consciousness** where collective intelligence makes everyone stronger.

### 2. Affordable WiFi Security — Off-the-Shelf Innovation

**The Hardware Revolution:**
- Raspberry Pi 5 ($60) + USB WiFi adapter ($15) = enterprise-grade security
- Add more USB adapters for instant coverage expansion
- One Pi + 3 adapters = full office WiFi with segmentation
- No proprietary appliances. No recurring fees. No vendor lock-in.

### 3. AI-Powered Detection & Prevention (Qsecbit)

Real-time threat scoring with automated response:

| Score | Status | Action |
|-------|--------|--------|
| < 0.45 | 🟢 GREEN | Normal operations, learning baseline |
| 0.45-0.70 | 🟡 AMBER | Auto-mitigation triggered |
| > 0.70 | 🔴 RED | Full defense activated |

**Detection + Prevention:** L2-L7 threat analysis, behavioral anomaly detection, and automated response in under 30 seconds.

### 4. NIS2 Compliance Built-In

EU's NIS2 Directive compliance out of the box — **mandatory** for essential and important entities:

```
✓ Automated incident reporting (Article 23)
✓ Risk management measures (Article 21)
✓ Supply chain security assessment
✓ Continuous monitoring and logging
✓ Compliance reports ready for auditors
```

### 5. Smart Network Segmentation

Automatic IoT isolation prevents lateral movement attacks:

```
┌──────────────────────────────────────────────────────┐
│            Single WiFi: "Office-Network"             │
│                         ↓                            │
│    ┌───────────────────────────────────────┐         │
│    │     HookProbe Fortress (Mini PC)      │         │
│    └─────┬───────┬───────┬───────┬─────────┘         │
│          │       │       │       │                   │
│   VLAN 10│ VLAN 20│ VLAN 30│ VLAN 99                 │
│   Trusted│  IoT   │ Guest  │ Quarantine              │
│    💻 📱 │  📷 💡 │  📱   │   ❓                     │
│          │        │        │                         │
│   ✗ IoT devices CANNOT access trusted network        │
│   ✗ Compromised camera CANNOT spread laterally       │
└──────────────────────────────────────────────────────┘
```

### Bonus: DNS Protection (dnsXai)

AI-powered DNS filtering blocks at the source:
- Ads and trackers (130K+ domains)
- Malware command & control
- Phishing domains
- Data exfiltration tunnels

---

## 🏗️ Architecture — Open Source Collaboration

HookProbe is built on **open collaboration** principles. Core components are AGPL-licensed, ensuring contributions benefit everyone.

```
hookprobe/
├── core/                    # 🧠 Core Intelligence
│   ├── htp/                 # Transport Protocol (AGPL)
│   ├── qsecbit/             # AI Threat Scoring
│   └── neuro/               # Neural Authentication
│
├── shared/                  # 🔧 Shared Innovation
│   ├── dnsXai/              # AI DNS Protection
│   ├── mesh/                # Collective Defense Network
│   ├── network/             # Network Segmentation
│   └── response/            # Automated Response (AGPL)
│
├── products/                # 📦 Distribution Tiers
│   ├── guardian/            # Travel Firewall (AGPL)
│   ├── fortress/            # Business Firewall
│   ├── nexus/               # ML Coordination
│   └── mssp/                # Managed Service Provider
│
└── deploy/                  # 🚀 Easy Deployment (AGPL)
```

📖 **[Full Architecture →](ARCHITECTURE.md)** | **[Mesh Documentation →](shared/mesh/ARCHITECTURE.md)**

---

## 💼 Who Uses HookProbe

### 🏠 Home & Power Users

**Use Cases:** Secure home WiFi, NAS protection, ad-blocking, privacy

**Deploy Guardian** on Raspberry Pi:
- ✅ Whole-home ad and tracker blocking
- ✅ Secure remote access to your NAS
- ✅ Protect all devices automatically
- ✅ VPN for secure browsing anywhere
- **Cost:** ~$75 one-time

### 🏢 Small Business (5-50 employees)

**Challenge:** Need enterprise security but can't afford $50K/year solutions.

**Deploy Fortress** on Mini PC + USB WiFi:
- ✅ Full office WiFi from one device
- ✅ NIS2 compliance automation
- ✅ IoT device isolation
- ✅ VPN for remote workers
- ✅ AI threat detection
- **Cost:** ~$150 one-time, zero ongoing fees

**ROI:** 99% cost savings vs. enterprise solutions.

### 🧳 Remote & Traveling Workers

**Challenge:** Hotel WiFi, coffee shops, airports — all hostile networks.

**Deploy Guardian** — your portable security shield:
- ✅ Carry-on sized secure WiFi hotspot
- ✅ Connect to hostile networks safely
- ✅ DNS-level threat blocking
- ✅ VPN tunnel back to home/office
- **Cost:** ~$75 fits in your bag

### 🏗️ Managed Service Providers (MSPs/MSSPs)

**Opportunity:** The $25B SMB security market is underserved.

**Deploy HookProbe** at client sites:
- ✅ Multi-tenant management dashboard
- ✅ Cross-client collective threat intelligence
- ✅ White-label capabilities
- ✅ Offer $50/month vs. $500/month competitors
- **Margin:** 10x better than enterprise resale

---

## 🌍 Community & Collaboration

HookProbe is a **collaborative, community-driven project**. We believe security should be accessible to everyone.

### How to Contribute

```bash
# Fork, clone, and contribute
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe
make install-dev
make test

# Submit pull request
```

### Community Resources

| Resource | Link |
|----------|------|
| 📖 Documentation | [docs/](docs/) |
| 🐛 Issues | [GitHub Issues](https://github.com/hookprobe/hookprobe/issues) |
| 💬 Discussions | [GitHub Discussions](https://github.com/hookprobe/hookprobe/discussions) |
| 📧 Security Issues | qsecbit@hookprobe.com |

### Contributors Welcome

- 🔧 **Developers:** Core features, bug fixes, integrations
- 📝 **Technical Writers:** Documentation, tutorials
- 🌐 **Translators:** Localization
- 🧪 **Testers:** Edge cases, hardware compatibility
- 💡 **Ideas:** Feature requests, use cases

📖 **[Contributing Guide →](docs/CONTRIBUTING.md)**

---

## 📊 The Federated Neuro-Resonant Security Mesh

> **More than a firewall. A living, learning, collective defense consciousness.**

### What Makes HookProbe Different

Traditional security is **reactive and isolated**. HookProbe is **proactive and collective**:

| Traditional | HookProbe |
|-------------|-----------|
| Static firewall rules | AI-evolving threat patterns |
| Isolated silos | Federated mesh intelligence |
| Reactive alerts | Predictive prevention |
| Hardware lock-in | Off-the-shelf components |
| Vendor dependencies | Community-driven innovation |

### The Four Pillars of Innovation

| Pillar | Technology | Why It Matters |
|--------|------------|----------------|
| **Neural Resonance** | Living cryptography | Keys evolve from device behavior — impossible to steal |
| **HTP Protocol** | Quantum-resistant transport | Survives DDoS, traverses NAT, future-proof |
| **Qsecbit Engine** | AI resilience scoring | Real-time threat detection with 30-second response |
| **Collective Mesh** | Federated defense | One node's detection → everyone's protection |

### Technical Depth

- **XDP/eBPF:** Kernel-level packet filtering (sub-microsecond decisions)
- **Post-Quantum Ready:** Kyber KEM hybrid encryption (NIST standard)
- **Energy Efficient:** 60-80% power savings vs. traditional appliances
- **Privacy-First:** Threat intelligence shared without exposing raw data

📖 **[Qsecbit Algorithm →](core/qsecbit/README.md)** | **[HTP Protocol →](docs/HTP_SECURITY_ENHANCEMENTS.md)**

---

## 📋 Documentation

### For Business Users

| Document | Description |
|----------|-------------|
| **[Quick Start](QUICK-START.md)** | Get running in 10 minutes |
| **[Beginner's Guide](docs/installation/BEGINNER-GUIDE.md)** | Step-by-step for non-technical users |
| **[Guardian Setup](products/guardian/README.md)** | Travel WiFi firewall |
| **[Fortress Setup](products/fortress/README.md)** | Small business firewall |
| **[VPN Access](docs/networking/VPN.md)** | Remote access setup |

### For Developers

| Document | Description |
|----------|-------------|
| **[Architecture](ARCHITECTURE.md)** | System design overview |
| **[CLAUDE.md](CLAUDE.md)** | AI assistant development guide |
| **[Mesh Architecture](shared/mesh/ARCHITECTURE.md)** | P2P communication |
| **[dnsXai](shared/dnsXai/README.md)** | DNS protection module |
| **[Contributing](docs/CONTRIBUTING.md)** | How to contribute |

### For Compliance

| Document | Description |
|----------|-------------|
| **[GDPR Compliance](docs/GDPR.md)** | Data protection |
| **[Security Policy](docs/SECURITY.md)** | Vulnerability reporting |
| **[Licensing](LICENSING.md)** | Dual license details |

---

## 📜 Licensing — Open Source with Innovation Protection

HookProbe uses a **dual licensing model** balancing open collaboration with sustainable development.

### Open Source (AGPL v3.0)

| Component | Status |
|-----------|--------|
| Deployment scripts | ✅ Fully Open |
| Guardian product | ✅ Fully Open |
| Mesh communication | ✅ Fully Open |
| Threat response | ✅ Fully Open |
| Documentation | ✅ Fully Open |

### Innovation Protection (Commercial License for SaaS/OEM)

| Innovation | Requires License For |
|------------|---------------------|
| Qsecbit AI Algorithm | SaaS/OEM use |
| Neural Resonance Protocol | SaaS/OEM use |
| dnsXai ML Classifier | SaaS/OEM use |
| MSSP Cloud Platform | SaaS/OEM use |

**Free for:**
- ✅ Personal/home use
- ✅ Internal business protection
- ✅ Non-commercial research

**Commercial license required for:**
- MSSP/SaaS offerings
- OEM product embedding
- White-label distribution

📖 **[Full Licensing Details →](LICENSING.md)** | Contact: qsecbit@hookprobe.com

---

## 🤝 Join the Movement

**Security shouldn't be a luxury. It should be a way of life.**

We're building something bigger than a firewall — a **federated security consciousness** where every home, every business, every traveler contributes to collective protection.

### Get Started Today

```bash
# One command. Off-the-shelf hardware. Enterprise security.
curl -fsSL https://hookprobe.com/install.sh | bash
```

### Be Part of the Mesh

- ⭐ **Star this repo** — Every star helps spread affordable security
- 🍴 **Fork and contribute** — Your code protects thousands
- 📢 **Share** — Tell others about the security gap we're closing
- 💬 **Discuss** — Shape the future of collective defense

---

<p align="center">
  <strong>HookProbe v5.0 "Liberty"</strong><br>
  <em>The Federated Neuro-Resonant Decentralized Security Mesh</em><br>
  <strong>More than a firewall — it's a way of life.</strong>
</p>

<p align="center">
  <a href="https://github.com/hookprobe/hookprobe">⭐ Star on GitHub</a> ·
  <a href="docs/installation/INSTALLATION.md">📖 Documentation</a> ·
  <a href="https://github.com/hookprobe/hookprobe/discussions">💬 Discussions</a>
</p>

<p align="center">
  <sub>Built by the community, for the community. One node's detection → Everyone's protection.</sub>
</p>
