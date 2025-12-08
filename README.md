<p align="center">
  <img src="assets/hookprobe-logo.svg" alt="HookProbe Logo" width="400"/>
</p>

<h1 align="center">Open-Source Network Security Firewall</h1>

<p align="center">
  <strong>Enterprise Firewall for Small Business · NIS2 Compliance Ready · Collective Defense</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL%20v3.0-blue.svg" alt="License: AGPL v3.0"/></a>
  <a href="https://github.com/hookprobe/hookprobe/stargazers"><img src="https://img.shields.io/github/stars/hookprobe/hookprobe?style=social" alt="GitHub Stars"/></a>
  <a href="https://github.com/hookprobe/hookprobe/releases"><img src="https://img.shields.io/github/v/release/hookprobe/hookprobe" alt="Latest Release"/></a>
  <a href="https://github.com/hookprobe/hookprobe/actions"><img src="https://img.shields.io/github/actions/workflow/status/hookprobe/hookprobe/app-tests.yml" alt="Build Status"/></a>
</p>

<p align="center">
  <img src="assets/hookprobe-future-ram-cine.png" alt="Open Source Firewall for Small Business" width="600"/>
</p>

<p align="center">
  <strong>$75-$150 Hardware · Enterprise-Grade Protection · Community-Driven Innovation</strong>
</p>

---

## 🎯 Why Small Businesses Choose HookProbe

**The Problem:** Traditional firewalls cost $10,000-$50,000/year. Small businesses are left unprotected while facing the same threats as enterprises. **NIS2 compliance** requirements add more pressure with no affordable solutions.

**HookProbe Solution:** Deploy enterprise-grade **open-source network security** on a $150 Raspberry Pi or Mini PC. Get the same protection that Fortune 500 companies pay $400K+/year for.

| Challenge | Traditional Firewall | HookProbe |
|-----------|---------------------|-----------|
| **Cost** | $10K-$50K/year | $150 one-time |
| **NIS2 Compliance** | Complex, expensive | Built-in automation |
| **Threat Response** | Manual (hours) | AI-automated (<30 sec) |
| **Updates** | Vendor-dependent | Community-driven |
| **Collective Defense** | Isolated | Shared threat intelligence |

> ⭐ **Star this repo** to support open-source network security for everyone!

---

## 🚀 Quick Start — Firewall for Small Business

```bash
# One-line installation on Raspberry Pi / Mini PC
curl -fsSL https://hookprobe.com/install.sh | bash

# Or clone and run manually
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe
./install.sh --tier guardian  # For travel/portable WiFi
./install.sh --tier fortress  # For office network (IoT segmentation)
```

**Hardware Requirements:**

| Product | Hardware | RAM | Best For |
|---------|----------|-----|----------|
| **Guardian** | Raspberry Pi 5 | 1.5GB+ | Travel WiFi hotspot, portable protection |
| **Fortress** | Mini PC (N100/N5105) | 4GB+ | **Small business firewall**, IoT segmentation, NIS2 |
| **Nexus** | Server | 16GB+ | Multi-site coordination, ML training |

📖 **[Installation Guide →](docs/installation/INSTALLATION.md)** | **[Beginner's Guide →](docs/installation/BEGINNER-GUIDE.md)**

---

## 🔥 Key Features for Business Networks

### 1. NIS2 Compliance Automation

**EU NIS2 Directive compliance** out of the box — required for essential and important entities by October 2024.

```
✓ Automated incident reporting (Article 23)
✓ Risk management measures (Article 21)
✓ Supply chain security assessment
✓ Continuous monitoring and logging
✓ Compliance reports for auditors
```

### 2. AI-Powered Threat Detection (Qsecbit)

Real-time threat scoring with automated response:

| Score | Status | Action |
|-------|--------|--------|
| < 0.45 | 🟢 GREEN | Normal operations |
| 0.45-0.70 | 🟡 AMBER | Auto-mitigation triggered |
| > 0.70 | 🔴 RED | Full defense activated |

### 3. Collective Defense Network

**One business's detection → Everyone's protection**

When any HookProbe node detects a new threat, the entire network learns instantly:

```
Business A (London):     Detects ransomware C2 callback
        ↓
HookProbe Mesh:          Shares anonymized threat signature
        ↓
Business B (Berlin):     Protected BEFORE attack reaches them
        ↓
Business C (Paris):      Automatically blocking
```

### 4. IoT Network Segmentation

**Fortress** automatically isolates IoT devices to prevent lateral movement:

```
┌─────────────────────────────────────────────────────┐
│           Single WiFi: "Office-Network"              │
│                        ↓                             │
│    ┌──────────────────────────────────────┐         │
│    │         Fortress Firewall            │         │
│    └──────────┬───────┬───────┬───────────┘         │
│               │       │       │                      │
│    VLAN 10    │ VLAN 20│ VLAN 30 │ VLAN 99           │
│    Trusted    │  IoT   │ Guest  │ Quarantine         │
│    💻 📱      │ 📷 💡  │  📱    │   ❓               │
│               │        │        │                    │
│  ✗ IoT devices CANNOT access trusted network        │
│  ✗ Compromised camera CANNOT spread to file server  │
└─────────────────────────────────────────────────────┘
```

### 5. DNS Protection (dnsXai)

AI-powered DNS filtering blocks:
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

## 💼 Business Use Cases

### Small Business (5-50 employees)

**Challenge:** Need enterprise security but can't afford $50K/year solutions.

**Solution:** Deploy Fortress on a $150 Mini PC:
- ✅ NIS2 compliance automation
- ✅ IoT device isolation
- ✅ VPN for remote workers
- ✅ AI threat detection
- ✅ Zero ongoing license fees

**ROI:** 99% cost savings vs. traditional enterprise firewalls.

### Remote/Hybrid Workforce

**Challenge:** Employees working from hotels, coffee shops, airports.

**Solution:** Deploy Guardian on Raspberry Pi:
- ✅ Portable secure WiFi hotspot
- ✅ L2-L7 threat detection
- ✅ DNS-level ad/malware blocking
- ✅ VPN back to office network

### Managed Service Providers (MSPs/MSSPs)

**Challenge:** Need affordable solution to protect SMB clients.

**Solution:** Deploy edge nodes at client sites:
- ✅ Multi-tenant management dashboard
- ✅ Cross-client threat intelligence
- ✅ White-label capabilities
- ✅ Offer $50/month vs. $500/month traditional

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

## 📊 Groundbreaking Innovation

### The Four Pillars

| Pillar | Innovation | What It Does |
|--------|------------|--------------|
| **Neural Resonance** | Living cryptography | No static keys — neural weights evolve continuously |
| **HTP Protocol** | Quantum-resistant transport | Survives DDoS, traverses NAT, post-quantum ready |
| **Qsecbit Engine** | AI resilience metrics | Real-time threat scoring with energy monitoring |
| **Collective Defense** | Federated mesh | One detection → global protection |

### Technical Highlights

- **XDP/eBPF Filtering:** Kernel-level packet decisions (sub-microsecond)
- **Post-Quantum Cryptography:** Kyber KEM hybrid encryption
- **Energy-Aware:** 60-80% power savings vs. traditional firewalls
- **Privacy-Preserving:** Threat intelligence shared without exposing raw data

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

**We're building the future of open-source network security.**

Small businesses shouldn't choose between security and budget. With HookProbe, they don't have to.

### Get Started Today

```bash
# Install on your Raspberry Pi or Mini PC
curl -fsSL https://hookprobe.com/install.sh | bash
```

### Support the Project

- ⭐ **Star this repo** — Help others discover open-source firewalls
- 🍴 **Fork and contribute** — Every improvement helps everyone
- 📢 **Share** — Tell other small businesses about affordable security
- 💬 **Discuss** — Join our community discussions

---

<p align="center">
  <strong>HookProbe v5.0 "Liberty"</strong><br>
  <em>Open Source · Collective Defense · Enterprise Security for Everyone</em>
</p>

<p align="center">
  <a href="https://github.com/hookprobe/hookprobe">⭐ Star on GitHub</a> ·
  <a href="docs/installation/INSTALLATION.md">📖 Documentation</a> ·
  <a href="https://github.com/hookprobe/hookprobe/discussions">💬 Discussions</a>
</p>

<p align="center">
  <sub>Built with ❤️ by the HookProbe community. One node's detection → Everyone's protection.</sub>
</p>
