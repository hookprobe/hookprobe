# HookProbe Documentation Index

<p align="center">
  <strong>Collective Intelligence for Network Security</strong><br>
  <em>One node's detection is everyone's protection.</em>
</p>

---

**Documentation for HookProbe v5.7**

HookProbe is advanced network security software that operates without the complexity. This index provides navigation to all documentation organized by topic and audience.

---

## 🚀 Getting Started

### For Complete Beginners
- **[Beginner's Guide](installation/BEGINNER-GUIDE.md)** ⭐ **START HERE if new to Linux**
- **[Quick Start Guide](../QUICK-START.md)** - 3-step installation
- **[Main README](../README.md)** - Project overview and features

### Installation Guides
- **[Edge Deployment](installation/INSTALLATION.md)** - Single-tenant setup (Raspberry Pi, Mini PC)
- **[Cloud Deployment](installation/cloud-deployment.md)** - Cloud backend setup
- **[Edge Deployment Checklist](../deploy/edge/checklist.md)** - Pre/post deployment tasks

---

## 🏗️ Architecture & Design

### Core Architecture
- **[Full Architecture](../ARCHITECTURE.md)** - Complete system design
- **[Mesh Architecture](../shared/mesh/ARCHITECTURE.md)** ⭐ **Collective defense network**
- **[Qsecbit Algorithm](../core/qsecbit/README.md)** - AI threat detection
- **[dnsXai DNS Protection](../shared/dnsXai/README.md)** - AI-powered DNS filtering
- **[AIOCHI (AI Eyes)](../shared/aiochi/README.md)** ⭐ **Cognitive network layer - human-readable narratives**
- **[SLA AI Business Continuity](../shared/slaai/ARCHITECTURE.md)** - Intelligent WAN failover

### Protocol Documentation
- **[HTP Protocol](HTP_SECURITY_ENHANCEMENTS.md)** - Transport protocol
- **[HTP Quantum Cryptography](HTP_QUANTUM_CRYPTOGRAPHY.md)** - Post-quantum design
- **[HTP Keyless Analysis](HTP_KEYLESS_PROTOCOL_ANALYSIS.md)** - Keyless authentication

---

## 📦 Product Documentation

### Edge Products (AGPL v3.0 - Open Source)

| Product | Use Case | Documentation |
|---------|----------|---------------|
| **Guardian** | Travel WiFi firewall (Raspberry Pi) | [Setup Guide](../products/guardian/README.md) |
| **Fortress** | Small business firewall (Mini PC) | [Setup Guide](../products/fortress/README.md) |
| **Sentinel** | Edge validator (IoT) | [Setup Guide](../products/sentinel/README.md) |
| **Nexus** | ML/AI coordination (Server) | [Setup Guide](../products/nexus/README.md) |

### Cloud Products (Commercial License)

| Product | Use Case | Documentation |
|---------|----------|---------------|
| **MSSP** | Managed security provider platform | See [hookprobe-com](https://github.com/hookprobe/hookprobe-com) repository |

---

## 🌐 Networking & Remote Access

### VPN Remote Access
- **[VPN Overview](networking/VPN.md)** ⭐ **Access your network from anywhere**
  - IKEv2 native VPN for iOS/Android/Windows/macOS
  - Works behind NAT/CGNAT without port forwarding
  - Certificate-based authentication

### SDN & IoT Segmentation
- **[SDN Overview](networking/SDN.md)** ⭐ **Plug-and-play network segmentation**
  - MAC-based VLAN assignment
  - Automatic device categorization
  - Quarantine for unknown devices

---

## 🛡️ Security Features

### Threat Detection
- **[Qsecbit Algorithm](../core/qsecbit/README.md)** - AI resilience scoring
- **[Layer Threat Detection](../core/threat_detection/)** - L2-L7 detection
- **[Automated Response](../shared/response/README.md)** - Threat mitigation

### Network Security
- **Network Segmentation** - VLAN isolation (see Guardian/Fortress setup guides)
- **SDN Controller** - OpenFlow management (see Fortress SDN module)
- **[Mesh Architecture](../shared/mesh/ARCHITECTURE.md)** - Collective defense network

### DNS Protection
- **[dnsXai Overview](../shared/dnsXai/README.md)** - AI DNS filtering
- 130K+ blocked domains
- CNAME uncloaking
- Federated learning

---

## 📊 Compliance & Privacy

### NIS2 Compliance
HookProbe provides built-in support for EU NIS2 Directive requirements:
- Automated incident reporting (Article 23)
- Risk management measures (Article 21)
- Supply chain security assessment
- Continuous monitoring and logging

### GDPR Compliance
- **[GDPR Guide](GDPR.md)** ⭐ **Complete GDPR documentation**
  - Privacy by design implementation
  - Data subject rights procedures
  - Breach notification process
  - Retention automation

---

## 🔧 Configuration & Operations

### Deployment
- **[Edge Deployment](../deploy/edge/README.md)** - Single-site deployment
- **[Cloud Deployment](../deploy/cloud/README.md)** - Multi-tenant backend
- **[Addon: n8n Automation](../deploy/addons/n8n/README.md)** - Workflow automation
- **[Addon: Web Server](../deploy/addons/webserver/README.md)** - Web hosting

### Infrastructure
- **[Email System](../infrastructure/pod-009-email/README.md)** - Email server setup
- **[DSM Infrastructure](../infrastructure/pod-010-dsm/README.md)** - Mesh infrastructure

---

## 🤝 Development & Contributing

### Contributing
- **[Contributing Guide](CONTRIBUTING.md)** - How to contribute
- **[Security Policy](SECURITY.md)** - Vulnerability reporting
- **[CI/CD Documentation](CI-CD.md)** - Build and test workflows

### Development Guide
- **[CLAUDE.md](../CLAUDE.md)** ⭐ **AI assistant development guide**
- **[Core Modules](../core/README.md)** - Core intelligence
- **[Shared Modules](../shared/README.md)** - Shared infrastructure

---

## 📜 Licensing

HookProbe uses a **dual licensing model**:

### Open Source (AGPL v3.0)
| Component | Location |
|-----------|----------|
| Deployment scripts | `deploy/` |
| Guardian product | `products/guardian/` |
| Mesh communication | `shared/mesh/` |
| Threat response | `shared/response/` |
| Documentation | `docs/` |

### Proprietary (Commercial License for SaaS/OEM)
| Innovation | Location |
|------------|----------|
| Qsecbit AI Algorithm | `core/qsecbit/` |
| Neural Resonance Protocol | `core/neuro/` |
| dnsXai ML Classifier | `shared/dnsXai/` |
| DSM Consensus | `shared/dsm/` |
| AIOCHI Cognitive Layer | `shared/aiochi/` |
| SLA AI Business Continuity | `shared/slaai/` |
| MSSP Cloud Platform | See [hookprobe-com](https://github.com/hookprobe/hookprobe-com) repository |

**Free for:** Personal use, internal business protection
**Commercial license for:** MSSPs, SaaS providers, OEM integrations

📖 **[Full Licensing Details](../LICENSING.md)** | Contact: qsecbit@hookprobe.com

---

## 🗂️ Quick Reference by Audience

### For Business Users
1. [Quick Start](../QUICK-START.md) - Get running fast
2. [Guardian Setup](../products/guardian/README.md) - Travel firewall
3. [Fortress Setup](../products/fortress/README.md) - Office firewall
4. [VPN Guide](networking/VPN.md) - Remote access

### For System Administrators
1. [Installation Guide](installation/INSTALLATION.md) - Deployment
2. [Architecture](../ARCHITECTURE.md) - System design
3. [GDPR Guide](GDPR.md) - Compliance
4. [Qsecbit](../core/qsecbit/README.md) - Threat detection

### For Developers
1. [CLAUDE.md](../CLAUDE.md) - Development guide
2. [Contributing](CONTRIBUTING.md) - How to contribute
3. [Mesh Architecture](../shared/mesh/ARCHITECTURE.md) - P2P design
4. [CI/CD](CI-CD.md) - Build system

### For MSSPs
1. [MSSP Platform](https://github.com/hookprobe/hookprobe-com) - See separate repository
2. [Cloud Deployment](installation/cloud-deployment.md) - Cloud backend setup
3. [Licensing](../LICENSING.md) - Commercial terms

---

## 📞 Support & Community

| Resource | Link |
|----------|------|
| 📖 Main README | [README.md](../README.md) |
| 🐛 Issues | [GitHub Issues](https://github.com/hookprobe/hookprobe/issues) |
| 💬 Discussions | [GitHub Discussions](https://github.com/hookprobe/hookprobe/discussions) |
| 📧 Security | qsecbit@hookprobe.com |
| 📧 Commercial | qsecbit@hookprobe.com |

---

<p align="center">
  <strong>HookProbe v5.7</strong><br>
  <em>Collective intelligence for network security.</em><br>
  <em>One node's detection is everyone's protection.</em>
</p>

**Version**: 5.7.0 | **Last Updated**: 2026-01-05
