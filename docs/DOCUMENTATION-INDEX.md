# HookProbe Documentation Index

<p align="center">
  <strong>The Future of Cybersecurity</strong><br>
  <em>Neural Resonance · Decentralized Mesh · Surgical Precision</em><br><br>
  <strong>Enterprise-Grade AI Security for $150 · Democratizing Cybersecurity for Millions</strong>
</p>

---

**Complete Navigation Guide to HookProbe v5.0 "Liberty" Documentation**

Welcome to HookProbe — the world's first Neurosurgical Cybersecurity Platform. This index provides comprehensive documentation organized by topic and audience.

---

## 🚀 Getting Started

Perfect for first-time users and those new to Linux/HookProbe.

### For Complete Beginners
- **[Beginner's Guide](installation/BEGINNER-GUIDE.md)** ⭐ **START HERE if new to Linux**
  - Download and install Linux (Ubuntu/Debian)
  - Create bootable USB drive
  - Partition disk for HookProbe
  - Complete Linux installation
  - Install HookProbe step-by-step

### For Linux Users
- **[Quick Start Guide](../QUICK-START.md)** - 3-step installation
- **[Interactive Installer](../install.sh)** - Main entry point with menu
- **[Main README](../README.md)** - Project overview and features

### Installation Guides
- **[Edge Deployment](installation/INSTALLATION.md)** - Single-tenant SBC setup
- **[Cloud Deployment](installation/cloud-deployment.md)** - Multi-tenant MSSP backend
- **[Edge Deployment Checklist](../install/edge/checklist.md)** - Pre/post deployment tasks

---

## 🏗️ Architecture & Design

Understanding HookProbe's security architecture.

### Core Architecture
- **[Security Model](architecture/security-model.md)** - Complete security architecture
- **[DSM Whitepaper](architecture/dsm-whitepaper.md)** ⭐ **Decentralized Security Mesh architecture**
- **[DSM Implementation](architecture/dsm-implementation.md)** - Technical implementation guide
- **[Neuro Protocol](architecture/hookprobe-neuro-protocol.md)** 🔥 **Revolutionary neural-weight-based authentication**
- **[HookProbe Protocol Overview](architecture/hookprobe-protocol.md)** - Edge-cloud communication protocol
- **[POD Components Overview](components/README.md)** - All 7-9 POD modules
- **[Network Topology](architecture/security-model.md#network-topology)** - VXLAN, OpenFlow, isolation

### Component Documentation

#### Core Infrastructure PODs (Required)
- **[POD-001: Web DMZ](components/POD-001.md)** - Nginx, WAF, Django CMS
- **[POD-002: IAM/Auth](components/POD-002.md)** - Logto, OAuth 2.0, SSO
- **[POD-003: Database](components/POD-003.md)** - PostgreSQL, NFS, RADIUS
- **[POD-004: Cache](components/POD-004.md)** - Redis, Valkey, sessions
- **[POD-005: Monitoring](components/POD-005.md)** - Grafana, ClickHouse, VictoriaMetrics
- **[POD-006: Security Detection](components/POD-006.md)** - Zeek, Snort, Suricata
- **[POD-007: AI Response](components/POD-007.md)** - Qsecbit, Kali Linux, mitigation
- **[POD-010: DSM Ledger](../infrastructure/pod-010-dsm/README.md)** 🔥 **Decentralized Security Mesh + Neuro**

#### Optional Extension PODs
- **[POD-008: Automation](components/POD-008.md)** - n8n workflows, MCP server
- **[POD-009: Email System](components/POD-009.md)** - Postfix, DKIM, Cloudflare Tunnel

### Dashboards & Interfaces
- **[Dashboard Overview](dashboards/README.md)** - All dashboard documentation
- **[Admin Dashboard](dashboards/admin-dashboard.md)** - AdminLTE system administration
- **[MSSP Dashboard](dashboards/mssp-dashboard.md)** - Security operations and SIEM

---

## 🌐 Networking & Remote Access

VPN, SDN, and network segmentation documentation.

### VPN Remote Access
- **[VPN Overview](networking/VPN.md)** ⭐ **Access your network from anywhere**
  - IKEv2 native VPN for iOS/Android/Windows/macOS
  - Works behind NAT/CGNAT without port forwarding
  - Certificate-based authentication via LogMe2
  - HTP tunnel for edge device connectivity

### SDN & IoT Segmentation
- **[SDN Overview](networking/SDN.md)** ⭐ **Plug-and-play network segmentation**
  - MAC-based VLAN assignment
  - Automatic device categorization
  - Inter-VLAN isolation for IoT security
  - Quarantine VLAN for unknown devices

### Edge Devices
- **[Guardian Setup](../products/guardian/README.md)** - Portable travel hotspot (Raspberry Pi)
- **[Fortress Setup](../products/fortress/README.md)** - Full SDN with VLAN segmentation (Mini PC)
- **[Sentinel Setup](../products/sentinel/README.md)** - Lightweight edge validator

---

## 🛡️ Security Features

Deep dive into HookProbe's security capabilities.

### Core Security
- **[Security Model](architecture/security-model.md)** - Six-layer defense system
- **[Qsecbit AI Algorithm](../src/qsecbit/README.md)** - Threat detection and scoring
- **[Response Engine](../src/response/README.md)** - Automated threat response
- **[WAF Configuration](components/POD-001.md#waf)** - NAXSI/ModSecurity

### Advanced Security
- **[Neuro Protocol](architecture/hookprobe-neuro-protocol.md)** 🔥 **Neural-weight-based continuous authentication**
- **[Neuro Implementation](../src/neuro/README.md)** - Proof-of-Sensor-Fusion (PoSF) signatures
- **[XDP/eBPF DDoS Mitigation](../src/qsecbit/README.md#xdp)** - Kernel-level filtering
- **[Network Hardening](architecture/security-model.md#network-hardening)** - OpenFlow ACLs
- **[Zero Trust Architecture](architecture/security-model.md#zero-trust)** - Security principles
- **[GDPR Compliance](GDPR.md)** - Privacy and data protection

---

## 📊 Monitoring & Analytics

Observability, metrics, and security analytics.

### Monitoring Stack
- **[POD-005 Monitoring](components/POD-005.md)** - Complete monitoring setup
- **[Grafana Dashboards](dashboards/README.md#grafana)** - Pre-built dashboards
- **[ClickHouse Integration](guides/clickhouse-integration.md)** - Security analytics
- **[ClickHouse Quick Start](guides/clickhouse-quick-start.md)** - Getting started

### Analytics & Queries
- **[Security Event Queries](guides/clickhouse-integration.md#queries)** - Example queries
- **[Custom Dashboards](dashboards/README.md#customization)** - Create your own
- **[Metrics Collection](components/POD-005.md#metrics)** - What's monitored

---

## 🔧 Configuration & Setup

Configuration guides and templates.

### Core Configuration
- **[Unified Configuration System](../install/common/README.md)** - Centralized config
- **[Configuration Wizard](../install/common/README.md#wizard)** - Interactive setup
- **[Network Configuration](../install/edge/README.md#network)** - VXLAN, OpenFlow
- **[Configuration Validation](../install/scripts/README.md#validation)** - Pre-deployment checks

### Service Configuration
- **[IAM Integration](IAM-INTEGRATION-GUIDE.md)** - Logto setup and OAuth
- **[n8n Workflow Automation](../install/addons/n8n/README.md)** - POD-008 setup
- **[Email System Setup](../infrastructure/pod-009-email/README.md)** - POD-009 deployment
- **[LTE/5G Connectivity](../install/addons/lte/README.md)** - Cellular failover

---

## 🤖 Optional Features & Extensions

Extend HookProbe with optional components.

### Web & Content Management
- **[Web Server Setup](../install/addons/webserver/README.md)** - Django CMS installation
- **[Web Server Deployment Guide](../install/addons/webserver/DEPLOYMENT_GUIDE.md)** - Complete guide
- **[Web Server Quick Start](../install/addons/webserver/QUICKSTART.md)** - Fast setup

### Workflow Automation (POD-008)
- **[n8n Integration](../install/addons/n8n/README.md)** - Workflow automation
- **[n8n Automation Guide](../install/addons/n8n/AUTOMATION.md)** - Use cases and workflows
- **[n8n Integration Checklist](../install/addons/n8n/integration-checklist.md)** - Setup checklist

### Email System (POD-009)
- **[POD-009 Overview](../infrastructure/pod-009-email/README.md)** - Email system architecture
- **[POD-009 Deployment](../infrastructure/pod-009-email/DEPLOYMENT.md)** - Complete deployment
- **[POD-009 Podman Guide](../infrastructure/pod-009-email/PODMAN.md)** - Podman-specific setup
- **[DKIM/SPF/DMARC Setup](../infrastructure/pod-009-email/dmz-gateway/spf-dmarc-setup.md)** - Email authentication

### Connectivity
- **[LTE/5G Setup](../install/addons/lte/README.md)** - Cellular connectivity

---

## 📋 Operations & Maintenance

Day-to-day operations, backups, and troubleshooting.

### Utility Scripts
- **[Utility Scripts Overview](../install/scripts/README.md)** - All utility scripts
- **[Configuration Validation](../install/scripts/README.md#validation)** - Validate configs
- **[GDPR Data Retention](../install/scripts/README.md#gdpr)** - Automated cleanup
- **[Backup & Restore](../install/scripts/README.md#backup)** - Backup strategies
- **[Container Updates](../install/scripts/README.md#updates)** - Update PODs

### Troubleshooting
- **[Common Issues](../README.md#troubleshooting)** - Quick fixes
- **[POD Troubleshooting](components/README.md#troubleshooting)** - POD-specific issues
- **[Network Issues](architecture/security-model.md#troubleshooting)** - Network debugging
- **[Dashboard Issues](dashboards/README.md#troubleshooting)** - Dashboard problems

---

## 🔒 Privacy & Compliance

GDPR compliance and data protection.

### GDPR Documentation
- **[GDPR Compliance Guide](GDPR.md)** ⭐ **COMPLETE GDPR DOCUMENTATION**
  - Legal basis for processing
  - Privacy by design implementation
  - Data subject rights procedures
  - Breach notification process
  - DPIA template
  - Pre/post deployment checklists

### Privacy Features
- **[Data Retention](GDPR.md#retention)** - Automated data cleanup
- **[Anonymization](GDPR.md#anonymization)** - IP/MAC anonymization
- **[Data Subject Rights](GDPR.md#rights)** - Access, erasure, portability

---

## 🏢 MSSP & Multi-Tenant

Documentation for managed security service providers.

### MSSP Backend
- **[Cloud Backend Deployment](installation/cloud-deployment.md)** - Multi-tenant setup
- **[MSSP Cloud Backend](../install/cloud/README.md)** - Apache Doris cluster
- **[MSSP Dashboard](dashboards/mssp-dashboard.md)** - Security operations center

### Multi-Tenant Features
- **[Tenant Isolation](installation/cloud-deployment.md#isolation)** - Security isolation
- **[Cross-Tenant Analytics](installation/cloud-deployment.md#analytics)** - Threat intelligence
- **[Edge Device Management](dashboards/mssp-dashboard.md#endpoints)** - Device monitoring

---

## 🤝 Development & Contributing

For contributors and developers.

### Contributing
- **[Contributing Guide](CONTRIBUTING.md)** - How to contribute
- **[CI/CD Documentation](CI-CD.md)** - Testing and workflows
- **[CI/CD Changelog](CHANGELOG-CICD.md)** - CI/CD updates and changes

### Development
- **[Source Code Overview](../src/README.md)** - Code structure
- **[Qsecbit Development](../src/qsecbit/README.md)** - AI algorithm development
- **[Web Application Setup](../src/web/README.md)** - Django development
- **[Response Engine](../src/response/README.md)** - Mitigation development

### Testing & Quality
- **[Installation Tests](../.github/workflows/installation-test.yml)** - Automated testing
- **[Container Tests](../.github/workflows/container-tests.yml)** - Integration tests
- **[ShellCheck Linting](../.github/workflows/shellcheck.yml)** - Shell script quality

---

## 📚 Reference Documentation

Technical reference and detailed specifications.

### Specifications
- **[DSM Whitepaper](architecture/dsm-whitepaper.md)** - Decentralized Security Mesh technical whitepaper
- **[Architectural Assessment](../ARCHITECTURAL-ASSESSMENT.md)** - 12-week roadmap
- **[Implementation Summary](../IMPLEMENTATION-SUMMARY-PHASE1-2.md)** - Phase 1-2 details
- **[Unified Install System](../UNIFIED-INSTALL-SYSTEM.md)** - Install architecture
- **[Dashboard Implementation Plan](DASHBOARD-IMPLEMENTATION-PLAN.md)** - Dashboard roadmap

### Hardware & Compatibility
- **[Hardware Compatibility](../README.md#hardware-compatibility)** - Supported platforms
- **[NIC Requirements](../README.md#nic-requirements)** - XDP/eBPF compatibility
- **[Platform Comparison](../README.md#platform-comparison)** - Hardware selection guide

### Legal & Licensing
- **[License](../LICENSE)** - MIT License (v5.0+)
- **[3rd Party Licenses](../3rd-party-licenses.md)** - Dependencies
- **[Security Policy](SECURITY.md)** - Responsible disclosure
- **[R&D Information](../hookprobe-r&d.md)** - Research and development

---

## 🗂️ Documentation by Audience

### For First-Time Users
1. [Beginner's Guide](installation/BEGINNER-GUIDE.md) ⭐ Start here!
2. [Quick Start](../QUICK-START.md)
3. [Main README](../README.md)
4. [Installation Guide](installation/INSTALLATION.md)

### For System Administrators
1. [DSM Whitepaper](architecture/dsm-whitepaper.md)
2. [Security Model](architecture/security-model.md)
3. [POD Components](components/README.md)
4. [Admin Dashboard](dashboards/admin-dashboard.md)
5. [Configuration Guide](../install/common/README.md)
6. [Utility Scripts](../install/scripts/README.md)

### For Security Teams
1. [DSM Whitepaper](architecture/dsm-whitepaper.md)
2. [MSSP Dashboard](dashboards/mssp-dashboard.md)
3. [Qsecbit Algorithm](../src/qsecbit/README.md)
4. [Security Model](architecture/security-model.md)
5. [Threat Detection](components/POD-006.md)
6. [Incident Response](components/POD-007.md)

### For MSSP Providers
1. [DSM Whitepaper](architecture/dsm-whitepaper.md)
2. [Cloud Backend Deployment](installation/cloud-deployment.md)
3. [MSSP Dashboard](dashboards/mssp-dashboard.md)
4. [Multi-Tenant Setup](../install/cloud/README.md)
5. [Edge Device Management](dashboards/mssp-dashboard.md#endpoints)

### For Developers
1. [Contributing Guide](CONTRIBUTING.md)
2. [Source Code Overview](../src/README.md)
3. [CI/CD Documentation](CI-CD.md)
4. [Web Development](../src/web/README.md)

---

## 📖 Documentation Updates

**Last Updated**: 2025-12-07
**Version**: 5.0.0
**Status**: Production Ready

### Recent Additions
- ✅ Complete POD documentation (POD-001 through POD-009)
- ✅ Dashboard documentation (Admin & MSSP)
- ✅ Source code overview (src/README.md)
- ✅ Infrastructure documentation (POD-009)
- ✅ Installation documentation improvements

### Documentation Coverage
- **Core Documentation**: 100% ✅
- **POD Components**: 100% ✅
- **Dashboards**: 100% ✅
- **Installation Guides**: 100% ✅
- **Security Documentation**: 100% ✅
- **GDPR Compliance**: 100% ✅

---

## 🔍 Quick Search

Can't find what you're looking for? Here are common topics:

- **Install HookProbe**: [Beginner's Guide](installation/BEGINNER-GUIDE.md) or [Quick Start](../QUICK-START.md)
- **Setup VPN remote access**: [VPN Guide](networking/VPN.md)
- **Segment IoT devices**: [SDN Guide](networking/SDN.md)
- **Setup Guardian (Raspberry Pi)**: [Guardian Setup](../products/guardian/README.md)
- **Configure network**: [Network Configuration](../install/edge/README.md#network)
- **Setup GDPR compliance**: [GDPR Guide](GDPR.md)
- **Add optional features**: [Optional Features](../README.md#optional-features)
- **Troubleshoot PODs**: [POD Troubleshooting](components/README.md#troubleshooting)
- **Monitor security**: [MSSP Dashboard](dashboards/mssp-dashboard.md)
- **Manage users**: [IAM Integration](IAM-INTEGRATION-GUIDE.md)
- **Setup email**: [POD-009 Deployment](../infrastructure/pod-009-email/DEPLOYMENT.md)
- **Automate workflows**: [n8n Integration](../install/addons/n8n/README.md)
- **Setup cloud backend**: [Cloud Deployment](installation/cloud-deployment.md)

---

## 📞 Support & Community

- **GitHub Issues**: https://github.com/hookprobe/hookprobe/issues
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Security Contact**: [SECURITY.md](SECURITY.md)
- **Main Project**: [README.md](../README.md)

---

## ℹ️ About This Index

This documentation index is automatically maintained to ensure all HookProbe documentation is easily discoverable. If you find any broken links or missing documentation, please open an issue on GitHub.

**Documentation Structure**:
```
hookprobe/
├── README.md                    # Main project README
├── QUICK-START.md              # Quick installation guide
├── docs/                        # All documentation
│   ├── DOCUMENTATION-INDEX.md  # This file
│   ├── installation/           # Installation guides
│   ├── architecture/           # Architecture docs
│   ├── components/             # POD documentation
│   ├── dashboards/             # Dashboard docs
│   ├── guides/                 # How-to guides
│   ├── GDPR.md                 # GDPR compliance
│   ├── IAM-INTEGRATION-GUIDE.md # Logto setup
│   └── CONTRIBUTING.md         # Contributing guide
├── install/                     # Installation scripts
│   ├── edge/                   # Edge deployment
│   ├── cloud/                  # Cloud backend
│   ├── common/                 # Shared configs
│   ├── scripts/                # Utility scripts
│   └── addons/                 # Optional features
├── infrastructure/             # Optional infrastructure
│   └── pod-009-email/          # Email system
└── src/                        # Source code
    ├── qsecbit/                # AI algorithm
    ├── response/               # Response engine
    └── web/                    # Django web app
```

---

**HookProbe Documentation** - *Comprehensive Guide to Democratizing Cybersecurity*

Built with ❤️ for the security community

**Version**: 5.0.0
**Last Updated**: 2025-12-07
**Maintained by**: HookProbe Team
