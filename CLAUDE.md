# CLAUDE.md - AI Assistant Guide for HookProbe

**Version**: 5.2
**Last Updated**: 2025-12-14
**Purpose**: Comprehensive guide for AI assistants working with the HookProbe codebase

---

## Quick Lookup: When User Wants To...

| User Request | Go To | Key Files |
|-------------|-------|-----------|
| **Run tests** | `pytest tests/` | `pytest.ini`, `tests/test_*.py` |
| **Check code quality** | `make lint` | `.pre-commit-config.yaml`, `Makefile` |
| **Deploy Sentinel** | `./install.sh --tier sentinel` | `products/sentinel/` |
| **Deploy Guardian** | `./install.sh --tier guardian` | `products/guardian/` |
| **Deploy Fortress** | `./install.sh --tier fortress` | `products/fortress/` |
| **Deploy Nexus** | `./install.sh --tier nexus` | `products/nexus/` |
| **Modify Qsecbit algorithm** | Edit core logic | `core/qsecbit/qsecbit.py` |
| **Add XDP/eBPF rules** | Edit XDP manager | `core/qsecbit/xdp_manager.py` |
| **Work with HTP protocol** | Core transport | `core/htp/transport/htp.py` |
| **Add DNS/Ad blocking** | dnsXai module | `shared/dnsXai/` |
| **Work with mesh networking** | Mesh module | `shared/mesh/` |
| **Configure n8n automation** | Deploy addon | `deploy/addons/n8n/` |
| **Add LTE/5G failover** | Check addon docs | `deploy/addons/lte/README.md` |
| **Debug CI/CD failures** | Check workflows | `.github/workflows/` |
| **Understand architecture** | Read mesh docs | `shared/mesh/ARCHITECTURE.md` |
| **Add new security feature** | Check shared response | `shared/response/` |
| **Modify DSM consensus** | Check shared DSM | `shared/dsm/` |
| **GDPR compliance** | Check privacy module | `core/qsecbit/gdpr_privacy.py` |
| **Guardian web UI** | Flask app | `products/guardian/web/` |
| **Fortress admin portal** | Flask + AdminLTE | `products/fortress/web/` |
| **Fortress development** | MVP plan | `products/fortress/DEVELOPMENT_PLAN.md` |
| **MSSP web portal** | Django app | `products/mssp/web/` |
| **NAT traversal** | Mesh networking | `shared/mesh/nat_traversal.py` |
| **Email infrastructure** | Infrastructure pod | `infrastructure/pod-009-email/` |
| **Cortex (3D Globe)** | Shared visualization | `shared/cortex/` |
| **Understand security fabric** | City-level visualization | `shared/cortex/README.md` (see "Understanding Your Security Fabric") |
| **Cortex connectors** | Product connectors | `shared/cortex/backend/connectors/` |
| **Add Cortex to Guardian** | Flask integration | `shared/cortex/backend/connectors/guardian.py` |
| **Add Cortex to MSSP** | Django integration | `shared/cortex/backend/connectors/mssp.py` |
| **Guardian UI styling** | Forty-inspired CSS | `products/guardian/web/static/css/main.css` |
| **UI design reference** | HTML5UP Forty template | `assets/forty/` |
| **E2E security flow** | Attack detection→response→propagation | See [E2E Security Flow](#end-to-end-e2e-security-flow) |
| **E2E integration tests** | Full flow validation | `tests/test_e2e_integration.py` |
| **Mesh propagation** | Threat gossip protocol | `shared/mesh/consciousness.py` |
| **Response orchestration** | Automated mitigation | `core/qsecbit/response/orchestrator.py` |

---

## Table of Contents

- [Project Overview](#project-overview)
- [Licensing](#licensing)
- [Codebase Structure](#codebase-structure)
- [Core Modules](#core-modules)
- [Shared Infrastructure](#shared-infrastructure)
- [Product Tiers](#product-tiers)
- [Cortex Visualization](#cortex-visualization)
- [End-to-End (E2E) Security Flow](#end-to-end-e2e-security-flow)
- [Testing Guide](#testing-guide)
- [CI/CD Workflows](#cicd-workflows)
- [Development Tooling](#development-tooling)
- [Scenario-Based Guidance](#scenario-based-guidance)
- [Key Conventions](#key-conventions)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

---

## Project Overview

### What is HookProbe?

> **"One node's detection → Everyone's protection"**

HookProbe is a **federated cybersecurity mesh** - a family of protectors building the future of collective defense. We believe security is a right, not a privilege. A $75 Raspberry Pi running HookProbe gets the same AI-powered protection as a $50,000 enterprise appliance.

**Core Philosophy:**
- 🛡️ **Protection is a right** - Enterprise-grade security for everyone
- 🔍 **Transparency builds trust** - Every decision is explainable
- 🤝 **Collective defense works** - One detection protects all
- 🧠 **AI serves humans** - Focus on what you love, we handle protection

**The HTP-DSM-NEURO-QSECBIT-NSE Security Stack:**

| Layer | Purpose | Innovation |
|-------|---------|------------|
| **HTP** | Transport | Post-quantum Kyber KEM, keyless authentication |
| **DSM** | Consensus | Byzantine fault-tolerant validation |
| **NEURO** | Identity | Neural fingerprinting via weight evolution |
| **QSECBIT** | Scoring | Real-time RAG status (GREEN/AMBER/RED) |
| **NSE** | Encryption | Keys emerge from neural state - nobody knows the password |

**Key Capabilities:**
- **AI-Powered Threat Detection**: Qsecbit algorithm for L2-L7 security analysis
- **Federated Defense**: Privacy-preserving collective intelligence
- **Multi-Tier Products**: Sentinel, Guardian, Fortress, Nexus, MSSP
- **Zero Trust Mesh**: HTP protocol with post-quantum cryptography
- **AI DNS Protection**: dnsXai for ML-based ad/tracker blocking
- **Mesh Consciousness**: Collective threat intelligence sharing
- **Adversarial Testing**: AI vs AI security validation

**Project Type**: Federated Security Platform / Infrastructure-as-Code
**Primary Languages**: Python (core logic), Bash (deployment)
**Web Frameworks**: Flask (Guardian), Django (MSSP)
**Deployment**: Podman containers with OVS networking
**License**: Dual Licensed (AGPL v3.0 + Commercial) - see [Licensing](#licensing)

### Product Tiers

| Tier | RAM | Use Case | Location |
|------|-----|----------|----------|
| **Sentinel** | 256MB | IoT Validator | `products/sentinel/` |
| **Guardian** | 1.5GB | Travel/Portable | `products/guardian/` |
| **Fortress** | 4GB | Small Business | `products/fortress/` |
| **Nexus** | 16GB+ | ML/AI Compute | `products/nexus/` |
| **MSSP** | 16GB+ | Central Brain | `products/mssp/` |

**Target Markets:**
- **Sentinel**: IoT devices, validators, lightweight edge nodes
- **Guardian**: Travelers, home users, portable protection
- **Fortress**: Small businesses (flower shops, bakeries, retail, trades)
- **Nexus**: AI/ML workloads, regional compute hubs
- **MSSP**: Service providers, multi-tenant cloud platform

---

## Licensing

HookProbe uses a **dual licensing model**. Understanding what license applies to which component is critical for AI assistants helping with the codebase.

### Open Source Components (AGPL v3.0)

These directories are open source and can be freely modified:

| Component | Location | License |
|-----------|----------|---------|
| Deployment Scripts | `deploy/` | AGPL v3.0 |
| Guardian Product | `products/guardian/` | AGPL v3.0 |
| Fortress Product | `products/fortress/` | AGPL v3.0 |
| Threat Response | `shared/response/` | AGPL v3.0 |
| Mesh Communication | `shared/mesh/` | AGPL v3.0 |
| HTP Base Protocol | `core/htp/` | AGPL v3.0 |
| Documentation | `docs/` | AGPL v3.0 |

### Proprietary Components (Commercial License)

These directories contain proprietary innovations. Commercial license required for SaaS/OEM use:

| Innovation | Location | License |
|------------|----------|---------|
| **Qsecbit AI Algorithm** | `core/qsecbit/` | Proprietary |
| **Neural Resonance Protocol** | `core/neuro/` | Proprietary |
| **dnsXai ML Classifier** | `shared/dnsXai/` | Proprietary |
| **DSM Consensus** | `shared/dsm/` | Proprietary |
| **MSSP Cloud Platform** | `products/mssp/` | Proprietary |

### Usage Guidelines

| Use Case | License Required |
|----------|------------------|
| Personal/Home use | Free (AGPL + personal use of proprietary) |
| Internal business protection | Free (AGPL + internal use of proprietary) |
| MSSP/SaaS offering | Commercial License Required |
| OEM/Product embedding | Commercial License Required |

**Full details**: See `LICENSING.md` in project root
**Contact**: qsecbit@hookprobe.com

---

## Codebase Structure

```
hookprobe/
├── CLAUDE.md                         # This file (AI assistant guide)
├── LICENSE                           # AGPL v3.0 License
├── LICENSING.md                      # Full licensing details (dual license)
├── Makefile                          # Development commands
├── pytest.ini                        # Test configuration
├── .pre-commit-config.yaml           # Pre-commit hooks
├── .shellcheckrc                     # ShellCheck config
├── .editorconfig                     # Editor config
├── 3rd-party-licenses.md             # Third-party licenses
├── hookprobe-r&d.md                  # R&D documentation
│
├── core/                             # CORE INTELLIGENCE
│   ├── __init__.py
│   ├── htp/                          # HookProbe Transport Protocol
│   │   ├── transport/
│   │   │   ├── htp.py               # Main HTP implementation
│   │   │   ├── htp_vpn.py           # VPN integration
│   │   │   ├── htp_file.py          # File transfer protocol
│   │   │   └── htp_file_integration_example.py
│   │   └── crypto/
│   │       ├── hybrid_kem.py        # Kyber post-quantum crypto
│   │       ├── transport.py         # ChaCha20-Poly1305
│   │       └── transport_v2.py      # Enhanced transport
│   │
│   ├── qsecbit/                      # Quantified Security Metric
│   │   ├── qsecbit.py               # Main algorithm (RAG scoring)
│   │   ├── qsecbit-agent.py         # Agent daemon
│   │   ├── energy_monitor.py        # RAPL power monitoring
│   │   ├── xdp_manager.py           # XDP/eBPF DDoS mitigation
│   │   ├── nic_detector.py          # NIC capability detection
│   │   ├── gdpr_privacy.py          # Privacy-preserving module
│   │   ├── README.md                # Qsecbit documentation
│   │   ├── detectors/               # L2-L7 layer threat detectors
│   │   ├── ml/                      # ML classifier components
│   │   ├── response/                # Threat response orchestration
│   │   └── signatures/              # Signature database and matching
│   │
│   ├── neuro/                        # Neural Resonance Protocol
│   │   ├── README.md                # Neuro protocol docs
│   │   ├── requirements.txt         # Python dependencies
│   │   ├── adversarial/             # Adversarial attack detection
│   │   ├── attestation/
│   │   │   └── device_identity.py   # Device attestation
│   │   ├── audit/
│   │   │   └── merkle_log.py        # Audit logging
│   │   ├── core/
│   │   │   ├── ter.py               # Telemetry Event Record
│   │   │   ├── posf.py              # Proof of Secure Function
│   │   │   └── replay.py            # Replay protection
│   │   ├── identity/
│   │   │   └── hardware_fingerprint.py  # Hardware identity
│   │   ├── network/
│   │   │   └── nat_traversal.py     # NAT traversal
│   │   ├── neural/
│   │   │   ├── engine.py            # Neural weight evolution
│   │   │   └── fixedpoint.py        # Q16.16 fixed-point math
│   │   ├── product_adapters/        # Product-specific adapters
│   │   ├── storage/
│   │   │   └── dreamlog.py          # Offline TER storage
│   │   ├── tools/                   # Neuro utility tools
│   │   └── validation/
│   │       └── validator_network.py  # Validator network
│   │
│   └── threat_detection/             # Shared threat detection utilities
│
├── shared/                           # SHARED INFRASTRUCTURE
│   ├── README.md
│   │
│   ├── dnsXai/                       # AI-POWERED DNS PROTECTION
│   │   ├── README.md                # Comprehensive documentation
│   │   ├── __init__.py
│   │   ├── engine.py                # ML classifier engine
│   │   ├── integration.py           # Product integration
│   │   ├── mesh_intelligence.py     # Federated learning
│   │   └── update-blocklist.sh      # Blocklist updater
│   │
│   ├── dsm/                          # Decentralized Security Mesh
│   │   ├── README.md
│   │   ├── requirements.txt
│   │   ├── consensus.py             # BLS signature aggregation
│   │   ├── gossip.py                # P2P threat announcement
│   │   ├── ledger.py                # Microblock chain
│   │   ├── validator.py             # Validator logic
│   │   ├── merkle.py                # Merkle tree verification
│   │   ├── node.py                  # Edge node microblocks
│   │   ├── identity.py              # Node identity management
│   │   └── crypto/
│   │       ├── attestation.py       # Remote attestation
│   │       ├── bls.py               # BLS signatures
│   │       └── tpm.py               # TPM integration
│   │
│   ├── mesh/                         # MESH COMMUNICATION LAYER
│   │   ├── ARCHITECTURE.md          # Unified mesh architecture
│   │   ├── __init__.py
│   │   ├── channel_selector.py      # Intelligent channel selection
│   │   ├── consciousness.py         # Mesh consciousness
│   │   ├── nat_traversal.py         # NAT/CGNAT traversal
│   │   ├── neuro_encoder.py         # Neural resonance auth
│   │   ├── port_manager.py          # Multi-port management
│   │   ├── relay.py                 # Relay network
│   │   ├── resilient_channel.py     # Reliable messaging
│   │   ├── tunnel.py                # Tunnel providers
│   │   └── unified_transport.py     # High-level transport API
│   │
│   ├── response/                     # Automated Threat Response
│   │   ├── README.md
│   │   ├── MITIGATION_INSTALLATION_GUIDE.md
│   │   ├── attack-mitigation-orchestrator.sh
│   │   ├── kali-scripts.sh          # Kali mitigation
│   │   ├── mitigation-maintenance.sh
│   │   └── hookprobe-mitigation-systemd.conf
│   │
│   ├── mobile_security/              # Mobile device security
│   │
│   ├── network/                      # Network utilities
│   │   └── sdn/                     # SDN integration
│   │
│   ├── wireless/                     # Wireless security tools
│   │
│   └── cortex/                       # HOOKPROBE CORTEX - Neural Command Center
│       ├── README.md                # Documentation
│       ├── ARCHITECTURE.md          # HTP integration analysis
│       ├── backend/
│       │   ├── server.py            # WebSocket server with demo/live toggle
│       │   ├── node_registry.py     # NodeTwin state management
│       │   ├── htp_bridge.py        # HTP mesh participant
│       │   ├── demo_data.py         # Demo event generator
│       │   ├── geo_resolver.py      # IP geolocation
│       │   └── connectors/          # Product tier connectors
│       │       ├── base.py          # ProductConnector base class
│       │       ├── manager.py       # ConnectorManager aggregator
│       │       ├── guardian.py      # Guardian Flask integration
│       │       ├── fortress.py      # Fortress DSM integration
│       │       ├── nexus.py         # Nexus ML/AI integration
│       │       └── mssp.py          # MSSP Django integration
│       ├── frontend/
│       │   ├── index.html           # Cortex main page
│       │   ├── css/globe.css        # Premium styling
│       │   └── js/
│       │       ├── globe.js         # Globe.gl visualization
│       │       ├── data-stream.js   # WebSocket client
│       │       ├── animations.js    # Premium effects engine
│       │       └── fallback-2d.js   # Mobile 2D fallback
│       └── tests/
│           └── test_globe_backend.py
│
├── products/                         # PRODUCT TIERS
│   ├── README.md                    # Product tier overview
│   │
│   ├── sentinel/                     # DSM Validator (256MB)
│   │   └── README.md
│   │
│   ├── guardian/                     # Travel Companion (1.5GB)
│   │   ├── README.md
│   │   ├── config/                  # WiFi/network configs
│   │   │   ├── dnsmasq.conf
│   │   │   ├── hostapd.conf
│   │   │   ├── hostapd-5ghz.conf
│   │   │   ├── hostapd.vlan
│   │   │   ├── mac_vlan.json
│   │   │   └── wpa_supplicant.conf
│   │   ├── lib/                     # Core Python modules
│   │   │   ├── guardian_agent.py    # Main agent
│   │   │   ├── config.py            # Configuration
│   │   │   ├── htp_client.py        # HTP client
│   │   │   ├── layer_threat_detector.py  # L2-L7 detection
│   │   │   ├── mesh_integration.py  # Mesh connectivity
│   │   │   ├── mobile_network_protection.py
│   │   │   ├── network_segmentation.py
│   │   │   └── openflow_controller.py
│   │   ├── scripts/
│   │   │   ├── setup.sh             # Installation (also installs shared/cortex)
│   │   │   ├── uninstall.sh         # Cleanup (removes shared/cortex)
│   │   │   └── update-blocklists.sh
│   │   └── web/                     # Flask Web UI (Forty-inspired design)
│   │       ├── app.py               # Main Flask app + cortex-modules route
│   │       ├── config.py
│   │       ├── utils.py
│   │       ├── modules/             # Flask Blueprint modules
│   │       │   ├── __init__.py      # register_blueprints()
│   │       │   ├── clients/         # Connected clients API
│   │       │   ├── config/          # Network config API
│   │       │   ├── core/            # Dashboard (main landing)
│   │       │   ├── cortex/          # Cortex globe integration
│   │       │   ├── debug/           # Browser CLI terminal
│   │       │   ├── dnsxai/          # DNS protection settings
│   │       │   ├── github_update/   # Git/GitHub update operations
│   │       │   ├── qsecbit/         # Qsecbit security scoring
│   │       │   ├── security/        # Security metrics + Qsecbit
│   │       │   ├── system/          # System status + updates
│   │       │   └── vpn/             # VPN management
│   │       ├── static/
│   │       │   ├── css/
│   │       │   │   └── main.css     # Forty-inspired premium CSS
│   │       │   ├── js/
│   │       │   │   └── main.js      # Tab navigation + API calls
│   │       │   └── images/          # Logo, icons
│   │       └── templates/
│   │           ├── base.html        # Main layout + full-screen menu
│   │           ├── clients/         # Client management views
│   │           ├── config/          # Network config views
│   │           ├── core/            # Dashboard template
│   │           │   └── dashboard.html
│   │           ├── cortex/          # Cortex globe integration
│   │           │   └── embedded.html # Uses /cortex-modules/* route
│   │           ├── debug/           # Browser CLI terminal
│   │           ├── dnsxai/          # DNS protection views
│   │           ├── security/        # Security metrics views
│   │           │   └── metrics.html # Qsecbit + layer cards
│   │           ├── system/          # System status views
│   │           └── vpn/             # VPN management views
│   │
│   ├── fortress/                     # Edge Router (4GB)
│   │   ├── README.md
│   │   └── setup.sh
│   │
│   ├── nexus/                        # ML/AI Compute (16GB+)
│   │   └── (minimal - future expansion)
│   │
│   └── mssp/                         # Cloud MSSP Platform
│       ├── README.md
│       ├── device_registry.py       # Device management
│       ├── geolocation.py           # Location services
│       ├── setup.sh
│       ├── uninstall.sh
│       ├── lib/
│       │   └── htp_validator.py     # HTP validation
│       ├── scripts/
│       │   └── health-check.sh
│       └── web/                     # Django Web Portal
│           ├── README.md
│           ├── .env.example
│           ├── Dockerfile.test
│           └── apps/               # Django apps
│               ├── admin_dashboard/ # Admin UI
│               ├── cms/             # Content management
│               ├── common/          # Shared utilities
│               ├── dashboard/       # Main dashboard
│               ├── devices/         # Device management
│               ├── merchandise/     # Product catalog
│               ├── monitoring/      # System monitoring
│               ├── mssp_dashboard/  # MSSP-specific views
│               ├── sdn/             # SDN management
│               ├── security/        # Security features
│               └── vpn/             # VPN services
│
├── deploy/                           # DEPLOYMENT SCRIPTS
│   ├── README.md
│   │
│   ├── edge/                         # Edge deployment
│   │   ├── README.md
│   │   ├── QUICK-START.md
│   │   ├── checklist.md
│   │   ├── provision.sh             # Node provisioning
│   │   ├── cleanup.sh               # Cleanup script
│   │   ├── update.sh                # Update script
│   │   ├── uninstall.sh
│   │   ├── hookprobe-ctl            # CLI control tool
│   │   ├── hookprobe-bootstrap.sh   # Bootstrap script
│   │   └── systemd/                 # Systemd services
│   │       ├── hookprobe-agent.service
│   │       ├── hookprobe-provision.service
│   │       ├── hookprobe-update.service
│   │       ├── hookprobe-update.timer
│   │       └── hookprobe-uninstall.service
│   │
│   ├── cloud/                        # Cloud deployment
│   │   ├── README.md
│   │   ├── config.sh
│   │   ├── setup.sh
│   │   └── uninstall.sh
│   │
│   ├── addons/                       # Optional addons
│   │   ├── n8n/                     # Workflow automation
│   │   │   ├── README.md
│   │   │   ├── AUTOMATION.md
│   │   │   ├── integration-checklist.md
│   │   │   ├── setup.sh
│   │   │   ├── config.sh
│   │   │   ├── uninstall.sh
│   │   │   ├── integrations/        # ClickHouse, Qsecbit
│   │   │   ├── tests/               # Integration tests
│   │   │   └── workflows/           # Pre-built workflows
│   │   ├── lte/                     # LTE/5G connectivity
│   │   │   └── README.md
│   │   └── webserver/               # Web server addon
│   │       ├── README.md
│   │       ├── QUICKSTART.md
│   │       ├── DEPLOYMENT_GUIDE.md
│   │       ├── SUMMARY.md
│   │       ├── Containerfile
│   │       ├── entrypoint.sh
│   │       ├── setup-webserver.sh
│   │       ├── setup-webserver-podman.sh
│   │       ├── config/
│   │       └── nginx/
│   │
│   └── install/
│       ├── README.md
│       └── validate-config.sh
│
├── infrastructure/                   # INFRASTRUCTURE TEMPLATES
│   ├── README.md
│   ├── pod-009-email/               # Email server infrastructure
│   │   ├── README.md
│   │   ├── DEPLOYMENT.md
│   │   ├── PODMAN.md
│   │   ├── docker-compose.yml
│   │   ├── dmz-gateway/             # Postfix, DKIM, SPF/DMARC
│   │   ├── internal-server/         # Internal mail server
│   │   ├── cloudflare/              # Cloudflare config
│   │   ├── django-integration/      # Django email settings
│   │   ├── firewall-rules/          # iptables rules
│   │   └── monitoring/              # Suricata SMTP rules
│   └── pod-010-dsm/                 # DSM infrastructure
│       ├── README.md
│       └── docker-compose.yml
│
├── scripts/                          # MAINTENANCE SCRIPTS
│   ├── gdpr-retention.sh            # GDPR data retention
│   ├── run-integration-tests.sh
│   ├── run-performance-tests.sh
│   └── lib/
│       ├── platform.sh              # Platform detection
│       ├── requirements.sh          # Dependency checks
│       └── instructions.sh          # Installation instructions
│
├── tests/                            # TEST SUITES
│   ├── __init__.py
│   ├── test_qsecbit.py              # Qsecbit algorithm tests
│   ├── test_htp_e2e.py              # HTP end-to-end tests
│   ├── test_htp_keyless.py          # Keyless protocol tests
│   └── test_htp_security_enhancements.py
│
├── docs/                             # DOCUMENTATION
│   ├── CLAUDE.md                    # Copy of this file
│   ├── CONTRIBUTING.md              # Contribution guide
│   ├── SECURITY.md                  # Security policy
│   ├── DOCUMENTATION-INDEX.md       # Doc navigation
│   ├── GDPR.md                      # GDPR compliance
│   ├── CI-CD.md                     # CI/CD documentation
│   ├── CHANGELOG-CICD.md            # CI/CD changelog
│   ├── IAM-INTEGRATION-GUIDE.md     # IAM integration
│   ├── DASHBOARD-IMPLEMENTATION-PLAN.md
│   ├── HTP_SECURITY_ENHANCEMENTS.md
│   ├── HTP_QUANTUM_CRYPTOGRAPHY.md
│   ├── HTP_KEYLESS_PROTOCOL_ANALYSIS.md
│   ├── architecture/
│   │   └── HOOKPROBE-ARCHITECTURE.md
│   ├── components/
│   │   └── README.md
│   ├── dashboards/
│   │   ├── README.md
│   │   ├── admin-dashboard.md
│   │   └── mssp-dashboard.md
│   ├── deployment/
│   │   └── MSSP-PRODUCTION-DEPLOYMENT.md
│   ├── guides/
│   │   ├── ai-business.md
│   │   ├── clickhouse-integration.md
│   │   └── clickhouse-quick-start.md
│   ├── installation/
│   │   ├── INSTALLATION.md
│   │   ├── BEGINNER-GUIDE.md
│   │   └── cloud-deployment.md
│   └── networking/
│       ├── VPN.md
│       └── SDN.md
│
├── config/                           # CONFIGURATION TEMPLATES
│   ├── dsm-phase1.yaml              # DSM phase 1 config
│   ├── neuro-phase1.yaml            # Neuro phase 1 config
│   ├── mitigation-config.conf       # Mitigation config
│   └── gdpr-config.sh               # GDPR config
│
├── assets/                           # IMAGES, BRANDING & UI TEMPLATES
│   ├── readme.md
│   ├── hookprobe-logo.svg
│   ├── hookprobe-emblem.svg
│   ├── hookprobe-emblem-small.png
│   ├── hookprobe-protocol.png
│   ├── hookprobe-neuro-resonant-protocol.png
│   ├── hookprobe-future-ram-cine.png
│   ├── hookprobe-r&d.png
│   ├── qsecbit-catcher.png
│   ├── xSOC-HLD-v1.2.png
│   └── forty/                        # HTML5UP Forty Template (UI Reference)
│       ├── index.html               # Main template structure
│       ├── landing.html             # Landing page example
│       ├── generic.html             # Generic content page
│       ├── elements.html            # UI component showcase
│       ├── images/                  # Stock images
│       └── assets/
│           ├── css/
│           │   ├── main.css         # Full-screen menu, tiles, premium styling
│           │   └── noscript.css
│           ├── js/                  # jQuery + scrolly effects
│           ├── sass/                # SCSS source files
│           │   ├── base/            # Typography, reset
│           │   ├── components/      # Buttons, forms, tiles
│           │   └── layout/          # Header, menu, banner, footer
│           └── webfonts/            # FontAwesome icons
│
└── .github/                          # CI/CD CONFIGURATION
    ├── dependabot.yml
    ├── markdown-link-check-config.json
    ├── PULL_REQUEST_TEMPLATE.md
    ├── workflows/
    │   ├── app-tests.yml            # Application tests
    │   ├── python-lint.yml          # Python linting
    │   ├── container-tests.yml      # Container tests
    │   ├── installation-test.yml    # Installation tests
    │   ├── arm64-tests.yml          # ARM64 tests
    │   ├── documentation.yml        # Doc validation
    │   ├── ci-status.yml            # CI status
    │   └── config-validation.yml    # Config validation
    ├── actions/
    │   ├── setup-python/            # Python setup action
    │   └── setup-podman/            # Podman setup action
    └── ISSUE_TEMPLATE/
        ├── bug_report.md
        ├── feature_request.md
        └── security_vulnerability.md
```

---

## Core Modules

### Qsecbit - Quantified Security Metric

**Location**: `core/qsecbit/`

The brain of HookProbe's threat detection.

| File | Purpose |
|------|---------|
| `qsecbit.py` | Main orchestrator - resilience metric calculation |
| `qsecbit-agent.py` | Agent daemon for continuous monitoring |
| `energy_monitor.py` | RAPL + per-PID power tracking |
| `xdp_manager.py` | XDP/eBPF DDoS mitigation at kernel level |
| `nic_detector.py` | NIC capability detection (XDP-hw/drv/skb) |
| `gdpr_privacy.py` | Privacy-preserving data anonymization |

**Algorithm**:
```python
# The Formula
Qsecbit = α·drift + β·p_attack + γ·decay + δ·q_drift + ε·energy_anomaly

# Default Weights (without energy monitoring)
α = 0.30  # System drift (Mahalanobis distance)
β = 0.30  # Attack probability (ML-predicted)
γ = 0.20  # Classifier decay
δ = 0.20  # Quantum drift

# With dnsXai integration
Qsecbit = 0.30·threats + 0.20·mobile + 0.25·ids + 0.15·xdp + 0.02·network + 0.08·dnsxai
```

**RAG Status**:

| Status | Range | Meaning | Action |
|--------|-------|---------|--------|
| **GREEN** | < 0.45 | Normal | Learning baseline |
| **AMBER** | 0.45-0.70 | Warning | Kali spins up |
| **RED** | > 0.70 | Critical | Full mitigation |

### HTP - HookProbe Transport Protocol

**Location**: `core/htp/`

Secure, keyless transport with post-quantum cryptography.

| Directory | Purpose |
|-----------|---------|
| `transport/` | Main HTP implementation, VPN, file transfer |
| `crypto/` | Kyber hybrid KEM, ChaCha20-Poly1305 |

**Key Features**:
- Keyless authentication via entropy echo
- Post-quantum Kyber KEM
- Adaptive streaming
- VPN integration

### Neuro - Neural Resonance Protocol

**Location**: `core/neuro/`

Living cryptography where neural networks become keys.

| Directory | Purpose |
|-----------|---------|
| `core/` | TER, PoSF signatures, replay protection |
| `neural/` | Weight evolution, fixed-point math |
| `attestation/` | Device identity |
| `identity/` | Hardware fingerprinting |
| `storage/` | Offline TER storage (dreamlog) |
| `validation/` | Validator network |
| `audit/` | Merkle log for auditing |

**Core Innovation**:
```
Traditional: "Do you know the password?"
Neuro: "Can you prove your sensor history through weight evolution?"

W(t+1) = W(t) - η_mod × ∇L(W(t), TER)
```

---

## Shared Infrastructure

### dnsXai - AI-Powered DNS Protection

**Location**: `shared/dnsXai/`

Next-generation DNS protection with machine learning.

| File | Purpose |
|------|---------|
| `engine.py` | ML classifier (20 features, 8 categories) |
| `integration.py` | Product integration utilities |
| `mesh_intelligence.py` | Federated learning across mesh |
| `update-blocklist.sh` | Blocklist updater script |

**Features**:
- ML-based classification for unknown domains
- CNAME uncloaking (detects first-party tracker masquerading)
- Federated learning across mesh network
- 5-tier protection levels (~130K to ~250K domains)
- <1ms inference on Raspberry Pi

**Protection Levels**:

| Level | Name | Protection |
|-------|------|------------|
| 1 | Base | Ads + Malware |
| 2 | Enhanced | + Fakenews |
| 3 | Strong | + Gambling |
| 4 | Maximum | + Adult Content |
| 5 | Full | + Social Trackers |

### Mesh - Unified Communication Layer

**Location**: `shared/mesh/`

Resilient, anti-blocking mesh communication.

| File | Purpose |
|------|---------|
| `ARCHITECTURE.md` | **COMPREHENSIVE** mesh architecture documentation |
| `consciousness.py` | Mesh consciousness states |
| `nat_traversal.py` | STUN/ICE/hole punching |
| `port_manager.py` | Multi-port failover |
| `resilient_channel.py` | Reliable messaging |
| `neuro_encoder.py` | Neural resonance authentication |
| `channel_selector.py` | Intelligent channel selection |
| `relay.py` | TURN-style relay network |
| `tunnel.py` | Cloudflare/ngrok/Tailscale tunnels |
| `unified_transport.py` | High-level API |

**Port Selection**:
```
PRIMARY:    8144/UDP + 8144/TCP
FALLBACK:   443/UDP (QUIC cover) + 443/TCP (TLS-wrapped)
STEALTH:    853/UDP (DoQ cover) + 853/TCP (DoT cover)
EMERGENCY:  80/TCP (WebSocket) + ICMP tunnel
```

**Consciousness States**:
- `DORMANT` → `AWAKENING` → `AWARE` → `SYNCHRONIZED` → `AUTONOMOUS`

### DSM - Decentralized Security Mesh

**Location**: `shared/dsm/`

Byzantine fault-tolerant consensus layer.

| File | Purpose |
|------|---------|
| `consensus.py` | BLS signature aggregation (2/3 quorum) |
| `gossip.py` | P2P threat announcement |
| `ledger.py` | Microblock chain storage |
| `validator.py` | Checkpoint verification |
| `node.py` | Edge node microblock creation |
| `merkle.py` | Merkle tree verification |
| `identity.py` | Node identity management |

### Response - Automated Threat Mitigation

**Location**: `shared/response/`

Kali Linux on-demand for automated response.

| File | Purpose |
|------|---------|
| `attack-mitigation-orchestrator.sh` | Main orchestrator |
| `kali-scripts.sh` | Kali tooling |
| `mitigation-maintenance.sh` | Maintenance tasks |

---

## Product Tiers

### Guardian - Travel Companion

**Location**: `products/guardian/`

Portable security gateway for travelers.

**Architecture**:
- **Backend**: `lib/` - Python modules for agent, detection, mesh
- **Web UI**: `web/` - Flask app with modular blueprints (Forty-inspired)
- **Config**: `config/` - WiFi (hostapd), DHCP (dnsmasq)

**Web UI Design** (Forty-inspired premium theme):
- **Template Reference**: `assets/forty/` - HTML5UP Forty template
- **Color Palette**:
  - Prussian Blue `#002742` (background)
  - Siren `#850033` (danger/alerts)
  - Tangerine `#e69500` (accent/highlights)
  - Ebb `#e6dbdb` (text)
  - Black Pearl `#02040d` (dark elements)
- **Key Features**:
  - Full-screen overlay menu (Forty-style)
  - Tab-based single-page app navigation
  - SVG icons for each menu item
  - Mobile-first responsive design
  - Premium cards, buttons, and forms

**Web UI Files**:
- `web/static/css/main.css` - Complete Forty-inspired stylesheet
- `web/static/js/main.js` - Tab navigation, API calls, menu control
- `web/templates/base.html` - Main layout with full-screen menu

**Web UI Modules** (`web/modules/`):
- `core/` - Main dashboard
- `clients/` - Connected devices
- `dnsxai/` - DNS protection settings
- `security/` - Security metrics + Qsecbit
- `config/` - Network configuration
- `system/` - System status
- `vpn/` - VPN management
- `debug/` - Browser CLI terminal
- `cortex/` - 3D globe visualization (embedded)

**Key Libraries**:
```python
from products.guardian.lib.guardian_agent import GuardianAgent
from products.guardian.lib.mesh_integration import GuardianMeshAgent
from products.guardian.lib.layer_threat_detector import LayerThreatDetector
```

**Cortex Integration**:
- Template: `web/templates/cortex/embedded.html`
- Route: `/cortex-modules/<filename>` serves shared modules
- Install path: `/opt/hookprobe/shared/cortex/frontend/js/`
- Setup: `scripts/setup.sh` copies modules during installation

### Fortress - Small Business Security

**Location**: `products/fortress/`

Enterprise-grade security for small businesses (flower shops, bakeries, retail, trades).

**Target Market**:
- Sole traders and small businesses
- Need professional security without enterprise complexity
- POS systems, guest WiFi, staff networks
- GDPR compliance requirements

**Architecture**:
- **Backend**: `lib/` - Python modules (extends Guardian)
- **Web UI**: `web/` - Flask app with AdminLTE 3.x dashboard
- **QSecBit**: `qsecbit/` - Fortress-enhanced agent with VLAN/MACsec monitoring
- **Config**: OVS bridge, VLANs, VXLAN tunnels

**What Fortress Adds Over Guardian**:

| Feature | Guardian | Fortress |
|---------|----------|----------|
| **Web UI** | Single-user | Multi-user with auth |
| **VLANs** | Basic | Full segmentation (5 VLANs) |
| **Reporting** | Basic stats | Business reports |
| **Dashboard** | Forty theme | AdminLTE professional |
| **Authentication** | None | Username/password + roles |

**Web UI Design** (AdminLTE 3.x):
- **Template**: AdminLTE 3.x (Bootstrap 4)
- **Color Palette**: Same HookProbe branding
- **Key Features**:
  - User authentication (admin, operator, viewer roles)
  - Sidebar navigation
  - Professional dark theme
  - DataTables for device management
  - Business reporting

**Web UI Files**:
- `web/app.py` - Flask application factory with Flask-Login
- `web/modules/auth/` - Authentication (login, logout, user management)
- `web/modules/dashboard/` - Main dashboard with widgets
- `web/modules/security/` - QSecBit and threat detection
- `web/modules/clients/` - Device management with VLAN assignment
- `web/modules/networks/` - VLAN configuration UI
- `web/modules/dnsxai/` - DNS protection with per-VLAN policies
- `web/modules/reports/` - Business reporting
- `web/modules/settings/` - System settings, user management
- `web/templates/base.html` - AdminLTE base layout

**Web UI Modules** (`web/modules/`):
- `auth/` - Login, logout, user management
- `dashboard/` - Main overview with widgets
- `security/` - QSecBit, threats, layer stats
- `clients/` - Device inventory with VLAN assignment
- `networks/` - VLAN configuration
- `dnsxai/` - DNS protection settings
- `reports/` - Weekly reports, device inventory
- `settings/` - System config, user management
- `api/` - REST API endpoints

**VLAN Configuration** (default):

| VLAN | ID | Purpose |
|------|-----|---------|
| Management | 10 | Admin devices |
| POS | 20 | Payment terminals |
| Staff | 30 | Employee devices |
| Guest | 40 | Customer WiFi |
| IoT | 99 | Cameras, sensors |

**Development Plan**: See `products/fortress/DEVELOPMENT_PLAN.md`

### MSSP - Cloud Federation Platform

**Location**: `products/mssp/`

Multi-tenant cloud platform at mssp.hookprobe.com.

**Architecture**:
- **Backend**: Django with multiple apps
- **API**: REST APIs with DRF
- **Services**: VPN, SDN, monitoring, CMS

**Django Apps** (`web/apps/`):

| App | Purpose |
|-----|---------|
| `admin_dashboard/` | Admin UI, AI content services |
| `cms/` | Content management system |
| `dashboard/` | Main user dashboard |
| `devices/` | Device management API |
| `monitoring/` | System monitoring |
| `mssp_dashboard/` | MSSP-specific views |
| `sdn/` | SDN management API |
| `security/` | Security features API |
| `vpn/` | VPN services (profiles, certs) |
| `merchandise/` | Product catalog |

**Management Commands**:
```bash
python manage.py seed_demo_data    # CMS demo content
python manage.py seed_ai_content   # AI-generated content
python manage.py seed_merchandise  # Product catalog
```

---

## Cortex Visualization

### HookProbe Cortex - Neural Command Center

**Location**: `shared/cortex/`
**Status**: Phase 2 Complete (City View with Deck.gl + MapLibre GL)
**Branding**: "Cortex" - The mesh's digital twin visualization

HookProbe Cortex is the **Neural Command Center** - a real-time 3D digital twin of the entire defense mesh. This is not just a dashboard showing data *about* the mesh - it *IS* the mesh visualized.

**Tagline**: *See your mesh. Command your defense.*

**Architecture**:
```
┌─────────────────────────────────────────────────────────────┐
│                     Frontend (Browser)                       │
│  ┌─────────────────────────────────────────────────────────┐│
│  │  Globe.gl (Three.js wrapper)                            ││
│  │  - 3D Earth rendering with night texture                ││
│  │  - Arc animations for attacks (red) / repelled (blue)   ││
│  │  - Point markers for nodes (color = Qsecbit status)     ││
│  │  - Demo/Live mode toggle                                ││
│  └─────────────────────────────────────────────────────────┘│
│                          ▲ WebSocket                         │
└──────────────────────────┼──────────────────────────────────┘
                           │
┌──────────────────────────┼──────────────────────────────────┐
│                     Backend (Python)                         │
│  ┌─────────────────────────────────────────────────────────┐│
│  │  GlobeServer (WebSocket + REST API)                     ││
│  │       ▲                                                 ││
│  │       │                                                 ││
│  │  ConnectorManager (aggregates all product connectors)   ││
│  │       ▲                                                 ││
│  │       ├── GuardianConnector (Flask integration)         ││
│  │       ├── FortressConnector (DSM participation)         ││
│  │       ├── NexusConnector (ML/AI metrics)                ││
│  │       └── MSSPConnector (Django integration)            ││
│  │                                                         ││
│  │  HTP Bridge → core/htp/ (mesh participant)              ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

**Key Files**:

| File | Purpose |
|------|---------|
| `backend/server.py` | WebSocket server with demo/live toggle |
| `backend/node_registry.py` | NodeTwin digital twin state management |
| `backend/htp_bridge.py` | HTP mesh participant skeleton |
| `backend/demo_data.py` | Simulated threat events |
| `backend/connectors/base.py` | ProductConnector base class |
| `backend/connectors/manager.py` | ConnectorManager aggregator |
| `backend/connectors/guardian.py` | Guardian Flask integration |
| `backend/connectors/fortress.py` | Fortress DSM integration |
| `backend/connectors/nexus.py` | Nexus ML/AI integration |
| `backend/connectors/mssp.py` | MSSP Django integration |
| `frontend/js/globe.js` | Globe.gl initialization with clustering |
| `frontend/js/data-stream.js` | WebSocket client with mode switching |
| `frontend/js/cluster-manager.js` | **Phase 1**: Supercluster spatial clustering |
| `frontend/js/zoom-controller.js` | **Phase 1**: Camera control and zoom transitions |
| `frontend/js/transitions.js` | **Phase 1**: Cluster expand/collapse animations |
| `frontend/js/deck-renderer.js` | **Phase 2**: Deck.gl GPU-accelerated renderer |
| `frontend/js/basemap-config.js` | **Phase 2**: MapLibre dark theme configuration |
| `frontend/js/view-manager.js` | **Phase 2**: Globe ↔ Map view transitions |
| `frontend/js/city-view.js` | **Phase 2**: City-level UI (search, filters, popups) |
| `frontend/css/city-view.css` | **Phase 2**: City view styling |
| `PHASE2-CITY-VIEW.md` | Phase 2 architecture documentation |

### Product Connector Integration

Each HookProbe product tier has a dedicated connector for the globe visualization:

**GuardianConnector** (`connectors/guardian.py`):
```python
from visualization.globe.backend.connectors.guardian import create_flask_connector

# In products/guardian/web/app.py
globe_connector = create_flask_connector(
    app,
    node_id="guardian-home-001",
    lat=37.7749,
    lng=-122.4194,
    label="Home Guardian"
)

@app.before_first_request
async def start_globe():
    await globe_connector.start()
```

**FortressConnector** (`connectors/fortress.py`):
```python
from visualization.globe.backend.connectors.fortress import create_fortress_connector

# Creates edge router connector with DSM participation
connector = create_fortress_connector(
    node_id="fortress-dc-001",
    lat=40.7128,
    lng=-74.0060,
    label="NYC Fortress",
    dsm_enabled=True
)
```

**NexusConnector** (`connectors/nexus.py`):
```python
from visualization.globe.backend.connectors.nexus import create_nexus_connector

# Creates ML/AI compute connector
connector = create_nexus_connector(
    node_id="nexus-ml-001",
    lat=37.3861,
    lng=-122.0839,
    label="Mountain View Nexus"
)
```

**MSSPConnector** (`connectors/mssp.py`):
```python
from visualization.globe.backend.connectors.mssp import create_django_connector

# In products/mssp/web/settings.py
GLOBE_CONNECTOR = create_django_connector()
```

### Demo/Live Mode Toggle

The visualization supports switching between demo and live data:

- **Demo Mode**: Generates simulated events for visual testing
- **Live Mode**: Receives real events from product connectors

Toggle via UI or API:
```bash
# REST API
curl -X POST http://localhost:8766/api/mode -d '{"mode": "live"}'

# WebSocket message
{"type": "set_mode", "mode": "demo"}
```

**Quick Start**:
```bash
# Backend (demo mode)
cd shared/cortex/backend
pip install -r requirements.txt
python server.py --demo

# Frontend (separate terminal)
cd shared/cortex/frontend
python -m http.server 8080
# Open http://localhost:8080
```

**Event Types**:

| Event | Color | Description |
|-------|-------|-------------|
| `attack_detected` | Red arc | Incoming attack trajectory |
| `attack_repelled` | Blue arc | Successfully mitigated attack |
| `node_status` | Point color | Node Qsecbit status (green/amber/red) |
| `snapshot` | N/A | Full state snapshot on connect |
| `mode_changed` | N/A | Demo/Live mode switch notification |

**Node Tiers** (visual representation):

| Tier | Size | Color | Description |
|------|------|-------|-------------|
| Sentinel | 0.3 | Gray | IoT validators |
| Guardian | 0.5 | Blue | Portable gateways |
| Fortress | 0.8 | Green | Edge routers |
| Nexus | 1.2 | Amber | ML/AI compute |

---

## End-to-End (E2E) Security Flow

### Attack Detection → Response → Propagation Pipeline

This section documents the complete E2E flow when an attack is detected, how it propagates through the mesh, and how consensus is achieved.

**Version**: 5.2
**Last Updated**: 2025-12-13

### E2E Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           HOOKPROBE E2E SECURITY FLOW                            │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │  DETECTION  │───▶│   SCORING   │───▶│  RESPONSE   │───▶│ PROPAGATION │      │
│  │  (Qsecbit)  │    │   (RAG)     │    │  (XDP/FW)   │    │   (Mesh)    │      │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘      │
│         │                  │                  │                  │              │
│         ▼                  ▼                  ▼                  ▼              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │    DSM      │◀──▶│    HTP      │◀──▶│   NEURO     │◀──▶│   CORTEX    │      │
│  │ (Consensus) │    │ (Transport) │    │   (Auth)    │    │   (Visual)  │      │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘      │
│                                                                                  │
│  Product Tiers:  SENTINEL ──▶ GUARDIAN ──▶ FORTRESS ──▶ NEXUS ──▶ MSSP        │
│                  (Validate)   (Detect)     (Route)      (ML)      (Aggregate)   │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Component Roles in E2E Flow

| Component | Role | Key Files |
|-----------|------|-----------|
| **Qsecbit** | Detection & scoring | `core/qsecbit/qsecbit.py`, `unified_engine.py` |
| **HTP** | Secure transport | `core/htp/transport/htp.py` |
| **DSM** | Consensus & ledger | `shared/dsm/consensus.py`, `node.py` |
| **Neuro** | Neural authentication | `core/neuro/core/ter.py`, `posf.py` |
| **Mesh** | Communication layer | `shared/mesh/unified_transport.py` |
| **Response** | Automated mitigation | `shared/response/`, `core/qsecbit/response/` |
| **Cortex** | Visualization | `shared/cortex/backend/server.py` |

### Phase 1: Attack Detection (Qsecbit)

**Detection Layers (L2-L7):**

```python
# core/qsecbit/detectors/ - 7 OSI layer detectors
L2DataLinkDetector   → ARP spoofing, MAC flooding, Evil Twin, Rogue DHCP
L3NetworkDetector    → IP spoofing, ICMP flood, Smurf attack, Fragmentation
L4TransportDetector  → SYN flood, Port scan, TCP reset, Session hijacking
L5SessionDetector    → SSL strip, TLS downgrade, Cert pinning bypass
L7ApplicationDetector → SQL injection, XSS, DNS tunneling, Malware C2
```

**Qsecbit Scoring Formula:**

```python
Qsecbit = α·drift + β·p_attack + γ·decay + δ·q_drift + ε·energy_anomaly

# Default weights (Guardian):
α = 0.30  # System drift (Mahalanobis distance)
β = 0.30  # Attack probability (ML classifier)
γ = 0.20  # Classifier decay
δ = 0.20  # Quantum drift (entropy deviation)
ε = 0.15  # Energy anomaly (RAPL monitoring)

# Layer-weighted formula:
Qsecbit = 0.25·L2 + 0.10·L3 + 0.10·L4 + 0.25·L5 + 0.10·L7 + 0.10·energy + 0.05·behavioral + 0.05·correlation
```

**RAG Status Thresholds:**

| Status | Score Range | Action Triggered |
|--------|-------------|------------------|
| **GREEN** | < 0.45 | Normal, learning baseline |
| **AMBER** | 0.45 - 0.70 | Warning, prepare Kali container |
| **RED** | ≥ 0.70 | Critical, full mitigation |

### Phase 2: Automated Response

**Response Orchestrator Actions:**

| Action | Implementation | Trigger Severity |
|--------|----------------|------------------|
| `BLOCK_IP` | XDP kernel-level / iptables | HIGH, CRITICAL |
| `BLOCK_MAC` | ebtables | MEDIUM+ |
| `RATE_LIMIT` | XDP tc qdisc | SYN_FLOOD, UDP_FLOOD |
| `ALERT` | Write to alerts.json | ALL |
| `TERMINATE_SESSION` | conntrack -D | SESSION_HIJACK |
| `QUARANTINE` | SDN isolation (via OVS) | MALWARE_C2 |
| `HONEYPOT_REDIRECT` | iptables REDIRECT | PORT_SCAN |

**Response Flow:**

```
ThreatEvent detected
    ↓
ResponseOrchestrator.respond(threat)
    ↓
├─ Get actions from DEFAULT_RESPONSE_MAP[attack_type]
├─ Execute each action:
│   ├─ BLOCK_IP → XDPManager.block_ip() or iptables
│   ├─ RATE_LIMIT → XDPManager.rate_limit()
│   └─ ALERT → _write_alert_file()
├─ Mark threat.blocked = True
└─ Return List[ResponseResult]
```

### Phase 3: Mesh Propagation

**Threat Intelligence Flow:**

```
Guardian detects threat
    ↓
QsecbitMeshBridge.report_threat(threat)
    ↓
├─ Convert to ThreatIntelligence
│   (intel_id, source_node, timestamp, threat_type, severity, ioc_type, ioc_value)
├─ Add to threat_cache (10K entries, LRU)
├─ Queue in _pending_gossip
└─ Create Cortex event (if callbacks registered)
    ↓
_gossip_loop() (every 5s)
    ↓
├─ For each connected peer:
│   ├─ Skip if peer in seen_by
│   ├─ Skip if hop_count ≥ 5
│   └─ transport.gossip(intel.to_bytes())
└─ PacketType.GOSSIP via UnifiedTransport
    ↓
Remote Node Receives
    ↓
├─ Dedup check (by intel_id)
├─ Add to local threat_cache
├─ intel.hop_count += 1
├─ Re-gossip if hop_count < 5
└─ Trigger local defense callbacks
```

**Mesh Packet Types:**

| Type | Code | Purpose |
|------|------|---------|
| `GOSSIP` | 0x32 | Threat intelligence propagation |
| `MICROBLOCK` | 0x30 | DSM microblock announcement |
| `CHECKPOINT` | 0x31 | Validator checkpoint broadcast |
| `SECURITY_EVENT` | 0x42 | Direct threat report |
| `CONSENSUS_VOTE` | 0x33 | BLS signature contribution |

### Phase 4: DSM Consensus

**Microblock Creation:**

```
ThreatEvent (from Qsecbit)
    ↓
DSMNode.create_microblock(event_type='threat_intel', payload=threat.to_bytes())
    ↓
├─ Increment sequence counter
├─ Hash payload (SHA-256)
├─ Sign with TPM (or RSA fallback)
├─ Calculate block ID
├─ Store in LevelDB ledger
└─ Announce via gossip protocol
```

**Checkpoint Consensus (Validators):**

```
Validators collect announced microblocks (5-minute epochs)
    ↓
Build Merkle tree from microblock IDs
    ↓
Create checkpoint:
  - merkle_root
  - included_ranges (node_id → seq range)
  - validator signature
    ↓
Broadcast to validator quorum
    ↓
ConsensusEngine.collect_signatures()
    ↓
├─ Gather signatures from validators
├─ Verify each signature
├─ Check 2/3 quorum (BFT threshold)
├─ Aggregate via BLS (RSA fallback)
├─ Commit finalized checkpoint
└─ Broadcast to all nodes
```

**Quorum Calculation:**

```python
def bft_quorum_required(total_validators: int) -> int:
    f = (total_validators - 1) // 3  # Byzantine tolerance
    return total_validators - f

# Examples:
# 10 validators → requires 7 (tolerates 3 Byzantine)
# 7 validators → requires 5 (tolerates 2 Byzantine)
```

### Phase 5: Neuro Authentication

**TER (Telemetry Event Record) Structure:**

```
H_Entropy    (32 bytes) - SHA256(CPU, memory, network, disk metrics)
H_Integrity  (20 bytes) - RIPEMD160(kernel, binary, config hashes)
Timestamp    (8 bytes)  - Unix microseconds
Sequence     (2 bytes)  - Monotonic counter
Chain_Hash   (2 bytes)  - CRC16(previous TER)
Total: 64 bytes fixed
```

**PoSF (Proof of Sensor Fusion) Verification:**

```
Message Hash + Nonce → NeuralEngine.forward() → Signature
    ↓
Cloud replays TER sequence
    ↓
Simulates weight evolution: W(t+1) = W(t) - η × ∇L(W(t), TER)
    ↓
Compares fingerprint: W_edge == W_simulated
    ↓
If mismatch: QUARANTINE (weight tampering detected)
```

**Resonance States:**

```
UNALIGNED → SEEKING → ALIGNED → DRIFTING → LOST
     │          │         │          │         │
  Initial   Handshake   Active   Drift>5%   Reconnect
```

### E2E Validation Checklist

Use this checklist to verify complete E2E flow:

```
[ ] DETECTION
    [ ] Detector identifies threat (Suricata/Zeek/ML)
    [ ] ThreatEvent created with all required fields
    [ ] Confidence score is realistic (0.0-1.0)
    [ ] Evidence dictionary populated
    [ ] MITRE ATT&CK ID assigned

[ ] SCORING
    [ ] Threat incorporated into layer score
    [ ] Unified Qsecbit score updated
    [ ] RAG status reflects severity
    [ ] Convergence rate calculated
    [ ] Trend analysis (IMPROVING/STABLE/DEGRADING)

[ ] RESPONSE
    [ ] ResponseOrchestrator.respond() called
    [ ] Appropriate ResponseAction(s) executed
    [ ] threat.blocked = True if successful
    [ ] ResponseResult logged
    [ ] Blocked IPs persisted (response_state.json)

[ ] PROPAGATION
    [ ] Threat converted to ThreatIntelligence
    [ ] Reported to mesh consciousness
    [ ] Cortex visualization event emitted
    [ ] DSM microblock created
    [ ] HTP encrypted transport used

[ ] CONSENSUS
    [ ] Microblock announced via gossip
    [ ] Validators collect blocks
    [ ] Merkle tree built
    [ ] Checkpoint created with signatures
    [ ] 2/3 quorum achieved
    [ ] Finalized checkpoint broadcast

[ ] NEURO AUTH
    [ ] TER generated with valid entropy
    [ ] Weight evolution applied
    [ ] PoSF signature created
    [ ] RDV (Resonance Drift Vector) validated
    [ ] Channel binding active

[ ] STORAGE
    [ ] ThreatEvent serialized to JSON
    [ ] QsecbitUnifiedScore saved to database
    [ ] Microblock stored in LevelDB
    [ ] Checkpoint persisted
    [ ] Audit trail in merkle_log
```

### Product Tier Integration

**Sentinel (256MB - IoT Validator):**
- Validates microblocks (timestamp, sequence, source)
- Contributes partial BLS signatures
- Maintains compact threat cache (100 entries)
- Gossip receive-only mode (bandwidth optimization)

**Guardian (1.5GB - Travel Companion):**
- Full L2-L7 detection pipeline
- Local Qsecbit scoring
- Dual-path: P2P mesh + MSSP uplink
- Collective score aggregation
- Autonomous defense (AUTONOMOUS state)

**Fortress (4GB - Edge Router):**
- Regional consensus coordinator
- Full DSM participation
- Microblock → Checkpoint aggregation
- SDN rule distribution

**Nexus (16GB+ - ML/AI Compute):**
- Federated ML model training
- Pattern correlation across mesh
- Predictive threat escalation
- Advanced behavioral analysis

**MSSP (16GB+ - Central Brain):**
- Multi-tenant aggregation
- Cross-tenant deduplication
- Historical threat database
- Dashboard and reporting

### Key Integration Files

| Integration | File | Key Method |
|-------------|------|------------|
| Detection → Scoring | `core/qsecbit/unified_engine.py` | `detect()` |
| Scoring → Response | `core/qsecbit/response/orchestrator.py` | `respond()` |
| Response → Mesh | `core/qsecbit/mesh_bridge.py` | `report_threat()` |
| Mesh → DSM | `shared/dsm/node.py` | `create_microblock()` |
| DSM → Consensus | `shared/dsm/consensus.py` | `collect_validator_signatures()` |
| Mesh → Cortex | `shared/cortex/backend/connectors/` | `report_threat()` |
| HTP → Neuro | `shared/mesh/neuro_encoder.py` | `generate_rdv()` |
| Neuro → TER | `core/neuro/core/ter.py` | `generate()` |

### Running E2E Tests

```bash
# Run E2E integration test
pytest tests/test_e2e_integration.py -v

# Test specific flow
pytest tests/test_e2e_integration.py::test_attack_detection_to_mesh_propagation -v

# Test with coverage
pytest tests/test_e2e_integration.py --cov=core --cov=shared --cov-report=html
```

---

## Testing Guide

### Test Location

All tests are in `tests/`:

```
tests/
├── __init__.py
├── test_qsecbit.py              # Qsecbit algorithm tests
├── test_htp_e2e.py              # HTP end-to-end tests
├── test_htp_keyless.py          # Keyless protocol tests
└── test_htp_security_enhancements.py
```

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with verbose output
pytest tests/ -vv

# Run with coverage
pytest tests/ --cov=core --cov=shared --cov-report=html

# Run specific test file
pytest tests/test_qsecbit.py

# Run by marker
pytest tests/ -m "unit"           # Unit tests only
pytest tests/ -m "integration"    # Integration tests
pytest tests/ -m "not slow"       # Skip slow tests

# Using Makefile
make test                         # Run all tests
make test-verbose                 # Verbose output
make test-coverage                # With coverage
make test-fast                    # Skip slow tests
```

### Test Markers

```python
@pytest.mark.unit          # Unit tests
@pytest.mark.integration   # Integration tests
@pytest.mark.slow          # Long-running tests
@pytest.mark.security      # Security-related tests
@pytest.mark.network       # Network configuration tests
@pytest.mark.htp           # HTP protocol tests
@pytest.mark.qsecbit       # Qsecbit algorithm tests
```

### Coverage Requirements

- **Minimum**: 30% (configured in `pytest.ini`)
- **Coverage paths**: `core/`, `shared/`
- **Report formats**: HTML + terminal

---

## CI/CD Workflows

**Location**: `.github/workflows/`

| Workflow | File | Purpose |
|----------|------|---------|
| **Python Lint** | `python-lint.yml` | Black, flake8, bandit |
| **App Tests** | `app-tests.yml` | Django, Nginx, addon validation |
| **Container Tests** | `container-tests.yml` | Container build/run |
| **Installation Test** | `installation-test.yml` | Install script validation |
| **ARM64 Tests** | `arm64-tests.yml` | ARM64 architecture |
| **Documentation** | `documentation.yml` | Markdown link checking |
| **Config Validation** | `config-validation.yml` | Config file validation |
| **CI Status** | `ci-status.yml` | Overall CI health check |

### Debugging CI Failures

```bash
# Python lint failures
make lint
black --check core/ shared/
flake8 core/ shared/

# Test failures
pytest tests/ -vv --tb=long

# Shell script failures
make validate
shellcheck products/**/*.sh deploy/**/*.sh
```

---

## Development Tooling

### Makefile Commands

```bash
# Setup
make install          # Install Python dependencies
make install-dev      # Install dev dependencies
make setup            # Complete dev environment

# Testing
make test             # Run all tests
make test-verbose     # Verbose output
make test-coverage    # With coverage report
make test-fast        # Skip slow tests

# Code Quality
make lint             # Run all linters
make format           # Format Python code
make security         # Security scan (bandit)
make check            # Lint + test

# Deployment
make deploy-sentinel  # Deploy Sentinel tier
make deploy-guardian  # Deploy Guardian tier
make deploy-fortress  # Deploy Fortress tier
make deploy-nexus     # Deploy Nexus tier
make deploy-mssp      # Deploy MSSP tier

# Status
make status           # Show deployment status
make logs             # Show recent logs
make health           # Service health check

# Cleanup
make clean            # Remove generated files
make validate         # Validate shell scripts
make validate-repo    # Repository cleanup validator
make version          # Show version info
```

### Pre-commit Hooks

Configuration: `.pre-commit-config.yaml`

**Installed Hooks**:
- `trailing-whitespace`, `end-of-file-fixer`
- `check-yaml`, `check-json`
- `detect-private-key`
- `shellcheck` - Bash linting
- `black`, `isort` - Python formatting
- `flake8`, `bandit` - Python linting/security
- `markdownlint`, `yamllint`

**Installation**:
```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

---

## Scenario-Based Guidance

### Adding DNS Protection Features

```bash
# 1. Read dnsXai documentation
cat shared/dnsXai/README.md

# 2. Check current engine
cat shared/dnsXai/engine.py

# 3. Add new detection logic
nano shared/dnsXai/engine.py

# 4. Update mesh intelligence
nano shared/dnsXai/mesh_intelligence.py

# 5. Test integration
python -m shared.dnsXai.engine --classify test-domain.com
```

### Working with Mesh Communication

```bash
# 1. Read mesh architecture (ESSENTIAL!)
cat shared/mesh/ARCHITECTURE.md

# 2. Check NAT traversal
cat shared/mesh/nat_traversal.py

# 3. Check consciousness states
cat shared/mesh/consciousness.py

# 4. Work with unified transport
cat shared/mesh/unified_transport.py
```

### Adding Guardian Web UI Feature

```bash
# 1. Create new blueprint module
mkdir products/guardian/web/modules/new_feature
touch products/guardian/web/modules/new_feature/__init__.py
touch products/guardian/web/modules/new_feature/views.py

# 2. Register blueprint in app.py
nano products/guardian/web/app.py

# 3. Create templates
mkdir products/guardian/web/templates/new_feature
nano products/guardian/web/templates/new_feature/index.html
```

### Adding Fortress Web UI Feature

```bash
# 1. Create new blueprint module (similar to Guardian but with AdminLTE)
mkdir products/fortress/web/modules/new_feature
touch products/fortress/web/modules/new_feature/__init__.py
touch products/fortress/web/modules/new_feature/views.py

# 2. Add @login_required decorator for authentication
# In views.py:
from flask_login import login_required
from ..auth.decorators import admin_required  # For admin-only pages

@new_feature_bp.route('/')
@login_required
def index():
    return render_template('new_feature/index.html')

# 3. Register blueprint in modules/__init__.py
nano products/fortress/web/modules/__init__.py

# 4. Create AdminLTE-based template
nano products/fortress/web/templates/new_feature/index.html
# Extend base.html which provides AdminLTE layout
```

### Fortress Development Workflow

```bash
# 1. Read the development plan
cat products/fortress/DEVELOPMENT_PLAN.md

# 2. Check existing Guardian module to port
ls products/guardian/web/modules/

# 3. Copy and adapt module
cp -r products/guardian/web/modules/security products/fortress/web/modules/
# Then add authentication decorators and AdminLTE template conversion

# 4. Run Fortress web UI (development)
cd products/fortress/web
pip install -r requirements.txt
python app.py  # Runs on https://localhost:8443

# Default login: admin / hookprobe (change immediately!)
```

### Adding MSSP Django App

```bash
# 1. Create Django app
cd products/mssp/web
python manage.py startapp new_app apps/new_app

# 2. Add to INSTALLED_APPS
nano settings.py

# 3. Create models, views, urls
nano apps/new_app/models.py
nano apps/new_app/views.py
nano apps/new_app/urls.py

# 4. Run migrations
python manage.py makemigrations
python manage.py migrate
```

### Working with Infrastructure

```bash
# 1. Check infrastructure docs
cat infrastructure/README.md

# 2. Email infrastructure
cat infrastructure/pod-009-email/README.md
cat infrastructure/pod-009-email/docker-compose.yml

# 3. DSM infrastructure
cat infrastructure/pod-010-dsm/README.md
```

---

## Key Conventions

### File Naming

| Type | Convention | Example |
|------|------------|---------|
| Python modules | `lowercase_underscore.py` | `qsecbit.py` |
| Shell scripts | `kebab-case.sh` | `install-edge.sh` |
| Config files | `kebab-case.conf/yaml` | `mitigation-config.conf` |
| Documentation | `UPPERCASE.md` | `README.md`, `CLAUDE.md` |

### Code Style

**Python** (PEP 8):
- Black formatting (line length 100)
- isort for imports (profile: black)
- Type hints for function signatures
- Google-style docstrings

**Bash**:
```bash
#!/bin/bash
set -e  # Exit on error
set -u  # Exit on undefined variable

# UPPERCASE for config variables
POSTGRES_PASSWORD="..."

# lowercase for local variables
local container_ip="10.200.1.10"
```

### Git Conventions

**Branch naming**:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation
- `security/` - Security updates
- `claude/` - AI-generated branches

**Commit format**:
```
type(scope): brief description

Detailed explanation

Fixes: #123
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `security`

---

## Security Considerations

### Critical Rules

1. **NEVER hardcode credentials**
2. **NEVER disable security features**
3. **ALWAYS validate input** in Python
4. **AVOID command injection**
5. **CHECK for secrets** before commit

### Sensitive Files

| File | Contains | Safe to Commit |
|------|----------|----------------|
| `deploy/*/config.sh` | Credentials | NO (with real values) |
| `*.py` | Logic only | YES |
| `*.sh` | Logic only | YES |
| `.env` files | Secrets | NO |
| `products/mssp/web/.env.example` | Template | YES |

### Security Testing

```bash
# Static analysis
shellcheck deploy/**/*.sh

# Python security scan
bandit -r core/ shared/ -ll

# Check for secrets
make security
```

---

## Troubleshooting

### Common Issues

| Issue | Diagnosis | Solution |
|-------|-----------|----------|
| Tests fail | Check pytest output | `pytest tests/ -vv --tb=long` |
| Lint errors | Run formatters | `make format` |
| Import errors | Check dependencies | `pip install -r requirements.txt` |
| CI failure | Run locally first | `make check` |
| Container issues | Check podman | `podman ps -a && podman logs <name>` |
| Guardian web 404 | Check blueprints | Verify module registered in `app.py` |
| MSSP Django errors | Check migrations | `python manage.py migrate` |

### Getting Help

1. **Check docs**: `docs/` directory, especially `DOCUMENTATION-INDEX.md`
2. **Read architecture**: `shared/mesh/ARCHITECTURE.md`
3. **Review tests**: `tests/` directory
4. **Search issues**: GitHub Issues
5. **Contact**: qsecbit@hookprobe.com (security only)

---

## Quick Reference

### Essential Paths

```
core/qsecbit/qsecbit.py          # Main security algorithm
core/htp/transport/htp.py        # HTP protocol
shared/dnsXai/engine.py          # DNS protection
shared/mesh/ARCHITECTURE.md      # Mesh architecture (MUST READ)
shared/mesh/unified_transport.py # Mesh transport API
products/guardian/web/app.py     # Guardian Flask app
products/mssp/web/apps/          # MSSP Django apps
shared/cortex/                   # Cortex - Neural Command Center
tests/                           # All tests
.github/workflows/               # CI/CD
```

### Essential Commands

```bash
make test           # Run tests
make lint           # Check code quality
make format         # Format code
pytest tests/ -vv   # Verbose tests
./install.sh --tier <tier>  # Deploy

# Guardian web UI (Flask)
cd products/guardian/web && python app.py

# MSSP web portal (Django)
cd products/mssp/web && python manage.py runserver

# Cortex visualization (demo mode)
cd shared/cortex/backend && python server.py --demo
```

---

**HookProbe v5.0** - Federated Cybersecurity Mesh
*One node's detection -> Everyone's protection*
