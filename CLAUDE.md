# CLAUDE.md - AI Assistant Guide for HookProbe

**Version**: 5.0
**Last Updated**: 2025-12-09
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
| **MSSP web portal** | Django app | `products/mssp/web/` |
| **NAT traversal** | Mesh networking | `shared/mesh/nat_traversal.py` |
| **Email infrastructure** | Infrastructure pod | `infrastructure/pod-009-email/` |
| **Cortex (3D Globe)** | Shared visualization | `shared/cortex/` |
| **Cortex connectors** | Product connectors | `shared/cortex/backend/connectors/` |
| **Add Cortex to Guardian** | Flask integration | `shared/cortex/backend/connectors/guardian.py` |
| **Add Cortex to MSSP** | Django integration | `shared/cortex/backend/connectors/mssp.py` |

---

## Table of Contents

- [Project Overview](#project-overview)
- [Licensing](#licensing)
- [Codebase Structure](#codebase-structure)
- [Core Modules](#core-modules)
- [Shared Infrastructure](#shared-infrastructure)
- [Product Tiers](#product-tiers)
- [Cortex Visualization](#cortex-visualization)
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

HookProbe is a **federated cybersecurity mesh** built for edge computing and distributed security. It provides:

- **AI-Powered Threat Detection**: Qsecbit algorithm for real-time security analysis
- **Federated Defense**: Privacy-preserving collective intelligence
- **Multi-Tier Products**: Sentinel, Guardian, Fortress, Nexus, MSSP
- **Zero Trust Mesh**: HTP protocol with post-quantum cryptography
- **AI DNS Protection**: dnsXai for ML-based ad/tracker blocking
- **Mesh Consciousness**: Collective threat intelligence sharing

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
| **Fortress** | 4GB | Edge Router | `products/fortress/` |
| **Nexus** | 16GB+ | ML/AI Compute | `products/nexus/` |
| **MSSP** | 16GB+ | Central Brain | `products/mssp/` |

---

## Licensing

HookProbe uses a **dual licensing model**. Understanding what license applies to which component is critical for AI assistants helping with the codebase.

### Open Source Components (AGPL v3.0)

These directories are open source and can be freely modified:

| Component | Location | License |
|-----------|----------|---------|
| Deployment Scripts | `deploy/` | AGPL v3.0 |
| Guardian Product | `products/guardian/` | AGPL v3.0 |
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
│   │   └── README.md                # Qsecbit documentation
│   │
│   └── neuro/                        # Neural Resonance Protocol
│       ├── README.md                # Neuro protocol docs
│       ├── requirements.txt         # Python dependencies
│       ├── attestation/
│       │   └── device_identity.py   # Device attestation
│       ├── audit/
│       │   └── merkle_log.py        # Audit logging
│       ├── core/
│       │   ├── ter.py               # Telemetry Event Record
│       │   ├── posf.py              # Proof of Secure Function
│       │   └── replay.py            # Replay protection
│       ├── identity/
│       │   └── hardware_fingerprint.py  # Hardware identity
│       ├── network/
│       │   └── nat_traversal.py     # NAT traversal
│       ├── neural/
│       │   ├── engine.py            # Neural weight evolution
│       │   └── fixedpoint.py        # Q16.16 fixed-point math
│       ├── storage/
│       │   └── dreamlog.py          # Offline TER storage
│       └── validation/
│           └── validator_network.py  # Validator network
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
│   │   │   ├── setup.sh
│   │   │   ├── uninstall.sh
│   │   │   └── update-blocklists.sh
│   │   └── web/                     # Flask Web UI
│   │       ├── app.py               # Main Flask app
│   │       ├── config.py
│   │       ├── utils.py
│   │       ├── modules/             # Blueprint modules
│   │       │   ├── clients/         # Connected clients
│   │       │   ├── config/          # Network config
│   │       │   ├── core/            # Dashboard
│   │       │   ├── dnsxai/          # DNS protection UI
│   │       │   ├── security/        # Security metrics
│   │       │   ├── system/          # System status
│   │       │   └── vpn/             # VPN management
│   │       ├── static/              # CSS/JS assets
│   │       └── templates/           # Jinja2 templates
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
├── assets/                           # IMAGES AND BRANDING
│   ├── readme.md
│   ├── hookprobe-logo.svg
│   ├── hookprobe-emblem.svg
│   ├── hookprobe-emblem-small.png
│   ├── hookprobe-protocol.png
│   ├── hookprobe-neuro-resonant-protocol.png
│   ├── hookprobe-future-ram-cine.png
│   ├── hookprobe-r&d.png
│   ├── qsecbit-catcher.png
│   └── xSOC-HLD-v1.2.png
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
- **Web UI**: `web/` - Flask app with modular blueprints
- **Config**: `config/` - WiFi (hostapd), DHCP (dnsmasq)

**Web UI Modules** (`web/modules/`):
- `core/` - Main dashboard
- `clients/` - Connected devices
- `dnsxai/` - DNS protection settings
- `security/` - Security metrics
- `config/` - Network configuration
- `system/` - System status
- `vpn/` - VPN management

**Key Libraries**:
```python
from products.guardian.lib.guardian_agent import GuardianAgent
from products.guardian.lib.mesh_integration import GuardianMeshAgent
from products.guardian.lib.layer_threat_detector import LayerThreatDetector
```

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
