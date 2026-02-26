# CLAUDE.md - AI Assistant Guide for HookProbe

**Version**: 5.9
**Last Updated**: 2026-01-07
**Purpose**: Comprehensive guide for AI assistants working with the HookProbe codebase

---

## Quick Lookup: When User Wants To...

| User Request | Go To | Key Files |
|-------------|-------|-----------|
| **Run tests** | `pytest tests/` | `pytest.ini`, `tests/test_*.py` |
| **Check code quality** | `make lint` | `.pre-commit-config.yaml`, `Makefile` |
| **Deploy Sentinel** | `./install.sh --tier sentinel` | `products/sentinel/` |
| **Deploy Guardian** | `./install.sh --tier guardian` | `products/guardian/` |
| **Deploy Fortress** | `./install.sh` (container mode) | `products/fortress/install.sh` |
| **Deploy Nexus** | `./install.sh --tier nexus` | `products/nexus/` |
| **Modify Qsecbit algorithm** | Edit core logic | `core/qsecbit/qsecbit.py` |
| **Add XDP/eBPF rules** | Edit XDP manager | `core/qsecbit/xdp_manager.py` |
| **Work with HTP protocol** | Core transport | `core/htp/transport/htp.py` |
| **Add DNS/Ad blocking** | dnsXai module | `shared/dnsXai/` |
| **dnsXai API server** | HTTP endpoints | `shared/dnsXai/api_server.py` |
| **dnsXai whitelist (wildcard)** | `*.domain.com` support | `shared/dnsXai/api_server.py` |
| **dnsXai DGA detection** | Malware C2 detection | `shared/dnsXai/engine.py` |
| **dnsXai DNS tunneling** | Exfiltration detection | `shared/dnsXai/engine.py` |
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
| **Fortress user auth** | Local auth (max 5) | `products/fortress/web/modules/auth/models.py` |
| **Fortress WiFi setup** | hostapd config | `products/fortress/devices/common/hostapd-generator.sh` |
| **Fortress network setup** | OVS VLAN, DHCP, NAT | `products/fortress/devices/common/ovs-post-setup.sh` |
| **Fortress containers** | Podman compose | `products/fortress/containers/podman-compose.yml` |
| **Device Groups (UI)** | Manual device organization | `products/fortress/web/modules/bubbles/views.py` |
| **D2D Bubble Algorithm** | Automatic relationship detection | `products/fortress/lib/ecosystem_bubble.py` |
| **Device Fingerprinting (ML)** | 99% accuracy classifier | `products/fortress/lib/ml_fingerprint_classifier.py` |
| **Behavioral Clustering** | DBSCAN D2D bubbles | `products/fortress/lib/behavior_clustering.py` |
| **Multi-Modal Presence** | mDNS, BLE, spatial | `products/fortress/lib/presence_sensor.py` |
| **mDNS Query/Response Pairing** | Device discovery tracking | `products/fortress/lib/presence_sensor.py` |
| **D2D Connection Graph** | NAPSE-based device affinity | `products/fortress/lib/connection_graph.py` |
| **Temporal Affinity Scoring** | Wake/sleep correlation | `products/fortress/lib/connection_graph.py` |
| **ClickHouse Graph Storage** | Device relationship persistence | `products/fortress/lib/clickhouse_graph.py` |
| **n8n Bubble Webhooks** | Workflow automation | `products/fortress/lib/n8n_webhook.py` |
| **Reinforcement Learning** | Learn from corrections | `products/fortress/lib/reinforcement_feedback.py` |
| **AI Autopilot (Efficiency)** | Event-driven device detection | `products/fortress/lib/autopilot/` |
| **DHCP Sentinel** | Low-power new device trigger | `products/fortress/lib/autopilot/dhcp_sentinel.py` |
| **OVS MAC Watcher** | Unknown device detection | `products/fortress/lib/autopilot/mac_watcher.py` |
| **On-Demand Probe** | 60s burst packet capture | `products/fortress/lib/autopilot/probe_service.py` |
| **IPFIX Collector** | Sampled D2D flow analysis | `products/fortress/lib/autopilot/ipfix_collector.py` |
| **Fingerbank API setup** | External enrichment | `products/fortress/docs/FINGERBANK-API-SETUP.md` |
| **NAT traversal** | Mesh networking | `shared/mesh/nat_traversal.py` |
| **Email infrastructure** | Infrastructure pod | `infrastructure/pod-009-email/` |
| **Cortex (3D Globe)** | Shared visualization | `shared/cortex/` |
| **Understand security fabric** | City-level visualization | `shared/cortex/README.md` (see "Understanding Your Security Fabric") |
| **Cortex connectors** | Product connectors | `shared/cortex/backend/connectors/` |
| **Add Cortex to Guardian** | Flask integration | `shared/cortex/backend/connectors/guardian.py` |
| **Guardian UI styling** | Forty-inspired CSS | `products/guardian/web/static/css/main.css` |
| **UI design reference** | HTML5UP Forty template | `assets/forty/` |
| **E2E security flow** | Attack detection→response→propagation | See [E2E Security Flow](#end-to-end-e2e-security-flow) |
| **E2E integration tests** | Full flow validation | `tests/test_e2e_integration.py` |
| **Mesh propagation** | Threat gossip protocol | `shared/mesh/consciousness.py` |
| **Response orchestration** | Automated mitigation | `core/qsecbit/response/orchestrator.py` |
| **WiFi DFS intelligence** | ML channel scoring | `shared/wireless/dfs_intelligence.py` |
| **WiFi channel scanning** | Congestion analysis | `shared/wireless/channel_scanner.py` |
| **hostapd-OVS patch** | Direct OVS bridge for WiFi | `shared/hostapd-ovs/build-hostapd-ovs.sh` |
| **hostapd-OVS integration** | OVS WiFi architecture | `shared/hostapd-ovs/README.md` |
| **Fortress LAN bridging** | OVS VLAN + DHCP | `products/fortress/install-container.sh` (search `setup_network`) |
| **Fortress device scripts** | Hardware profiles | `products/fortress/devices/common/` |
| **SLA AI / Business Continuity** | Intelligent failover | `shared/slaai/` |
| **WAN failover prediction** | LSTM predictor | `shared/slaai/predictor.py` |
| **Cost-aware failback** | Metered LTE tracking | `shared/slaai/cost_tracker.py` |
| **Adaptive DNS failover** | Multi-provider DNS | `shared/slaai/dns_intelligence.py` |
| **PBR integration** | Route switching | `shared/slaai/integrations/pbr.py` |
| **Fortress dual-WAN** | PBR failover | `products/fortress/devices/common/wan-failover-pbr.sh` |
| **AIOCHI (AI Eyes)** | Cognitive network layer | `shared/aiochi/` |
| **AIOCHI architecture** | Design docs | `shared/aiochi/ARCHITECTURE.md` |
| **AIOCHI containers** | Podman compose | `shared/aiochi/containers/podman-compose.aiochi.yml` |
| **AIOCHI + Fortress install** | Enable AI Eyes | `./install.sh --tier fortress --enable-aiochi` |
| **Ollama LLM integration** | Local AI reasoning | `shared/aiochi/containers/` (aiochi-ollama service) |
| **AIOCHI n8n workflows** | Agentic security | `shared/aiochi/n8n-workflows/` |
| **AIOCHI ClickHouse schema** | Event analytics | `shared/aiochi/schemas/clickhouse-init.sql` |
| **NAPSE IDS/NSM** | AI-native IDS engine | `core/napse/` |
| **NAPSE packet inspector** | Deep packet inspection | `core/napse/inspector/packet_inspector.py` |
| **NAPSE QSecBit scoring** | SENTINEL-aware scoring | `core/napse/qsecbit/qsecbit_engine.py` |
| **NAPSE ClickHouse schema** | IDS event tables | `core/napse/configs/clickhouse/init.sql` |
| **HYDRA threat intel** | Feed sync + SENTINEL pipeline | `core/hydra/` |
| **HYDRA feed sync** | Threat feed → XDP blocklist | `core/hydra/feed_sync.py` |
| **HYDRA anomaly detection** | Isolation Forest ML | `core/hydra/anomaly_detector.py` |
| **HYDRA SENTINEL lifecycle** | Self-learning IDS | `core/hydra/sentinel_lifecycle.py` |
| **HYDRA temporal memory** | Behavioral drift tracking | `core/hydra/temporal_memory.py` |
| **HYDRA RDAP enrichment** | IP ownership classification | `core/hydra/rdap_enricher.py` |
| **HYDRA Fortress containers** | IDS profile deployment | `products/fortress/containers/Containerfile.hydra` |
| **Guardian HYDRA lite** | Feed sync + event consumer only | `products/guardian/lib/hydra_lite.py` |
| **AEGIS AI reasoning** | 8-agent AI orchestrator | `core/aegis/` |
| **AEGIS XDP fast-path** | Zig XDP scaffolding (not AI) | `core/napse/aegis/` |
| **VIRE visualization** | hookprobe-com only (dashboard viz) | _Not in this codebase_ |
| **Community guidelines** | Code of Conduct | `CODE_OF_CONDUCT.md` |
| **Contributing** | Contribution guide | `docs/CONTRIBUTING.md` |
| **Security reporting** | Vulnerability disclosure | `docs/SECURITY.md` |

---

## Table of Contents

- [Project Overview](#project-overview)
- [Licensing](#licensing)
- [Codebase Structure](#codebase-structure)
- [Core Modules](#core-modules)
- [Shared Infrastructure](#shared-infrastructure)
- [AIOCHI - AI Eyes](#aiochi---ai-eyes)
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
- **Multi-Tier Products**: Sentinel, Guardian, Fortress, Nexus
- **Zero Trust Mesh**: HTP protocol with post-quantum cryptography
- **AI DNS Protection**: dnsXai for ML-based ad/tracker blocking
- **Mesh Consciousness**: Collective threat intelligence sharing
- **Adversarial Testing**: AI vs AI security validation

**Project Type**: Federated Security Platform / Infrastructure-as-Code
**Primary Languages**: Python (core logic), Bash (deployment)
**Web Frameworks**: Flask (Guardian, Fortress)
**Deployment**: Podman containers with OVS networking
**License**: Dual Licensed (AGPL v3.0 + Commercial) - see [Licensing](#licensing)

### Product Tiers

| Tier | RAM | Use Case | Location |
|------|-----|----------|----------|
| **Sentinel** | 256MB | IoT Validator | `products/sentinel/` |
| **Guardian** | 1.5GB | Travel/Portable | `products/guardian/` |
| **Fortress** | 4GB | Small Business | `products/fortress/` |
| **Nexus** | 16GB+ | ML/AI Compute | `products/nexus/` |

**Target Markets:**
- **Sentinel**: IoT devices, validators, lightweight edge nodes
- **Guardian**: Travelers, home users, portable protection
- **Fortress**: Small businesses (flower shops, bakeries, retail, trades)
- **Nexus**: AI/ML workloads, regional compute hubs

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
| **SLA AI Business Continuity** | `shared/slaai/` | Proprietary |
| **AIOCHI (AI Eyes) Cognitive Layer** | `shared/aiochi/` | Proprietary |
| **Ecosystem Bubble (Atmospheric Presence)** | `products/fortress/lib/ecosystem_bubble.py` | Proprietary |
| **ML Fingerprint Classifier** | `products/fortress/lib/ml_fingerprint_classifier.py` | Proprietary |
| **Behavioral Clustering Engine** | `products/fortress/lib/behavior_clustering.py` | Proprietary |
| **Presence Sensor (Multi-Modal)** | `products/fortress/lib/presence_sensor.py` | Proprietary |
| **D2D Connection Graph** | `products/fortress/lib/connection_graph.py` | Proprietary |
| **ClickHouse Graph Storage** | `products/fortress/lib/clickhouse_graph.py` | Proprietary |
| **n8n Webhook Integration** | `products/fortress/lib/n8n_webhook.py` | Proprietary |
| **Reinforcement Learning Feedback** | `products/fortress/lib/reinforcement_feedback.py` | Proprietary |
| **AI Autopilot (Efficiency Engine)** | `products/fortress/lib/autopilot/` | Proprietary |

### Usage Guidelines

| Use Case | License Required |
|----------|------------------|
| Personal/Home use | Free (AGPL + personal use of proprietary) |
| Internal business protection | Free (AGPL + internal use of proprietary) |
| SaaS offering | Commercial License Required |
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
│   ├── wireless/                     # WIRELESS & DFS INTELLIGENCE
│   │   ├── __init__.py              # Module exports
│   │   ├── channel_scanner.py       # WiFi channel scanning
│   │   ├── dfs_intelligence.py      # ML-powered DFS channel scoring
│   │   └── containers/              # Containerized DFS API
│   │       └── dfs-intelligence/
│   │           └── dfs_api_server.py
│   │
│   ├── hostapd-ovs/                  # HOSTAPD OVS BRIDGE PATCH
│   │   ├── build-hostapd-ovs.sh     # Build & install script
│   │   └── README.md                # Integration documentation
│   │
│   ├── cortex/                       # HOOKPROBE CORTEX - Neural Command Center
│   │   ├── README.md                # Documentation
│   │   ├── ARCHITECTURE.md          # HTP integration analysis
│   │   ├── backend/
│   │   │   ├── server.py            # WebSocket server with demo/live toggle
│   │   │   ├── node_registry.py     # NodeTwin state management
│   │   │   ├── htp_bridge.py        # HTP mesh participant
│   │   │   ├── demo_data.py         # Demo event generator
│   │   │   ├── geo_resolver.py      # IP geolocation
│   │   │   └── connectors/          # Product tier connectors
│   │   │       ├── base.py          # ProductConnector base class
│   │   │       ├── manager.py       # ConnectorManager aggregator
│   │   │       ├── guardian.py      # Guardian Flask integration
│   │   │       ├── fortress.py      # Fortress DSM integration
│   │   │       └── nexus.py         # Nexus ML/AI integration
│   │   ├── frontend/
│   │   │   ├── index.html           # Cortex main page
│   │   │   ├── css/globe.css        # Premium styling
│   │   │   └── js/
│   │   │       ├── globe.js         # Globe.gl visualization
│   │   │       ├── data-stream.js   # WebSocket client
│   │   │       ├── animations.js    # Premium effects engine
│   │   │       └── fallback-2d.js   # Mobile 2D fallback
│   │   └── tests/
│   │       └── test_globe_backend.py
│   │
│   └── slaai/                        # SLA AI - BUSINESS CONTINUITY ENGINE
│       ├── ARCHITECTURE.md          # Comprehensive architecture doc
│       ├── __init__.py              # Module exports
│       ├── config.py                # YAML configuration loader
│       ├── database.py              # SQLite time-series storage
│       ├── engine.py                # Central SLA engine coordinator
│       ├── metrics_collector.py     # RTT, jitter, signal collection
│       ├── predictor.py             # LSTM failure prediction
│       ├── failback.py              # Cost-aware failback intelligence
│       ├── cost_tracker.py          # Metered usage tracking
│       ├── dns_intelligence.py      # Adaptive multi-provider DNS
│       ├── integrations/
│       │   ├── __init__.py
│       │   └── pbr.py               # Fortress PBR integration
│       └── tests/
│           └── test_slaai.py        # Comprehensive test suite
│
│   └── aiochi/                       # AIOCHI - AI EYES (COGNITIVE LAYER)
│       ├── ARCHITECTURE.md          # Comprehensive architecture doc
│       ├── __init__.py              # Module exports
│       ├── containers/
│       │   ├── podman-compose.aiochi.yml  # AIOCHI container orchestration
│       │   ├── Containerfile.identity     # Identity engine build
│       │   ├── Containerfile.logshipper   # Log shipper build
│       │   └── configs/                   # Service configurations
│       │       ├── clickhouse/            # ClickHouse init scripts
│       │       ├── grafana/               # Grafana provisioning
│       │       └── napse/                 # NAPSE configuration
│       ├── schemas/
│       │   └── clickhouse-init.sql        # ClickHouse schema
│       ├── n8n-workflows/
│       │   └── agentic-security-agent.json # AI security workflow
│       ├── personas/                      # Device persona templates
│       └── templates/                     # Narrative templates
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
│   │   ├── DEVELOPMENT_PLAN.md      # MVP implementation roadmap
│   │   ├── install.sh               # Unified installer (container + native)
│   │   ├── install-container.sh     # Container-based installation
│   │   ├── setup.sh                 # Native mode installation
│   │   ├── uninstall.sh             # Uninstall script
│   │   ├── fortress-ctl.sh          # CLI management tool
│   │   ├── lib/                     # Python libraries
│   │   │   ├── config.py            # Configuration loading
│   │   │   ├── device_manager.py    # Device discovery, OUI lookup
│   │   │   ├── vlan_manager.py      # VLAN creation, DHCP config
│   │   │   ├── cloudflare_tunnel.py # Remote access integration
│   │   │   ├── ecosystem_bubble.py  # Same-user device grouping
│   │   │   ├── presence_sensor.py   # mDNS/BLE presence detection
│   │   │   ├── behavior_clustering.py # DBSCAN device clustering
│   │   │   ├── connection_graph.py  # D2D affinity via NAPSE
│   │   │   ├── clickhouse_graph.py  # ClickHouse graph persistence
│   │   │   ├── n8n_webhook.py       # n8n workflow webhooks
│   │   │   └── reinforcement_feedback.py # RL from corrections
│   │   ├── web/                     # Flask + AdminLTE UI
│   │   │   ├── app.py               # Flask app with Flask-Login
│   │   │   └── modules/             # Blueprints (auth, dashboard, clients...)
│   │   ├── devices/                 # Hardware-specific profiles
│   │   │   ├── common/              # Shared network scripts
│   │   │   │   ├── detect-hardware.sh
│   │   │   │   ├── network-integration.sh  # NIC + LTE detection
│   │   │   │   ├── bridge-manager.sh       # Linux bridge setup
│   │   │   │   ├── setup-dhcp.sh           # dnsmasq DHCP config
│   │   │   │   ├── hostapd-generator.sh    # WiFi AP config
│   │   │   │   ├── wifi-regulatory-dfs.sh  # DFS channel management
│   │   │   │   └── lte-manager.sh          # LTE modem setup
│   │   │   ├── intel-n100/          # Intel N100 profile
│   │   │   ├── rpi-cm5/             # Raspberry Pi CM5 profile
│   │   │   └── radxa-rock5b/        # Radxa Rock5B profile
│   │   └── containers/              # Podman deployment
│   │       ├── podman-compose.yml   # Container orchestration
│   │       └── Containerfile.*      # Container definitions
│   │
│   └── nexus/                        # ML/AI Compute (16GB+)
│       └── (minimal - future expansion)
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
│   │   └── monitoring/              # Napse SMTP intent rules
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
│   │   └── admin-dashboard.md
│   ├── deployment/
│   │   └── README.md
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

| Status | Protection | Meaning | What's Happening |
|--------|------------|---------|------------------|
| **GREEN** | > 55% | Protected | All clear |
| **AMBER** | 30-55% | Monitoring | Investigating activity |
| **RED** | < 30% | Defending | Active mitigation |

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
**Version**: 5.1.0

Next-generation DNS protection with machine learning, competitive with AdGuard, Pi-hole, and NextDNS.

| File | Purpose |
|------|---------|
| `engine.py` | ML classifier (30+ features, 8 categories, DGA detection) |
| `api_server.py` | HTTP API for dashboard integration |
| `integration.py` | Product integration utilities |
| `mesh_intelligence.py` | Federated learning across mesh |
| `update-blocklist.sh` | Blocklist updater script |

**Core Features**:
- ML-based classification for unknown domains (30+ features)
- CNAME uncloaking (detects first-party tracker masquerading)
- Federated learning across mesh network
- 5-tier protection levels (~130K to ~250K domains)
- <1ms inference on Raspberry Pi
- Whitelist auto-sync between API and DNS engine (5s polling)
- Protected infrastructure domains (never blocked)

**AI/ML Threat Detection** (NextDNS-style):
- **DGA Detection**: Domain Generation Algorithm patterns for malware C2
- **DNS Tunneling Detection**: Data exfiltration via long encoded subdomains
- **Query Pattern Analysis**: Flood and enumeration attack detection
- **Threat Keywords**: Malware/phishing indicator scanning
- **Punycode Detection**: Internationalized domain phishing
- **New TLD Scoring**: Suspicious TLD risk assessment
- **Adaptive Learning**: Learn from false positives/negatives

**Whitelist Features**:
- Wildcard patterns: `*.example.com` matches all subdomains
- Parent domain matching: `example.com` auto-whitelists subdomains
- Exact match: `sub.example.com` for specific subdomain
- Search functionality: Filter whitelist by keyword
- Bulk operations: Add multiple domains at once

**API Endpoints**:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/stats` | GET | Protection statistics |
| `/api/status` | GET | Protection status |
| `/api/level` | POST | Set protection level (0-5) |
| `/api/pause` | POST | Pause protection |
| `/api/resume` | POST | Resume protection |
| `/api/whitelist` | GET | Get whitelist (`?search=keyword`) |
| `/api/whitelist` | POST | Add domain to whitelist |
| `/api/whitelist/bulk` | POST | Bulk add domains |
| `/api/whitelist/status` | GET | Detailed whitelist info |
| `/api/blocked` | GET | Blocked domains (`?search=&category=&hours=`) |
| `/api/blocked/stats` | GET | Blocking statistics with trends |
| `/api/blocked/whitelist` | POST | Quick whitelist from blocked |
| `/api/blocklist/info` | GET | Blocklist file info |
| `/api/ml/status` | GET | ML model status |
| `/api/ml/train` | POST | Trigger ML training |
| `/api/test/classify` | GET | Test domain classification |

**Protected Infrastructure** (never blocked):
- System connectivity: `msftconnecttest.com`, `captive.apple.com`, etc.
- Software repos: `raspberrypi.com`, `pypi.org`, `github.com`, etc.
- CDN/Cloud: `cloudflare.com`, `amazonaws.com`, `akamaiedge.net`, etc.

**Protection Levels**:

| Level | Name | Protection | Domains |
|-------|------|------------|---------|
| 0 | Off | Passthrough | 0 |
| 1 | Base | Ads + Malware | ~130K |
| 2 | Enhanced | + Fakenews | ~132K |
| 3 | Strong | + Gambling | ~135K |
| 4 | Maximum | + Adult Content | ~200K |
| 5 | Full | + Social Trackers | ~250K |

**CLI Usage**:
```bash
# Test domain classification
curl "http://localhost:8080/api/test/classify?domain=doubleclick.net"

# Search blocked domains
curl "http://localhost:8080/api/blocked?search=google&category=tracking"

# Add wildcard whitelist
curl -X POST http://localhost:8080/api/whitelist -d '{"domain": "*.example.com"}'

# Get blocking stats
curl http://localhost:8080/api/blocked/stats
```

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

### Wireless - DFS Intelligence & Channel Management

**Location**: `shared/wireless/`

ML-powered WiFi channel selection and DFS (Dynamic Frequency Selection) intelligence.

| File | Purpose |
|------|---------|
| `__init__.py` | Module exports (DFSDatabase, ChannelScorer, etc.) |
| `channel_scanner.py` | WiFi channel scanning and congestion analysis |
| `dfs_intelligence.py` | ML-powered DFS with radar event tracking |
| `containers/dfs-intelligence/` | Containerized DFS API server |

**DFS Intelligence Features**:
- **Radar Event Tracking**: SQLite database for radar detection history
- **NOP Management**: 30-minute Non-Occupancy Period compliance (ETSI EN 301 893)
- **ML Channel Scoring**: Multi-factor scoring with configurable weights:
  - Time since last radar (exponential decay)
  - Historical radar frequency
  - Bandwidth capability
  - Time-of-day risk patterns
  - Weather radar proximity
  - ML prediction confidence
- **Channel Switch Announcement (CSA)**: Automated channel switching via hostapd_cli
- **Reinforcement Learning**: Learns from channel switch outcomes

**Channel Information** (5GHz Bands):

| Band | Channels | DFS | CAC Time | Use Case |
|------|----------|-----|----------|----------|
| UNII-1 | 36-48 | No | 0s | Indoor, always safe |
| UNII-2A | 52-64 | Yes | 60s | Short CAC, moderate risk |
| UNII-2C | 100-144 | Yes | 600s | Weather radar band, high risk |
| UNII-3 | 149-165 | No | 0s | High power, country-restricted |

**CLI Usage**:
```bash
# Score a specific channel
python -m shared.wireless.dfs_intelligence score --channel 52

# Get best channel recommendation
python -m shared.wireless.dfs_intelligence best --prefer-dfs --min-bandwidth 80

# Rank all channels
python -m shared.wireless.dfs_intelligence rank --include-dfs

# Start radar monitoring
python -m shared.wireless.dfs_intelligence monitor --interface wlan0

# Show DFS status
python -m shared.wireless.dfs_intelligence status
```

**Key Classes**:
```python
from shared.wireless import (
    WiFiChannelScanner,  # Channel scanning
    DFSDatabase,         # Radar event storage
    ChannelScorer,       # ML-powered scoring
    RadarMonitor,        # Real-time monitoring
    DFSMLTrainer,        # Model training
)
```

### hostapd-ovs - OVS Bridge Support for WiFi

**Location**: `shared/hostapd-ovs/`
**Status**: Production Ready

This module provides a patched version of hostapd (2.10/2.11) that can directly bridge WiFi interfaces to Open vSwitch (OVS) bridges, eliminating the need for veth pairs and intermediate Linux bridges.

**The Problem**:

Standard hostapd uses sysfs (`/sys/class/net/<bridge>/brif/`) to detect bridge membership. This works for Linux bridges but **fails for OVS bridges** because OVS doesn't populate sysfs bridge interfaces.

**Architecture Comparison**:

| Mode | Traffic Flow | Components | Performance |
|------|-------------|------------|-------------|
| **hostapd-ovs** (direct) | WiFi → OVS (FTS) | Direct integration | Better |
| **veth mode** (fallback) | WiFi → br-wifi → veth pair → OVS | Extra bridge + veth | Overhead |

**The Solution**:

The patch adds `linux_br_get_ovs()` helper function to `src/drivers/linux_ioctl.c`. When the standard sysfs lookup fails, it queries `ovs-vsctl port-to-br` to find the OVS bridge.

```c
/* OVS Bridge Support (HookProbe Patch) */
static int linux_br_get_ovs(char *brname, const char *ifname)
{
    // Input validation prevents command injection
    // Only alphanumeric, hyphens, underscores, dots allowed
    snprintf(cmd, sizeof(cmd), "ovs-vsctl --timeout=1 port-to-br %s 2>/dev/null", ifname);
    fp = popen(cmd, "r");
    // ... reads bridge name from output
}
```

**Key Files**:

| File | Purpose |
|------|---------|
| `build-hostapd-ovs.sh` | Downloads, patches, builds, installs hostapd-ovs |
| `README.md` | Comprehensive integration documentation |

**Fortress Integration**:

The Fortress installer automatically builds hostapd-ovs during `check_prerequisites()`:

```bash
# Automatic during Fortress install
sudo ./install.sh

# Manual build
sudo ./shared/hostapd-ovs/build-hostapd-ovs.sh

# Check installation
./shared/hostapd-ovs/build-hostapd-ovs.sh --check

# Uninstall
sudo ./shared/hostapd-ovs/build-hostapd-ovs.sh --uninstall
```

**Configuration**:

The mode is stored in `/etc/hookprobe/fortress.conf`:
```bash
HOSTAPD_OVS_MODE=true   # Direct OVS integration
HOSTAPD_OVS_MODE=false  # veth fallback mode
```

**hostapd.conf with OVS**:
```ini
interface=wlan_24ghz
bridge=FTS              # Direct OVS bridge name (no br-wifi needed)
ap_isolate=1            # Recommended for OVS policy control
```

**Supported Versions**:

| hostapd | WiFi Standards | Notes |
|---------|----------------|-------|
| 2.10 | WiFi 5 (802.11ac), WiFi 6 (802.11ax) | Stable, widely tested |
| 2.11 | WiFi 5, WiFi 6, WiFi 7 (802.11be) | Latest features |

**Build Features Enabled**:
- `CONFIG_DRIVER_NL80211` - Modern Linux WiFi driver
- `CONFIG_FULL_DYNAMIC_VLAN` - Network segmentation
- `CONFIG_ACS` - Auto channel selection
- `CONFIG_SAE`, `CONFIG_OWE` - WPA3 security
- `CONFIG_IEEE80211BE` - WiFi 7 (2.11 only)

**Security**:
- Interface name validation prevents command injection
- 1-second timeout on ovs-vsctl prevents hangs
- Only alphanumeric, hyphens, underscores, and dots allowed in interface names

**Future Work** (identified gaps):
- OpenFlow rules for D2D client isolation
- mDNS/DHCP broadcast handling
- Dynamic VLAN infrastructure
- OVS port VLAN trunk mode configuration

### SLA AI - Business Continuity Engine

**Location**: `shared/slaai/`

HookProbe's proprietary **SLA AI** (Service Level Agreement Artificial Intelligence) is an intelligent network continuity system that ensures **Business Continuity Objectives (BCO)** and **Business Process Objectives (BPO)** are met through predictive failover and cost-aware failback.

**Core Philosophy**: *Feel, Sense, Adapt, Learn, Optimize*

| File | Purpose |
|------|---------|
| `ARCHITECTURE.md` | Comprehensive architecture documentation |
| `engine.py` | Central SLA engine coordinator |
| `metrics_collector.py` | RTT, jitter, packet loss, LTE signal collection |
| `predictor.py` | LSTM neural network for failure prediction |
| `failback.py` | Cost-aware failback with hysteresis |
| `cost_tracker.py` | Metered connection usage and budget tracking |
| `dns_intelligence.py` | Multi-provider adaptive DNS failover |
| `database.py` | SQLite time-series storage |
| `integrations/pbr.py` | Fortress PBR route switching integration |

**Business Continuity Metrics**:

| Metric | Target | Description |
|--------|--------|-------------|
| **BCO Uptime** | 99.9% | Total connectivity uptime |
| **RTO** (Recovery Time Objective) | < 5s | Time to failover |
| **RPO** (Recovery Point Objective) | 0 bytes | No data loss during switch |
| **MTTR** | < 5s | Mean Time to Recovery |
| **MTTD** | < 30s | Mean Time to Detection (predictive) |
| **False Positive Rate** | < 5% | Unnecessary failovers |
| **Cost Efficiency** | 80%+ | Primary usage vs metered backup |

**LSTM Predictor Features** (24 input features):
- RTT statistics (current, mean, std, trend)
- Jitter statistics (current, mean, std, trend)
- Packet loss (current, mean, trend)
- LTE signal (RSSI, RSRP, RSRQ normalized)
- DNS response times
- Time encoding (hour/day cyclical)
- Interface error rate
- Historical failure count (24h)

**Failback Intelligence**:
```python
# Cost-aware failback policy
FailbackPolicy(
    min_backup_duration_s=120,      # 2 min on backup before considering
    primary_stable_duration_s=60,   # Primary must be stable 1 min
    health_checks_required=5,       # 5 successful checks needed
    metered_failback_urgency=1.5,   # 1.5x faster on metered
    business_hours_multiplier=1.2,  # Prioritize during 9-6
    max_switches_per_hour=4,        # Flap prevention
)
```

**State Machine**:
```
PRIMARY_ACTIVE ──[failure/predicted]──> FAILOVER_IN_PROGRESS ──> BACKUP_ACTIVE
       ▲                                                              │
       │                                                              │
       └──────────── FAILBACK_IN_PROGRESS <──[primary recovered]──────┘
```

**PBR Integration** (writes to `/run/fortress/slaai-recommendation.json`):
```json
{
    "timestamp": "2024-01-15T10:30:00Z",
    "recommendation": "failback",
    "confidence": 0.85,
    "reason": "Primary healthy (92%); High backup cost (78%)",
    "active_interface": "wwan0",
    "cost_status": {
        "daily_usage_mb": 145,
        "daily_budget_mb": 500,
        "urgency_score": 0.78
    }
}
```

**CLI Usage**:
```bash
# Start SLA engine (standalone)
python -m shared.slaai.engine --config /etc/hookprobe/slaai.conf --debug

# Run tests
pytest shared/slaai/tests/ -v
```

**Key Classes**:
```python
from shared.slaai import (
    SLAEngine,             # Central coordinator
    SLAState,              # State machine enum
    MetricsCollector,      # Metrics gathering
    WANMetrics,            # Metrics dataclass
    LSTMPredictor,         # Failure prediction
    Prediction,            # Prediction result
    FailbackIntelligence,  # Failback decisions
    FailbackPolicy,        # Policy configuration
    CostTracker,           # Metered usage tracking
    DNSIntelligence,       # Adaptive DNS
)
```

---

## AIOCHI - AI Eyes

### Cognitive Network Layer for HookProbe

**Location**: `shared/aiochi/`
**Status**: Production Ready
**Branding**: "AIOCHI" (AI Eyes) - See your network, understand your security

AIOCHI transforms raw network data into **human-readable narratives** using local AI. It's the "eyes" that make complex security events understandable to non-technical users.

> *"Mom's iPhone joined the network"* instead of *"MAC aa:bb:cc:dd:ee:ff DHCP lease 10.200.0.45"*

**Philosophy**: *Feel → Sense → Adapt → Learn → Optimize*

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AIOCHI - AI EYES                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │  CAPTURE    │───▶│   STORE     │───▶│  ANALYZE    │───▶│  NARRATE    │  │
│  │ (IDS/NSM)   │    │ (ClickHouse)│    │ (Identity)  │    │ (LLM/n8n)   │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│   NAPSE             Time-series        Device            Ollama            │
│   IDS/NSM           VictoriaMetrics    Fingerprinting    llama3.2:3b       │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                         VISUALIZATION (Grafana)                         ││
│  │  Network presence map • Security health score • Human-readable feed    ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Container | Purpose | Port |
|-----------|-----------|---------|------|
| **ClickHouse** | aiochi-clickhouse | Event analytics database | 8123, 9000 |
| **VictoriaMetrics** | aiochi-victoria | Time-series metrics | 8428 |
| **NAPSE** | aiochi-napse | AI-native IDS/IPS/NSM | host network |
| **Grafana** | aiochi-grafana | Visual dashboards | 3000 |
| **n8n** | aiochi-narrative | Workflow automation | 5678 |
| **Ollama** | aiochi-ollama | Local LLM (llama3.2:3b) | 11434 |
| **Identity Engine** | aiochi-identity | Device fingerprinting | 8060 |
| **Log Shipper** | aiochi-logshipper | Event pipeline | - |

### Installation

```bash
# Enable AIOCHI with Fortress
sudo ./install.sh --tier fortress --enable-aiochi

# AIOCHI adds ~2GB RAM usage and ~4GB disk for:
# - Container images (~2GB)
# - LLM model llama3.2:3b (~2GB, downloaded async)
```

### Key Files

| File | Purpose |
|------|---------|
| `shared/aiochi/ARCHITECTURE.md` | Comprehensive architecture documentation |
| `shared/aiochi/containers/podman-compose.aiochi.yml` | Container orchestration |
| `shared/aiochi/containers/Containerfile.identity` | Identity engine build |
| `shared/aiochi/containers/Containerfile.logshipper` | Log shipper build |
| `shared/aiochi/schemas/clickhouse-init.sql` | ClickHouse schema |
| `shared/aiochi/n8n-workflows/agentic-security-agent.json` | AI security workflow |

### Narrative Examples

AIOCHI transforms technical events into human-readable stories:

| Raw Event | AIOCHI Narrative |
|-----------|------------------|
| `DHCP ACK 10.200.0.45 aa:bb:cc:dd:ee:ff` | "Sarah's iPhone joined the network" |
| `DNS query blocked: ads.tracker.com` | "Blocked advertising tracker (protects privacy)" |
| `NAPSE alert: ET SCAN` | "Someone is probing the network - already blocked" |
| `New device: Apple vendor` | "New Apple device detected - awaiting identification" |

### CLI Commands

```bash
# Check AIOCHI container status
podman ps --filter "name=aiochi-"

# Monitor LLM model download
tail -f /var/log/fortress/aiochi-llm-download.log

# Access Grafana dashboards
open http://localhost:3000  # admin/fortress_grafana_admin

# Access n8n workflows
open http://localhost:5678  # admin/fortress_n8n_admin

# Query ClickHouse directly
podman exec -it aiochi-clickhouse clickhouse-client -d aiochi
```

### Integration with Fortress

When `--enable-aiochi` is used:
1. Core Fortress containers (fts-*) start normally
2. AIOCHI containers (aiochi-*) start separately
3. Optional fts-* services (grafana, victoria, n8n, etc.) are **skipped** (AIOCHI provides them)
4. Ollama starts and downloads LLM model in background
5. `INSTALL_AIOCHI=true` saved to `/etc/hookprobe/fortress.conf`

**Note**: The LLM model download (~2GB) runs **asynchronously** so installation completes without blocking.

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
**Version**: 5.5.0

Enterprise-grade security for small businesses (flower shops, bakeries, retail, trades).

**Target Market**:
- Sole traders and small businesses
- Need professional security without enterprise complexity
- POS systems, guest WiFi, staff networks
- GDPR compliance requirements

**Architecture**:
- **Containers**: Podman with podman-compose orchestration (single `fts-internal` network)
- **Web UI**: Flask + AdminLTE 3.x (gunicorn in container)
- **Database**: PostgreSQL 15 with persistent volume
- **Cache**: Redis 7 for sessions and rate limiting
- **Network**: OVS bridge (`FTS`) - Layer 2 only, VLAN-based segmentation
- **WiFi**: Dual-band hostapd AP with stable naming via udev rules
- **Security Core**: QSecBit threat detection, dnsXai DNS protection, DFS WiFi intelligence

**Installation**:
```bash
# Interactive install (recommended)
sudo ./install.sh

# Quick install with defaults (for testing)
sudo ./install.sh --quick
```

**Installation Prompts**:

| Prompt | Default | Description |
|--------|---------|-------------|
| LAN Subnet | `/23` | Network size (/29 to /23) |
| Admin Username | `admin` | Web UI admin username |
| Admin Password | (required) | Min 8 chars |
| WiFi SSID | `HookProbe-Fortress` | Access point network name |
| WiFi Password | Random 12-char | Or user-specified (min 8 chars) |
| Web Port | `8443` | HTTPS port for admin UI |

**Services (Containers)**:

| Container | Purpose | Profile |
|-----------|---------|---------|
| fts-postgres | PostgreSQL database | Core |
| fts-redis | Session cache, rate limiting | Core |
| fts-web | Flask admin UI (gunicorn) | Core |
| fts-qsecbit | QSecBit threat detection (host network) | Core |
| fts-dnsxai | dnsXai DNS ML protection | Core |
| fts-dfs | DFS WiFi channel intelligence | Core |
| fts-grafana | Monitoring dashboard | Optional (`--profile monitoring`) |
| fts-victoria | VictoriaMetrics database | Optional (`--profile monitoring`) |
| fts-lstm-trainer | ML training (one-shot) | Optional (`--profile training`) |
| fts-napse | NAPSE AI-native IDS/IPS/NSM (host network) | Optional (`--profile ids`) |
| fts-xdp | XDP/eBPF DDoS protection | Optional (`--profile ids`) |
| fts-n8n | n8n workflow automation | Optional (`--profile automation`) |
| fts-clickhouse | ClickHouse analytics | Optional (`--profile analytics`) |
| fts-mesh | HTP/Neuro/DSM mesh orchestrator | Optional (`--profile mesh`) |
| fts-cloudflared | Cloudflare Tunnel | Optional (`--profile tunnel`) |

**Network Architecture**:
- **OVS Bridge**: `FTS` - Layer 2 switch with OpenFlow-based micro-segmentation
- **LAN**: 10.200.0.0/XX subnet on OVS bridge (configurable subnet size)
- **DHCP**: dnsmasq on OVS bridge (range calculated based on subnet size)
- **NAT**: iptables masquerade on WAN interface
- **Container Network**: `fts-internal` (172.20.200.0/24) for inter-container communication
- **WiFi**: hostapd bridged to OVS (`wlan_24ghz`, `wlan_5ghz` stable names)
- **Segmentation**: OpenFlow rules for device isolation (no VLAN tagging)

**Subnet Sizes**:

| Mask | Devices | DHCP Range |
|------|---------|------------|
| /29 | 6 | 10.200.0.2 - 10.200.0.6 |
| /28 | 14 | 10.200.0.2 - 10.200.0.14 |
| /27 | 30 | 10.200.0.10 - 10.200.0.30 |
| /26 | 62 | 10.200.0.10 - 10.200.0.62 |
| /25 | 126 | 10.200.0.10 - 10.200.0.126 |
| /24 | 254 | 10.200.0.100 - 10.200.0.200 |
| /23 | 510 | 10.200.0.100 - 10.200.1.200 |

**Systemd Services**:

| Service | Purpose |
|---------|---------|
| `fortress.service` | Main container orchestration (podman-compose) |
| `fortress-vlan.service` | OVS post-setup after netplan |
| `fts-hostapd-24ghz.service` | 2.4GHz WiFi access point |
| `fts-hostapd-5ghz.service` | 5GHz WiFi access point |

**Key Files**:
- `install.sh` - Unified installer (defaults to container mode)
- `install-container.sh` - Container-based installation
- `uninstall.sh` - Complete removal with data preservation options
- `fortress-ctl.sh` - Runtime management (backup, status)
- `containers/podman-compose.yml` - Container orchestration
- `containers/Containerfile.*` - Container definitions
- `devices/common/netplan-ovs-generator.sh` - Netplan config generator
- `devices/common/ovs-post-setup.sh` - OVS OpenFlow rules and VLAN setup
- `devices/common/hostapd-generator.sh` - WiFi AP configuration
- `systemd/fortress-vlan.service` - VLAN boot persistence

**Web UI Modules** (`web/modules/`):

| Module | Purpose |
|--------|---------|
| `auth/` | Authentication (Flask-Login, bcrypt) |
| `dashboard/` | Main dashboard |
| `clients/` | Connected device management |
| `sdn/` | Unified SDN device/policy management |
| `slaai/` | SLA AI WAN failover dashboard |
| `security/` | QSecBit security metrics |
| `dnsxai/` | DNS protection settings |
| `networks/` | Network configuration |
| `settings/` | System settings |
| `tunnel/` | Cloudflare Tunnel management |
| `api/` | REST API endpoints |

**Authentication**:
- **Storage**: JSON file (`/etc/hookprobe/users.json`)
- **Max Users**: 5 (sufficient for small business)
- **Password Hashing**: bcrypt
- **Roles**: admin, operator, viewer
- **Default Admin**: Created during install

**Useful Commands**:
```bash
# Service management
systemctl status fortress             # Check container orchestration
systemctl restart fortress            # Restart all containers
systemctl status fortress-vlan        # OVS/VLAN status
systemctl status fts-hostapd-24ghz    # 2.4GHz WiFi status
systemctl status fts-hostapd-5ghz     # 5GHz WiFi status

# Container logs
podman logs fts-web                   # Web app logs
podman logs fts-postgres              # Database logs
podman logs fts-qsecbit               # Threat detection logs
podman logs fts-dnsxai                # DNS protection logs

# Network status
ovs-vsctl show                        # OVS bridge status
ip addr show FTS                      # OVS bridge IP
cat /etc/dnsmasq.d/fts-lan.conf       # DHCP config

# Backup
./fortress-ctl.sh backup              # Create backup
```

**WiFi Interface Naming**:
- udev rules created during install (`/etc/udev/rules.d/70-fts-wifi.rules`)
- MAC address-based stable naming: `wlan_24ghz`, `wlan_5ghz`
- Interface mapping saved to `/etc/hookprobe/wifi-interfaces.conf`

**Development Plan**: See `products/fortress/DEVELOPMENT_PLAN.md`

### D2D Bubble System (Ecosystem Bubble) - Automatic Device Relationship Detection

**Location**: `products/fortress/lib/`
**Status**: Production Ready
**Branding**: "Atmospheric Presence" - Detecting device relationships through behavioral patterns

> **IMPORTANT: Device Groups vs D2D Bubbles**
> | Concept | Description | Code Location |
> |---------|-------------|---------------|
> | **Device Groups** | Manual CRUD for user-organized device grouping with OpenFlow policies. Users create, edit, delete groups via Web UI. | `web/modules/bubbles/views.py` |
> | **D2D Bubbles** | Automatic background algorithm that detects device relationships through network traffic and colors them similarly. | `lib/ecosystem_bubble.py` |
>
> These are **INDEPENDENT** - a device can be in "Work" group but colored same as "Dad's iPhone" based on D2D patterns.

The D2D Bubble system (also called "Ecosystem Bubble" or "Atmospheric Presence") automatically detects which devices belong to the same user through multi-modal signals without requiring manual configuration.

> *"Dad's iPhone and MacBook wake up together at 7am, share files via AirDrop, and query the same Apple TV - they're colored the same in the UI"*

**Architecture Overview**:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ECOSYSTEM BUBBLE SYSTEM                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │  PRESENCE   │───▶│ CONNECTION  │───▶│  BEHAVIOR   │───▶│   BUBBLE    │  │
│  │   SENSOR    │    │    GRAPH    │    │  CLUSTERING │    │   MANAGER   │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│   mDNS/BLE/WiFi     NAPSE events         DBSCAN ML         SDN Rules        │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                      INTEGRATION MODULES                                 ││
│  │  ClickHouse ─── n8n Webhooks ─── Reinforcement Learning                ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Core Components**:

| Component | File | Purpose |
|-----------|------|---------|
| **Ecosystem Bubble Manager** | `ecosystem_bubble.py` | Orchestrator, bubble lifecycle, SDN rules |
| **Presence Sensor** | `presence_sensor.py` | mDNS, BLE, network events |
| **Behavior Clustering** | `behavior_clustering.py` | DBSCAN unsupervised clustering |
| **Connection Graph** | `connection_graph.py` | NAPSE-based D2D affinity analysis |
| **ClickHouse Storage** | `clickhouse_graph.py` | Time-series persistence for AI |
| **n8n Webhooks** | `n8n_webhook.py` | Workflow automation integration |
| **Reinforcement Learning** | `reinforcement_feedback.py` | Learn from user corrections |

**Affinity Score Algorithm**:

```python
# The Formula (0.0 - 1.0)
S_aff = (Discovery Hits × W_discovery) + (D2D Flows × W_d2d) + (Temporal Sync × W_temporal)

# Default Weights:
W_discovery = 0.10   # mDNS query/response pairing
W_d2d = 0.05         # Device-to-device connections (NAPSE)
W_temporal = 0.02    # Wake/sleep correlation

# Enhanced with Reinforcement Learning:
S_adjusted = S_aff + RL_adjustment  # Range: -0.5 to +0.5
```

**Bubble Types**:

| Type | VLAN | Internet | LAN | D2D | Use Case |
|------|------|----------|-----|-----|----------|
| **FAMILY** | 110 | ✅ | ✅ | ✅ | Dad, Mom, Kids |
| **GUEST** | 150 | ✅ | ❌ | ❌ | Visitors, temporary |
| **IOT** | 130 | ✅ | ❌ | ✅ | Smart home devices |
| **WORK** | 120 | ✅ | ⚠️ | ✅ | Business devices |

**Key Files**:

| File | Lines | Purpose |
|------|-------|---------|
| `ecosystem_bubble.py` | ~1200 | Main orchestrator, bubble CRUD, SDN |
| `presence_sensor.py` | ~1050 | mDNS listener, BLE scanner, events |
| `connection_graph.py` | ~1000 | NAPSE event parsing, temporal patterns |
| `behavior_clustering.py` | ~600 | DBSCAN, feature engineering |
| `clickhouse_graph.py` | ~540 | ClickHouse persistence |
| `n8n_webhook.py` | ~455 | Async webhook client |
| `reinforcement_feedback.py` | ~500 | Correction learning |

#### mDNS Query/Response Pairing

Tracks which device queries which service to detect ownership relationships.

**How it works**:
1. iPhone queries `_airplay._tcp.local.` (looking for Apple TV)
2. Apple TV responds (advertising service)
3. System creates "discovery pair" linking iPhone ↔ Apple TV
4. Multiple discoveries = high affinity = same bubble

```python
from presence_sensor import PresenceSensor

sensor = PresenceSensor()
sensor.record_mdns_query("AA:BB:CC:DD:EE:01", "_airplay._tcp", "Apple TV")
sensor.record_mdns_response("FF:EE:DD:CC:BB:AA", "_airplay._tcp")

# Get discovery hit count between devices
hits = sensor.get_discovery_hits("AA:BB:CC:DD:EE:01", "FF:EE:DD:CC:BB:AA")
```

**Database Tables** (SQLite):
- `mdns_discovery_pairs` - Individual query/response pairs
- `discovery_hits` - Aggregated hit counts per device pair

#### Temporal Affinity Scoring

Detects devices that follow the same schedule (same user).

**Pattern Detection**:
- Active hours (0-23) - Jaccard similarity
- Wake events (hour, weekday) - Join network pattern
- Sleep events (hour, weekday) - Leave network pattern
- Session duration - How long device stays active

```python
from connection_graph import TemporalPattern

# Two devices with similar patterns
pattern_dad_phone = TemporalPattern(mac="AA:BB:CC:DD:EE:01")
pattern_dad_phone.active_hours = {7, 8, 9, 18, 19, 20, 21, 22}
pattern_dad_phone.wake_events = [(7, 0), (7, 1), (7, 2)]  # 7am weekdays

pattern_dad_laptop = TemporalPattern(mac="AA:BB:CC:DD:EE:02")
pattern_dad_laptop.active_hours = {7, 8, 9, 18, 19, 20, 21, 23}

similarity = pattern_dad_phone.similarity(pattern_dad_laptop)  # ~0.85
```

**Coincident Event Detection**:
- Events within 60-second windows get bonus scoring
- Wake events (join) worth more than sleep events (leave)
- Closeness bonus: closer events = higher score

#### ClickHouse Graph Storage

Persists device relationships for AI learning and trend analysis.

**Tables**:

| Table | Purpose | TTL |
|-------|---------|-----|
| `bubble_device_relationships` | D2D connections | 90 days |
| `bubble_mdns_discoveries` | Discovery pairs | 30 days |
| `bubble_temporal_patterns` | Wake/sleep cycles | 30 days |
| `bubble_assignments` | Bubble membership | 365 days |
| `bubble_affinity_history` | Score trends | 90 days |

```python
from clickhouse_graph import get_clickhouse_store

store = get_clickhouse_store()
store.record_relationship(
    mac_a="AA:BB:CC:DD:EE:01",
    mac_b="AA:BB:CC:DD:EE:02",
    connection_count=15,
    high_affinity_count=8,
    services=["smb", "mdns", "airplay"],
    temporal_sync=0.82,
    affinity_score=0.75,
)
```

#### n8n Webhook Integration

Sends events to n8n for workflow automation.

**Event Types**:

| Event | Trigger | Use Case |
|-------|---------|----------|
| `bubble_change` | Device moved | Notify admin |
| `device_join` | New device | Welcome automation |
| `device_leave` | Device left | Session logging |
| `relationship_detected` | High affinity found | Suggest grouping |
| `manual_correction` | User edit | RL training |
| `bubble_created` | New bubble | Policy setup |

**Configuration** (`/etc/hookprobe/fortress.conf`):
```bash
N8N_WEBHOOK_URL="http://localhost:5678/webhook/bubble-events"
N8N_AUTH_TOKEN="your-bearer-token"
```

```python
from n8n_webhook import get_webhook_client

client = get_webhook_client()
client.on_bubble_change(
    mac="AA:BB:CC:DD:EE:01",
    old_bubble="guests",
    new_bubble="family-dad",
    confidence=0.92,
    reason="High temporal correlation with existing devices"
)
```

#### Reinforcement Learning Feedback

Learns from user manual corrections to improve automatic assignment.

**How it works**:
1. AI assigns device to "Guests" bubble
2. User manually moves device to "Dad" bubble
3. System records negative feedback (wrong assignment)
4. System records positive feedback (correct assignment)
5. Affinity scores adjusted for future predictions

**Constants**:
```python
POSITIVE_FEEDBACK_WEIGHT = 0.15   # +15% affinity boost
NEGATIVE_FEEDBACK_WEIGHT = -0.20  # -20% affinity penalty
DECAY_FACTOR = 0.95               # Daily decay (old corrections matter less)
MAX_FEEDBACK_AGE_DAYS = 30        # Discard very old feedback
```

```python
from reinforcement_feedback import get_feedback_engine

engine = get_feedback_engine()

# Record user correction
engine.record_correction(
    mac="AA:BB:CC:DD:EE:01",
    old_bubble_id="bubble-guests",
    new_bubble_id="bubble-dad",
    old_bubble_devices=["GG:UU:EE:SS:TT:01"],  # Negative feedback
    new_bubble_devices=["AA:BB:CC:DD:EE:02"],  # Positive feedback
    reason="Device belongs to Dad"
)

# Apply to affinity scores
engine.apply_pending_corrections()

# Get adjusted affinity
base = 0.5
adjusted = engine.get_adjusted_affinity("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", base)
# Returns: 0.65 (base + positive adjustment)
```

**CLI Tools**:
```bash
# Reinforcement learning stats
python -m reinforcement_feedback stats

# Top adjusted device pairs
python -m reinforcement_feedback pairs --limit 20

# Apply daily decay
python -m reinforcement_feedback decay

# n8n webhook status
python -m n8n_webhook status

# Test webhook
python -m n8n_webhook test
```

**Python API**:
```python
from products.fortress.lib import (
    get_ecosystem_bubble_manager,
    get_presence_sensor,
    get_d2d_connection_graph,
    get_clickhouse_graph_store,
    get_n8n_webhook_client,
    get_reinforcement_feedback_engine,
)

# Get manager and check if devices are same bubble
manager = get_ecosystem_bubble_manager()
same, confidence = manager.are_same_bubble("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02")

# Create manual bubble
bubble = manager.create_manual_bubble(
    name="Dad's Devices",
    bubble_type=BubbleType.FAMILY,
    devices=["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"]
)

# Move device (triggers webhook + RL)
manager.move_device(mac="AA:BB:CC:DD:EE:03", to_bubble_id=bubble.bubble_id)
```

### AI Autopilot - Event-Driven Efficiency Architecture

**Location**: `products/fortress/lib/autopilot/`
**Status**: Production Ready
**Branding**: "Sleep-and-Wake" Architecture

AI Autopilot replaces continuous monitoring with event-driven detection to achieve 99% efficiency. Instead of running traditional IDS/NSM 24/7 (15-40% CPU, 2GB RAM), it uses low-power sentinels that trigger deep analysis only when needed.

> *"Like motion-activated lights instead of stadium floodlights"*

**Resource Comparison**:

| Mode | CPU Usage | RAM Usage | Coverage |
|------|-----------|-----------|----------|
| Continuous (traditional IDS/NSM) | 15-40% | 2GB+ | 100% |
| AI Autopilot (Event-Driven) | 1% idle / 10% burst | <200MB | 99% |

**Architecture Overview**:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    AI AUTOPILOT (Event-Driven)                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ALWAYS-ON SENTINELS (<1% CPU)                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                     │
│  │    DHCP     │  │     OVS     │  │    IPFIX    │                     │
│  │  SENTINEL   │  │ MAC WATCHER │  │  SAMPLER    │                     │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                     │
│         │                │                │                             │
│         └────────┬───────┴────────┬───────┘                             │
│                  │                │                                     │
│                  ▼                ▼                                     │
│          ┌─────────────┐  ┌─────────────┐                              │
│          │ EFFICIENCY  │──│    n8n      │                              │
│          │   ENGINE    │  │  WORKFLOWS  │                              │
│          └──────┬──────┘  └─────────────┘                              │
│                 │                                                       │
│  BURST MODE (10% CPU, 60 seconds)                                      │
│                 ▼                                                       │
│          ┌─────────────┐                                               │
│          │  ON-DEMAND  │  tshark capture                               │
│          │    PROBE    │  MAC-filtered                                 │
│          └──────┬──────┘                                               │
│                 │                                                       │
│                 ▼                                                       │
│          ┌─────────────┐                                               │
│          │   BUBBLE    │  SDN rule update                              │
│          │ ASSIGNMENT  │                                               │
│          └─────────────┘                                               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Core Components**:

| Component | File | CPU | Purpose |
|-----------|------|-----|---------|
| **DHCP Sentinel** | `dhcp_sentinel.py` | 0% | Hook into dnsmasq lease events |
| **MAC Watcher** | `mac_watcher.py` | <0.1% | Poll OVS MAC table every 5s |
| **On-Demand Probe** | `probe_service.py` | 10% burst | 60s tshark capture per device |
| **IPFIX Collector** | `ipfix_collector.py` | <0.1% | Sampled D2D flow analysis |
| **Efficiency Engine** | `efficiency_engine.py` | <0.1% | Central coordinator |

**Dashboard State Indicators**:

| State | Icon | Meaning |
|-------|------|---------|
| **SLEEPING** | 🟢 Green | Idle, sentinels watching (saving power) |
| **IDENTIFYING** | 🔵 Blue Pulse | Processing new device (60s burst) |
| **PROTECTED** | 🛡️ Gold Shield | All devices in bubbles |

**DHCP Sentinel Setup**:

```bash
# In /etc/dnsmasq.d/fts-dhcp.conf:
dhcp-script=/opt/hookprobe/fortress/scripts/dhcp-hook.sh

# The hook captures DHCP Option 55 (OS fingerprint) for instant identification
```

**IPFIX Sampling Setup**:

```bash
# Configure OVS to sample 1/100 packets (discovery protocols only)
ovs-vsctl -- --id=@br get Bridge FTS -- \
    --id=@ipfix create IPFIX targets=\"127.0.0.1:4739\" \
    sampling=100 -- set Bridge FTS ipfix=@ipfix
```

**Python API**:

```python
from products.fortress.lib.autopilot import (
    get_efficiency_engine,
    get_dhcp_sentinel,
    get_mac_watcher,
    get_probe_service,
    get_ipfix_collector,
    AutopilotState,
)

# Start the engine (typically done by systemd)
engine = get_efficiency_engine()
engine.start()

# Check state for dashboard
if engine.state == AutopilotState.SLEEPING:
    print("🟢 Network quiet, saving power")
elif engine.state == AutopilotState.IDENTIFYING:
    print("🔵 Processing new device...")

# Manual probe trigger
probe = get_probe_service()
result = probe.probe("AA:BB:CC:DD:EE:FF", duration=60)
print(f"Ecosystem: {result.ecosystem}, Confidence: {result.confidence:.0%}")
```

**n8n Workflow**:

The workflow in `n8n-workflows/device-identification.json` automates:
1. Receive webhook from DHCP Sentinel
2. Trigger 60s probe capture
3. Parse fingerprint results
4. Auto-assign bubble (if confidence ≥80%) or notify admin
5. Save to ClickHouse
6. Update SDN rules

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
│  │       └── NexusConnector (ML/AI metrics)                ││
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
│  Product Tiers:  SENTINEL ──▶ GUARDIAN ──▶ FORTRESS ──▶ NEXUS                 │
│                  (Validate)   (Detect)     (Route)      (ML/Aggregate)          │
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

| Status | Protection | Action Triggered |
|--------|------------|------------------|
| **GREEN** | > 55% | All clear, learning baseline |
| **AMBER** | 30-55% | Monitoring, investigating |
| **RED** | < 30% | Defending, active mitigation |

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
    [ ] Detector identifies threat (NAPSE/ML)
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
- Dual-path: P2P mesh + cloud uplink
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
- Multi-tenant aggregation
- Historical threat database

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
products/fortress/web/app.py     # Fortress Flask app
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

# Fortress web UI (Flask)
cd products/fortress/web && python app.py

# Cortex visualization (demo mode)
cd shared/cortex/backend && python server.py --demo
```

---

**HookProbe v5.1 "Neural"** - Federated Cybersecurity Mesh
*One node's detection -> Everyone's protection*
