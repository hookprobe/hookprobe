# CLAUDE.md - AI Assistant Guide for HookProbe

**Version**: 6.1
**Last Updated**: 2026-09-08
**Purpose**: Non-derivable knowledge for AI assistants working with the HookProbe codebase. Layout, file listings, standard commands, and API details were removed in 6.1 — derive them from the code (`ls`, manifests, module READMEs) instead of this file.

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
| **D2D Bubble Algorithm** | Automatic relationship detection | `shared/aiochi/bubble/ecosystem_bubble.py` |
| **Device Fingerprinting (ML)** | 99% accuracy classifier | `products/fortress/lib/ml_fingerprint_classifier.py` |
| **Behavioral Clustering** | DBSCAN D2D bubbles | `products/fortress/lib/behavior_clustering.py` |
| **Multi-Modal Presence** | mDNS, BLE, spatial | `products/fortress/lib/presence_sensor.py` |
| **mDNS Query/Response Pairing** | Device discovery tracking | `products/fortress/lib/presence_sensor.py` |
| **D2D Connection Graph** | NAPSE-based device affinity | `shared/aiochi/bubble/connection_graph.py` |
| **Temporal Affinity Scoring** | Wake/sleep correlation | `shared/aiochi/bubble/connection_graph.py` |
| **ClickHouse Graph Storage** | Device relationship persistence | `shared/aiochi/bubble/clickhouse_graph.py` |
| **n8n Bubble Webhooks** | Workflow automation | `shared/aiochi/bubble/n8n_webhook.py` |
| **Reinforcement Learning** | Learn from corrections | `shared/aiochi/bubble/reinforcement_feedback.py` |
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
| **E2E security flow** | Attack detection→response→propagation | `/e2e-security-flow` skill (`.claude/skills/e2e-security-flow/SKILL.md`) |
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

## Project Overview

> **"One node's detection → Everyone's protection"**

HookProbe is a **federated cybersecurity mesh**: a $75 Raspberry Pi running HookProbe gets the same AI-powered protection as a $50,000 enterprise appliance. Security is a right, not a privilege.

**The HTP-DSM-NEURO-QSECBIT-NSE Security Stack:**

| Layer | Purpose | Innovation |
|-------|---------|------------|
| **HTP** | Transport | Post-quantum Kyber KEM, keyless authentication |
| **DSM** | Consensus | Byzantine fault-tolerant validation |
| **NEURO** | Identity | Neural fingerprinting via weight evolution |
| **QSECBIT** | Scoring | Real-time RAG status (GREEN/AMBER/RED) |
| **NSE** | Encryption | Keys emerge from neural state - nobody knows the password |

**Project Type**: Federated Security Platform / Infrastructure-as-Code
**Primary Languages**: Python (core logic), Bash (deployment)
**Web Frameworks**: Flask (Guardian, Fortress)
**Deployment**: Podman containers with OVS networking
**License**: Dual Licensed (AGPL v3.0 + Commercial) - see [Licensing](#licensing)

### Product Tiers

| Tier | RAM | Use Case | Location |
|------|-----|----------|----------|
| **Sentinel** | 256MB | IoT Validator (DSM validation, gossip receive-only) | `products/sentinel/` |
| **Guardian** | 1.5GB | Travel/Portable (full L2-L7 detection, local scoring) | `products/guardian/` |
| **Fortress** | 4GB | Small Business edge router (regional consensus, SDN) | `products/fortress/` |
| **Nexus** | 16GB+ | ML/AI Compute (federated training, aggregation) | `products/nexus/` |

---

## Licensing

Dual licensing model — know which license applies before advising on reuse. Full details: `LICENSING.md`. Contact: qsecbit@hookprobe.com.

- **Open source (AGPL v3.0)**: `deploy/`, `products/guardian/`, `products/fortress/`, `shared/response/`, `shared/mesh/`, `core/htp/`, `docs/`.
- **Proprietary (commercial license for SaaS/OEM use)**: `core/qsecbit/`, `core/neuro/`, `shared/dnsXai/`, `shared/dsm/`, `shared/slaai/`, `shared/aiochi/` (including the bubble modules), `products/fortress/lib/ml_fingerprint_classifier.py`, `behavior_clustering.py`, `presence_sensor.py`, and `products/fortress/lib/autopilot/`.
- Personal/home and internal business use of everything is free; SaaS offerings and OEM embedding require a commercial license.

---

## Codebase Structure

Derive the layout from the repo itself (`ls`, `find`, the Quick Lookup table above). Top-level map:

- `core/` — core intelligence: `htp/` (transport + crypto), `qsecbit/` (scoring, detectors, XDP, response), `neuro/` (neural resonance protocol), `napse/` (AI-native IDS), `hydra/` (threat intel pipeline), `aegis/` (AI orchestrator)
- `shared/` — cross-product infrastructure: `dnsXai/`, `dsm/`, `mesh/`, `response/`, `wireless/`, `hostapd-ovs/`, `cortex/`, `slaai/`, `aiochi/`
- `products/` — tier-specific code: `sentinel/`, `guardian/`, `fortress/`, `nexus/`
- `deploy/` — edge/cloud deployment scripts and addons (n8n, LTE, webserver)
- `infrastructure/` — pod templates (email, DSM)
- `tests/` — all test suites; `docs/` — documentation index at `docs/DOCUMENTATION-INDEX.md`
- `assets/forty/` — HTML5UP Forty template, the UI design reference for product web UIs

---

## Core Modules

### Qsecbit (`core/qsecbit/`)

The threat-scoring brain. The resilience metric:

```python
Qsecbit = α·drift + β·p_attack + γ·decay + δ·q_drift + ε·energy_anomaly
# Defaults: α=0.30 drift, β=0.30 attack probability, γ=0.20 classifier decay, δ=0.20 quantum drift
# With dnsXai: 0.30·threats + 0.20·mobile + 0.25·ids + 0.15·xdp + 0.02·network + 0.08·dnsxai
```

| RAG Status | Protection | Meaning |
|--------|------------|---------|
| **GREEN** | > 55% | Protected, learning baseline |
| **AMBER** | 30-55% | Monitoring, investigating |
| **RED** | < 30% | Defending, active mitigation |

Subpackages: `detectors/` (L2-L7 per-OSI-layer detectors), `ml/`, `response/` (orchestrator), `signatures/`. XDP/eBPF mitigation in `xdp_manager.py`; NIC capability detection (XDP-hw/drv/skb) in `nic_detector.py`.

### HTP (`core/htp/`)

Keyless secure transport: authentication via entropy echo instead of stored keys, post-quantum Kyber hybrid KEM (`crypto/hybrid_kem.py`), ChaCha20-Poly1305 transport, VPN and file-transfer modes.

### Neuro (`core/neuro/`)

Living cryptography — the neural network *is* the key: identity proven by replaying sensor history through weight evolution `W(t+1) = W(t) - η_mod × ∇L(W(t), TER)`. TER/PoSF/replay in `core/`, fixed-point Q16.16 math in `neural/`, hardware fingerprinting in `identity/`, offline TER storage in `storage/dreamlog.py`.

---

## Shared Infrastructure

### dnsXai (`shared/dnsXai/`)

ML-based DNS protection (DGA, DNS-tunneling, CNAME-uncloaking detection; 5 protection levels; wildcard whitelisting). See `shared/dnsXai/README.md` for the API surface and feature list; the HTTP API lives in `api_server.py`, the classifier in `engine.py`. Non-obvious: the whitelist auto-syncs between API and DNS engine via 5s polling, and a set of protected infrastructure domains (OS connectivity checks, package repos, CDNs) is never blocked regardless of level.

### Mesh (`shared/mesh/`)

**Read `shared/mesh/ARCHITECTURE.md` before touching mesh code.** Anti-blocking port ladder (not guessable from code alone):

```
PRIMARY:    8144/UDP + 8144/TCP
FALLBACK:   443/UDP (QUIC cover) + 443/TCP (TLS-wrapped)
STEALTH:    853/UDP (DoQ cover) + 853/TCP (DoT cover)
EMERGENCY:  80/TCP (WebSocket) + ICMP tunnel
```

Consciousness states: `DORMANT → AWAKENING → AWARE → SYNCHRONIZED → AUTONOMOUS` (`consciousness.py`). High-level API: `unified_transport.py`.

### DSM (`shared/dsm/`)

Byzantine fault-tolerant consensus: BLS signature aggregation with 2/3 quorum (`consensus.py`), P2P gossip, microblock ledger, TPM-backed attestation in `crypto/`.

### Response (`shared/response/`)

Automated mitigation orchestration (Kali-on-demand). Entry point: `attack-mitigation-orchestrator.sh`; install guide in `MITIGATION_INSTALLATION_GUIDE.md`.

### Wireless / DFS (`shared/wireless/`)

ML-powered WiFi channel selection with radar-event tracking. Regulatory constraint worth remembering: DFS channels require CAC (60s UNII-2A, 600s UNII-2C weather-radar band) and a 30-minute Non-Occupancy Period after radar detection (ETSI EN 301 893) — the scoring in `dfs_intelligence.py` encodes this; don't bypass it.

### hostapd-ovs (`shared/hostapd-ovs/`)

**Why this exists (gotcha)**: standard hostapd detects bridge membership via sysfs (`/sys/class/net/<bridge>/brif/`), which OVS bridges never populate — so stock hostapd cannot bridge WiFi directly to OVS. The patch adds an `ovs-vsctl port-to-br` fallback (with interface-name validation against command injection and a 1s timeout). Without it, Fortress falls back to a veth + Linux-bridge shim. Mode is recorded in `/etc/hookprobe/fortress.conf` as `HOSTAPD_OVS_MODE=true|false`; the Fortress installer builds it automatically. `bridge=FTS` goes directly in hostapd.conf with `ap_isolate=1` recommended. Details: `shared/hostapd-ovs/README.md`.

### SLA AI (`shared/slaai/`)

Predictive WAN failover + cost-aware failback (LSTM predictor, metered-LTE budget tracking, adaptive DNS). Read `shared/slaai/ARCHITECTURE.md`. Integration contract with Fortress PBR: recommendations are written to `/run/fortress/slaai-recommendation.json` (`integrations/pbr.py`).

### AIOCHI (`shared/aiochi/`)

Cognitive layer that turns raw events into human narratives via local LLM (Ollama llama3.2:3b) + ClickHouse + Grafana + n8n. Read `shared/aiochi/ARCHITECTURE.md`. Install with `./install.sh --tier fortress --enable-aiochi` (~2GB RAM, ~4GB disk). Non-obvious behaviors:
- When AIOCHI is enabled, the overlapping optional fts-* services (grafana, victoria, n8n, clickhouse) are **skipped** — AIOCHI's containers provide them; `INSTALL_AIOCHI=true` is saved to `/etc/hookprobe/fortress.conf`.
- The ~2GB LLM model download runs **asynchronously** after install (log: `/var/log/fortress/aiochi-llm-download.log`) — don't treat a missing model right after install as a failure.

---

## Product Tiers

### Guardian (`products/guardian/`)

Portable travel gateway. Backend in `lib/` (agent, L2-L7 detection, mesh integration), Flask web UI in `web/` with blueprint modules under `web/modules/` — register new blueprints in `app.py`. UI follows the Forty design (reference: `assets/forty/`, palette in `web/static/css/main.css`). Cortex globe is served via the `/cortex-modules/<filename>` route from `/opt/hookprobe/shared/cortex/frontend/js/` (copied by `scripts/setup.sh`).

### Fortress (`products/fortress/`)

Small-business edge router: Podman containers (fts-* prefix, single `fts-internal` network 172.20.200.0/24), Flask + AdminLTE web UI behind Flask-Login, PostgreSQL + Redis, OVS bridge `FTS` (Layer 2 only — segmentation via OpenFlow rules, **no VLAN tagging**), dnsmasq DHCP on 10.200.0.0/XX. Read `products/fortress/DEVELOPMENT_PLAN.md` for the roadmap. Non-obvious facts:

- **WiFi interface naming is udev-pinned**: MAC-based stable names `wlan_24ghz`/`wlan_5ghz` via `/etc/udev/rules.d/70-fts-wifi.rules`, mapping saved to `/etc/hookprobe/wifi-interfaces.conf`. Systemd APs: `fts-hostapd-24ghz.service`, `fts-hostapd-5ghz.service`.
- **Auth is a JSON file, not the database**: `/etc/hookprobe/users.json`, bcrypt, max 5 users, roles admin/operator/viewer.
- Boot ordering: `fortress-vlan.service` runs OVS post-setup after netplan, before containers (`fortress.service`).
- Optional containers are compose *profiles* (monitoring, training, ids, automation, analytics, mesh, tunnel).
- Runtime management: `fortress-ctl.sh` (backup/status); config lives in `/etc/hookprobe/fortress.conf`.
- When porting a Guardian web module: add `@login_required` (and `admin_required` where appropriate) and convert the template to AdminLTE `base.html`.

### D2D Bubble System (Ecosystem Bubble)

> **IMPORTANT — two different things share the "bubble" name:**
> | Concept | Description | Code Location |
> |---------|-------------|---------------|
> | **Device Groups** | Manual CRUD for user-organized device grouping with OpenFlow policies (Web UI) | `products/fortress/web/modules/bubbles/views.py` |
> | **D2D Bubbles** | Automatic background algorithm detecting device relationships from traffic, coloring them in the UI | `shared/aiochi/bubble/ecosystem_bubble.py` |
>
> They are **INDEPENDENT** — a device can be in the "Work" group yet colored with "Dad's iPhone" by D2D affinity.

Affinity score: `S_aff = discovery_hits×0.10 + d2d_flows×0.05 + temporal_sync×0.02`, adjusted ±0.5 by reinforcement feedback from user corrections (`reinforcement_feedback.py`: +0.15 positive, −0.20 negative, 0.95 daily decay). Components: `presence_sensor.py` (mDNS query/response pairing → discovery hits), `connection_graph.py` (NAPSE flows + temporal wake/sleep correlation), `behavior_clustering.py` (DBSCAN), `clickhouse_graph.py` (persistence), `n8n_webhook.py` (events). Bubble types map to VLANs: FAMILY=110, WORK=120, IOT=130, GUEST=150.

### AI Autopilot (`products/fortress/lib/autopilot/`)

Event-driven "sleep-and-wake" replacement for 24/7 IDS monitoring (~1% idle CPU vs 15-40%): DHCP sentinel + OVS MAC watcher + sampled IPFIX trigger a 60s tshark burst probe on new/unknown devices, then bubble assignment. Wiring that isn't obvious from the code:
- dnsmasq hook: `dhcp-script=/opt/hookprobe/fortress/scripts/dhcp-hook.sh` in `/etc/dnsmasq.d/fts-dhcp.conf` (captures DHCP Option 55 OS fingerprints).
- OVS IPFIX sampling (1/100, discovery protocols) is configured on bridge `FTS` targeting `127.0.0.1:4739`.
- Dashboard states: SLEEPING (green), IDENTIFYING (blue, 60s burst), PROTECTED (gold).

### Cortex (`shared/cortex/`)

Real-time 3D digital twin of the mesh (Globe.gl + Deck.gl/MapLibre city view). WebSocket server in `backend/server.py` with demo/live mode toggle; per-tier connectors in `backend/connectors/` aggregated by `manager.py`. Node color = Qsecbit RAG status; red arcs = attacks, blue = repelled. Phase 2 docs: `shared/cortex/PHASE2-CITY-VIEW.md`.

---

## End-to-End (E2E) Security Flow

The full detection → scoring → response → mesh propagation → DSM consensus → Neuro auth pipeline, including the E2E validation checklist and integration file map, lives in the **`/e2e-security-flow` skill** (`.claude/skills/e2e-security-flow/SKILL.md`). Load it when validating or reasoning about the complete flow. E2E tests: `pytest tests/test_e2e_integration.py -v`.

---

## Testing

`pytest tests/` (config in `pytest.ini`: markers, 30% coverage floor over `core/` + `shared/`). `make test` / `make lint` / `make format` — see the `Makefile` for the rest. CI gates on the engine-unit lane: `python -m pytest tests/ -m "not integration and not product" -q`.

---

## CI/CD Workflows

Workflows live in `.github/workflows/` (lint, app tests, container/installation/ARM64 tests, docs, config validation).

> **App Tests deps are inline, not a requirements file** (updated 2026-06-11):
> the gate installs exactly `pytest numpy scipy cryptography psutil`. There is
> no `requirements-test.txt`, so a new module-level third-party import in any
> code that tests touch (e.g. `shared/dsm/crypto/tpm.py` → `cryptography`,
> `core/qsecbit/qsecbit.py` → `scipy`) fails COLLECTION and kills the whole
> gate — and the abort masks any further missing deps behind it. When CI
> fails with `ModuleNotFoundError`, reproduce with a clean venv installing
> exactly that list, fix the list in BOTH jobs of `app-tests.yml`, and re-run
> the full lane locally before pushing (`python -m pytest tests/ -m "not
> integration and not product" -q` — expect ~945 passed). A mock-assertion
> failure appearing only alongside import errors is usually cascade
> pollution, not a real regression.

### Security posture: socket binds (CodeQL, resolved 2026-06-11)

All 15 CodeQL alerts triaged. `0.0.0.0` binds in STUN/NAT-traversal/relay
sockets are a **protocol requirement** (hole punching must receive on the
path interface) — dismissed as won't-fix with rationale on each alert. The
four plain service listeners are env-overridable for multi-homed hosts
(defaults unchanged): `SENTINEL_BIND_HOST`, `IPFIX_BIND_HOST`,
`HTP_BIND_HOST`, `DSM_GOSSIP_BIND_HOST` (commit `e5a659c7`). The
clear-text-logging alert on `core/hydra/anomaly_detector.py` was a false
positive (log emits only `len()` counts; CH auth goes via headers).

> **Expect re-flags**: CodeQL traces the intentional `0.0.0.0` default
> literal through `os.environ.get()`, so any edit that shifts these lines
> opens NEW alert numbers for the same sites (seen 2026-06-11: #947-#950
> re-flagged the four hardened listeners). Dismiss as won't-fix citing the
> env override + this section — do not "fix" by changing the default,
> which would break the services.

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

**Python** (PEP 8): Black (line length 100), isort (profile: black), type hints on signatures, Google-style docstrings.

**Bash**: `set -e` and `set -u` at the top; UPPERCASE config variables, lowercase locals.

### Git Conventions

Branches: `feature/`, `fix/`, `docs/`, `security/`, `claude/` (AI-generated).

Commit format: `type(scope): brief description` + body + `Fixes: #123`. Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `security`.

---

## Security Considerations

1. **NEVER hardcode credentials**
2. **NEVER disable security features**
3. **ALWAYS validate input** in Python
4. **AVOID command injection**
5. **CHECK for secrets** before commit (`make security`; `deploy/*/config.sh` and `.env` files must never be committed with real values)

Getting help: `docs/DOCUMENTATION-INDEX.md`, `shared/mesh/ARCHITECTURE.md`, GitHub Issues; security contact qsecbit@hookprobe.com.

---

**HookProbe v5.1 "Neural"** - Federated Cybersecurity Mesh
*One node's detection -> Everyone's protection*
