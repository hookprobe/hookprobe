# V1 source map — complete structural inventory of `~/hookprobe`

> **Scope:** every folder/subfolder of the HookProbe **V1** source tree (`/home/andrei/hookprobe`), what it is, language, entry point, and how it builds — so nothing is unmapped. Prior passes only covered specific engines (htp/dsm/neuro/napse/qsecbit); this covers **everything**, especially the previously-unmapped **`products/`**, **`infrastructure/`**, **`deploy/`**, **`sdk/`**, and tooling layers.
>
> **Method:** first-hand inspection on 2026-06-29 (read-only). Trees from `find`, file/LOC counts from `find … | cat | wc -l`, build mechanics from reading `install.sh`, `Makefile`, every `Containerfile*`, the `podman-compose*.yml`, `build.zig`, the two `Makefile`s, and all systemd units.
>
> **Companion:** [runtime-engine-map.md](runtime-engine-map.md) maps `core/*` + `shared/*` engines to V2 runtimes. **It does not cover `products/`, `infrastructure/`, `deploy/`, `sdk/`, `scripts/`, `bin/`, `config/`, `tests/`** — §12 below closes that gap. §13 records where V1's build reality contradicts the V2 scaffold (chiefly eBPF compile strategy).

---

## 1. Top-level layout

13 significant top-level directories + a large set of root scripts/docs.

| Dir / file | Purpose | Primary lang | In runtime-map? |
|---|---|---|---|
| `core/` | The engines (detection/identity/transport/orchestration) | Python + Zig + C + Mojo | ✅ all 9 subdirs |
| `shared/` | Cross-product engines/libs (mesh, dnsXai, dsm, aiochi, iam, mssp, slaai, wireless, …) | Python (+ JS, bash, C) | ✅ all 15 subdirs |
| `products/` | The 4 deployment SKUs (Sentinel/Guardian/Fortress/Nexus): product-assembly code, web UIs, containers, systemd, HW profiles | Python + Bash + HTML/JS | ❌ **not mapped** |
| `scripts/` | Operational/install/test helper scripts + shared bash libs | Bash | ❌ not mapped |
| `deploy/` | Edge systemd units, mesh-gateway, addons (n8n/webserver/lte), cloud | Bash + systemd + Python | ❌ not mapped |
| `sdk/` | Public SDKs: Python (`hookprobe`) + TypeScript (`@hookprobe/sdk`) MSSP API clients | Python + TypeScript | ❌ not mapped |
| `infrastructure/` | Numbered "POD" services: pod-002-iam (Logto), pod-009-email (mail DMZ), pod-010-dsm | YAML compose + Python + Bash | ❌ not mapped |
| `tests/` | pytest suite (unit/integration/security/e2e), 30 modules | Python | ❌ not mapped |
| `bin/` | `hookprobe-ctl` CLI wrapper | Bash | ❌ not mapped |
| `config/` | Runtime config: mitigation, GDPR, neuro/dsm phase-1 YAML | conf/YAML/Bash | ❌ not mapped |
| `docs/` | Project docs (architecture, components, guides, installation, dashboards) | Markdown | n/a |
| `assets/`, `reports/` | Static assets / generated reports | — | n/a |
| **root scripts** | `install.sh` (131 KB interactive installer), `uninstall.sh`, `install-validator.sh`, `install-sentinel-lite.sh`, `Makefile` | Bash + Make | ❌ not mapped |

---

## 2. Full directory tree (annotated, `__pycache__`/`.git` excluded)

```
hookprobe/
├── core/                       # ENGINES (9 dirs + agency_shim.py)
│   ├── aegis/                  # security orchestration (LLM planner + deterministic guards)
│   │   ├── agents/             #   persona agents: scout/medic/shield/vigil/watchdog/oracle/guardian/scribe/forge
│   │   ├── bridges/            #   adapters to dhcp/dnsxai/hydra/napse/qsecbit/wan
│   │   ├── neurokernel/        #   LLM-driven eBPF synthesis: ebpf_compiler, sandbox, verifier, RAG, vector_store
│   │   ├── profiles/ prompts/ reflex/ tools/
│   ├── brain/                  # AI inference + HW detection
│   │   └── engines/            #   backends: llama/openvino/tensorrt/hailo/rknn/coreml/litert
│   ├── cno/                    # "cognitive organism" (prefrontal/metacognition/global_workspace), federated_sync
│   │   └── native/             #   popcount.c, xsk_consumer.c, synaptic_sort.zig (userspace .so via ctypes)
│   ├── common/                 # health.py, clickhouse.py
│   ├── htp/                    # HookProbe Transport Protocol (post-quantum, keyless)
│   │   ├── crypto/             #   hybrid_kem.py (X25519+Kyber512), transport(_v2).py
│   │   ├── steganography/      #   decoy_generator, domain_fronting, traffic_shaper
│   │   └── transport/          #   htp.py, htp_file.py, htp_vpn.py
│   ├── hydra/                  # SOAR analytics: anomaly/baseline/predictor + feed_sync/cve/rdap + bpf_map_ops
│   ├── napse/                  # IDS/NSM — the split-brain capture engine (see §4)
│   │   ├── aegis/              #   ZIG XDP capture: build.zig, src/{xdp_program,main,entropy,feature_extract,ring_buffer}.zig
│   │   ├── brain/              #   MOJO classify: src/*.mojo (8 files), mojoproject.toml
│   │   ├── kernel/             #   C eBPF: xdp_gate/conntrack_lite/ringbuf_events/process_tracer/syscall_monitor/hotpatch + xdp_hydra/xdp_synwall (+.o) + af_xdp_rx.c (userspace)
│   │   ├── inspector/          #   packet_inspector.py (Python fallback classifier)
│   │   ├── intelligence/       #   bayesian_scorer, entity_graph, graph_embedder, intent_decoder, sia_engine
│   │   ├── synthesis/          #   event_bus.py
│   │   ├── signatures/         #   napse_rules.yaml + converter.py
│   │   ├── qsecbit/ config/ configs/ schemas/ engine(DEPRECATED) tests/
│   ├── neuro/                  # neural-resonance device identity / NSE crypto
│   │   ├── core/               #   posf, replay, ter, weight_chain
│   │   ├── neural/             #   backprop, engine, fixedpoint
│   │   ├── puf/                #   sram/clock_drift/cache_timing PUFs, composite_identity
│   │   ├── adversarial/ attestation/ audit/ identity/ network/ product_adapters/ storage/ tools/ validation/
│   └── qsecbit/                # composite resilience score
│       ├── detectors/          #   l2..l7 layer detectors
│       ├── ml/                 #   classifier, hybrid_classifier, vae_anomaly, neural_drift
│       ├── response/ signatures/
│       └── xdp_manager.py nic_detector.py  # eBPF DDoS (BCC-runtime) + NIC capability probe
├── shared/                     # CROSS-PRODUCT ENGINES (15 dirs)
│   ├── aiochi/                 # "AI eyes" narrative layer + openrouter client (backend/bubble/playbooks/containers)
│   ├── common/                 # gossip_envelope
│   ├── cortex/                 # fleet command center (backend + frontend JS + globe)
│   ├── dnsXai/                 # explainable DNS adblock (lexical features + neural classifier + CNAME uncloak)
│   ├── dsm/                    # Byzantine consensus, merkle, gossip, BLS, ledger, bloom_ioc, microblock
│   ├── hostapd-ovs/            # hostapd 2.10/2.11 + OVS bridge patch (C build)
│   ├── iam/                    # RBAC + Keycloak middleware
│   ├── mesh/                   # federated transport, NAT traversal, htp_gateway, consciousness
│   ├── mirage/                 # adaptive honeypot / deception
│   ├── mobile_security/        # mobile network protection
│   ├── mssp/                   # multi-tenant telemetry/bootstrap/client
│   ├── network/                # segmentation + SDN OpenFlow controller (sdn/)
│   ├── response/               # mitigation (bash + systemd, iptables/kali)
│   ├── slaai/                  # SLA failover/failback, PBR, cost-aware routing
│   └── wireless/               # DFS intelligence + channel scanner (containers/)
├── products/                   # 4 SKUs (see §5) — NOT in runtime-map
│   ├── sentinel/  guardian/  nexus/  fortress/
├── infrastructure/             # PODs (see §6) — NOT in runtime-map
│   ├── pod-002-iam/  pod-009-email/  pod-010-dsm/
├── deploy/                     # edge systemd, mesh-gateway, addons, cloud, install
├── sdk/                        # python/ + typescript/
├── scripts/                    # ops/install/test bash + lib/
├── tests/  bin/  config/  docs/  assets/  reports/
└── install.sh uninstall.sh install-validator.sh install-sentinel-lite.sh Makefile
```

---

## 3. `core/*` engine inventory

`core/` = **232 Python files + native hot paths**. No top-level daemon — engines are libraries imported by products/systemd; only `core/cno/__main__.py` is directly runnable.

| Engine | Lang(s) | Key files / entry | Native? |
|---|---|---|---|
| `core/aegis` | Python | `orchestrator.py`, `oracle.py`, `narrator.py`, `principle_guard.py`, `client.py`, `agents/*`, `neurokernel/*`, `bridges/*`, `reflex/*` | neurokernel **generates eBPF at runtime** (`ebpf_compiler.py`) |
| `core/brain` | Python | `hw_detect.py` (probes 13 accel types at startup), `inference_bridge.py`, `engines/{llama,openvino,tensorrt,hailo,rknn,coreml,litert}_engine.py` | calls vendor runtimes |
| `core/cno` | Python + **C + Zig** | `__main__.py` (only runnable entry), `cno_organism.py`, `federated_sync.py`, `native/{popcount.c, xsk_consumer.c, synaptic_sort.zig}` + `native/Makefile` | **yes** (userspace `.so` via ctypes; xsk_consumer uses AF_XDP/libbpf) |
| `core/common` | Python | `health.py`, `clickhouse.py` | — |
| `core/htp` | Python | `transport/{htp,htp_file,htp_vpn}.py`, `crypto/hybrid_kem.py` (X25519+**Kyber512**), `steganography/*` | — |
| `core/hydra` | Python | `event_consumer.py`, `anomaly_detector.py`, `predictor_engine.py`, `feed_sync.py`, `cve_enricher.py`, `rdap_enricher.py`, `bpf_map_ops.py` | reads eBPF maps |
| `core/napse` | **Zig + C + Mojo + Python** | split-brain: `aegis/` (Zig XDP capture), `brain/` (Mojo classify), `kernel/` (C eBPF), `inspector/` (Python fallback), `intelligence/` (Python synthesis), `synthesis/event_bus.py` | **yes — the crown jewel** (see §9) |
| `core/neuro` | Python | `synaptic_encryption.py` (bespoke "nobody-knows-the-key" crypto), `puf/*`, `core/{posf,ter,weight_chain}.py`, `neural/*`, `attestation/`, `identity/` | — |
| `core/qsecbit` | Python | `qsecbit.py`/`unified_engine.py` (score), `detectors/l2..l7`, `ml/{classifier,vae_anomaly,neural_drift,hybrid_classifier}.py`, `xdp_manager.py` (BCC eBPF), `nic_detector.py`, `qsecbit-agent.py` | `xdp_manager.py` compiles eBPF via **BCC at runtime** |
| `core/agency_shim.py` | Python | single-file governance shim | — |

## 4. `shared/*` engine inventory

`shared/` = **135 Python + 15 bash files** (+ JS in cortex/aiochi).

| Engine | Key files / entry | Notes |
|---|---|---|
| `shared/aiochi` | `backend/*` (honeypot_mesh, attack_chain_predictor, data_gravity_monitor, nse_ghost_probe), `bubble/`, `containers/` (3 Containerfiles + compose + `aiochi.service`) | large; LLM narration; ClickHouse-backed |
| `shared/cortex` | `backend/` + `frontend/` (JS) | fleet command center UI |
| `shared/dnsXai` | `engine.py`, `api_server.py`, `mesh_intelligence.py`, `data/` | lightweight ML DNS classifier |
| `shared/dsm` | `consensus.py`, `merkle.py`, `gossip.py`, `ledger.py`, `microblock.py`, `bloom_ioc.py`, `validator.py`, `identity.py` | Byzantine consensus + BLS |
| `shared/hostapd-ovs` | hostapd source + OVS bridge patch (C/bash build) | image-layer dataplane |
| `shared/iam` | `middleware.py`, `backends.py`, `roles.py`, `decorators.py` | Keycloak/RBAC |
| `shared/mesh` | `mesh_server.py`, `federated_transport.py`, `htp_gateway.py`, `nat_traversal.py`, `consciousness.py`, `channel_selector.py` | P2P transport; `htp_gateway.py` is the mesh-gateway daemon |
| `shared/mirage` | `adaptive_honeypot.py`, `orchestrator.py`, `intelligence_feedback.py` | deception |
| `shared/mobile_security` | `mobile_network_protection.py` | niche detection |
| `shared/mssp` | `bootstrap.py`, `client.py`, `telemetry_collector.py` | the cloud-enrollment client used by all products |
| `shared/network` | `segmentation.py`, `sdn/` (OpenFlow controller) | over OVS |
| `shared/response` | bash + systemd mitigation (iptables) | no Python entry |
| `shared/slaai` | `engine.py`, `predictor.py`, `failback.py`, `cost_tracker.py`, `metrics_collector.py`, `dns_intelligence.py` | SLA/WAN failover |
| `shared/wireless` | `dfs_intelligence.py`, `channel_scanner.py`, `containers/dfs-intelligence/Containerfile` | needs reg-domain host access |
| `shared/common` | `gossip_envelope.py` | shared fleet lib |

---

## 5. `products/*` — the 4 deployment SKUs (NOT in runtime-map)

Products are **product-assembly layers** that wire core/shared engines into a shippable SKU (web UI + systemd + containers + HW profiles). They reuse core/shared via imports (`shared.mssp` 26×, `shared.aiochi` 11×, `core.aegis` 7×, `shared.wireless` 7×, `core.qsecbit` 3×, `core.brain.hw_detect` 4×, `shared.mesh`/`shared.dsm`/`shared.slaai`/`core.htp` …) **but also carry substantial product-only engine code** (see "unique engines").

| Product | Role / target | LOC (py+sh) | Containers | systemd | Web UI | Unique engines (not in core/shared) |
|---|---|---|---|---|---|---|
| **Sentinel** | 256 MB IoT validator | ~5.8 K (8 py, 2 sh) | 0 | 1 (generated by `bootstrap.sh`) | none | `lib/{aegis_pico, sentinel_agent, defense}.py`, `signatures/basic.rules` |
| **Guardian** | 1.5 GB RPi travel gateway | ~29.6 K (53 py, 11 sh) | 0 (containerless daemons) | 11 (`config/systemd/guardian-*.service`) | Flask (`web/app.py`) | `lib/{aegis_lite, hydra_lite, evil_twin_detector, captive_portal_detector, doh_proxy, openflow_controller, offline_mode_manager}.py` |
| **Fortress** | 4 GB edge router (~51% of products LOC) | ~105 K (88 py, 62 sh) | **8 Containerfiles** | **21** (`systemd/fts-*.service`) | Flask + AdminLTE (16 web modules) | `qsecbit/fortress_agent.py` (L2-L7 score), `lib/{sdn_autopilot.py (108KB), unified_fingerprint_engine, ml_fingerprint_classifier, ja3_fingerprint, behavior_clustering, lstm_threat_detector, device_trust_framework, device_lifecycle, presence_sensor, fingerbank, mdns_resolver, hostname_decoder}.py`, `lib/autopilot/{dhcp_sentinel, ipfix_collector, mac_watcher, efficiency_engine, probe_service}.py` |
| **Nexus** | 16 GB+ ML/fleet hub | ~9.7 K (18 py, 4 sh) | 0 (container-based via setup.sh) | 0 | none | `lib/aegis_deep.py`, `lib/federated/{aggregation_server, model_registry, participant, privacy}.py`, `lib/intelligence/{analysis_engine, correlator, recommender, mssp_worker}.py`, `lib/red_purple_teaming/{orchestrator, digital_twin, meta_regressor, bubble_attacks, nse_heartbeat}.py`; `radius/` (FreeRADIUS 802.1X), `vpn/` (StrongSwan IPsec) |

**Fortress web** (`products/fortress/web/app.py`, gunicorn) is a Flask app whose `modules/` are workspace-like lenses: `auth, api, dashboard, dnsxai, security, clients, networks, settings, sdn, tunnel, vpn, aegis, aiochi, bubbles, mssp, slaai` — effectively a V1 precursor to Mission Control workspaces.

**Fortress HW profiles** (`products/fortress/devices/`): `common/` (shared scripts: detect-hardware.sh, dfs-radar-monitor.py, bridge-manager.sh, adaptive-txpower.sh) + per-board `intel-n100/`, `rpi-cm5/`, `radxa-rock5b/`, `template/` each with `interfaces.sh` + `profile.conf`. This is the V1 analogue of V2's `platforms/*.yaml`.

**Fortress systemd families** (21): XDP (`fts-xdp` loads `xdp_hydra` in monitor mode), detection (`fts-napse`, `fortress-ids`, `fts-fingerprint-engine`), network (`fts-vlan`, `fts-nac-sync`, `fts-wan-failover`, `fts-wifi-signal*`), device (`fts-device-lifecycle*`, `fts-device-status*`, `fts-arp-export*`, `fts-presence-sensor`), mesh (`fts-htp-vpn`, `fts-cno`, `fts-bubble-manager`, `aiochi`), continuity (`fts-slaai`, `fts-lte-collector*`), cleanup (`fortress-ovs-cleanup`, `fortress-selfheal*`).

---

## 6. `infrastructure/` — the "POD" services (NOT in runtime-map)

`pod-NNN` = numbered infrastructure/security zones (the installer/uninstaller reference PODs 001–010; 002/009/010 are present as standalone compose stacks).

| POD | What it is | Stack |
|---|---|---|
| `pod-002-iam` | **Logto 1.14** OIDC identity provider (API :3001, Admin :3002), Postgres-backed | `podman-compose.yml` + `setup.sh` + `.env.example` |
| `pod-009-email` | **Self-hosted email with dual-firewall DMZ**: Postfix relay, SpamAssassin, ClamAV, **NAPSE-as-mail-IDS** (`hookprobe/napse:2.0`), internal Dovecot mailserver, Cloudflare tunnel, Promtail | `docker-compose.yml` (335 lines, 9 services) + `firewall-rules/*.sh` (iptables) + `dmz-gateway/`, `internal-server/`, `cloudflare/`, `django-integration/` |
| `pod-010-dsm` | **Decentralized Security Mesh** ledger node + API: LevelDB microblocks, gossip, TPM signing (sw fallback), BLS quorum | `docker-compose.yml` (env: `DSM_NODE_ROLE=edge|validator`, `DSM_TPM_ENABLED`) |

---

## 7. `deploy/`, `sdk/`, `scripts/`, `bin/`, `config/`, `tests/`

**`deploy/`** (Bash + systemd + Python):
- `edge/systemd/` — 5 units: `hookprobe-provision.service` (oneshot first-boot `provision.sh`, after podman+openvswitch), `hookprobe-agent.service` (runs `qsecbit-agent.py`, CAP_BPF/NET_ADMIN/NET_RAW/SYS_ADMIN, 1 GB cap, health :8888), `hookprobe-update.service` + `.timer` (weekly `git pull` Sun 03:00 ±1 h), `hookprobe-uninstall.service` (`cleanup.sh`).
- `mesh-gateway/mesh-gateway.service` — runs `shared/mesh/htp_gateway.py` (HTP node discovery; hardened: NoNewPrivileges/ProtectHome/PrivateTmp).
- `addons/` — `n8n/` (workflow automation), `webserver/` (Containerfile + entrypoint, host sites behind HookProbe), `lte/` (WAN failover).
- `cloud/` — `setup.sh`/`config.sh`/`uninstall.sh` (Nexus cloud).
- `install/validate-config.sh`.

**`sdk/`**:
- `python/` — pkg `hookprobe` 0.1.0 (setuptools, AGPL-3.0, py≥3.9), CLI `hookprobe-ctl` → `hookprobe.cli:main`; exports `HookProbeClient` (MSSP REST: nodes/qsecbit/heartbeat/telemetry/incidents/iocs/verdicts), `detect_hardware()`, `InferenceBridge`. Optional extras `inference`/`full` (numpy, llama-cpp-python).
- `typescript/` — pkg `@hookprobe/sdk` 0.1.0 (MIT, Node≥18, ESM), build `tsc` → `dist/`; `src/index.ts` + `src/types.ts`.

**`scripts/`** (16 bash + `lib/`): `install-edge.sh` (139 KB), `install-hookprobe.sh`, `setup-ids-mirror.sh`, `setup-vrf.sh`, `hydra-xdp-deploy.sh`, `hydra-nftables-sync.sh`, `gdpr-retention.sh`, `security-alert.sh`, `repo-cleanup-validator.sh`, `run-{unit,integration,performance}-tests.sh`, `run-benchmark.sh`. `lib/` = `platform.sh` (HW detection), `requirements.sh` (dep checker), `instructions.sh` (menu).

**`bin/`**: `hookprobe-ctl` (4.6 KB bash CLI).

**`config/`**: `mitigation-config.conf` (auto-block/honeypot thresholds, qsecbit :8888/VictoriaMetrics/ClickHouse endpoints), `gdpr-config.sh`, `neuro-phase1.yaml`, `dsm-phase1.yaml`.

**`tests/`**: pytest, ~18 K LOC, 30 modules. Markers (`pytest.ini`): `unit, integration, slow, security, network, htp, qsecbit, ai_vs_ai, e2e, product`. Notable: `test_qsecbit`, `test_neurokernel`, `test_htp_e2e`, `test_dsm_*`, `test_aegis_*`, `test_guardian_*`, `test_red_purple_teaming`, `test_mirage`.

---

## 8. Build & packaging

**`install.sh` (131 KB, interactive menu installer)** — the V1 master entry. Flow: `detect_os` → `detect_{architecture,kernel,cpu,ram,storage,platform}` → `detect_network_interfaces` → `detect_{internet,virtualization,cgroups,security,gpu,npu,container_runtime,capabilities}` → `evaluate_deployment_tiers` → `configure_hookprobe_bridge` → menu → `install_{sentinel,guardian,fortress,nexus}` / `uninstall_*`. **It re-probes hardware on every run** (detect-once violation, mirrors `core/brain/hw_detect.py`). `uninstall.sh` (v5.1) tears down tiers + PODs 001–007 + cloud + n8n.

**Root `Makefile`** — dev/ops convenience: `install`/`install-dev`/`setup` (pip), `test`/`test-coverage`/`test-fast` (pytest markers), `lint`/`format`/`security`, `deploy-{sentinel,guardian,fortress,nexus}`, `status`/`logs`/`health`, `validate`/`validate-repo`.

**Containerfiles (20 total)** — all `podman build`, Python services on `python:3.11/3.12-slim`:

| Containerfile | Builds | Base / entry |
|---|---|---|
| `core/napse/Containerfile.napse` | NAPSE split-brain (4-stage: Zig+Mojo+Python) | ubuntu24.04→python3.12-slim; installs Zig 0.13 + Modular MAX, Mojo build optional w/ Python fallback |
| `core/napse/aegis/Containerfile` | Zig XDP capture + loader | ubuntu24.04, `zig build -Doptimize=ReleaseFast`, runtime links `libbpf1` |
| `core/napse/brain/Containerfile` | Mojo classifier | Modular MAX |
| `core/napse/inspector/Containerfile`, `core/napse/qsecbit/Containerfile` | Python fallback / score | python-slim |
| `core/cno/Containerfile`, `core/hydra/Containerfile` | cognitive organism / SOAR | python-slim |
| `products/fortress/containers/Containerfile.{web,dnsxai,xdp,mesh,hydra,lstm,agent,dfs}` | fts-web (gunicorn Flask+AdminLTE), dnsxai (:5353), **xdp (BCC eBPF)**, mesh (HTP/DSM, Cortex WS :8766), hydra (IDS microservices), lstm (PyTorch trainer one-shot), agent (`fortress.qsecbit.fortress_agent`), dfs (gunicorn :8050) | python:3.11-slim except xdp (debian-bookworm) |
| `shared/aiochi/containers/Containerfile.{bubble,identity,logshipper}` | aiochi services | python-slim |
| `shared/wireless/containers/dfs-intelligence/Containerfile`, `deploy/addons/webserver/Containerfile` | DFS / webserver | python-slim / nginx |

Build driver: `products/fortress/containers/build-images.sh` runs `podman build -f Containerfile.X -t localhost/fts-X:latest .` from repo root (web COPYs `products/fortress/web`).

**Compose files**: `core/napse/podman-compose.ids.yml` (services: inspector, qsecbit, hydra-{feed,consumer,enricher,features,anomaly,profiler,cve,temporal,sentinel,lifecycle}); `products/fortress/containers/podman-compose.yml` (postgres, redis, web, dnsxai, dfs-intelligence, qsecbit-{agent,ids}, mesh-orchestrator, hydra-{feed,consumer,enricher,features,anomaly,lifecycle,temporal,sentinel,cve}) + `.mesh.yml`; `shared/aiochi/containers/podman-compose.aiochi.yml` (clickhouse, napse, identity, bubble); infra pod composes (§6).

**systemd**: deploy/edge (5), fortress (21), guardian (11, in `config/systemd/`), aiochi (1), mesh-gateway (1).

---

## 9. eBPF / XDP programs — enumerated, with compile/load strategy

**THIS IS THE KEY BUILD FINDING.** V1 carries **three different and partly-conflicting** eBPF/XDP toolchains:

| File | Type | How compiled | How loaded |
|---|---|---|---|
| `core/napse/kernel/xdp_gate.c` | XDP firewall gate | **BCC at runtime** — `Makefile` (clang `-target bpf -g`) is "for dev/validation only"; production loads the **C source as a string** into Python `XDPManager` and compiles via BCC's `BPF()` ctor | BCC → kernel JIT |
| `core/napse/kernel/conntrack_lite.c` | conntrack | same (BCC) | BCC |
| `core/napse/kernel/ringbuf_events.c` | ringbuf emit | same (BCC) | BCC |
| `core/napse/kernel/process_tracer.c` | process eBPF | same (BCC) | BCC |
| `core/napse/kernel/syscall_monitor.c` | syscall eBPF | same (BCC) | BCC |
| `core/napse/kernel/hotpatch.c` | hot-patch | same (BCC) | BCC |
| `core/napse/kernel/xdp_flow_ctrl.c` | flow control | (not in Makefile SRCS) | BCC/manual |
| `core/napse/kernel/xdp_hydra.c` + **`xdp_hydra.o`** | DDoS XDP | **precompiled `.o` checked into repo** (not in Makefile SRCS); `-g` BTF required | `ip link set … xdp obj` (iproute2). `fts-xdp.service` loads this in monitor mode |
| `core/napse/kernel/xdp_synwall.c` + **`xdp_synwall.o`** | SYN-flood wall | **precompiled `.o`** (BTF `-g`) | `ip link set … xdp obj` at WAN boot |
| `core/napse/kernel/af_xdp_rx.c` | **userspace** AF_XDP RX lib | clang (separate, "part of the Rust engine build" per Makefile note) | linked into capture engine |
| `core/napse/aegis/src/xdp_program.zig` | XDP capture | **Zig AOT** → `bpfel`/freestanding object via `build.zig` (`aegis_xdp.o`, ReleaseFast) | `aegis-loader` (Zig, links `libbpf`+`libelf`+`z`) |
| `core/qsecbit/xdp_manager.py` (embeds `XDP_DDOS_PROGRAM` C string) | DDoS XDP | **BCC at runtime** (`python3-bpfcc`) | BCC |
| `products/fortress/containers/Containerfile.xdp` | packaging of the above | ships **`python3-bpfcc`, `bpfcc-tools`, `bpftool`, clang/LLVM** in a Debian image; `xdp_daemon.py` loads `xdp_manager.py`/`nic_detector.py` and compiles eBPF **at container runtime** | BCC → JIT; health via `bpftool prog list` |
| `core/cno/native/xsk_consumer.c` | **userspace** AF_XDP consumer (`.so`) | `gcc -shared -lxdp -lbpf -lelf -lz` (`native/Makefile`) | ctypes from Python |

So: **C eBPF = BCC runtime-compiled** (dominant path); **two checked-in `.o` = AOT loaded via iproute2**; **Zig eBPF = AOT + libbpf loader**. `nic_detector.py` decides native-XDP vs SKB/generic mode (used for OVS mirror interfaces).

---

## 10. Mojo / native libs / ML models

**Mojo** (`core/napse/brain/src/`, 8 files): `main.mojo` (entry), `simd_classify.mojo`, `hmm.mojo`, `intent_engine.mojo`, `meta_regression.mojo`, `semantic_tokenizer.mojo`, `ring_reader.mojo`, `output.mojo`. Project `mojoproject.toml` + `napse.toml`. Built via **Modular MAX** (`mojo build src/main.mojo -o napse-brain`) inside `Containerfile.napse`; build is **optional** — falls back to the Python `inspector/packet_inspector.py` if Mojo/MAX is absent.

**Userspace native `.so`** (`core/cno/native/Makefile`): `popcount.c` (`gcc -O3 -march=native -mpopcnt`, SIMD bit-density), `xsk_consumer.c` (AF_XDP, links libxdp/libbpf), `synaptic_sort.zig` (`zig build-lib … -dynamic`). Loaded via ctypes; arch-tuned (x86_64/aarch64).

**ML models**: **no pre-trained model binaries** are checked in (no `.onnx/.pt/.pth/.pkl/.gguf/.tflite`). Models are **trained at runtime/deploy**: `Containerfile.lstm` runs PyTorch `lstm_threat_detector.py --train --epochs 100 --save-model` as a one-shot job; `core/qsecbit/ml/*` (vae_anomaly, classifier, neural_drift) and `core/brain/engines/*` load/serve models per backend (llama/openvino/tensorrt/hailo/rknn/coreml/litert). dnsXai and fortress `ml_fingerprint_classifier`/`behavior_clustering` train lightweight models on-device.

---

## 11. Counts

**Files by extension** (excluding `__pycache__`/`.git`):

| ext | count | | ext | count |
|---|---|---|---|---|
| `.py` | 571 | | `.yml` | 22 |
| `.sh` | 135 | | `.js` | 22 |
| `.md` | 120 | | `.c` | 12 |
| `.yaml` | 10 | | `.mojo` | 8 |
| `.zig` | 7 | | `.toml` | 4 |
| `.ts` | 2 | | Containerfiles | ~20 |

**LOC ballpark per top dir** (code only: py/sh/zig/c/mojo/js; products row adds html/css):

| Dir | LOC | py files | sh files |
|---|---|---|---|
| `products/` | ~154 K (90.9 K py · 61.6 K sh · 30.8 K html · 5.2 K css · 4.6 K js) | 167 | 79 |
| `core/` | ~93 K | 232 | 0 |
| `shared/` | ~86 K | 135 | 15 |
| `tests/` | ~18 K | 30 | 0 |
| `scripts/` | ~9 K | 0 | 16 |
| `deploy/` | ~7 K | 4 | 17 |
| `infrastructure/` | ~1.1 K | 1 | 4 |
| `config/` | ~0.3 K | 0 | — |
| `sdk/` | ~0.2 K | 2 | 0 |

Products LOC by SKU: Fortress ~105 K, Guardian ~30 K, Nexus ~9.7 K, Sentinel ~5.8 K.

---

## 12. Gap analysis — components with NO entry in `runtime-engine-map.md`

`runtime-engine-map.md` maps **all of `core/*` and `shared/*`**. Everything below is the **product/delivery/tooling layer** the runtime map never touched. Two buckets: (A) **real engines/logic** (need a V2 home), (B) **packaging/ops** (fold into V2 builder/installer/manifest, no engine port).

**(A) Unmapped engines & logic (need a V2 decision):**
- **Fortress product engines** — `qsecbit/fortress_agent.py` (L2-L7 NAPSE+HYDRA+XDP scoring), `lib/sdn_autopilot.py` (108 KB OpenFlow autopilot), `lib/unified_fingerprint_engine.py` + `ml_fingerprint_classifier.py` + `ja3_fingerprint.py` + `behavior_clustering.py` + `lstm_threat_detector.py` (device-ID/behavior ML), `device_trust_framework.py` / `device_lifecycle.py` / `presence_sensor.py` (NAC/lifecycle), `fingerbank.py` (122 KB device DB), `mdns_resolver.py` / `hostname_decoder.py`, `lib/autopilot/*` (dhcp_sentinel, ipfix_collector, mac_watcher). These overlap with but are **not** core `napse`/`qsecbit`/`neuro` — they're a product-tier fingerprinting/NAC/SDN stack.
- **Nexus engines** — `lib/federated/*` (federated-learning aggregation_server/model_registry/participant/privacy), `lib/intelligence/*` (analysis_engine/correlator/recommender/mssp_worker), `lib/red_purple_teaming/*` (digital_twin, meta_regressor, bubble_attacks, nse_heartbeat), `aegis_deep.py`. The fleet-ML and adversarial-simulation layer.
- **Guardian product engines** — `aegis_lite.py`, `hydra_lite.py` (resource-constrained variants of core engines), `evil_twin_detector.py`, `captive_portal_detector.py`, `doh_proxy.py`, `openflow_controller.py`, `offline_mode_manager.py`.
- **Sentinel** — `aegis_pico.py`, `sentinel_agent.py`, `defense.py` (ultra-light validator).
- **infrastructure PODs** — `pod-009-email` (NAPSE deployed as a **mail IDS**, plus the whole Postfix/ClamAV/SpamAssassin DMZ topology), `pod-002-iam` (Logto OIDC), `pod-010-dsm` (the DSM **node/api** packaging, distinct from the `shared/dsm` library).
- **Nexus `radius/` + `vpn/`** — FreeRADIUS 802.1X (MAB) and StrongSwan IPsec configs (NAC + site-to-site), no V2 mapping.
- **SDKs** — `sdk/python` + `sdk/typescript` (the public MSSP API surface), no V2 mapping.

**(B) Unmapped packaging/ops (no engine port; absorb into V2 builder/manifest/installer):**
- `install.sh` / `uninstall.sh` / `install-validator.sh` / `install-sentinel-lite.sh` / root `Makefile` (V1 imperative installer → V2 bootc image build + intent reconciler).
- `deploy/edge/systemd/*`, `deploy/mesh-gateway`, `deploy/addons/{n8n,webserver,lte}`, `deploy/cloud` (→ Quadlet/sysext + fleet GitOps).
- `products/fortress/devices/*` HW profiles (→ V2 `platforms/*.yaml`).
- `products/*/web` Flask UIs (→ Mission Control).
- `scripts/`, `bin/hookprobe-ctl`, `config/`, `tests/`.

**Net:** the runtime map's "every significant engine" is true **for `core` + `shared` only**. The four products contribute a **second, parallel engine set** (esp. Fortress fingerprinting/SDN/NAC and Nexus federated-ML/red-team) plus the email-IDS POD — none of which has a V2 runtime/workspace assignment yet.

---

## 13. Build mechanisms that contradict the V2 scaffold

1. **eBPF is dominantly compiled at runtime via BCC — incompatible with the immutable bootc image.** `core/napse/kernel/Makefile` states plainly that its clang build is "for development/validation only" and that **production loads the C source as a string and compiles it via BCC's `BPF()` constructor**; `core/qsecbit/xdp_manager.py` embeds an `XDP_DDOS_PROGRAM` C string compiled by BCC; `products/fortress/containers/Containerfile.xdp` therefore ships **`python3-bpfcc` + `bpfcc-tools` + clang/LLVM + kernel headers** and compiles eBPF **fresh at container start**. The V2 runtime map (§0 + open-question #2) and Architecture both assume **pre-compiled CO-RE objects baked into the signed image** (no compiler/headers at runtime). → The runtime-map call *"core/napse capture → repackage as-is (crown jewel)"* holds **only for the Zig/aegis path** (`build.zig` already does AOT `bpfel` + libbpf loader) and the two checked-in `.o` files (`xdp_hydra.o`, `xdp_synwall.o`, loaded via iproute2). **The C/BCC path must be rebuilt to AOT CO-RE, not repackaged** — otherwise it breaks the "trust nothing unsigned / immutable rootfs" invariant (runtime compilation = unsigned kernel code generated on-device).

2. **Three coexisting eBPF toolchains, no single loader.** BCC-runtime (C), iproute2 (`.o`), and Zig+libbpf all load programs independently. V2 wants one host-action/dataplane bridge — V1 has at least three. (Open-question #4 in the runtime map flags this for host actions; it also applies to eBPF *loading*.)

3. **Hardware re-probed on every install/boot.** `install.sh` runs ~15 `detect_*` functions each run, and `core/brain/hw_detect.py` re-probes accelerators at startup — both violate V2 **detect-once / signed Platform Manifest**. `scripts/lib/platform.sh` and `core/qsecbit/nic_detector.py` are further probe paths. V2 bootstrap must subsume all of them.

4. **`docker-compose.yml` + ClickHouse + bespoke crypto baked into infra.** `pod-009-email`/`pod-010-dsm` use `docker-compose` (not Quadlet), aiochi/napse use **ClickHouse** (Architecture mandates SQLite+DuckDB), and `pod-010-dsm`/`core/htp`/`core/neuro` carry bespoke/pre-final crypto (NSE "nobody-knows-the-key", Kyber512, DSM-BLS) — all flagged in the runtime map but reasserted by the infra layer that the map never inspected.

5. **Models trained on-device, no signed artifacts.** `Containerfile.lstm` trains PyTorch at deploy time; fortress/dnsXai train lightweight models on-device. V2's signed-everything posture needs model artifacts with provenance, not in-place training jobs.
