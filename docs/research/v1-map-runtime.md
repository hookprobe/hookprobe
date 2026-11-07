# HookProbe V1 — Runtime Map (host `fortress001`)

> Read-only inventory of the **deployed/running V1 system** on this machine, captured 2026-06-29.
> Hardware: Intel N100 box (`HOOKPROBE_NODE_ID=fortress-n100-01`, `HOOKPROBE_TIER=fortress`). Fortress version **5.5.0**, deployment mode **container**, network mode **flat** (single OVS bridge `FTS`).
> Method: `systemctl`, `ps`, `ss`, `ip`, file reads. Items needing root (OVS DB, root `podman`) are flagged in §8 and reconstructed from process/socket/compose evidence.

This box is **not a passive SOC sensor** — it is the household/site **edge router + WiFi access point + VPN client + IDS**, all in one. That framing is the headline mismatch with V2 (see §9).

---

## 0. Headline counts

- **Systemd units (fortress/fts/aiochi):** 27 services + 7 named timers (+ ~21 transient podman-healthcheck timers).
- **Long-running daemons actually running:** 12 systemd `simple` services + ~21 podman containers (3 stacks: fortress-core, fortress-IDS/HYDRA, AIOCHI).
- **Datastores live:** PostgreSQL (`fortress` DB), ClickHouse (`hookprobe_ids` DB), Redis, ~20 SQLite DBs in `/var/lib/hookprobe`.
- **WAN:** PPPoE on `enp1s0` → `ppp0` (primary) + LTE `wwan0` (Vodafone, backup) with PBR failover. **VPN:** custom HTP tunnel `htp0` → `mesh.hookprobe.com:8144`.
- **Cloud:** MSSP **enabled by default** (`mssp.hookprobe.com`, API key on disk).

---

## 1. systemd services (27)

### 1a. Long-running daemons (`Type=simple`, currently `active (running)`)

| Unit | Runs | Binary / module | User | Notes |
|---|---|---|---|---|
| `fts-cno.service` | CNO "Cognitive Network Organism" | `python3 -m core.cno` (cwd `/home/andrei/hookprobe`) | andrei | Health port **8900**; `MemoryMax=2G CPUQuota=50%`; reads ClickHouse `hookprobe_ids`; `OLLAMA_MODEL=tinyllama` @ `127.0.0.1:11434`; `REFLEX_VELOCITY=0.30`/`REASON_VELOCITY=0.10` |
| `fts-napse.service` | NAPSE packet inspector | `python3 -m core.napse.inspector.packet_inspector --interface FTS-mirror` | root→nobody | Sniffs OVS mirror `FTS-mirror`, writes `napse_flows` in ClickHouse `hookprobe_ids` (creds in unit: user `ids` / `hookprobe_ids_2026`); `MemoryMax=512M` |
| `fts-htp-vpn.service` | HTP VPN client | `python3 /opt/hookprobe/fortress/lib/htp_vpn_client.py` | root | Creates `htp0`, nft kill-switch table `inet fortress_vpn`, `ip rule fwmark 0x300 → table 300`. Caps: `CAP_NET_ADMIN/RAW/DAC_OVERRIDE`; hardened (`ProtectSystem=strict`) |
| `fts-slaai.service` | SLA AI WAN continuity | `python3 -m shared.slaai.engine -c /etc/hookprobe/slaai.conf` | root | **Observe-only** per unit comment — its `failover/failback/hold` output does NOT match wan-failover's `demote/promote` vocabulary (Phase-2 TODO). Writes `/run/fortress/slaai-recommendation.json` + `slaai.db` |
| `fts-wan-failover.service` | PBR WAN failover | `/opt/hookprobe/fortress/devices/common/wan-failover-pbr.sh start` | root (CAP_NET_ADMIN/RAW) | Maintains tables 100/200/300, nft fwmarks, conntrack-sticky sessions |
| `fts-pppoe.service` | PPPoE WAN | `pppd call ftth nodetach` on `enp1s0` | root | Sets `enp1s0` unmanaged in NM; `Restart=always` |
| `fts-dhcp6c.service` | DHCPv6-PD client | `dhcp6c -f -c /etc/wide-dhcpv6/dhcp6c.conf ppp0` | root | WIDE dhcp6c retry daemon on `ppp0` |
| `fts-hostapd-24ghz.service` | 2.4 GHz WiFi AP | `/usr/local/bin/hostapd-ovs -B ... /etc/hostapd/hostapd-24ghz.conf` | root | Custom `hostapd-ovs` build; adds `wlan_24ghz` to OVS `FTS`; refreshes mDNS/AirPlay OpenFlow |
| `fts-hostapd-5ghz.service` | 5 GHz WiFi AP | `hostapd-ovs ... hostapd-5ghz.conf` | root | adds `wlan_5ghz` to OVS `FTS` (altname `wlp6s0`) |
| `fts-fingerprint-engine.service` | Unified device fingerprinting | `python3 /opt/hookprobe/fortress/lib/unified_fingerprint_engine.py --daemon` | root | Reads dnsmasq leases + OVS; many fingerprint SQLite DBs |
| `fts-presence-sensor.service` | Multi-modal presence | `python3 /opt/hookprobe/fortress/lib/presence_sensor.py --daemon` | root | BLE + mDNS; wants `bluetooth.service`; `presence.db` |
| `fts-device-lifecycle.service` | Device lifecycle daemon | `python3 -m device_lifecycle --daemon` (cwd `/opt/hookprobe/fortress/lib`) | root | Uses `host-services.env` (PG `172.20.200.10`, Redis `172.20.200.11`) |

### 1b. Oneshot, `active (exited)` (`RemainAfterExit=yes`) — boot/orchestration

| Unit | Purpose |
|---|---|
| `fortress.service` | **Core orchestrator.** Brings up OVS `FTS` bridge + gateway `10.200.0.1/28`, podman net `containers_fts-internal` (172.20.200.0/24), then `podman-compose up` core: `postgres redis web qsecbit-agent dnsxai dfs-intelligence`. Post: `fts-ovs-connect.sh`, `fts-deploy-hotfix.sh` |
| `fortress-ids.service` | `podman-compose up` IDS profile: `hydra-{feed,consumer,enricher,features,anomaly,lifecycle,temporal,sentinel}` + `qsecbit-ids` |
| `aiochi.service` | `podman-compose up` AIOCHI: `clickhouse suricata zeek log-shipper identity-engine bubble-manager` |
| `fortress-vlan.service` | OVS post-netplan: OpenFlow rules, port modes, container veth (`ovs-post-setup.sh setup`) |
| `fortress-ovs-cleanup.service` | Pre-netplan: removes stray OVS bridges/ports |
| `fts-xdp.service` | Attaches `core/napse/kernel/xdp_hydra.o` to `FTS-mirror` in **xdpgeneric/SKB monitor mode** (prog id 567 confirmed attached) |
| `fts-wanguard.service` | `nft -f /etc/hookprobe/wanguard.nft` — drops unsolicited inbound on `ppp0`/`wwan0` |
| `fts-lte.service` | Brings up LTE modem, `connect_lte internet.vodafone.ro` |
| `ids-mirror.service` | Creates `dummy-mirror` (169.254.255.1/32) |

### 1c. Timer-driven / currently `inactive (dead)` (run on schedule, see §2)

`fortress-selfheal.service`, `fts-arp-export.service`, `fts-nac-sync.service`, `fts-device-status.service`, `fts-lte-collector.service`, `fts-wifi-signal.service`.

### 1d. Enabled unit-files (`systemctl list-unit-files`)

`fortress.service`, `fortress-ids.service`, `fortress-ovs-cleanup.service`, `fortress-vlan.service`, `fts-cno.service`, `fts-htp-vpn.service`, `fts-napse.service`, `fts-xdp.service` (enabled); `fortress-selfheal.service` static.

---

## 2. systemd timers (fortress scope)

| Timer | Schedule | Triggers |
|---|---|---|
| `fortress-selfheal.timer` | `OnBootSec=10min`, `OnUnitActiveSec=5min` | `organism_selfheal.py` watchdog (exit 0=healthy,1=healed,2=critical) |
| `fts-arp-export.timer` | every **5 s** (`OnUnitActiveSec=5s`) | `arp-export.sh` → `/var/lib/hookprobe/arp-status.json` |
| `fts-nac-sync.timer` | every **5 s** | `nac-policy-sync.sh --trigger` (NAC policy → OVS) |
| `fts-device-status.timer` | every **30 s** | `device-status-updater.sh` |
| `fts-lte-collector.timer` | every **30 s** | `lte-usage-tracker.sh collect` → `lte_usage.db` |
| `fts-wifi-signal.timer` | every **30 s** | `wifi-signal-collector.sh` |
| `fts-device-lifecycle.timer` | every **60 s** | (note: the daemon §1a is the live path; timer also present) |

Plus **~21 transient `<sha256>.timer`** units = **podman container health-checks** (`/usr/bin/podman healthcheck run <id>`, `OnUnitInactiveSec=30s`), one per healthchecked container. These confirm ~21 containers are registered with podman.

---

## 3. Install tree

### `/opt/hookprobe/` (root-owned, **mutable** — note `.bak` files, hotfix scripts, backup tarballs)
```
/opt/hookprobe/
├── fortress/                      VERSION=5.5.0, fortress-ctl.sh, install-container.sh
│   ├── lib/        (Python engines — the bulk of V1 logic, ~30 modules)
│   │     unified_fingerprint_engine.py  presence_sensor.py  htp_vpn_client.py
│   │     sdn_autopilot.py (108 KB)  device_lifecycle.py  device_trust_framework.py
│   │     fingerbank.py (122 KB)  ja3_fingerprint.py  lstm_threat_detector.py
│   │     behavior_clustering.py  mdns_resolver.py  ml_fingerprint_classifier.py
│   │     cloudflare_tunnel.py  vlan_manager.py  network_policy_manager.py …
│   │     (several *.bak-2026* files present → live-patched in place)
│   ├── bin/        fts-ovs-connect.sh  fts-deploy-hotfix.sh  validate-fortress.sh  diagnose-and-fix.sh  fix-ghost-names.sh  debug-sdn-autopilot.sh  dhcp-event.sh
│   ├── scripts/    organism_selfheal.py  fts-host-agent.py  arp-export.sh  update-sdn-state.sh  migrate-sdn-config.sh  diagnose-packet-loss.sh
│   ├── containers/ podman-compose.yml  Containerfile.{xdp,lstm,dfs,dnsxai}  build-images.sh  init-db.sql  podman-compose.mesh.yml  (+ many .bak-2026* compose files)
│   ├── devices/    common/ rpi-cm5/ intel-n100/ radxa-rock5b/ template/   (per-board scripts incl. ovs-post-setup.sh, wan-failover-pbr.sh, network-integration.sh, nac-policy-sync.sh)
│   ├── web/        Flask app (app.py, gunicorn.conf.py, modules/, templates/, static/)  → fts-web container
│   └── data/       autopilot.db, devices.json, wifi_status.json, qsecbit_stats.json, wan_health.json, lte_usage.json, ioc/, layer_detectors/ …
├── shared/
│   ├── aiochi/     backend/ bubble/ schemas/ tools/ containers/(podman-compose.aiochi.yml) n8n-workflows/  ARCHITECTURE.md
│   ├── mssp/       client.py auth.py mesh_propagation.py webhook_receiver.py recommendation_handler.py  (cloud/MSSP integration)
│   └── mesh/       mesh_server.py
├── guardian/htp/   vpn_state.json (STALE — state "error", from Mar 10; live state is in /etc/hookprobe/vpn-state.json)
├── data/           (world-writable 0777 — note)
└── fortress-code-backup-*.tgz, fortress-stale-bubble-*.tgz   (ad-hoc backups in place)
```

> **Note:** the *running* CNO/NAPSE/HYDRA code is **not** under `/opt/hookprobe` — it runs from **`/home/andrei/hookprobe/core/`** (`core/{cno,napse,hydra,qsecbit,aegis,neuro,brain,htp,common}`, `PYTHONPATH=/home/andrei/hookprobe`). So V1 has **two code roots**: `/opt/hookprobe/fortress/lib` (gateway/device engines) and `/home/andrei/hookprobe/core` (CNO/NAPSE/HYDRA/AEGIS). `core/aegis` exists as code but **no AEGIS systemd unit is running**.

### `/etc/hookprobe/` (config + secrets, owned by `andrei`)
```
fortress.conf            FORTRESS_VERSION=5.5.0, NETWORK_MODE=flat, LAN 10.200.0.0/28,
                         INSTALL_AIOCHI=true, INSTALL_LTE=true, MSSP_ENABLED=true,
                         SKIP_OVS_CONTAINER_ATTACH=true, WIFI_SSID=hookprobe
node.conf                API_KEY=hp_… , MSSP_URL=https://mssp.hookprobe.com   (← cloud creds on disk)
host-services.env        PG 172.20.200.10 / Redis 172.20.200.11 / DATABASE_PASSWORD=… (plaintext)
optional-services.conf   INSTALL_CLICKHOUSE=true, INSTALL_IDS=true, INSTALL_N8N=false, LTE_APN=internet.vodafone.ro
wan-failover.conf        PRIMARY=ppp0, BACKUP=wwan0, PING 1.1.1.1/8.8.8.8/9.9.9.9
slaai.conf               primary=enp1s0, backup=wwan0 (metered, 500MB/day, 10GB/mo)
vpn-state.json           state=connected, server mesh.hookprobe.com:8144, ChaCha20-Poly1305, htp0=10.250.0.2, uptime 123h
fortress-state.json      containers[] + volumes[] manifest of what was installed
wanguard.nft, fortress_vpn.json, fingerbank.json, oui_policies.conf, wifi-interfaces.conf,
mesh_vpn_psk, mssp-hmac.key, model-integrity.key, vpn_known_hosts.json, openrouter.json, users.json
secrets/  →  admin_password, wifi_password, fortress_secret_key, openrouter_api_key,
             openrouter.env, cno.env, vxlan_psk   (all plaintext files)
certs/    →  dnsxai.crt/.key (DoT), flask-secret.key
persistent/dnsxai/  whitelist.txt, config.json, stats.json
```

### `/var/lib/hookprobe/` (state DBs, owned by `andrei`, dir 0777)
~20 SQLite DBs: `autopilot.db, bubbles.db, clustering.db, d2d_graph.db, device_identity.db, devices.db, ecosystem_bubbles.db, feedback.db, fingerbank.db, fingerprint.db, ja3_fingerprints.db, lte_usage.db (1.8 MB), mdns_cache.db, ml_fingerprints.db, presence.db, unified_fingerprint.db, dfs_intelligence.db (empty)`; dirs `ml_models/ ml_fingerprint_models/ slaai/(slaai.db) userdata/dnsxai/`; JSON `arp-status.json, blocked_macs.json, hostapd-ovs.state`.

### `/usr/lib/hookprobe/` — **does not exist.** `/opt/fortress`, `/etc/fortress` — do not exist.

---

## 4. Running processes → unit mapping

| PID | etime | Args | Maps to |
|---|---|---|---|
| 2811207 | 12d | `python3 -u -m core.cno` | `fts-cno.service` (listens :8900) |
| 1582351 | 12d | `python3 -m core.napse.inspector.packet_inspector --interface FTS-mirror` (user nobody) | `fts-napse.service` |
| 3102426 | 9d | `python3 /opt/hookprobe/fortress/lib/htp_vpn_client.py` | `fts-htp-vpn.service` |
| 1300774 | 12d | `python3 -m shared.slaai.engine -c …/slaai.conf` | `fts-slaai.service` |
| 2693460 | 12d | `wan-failover-pbr.sh start` | `fts-wan-failover.service` |
| 7057 | 13d | `unified_fingerprint_engine.py --daemon` | `fts-fingerprint-engine.service` |
| 7058 | 13d | `presence_sensor.py --daemon` | `fts-presence-sensor.service` |
| 1368 | 13d | `/opt/hookprobe/fortress/scripts/fts-host-agent.py` | **No matching systemd unit found** — orphan/long-lived host agent (likely launched by fortress orchestration or manually). FLAG. |
| 708362 | 12d | `python -m fortress.qsecbit.fortress_agent --config /etc/hookprobe/qsecbit.conf` (in container, user andrei) | container `fts-qsecbit` ← `fortress.service` |
| 1908856 | 12d | `python3 /app/qsecbit/qsecbit_engine.py --auto-incidents` (in container) | container `fts-qsecbit-ids` ← `fortress-ids.service` |
| 3170921 | 9d | `engine.py --serve :5353 --dot :853 --dot-cert …/dnsxai.crt` (in container) | container `fts-dnsxai` ← `fortress.service` |
| 3199794 | 9d | `postgres: fortress fortress 172.20.200.1 idle` | container `fts-postgres` |
| 9321 | 13d | `python3 /opt/hookprobe/bubble_entrypoint.py` (container path) | container `aiochi-bubble` ← `aiochi.service` |
| 1453648–1652073 | ~12d | 8× `conmon … fts-hydra-{enricher,features,anomaly,lifecycle,temporal,sentinel,consumer,feed}` | `fortress-ids.service` |
| 803 | 13d | `avahi-daemon [fortress001.local]` | system (mDNS, supports AP) |

> Container processes (qsecbit, hydra, dnsxai, postgres) appear under `conmon`/in-namespace paths; root `podman ps` was password-gated (§8), so the **authoritative running-container list** is reconstructed from conmon names + listening sockets + compose CORE sets.

---

## 5. Network / data-plane runtime

### Interfaces (`ip -br addr`)
| iface | role | addr |
|---|---|---|
| `enp1s0` | WAN uplink (PPPoE carrier) | UP, no IP (PPP rides on it) |
| `ppp0` | **Primary WAN** | `100.102.132.57` peer `10.0.4.209` |
| `wwan0` | **Backup WAN (LTE Vodafone)** | `10.179.24.179/29`, gw `10.179.24.180` |
| `FTS` | **LAN gateway** (OVS bridge) | `10.200.0.1/28` + IPv6 `fd14:facf:22f3:4407::/64` |
| `FTS-mirror` | OVS mirror of `FTS` (IDS tap) | IPv6 only; **XDP prog id 567 attached (xdpgeneric)** |
| `wan-mirror` | dummy, PROMISC (WAN tap) | link-local |
| `wlan_24ghz`,`wlan_5ghz` | WiFi AP radios, enslaved to OVS `FTS` | link-local |
| `htp0` | **HTP VPN tun** | `10.250.0.2/24` (peer gw `10.250.0.1`) |
| `podman1` | fortress container net (`containers_fts-internal`) | `172.20.200.1/24` |
| `podman2` | second container net | `172.20.210.1/24` |
| `enp2s0/3s0/4s0` | enslaved to `ovs-system`, NO-CARRIER | DOWN |

### Policy routing (`ip rule` + named tables `wan_primary`/`wan_backup`/`wan_vpn`)
```
45:  fwmark 0x300/0xf00 → wan_vpn      (table 300: default via 10.250.0.1 dev htp0)   ← VPN egress
50:  from 100.102.132.57/82.76.169.190/192.168.1.101 → wan_primary
60:  from 10.179.24.179 → wan_backup
100: fwmark 0x100/0xf00 → wan_primary  (table 100: default via 10.0.4.209 dev ppp0)
200: fwmark 0x200/0xf00 → wan_backup   (table 200: default via 10.179.24.180 dev wwan0)
main: default via ppp0 (metric 110), default via wwan0 (metric 200)
```
So: packet **fwmark selects WAN** (primary ppp0 / backup wwan0 / VPN htp0). Failover by `fts-wan-failover`; VPN steering by `fts-htp-vpn`.

### XDP / eBPF
`FTS-mirror` has `xdp_hydra` attached in **generic/SKB monitor mode** (prog id 567) — emits ringbuf events to `fts-hydra-consumer`, no drops. `bpftool` map/detail needs root (§8).

### OVS
`ovs-vsctl` present at `/usr/bin/ovs-vsctl`; bridge `FTS` confirmed via netlink (`master ovs-system`, internal ports `FTS`, `FTS-mirror`). Full `ovs-vsctl show` + mirror config needs root (§8). Architecture is **flat bridge** (`NETWORK_MODE=flat`, no VLANs), `SKIP_OVS_CONTAINER_ATTACH=true` (containers use podman DNAT, not OVS veth, to preserve port 8443 forwarding).

### Listening sockets (`ss -tulpn`, process owners mostly root → not shown without priv)
| Port | Bind | Service (inferred) |
|---|---|---|
| 8443 | 0.0.0.0 | `fts-web` Flask UI (podman DNAT) |
| 8900 | 0.0.0.0 | CNO health (pid 2811207, confirmed) |
| 53 / 853 | 10.200.0.1 (+IPv6) | dnsmasq (53) + dnsXai DoT (853) |
| 8050 | 10.200.0.1 | DFS intelligence API |
| 8053 / 8060 / 8070 | 127.0.0.1 / 0.0.0.0 | dnsXai HTTP API / aiochi-identity / aiochi-bubble |
| 8123 / 9000 | 127.0.0.1 | ClickHouse HTTP / native |
| 9300–9308 | 0.0.0.0 | metrics/IPC endpoints (NAPSE/HYDRA/QSecBit engines) |
| 9090 | 0.0.0.0 | (Prometheus-style metrics) |
| 5353 | 0.0.0.0 | mDNS/dnsXai |
| 22 | 0.0.0.0 | sshd |

---

## 6. Containers

Root `podman ps/images/volumes` were **password-gated** (§8). Reconstructed from compose files + conmon process names + healthcheck timers + sockets.

### Stack A — fortress core (`/opt/hookprobe/fortress/containers/podman-compose.yml`, net `containers_fts-internal` 172.20.200.0/24)
| Container | Image | Confirmed running |
|---|---|---|
| `fts-postgres` | `docker.io/library/postgres:15-alpine` | ✅ (postgres proc, 172.20.200.10) |
| `fts-redis` | `docker.io/library/redis:7-alpine` | expected (172.20.200.11) |
| `fts-web` | `localhost/fts-web:latest` (built) | ✅ (:8443) |
| `fts-dnsxai` | `localhost/fts-dnsxai:latest` | ✅ (engine.py :53/:853/:8053) |
| `fts-dfs` | `localhost/fts-dfs:latest` | ✅ (:8050) |
| `fts-qsecbit` | `localhost/fts-agent:latest` | ✅ (fortress_agent proc) |
| `fts-mesh` | `localhost/fts-mesh:latest` | defined; mesh stack (see mesh compose, ports 8144/8543/8853/3478) — not in default CORE |

### Stack B — fortress IDS / HYDRA (same compose, started by `fortress-ids.service`, all `localhost/fts-hydra:latest`)
`fts-hydra-feed` ✅, `fts-hydra-consumer` ✅, `fts-hydra-enricher` ✅, `fts-hydra-features` ✅, `fts-hydra-anomaly` ✅, `fts-hydra-lifecycle` ✅, `fts-hydra-temporal` ✅, `fts-hydra-sentinel` ✅, `fts-qsecbit-ids` ✅ (`localhost/fts-hydra:latest`). Also defined but not in active set: `hydra-cve`, `hydra-sentinel-engine`.

### Stack C — AIOCHI (`/opt/hookprobe/shared/aiochi/containers/podman-compose.aiochi.yml`, net `aiochi-internal`)
| Container | Image | Confirmed |
|---|---|---|
| `aiochi-clickhouse` | `clickhouse/clickhouse-server:24.8` | ✅ (:8123/:9000) |
| `aiochi-suricata` | `jasonish/suricata:7.0.8` | expected (IDS DPI) |
| `aiochi-zeek` | `zeek/zeek:7.0.3` | expected (NSM) |
| `aiochi-logshipper` | built | expected |
| `aiochi-identity` | built | ✅ (:8060) |
| `aiochi-bubble` | built | ✅ (bubble_entrypoint.py) |
| `aiochi-narrative` | `n8nio/n8n:1.70.3` | defined, `INSTALL_N8N=false` → not started |

**Named volumes** (from compose/`fortress-state.json`): `postgres_data, postgres_certs, redis_data, web_data, web_logs, dnsxai_data, dnsxai_blocklists, dnsxai_certs, dfs_data, mesh_data, mesh_neuro, hydra_models, zeek_logs` + AIOCHI `clickhouse_data/logs, suricata_logs, zeek_{logs,spool}, identity_data, bubble_data, n8n_data`.

**Quadlet:** none — orchestration is **podman-compose driven by oneshot systemd units**, not Quadlet `.container` files.

---

## 7. Cron

- **System cron** (`/etc/cron.d`, `cron.daily`): only stock Ubuntu (`e2scrub_all`, `sysstat`, `apt-compat`, `logrotate`, `man-db`, `apport`, `dpkg`). **No hookprobe/fortress cron entries.**
- **User `andrei` + root crontab:** identical, and belong to a **different project (`hequx`)** — `/home/andrei/hequx/scripts/*.sh` (trading/research: `forward_tick`, `live_tick`, `edge_hunt`, `equity_collector`, etc.). **Unrelated to HookProbe**; noted to avoid confusion.

All HookProbe scheduling is via **systemd timers** (§2), not cron.

---

## 8. What needs root (not read — do not guess contents)

| Item | Command blocked |
|---|---|
| OVS bridge/port/mirror config | `ovs-vsctl show`, `ovs-vsctl list mirror` (sudo password required) |
| Authoritative container list/state/health | root `podman ps -a`, `podman images`, `podman volume ls`, `podman network ls` |
| eBPF/XDP map contents & program detail | `bpftool prog/map show` (attachment confirmed via `ip -d link`, internals not) |
| nft rule contents live | `nft list ruleset` (files `wanguard.nft`, `fortress_vpn` table inferred from unit defs) |
| `/etc/hookprobe/secrets/*` values, `qsecbit.conf`, `cno.env` | readable as files but values not dumped here (secrets) |
| Listening-socket → PID for root-owned ports (8443, 53, 9300-9308, etc.) | `ss -p` needs root; mapped by inference |

---

## 9. Top mismatches: what the running V1 reveals that V2 docs/CLAUDE.md do NOT account for

1. **V1 IS a router + WiFi AP + DHCP/DNS server, not a passive SOC sensor.** Live units `fts-pppoe` (`pppd call ftth`→`ppp0`), `fts-dhcp6c` (DHCPv6-PD), `fts-lte`/`wwan0`, `fts-wan-failover` (PBR tables 100/200/300), `fts-hostapd-24ghz/5ghz` (custom `/usr/local/bin/hostapd-ovs`), dnsmasq (DHCP 10.200.0.0/28, DNS :53), `fts-wanguard`. **V2's `docs/architecture/Readme.md`/CLAUDE.md have no edge-router, WAN-failover, PPPoE, LTE, DHCP-server, or WiFi-AP concept at all.** This is the single biggest unmapped surface — V2 treats the box as out-of-band observation; V1 is **inline and load-bearing for connectivity**.

2. **HYDRA's V1 meaning directly contradicts the V2 "resolved canonical" mapping.** On this box HYDRA = the **threat-intel/IDS enrichment pipeline** (`fortress-ids.service` runs `hydra-feed/consumer/enricher/features/anomaly/temporal/sentinel/cve` + `xdp_hydra`). CLAUDE.md asserts "**HYDRA = automation/orchestration (SOAR)**… threat-intel enrichment lives in the Intelligence workspace, not HYDRA." The running system says the opposite — HYDRA *is* the threat-intel/enrichment engine. The V2 "mapping resolved" decision relitigates a name that already means something else in production.

3. **No Platform Manifest exists — V2's central invariant is absent.** There is **no `/var/lib/hookprobe/manifest.json` (schema 2)**. Capabilities are not "granted"; they are install-time config flags (`INSTALL_AIOCHI/IDS/LTE/CLICKHOUSE` in `fortress.conf`/`optional-services.conf`) plus `fortress-state.json`. "Detect once, query forever" / capability-gating has no runtime backing on V1.

4. **No bootc / Wasm / immutable rootfs / signing — the three "load-bearing decisions" are all unmet.** Reality = mutable `/opt/hookprobe` (with `*.bak-2026*` files and `fts-deploy-hotfix.sh` patching live code), Python daemons, and `podman-compose` pulling **unsigned `docker.io` images** (`postgres:15`, `redis:7`, `clickhouse:24.8`, `suricata:7.0.8`, `zeek:7.0.3`, `n8n:1.70.3`). No `.wasm`, no `bootc`, no cosign/SBOM/CBOM, no manifest signing.

5. **MSSP cloud is ON by default, with credentials on disk — violates "standalone by default, no account."** `fortress.conf` `MSSP_ENABLED=true` + `node.conf` `API_KEY=hp_…` + `mssp-hmac.key`. The device ships pre-enrolled to `mssp.hookprobe.com`. V2 invariant: cloud/account is additive, never a precondition, identity is TPM-bound. Here it's a plaintext API key and an N100 with no TPM.

6. **A bespoke "HTP VPN" (HookProbe Transport Protocol) is a core, always-on subsystem with zero mention in V2.** `fts-htp-vpn` → `htp0` (10.250.0.2) → `mesh.hookprobe.com:8144`, **ChaCha20-Poly1305**, nft kill-switch (`inet fortress_vpn`), fwmark `0x300`→table 300, plus a `fts-mesh` container (VXLAN, ports 8144/8543/8853/3478) and `mssp/mesh_propagation.py`. V2 docs cover PQC/ML-KEM but never the existing HTP/mesh transport — and HTP today is **classical crypto only** (a migration gap for the PQC story).

7. **AEGIS runs nowhere; the V1 "reconciler" is actually SDN-Autopilot + a self-heal watchdog + NAC-sync.** `core/aegis` exists as code but has **no systemd unit**. The live reconciliation loop is `sdn_autopilot.py` (108 KB), `organism_selfheal.py` (`fortress-selfheal.timer`, every 5 min), and `nac-policy-sync.sh` (every 5 s). V2's "AEGIS = deterministic reconciler + AI planner, operated by intent" has no running counterpart; there is **no intent layer** at all.

8. **"One data model / one evidence graph" is, in reality, 3 datastores + ~20 SQLite DBs.** Live: **ClickHouse** `hookprobe_ids` (NAPSE `napse_flows`, Suricata/Zeek events), **PostgreSQL** `fortress`, **Redis**, and ~20 SQLite files in `/var/lib/hookprobe` (`bubbles.db, d2d_graph.db, device_identity.db, ja3_fingerprints.db, presence.db, …`). No unified evidence graph; data is sharded across engines.

9. **A whole "biological organism" V1 vocabulary has no V2 home: CNO, AIOCHI, bubbles, presence, DFS, SLA-AI.** Running: `fts-cno` ("Cognitive Network Organism", uses Ollama `tinyllama` locally), the AIOCHI "AI Eyes" stack (ClickHouse+Suricata+Zeek+identity+bubble), `presence_sensor` (BLE/mDNS occupancy), `dfs-intelligence` (WiFi), `fts-slaai`. V2's component table (Senzorium/NAPSE/AEGIS/HYDRA/QSECBIT) names **none** of these — Senzorium especially is a V2 invention with no V1 service; its function is today split across NAPSE + Suricata + Zeek + fingerprint + presence engines.

10. **Real config contradicts the "soft-real-time, small edge footprint" framing.** Two LLM paths are wired into the live security loop: CNO embeds **Ollama tinyllama** with `REFLEX_VELOCITY=0.30`/`REASON_VELOCITY=0.10` (implying it may *act*, not just advise), and `openrouter.json`/`secrets/openrouter.env` provide a cloud LLM. V2 says "AI planner is assistive, **never in the enforcement path**" — V1 CNO's reflex velocities suggest model-in-the-loop actuation that needs auditing. Resource caps are coarse (`fts-cno MemoryMax=2G/CPU 50%`, `fts-napse 512M/50%`) — no formal real-time budget.

11. **Code lives in two roots and is hot-patched in place — no provenance.** Gateway engines run from `/opt/hookprobe/fortress/lib`; CNO/NAPSE/HYDRA/AEGIS run from a developer home dir `/home/andrei/hookprobe/core` (`PYTHONPATH=/home/andrei/hookprobe`). `*.bak-2026*` files and `fts-deploy-hotfix.sh` show live in-place patching. V2's signed-immutable-image model has no purchase on this layout.

12. **Orphan/unmapped daemon:** `fts-host-agent.py` (pid 1368, root, 13 d uptime) has **no matching systemd unit** — a long-lived agent outside the supervised set. Worth tracking before any V2 migration inventory.
