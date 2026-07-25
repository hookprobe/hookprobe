# V1 Map — `~/hookprobe-com` (the cloud / `mssp.hookprobe.com` + `mesh.hookprobe.com` deployment)

> Read-only map produced from the **files** in `~/hookprobe-com` (no live host was contacted).
> Snapshot date of files: 2026-06-28. This is the V1 *cloud control-plane* repo — the production
> MSSP web app, identity, databases, IDS pipeline, and mesh/VPN gateway that edge appliances dial home to.
> Purpose: feed the V2 "cloud-linked (MSSP) lens" planning (`docs/MissionControl.md`, `docs/Readme.md`).

---

## 1. Top-level tree (purpose, one line each)

```
hookprobe-com/
├── astro-landing/        Astro SSG marketing site → hookprobe.com (static, nginx-served)
├── astro-dashboard/      Astro 5.16 SSR app → mssp.hookprobe.com (the MSSP/SOC dashboard) ★
├── astro-docs/           Astro Starlight SSG docs → docs.hookprobe.com (Pagefind search)
├── hookprobe/            GIT SUBMODULE (url=../hookprobe) → the V1 engine repo; NOT checked out here (empty dir)
├── alexandria/           Python "Alexandria-CNO" governance/AI brain (librarian, gatekeeper, hormones, drift, federation)
├── hsg/                  "HTP Synaptic Gateway" — Zig executable (IKE/ESP/PKI/crypto/bridge): the mesh VPN crypto core
├── sdks/                 sdks/python/hookprobe_tamper — tamper-signal client SDK for products → aegis-ledger
├── deploy/               systemd units (rootless user service + glassbrain/ssol timers)
├── containers/           ALL Containerfiles + the two compose overlays + per-service code (see §2)
├── docs/                 V1 internal docs (Alexandria-CNO, Glass-Brain, fortiarchitect, runbooks)
├── scripts/              bench harness, attestation, asset/video pipeline, libs
├── secrets/              PRESENT: aiven-ca.pem, gsc-service-account.json, social-credentials.json (NOT read)
├── certs-backup-2026…/   PRESENT: cloudflare-origin.crt/-ca.pem, hookprobe.com.crt, dashboard.hookprobe.com.crt (NOT read)
├── reports/ logs/ tests/ vw-id-buzz/   misc working dirs / fixtures
├── podman-compose.yml    ★ the MSSP (rootless) stack — public web + identity + data + mesh + AI-WAF
├── install.sh (61 KB)    production installer/orchestrator (rootless MSSP + root IDS), uninstall.sh, Makefile
├── package.json          near-empty (only playwright for tests); real package.json's live per astro-* app
├── 2131ba4d35da / 3bc47e121a5e / baa153764295   empty hash-named marker files (build/state markers, 0 bytes)
└── *.png, *.md           screenshots + status/setup notes (BLOG_*, IMPLEMENTATION_STATUS, SECURITY_FIXES)
```

---

## 2. Deployment / VM setup

### Host model — ONE Ubuntu/Debian VM, two podman namespaces

`install.sh` header: *Ubuntu 22.04+ / Debian 12+, 4 GB+ RAM (8 GB+ for IDS), Podman + podman-compose.*
The systemd unit (`deploy/systemd/hookprobe-com.service`) has `WorkingDirectory=/home/ubuntu/hookprobe-com`
and runs `podman-compose up -d` as a **`systemctl --user`** (rootless) oneshot → so the production box is a
single cloud VM with an `ubuntu` user. There is **no multi-VM / k8s / swarm** — it is one host.

Two podman namespaces on that one host:

| Stack | Namespace | Network | Compose file | Started by |
|---|---|---|---|---|
| **MSSP / public** | rootless (`ubuntu`) | `hookprobe-public` bridge `172.30.0.0/24` | `podman-compose.yml` | `hookprobe.service` (user) |
| **IDS / sensor** | **root** podman | `hp-ids-net 172.33.0.0/24` **+ `network_mode: host`** | `containers/ids/podman-compose.ids.yml` | root systemd (`--with-ids`) |

The two namespaces talk over the **host loopback** via `host.containers.internal` — the rootless MSSP
containers reach the root IDS ClickHouse at `host.containers.internal:8123` and the CNO at `:8900`.
That host-loopback bridge is the *only* coupling between the two stacks (fail-open, async).

### Services in the MSSP (rootless) stack — `podman-compose.yml`

| Service | Image / build | Net IP | Ports | Role |
|---|---|---|---|---|
| **proxy** | `openresty/openresty:alpine-fat` | .2 | **80/443 host** | nginx + Lua reverse proxy; subdomain router; inline AI-WAF gate |
| **website** | build `containers/landing/Containerfile` | .10 | 8000 (internal) | hookprobe.com SSG (nginx); also serves blog API |
| **dashboard** | build `astro-dashboard/Containerfile` | .11 | 3000 (internal) | ★ mssp.hookprobe.com Astro SSR (Node standalone) |
| **docs** | build `astro-docs/Containerfile` | .12 | 8000 (internal) | docs.hookprobe.com Starlight SSG (nginx) |
| **mesh** | build `containers/mesh/Containerfile` | .13 | **8144 tcp+udp, 3478/udp, 500/udp, 4500/udp host; 8766 lo** | HTP/Neuro/DSM mesh + VPN gateway (see §2 mesh) |
| **postgres** | build `containers/postgres` (pgvector) | .30 | 5432 (internal) | app DB + Keycloak DB; ~20 init SQL files (blog, seo, mssp, dsar, sessions) |
| **valkey** | `valkey/valkey:7.2.11-alpine` | .31 | 6379 (internal) | Redis-compatible cache / rate-limit |
| **keycloak** | `quay.io/keycloak/keycloak:24.0` | .40 | 8080 (internal) | auth.hookprobe.com OIDC IdP; DB=postgres; `KC_PROXY=edge` |
| **ai-waf** | build `containers/ai-waf` | .50 | 9999 (internal) | TinyBERT INT8 ONNX WAF sidecar (shadow + inline admission) |
| **aegis-ledger** | build `containers/aegis-ledger` | .51 | 9998/9997 (internal) | signed action ledger + IOC gossip + tamper-signal sink (SQLite, opt PG) |
| **video** | build `containers/video` | .14 | 8100 (internal) | Whisper + FFmpeg transcription (blog/social media) |
| **ssl-init** | `alpine:3.19` (oneshot) | — | — | installs certs from `certs-backup/` into `ssl-certs` volume, else self-signs |

Named volumes: `ssl-certs, postgres-data, valkey-data, blog-images, mesh-data, mesh-neuro,
ai-waf-models, ai-waf-attrib, aegis-ledger-data`.

### Services in the IDS (root) stack — `containers/ids/podman-compose.ids.yml`

All run with `network_mode: host` (need raw packet / XDP access). 15 services:

- **clickhouse** — `clickhouse/clickhouse-server:24.8`, binds host **8123 (HTTP) / 9000 (native)**, DB `hookprobe_ids`, user `ids`. This is the **central telemetry/event store** everything writes to.
- **inspector** — packet/flow inspector (build from `hookprobe/core/napse/inspector`) → ClickHouse.
- **qsecbit** — the QSECBIT resilience-score engine (`hookprobe/core/napse/qsecbit`).
- **hydra-*** (10 services) — feed, consumer, enricher, features, sentinel, cve, sentinel-engine, temporal, lifecycle, anomaly, predictor — the HYDRA automation/ML pipeline, all built from `hookprobe/core` `hydra/Containerfile`.
- **cno-organism** — Alexandria "Cognitive Network Organism": health on host **:8900**, `/status` Bearer-gated (`HOOKPROBE_CNO_BEARER`), writes XDP blocklist/allowlist/stress_level via privileged host access.

> The IDS stack **depends on the `hookprobe/` submodule** (napse inspector, qsecbit, hydra, cno are all
> built from `hookprobe/core/...`). In this checkout that submodule is empty, so the IDS stack cannot be
> built from this repo alone — it needs the sibling `~/hookprobe` engine repo.

### TLS / certs

Cloudflare in front (proxy mode). `ssl-init` copies a **Cloudflare Origin certificate**
(`certs-backup/cloudflare-origin.crt/.key`, CA `cloudflare-origin-ca.pem`) into the `ssl-certs` volume and
reuses that single origin cert for `mssp.`, `auth.`, `docs.` (and `hookprobe.com.crt` for apex). nginx
terminates TLS on 443 with these. So: **Cloudflare edge → origin cert → OpenResty :443 → internal HTTP upstreams.**

### How the dashboard backend reaches data

`astro-dashboard/src/lib/*` clients (env-driven, defaults shown):
- **PostgreSQL** (`db.ts`, `pg` Pool) → `hookprobe-postgres:5432` (app/site/node data). Plus a **second
  Aiven managed Postgres** (`AIVEN_DB_*`, `aivencloud.com:23718`) for "persistent GDPR user data" with
  `secrets/aiven-ca.pem`.
- **ClickHouse** (`clickhouse.ts`, `@clickhouse/client`) → `host.containers.internal:8123` (the root IDS
  store) for the xSOC/telemetry pages.
- **Valkey/Redis** (`ioredis`) → `hookprobe-valkey:6379` for rate-limiting.
- **Keycloak** — OIDC for users (`oidc-config.ts`) + admin REST (`keycloak-admin.ts`) for user management.
- **CNO** → `host.containers.internal:8900` (Bearer) for the "Organism" page.
- External: SMTP (OCI), Gemini/OpenRouter (AI content), LinkedIn/Discord (social/VIRE), GSC service account.

---

## 3. `mesh.hookprobe.com` — how it is served

**Key finding: `mesh.hookprobe.com` is NOT an HTTP vhost and does NOT go through nginx.**
The OpenResty `server_name` blocks only cover `hookprobe.com / www`, `mssp.`, `auth.`, `docs.` — there is
no `mesh.` server block. Instead the **`mesh` container binds its ports directly on the host**:

```
0.0.0.0:8144/tcp   HTP mesh peering (native TCP)        ← mesh.hookprobe.com:8144
0.0.0.0:8144/udp   HTP VPN data plane (ChaCha20-Poly1305)
0.0.0.0:3478/udp   STUN/TURN NAT traversal
0.0.0.0:500/udp    IKE (IPsec)
0.0.0.0:4500/udp   IPsec NAT-T
127.0.0.1:8766     Cortex WS / healthcheck (loopback only)
```

So `mesh.hookprobe.com` is just a **DNS A-record pointing at the same VM's public IP** (almost certainly a
*DNS-only / grey-cloud* Cloudflare record, since these are UDP/non-HTTP ports Cloudflare's proxy can't
carry). Edge appliances (Guardian / Fortress / Nexus) dial `mesh.hookprobe.com:8144` directly and the host
forwards to the mesh container. The container runs with `NET_ADMIN`/`NET_RAW`, `/dev/net/tun`, and
`ip_forward=1`. Identity `MESH_NODE_TYPE=mssp`, DSM consensus quorum 0.67, Neuro drift threshold 0.05.
It also ships mesh threat telemetry to the central ClickHouse (`host.containers.internal:8123`).
The crypto/IKE/ESP/PKI core for this gateway is the **`hsg/`** Zig project ("HTP Synaptic Gateway").

The dashboard's node-heartbeat path advertises gateway endpoints
`HTP_GATEWAY_ENDPOINT=mssp.hookprobe.com:8144` and `HTP_MESH_ENDPOINT=mesh.hookprobe.com:8144`.

---

## 4. `astro-dashboard` (the MSSP / SOC dashboard) — confirmed + extended

- **Astro `^5.16.15`, `output: 'server'`, `@astrojs/node` standalone adapter, port 3000.** React 19
  islands (`@astrojs/react`).
- **3D / viz:** `three ^0.183`, `@react-three/fiber 9`, `@react-three/drei 10`, `@react-three/postprocessing`,
  `d3-force-3d`, `framer-motion` (the "Organism" / node-graph / threat-feed visuals).
- **Editor:** Tiptap 3 full suite (blog/CMS authoring).
- **State:** `zustand 5` + `nanostores` + `@nanostores/react` (SSR-noExternal'd).
- **Auth:** `oidc-client-ts 3` (Keycloak Authorization Code flow; `loadUserInfo:false`, claims from ID token).
- **Data clients:** `@clickhouse/client`, `pg`, `ioredis`, `nodemailer`, `sharp`.

**`src/` layout**
- `pages/` workspaces: `mssp/`, `agency/`, `admin/`, `xsoc/`, `auth/`, `legal/`, plus `api/`.
- `components/`: `dashboard, nodes, threat-feed, combat-mode, xsoc, free-tier, blog, layout, ui`.
- `lib/`: data + auth clients listed in §2 plus `api-auth.ts, mssp-auth.ts, mssp-tiers.ts, tier-limits.ts,
  qsecbit-engine.ts, recommendation-engine(+signing).ts, geoip.ts, audit.ts, privacy.ts, csrf(.client).ts`.
- `middleware.ts`: process-level crash guard + **global read-only gate** — the whole dashboard is read-only
  for everyone except `master_admin`, with an allow-list of write endpoints (node telemetry, auth
  bookkeeping, public sign-up, SEO/Discord bridges authed by API-key/shared-secret, not user JWT).

**API routes (`src/pages/api/**`, ~80 files)** — the real backend surface, grouped:
- **Fleet / edge nodes:** `nodes/{heartbeat,provision,provision/stream,claim,intel,auto-assign,qsecbit,telemetry,[id]}` — appliance enrollment + heartbeat + telemetry ingest (the mesh control plane over HTTP).
- **Mesh:** `mesh/{devices,enroll,intel}`.
- **MSSP multi-tenant:** `mssp/{apply,billing,analytics,index,companies/[slug]}`, `admin/mssp-applications/*`.
- **SOC data:** `alerts/{index,[id],bulk,predictive}`, `logs/index`, `dashboard/overview`, `public/senzorium/snapshot`.
- **Agency / AI ("Alexandria"):** `agency/{cognition,convergence,lesson,snapshot,timeline,training,verdicts}`, `internal/cognition`.
- **Admin/content/SEO/social:** large `admin/{blog/*,seo/*,social/*,nodes,sites,stats,sync-users,health}` surface (this app is also the marketing CMS + SEO/social automation engine).
- **Auth/compliance:** `auth/{set-token,clear-token,csrf}`, `gdpr/request`, `contact`, `activate`, `settings/api-keys`, `health`.

OIDC wiring: authority `https://auth.hookprobe.com/realms/hookprobe`, client `hookprobe-dashboard`,
redirect `https://mssp.hookprobe.com/auth/callback`. Server-side Keycloak admin REST via service account.

---

## 5. `alexandria` / `hsg` / `hookprobe` subdirs

- **`alexandria/`** — Python package, the **"Alexandria-CNO" cognitive/governance brain** (NOT a blog/CMS).
  Modules: `librarian, gatekeeper, constitution, hormones, drift_monitor, mood_journal, motivator,
  curriculum, knowledge_synthesis, federated_peer_transport, model_registry, deception, canaries,
  connectome (eBPF), identity, provenance, verification`. It is the AI layer that the IDS `cno-organism`
  container runs and that the dashboard's `agency/*` pages surface. ≈ V2's **AEGIS AI planner** ancestor.
- **`hsg/`** — **HTP Synaptic Gateway**, a **Zig** executable (`build.zig`, `src/{ike,esp,crypto,pki,bridge}`,
  `pki/`). The low-level VPN/mesh crypto + IKE/ESP + PKI engine behind the `mesh` service. ≈ V2 mesh/data-plane.
- **`hookprobe/`** — a **git submodule** (`.gitmodules`: `url = ../hookprobe`) that is the V1 **engine repo**
  (napse, qsecbit, hydra, cno, XDP). Empty in this checkout; the IDS stack builds from it, so the cloud repo
  is *not self-contained* — it composes the sibling engine repo + the web/control-plane defined here.
- **`sdks/python/hookprobe_tamper`** — small client SDK products use to POST signed tamper-signals to aegis-ledger.

## 5b. secrets / certs (presence only — values NOT read)

- `secrets/`: `aiven-ca.pem` (Aiven PG TLS CA), `gsc-service-account.json` (Google Search Console),
  `social-credentials.json` (LinkedIn/social). Mounted read-only into the dashboard.
- `certs-backup-20260127_060415/`: `cloudflare-origin.crt`, `cloudflare-origin-ca.pem`,
  `hookprobe.com.crt`, `dashboard.hookprobe.com.crt` — Cloudflare Origin TLS material for nginx.
- `containers/proxy/certs/` present (proxy cert staging). All other live secrets come from a `.env` at
  install time (every compose var uses `${VAR:?must be set}` — no secrets are committed in compose).

---

## 6. Deployment topology (text diagram)

```
                         Internet
                            │
                    ┌───────┴────────┐
                    │   Cloudflare   │   (proxied for web; DNS-only for mesh UDP)
                    └───────┬────────┘
   hookprobe.com / mssp. / auth. / docs.        mesh.hookprobe.com  (A → same VM IP)
                    │ 443/HTTPS                           │ 8144 tcp+udp, 3478/500/4500 udp
══════════════════ ONE Ubuntu/Debian VM ════════════════════════════════════════════
 ┌──────────────────── rootless podman (net 172.30.0.0/24) ───────────────────────┐
 │  OpenResty proxy :80/:443  ──Lua AI-WAF gate──►  ai-waf(.50)                     │
 │     ├─ hookprobe.com  → website(.10, Astro SSG)                                  │
 │     ├─ mssp.          → dashboard(.11, Astro SSR :3000) ★                        │
 │     ├─ auth.          → keycloak(.40, OIDC :8080)                                 │
 │     └─ docs.          → docs(.12, Starlight SSG)                                  │
 │  postgres(.30) + pgvector   valkey(.31)   aegis-ledger(.51)   video(.14)         │
 │  mesh(.13) ── binds host UDP/TCP directly (mesh.hookprobe.com) + TUN, NET_ADMIN  │
 └──────────────────────────────────────────────────────────────────────────────────┘
        │ dashboard → host.containers.internal:8123 (ClickHouse), :8900 (CNO)
 ┌──────────────────── ROOT podman (network_mode: host, net 172.33.0.0/24) ────────┐
 │  clickhouse :8123/:9000  ◄── inspector, qsecbit, hydra-{feed,consumer,enricher,  │
 │  features,sentinel,sentinel-engine,cve,temporal,lifecycle,anomaly,predictor}     │
 │  cno-organism :8900 (Bearer)  ── XDP blocklist/allowlist (privileged host)       │
 │  (all built from the hookprobe/ engine submodule)                                │
 └──────────────────────────────────────────────────────────────────────────────────┘
        ▲ heartbeat/enroll/telemetry (HTTPS /api/nodes/*) + mesh VPN (UDP 8144)
   Edge appliances: Guardian / Fortress / Nexus
 External managed: Aiven PostgreSQL (GDPR user data), OCI SMTP, Gemini/OpenRouter, GSC, LinkedIn
```

---

## 7. Mapping to V2 + implications

### Maps cleanly onto the V2 "cloud-linked (MSSP)" lens
- `mssp.hookprobe.com` **is exactly the V2 "Cloud-linked (MSSP)" deployment mode** (`docs/Readme.md`
  deployment-modes table): a multi-tenant control plane edge devices enroll into. V1 already implements:
  multi-tenant `mssp/*` + `admin/mssp-applications`, per-tier RBAC (`mssp-tiers.ts`, `tier-limits.ts`),
  Keycloak identity, node enrollment/claim/heartbeat, and a signed action/IOC ledger (aegis-ledger) —
  the concrete backbone V2's MSSP lens describes.
- The dashboard's workspace folders (`xsoc`, `agency`, `nodes`, `threat-feed`, `combat-mode`, `admin`,
  `mssp`, `free-tier`) are a V1 prototype of the V2 Mission Control **workspaces** in `docs/MissionControl.md`
  (Observe/Detect/Investigate/Automate/Customers/Administration). The "Organism" orb (R3F/Three.js) ↔ V2
  **QSECBIT "Organism Status" orb**. `agency/*` (Alexandria cognition/verdicts/lessons) ↔ V2 **AEGIS AI planner**.

### Real backend dependencies the VM deployment proves out
These are *actually running* services, not aspirational — V2 must treat them as real cloud-side deps:
1. **ClickHouse** — the central event/telemetry store (the `Telemetry Fabric` substrate). Heavy, root,
   host-net.
2. **PostgreSQL (pgvector)** + a second **Aiven managed PG** for GDPR user data.
3. **Keycloak** — OIDC identity / multi-tenant RBAC.
4. **Valkey/Redis** — cache + rate-limit.
5. **Mesh/VPN gateway** (HTP, host UDP 8144 + STUN/IPsec) backed by the **Zig HSG** crypto core.
6. **AI-WAF (TinyBERT ONNX)** + **aegis-ledger** (signed action ledger / IOC gossip / tamper sink).
7. The **`hookprobe` engine submodule** (napse/qsecbit/hydra/cno) — V1's detection brain.

### Top V2 implications
- **Heavy stateful services = Podman containers, exactly as V2 says.** V1 already does ClickHouse/PG/Keycloak/
  Valkey as containers; V2's "Wasm for logic, Podman (Quadlet) for heavy stateful services" rule is validated.
  V2 should formalize these as the cloud-plane's Quadlet services and treat ClickHouse as the canonical store.
- **Edge↔cloud contract already exists:** `/api/nodes/{enroll,claim,heartbeat,telemetry,provision}` + the
  HTP mesh on `mesh.hookprobe.com:8144`. V2's "device identity (TPM-bound) before any account / additive
  enrollment" should reuse/replace this enroll path; HSG (Zig) is the candidate V2 mesh data-plane.
- **Single-VM, dual-namespace podman is fragile** for the "fleet/MSSP" story — there is no HA, no k8s, no
  GitOps. V2's fleet model (pull-based GitOps, rollout rings) is *not* present here; V1 is a hand-installed
  single host via `install.sh` + `systemctl --user`. Treat V1 as the *functional* reference, not the ops model.

### Contradictions / tensions with the V2 docs
- **bootc / signed-OCI / Wasm modules: absent.** V1 is plain podman-compose + per-service Containerfiles
  with no cosign / SBOM / CBOM / SLSA and no Wasm. The whole supply-chain + Wasm-component invariant of V2
  (`docs/Readme.md` decisions 1 & 2) is greenfield relative to V1.
- **"Intent, not configuration" (V2 decision 3): not present.** V1 is configured by env vars + `install.sh`
  + SQL init files; there is no AEGIS-style reconciler-from-intent. Alexandria is an AI *governance* brain,
  not an intent reconciler.
- **"Standalone by default, no account": V1 is the opposite end** — `mssp.hookprobe.com` is account-first
  (Keycloak-gated). This is fine (it's the *additive cloud layer* V2 allows), but note V1 has **no
  standalone/air-gapped SOC** here — that lives in the engine repo, not this cloud repo.
- **Dashboard is globally read-only except `master_admin`** (middleware gate) — a V1 product decision that
  conflicts with V2's "everything operated by intent / plan-as-diff" interaction model; V2 will need a real
  write/authorization model, not a blanket read-only gate.
- **Crypto-agility/PQC (V2): not visible** in the web/cloud layer (classical TLS via Cloudflare origin certs).
  PQC posture, if any, would be in the HSG Zig core / engine repo, not here.

---

## 8. If a live check of `mesh.hookprobe.com` is wanted (NOT performed)

A live check would confirm the file-derived topology and reveal real runtime state. Methods/creds needed:
- **DNS / Cloudflare mode:** `dig +short mesh.hookprobe.com` and compare to `mssp.hookprobe.com` — equal IP
  and a non-Cloudflare IP confirms the "same VM, DNS-only grey-cloud" inference. (No creds.)
- **Mesh port reachability:** `nc -vz -u <ip> 8144`, `nc -vz <ip> 8144`, STUN probe to `3478/udp` — confirms
  the host-bound mesh ports are live. (No creds; UDP probes are best-effort.)
- **Health:** `:8766` is loopback-only, so only reachable via SSH on the VM (`curl localhost:8766/health`).
  Requires **SSH access to the `ubuntu` VM**.
- **Stack state:** `ssh ubuntu@<vm>` then `podman ps` (rootless) + `sudo podman ps` (root IDS) +
  `./install.sh status`. Requires **SSH key for the `ubuntu` user** (and sudo for IDS).
- **TLS/cert:** `openssl s_client -connect mssp.hookprobe.com:443 -servername mssp.hookprobe.com` to read the
  live origin/edge cert chain. (No creds.)

> Per instructions, none of the above was attempted; this map is built purely from repository files.
