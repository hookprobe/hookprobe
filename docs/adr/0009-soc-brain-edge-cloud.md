# ADR 0009 — The SOC brain: two-tier detect→track→trace→display (edge muscle / cloud brain)

**Status:** ✅ Accepted (2026-07-02). Grounded in a live investigation of the V1 production system
(`mesh.hookprobe.com`), the V2 module tree, and `docs/architecture/MissionControl.md`. Governs Track-B Phase 2
("Modules, Data & Supervisor") + the SOC surfaces of Track-A.
**Relates to:** [ADR 0002](0002-crypto-agility-pqc.md) (crypto-agility), [ADR 0003](0003-platform-manifest-schema.md)
(manifest), [ADR 0005](0005-unified-ebpf-detection.md) (eBPF), `docs/research/v2-reconciliation.md`, `docs/architecture/MissionControl.md`.

## Context (what the investigation found)

- **V1's detection is home-grown, not Suricata/Zeek** (the systemd names are stale). Real engines: XDP
  line-rate filter → heuristic + HMM intent classifier → Isolation-Forest anomaly → Bayesian fusion +
  temporal/predictive. Its **ClickHouse schema is the crown jewel** — `napse_intents/flows`,
  `hydra_events/verdicts`, `iocs`, `incidents`, `cti_*`, `ip_risk_scores`, `qsecbit_scores` — already a
  coherent common-event schema + evidence spine.
- **The science is already ported to Wasm** — `napse`, `qsecbit`, `dnsxai`, `aegis-guard` (pure-Rust),
  + the `napse-capture` XDP sysext (CO-RE, `BPF_MAP_TYPE_LPM_TRIE` blocklist/allowlist). **The blocker:
  the supervisor's loader is `MockLoader` — the modules don't execute yet.**
- **The display side is a fully specified contract** (`os/mission-control/src/store/*Mock.ts`) but the **evidence graph
  (track&trace spine) doesn't exist**, and there's no live push (Axum/SSE).
- `mesh` runs **15 podman daemons + ClickHouse** — far too heavy for a 1–2 GB edge.

## Decision 1 — Two tiers: edge MUSCLE, cloud BRAIN (standalone-first)

HookProbe is a **sovereign enforcement layer on top of** existing firewalls/switches — it supersedes
them rather than depending on their fabric. Split accordingly — and, per the Readme standalone-first
invariant, **the edge runs a COMPLETE local SOC air-gapped** (detection + enforcement + evidence). The
cloud is **additive accuracy + fleet scale + long retention**, never a precondition and never the sole
home of a detection class.

| | **Edge** (Pi/CM5/N100/appliance) | **Cloud / Mesh** (MSSP, `mesh`) — *additive* |
|---|---|---|
| Role | capture · line-rate enforce · **full local detect** · local evidence · local verdict | **accuracy upgrades** · CTI · fleet correlation · long retention |
| Compute | XDP + AOT-Wasm engines (target ≤~333 MB SOC¹) | ClickHouse + pod-consolidated HYDRA/ML |
| Store | **DuckDB** (in-process) → Parquet chunks | ClickHouse (MergeTree) + **AggregatingMergeTree MVs** |
| Detect | **complete stack:** napse (HMM/Bayesian/signatures) · qsecbit (Mahalanobis/entropy) · dnsxai · aegis-guard — all Wasm | **heavier/retrained** Isolation-Forest · full Bayesian fusion · temporal/predictor · sentinel — refine edge verdicts, never replace them |

¹ *333 MB = the measured live-Pi SOC working set (§perf), used here as the edge budget target.*

## Decision 2 — Reuse V1, don't rebuild

Adopt V1's **ClickHouse schema (lightened) as the evidence-graph model**; **reuse the CTI ingestion**
(`feed_sync`, `cti-sync`, `cve_enricher` — free STIX-aligned feeds) and the **XDP enforcement**; the 4
Wasm engines are the ported detection math. Rebuild only: delivery/orchestration (15 daemons → few
Wasm + pods), the Mojo classifier (→ Rust+WASI-NN), and drop the bespoke NSE crypto (use ADR 0002).

## Decision 3 — The pipeline: detect → track → trace → display

```
DETECT  capture(napse-XDP / senzorium) → flows/events → Wasm engines → detections+scores
TRACK   every record → node(stable id)+typed edges in the EVIDENCE GRAPH (DuckDB, V1 schema)
TRACE   AEGIS correlation → Threat→Incident story {why·confidence·evidence·model·plan}  (deterministic core; LLM assistive)
DISPLAY Axum read-API + SSE/WS over the graph → Observe/Detect/Investigate/Intelligence boards
```
Boards are **lenses over one substrate** — every displayed number resolves to a graph node id
(drill-down), every decision carries the AI-explanation envelope.

**Evidence-graph model (V1 flat tables → Mission Control graph).** The graph is materialized in DuckDB
as the V1 tables (node stores) + one `edges(src_id, edge_type, dst_id, ts)` table populated on write:

| Graph node (MissionControl) | Backing V1 table | Stable id |
|---|---|---|
| Device/Asset · Interface | asset registry (ip/mac) | `mac` (universal) else asset-key |
| Connection/Session/Flow | `napse_flows` | `hash(5-tuple + ts-window)` = `community_id` |
| Detection→Threat | `napse_intents` + `hydra_verdicts` | `hash(rule_id + community_id + ts)` |
| Incident | `incidents` | `incidents.id` (UUID) |
| IOC · CVE · Technique | `iocs` · `cti_vulnerabilities` · `cti_attack_patterns` | native id (UUID / CVE-id / Txxxx) |
| Response | enforcement action record | `hash(action + target + ts)` |

Edges are written when a record links two nodes: `detection→flow` (community_id), `flow→device`
(src_ip/mac), `incident→detection` (campaign/src_ips), `ioc→event` (ip match), `cve→asset` (cpe match).
Same node id everywhere (never a copy) → the drill-down + evidence-count + IOC/CVE joins the boards
require. Full node/edge DDL is Build step 2's deliverable; this is the contract.

## Decision 4 — Edge efficiency (the three pillars, validated)

- **AOT Wasm.** Precompile each module to `.cwasm` **per target arch at build time** (Wasmtime,
  epoch + StoreLimits) → no JIT, deterministic memory, ~ms cold start. Replaces `MockLoader`.
  *(Status, ADR 0016/0017: build step 1 shipped this as an on-device, first-boot,
  writable-partition precompile instead — cross-arch precompile at image-build time was judged
  too fragile to validate without target hardware. A 2026-07-05 security audit found that
  writable cache was an unauthenticated bypass (ADR 0016 Errata); Fix A closed it by disabling
  the AOT fast path for signed modules entirely (~1000x cold-start regression, measured). ADR
  0017 restores THIS decision's original ~ms target properly: build-time precompile, per arch,
  digest-pinned inside the same signed `module.yaml`, shipped read-only — the "too fragile"
  objection no longer applies once the build stage runs AS the target arch (QEMU-emulated),
  which this repo's Containerfile already does.)*
- **DuckDB + Parquet columnar offload.** DuckDB is the light evidence store (single-process in-process
  writer, tiny, sequential writes → compressed Parquet row groups every ~10k flows / 30 s). Offload:
  the edge **pushes** Parquet to object storage (a no-IP/NAT'd bridge can't be pulled from) and
  **signals** the mesh over the nerve; ClickHouse ingests via **`s3()`** into MergeTree — a
  **columnar bulk-load with no vendor normalization / log-stasher** (Parquet encode↔MergeTree decode
  remains — not literally "zero," but no impedance mismatch). One choice = light store *and* clean
  offload. *(DuckDB is single-writer → the supervisor/store service is the sole writer.)*
- **Ring-0 enforcement with atomic map swaps.** XDP already uses `LPM_TRIE` (CIDR-efficient, O(L)).
  Push cloud `ip_risk_scores` down into an eBPF risk map for Ring-0 drop. Update via **double-buffering**
  (`BPF_MAP_TYPE_ARRAY_OF_MAPS`): the native loader builds a new inner LPM off-datapath
  (`bpf_map_update_batch`), then an **atomic RCU pointer swap** at `outer[0]` — XDP lookup cost stays
  static whether updating 10 or 100 000 IPs. **No packet stall.** (libbpf-rs 0.24, kernel ≥5.6/6.1.)

## Decision 5 — Sovereign invisible overlay: legacy iron is a dumb pipe

**Positioning (superseding, not integrating):** the edge does NOT ask Cisco/Fortinet for data
(NetFlow) or permission (FortiManager/ISE APIs). It is a **sovereign, invisible enforcement layer** that
sits *on top of* their hardware and makes it look bloated. Deployment map: **inline = branch/edge/
chokepoint/SMB; out-of-band tap = high-throughput cores** (telemetry advantage holds either way).

- **Invisible transparent bridge (bump-in-the-wire).** Bridge two physical NICs (WAN↔LAN), **no IP on
  the bridge** → the board can't be scanned, targeted, or managed by the enterprise fabric — a ghost.
  XDP binds to the physicals. **Requires ≥2 data NICs + a management path** (NanoPi R3S dual-GbE uses
  Wi-Fi/USB for mgmt; N100 4×2.5GbE has spare ports — *not* a 1-NIC Pi without a USB NIC).
  **Fail-open, honestly tiered** (per the Readme): a **software bridge bypass** covers a graceful stop /
  crashed userspace, but only a **hardware-bypass NIC** (relay that shorts the ports on power loss)
  covers a *dead/unpowered* board — the named boards lack that relay, so true dead-board fail-open needs
  a bypass NIC. Default posture stays **out-of-band** (safe); the inline bridge is the powerful opt-in.
  Management is out-of-band — the SASE tunnel over the mgmt NIC/AP, never an IP on the bridged subnet.
- **Superior telemetry — AF_XDP, not NetFlow.** Raw wire off the NIC ring → **unsampled** L7 (TLS
  SNI/JA3-JA4, DNS, cleartext HTTP) + flow metrics (entropy, jitter, retransmits) at µs precision →
  `napse_flows`/`napse_intents` directly. Richer than sampled NetFlow, no DPI license. **Two honest
  limits:** (a) **zero-copy needs driver support** — native XDP + ZC on `igc`/N100; Pi `bcmgenet` is
  **copy-mode over generic XDP** (ADR 0005), so the sovereign story is strongest on N100-class NICs;
  (b) L7 is **cleartext-only** — ECH + DoH shrink it industry-wide → lean on metadata + JA3/JA4
  fingerprints + entropy, don't over-promise payload inspection. Same path runs **inline or on a tap**.
- **Sovereign Ring-0 enforcement — local-first.** The edge's OWN `aegis-guard`/`napse` verdicts drive
  the LPM double-buffer directly (the **primary, air-gapped** path — no cloud). *Additionally*, when
  cloud-linked, a mesh `hydra_verdict` streams down (NATS, crypto-agile signed) into the **same** map.
  Either way: atomic LPM-Trie swap → **XDP drops at Ring-0 before the packet reaches the Cisco/Forti
  hardware.** **Throughput ceiling scales with the board** (Pi ~1–2 G, N100 ~2.5 G/port) → inline
  enforcement fits chokepoints, not a 100 G core (where XDP runs out-of-band on a tap for telemetry).
- **Data sovereignty (columnar, no normalization).** `napse_flows` written locally to Parquet via
  DuckDB → ClickHouse ingests exactly that schema. No log stashers, syslog forwarders, or vendor
  normalization scripts — we own the pipeline from the electron on the wire to the Mission Control board.

> **Cooperative mode (optional additive, NOT the hero):** for customers who *do* want fabric
> integration, the same verdict can drive a FortiManager Dynamic-Address-Object or Cisco pxGrid-ANC
> quarantine as a reversible plan-as-diff. Secondary — sovereign enforcement is the default architecture.

**Competitive frame:**

| | Legacy enterprise iron | V2 sovereign edge |
|---|---|---|
| Telemetry | sampled NetFlow (L4), delayed | **AF_XDP raw wire**, µs L7/fingerprints |
| Enforcement | proprietary ASIC, rule compilation | **XDP Ring-0 LPM**, atomic map swaps |
| Storage | expensive SIEM ingestion | **DuckDB → ClickHouse (Parquet, zero-ETL)** |
| Footprint | heavy routing, visible hops | **invisible transparent bridge (no IP)** |

## Decision 6 — The nerve + guardrails

- **Transport:** **NATS JetStream** (pub/sub, disconnect-tolerant) for telemetry-up + verdict-down —
  additive (cloud-linked); GitOps HTTP pull stays for desired-state. Reachability uses the existing
  **SASE tunnel** (edge behind NAT is reachable over it, or pushes Parquet to object storage).
- **Signed sync is crypto-agile, NOT raw Ed25519 — but a NEW crypto domain.** Pushed CTI/risk payloads
  are signed and the edge verifies **before** touching any eBPF map. Use the ADR-0002 provider
  abstraction (hybrid ml-dsa-65 + ed25519), but define a **new `feed_signing` / `telemetry_auth`
  domain** in the manifest `crypto` block — do **NOT** overload `module_signing`, whose key custody is
  **offline in the release HSM (devices only verify)**. A live mesh feed uses an **online** signing key
  (different custody) — same algorithms, different domain. A long-lived feed key is exactly the HNDL /
  CNSA-2.0-by-2027 target; never hardcode a classical algorithm.
- **eBPF stays in the native loader, not the Wasm sandbox.** `wasm-bpf` would grant a sandbox raw
  kernel-map access — defeating the sandbox. Privileged eBPF management stays in the small, audited,
  signed native loader; Wasm does detection logic only.
- **Serialization:** JSON for control/config + module-dev simplicity; **Parquet for bulk offload**
  (subsumes Cap'n Proto's zero-parse benefit); WIT will later formalize module-to-module.

## Build order (each validated on live edge/cloud hardware as appropriate)

1. **Wasmtime loader + AOT precompile** → the 4 Wasm engines execute sandboxed on the Pi (unblock —
   proves *execution*; real capture input arrives at step 3).
2. **DuckDB evidence store + Parquet chunks** (V1 schema, stable node ids + edges).
3. **AF_XDP sovereign capture** — transparent bridge (≥2 NIC, fail-open bypass) or mirror tap →
   `napse_flows`/`napse_intents` (unsampled, µs L7). *(Cooperative NetFlow/syslog ingest = optional.)*
4. **Axum read-API + SSE** over DuckDB → wire the Mission Control boards to live edge data.
5. **eBPF risk-score map + atomic double-buffer + crypto-agile signed sync** → sovereign Ring-0 drop.
6. **Cloud:** pod-consolidate HYDRA/ML, ClickHouse MVs, `url()`-pull Parquet, ~~**fix `modules/hydra`**
   (stale "SOAR" manifest → threat-intel / Intelligence)~~ — ✅ **CLOSED 2026-07-05** (ADR 0015 C1):
   `modules/hydra/module.yaml:23` now `workspace: Intelligence`. The rest of the cloud step remains open.
7. **AEGIS correlation** (incident envelope + plan-as-diff). *(Optional cooperative fabric adapters —
   FortiManager / Cisco ISE — as reversible plan-as-diffs.)*

## Consequences

- The two-tier shape means the **same edge image** is a standalone SOC *and* a mesh sensor; capability
  and mode gate the cloud features.
- The evidence graph (DuckDB→ClickHouse, one schema) is the single spine behind **all SOC boards**
  (Observe/Detect/Investigate/Intelligence *and* Protect/Network) — the "one system" invariant, made real.
- The **sovereign invisible overlay** (transparent bridge · AF_XDP telemetry · Ring-0 enforcement)
  makes HookProbe *supersede* legacy iron rather than depend on it — the core differentiator — while
  per-interface fail-open keeps the inline path safe and AEGIS stays assistive (out of the hard path).
- Open follow-ups: WIT interfaces (close the JSON-lines↔WIT gap), the WASI-NN accuracy upgrades
  (GNN/RF/VAE/ensemble), the Mojo classifier rebuild, and `fleet_mesh` (PQC-first) — none block the
  standalone SOC brain.

## Canonical alignment (tracks `docs/architecture/MissionControl.md` + `docs/architecture/Readme.md` + `docs/roadmap/BuildPlan.md`)

Per the repo rule — *treat Readme.md + MissionControl.md as canonical; keep them in sync; flag (don't
silently resolve) contradictions.* This ADR **refines**, never overrides, those specs:

| ADR 0009 decision | Readme.md (OS) | MissionControl.md (dashboard) | BuildPlan phase |
|---|---|---|---|
| D1 two-tier edge/cloud | "Standalone by default" · "offload to SIEM to exceed local capacity" | mode-aware (standalone hides fleet/tenant) | B-Phase 2/7; A-Phase 4 |
| D2 reuse V1 (schema/CTI/XDP/Wasm) | modules on one base | Intelligence=HYDRA (v2-reconciliation D2) | B-Phase 2 |
| D3 detect→track→trace→display | one data model · common event schema | **evidence graph** + **telemetry fabric** + AI-explanation envelope + plan-as-diff | A-Phase 3/4 |
| D4 AOT-Wasm · DuckDB · Ring-0 atomic swap | Wasm 1–5 ms · resource budgets · ADR 0005 eBPF | Observe retention tiers | B-Phase 2 |
| D5 sovereign invisible overlay | **"Data plane out-of-band by default, inline opt-in; per-interface fail-open"** | Protect (per-iface posture oob/inline, fail-open/closed) | B-Phase 7 (data plane) |
| D6 crypto-agile signed sync · native-loader eBPF | "Trust nothing unsigned" · ADR 0002 PQC | — | B-Phase 5 |

**Invariants honored:** standalone-first · capabilities-not-branches · out-of-band-default/inline-opt-in
(D5 = the inline mode) · trust-nothing-unsigned · crypto-agility · bounded/honest retention (DuckDB tiers).

**Reconciliations flagged (not silently resolved):**
1. **`modules/hydra` manifest was stale** ("automation/SOAR") — contradicted `v2-reconciliation.md` D2
   (HYDRA = threat-intel → **Intelligence**). ✅ **CLOSED 2026-07-05** (ADR 0015 C1): `module.yaml:23`
   now `workspace: Intelligence`. Any remaining prose in `runtime-engine-map.md:40,56` / `V1-alignment.md:26`
   is the residual doc-sweep, not the manifest.
2. **Sovereign D5 vs "out-of-band default"** — NOT a contradiction: the sovereign transparent bridge
   *is* the inline opt-in mode; out-of-band tap remains the default and the high-throughput-core path.
3. **JSON-lines vs the CLAUDE.md "WIT" framing** — module I/O is line-delimited JSON today; WIT is a
   tracked follow-up, not yet reality.

**On build: update `docs/roadmap/BuildPlan.md` change-log per step, and keep this table current** so the ADR
never drifts from canon.

---

## Revision 2026-07-02 — Edge store: SQLite, not DuckDB (corrected tier mapping)

**Decision:** the EDGE evidence graph uses **SQLite** (rusqlite, bundled); the CLOUD analytical tier stays **ClickHouse** (already deployed at `mssp.hookprobe.com`, DB `hookprobe_ids`: 2.4M napse_flows, 29.7M hydra_events, the cno/sentinel/hydra brain).

**Why the original DuckDB pick was wrong for the edge:** DuckDB's only advantage over SQLite is columnar analytical scans + native Parquet — both of which matter at *cloud* scale, which ClickHouse already owns. At the edge (point lookups + bounded graph traversal over retention-capped data) SQLite is the right fit: ~1.7 MB static binary vs DuckDB's ~50 MB C++/`.so`, trivial aarch64 cross-compile (no g++, no shipped lib), instant standalone.

**Performance, measured on the live Pi 4 (not asserted):**
- Ingest 1063 flows + 224 detections + 15k edges: **0.9s** (fix: `PRAGMA journal_mode=WAL; synchronous=NORMAL` + one transaction around the ingest — default autocommit fsync-per-INSERT was the real cause of an apparent "SQLite is slow", not the engine).
- `attack_path` on a dense hub (224 detections + 1063 flows on one device): **10.7s → 0.115s (93×)** by adding `CREATE INDEX idx_edges_dst ON edges(dst_id)` (the PK covers `src_id`; the bidirectional traversal `src=x OR dst=x` needed `dst_id` indexed too).

**Offload:** SQLite → ClickHouse via **JSONEachRow** (`export_jsonl`), which ClickHouse ingests natively (`INSERT … FORMAT JSONEachRow`) — DuckDB's zero-ETL Parquet is unnecessary since the cloud already speaks JSONEachRow. Transport is the mesh gateway (`hookprobe-mesh:8144`) → the heartbeat/`node_intel` + ClickHouse path (V1 contract, §V1-alignment).

**DuckDB reconsidered + rejected (2026-07-02):** DuckDB *does* run on a Pi (official aarch64 build), but the measured SQLite numbers above (0.9s ingest, 0.115s threat-graph) meet the edge's need at 1/30th the footprint, so DuckDB's columnar edge buys nothing the edge uses. Revisit ONLY if the edge must serve heavy *local* analytical aggregations standalone (unlikely — that's the cloud tier).

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: SOFT (with HARD capture/enforce legs).** The two-tier detect→track→trace shape and the Wasm detection *science* survive; the AF_XDP sovereign capture + `tc-mirred` bridge + Ring-0 LPM enforcement legs are re-implemented on heqk's zero-copy Packet Engine + BPF plane. → **Phase M2**.
