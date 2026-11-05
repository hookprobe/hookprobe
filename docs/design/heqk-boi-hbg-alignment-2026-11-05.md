# BOI / HookProbe Behavioural Genome (HBG) — deep alignment with heqk + HookProbe OS (2026-11-05)

> **Status: design alignment, Amber (operator reviews).** This takes the operator's BOI/HBG
> proposal (behavioural DNA with three temporal layers, Bayesian recurrence, compact signature
> deltas, next-event prediction, an isolated subsystem with its own storage/identity) and maps
> it onto the repo **as it stands** — real seams, real sizes, real gates — so the formal spec
> and ADR 0048 can be written against facts. Every claim below is grounded in code or canon;
> where the proposal and canon collide, the collision is named and resolved, not smoothed.
> Canon: ADR 0047 (heqk everywhere, Mission Control on-device), ADR 0023 (enforcement
> separation), ADR 0014 (continuous improvement: no on-device training), ADR 0038 (AI tiers,
> C9 by construction), ADR 0003 (manifest tokens), `docs/Readme.md` (bounded & honest; the
> "not predictive" guardrail), `docs/MissionControl.md` (Detect → Behavioral, explanation
> envelope), `heqk-everywhere-report-2026-10-09.md` (gap ranking, port order).

## 0. The one-paragraph answer

HBG fits HookProbe OS unusually well — better than it would fit a Linux-tier product — because
the three things it needs most already exist on heqk as proven primitives: an **authenticated,
loss-honest, sequenced delta transport** (the M6 `HQXR` v2 export plane), an **anti-poisoning
pattern for accepting state from outside the node** (the C9/C16 operator-signed policy with
gen-floor + tenant + TOFU-pinned key), and a **signed-module isolation boundary** (the Ed25519-
verified Wasm excursion in EL0). What does *not* exist yet, and what the design must be honest
about: observations today are 24-byte detection events with **no destination, port, protocol
or byte count**; on-device persistence is a **16 KiB sealed window plus a 16-sector DataVolume**;
the CM5 production loop runs **IRQs-off with no scheduler**, so "an independent subsystem with
its own runtime" is, on CM5 today, a **signed Wasm step invoked per heartbeat**, not a daemon;
and three pieces of canon push back — **ADR 0014 D1** (no on-device training of detection
logic), the **Readme honesty text** ("not predictive"), and the **absence of any privacy /
profiling stance** in V2. BOI is therefore scoped as: *on-device = Observation + Memory
(immediate + intermediate layers, as bounded state) + Deviation (observe-only detections)*;
*off-device/fleet = long-term genome, graph, prediction models (trained off-device, signed),
replication*. Decision stays exactly where it is: `verdict::decide()`.

## 1. Vocabulary mapping (proposal → repo)

| Proposal | HookProbe OS / heqk equivalent (today) | State |
|---|---|---|
| Observation | heqk `events::Event` (SOAR ring, 64 slots, 24 B: ts/src/rule/sev/verdict/class) + Linux `detections`/`flows` rows | exists, **too thin** (no dst/port/proto/bytes — everywhere-report gap 6) |
| Memory (genome) | nothing persistent; `behavioral.rs` keeps 10-min windows in 16-key tables; `prodfull` snapshot persists 64 events | **gap** — this is what HBG adds |
| Prediction | none in V2 (`Readme.md:464-468` says so on purpose); V1 had `lstm_threat_detector.py` (attack-category sequences, trained on-device — an anti-pattern per `v1-map-source.md:323`) | [vision] |
| Deviation | `FindingClass::Behavioral` → `Verdict::Observe` unconditionally; `corroboration.rs` axis bitmask raises severity only | exists, extend |
| Decision | `verdict::decide()` tri-state + `Allowlisted` floor; ADR 0023 D2's four drop classes | exists, **untouched by BOI** |
| Behavioural entity | Linux: `fingerprint.rs` `DeviceProfile` (identity independent of MAC — MACs randomise); heqk: DHCP MAC-bound lease table (`ApDhcp.leases`), `mac_hash` keys | partial (fingerprint is PORT-listed for heqk) |
| Context (office/VPN/travel/off-hours) | `enroll` tenant, `segment.rs` reach, interface role (`PortRole`), time-of-day — **no context model exists** | gap |
| Behavioural Signature (BSIG) + delta | `exportwire.rs` v2 frames (seq, loss, tenant, device_fp, class) — the delta *transport* exists; no BSIG codec | transport exists, codec = new |
| Secure replication / "a node must not blindly accept a DNA update" | `enroll.rs` `apply_reach_policy`: operator Ed25519 sig (key distinct from the Noise static) → tenant check → gen > persisted floor → else state unchanged; TOFU-pinned op key | **exists — reuse verbatim** |
| BOI's own crypto identity | device identity = Ed25519 from HKDF(SRK, "HEQK-DEVICE-IDENTITY-ed25519-v1"); sealing = HQKSEAL1 under SRK + policy | exists; BOI needs its own HKDF label, not a new root |
| Isolated runtime | EL0 Wasm host: Ed25519-verified module, own ASID/CSpace, W^X; on CM5 a synchronous excursion in a 2 MiB window, 256 KiB heap, no `random_get`, no WASI-NN | exists for classify-shaped modules; **budget-bound** |
| Hierarchical DNA (user/device/segment/org) | evidence graph nodes `users` / `devices` / `interfaces` / tenant (`enroll.tenant_id`) + edges; `REACH_CTE` traversal | exists off-device; on-device only device + segment |

## 2. Where the proposal collides with canon — and the resolution

| # | Collision | Resolution (goes into ADR 0048) |
|---|---|---|
| C1 | **ADR 0014 D1 / ADR 0038 D5:** "neither tier self-trains on-device in the enforcement path"; models are trained off-device, signed, digest-pinned, model-carded. HBG *learns* on the device. | Split *state* from *logic*. The genome's per-entity statistics (counts, active-day bitmaps, time/context histograms, Welford mean/var, recurrence posterior) are **state** — the same class of thing as `ratelimit`'s flow tables and `prodfull`'s snapshot, persisted and sealed. The **logic** that turns state into a verdict (priors, decay constants, thresholds, Markov/LSTM weights) is **shipped signed** and never updated by the device. Enforcement never reads BOI. This is consistent with D1's reasons (C9, explainability, trust-nothing-unsigned, poisoning) because the only thing an attacker can influence by behaving is *evidence*, never *policy*. |
| C2 | **ADR 0023 D2:** exactly four safe-to-drop classes. The proposal's "novel destination" is not one, and must never become one. | BOI emits `FindingClass::Behavioral` detections only (Observe by construction, like rules 116/117/119). A BOI deviation may become **one corroboration axis** (`AXIS_BEHAVIOUR`, severity-only, never wire). A11's ruling stands: corroboration never quarantines. |
| C3 | **`trust.rs` hazard:** a `PostureSignal` with default `SignalProvenance::Direct` can quarantine alone (threshold 70). | BOI never produces a `Direct` posture signal. If it feeds trust at all it does so as a non-Direct, corroboration-gated input, and a device-level BOI score never counts as a distinct per-device signal twice (HYDRA `verdict.rs` rule for the host-global QSECBIT). |
| C4 | **`Readme.md:464-468`:** HookProbe "does not perform ML-based attack-pattern anticipation… not predictive"; public claims barred until built. | The prediction engine is **[vision]** until a signed model passes a gate; the text is updated only then, tagged [realized]/[partial] per ADR 0047 D4. Phase 6 below is the gate. Marketing copy does not move first. |
| C5 | **No privacy / PII / profiling stance exists** in V2 (no ADR, `SECURITY.md` silent). HBG stores working schedules, destinations, relationships — more sensitive than logs, as the proposal itself says. | ADR 0048 is where the stance is decided. Minimum: data minimisation (destination = hashed FQDN/SNI or ASN+port, never URL/path; user = pseudonymous principal id), on-device by default and standalone (no cloud precondition — CLAUDE.md invariant), per-tenant sealing keys, bounded retention shown to the operator, deletion = region wipe + key rotation, fleet contribution **opt-in** (ADR 0014 D5), and the V1 rule kept: *model how targets are attacked, not what people browse* — long-term DNA keeps destination *classes* and *relationships*, not browsing history. |
| C6 | **Licensing** (`LICENSING.md:50-54`): trained scoring weights and federated learning are commercial; V1 `behavior_clustering.py` is marked proprietary. | The HBG spec, codec, observe-only scorer and on-device state machine are AGPL (part of the base SOC); trained prediction weights and fleet-level learning are commercial artifacts. State this in the ADR so the boundary is designed, not discovered. |
| C7 | **ADR 0047 D3:** new capability lands in heqk, not the Linux tier. The proposal suggests BOI "on an N100 receiving observations from CM5". | Correct direction, wrong substrate word: the receiver is **another heqk node** (fleet/MSSP) in the end state; today the only off-device consumer is `responder-sim` → `hookprobe-evidence`, which ADR 0047 D3 permits as *host-side tooling*. So BOI's core is a portable `no_std` crate linked by both (the `#[path]` pattern already used for `exportwire.rs` and `rulecat.rs`), never a Linux-only service. N100 heqk is multi-quarter (gap 11) — BOI must not depend on it. |
| C8 | **Capabilities, not branches** (ADR 0003): flat tokens, `requires` vs `provides`, `ml_cpu` ≠ `edge_ai`. | BOI is a module that `provides: [boi]`, `requires: [soc]` for the statistical tiers and `ml_cpu` / `edge_ai` only for model tiers; honest `PresentUnsafe` reasons. No new platform token unless a hardware/policy fact demands it. WASI-NN on heqk does not exist — do not design against it. |
| C9 | **Signing mismatch** (gap 7): catalogue modules are ML-DSA-65 + Ed25519; heqk verifies Ed25519 only. | BOI's module/model artifacts ride the catalogue path; the mismatch is fixed once for all modules (ADR 0002 says fail-closed hybrid), not special-cased for BOI. |

## 3. Attachment seams — concrete

### 3.1 Observation (the event contract)
- **Do not drain the SOAR ring for BOI.** There is one drain point per profile and a second
  drainer silently steals events (`main.rs` comment, everywhere gap 5). SOAR = *detections*.
- Add an **observation stream** distinct from detections: a per-flow record emitted where the
  5-tuple is actually known — `packet::classify` (has `src`, `dst`, `dst_port`, `ip_proto`) and
  the NAT path (`nat.rs` entries; today they store **no dst ip/port** — add them, which also
  closes the UI's `:0` port display, gap 6). Proposed `Obs` (32 B): `ts:u64, ent:u32
  (entity key), dst:u32, dport:u16, proto:u8, dir:u8, bytes:u32, ctx:u8 (iface role | tenant
  bit | vpn bit | hours bucket), flags:u8, pad:u16`.
- Own ring, deeper than 64: 1024 × 32 B = 32 KiB static, drained by the BOI step each
  heartbeat; overruns counted and exported like `heqk_sensor_loss` ("what did NOT arrive is
  evidence too").
- **Sessionisation happens at ingestion**, exactly as the proposal warns: one `Obs` per
  (entity, dst, dport, proto) per `FLOW_IDLE_SECS`-style window, not per packet — the
  flow-gauge in `ratelimit.rs` already keys on this shape.
- Entity key: `fingerprint.rs` profile id ported (PORT list), seeded on heqk from the MAC-bound
  DHCP lease + DHCP option 55/60/hostname signals the AP server already parses; **never raw IP,
  never raw MAC** (randomised MACs would fork a user's genome every join).

### 3.2 Memory — the three temporal layers as bounded state
- **Immediate (s–min):** a windowed ring per entity, in RAM, lost on reboot by design — the
  `behavioral.rs` tables are already this shape (beacon 16 keys × 8 timestamps, lateral 16 × 64
  peers). Keep those detectors as the deterministic ADR 0023 parity rows; BOI's immediate layer
  is a second consumer of the same `Obs` stream, not a replacement.
- **Intermediate (h–weeks):** per (entity, destination-class) record: `first_seen, last_seen,
  obs_count, active_days (u64 bitmap, 64 days), hour_hist[24]:u8, ctx_hist[8]:u8, state:u8
  (Novel/Emerging/Established/Dormant), recurrence_q16:u16, novelty_q8, persistence_q8` ≈ 56 B.
  The Bayesian recurrence update is integer-only (Q16 fixed point; `no_std`, no float — the
  same constraint `behavioral.rs` lives under). **Active-days, not visit counts**, drives
  Emerging→Established — the proposal's "three visits in three minutes ≠ three weeks" point.
- **Long-term (weeks–months):** the compact BSIG — the established set + context baseline only,
  decayed, versioned. On device it is a **few KiB**, which the persistence budget forces:
  `fslog` sealed records are ≤ 352 B payload, the metal DataVolume is 16 sectors today and the
  keystore window 32 sectors (16 KiB) shared with VEK/OTA/cookie. So: on-device long-term DNA =
  `N_ENT × ~56 B` intermediate records + one BSIG blob, with `N_ENT` sized per platform
  (CM5 bench: 64 entities ≈ 3.6 KiB + 512 B BSIG). The **dedicated DataVolume partition**
  (M3 open item, everywhere gap 4) is the prerequisite for anything bigger. Full history lives
  off-device in the evidence graph (`RAW_AGE_TABLES` retention, 30-day default).
- One event updates all three layers once (the proposal's "not three databases"): the BOI
  step consumes an `Obs`, bumps the immediate ring, folds into the intermediate record, and
  only a state transition (Novel→Emerging→Established→Dormant) touches the BSIG.
- Decay = `Dormant` with relevance decay, never erasure on device; erasure is a retention
  policy and a key rotation, surfaced in `/api/evidence/stats`.

### 3.3 Runtime placement (the "independent subsystem" question, answered honestly)
- Target shape (**[partial] today**): the BOI update step is a **signed wasip1 module** run by
  the EL0 Wasm host once per heartbeat, state passed through the work page, output = BSIG
  delta + zero or more Behavioral detections. This gives the proposal's install/upgrade/disable-
  independently property through the existing catalogue + Ed25519 gate, and the isolation
  boundary (own ASID/CSpace, W^X, fault-contained — proven on CM5 for classify modules).
- Budget reality on CM5: 2 MiB window, 256 KiB heap, synchronous excursion, no `random_get`,
  std wasip1 modules need ~1.1 MiB linear memory (QEMU-only today). A `no_std` wasip1 BOI
  module (like `wasip1-fixture`) fits; a std one does not until the window grows. The first
  on-device increment can be a `no_std` library called from the prod loop (the `prodfull` /
  `export` shape) with the module boundary added once the state ABI is stable — mark
  [partial] and say so in the UI engines list (`real_engine_entry`, not `"source":"mock"`).
- A long-running EL0 BOI *service* needs the scheduler/IPC path enabled in prod (cm5 prod is
  IRQs-off); that is its own design, not a BOI prerequisite.

### 3.4 Protection of the genome
- At rest: `fslog` `append_sealed` under a **BOI-specific VEK** (`load_or_create_vek` with its
  own policy label), itself sealed under SRK + policy — so a leaked DataVolume is ciphertext
  and a different image measurement cannot unseal it. Per-tenant key = tenant id folded into
  the HKDF label.
- Integrity + replay: record `seq` + HMAC are HQKSEAL1 properties already; `Tracker` on the
  receiver reports gaps/late/reboots.
- Inbound genome updates (fleet → node): **reuse `apply_reach_policy`'s shape exactly** —
  signature by an independent operator/fleet key (not the channel key), tenant match, gen >
  persisted floor, TOFU-pinned key, any failure = state unchanged. That is the proposal's
  "verify provenance, authority, version and integrity" with a metal-proven implementation.
- Poisoning of baselines by *behaving*: bounded by (a) active-days rather than counts, (b)
  per-entity caps, (c) Established requiring independent-day evidence, (d) a detector-side
  rule that **BOI state never auto-promotes anything into an allowlist or a policy** (the
  A9-4 lesson: operator-confirmed only, (MAC, port)-scoped).

### 3.5 Deviation → detections (the only enforcement-adjacent surface)
- Rule-id band **1_300_000** (free: napse 1_000_xxx, heqk 1_200_000+, supply 9_1xx/9_2xx,
  Sigma 2e9, YARA 3e9, HYDRA 4e9, dga-lm "9M" reserved). Proposed ids: `001 novel_destination`,
  `002 emerging_relationship`, `003 dormant_reactivated`, `004 context_shift`,
  `005 sequence_surprise` (prediction-backed, Phase 6), `006 entity_genome_reset`.
- Severity on the canonical 1–5 scale (`SEV_LOW=4` for Novel; never above MEDIUM without
  corroboration). Class `Behavioral` → `Observe`. Confidence = recurrence posterior, emitted
  in the explanation envelope (`why · confidence · evidence · model`), `model: null` until a
  signed model is in play. `correlate_incident` folds BOI rows into the per-device incident
  automatically via `src_ip` — set it.
- Explanation text is deterministic and specific: "first contact with <dst class> during
  working hours, VPN=corporate; 0 prior active days" — the proposal's Tuesday 11:32 example
  rendered as evidence, not as an alarm.

### 3.6 Export / fleet (BSIG deltas over the existing plane)
- New HQXR record kind (`REC_BSIG_DELTA`) carried in the same v2 frame family (`frame_seq`,
  `first_ev_seq`, loss counters, tenant, device_fp, AEAD AD domain-separated); receiver
  `export_rx` → JSONL `type:"heqk_bsig_delta"` → `hookprobe-evidence` ingest into **new node
  tables + edges** (`behaviour_entities`, `behaviour_relations(entity, dst_class, state,
  recurrence, first/last_seen, active_days)`, edge `behaves_toward`), never new columns on
  `devices` (the crate's stated migration rule). Retention: joins `RAW_AGE_TABLES` or carries
  its own documented sweep, surfaced in `graph_stats`.
- Bytes-per-update is a first-class metric: a delta is one 56-B record or less, versus
  re-sending a profile — the proposal's low-bandwidth argument lands directly on the M6 plane's
  4-frames-per-heartbeat budget.

### 3.7 UI / API
- `docs/MissionControl.md` already reserves the slots: Detect → **Behavioral Detection**
  (`/detect/behavioral`), Investigate → the explanation envelope, Intelligence (HYDRA
  predictor/temporal) for fleet-level prediction, Network → Device Trust for per-device genome
  status, Administration → AI Models for provenance/retention.
- `hookprobe-api` is GET-only and is the contract `mcserve` implements: add
  `/api/behaviour/entities`, `/api/behaviour/entities/{id}` (genome summary + state), fold BOI
  rows into `/api/detections` and `poll_since` for SSE. The `/api/engines` "Behavioral" row
  becomes `real_engine_entry` backed by a status file / `McState` render.
- On heqk `http.rs` is a hard-coded route match with no publish hook: a BOI render needs a new
  `McState` renderer + route arm (same as every other state). Adjudication ("this is expected
  / this is not") is a **write** → a separate service/port per ADR 0025 D4, RBAC verb
  `annotate`/`investigate`; it becomes a signed `adjudication` node (ADR 0014 D4) and the only
  human label source.

## 4. What it buys HookProbe (benefits, specific to this product)

1. **Memory for the Observe tier.** Today every behavioural table is a ≤10-minute window and
   nothing survives a reboot except 64 detection images. HBG gives the sensor a persistent,
   bounded notion of "normal for *this* device/user", which is what the Observe tier lacks to
   be useful rather than noisy.
2. **Evidence-based admission instead of "unknown = quarantine".** The bench this week was
   blocked by exactly the posture HBG replaces: the fortress NAC quarantined an unknown MAC
   outright. A device genome (Novel → Emerging → Established on independent days) lets the
   NAC *suggest* admission with evidence and confidence — still operator-confirmed, still
   inside ADR 0018/0022 anti-spoof rules — and lets Mission Control explain *why* a device is
   where it is.
3. **Alert fatigue down without allowlists.** "Novel" is an observation with a confidence,
   not an alert; "Established" suppresses by evidence, not by a static list; "Dormant
   reactivated" is the one state a static allowlist can never express.
4. **Fits the budgets by construction.** The compact-signature/delta design is not an
   optimisation — it is the only thing that fits a 16 KiB sealed window, a ≤352-B sealed
   record and a 4-frame heartbeat export budget. The proposal and the hardware agree.
5. **Poisoning resistance for free.** The signed-policy-with-gen-floor pattern and the
   "state, not logic" split mean an attacker who behaves can only create evidence; nothing
   they do rewrites priors, thresholds or policy, and nothing accepted from the fleet is
   trusted without an independent signature.
6. **The training corpus ADR 0014 D2 asks for.** Long-term DNA plus adjudication nodes are
   precisely the labelled, provenance-carrying corpus for *off-device* training of the
   prediction models — closing the "no labels" problem in the lifecycle without on-device
   training.
7. **Hierarchy maps onto the evidence graph.** User / device / segment / tenant / fleet are
   existing node kinds; deviation-at-scale ("device abnormal on a normal segment") is a
   `REACH_CTE`-style query, not a new store.
8. **SASE context, for real.** The AP/NAT path now sees per-client flows with lease-bound
   identity; VPN/office/travel/off-hours contexts are the `ctx` byte on every observation —
   the "same user, different context, not a contradiction" principle costs one histogram.

## 5. What it must NOT do (so it stays HookProbe)

- Never drop a frame, never add a drop class, never feed `decide()`; never produce a `Direct`
  posture signal; never auto-promote to allowlist/policy.
- Never train detection logic on the device; never let a prediction become its own evidence
  (calibrate only against observations and adjudications).
- Never store browsing history as long-term DNA (classes and relationships only); never key
  on raw MAC/IP; never require cloud or an account.
- Never report "predictive" until the Phase 6 gate passes; never show mock engine status as
  real.

## 6. Phasing — mapped to the repo's gates (QEMU/host first, flash last)

| Phase | Deliverable | Where | Gate (no flash) | Metal check |
|---|---|---|---|---|
| 0 | **ADR 0048** (next free number): C1–C9 resolutions, privacy/profiling stance, licensing boundary, token `boi`, band 1_300_000, four-concern vocabulary (Observation/Memory/Prediction/Deviation + Decision untouched) | `docs/adr/0048-*.md` (product-steward) | docs gate | — |
| 1 | **HBG event contract**: `Obs` record + sessionised observation ring in heqk; dst/port added to NAT entries; the same record ingested by `hookprobe-evidence` | `kernel/heqk/kernel/src/hbg/obs.rs` (new), `packet.rs`, `nat.rs`; evidence crate | new `[P-hbg-obs]`: 5-tuple + bytes + ctx captured for a synthetic flow set; overruns counted | heartbeat shows `obs=`, `:0` ports gone in MC |
| 2 | **BSIG codec + delta** as a pure `no_std` crate linked via `#[path]` by kernel, responder-sim and evidence; host KAT with golden vectors | `kernel/heqk/kernel/src/hbgwire.rs` | host harness `tools/hbg-kat.rs` (Stage-1 hard gate like the crypto KAT) | — |
| 3 | **Three temporal layers** as bounded state + integer Bayesian recurrence + decay + the four states; deterministic replay of the proposal's test list (09–17 routine, VPN/non-VPN, one new site, repeated visits on independent days, unusual sequence, dormant) under a synthetic clock | `hbg/genome.rs` | new `[P-hbg-layers]` asserting the exact transitions + that 3 visits in 3 minutes ≠ 3 weeks | — |
| 4 | **Persistence + export + UI**: `fslog` `RT_HBG` records under a BOI VEK; HQXR `REC_BSIG_DELTA`; evidence tables + edges; `/api/behaviour/*`; Detect → Behavioral page; engines row real | `fslog.rs`, `export.rs`, `exportwire.rs`, `http.rs`/`mcstate.rs`, evidence, ui | `[P-hbg-persist]` (p15-write two-boot), `[P-m6-export]` extended, `mc-e2e` | genome survives a power-cycle; delta seen in sim JSONL; **needs the DataVolume partition** |
| 5 | **Novelty detection** → Behavioral detections 1_300_001–004 + corroboration axis; adjudication service (separate port, RBAC) | `rules.rs`, `corroboration.rs`, new service | `[P-hbg-novelty]`: novel fires once, established suppresses, dormant-reactivated fires; wire verdict always PASS (separation matrix row added) | `[SEPDIAG-HBG]` self-test; zero legit drops |
| 6 | **Prediction** — off-device first (Markov transition model in the evidence crate, then LSTM trained off-device, signed, model-carded); on-device inference only as a signed `no_std` module where `ml_cpu` is granted; calibration against adjudications; then and only then the Readme text changes | evidence crate; `el0-wasmhost` module | `[P-hbg-predict]`: surprise score A_t = −log P, calibration curve from a held-out replay | advisory only on metal |
| 7 | **Distributed correlation**: inbound genome updates via the operator-signed/gen-floor pattern; fleet-level DNA (commercial boundary) | `enroll.rs` pattern | `[P-hbg-sync]`: tampered/stale/wrong-tenant updates refused, state unchanged | two nodes, one tenant |

Metrics (the proposal's list, each tied to a gate): detection latency (Phase 5), false-positive
rate on the replay set (Phase 3/5), baseline adaptation time in active-days (Phase 3), storage
per entity and total (Phase 4, shown in `/api/evidence/stats`), bytes per DNA update (Phase 4,
from `Tracker`), calibration error (Phase 6).

## 7. Proposed ADR 0048 skeleton (for product-steward to cut)

**Title:** Behavioural Observation & Intelligence (BOI) as an optional signed module; the
HookProbe Behavioural Genome (HBG) as on-device state, never on-device policy.
**Decisions:** D1 four concerns + decision untouched; D2 state/logic split (resolves ADR 0014
D1); D3 observe-only + one corroboration axis, no posture `Direct` (ADR 0023/0038); D4
privacy & minimisation stance (first in V2); D5 persistence on the sealed DataVolume, bounded
and shown; D6 transport = M6 HQXR deltas, inbound = operator-signed gen-floor pattern; D7
module = catalogue-signed, `provides: boi`, `requires: soc [+ml_cpu|edge_ai]`; D8 prediction
is [vision] behind a gate, Readme text follows the gate; D9 licensing boundary (AGPL core,
commercial trained weights/fleet learning). **Consequences:** `Readme.md` honesty text and
`MissionControl.md` Behavioral section updated when phases land; `retirement-agent` tracks V1
behaviour_clustering/LSTM as superseded, not ported.
