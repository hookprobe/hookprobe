# BOI / HBG — adversarial architecture review (input to ADR 0048), 2026-11-05

> **Read-only review. No implementation code was modified. No existing ADR is relaxed.**
> Scope: the seven questions the operator's reviewer asked of
> `heqk-boi-hbg-alignment-2026-11-05.md`, each answered against the actual source, ADR text,
> primitives and gates in this worktree (HEAD `1c1594c`). Three review tracks ran in parallel
> (transport + fleet trust · persistence + prod-loop determinism · identity + ADR 0014 text +
> privacy/licensing); every finding below carries a `file:line` citation from them. Where the
> alignment doc was **wrong**, this document says so (§9) — the alignment doc is not amended in
> place, so the correction trail stays visible for ADR 0048.
>
> **Governing principle (operator):** *an attacker may influence what heqk OBSERVES, but must
> never be able to redefine what heqk TRUSTS.*

## 0. Verdict

| Area | Verdict | One-line reason |
|---|---|---|
| Q1 M6 delta transport | **Reuse — conditional** | Fire-and-forget with honest loss counters (`export.rs:207-216`, no ack anywhere in `responder-sim/src/main.rs:262-279`). Deltas must be **absolute, versioned, idempotent** records in a **new frame family** with its own budget; increments would diverge silently. |
| Q2 Signed-policy pattern for evidence | **Adapt — the alignment doc's "reuse verbatim" is wrong** | `apply_reach_policy` proves *operator authority* (`enroll.rs:456-463, 586-604`); nobody can sign what a node *observed*. Remote evidence must be inert w.r.t. local state (no code path), with three trust levels. |
| Q3 Persistence | **Validate — two production defects found first** | prodfull snapshot never restores on `prod-mc` metal (F1, metal-evidenced) and its multi-sector write is not crash-consistent (F2). fslog is record-atomic only. Capacity numbers in the alignment doc were wrong; corrected in §4. |
| Q4 Entity identity | **Refine — the claimed primitive does not exist** | `fingerprint.rs` yields a *class*, not an id (`DeviceProfile`, `:108-117`); the heqk AP parses no DHCP opt 12/55/60 (`cyw43.rs:3113-3141`); every existing id is a raw/reversible MAC or IP. |
| Q5 ADR 0014 compliance | **Sound — with a precise boundary** | Statistics are *state* on D1's own terms; the alignment doc's boundary wording was too broad (it would condemn `behavioral.rs`). Empirical Bayes, adaptive thresholds and on-device calibration are **training** and are forbidden. |
| Q6 Privacy + licensing | **Specify — ADR required; legal items are not code's** | "Hashed FQDN" ≠ anonymisation; the BOI VEK / tenant label the doc described does not exist (`fslog.rs:589`, `seal.rs:66-72`); per-entity deletion by rotation is impossible with one VEK; `kernel/heqk/SECURITY.md:461` already publishes "No behavioral profiling of individuals". |
| Q7 Bounded + deterministic on CM5 | **Yes, as a `no_std` step in the drained branch — not as a per-heartbeat Wasm module** | Three concrete blockers to per-heartbeat Wasm (VA conflict with the GEM pages, 712 KiB frame leak per load, non-re-entrant host); the GEM ring already overflows on metal (`rsr=0x7` on 368 heartbeat samples) and `faults=0` cannot see it. |

**Recommendation: proceed with ADR 0048; no implementation.** The architecture is compatible and reuses real primitives, but five claims in the alignment doc must be corrected in the ADR (§9), two pre-existing persistence defects must be fixed independently of BOI (§4 F1/F2), and the entity-identity and privacy designs must be rewritten against what actually exists.

---

## 1. Q1 — the M6 export plane for HBG deltas

Evidence base: `kernel/src/export.rs` (queue 64 `:111`; `seal_next` advances on seal `:207-209`; `tx_failed` only counts `:213-216`), `exportwire.rs` (v2: `MAX_EVENTS=16`, `MAX_FRAME=424`, `Tracker` `:213-256`), `main.rs:1970-2056` (4 frames/heartbeat `:1999`, export runs *before* the single SOAR drain), `securechannel.rs:754-846` (explicit-seq `seal_record`, RFC 6479 window of 448, **no rekey**), `responder-sim/src/{export_rx.rs,main.rs}`.

Ranked findings:
- **H1 — no loss recovery.** Lost detection = one missing, *counted* row. A lost *increment* delta = a receiver genome that is wrong, compounding, and the gap counter cannot say which entity. An on-path attacker can drop only "Dormant" transitions. → deltas must be **absolute versioned state assertions** (idempotent last-writer-wins) plus a **rolling snapshot cursor**.
- **H2 — reordered/late frames are accepted** (`exportwire.rs:250-256`; `[P-m6-export]` treats "B arrives late and is accepted" as correct, `export.rs:357`). Right for detections, wrong for state: apply a record only if `(genome_epoch, rec_version)` is newer.
- **H3 — a shared queue/budget starves detections.** A full 64-record genome snapshot costs ~13 v2 frames ≈ 3.25 heartbeats of the *entire* 4-frame budget; an attacker churning novel destinations fills the shared queue and then attacks while detections are dropped. → BSIG gets **no FIFO**: a dirty bitmap over the genome table + round-robin snapshot cursor (coalesces by construction), ≤ 1 frame/heartbeat, never one of the 4 detection frames while the detection queue is non-empty.
- **H4 — BSIG inside a v2 frame would be ingested as fake detections.** `parse` checks only magic/version/length (`exportwire.rs:153-186`); `frame_to_jsonl` turns every record into `heqk_detection` (`export_rx.rs:75-98`). → **new frame family**: magic `HQB1`, AEAD AD `HQB1-bsig`, datagram tag `HQXB` (leading `"HQ"` keeps the handshake-chunk demux property, `exportwire.rs:39-43`), own `BsigTracker`; v2 stays byte-identical.
- **M1 — per-boot Tracker semantics are wrong for persisted state** → persisted `genome_epoch` (changes only on wipe/key rotation) + monotonic `rec_version`; `boots` stays transport metadata.
- **M2 — no rekey; session key lives until the next reboot** (weeks–months). Profiling data under one long-lived key. → Noise rekey / forced re-handshake ≤ 24 h before BSIG export ships; BSIG uses `seal_record` only, never `encrypt_into`.
- **M3 — enrolment is not consent to export profiling data** (`should_export` = `Enrolled`, `export.rs:78-80`) → `should_export_bsig = Enrolled ∧ operator-signed opt-in`.
- **L1 — the alignment doc's rule band cannot ride the wire**: `rule_id` is `u16` (`events.rs:59`, `exportwire.rs:53`) → max operator id 1_265_535. BOI ids must live in the 1_2xx_xxx band or the BOI record carries an explicit band field.
- **L2 — sizing ambiguity**: 56 B is per *(entity, destination-class)* record, so "64 entities ≈ 3.6 KiB" means 64 *records*.

Acceptance / failure (E1–E11):

| # | Acceptance | Failure | Gate |
|---|---|---|---|
| E1 | v2 detection frame (`HQX1`/v2, `HQX2-export`, `HQXR`) byte-identical before/after BOI | any change to v2 layout/`Rec`/AD/Tracker | existing `export_rx.rs` goldens + `[P-m6-export]` |
| E2 | a BSIG datagram never parses as a detection on any receiver | `HQXB` record opens under `HQX2-export`, or `exportwire::parse` accepts BSIG plaintext | host `bsig_never_opens_or_parses_as_detection` |
| E3 | detections never starved: BSIG saturated → detection `lost`/`gap_events` identical to a BSIG-off run | any extra detection loss attributable to BSIG | `[P-hbg-export-starve]` |
| E4 | BSIG never uses/advances the detection `ev_seq` space or `Exporter.lost` | `first_ev_seq` gaps caused by BSIG | part of E3 |
| E5 | **convergence**: a receiver missing any set of frames matches the sender byte-for-byte within 2 sweeps | divergence past 2 sweeps; any record depending on an earlier frame | `[P-hbg-converge]` (random 30 % / burst 100 / every-other) |
| E6 | late/replayed-in-window frame counted, never applied over a newer `(epoch, rec_version)` | state regresses after reorder | host `bsig_late_frame_does_not_regress_state` |
| E7 | applying an accepted frame N times == once | double-apply changes state | host `bsig_apply_idempotent` |
| E8 | wipe/key rotation bumps `genome_epoch`; receiver drops the old epoch and reports `genome_reset` | old-epoch records survive | E5 epoch leg |
| E9 | zero `HQXB` unless enrolled **and** operator-signed opt-in | any `HQXB` without opt-in | `[P-m6-export]` air-gap leg + `[P-hbg-optin]` |
| E10 | rekey/re-handshake ≤ T (≤ 24 h proposed); `seal_record` only | one key carries BSIG > T | `[P-hbg-rekey]` |
| E11 | N emissions grow the heap by 0 | heap growth | extend `heap_stability_check` (`export.rs:483-510`) |

## 2. Q2 — behavioural evidence vs operator-signed policy

Evidence base: `enroll.rs:245-655` (`apply_reach_policy`: sig → tenant C14 → gen > floor C11; floor persisted *after* apply `:604,651`; TOFU first-write-wins `:550-569`; raw `body‖device_fp` signed message `:356-361`), `corroboration.rs` (16 slots, collision-evict `:49,78-89`; severity only `:8-23`), `hydra/verdict.rs:28-38`, `trust.rs:36-39,62-63,138-147,354-357`, `heqk-detection-parity.md` §5 (A9-4, A11), `responder-sim/src/main.rs:336-350`.

Ranked findings:
- **C1 (Critical, design) — "reuse `apply_reach_policy` verbatim" conflates authority with truth.** A compromised but validly enrolled node streams correctly sealed records saying "malicious X is Established for E"; AEAD, window, tenant and fp all pass. *Authenticated and false.* → split the pattern: **operator-signed** for logic (priors, decay, thresholds, weights, opt-in bits, allowlist/"expected" promotion); **channel-authenticated node evidence** lands in a separate fleet-evidence store with **no write path into any node's local genome**.
- **H1 — the receiver takes `device_fp` from the device's own msg1 payload, zero on bad length** (`responder-sim/src/main.rs:341-347`); nobody checks `device_fp == sha256(authenticated static)`. Node A can claim B's fp. → receiver computes fp from the static key, refuses disagreement, never defaults to zero, accepts a node's records only for its own fp.
- **H2 — `PostureSignal` defaults to `Direct`** (`trust.rs:36-39`, `#[serde(default)]` `:62-63`) and trusts `corroborated` verbatim (`:354-357`): a careless BOI→posture bridge quarantines on one poisoned `context_shift`. → `SignalProvenance::Behavioral` capped at `StepUp`; structural barrier: the BOI crate must not depend on `hookprobe-manifest::trust` (CI edge check).
- **H3 — entity identity is attacker-assertable** (MAC + DHCP options are client-chosen) — the A11 "shared forgeable trust root" again. → BOI outputs are severity + explanation only; "Established" may lower **only BOI's own** novelty rules, never another family, never a corroboration axis; NAC "suggest admission" is `(MAC, port)`-scoped and operator-confirmed with the ingress port shown (A9-4, non-negotiable).
- **H4 — fleet aggregation launders poison into "operator-signed" logic.** A signature proves authority, not truth (the HYDRA lesson one layer down). → a fleet prior is signable only after ≥ K distinct contributing nodes (distinct fp **and** tenant/site), per-node weight ≤ 1/K, provenance count in the signed body; on-device a fleet prior may only *raise* sensitivity; suppression needs an explicit `(entity, dst_class)`-scoped operator allowlist entry.
- **M1 — baseline poisoning by behaving.** Active-days slow an attacker, they don't stop one. → any reputation/IOC hit pins a destination at ≤ Emerging (`AXIS_REPUTATION` is the one axis an attacker cannot frame onto a victim, `corroboration.rs:31-35`); every transition to Established is itself an Observe event; per-entity promotion rate cap.
- **M2 — gen-floor/key details before reuse for priors**: persist-before-adopt (not-adopting a prior is harmless, unlike stranding a device); context prefix `"HEQK-BOI-PRIORS-v1"‖body‖fp‖tenant`; distinct operator sub-key/role; no key rotation exists (`enroll.rs:552`) — documented residual.
- **L1 — `AXIS_BEHAVIOUR` acceptable** (severity only); the 16-slot table evicts on collision, size per platform.

Three trust levels — accepted, with one constraint each:

| Level | Proven by | Allowed effect |
|---|---|---|
| Authenticated | AEAD + window + receiver-computed `sha256(static)` = fp + tenant | stored in the fleet-evidence store attributed to (tenant, fp); no effect on any node |
| Validated | schema/magic/AD; record scope = sender's own fp **and** tenant; `rec_version` monotonic; `active_days` popcount non-decreasing within an epoch except by decay; `last_seen ≥ first_seen` ≤ rx + skew; rate ≤ R/heartbeat; transitions legal under the signed state machine | shown in the fleet view as "reported by node" |
| Corroborated | ≥ K independent nodes/sites, each ≤ 1/K | may be an **input** to an operator-signed fleet-prior artifact; never applied directly |

None of the three lets a remote record write local state — enforced by the absence of a code path, not by a policy that asks it not to.

| # | Acceptance | Failure | Gate |
|---|---|---|---|
| T1 | no remote input moves any entity's **local** state or counters | any local genome byte changes on remote input | `[P-hbg-remote-inert]`: 10k validated remote records → `sha256(local)` unchanged |
| T2 | tampered / stale / wrong-tenant / wrong-fp / below-window record → **all** state byte-identical incl. the fleet store | any mutation on a rejected record | `[P-hbg-sync]` with before/after hashes |
| T3 | records accepted only for the receiver-computed fp | another fp accepted; payload1 ≠ sha256(static) accepted; zero default | host `export_rx_binds_fp_to_static_not_payload` |
| T4 | no BOI output reaches `decide()`, `set_reach`, `set_port_role`, or a `PostureSignal` ≠ `Behavioral`; `Behavioral` caps at `StepUp` | any such path; `Behavioral` yields `Quarantine` | CI `boi-no-enforcement-edges` + `behavioral_never_quarantines` |
| T5 | BOI detections are `Behavioral` → `Observe`; wire PASS in every BOI separation-matrix row | any BOI row RateLimit/FrameDrop/Quarantine | `0.7-separation-matrix` rows + `[P-hbg-novelty]` |
| T6 | Established lowers only BOI's own rule ids | another family's severity differs with/without Established | `[P-hbg-novelty]` cross-family leg |
| T7 | IOC-hit destination never reaches Established; every Established transition emits Observe | silent Established | `[P-hbg-layers]` K-day walk |
| T8 | fleet prior applied only if operator-signed (pinned BOI key, context-prefixed), tenant-bound, gen > floor, **floor persisted before adoption** | adoption with unpersisted floor; inline MSSP key; cross-domain verify | `[P-hbg-priors]` |
| T9 | fleet priors carry ≥ K / 1/K provenance; on-device only raise sensitivity; suppression needs a scoped allowlist entry | one node moves a prior > 1/K; prior lowers novelty without allowlist | aggregator `single_node_cannot_launder` + `[P-hbg-priors]` |
| T10 | NAC use is suggestion-only, `(MAC, port)`-scoped, operator-confirmed, ingress port shown | any auto-admit/auto-allowlist | `[P-hbg-novelty]` + `mc-e2e` |

## 3. Q4 — entity identity

Findings (all cited): `fingerprint.rs` outputs a class (13 variants, `:40-54`, struct `:108-117`), no id; its stated precedence (`:10`) is not what the code does (sort by confidence, `:171`); every input is self-asserted plaintext (`:21-36`); NAC `identity` is free text from intent YAML (`nac.rs:118-119`) and enforcement is by MAC (`:252-278`); the heqk AP `parse_client_dhcp` reads only opt 53/50 (`cyw43.rs:3113-3141`); leases keyed on raw MAC (`:3003-3050`); `ratelimit::mac_hash` is a reversible packing, not a hash (`:115-121`), and the exported `src_mac_hash` is the raw first 4 MAC octets (`events.rs:26-28`, `export_rx.rs:81`); evidence `dev:` ids are unkeyed FNV over raw IP with no tenant (`lib.rs:140-150, 917`); Wi-Fi gives no per-device credential (shared PMK, `wpa.rs:147`; PTK ephemeral; no EAP) — the one feasible clone-resistant anchor is **per-device PSK (PPSK)**, which the host-side 4-way (`cyw43.rs:3398`, `wpa_mic_sha1`) could trial against cached PMKs.

Scenarios: (i) clone MAC + DHCP signature → inherits the victim's Established genome and reach policy — **fails**; (ii) MAC randomisation forks the genome per join, while class-level signals *merge* different same-model devices — **fails stability and correctness**; (iii) identical fingerprints across tenants + colliding RFC1918 ids — **fails scoping**; `Obs.ent:u32` collides fleet-wide around 2^16 entities.

Required identity: `K_ent = HKDF(K_hbg sealed under SRK, "HBG-ENT-v1" ‖ tenant)`; `ent = Trunc128(HMAC-SHA256(K_ent, "ENT" ‖ segment ‖ anchor_kind ‖ anchor))` (primitives exist: `boot-abi/src/kdf.rs:18-62`); anchors ranked A3 credential (PPSK/EAP) > A2 universal MAC > A1 locally-administered MAC > A0 fingerprint tuple (**hint only, never an anchor**); PSK/PMK is never identity. Corroboration before a weaker anchor inherits a genome: (a) credential continuity, (b) non-overlapping handover with identical A0 tuple on the same BSS/port — simultaneous presence = clone conflict → both Novel + `entity_genome_reset`, or (c) a signed adjudication.

| # | Acceptance | Gate |
|---|---|---|
| A4.1 | no persisted/exported HBG record contains a raw MAC, raw IP, or reversible packing as entity key | byte-scan + grep-gate (`mac_hash`/`src_ip` never flow into the key) |
| A4.2 | `ent` = HMAC-SHA256 under tenant-scoped `K_ent`, segment included, ≥ 128 bit off-device | KAT: same anchor, different tenant/segment → different `ent` |
| A4.3 | two tenants with identical fingerprints/MACs/IPs → disjoint entity sets | evidence test, overlapping 10.x |
| A4.4 | cloned A0 + A1/A2 inherits nothing without (a)/(b)/(c) | `[P-hbg-clone]`: clone's first C2 contact fires `novel_destination`; simultaneous presence → reset + both Novel |
| A4.5 | rotating locally-administered MAC keeps one genome only via (a)/(b); otherwise forks honestly and surfaces it | handover replay |
| A4.6 | records carry `anchor_strength`; severity/axis weight capped by it | unit: A1 entity's axis never counts as Direct |
| A4.7 | heqk DHCP opt 12/55/60/61 parsing is bounded, fuzzed, observe-only | fuzz/KAT on `parse_client_dhcp`; separation row |

Failure: any raw/reversible/unkeyed key; A0 as anchor; no tenant+segment scope; inheritance without corroboration; clone conflict undetected; PSK as identity; the "already parses" claim carried into the ADR.

## 4. Q3 — persistence (with two production defects found first)

**Pre-existing defects — not BOI's, must be fixed regardless (reported to the owner session):**
- **F1 (HIGH, metal-evidenced): the `prod-mc` snapshot never restores across reboot.** `cm5_p15_block_seal()` runs unconditionally under `hboot` (`main.rs:587-588`) and with `p15-write` writes a 144-B sealed Event at LBA 2016 every boot (`:3866-3945`, `store.rs:384-385` always starts at `guard.lo`); `ProdFull::init` then reads 2016 and finds a non-snapshot blob. `~/heqk-metal-logs/20261104-prod-mc-serial.log:2543,2577,3995,4029`: `sealed+stored=true` → `[PROD-FULL] M3: … not a v1/v2 snapshot — starting fresh`, `boots=1` on every persisted line.
- **F2 (HIGH): the multi-sector snapshot write is in-place and not crash-consistent.** `SealedStore::store` writes 2016,2017,2018 sequentially (`store.rs:384-413`), no A/B, no commit marker; a power loss after the first sector leaves new header + old tail → HMAC fails → the *previous* state is destroyed ("starting fresh", `prodfull.rs:147-150`).
- **F4 (HIGH): the segmetal 16-sector slice is not usable by BOI** — it holds the reach floor ring (`main.rs:2222-2224`); eviction by BOI appends would drop the floor to 0 and lose C11 anti-rollback (`enroll.rs:498-513`).
- **F5 (MED): the sepdiag DataVolume self-test writes outside every partition on the factory layout** (`main.rs:3958-3970` hard-codes LBA 16,777,216; p2 is 139,264..1,048,576 per `builder/make-cm5-heqk-disk.sh:147-149`; runs on every prod-mc boot, log `:2544,3996`).

fslog facts: record-atomic only (one 512-B CMD24, `emmc.rs:383-400`; no CMD25), records never span sectors (`MAX_PAYLOAD=480`), superblock written only at format (`fslog.rs:449`), recovery = seq + 8-B digest + ring placement + HMAC when sealed; **no** generation/commit/dual-slot. `[P15-fs]` torn injection corrupts a byte of a *whole* sector (proves digest detection, not a partially-programmed sector). `[P15-abcommit]` proves ordered whole-sector writes with a commit point and boot-time repair *between* writes (`abboot.rs:152-166, 226-300`; metal `20261104-abcommit-metal-PASS-c748cf0.log`) — the usable pattern.

**Corrected capacity (replaces alignment §3.2):** the factory image already carries a 0xDA DataVolume of ≈ 444 MiB (`make-cm5-heqk-disk.sh:9-11,147-149`; `[SEGMETAL] home=DataVolume-partition(0xDA)`), so "the dedicated partition is the prerequisite" is **stale** — the prerequisite is a **sub-allocation + region registry** (today `main.rs:2222` and `:3966` pick LBAs ad hoc). Sealed record payload ≤ 352 B → **6 × 56-B records per sector**; a 64-record genome = 11 records + BSIG (≤ 352 B or 2 chunks) + 1 commit = 14 slots; crash-consistency needs two complete generations resident → **29 sectors → allocate 32 (16 KiB) of p2**. RAM 64 × 56 = 3,584 B.

Keystore map (32 sectors, 2016..2047): 2016-2018 snapshot blob (and the colliding sepdiag blob at 2016); 2019-2023 free (blob headroom to 8 sectors); 2024 VEK (never written on a cm5 prod path today); **2025-2039 free (15)**; 2040 boot cookie; 2041-2043 free; 2044 OTA (opt-in); 2045-2047 free.

Wear: steady state ≤ 288 persists/day × 3 sectors = ≤ 864 sector-writes/day to 2016-2018; a naive BOI persist of 11-14 records/300 s adds ≤ 4,032/day — dirty-per-record delta persist is the lever. **No eMMC endurance number exists in-tree** (grep over all docs/ADRs/kernel: nothing) and none is invented here; instead require exported counters and decode EXT_CSD[267..269] (`PRE_EOL_INFO`, `DEVICE_LIFE_TIME_EST`) at probe — the driver already reads EXT_CSD (`emmc.rs:165-178`).

| # | Acceptance | Failure | Gate |
|---|---|---|---|
| A3.1 | two-boot: gen g written, g+1 with an injected torn record at **every** member/commit boundary → boot 2 loads g intact when g+1 incomplete, g+1 when complete | any boundary yields "no genome" or mixed-gen; "starting fresh" with a prior complete gen | `[P-hbg-persist]` (virtio-blk, then CM5) |
| A3.2 | BOI records in a sub-region of the 0xDA partition from `datavolume_from_mbr`, registered in one region registry; floor region untouched | hard-coded LBA; append into `[p2.lo, p2.lo+16)`; floor regresses | region-registry test + `[SEGMETAL]` |
| A3.3 | F1/F2 fixed (or BOI never uses the keystore blob path): `boots=N+1` across a real power cycle on prod-mc | `boots=1` after reboot; "not a v1/v2 snapshot" after a prior persist | metal prod-mc |
| A3.4 | compile-time capacity constants reported (`N_ENT=64`, 6/record, 11+2+1 per gen, 2 gens ≥ 29 sectors); doc restated | doc still claims 16 sectors / 64 entities + 512-B BSIG in one record | docs gate |
| A3.5 | writes/day bounded (delta-only persist) and exported: `persist_ok/fail`, `sectors_written`, `boi_sectors_written`; EXT_CSD[267..269] exported | no counters; BOI persist every heartbeat | heartbeat + `/api` |
| A3.6 | BSIG ≤ 352 B or chunked under one gen + commit; sealed under a BOI-label VEK seeded from `rng200` on metal | BSIG via `SealedStore::store` (F2 path) or unsealed | `[P-hbg-persist]` |

## 5. Q5 — ADR 0014 compliance (the exact boundary)

ADR 0014 D1 (`:19-32`) forbids self-training *"in the enforcement path"* for four reasons (C9, explainability, trust-nothing-unsigned, poisoning); D4 (`:64-70`) labels only via adjudication/corroboration; D5 cold-start; D6.3 "never taken from the device's own fast-path number"; ADR 0038 D2 "the enforcement path carries no model weights", D5 models off-device, signed, attested; ADR 0023 D4 behavioural detectors have no enforcement consumer by design; ADR 0025 D1 C9 by type.

Evaluation: with a fixed model family, fixed priors and a closed-form bounded fold, counters / active-day bitmaps / histograms / Welford / a fixed-prior posterior are **sufficient statistics of past observations** — the same class `behavioral.rs` already keeps (16 × 8 timestamp rings against compile-time constants, `:76-92`). On D1's own terms: no weights rewritten; verdicts trace to a fixed versioned table + human-readable, replay-reproducible state; nothing unsigned produced. **Poisoning is not answered by determinism** — see T7/A5.7.

The alignment doc's boundary ("anything that changes how a future observation is scored is logic") is **too broad** — every baseline does that; it would ban `behavioral.rs`. The precise boundary:

> **Logic θ** = the scoring function and every constant it takes that is *not* computed from this device's observations (priors, decay, thresholds, transition rules, caps, model weights, category maps) — signed, digest-pinned, model-carded, immutable on device.
> **State S** = per-entity values computed only by a θ-fixed, closed-form, bounded fold over **that entity's own** observations (plus signed adjudications scoped to it).
> **Training** = any process in which θ, or a value used in place of θ, becomes a function of observations.
> **Test:** two devices with the same θ digest replaying the same observation sequence from empty state produce bit-identical S and verdicts; no byte of θ is writable on device except from a verified signed artifact.

Rulings ADR 0048 must make: posterior-as-confidence allowed only with the prior in θ and never updated from other entities — **empirical Bayes is training**; adaptive thresholds / adaptive decay / on-device Platt-isotonic calibration are **training**; per-entity Markov counts allowed as S only with family/order/smoothing in θ and no cross-entity sharing (cross-entity models trained off-device); adjudication may move S by fiat only when signed and scoped; BOI's own detections/predictions never feed `fold`; Established suppresses **only** BOI's novelty rules, promotion needs ≥ N independent active days (θ) + a rate cap, every promotion is an exported Observe event, and the deterministic beacon rule still fires on a slow-burn C2 regardless of HBG state. Type-level C9 (the ADR 0025 D1 analogue): `ScoringTable` constructible only `from_verified_blob`; `fold(&ScoringTable, &mut EntityState, &Obs)` / `score(&ScoringTable, &EntityState, &Obs) -> Finding`; `EntityState` has no field a threshold could live in; no `&mut ScoringTable` escapes; `decide()` does not import the crate.

| # | Acceptance | Gate |
|---|---|---|
| A5.1 | all scoring parameters in one signed, digest-pinned, model-carded `ScoringTable`; digest in every finding's envelope | host KAT + tampered-table refusal |
| A5.2 | replay determinism across runs/devices/platforms (bit-identical S and verdicts) | `[P-hbg-layers]` goldens, host + QEMU |
| A5.3 | arbitrary (fuzzed) S never changes θ's digest; replay from empty after a state diff gives the same verdict | fuzz |
| A5.4 | type-level separation (no public ctor but `from_verified_blob`; no `&mut ScoringTable`; `EntityState` = counts/bitmaps/histograms/Q16/timestamps only) | compile-fail tests + grep-gate |
| A5.5 | no cross-entity parameter estimation on device | unit: B's score independent of A's history |
| A5.6 | only signed adjudications move S by fiat; BOI output fed back → state unchanged | feedback test |
| A5.7 | Established needs ≥ N active days + rate cap; suppresses only 1_2xx BOI ids; beacon still fires on slow-burn | `[P-hbg-novelty]` slow-burn |
| A5.8 | `decide()`/reach never read HBG; wire PASS always | `[SEPDIAG-HBG]`, separation matrix |
| A5.9 | cold start: empty S + baseline θ fully functional; nothing gates the device | boot-from-empty |

## 6. Q6 — privacy and licensing

Canon/code reality: `LICENSING.md:50-54` (commercial: trained weights, federated learning) and `kernel/heqk/LICENSING.md:69` (adds *training data*) vs **ADR 0007 `:11` "The OS stays OPEN (Apache-2.0)"** — a contradiction. Root `SECURITY.md` has no privacy text; **`kernel/heqk/SECURITY.md:393-515` publishes stale V1 claims** — "GDPR-compliant by design", MAC anonymisation, **"No behavioral profiling of individuals"** (`:461`), "NOT collected: browsing history" — citing `GDPR.md` / `gdpr-retention.sh` / `DPIA.pdf`, **none of which exist in the repo**. The V1 "model how targets are attacked, not what they browse" principle is uncited anywhere but the alignment doc — ADR 0048 adopts it as a *new* decision. Primitives: keyed HMAC-SHA256 + HKDF exist (`boot-abi/src/kdf.rs:18-62`; `seal.rs` labels); **no** labelled/BOI VEK (`fslog.rs:589-600`, one VEK at 2024 for all record types), **no** tenant in `seal::Policy` (`seal.rs:66-72`), SRK is synthetic until V3 (`seal.rs:16-20`), VEK entropy `cntpct‖SRK` "NOT hardware-grade" (`fslog.rs:543-547`), and **cross-boot nonce uniqueness is not guaranteed** (`seal.rs:162-168`) — keystream reuse is a real risk for records rewritten every heartbeat across reboots. With one VEK, **per-entity deletion by rotation is impossible** (rotating shreds everything; derived keys are re-derivable) — crypto-shredding needs random per-entity DEKs in a sealed keyslot table; eMMC FTL remanence [ext] needs an epoch folded into the key.

Reviewer's points, evaluated: (1) hashing ≠ anonymisation — correct; require `dst_id = Trunc128(HMAC-SHA256(K_dst_tenant, "HBG-DST-v1" ‖ eTLD+1-or-SNI))`, and call it **pseudonymisation** (device holds the key; protects exports/fleet/leaked volume, not a compromised device); per-tenant keys make destinations unlinkable across tenants, which **conflicts with Phase 7 fleet-level DNA** — ADR 0048 must choose a signed public category map or an explicitly opted-in fleet key with k-anonymity. (2) categories can be sensitive — correct; taxonomy = **attack-surface classes** (internal/same-segment/gateway/external-by-ASN-class/port-service class/known-bad/unclassified), shipped in θ, never content categories (GDPR Art. 9 [ext]). (3) long-term DNA holds entity → {surface class, port class, proto, direction, state, coarse first/last, active-day *count*}; `hour_hist[24]` and the 64-day bitmap are schedule data — on-device sealed only, coarsened (day-parts) on export, shown to the operator. (4) data ownership of fleet-derived information: CLAUDE.md's hard per-tenant isolation + ADR 0014 D5 opt-in vs the "training data is proprietary" claim — **code can tag provenance and enforce opt-in/revocation; it cannot settle ownership.** (5) the AGPL/commercial split for weights and datasets, controller/processor roles, lawful basis and DPIA are **operator/legal decisions** — ADR 0048 lists them as open, owned items, and asserts no legal conclusion as a code fact.

| # | Acceptance | Gate |
|---|---|---|
| A6.1 | no plaintext FQDN/URL/path/SNI/IP/MAC in any persisted or exported HBG record | byte-scan over sealed plaintext + JSONL against a seeded corpus |
| A6.2 | destination ids = HMAC-SHA256 under a tenant key from an SRK-sealed HBG key; unkeyed hashes rejected | KAT: two tenants → different ids; dictionary attack on an exported id fails |
| A6.3 | long-term DNA = attack-surface classes from a signed map; no content/special-category classes | schema test; map in θ |
| A6.4 | HBG key hierarchy: `K_hbg` (own sealed keyslot/label) → per-tenant HKDF → per-entity **random** DEK in a sealed keyslot table | `[P-hbg-persist]`; wrong label cannot open |
| A6.5 | deletion = record wipe + per-entity DEK destruction; other entities unaffected; FTL caveat documented or RPMB epoch | `[P-hbg-erase]` |
| A6.6 | cross-boot HQKSEAL1 nonce uniqueness **before** HBG persistence ships | N reboots × M seals → no repeated (key, nonce) |
| A6.7 | retention bounded, configurable, enforced on device and in evidence, shown in `/api/evidence/stats` | prune test |
| A6.8 | fleet contribution default-off; enabling = signed operator action; each delta carries tenant + opt-in epoch; revocation stops export | no `HQXB` with the flag off |
| A6.9 | AGPL core builds/runs with zero commercial artifacts; weights only as separate signed artifacts with a license field | standalone build gate; `cargo-deny` |
| A6.10 | `kernel/heqk/SECURITY.md:393-515` retracted/reconciled; ADR 0007 licence contradiction fixed; legal items listed as operator/legal-owned | docs honesty gate (ADR 0047 D4 tags) |

## 7. Q7 — bounded and deterministic on the CM5 production loop

Facts: `cm5_prod_service` is IRQs-off, no scheduler (`main.rs:1239`); WFE event stream ~19 µs (`:1241-1257`); heartbeat 5 s (`:1346-1349`); GEM ring `NRX=128` (`gem.rs:343`), `RX_BUDGET=64` (`:1339`); measured saturation 8.0–9.4k fps (`GAP_REGISTER.md:466-467`) → the ring fills in **13.6 ms** (86 µs at 64-B line rate). **The 2026-11-04 prod-mc log shows `rsr=0x7` (BNA|REC|OVR) on 368 of ≈1,310 heartbeat samples with `faults=0` throughout** — ring overflow is invisible to `seen/dropped/faults`. Heartbeat work that already blocks: PL011 kprint (a ~115-char line ≈ 10 ms at 115200, `uart.rs:50-62`), the ≤64 event drain, ≤4 export frames, the eMMC PIO persist (unmeasured). Toolchain: `aarch64-unknown-none-softfloat` compiles `f32/f64` as soft-float calls (`.cargo/config.toml:3`); the kernel has `extern crate alloc` over a 1 MiB bump allocator whose `dealloc` is a no-op (`heap.rs:10,58`) — any per-step allocation is a permanent leak. **Neither "no float" nor "no alloc" is enforced; both must be gated.**

Per-heartbeat Wasm step — **not possible today** (F6): (i) the `syncabi` host at `0x1_4000_0000` (`link-cm5.ld:10`) overlaps the prod GEM driver's pages at `base+0/0x1000/0x3000` (`main.rs:1271-1276`) and unmaps `base..foot_top` on exit (`:1137-1138`); (ii) `load_el0_wasmhost_cm5` leaks ≈ 712 KiB per load from a bump pool with no free (`mmu_cm5.rs:396-410`) → pool exhausted in ≈ 15 min at one load per heartbeat; (iii) the host is non-re-entrant (`_start -> !`, monotonic bump heap, one-u32 return, `el0-wasmhost/src/main.rs:86-165`); excursion time is not measured anywhere.

Realistic first shape: a `no_std` `boi.rs` with static fixed-size tables (the `segment.rs:98-105` / `behavioral.rs:89-92` pattern), fed by an **Obs ring** the per-packet path only *enqueues* into; the step runs in the **drained branch** (NAPI loop exited with `batch < RX_BUDGET`, `main.rs:2148-2397`) as a sliced pass of K entities per call — off the ring-fill critical window; persist separately throttled and staggered from the snapshot persist. Determinism: mirror the injected-clock pattern every detector already uses (`conn_rate_over_at` `ratelimit.rs:446-467`, `ra_rate_over_at` `:494`, `beacon_observe_at` `behavioral.rs:113,190-191`): `boi_step_at(now_ticks, &[Obs], &mut BoiState)` pure over its state; active-days keyed on `now / (cntfrq·86400)`.

| # | Acceptance | Failure |
|---|---|---|
| A7.1 | BOI called only from the drained branch (or a heartbeat slice), never from `packet::verdict`/`classify`; per-packet cost = one bounded enqueue | any BOI table access reachable from the per-packet path |
| A7.2 | `boi_step_max_us` (cntpct, the `RxProf` pattern `main.rs:998-1032`) ≤ 200 µs p99 / 1 ms max under the 9.4k-fps replay; RSR BNA/OVR not worse than BOI-off baseline | step over bound; BNA/OVR rises |
| A7.3 | compile-time `BOI_N_ENT` (64 on CM5), `BOI_N_REL`, `BOI_OBS_RING` (256) + `obs_overruns`, `BOI_MAX_OBS_PER_STEP`, `BOI_SLICE`; all loops bounded; printed in the heartbeat | unbounded loop, dynamic table, unreported constants |
| A7.4 | `heap::used()` identical before/after a step; no `f32/f64` in `boi.rs` (lint/grep gate) | any alloc or float |
| A7.5 | `[P-boi-replay]`: identical Obs vector + synthetic clock on QEMU and host → identical SHA-256 state digest; no cntpct inside the step | divergent digest |
| A7.6 | Wasm-module shape stays `[partial]`; before any per-heartbeat Wasm: host re-linked clear of `base+0..0x4000`, loaded once, re-entrant heap reset, excursion time measured | per-heartbeat `load_el0_wasmhost_cm5`; unmap after GEM setup |
| A7.7 | `faults=0` preserved **and** an RSR-derived `rx_overrun` counter added to the heartbeat | relying on `drop=0/faults=0` alone |

## 8. Invariants preserved — stated explicitly

ADR 0023 D1/D2/D4 (tri-state `decide()`, four drop classes, behavioural = no enforcement consumer); ADR 0014 D1/D4/D5/D6 (no on-device training in the enforcement path; labels via adjudication/corroboration; cold-start; advisory ML); ADR 0038 D2/D5 (no weights in the enforcement path; models off-device, signed, attested); ADR 0025 D1 (C9 by type); ADR 0011/0013 (roster cap 11 — BOI adds no agent); ADR 0003 (flat tokens, `requires`/`provides`, `ml_cpu`≠`edge_ai`); ADR 0002 (hybrid signing, fail-closed — the heqk Ed25519-only verify is an existing gap, not relaxed here); ADR 0047 D3/D4 (heqk first; honesty tags); CLAUDE.md standalone-by-default, bounded-and-honest retention, hard per-tenant isolation. **No ADR is amended by this review.** Two documents are found *already inconsistent* with canon and must be fixed by their owners: `kernel/heqk/SECURITY.md:393-515` and ADR 0007 `:11`.

## 9. Corrections the alignment doc needs before it becomes ADR 0048

1. **§1 "Secure replication" row and §3.4 "reuse `apply_reach_policy` verbatim"** → wrong: authority ≠ truth. Replace with the split in §2 (operator-signed logic; channel-authenticated evidence, inert w.r.t. local state).
2. **§3.1 entity key** → `fingerprint.rs` has no profile id (class only); the heqk AP parses no DHCP opt 12/55/60; "already parses" is false. Replace with §3.
3. **§3.2 capacity** → the 0xDA partition exists in the factory image (≈ 444 MiB); numbers corrected to 6 records/sector, 11+2+1 per generation, 2 generations resident, ≥ 29 → 32 sectors; "64 entities ≈ 3.6 KiB" is 64 *records* ≈ 3.5 KiB.
4. **§3.4 "BOI-specific VEK via `load_or_create_vek` with its own label; tenant in the HKDF label"** → neither exists; per-entity deletion by rotation is impossible with one VEK; the design in §6 (own keyslot, random per-entity DEKs) replaces it. Cross-boot nonce uniqueness must land first.
5. **§2 C1 "an attacker influences evidence, never policy"** → true for enforcement, **false for detection outcomes** (Established suppresses novelty). Add the poisoning bound (T7/A5.7).
6. **§2 C5 "`SECURITY.md` silent"** → true for the root file only; `kernel/heqk/SECURITY.md` contradicts HBG. "Hashed FQDN" → keyed HMAC, named pseudonymisation. The V1 browsing principle is uncited; adopt it as new.
7. **§3.5 band 1_300_000** → not expressible on the u16 wire (max 1_265_535); choose 1_2xx_xxx ids or add a band field.
8. **§3.3** → per-heartbeat Wasm is blocked by three concrete facts (F6); the first shape is the drained-branch `no_std` step.
9. **Boundary wording in C1** ("changes how a future observation is scored") → replace with the θ/S/training definition of §5.

## 10. Incidental findings outside BOI (for their owners; `informed_by` candidates)

- `prod-mc` snapshot never restores on metal (F1) + non-crash-consistent blob write (F2) — **production defects**, owner: the prod-mc profile.
- sepdiag DataVolume self-test writes outside every partition on the factory layout (F5).
- GEM ring overflow (`rsr=0x7`) is invisible to the heartbeat's `drop/faults` (A7.7) — add `rx_overrun`.
- `src_mac_hash` is the raw first four MAC octets (`events.rs:26-28`) — a misnomer in an exported field; evidence `dev:` ids are unkeyed FNV over raw IP with no tenant (`lib.rs:140-150`).
- `responder-sim` binds `device_fp` to the device's self-claim (Q2-H1) — fix before any multi-device receiver.
- `kernel/heqk/SECURITY.md` stale GDPR/"no profiling" claims; ADR 0007 Apache-2.0 vs AGPL contradiction.
- No eMMC endurance figure anywhere in-tree; EXT_CSD life-time fields are readable and unexported.
