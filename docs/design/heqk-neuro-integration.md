# heqk × Neuro: kernel–agent alignment and integration design

**Status:** design + stage-1 (N0) implementation behind the `neuro` feature, QEMU-proven, **not on metal, not in any
shipping or bench image** · 2026-11-22 · repository truth at `origin/main` `ed7a35aab`
**Machine-readable register:** [`heqk-neuro-status.yaml`](heqk-neuro-status.yaml)
**Governance:** ADR 0048 (reserved) is the home for Neuro decisions (ADR 0067 §"Review C"). This document approves
nothing on its own. §10 lists the decisions that need the operator.

## 1. The rule

**heqk owns the EL1 trusted computing base. Neuro is an isolated EL0 service that observes and recommends. Policy
validation and owner authorisation sit between any recommendation and an enforcement action in heqk.**

In concrete terms:

- **Neuro holds no capability.**
  - It has no network, storage, policy or device access, and no clock.
  - It sees fingerprints, never addresses or names.
  - It runs only when the kernel calls it, inside a bounded excursion with a CPU budget.
- **Every byte Neuro returns is untrusted input to EL1.**
  - The kernel validates status, lengths and each record before keeping anything.
  - A reply that breaks the protocol is refused, journaled as a complaint, and the server is reset.
- **Stage 1 output is evidence only.**
  - It is never an alert, a notification, a Qsecbit penalty, a `decide()` input or a Shield action.
  - Rationale: docs/research/neuro/20; ADR 0023 contract C9; D1 measured 72 benign deviations per device per week.
- **No path from Neuro to enforcement exists today.**
  - §7 specifies the only acceptable future path: a deterministic policy compiler, then a signed proposal, then
    owner authorisation, then the existing ADR 0053 actions. It is **proposed, not built**.
- **Neuro is fail-open for the data plane.**
  - A missing, faulted, throttled or held-off server costs a counter, never a stall.

## 2. Repository truth (2026-11-22)

| Item | State | Evidence |
|---|---|---|
| Integer behavioural memory ("Neural DNA") matches the float design | **measured** (Python) | `docs/research/neuro/data/e-n0-*`; `os/neuro/README.md` |
| `neuro-core` Rust is bit-exact with the integer reference | **passed on host** | `os/neuro/neuro-core/tests/golden.rs` (1,200 hour closes), `peerkey.rs` (3,000 keys) |
| `el0-neuro` builds for heqk (QEMU and CM5); zero FP/SIMD instructions | **passed** | re-checked 2026-11-22 after the ABI move: 0 FP/SIMD register operands (`llvm-objdump`) |
| D1 / D1b / D1c: alerting on the score | **measured, negative** | D1 median 72/device/week; D1b 29/week (AUC 0.995); D1c no per-device threshold qualifies (docs 17–19) |
| Decision: evidence, never an alert | **decided** | docs/research/neuro/20 |
| P3/P4 (golden replay and fault containment inside heqk) | **passed in QEMU on a throwaway patch, never committed** | `docs/research/neuro/data/p3-p4-heqk-report.md` |
| **Kernel host + permanent ABI (this work)** | **implemented, QEMU PASS** | `kernel/src/neuro.rs`, `hal/src/neuroabi.rs`, `[P-neuro*]` (§8) |
| Data-plane adapter (doc 20 §2) + AP-loop taps + hourly close | **QEMU PASS; parity with the reference converter** | `os/neuro/neuro-dp` (host parity test), `[P-neuro-dp]`; AP taps compile for CM5 behind `neuro` |
| CM5 metal (timing, loop-gap impact) | **not run** | §9 P3 |
| Sealed snapshots of the behavioural memory | **proposed** (doc 14 P5) | not designed; privacy review needed (§10 D4) |
| Protection model (DNA v1 f16 baseline, policy compiler, HQPROP1) | **proposed**; M3 (doc 31) **approved for unsealing and in progress** — gates P5; no L1 threshold before it | docs 27–31, 32 §3 |
| HNX model package, model region, FP/SIMD lease (L1+) | **proposed** | docs 06, 12 (R2–R9) |
| SMP (ADR 0060), memory budgets (ADR 0061) | **proposed ADRs**; single core today | ADR 0060/0061 status lines |

### Contradictions found and how this design resolves them

1. **QEMU status.** The README says "not started". The throwaway P3/P4 passed. Now: **committed and passing**
   (`[P-neuro-golden]` replays the same 1,200 closes through the permanent ABI plus EL1 validation).
2. **Peer key.** abi.rs said `fingerprint(peer_key(ip:port))`; doc 20 says `peer_fp(Mode::V2{plen:24})`. The ABI
   comment now follows doc 20, which is decided. The engine is key-agnostic; the kernel computes the key (§9 P2).
3. **Bytes per device.** Doc 13 says 672 B; the measured figure is 1,296 B (`INFO` reports it on every boot).
4. **"Alarm" wording** in docs 13 and 20 and in the README's IoT-23 line is superseded by doc 20. The result byte is
   `deviant`.
5. **Two DNAs.** Doc 27's DNA v1 (32 features, f16 baseline) is not the shipping engine. Under softfloat it needs
   integer quantisation or the FP lease (§5.4) before it can run in EL0.
6. **Loader RW cap.** hsh-style loaders cap writable pages at 8; el0-neuro needs 21. The host uses `RW_MAX = 32`.
7. **ADR 0067 F16** ("the Neuro engine is not on main") is stale: the engine has been on main since doc 13. The host
   is added here.

## 3. Target architecture

```
                 EL1 (heqk TCB)                                             EL0 (el0-neuro, own ASID)
 ┌─────────────────────────────────────────────────────┐             ┌──────────────────────────────┐
 │ data plane ──► attribution (MAC→slot, ≤64)           │  CMD_EVENTS │ 64 × (Dna + HourAgg) in .bss │
 │   flow/DNS     fingerprint (peer_fp V2/24, FNV)      │ ──────────► │ integer-only, no alloc,      │
 │                batch (≤512 ev) ── backpressure ctr   │             │ no capability                │
 │ clock (SNTP) ─► UTC hour roll ── CMD_CLOSE_HOUR ─────│ ──────────► │ score + guarded learning     │
 │                                                      │ ◄────────── │ 20-B result per fed device   │
 │ validate (hal::neuroabi) ── refuse+complain+reset    │             └──────────────────────────────┘
 │ evidence ring ("behaviour deviation", deviant only)  │   supervision: hal::superv entry "el0-neuro"
 │   └► Mission Control evidence view / explainer ctx   │   (Degrade, 200 ms CPU / 1 s, Volatile state)
 │ (future, §7) policy compiler ► HQPROP1 ► OWNER ► ADR 0053 action
 └─────────────────────────────────────────────────────┘
```

**Placement.** el0-neuro is a bounded excursion server: one command per excursion, ending in `SYS_EXIT_USER`, the
same substrate as el0-hsh and el0-lansvc. It is not a resident server.

| Platform | Window | Contents |
|---|---|---|
| CM5 | `0x1_4026_0000` (the free gap between el0-lansvc, which ends at `0x1_4025_4000`, and el0-hsh at `0x1_4030_0000`) | 128 KiB image, 16 KiB stack, 16 KiB IO |
| QEMU | `0xBE00_0000` | same layout |

Compile-time asserts in `hal::neuroabi` pin the window.

**State.**
- The behavioural memory lives in the server's own `.bss` (21 pages, zero-filled, nothing added to the ELF).
- The kernel keeps those pages across excursions.
- A fault or protocol complaint reloads the writable pages from the signed ELF. The memory is lost and relearns from
  cold.
- Supervisor state class: `Volatile`, `Exhausted::Degrade`. Neuro can never cause a reboot.

**Isolation.** The server runs in its own address space. `[P-el0-as]` now counts 9 servers, each mapping only its own
pages. The server cannot see kernel memory, other servers, the DataVolume or the network.

**Budget.**
- Per excursion: 5 ms on CM5, 2 s in QEMU (TCG).
- Per component: 200 ms of CPU per 1 s window (`hal::superv` H5), enforced on metal.
- The P3/P4 QEMU figures were a 64-device hour close in about 150 µs and a 512-event batch in about 45 µs. CM5
  numbers do not exist yet (§9 P3).

## 4. The kernel–Neuro ABI, version 1 (`os/kernel/hal/src/neuroabi.rs`)

The ABI is shared by the kernel and the server (the hal convention), so the two cannot drift.

**Versioning:**
- **v1.0** is the wire format of the former `os/neuro/el0-neuro/src/abi.rs`, byte for byte. A unit test pins every
  offset.
- **v1.1** adds:
  - **`H_ABI` at offset 20.** The kernel writes `major << 16 | minor`. A server that sees a different major answers
    `ST_BAD_VERSION`. `0` means a v1.0 kernel.
  - **Extended `CMD_INFO`** (16 bytes): `abi_minor`, a `caps` bitmask and `engine_rev`. The kernel accepts both the
    8-byte v1.0 and the 16-byte v1.1 replies, and refuses a server whose major or device-table size differs from its
    own.
  - **`CMD_HEALTH`:** events ok/bad, bad batches, hours closed, reports dropped, active devices, slots used.
- **Rules for future changes:**
  - A new command or field is a minor bump, gated by a `caps` bit.
  - Anything that changes the meaning of existing bytes is a major bump.
  - A kernel never sends a command the server did not advertise.

**Commands:**

| Cmd | In | Out | Notes |
|---|---|---|---|
| `EVENTS` 1 | n × 16 B | 0 | ≤ 512 events per excursion. Records: `EV_FLOW`, `EV_VOLUME`, `EV_DNS` (NX flag) |
| `CLOSE_HOUR` 2 | `[hr u8]` | k × 20 B | one result per device fed this hour |
| `RESET_DEV` 3 | `[dev u16]` | 0 | slot reassigned |
| `INFO` 4 | – | 8 or 16 B | version handshake at load |
| `HEALTH` 5 | – | 24 B | v1.1, `CAP_HEALTH` |
| `SELFTEST_FAULT` 99 | – | – | test only: the server panics |

**Validation in EL1** (`parse_close_reply`, all-or-nothing):
- the length is a whole number of records, no more than `OUT_MAX`, and no more than `DEVICES` records;
- every device is one the kernel fed an event this hour;
- no duplicates;
- `driver` is in 0..=4 and `deviant` is in {0, 1};
- `deviant` agrees with `score >= 1.0`;
- the reserved field is 0.

On any failure nothing is kept, a complaint is journaled (`WHY_BAD_LENGTH`) and the server is reset.

**Backpressure:**
- The kernel never waits.
- If the server is held off, over its CPU budget, unloaded, or the clock is unset (no UTC hour to attribute events
  to), the event is dropped and `events_dropped` is incremented.
- A full batch is delivered at once.
- If all 64 slots are in use, the least recently seen device is evicted (`RESET_DEV`), unless it has events in the
  open hour, in which case the new device's event is dropped.

**Health and evidence export:**
- `Host::health()` returns the server's counters. `Host::c` holds the kernel's counters: fed, dropped, batches,
  refused, hours closed or failed, results, deviant, server resets, evictions.
- `Host::evidence()` returns the newest 64 deviant records `{mac, utc_hour, driver, score_q8, parts}`. This is the
  doc 20 node.
- Not yet wired: an `/api` read endpoint, so Mission Control can show it as evidence (backend fields only; the UI is
  designer-owned), and inclusion in the sealed evidence log. Both are §9 P2.

**Recommendations: none in v1.**
- No command, record or field carries a recommendation.
- §7 reserves the shape for a future minor version behind a `caps` bit, which the kernel must not advertise until
  the §7 chain exists.

## 5. Prerequisites for anything beyond N0

### 5.1 SMP (ADR 0060, proposed)
- N0 needs no SMP; heqk runs on one core.
- Do **not** start secondaries early for Neuro. Secondaries start only through hboot with stage-2 confirmed
  (ADR 0060 D2), after the D3 conversions.
- If Neuro later gets a core, it is an **MG-class best-effort reservation**, never on a DP core (D5 "never"). Its
  excursions must stay preemptible by DP work.
- Until then, doc 12 R7(b) applies: token-sized excursions of ≤ 10 ms.

### 5.2 Memory (ADR 0061, proposed)
- N0 takes about 21 RW frames, 4 stack frames, 4 IO frames, and code/rodata frames from the frame pool, allocated
  once at load. There is no runtime allocation.
- L1+ needs:
  - DTB RAM discovery (ADR 0061 D1);
  - a `Model` budget kind with admission refusal (doc 12 R6);
  - a contiguous model reservation outside the 128 MiB pool (R3).
- No model may be admitted by optimistic allocation. A model that does not fit is refused with a reason.

### 5.3 Multi-tenant (ADR 0062)
- Neuro makes no multi-tenant claim.
- Its isolation is single-owner process isolation (ASID, W^X, no shared pages except IO).
- Microarchitectural isolation between tenants (ADR 0062) is out of scope and must not be implied.

### 5.4 FP/SIMD in EL0 (doc 12 R2; not built)

**Facts:**
- No code in the tree sets CPACR_EL1 or CPTR_EL2.
- Every kernel and EL0 crate is built for `aarch64-unknown-none-softfloat`.
- An accidental FP/SIMD instruction therefore has an outcome nobody has characterised (doc 00: a contained fault, a
  SoC reset, or V-register state shared across servers).
- N0 is integer-only by design.

**Requirement before any NEON engine:**
- R0 readouts on CM5 first: CPACR_EL1 and CPTR_EL2 as firmware leaves them.
- Then a **per-server lease**:
  - FPEN set only while that server's excursion runs;
  - V0–V31, FPCR and FPSR saved and restored (lazy save allowed);
  - **scrubbed before any other server runs**;
  - EL1 stays softfloat;
  - a global enable is never allowed.

**Decision:** this is a security decision (cross-server data leak), listed as §10 D2.

## 6. Inference roadmap

| Level | What | Where | Gate to start |
|---|---|---|---|
| **L0** | Integer temporal engine (N0): per-device behavioural memory, evidence only | el0-neuro, EL0 excursion | **implemented, QEMU**; CM5 evidence (§9 P3) |
| **L1** | Small learned classifiers confirming an L0 detector — the pre-registered candidate is doc 31 S1 (logistic regression, 28 features, 0.002 false alerts per device-day on dev; the 0.031 figure was the 32-feature variant) | EL0, **integer-only** (doc 32 §1: i16 weights / i32 accumulator make the same decisions as float on dev: 1 of 544 and 0 of 15,521 windows differ; ~288 B model) | M3 sealed result (doc 31); §5.4 lease or integer quantisation; signed package (§6.1) |
| **L2** | Larger models (gradient boosting, small CNN) | companion / PoP until the model region exists | doc 12 R3–R6; ADR 0061 admission |
| **L3** | Language tier: explainer only, never a judge (Phase 0: as a judge 0.37–0.50 vs L0 0.59) | off-device (ADR 0025 BYO endpoint); on-device only on SKUs with ≥ 4 GB, leased and paced | R2–R8; never on the protection path |

At every level the model **never judges**. Detection verdicts stay deterministic: L0 detector **AND** confirming
classifier (doc 30). Language output only explains.

### 6.1 Signed model package (proposed: HNX, doc 06)

- **Contents:** header (magic, version, target, engine ABI), capability requirements (FP lease, cores), resource
  manifest (weights, arena, state), execution plan as data (known kernel ids only, **no code**), 2 MiB-aligned weight
  segments, provenance (source SHA, SPDX licence, compiler, **eval-report hash**: no passing eval, no admission),
  and a Merkle root.
- **Signature:** a hybrid Ed25519 + SLH-DSA-SHA2-128s signature on the root (the image trust root's algorithms).
- **Verification:** by the kernel (doc 12 R5), never by the engine.
- **Device sequence:** verify, admit (budget), stream with per-segment hashing, map read-only, bounds-check once.
- **Open (§10 D3):**
  - who signs models (a new key is an irreversible trust commitment);
  - the update channel (A/B with the OS image or separate);
  - revocation.

## 7. From observation to enforcement: the only acceptable path (proposed, not built)

```
Neuro evidence ─┐
L0 verdict ─────┼─► deterministic policy compiler (pure function, signed rule table; never sees model text/weights)
classifier ─────┘        │
                         ▼
                 HQPROP1 proposal (signed, `expires_at` 30 min if unapproved, `ttl_s` of the applied action 60 s–24 h session / ≤ 7 days durable, nonce, evidence refs, tightening only)
                         │
                         ▼
                 OWNER authorisation (K_own, HQMGMT1 envelope, journaled)  ◄── the only authority
                         │
                         ▼
                 existing ADR 0053 action / owner journal rule (expiry), validated by the same EL1 code as today
```

- **Neuro deviation alone gives no action and no notification** (doc 29, line 88).
- **Loosening is never proposed.**
- **The only automatic path** would be a future, separately approved K_adm delegation: session-scoped and TTL-bound
  (doc 29 R-P4). Not designed and not approved.
- **Kernel requests in doc 29** (R-P1 expiry on journal rules, R-P2 evidence reference, R-P3 signed delta, R-P4 K_adm)
  are tracked in the register, all `proposed`.

## 8. Tests

**Host:**
- `hal::neuroabi` unit tests (4): the v1.0 layout is frozen; event encoding (kind, device range, 48-bit saturation,
  NX only on DNS); reply validation (every refusal class); INFO and HEALTH decode.
- `neuro-core` golden and peerkey tests (unchanged, passing).

**QEMU** (`os/kernel/tools/neuro-qemu.sh`, mcserve boot with `--features mcserve,wpa3,hsh,neuro`), 2026-11-22, all
PASS:

| Tag | Proves |
|---|---|
| `[P-neuro-abi]` | INFO v1.1 (caps HEALTH, 64 devices, 1,296 B per device); HEALTH answers; a major-2 kernel is refused by the server (`ST_BAD_VERSION`) |
| `[P-neuro-golden]` | **1,200/1,200** golden hour closes bit-exact through the real ABI and the EL1 validation (8,567 events, every batch accepted) |
| `[P-neuro-fault]` | bad batch, device, kind and hour return `ST_BAD_INPUT`; an unknown command returns `ST_BAD_CMD`, with no reset; a forced panic is contained and journaled; the server is reset from the signed ELF with its memory provably gone (HEALTH slots 0, events 0); the kernel is alive |
| `[P-neuro-validate]` | a reply longer than OUT is refused, journaled as a complaint, the server reset, and no evidence kept |
| `[P-neuro-host]` | no clock: event dropped and counted. 31 UTC hours closed by the hour roll (91 results, 0 failed). A burst of 400 novel peers on one device becomes a behaviour-deviation record for that hour (driver novel-peers). No alert, verdict or action |
| `[P-neuro-backpressure]` | after a fault streak the supervisor holds the server off; 10/10 events dropped and counted; the caller never waited |
| `[P-el0-as]` | 9 EL0 servers, each in its own address space (el0-neuro included) |

The other 24 boot self-tests in the same boot passed.

**Not shown:** anything on CM5. QEMU TCG timings are not the device's.

## 9. Priorities

| P | Work | State |
|---|---|---|
| **P0** | Repository-truth baseline, permanent ABI v1 in hal, kernel host behind `neuro`, QEMU tests, this design + register | **done (this change)** |
| **P1** | Operator review of §10 and of the ABI; ADR 0048 drafted from §1, §4 and §7 (operator-merged) | needs operator |
| **P2** | Data-plane adapter `os/neuro/neuro-dp` (doc 20 §2: DNS / new-connection / bytes rules, `peer_fp` V2/24, `NameTable<4096>`), bounded (UDP idle table 1,024, 256 pending DNS, 10 s DNS wait); AP-loop taps at the Wi-Fi boundary (station RX, `wifi_send!`, NAT-inbound send) + `ap_tick()` in the heartbeat, UTC only once NTP-synced; `[NEURO beat]` counters | **done in QEMU**: host parity test (16/16 device-hours, 762 connections, 349 DNS incl. 58 NX, every rule) + `[P-neuro-dp]` (same in the kernel, 1,127 engine events, 4 hours closed, 0 dropped). `/api` evidence fields: still open |
| **P3** | CM5 metal: bench image with `neuro`; excursion cost and **worst loop gap** vs baseline; `[IDS-BENCH]` ns/packet unchanged; fault injection on metal; 24 h bench run (not the REL-05 soak) | needs bench slot |
| **P4** | Sealed snapshot of the behavioural memory (survives reboot/OTA) — privacy review first (§10 D4) | proposed |
| **P5** | L1 behind M3 + the FP lease or integer quantisation; HNX verify in kernel | proposed, gated |

**Not in scope until the soak and release gates are done:** any change to the shipping AP image. The `neuro` feature
is off everywhere and adds nothing to the AP payload.

## 9b. Neuro-side alignment (doc 32, 2026-11-22)

The research track agreed §1, §4, §6 and §7 in full and corrected §6 L1, §7 HQPROP1 and the M3 status (applied above).
The connection rule stays doc 20's (TCP SYN / UDP idle ≥ 120 s) for N0; the Zeek-style 300/60 s rule of the DNA v1
benchmark is Neuro's own mismatch to re-measure before any L1 threshold reaches the device — no kernel change. The L0
beacon rule (22.4% of home device-hours) waits for M3 S2 before any kernel change (R-D1). Next joint steps: M3 result →
fixed-point DNA v1 extractor + integer S1 scorer with golden tests (Neuro, `os/neuro`) → an EL0 L1 behind a `caps` bit
(kernel), after D1–D3.

## 9a. Data-plane adapter (P2)

`os/neuro/neuro-dp` is EL1 code: it sees addresses so the engine never does. It is a no_std, allocation-free,
`unsafe`-free crate that mirrors `tools/neuro-research/unsw_to_d1.py --peer-key v2-24 --name-table 4096`.
`tests/gen_fixture.py` writes a deterministic capture (2,418 frames over 4 UTC hours and 4 devices) together with the
reference converter's output on it. `tests/parity.rs` checks that every device-hour is equal: connections, bytes, and
the peer and DNS multisets.

**Bounded-state differences from the reference.** Each is counted, and none occurs on the fixture:
- the UDP idle table holds 1,024 flows (4-way, oldest evicted);
- at most 256 DNS queries are pending at a time;
- a query waits at most 10 s for its response, then is reported without the NX flag.

**Memory and payload.**
- Memory: about 160 KiB of `.bss` (128 KiB name table, 24 KiB UDP table, 8 KiB pending DNS) in its own static.
- AP payload with `neuro` on: **3,113,984 B**, under the 3,137,736 B HBoot window (23,752 B headroom). The host
  state was moved from `.data` to `.bss` to get there.
- The shipping AP image without `neuro` is unchanged.

**Model work.** Nothing in N0 or P2 is trained: the engine and the adapter are deterministic. Model training and
evaluation (L1+ classifiers, the explainer, blind gates) belong to the Neuro research session on the Apple M5 Pro
host. This integration consumes its outputs only as signed packages (§6.1), once D3 is decided.

## 10. Decisions for the operator

| # | Decision | Options | Recommendation |
|---|---|---|---|
| D1 | Accept the el0-neuro window `0x1_4026_0000` (CM5) / `0xBE00_0000` (QEMU) and ABI v1 as permanent | accept / reassign | accept (reversible; pinned by asserts) |
| D2 | FP/SIMD for EL0 (L2+) | (a) never: integer-only engines; (b) per-server lease with save/restore/scrub (doc 12 R2); (c) global enable | (a) through L1 — doc 32 §1 shows the L1 scorer runs integer-only with the same decisions (its DNA v1 extractor still needs fixed-point log1p/entropy/CV with golden tests); (b) only if an L2 model needs it, after R0 readouts on CM5. **(c) is unsafe** (cross-server V-register leak) |
| D3 | Who signs model packages | (a) the image key (models ride OTA); (b) a separate model key under the same root; (c) the owner | decide before any L1; a new signing identity is an irreversible trust commitment |
| D4 | Persist the behavioural memory (sealed) across reboot/OTA | (a) no (relearn, current); (b) sealed snapshot, device-bound key, owner-erasable | (a) until a privacy review (per-device behaviour profiles are personal data) |
| D5 | Owner "this is normal" feedback | (a) none; (b) per-device acknowledgement journaled, used only for display ranking | (a) for N0 (doc 20: undesigned) |
