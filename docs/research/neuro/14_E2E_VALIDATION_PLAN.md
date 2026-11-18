# 14 — End-to-end validation plan for native recurrent security inference

> 2026-11-18. **A plan, not a result.** It turns the first experiment ("native recurrent security
> inference on heqk", `13`) into phases with entry conditions, measurements and kill criteria.
>
> The **success criterion it must prove:** useful, measurable behavioural-anomaly performance while
> memory and CPU stay low enough that **network protection is unaffected**.
>
> `os/kernel/**` remains HomePods'. Every kernel-side step is either theirs, or done in a throwaway
> copy that is never committed.

## 0. The end-to-end chain being validated

```
 packet ─▶ heqk data plane (EL1) ──▶ per-device attribution + fingerprints (no addresses leave the DP)
                                          │ batched events (16 B each)
                                          ▼
                              el0-neuro (EL0 excursion, integer-only)
                              per-device memory (DNA, + learned cell if it earns it)
                                          │ hourly scores + named driver
                                          ▼
               evidence graph node "behaviour deviation" ─▶ Mission Control (Observe / Investigate)
               L0 template explanation ─▶ owner confirms "normal" ─▶ memory adapts
               (never a path into decide() / enforcement)
```

**"Validated end to end" means every arrow is proven:**
- **(a) Correctness:** each stage computes what the reference computes.
- **(b) Usefulness:** real deviations are found at a tolerable nuisance rate.
- **(c) Cost:** each stage's CPU, memory and latency are measured, on QEMU and then on CM5 metal.
- **(d) Harmlessness:** the packet path, the main loop and Mission Control are unaffected.
- **(e) Robustness:** faults, resets and poisoning attempts are contained.

## 1. Where we stand (evidence, not plans)

| Link | Status | Evidence |
|---|---|---|
| Behavioural memory works on data | **partial** | synthetic AUC 0.999; real IoT-23: 14/14 onsets, Hue honeypot 2 alarms/day (**one device, 11 h**) |
| Integer engine = float engine | **done** | same experiments, same results (`data/e-n0-*`) |
| Rust engine = integer reference | **done** | 1,200 hour closes bit-exact, host test |
| el0-neuro builds for heqk | **done** | 5.4 KB code, 83 KB .bss, zero FP/SIMD |
| heqk gate on the dev Mac | **done: all implemented phases GREEN** (3 min 31 s) | one real finding for HomePods: the WiFi/WPA crypto KAT is silently skipped since a file move; a verified one-line fix is in `data/heqk-gate-macos-2026-11-18.md` |
| Learned recurrent model | **not started** | — |
| Anything inside heqk, DP hookup, UI, metal, field | **not started** | — |

**The two weakest points** decide the order of the plan:
1. **There is no realistic multi-day data with DNS.** Every usefulness number so far rests on synthetic
   data or a 22-hour honeypot.
2. **Nothing has run inside heqk**, so cost and harmlessness are unmeasured.

## 2. Phases

Each phase has an **entry** condition, the **work**, what is **measured**, a **pass** and a **kill**
criterion, and the **owner**. A phase may start when its entry condition holds. Phases P1 and P3 can
run in parallel.

### P1 — Data you can trust (Mac; prerequisite for every usefulness claim)

- **Entry:** consent and an export path (§3 items D1–D3).
- **Work.** Build a dataset with these properties:
  - **Real benign traffic:** ≥ 14 days, ≥ 20 devices of mixed kinds, flows **and DNS**, from a
    HookProbe network. It is exported as **fingerprints, counts and hour of day only**, using the same
    hashing as the device (`fingerprint(peer_key)`, FNV of the registered DNS suffix). No raw
    addresses or names leave the source.
  - **Attacks spliced onto real devices' timelines** (semi-synthetic, labelled as such):
    - real malware hours from IoT-23 (C&C, scan, DDoS, heartbeat);
    - scripted lab attacks: port scan, new beacon, exfil burst, DGA burst, lateral SMB.
  - **A controlled live attack set** from a lab VLAN with known start times. This is the only source
    of true time-to-detection.
  - **Splits:** **temporal** (train on days 1–7, tune on 8–10, test on 11–14) **and** by device
    (held-out devices). Base rates realistic (attacks ≪ 1% of device-hours). Arp et al.'s pitfalls
    checklist is attached to the dataset card.
- **Measured:** dataset card (devices, kinds, hours, DNS share, label provenance).
- **Pass:** card reviewed; no label leakage (attack labels never enter features); test split untouched.
- **Owner:** HookProbe research (me) plus the data owner (you).

### P2 — Is a learned recurrent model worth it? (Mac)

- **Entry:** P1 dev split.
- **Work.**
  - **Baseline:** the current integer DNA, unchanged, including the Phase 0b cold-start fix.
  - **Candidates**, each with a per-device state budget ≤ the DNA's (1,296 B) and trained only on
    benign dev data:
    - (i) a tiny GRU / minimal-RNN per device (shared int8 weights, int8 or int16 state);
    - (ii) a diagonal state-space cell (S4D/LRU-style: elementwise, integer-friendly);
    - (iii) the DNA's statistics as **inputs** to (i). This hybrid is often where learned models
      actually help.

    Each is trained as a next-hour predictor; the anomaly score is the prediction error.
  - **Quantisation:** post-training int8, then **bit-exact integer reference + golden vectors**,
    exactly as for the DNA.
  - **DNS fix:** a minimum query count before the NX share counts, tuned on the dev split only.
- **Measured on test:**
  - AUC and detection at 1% FPR per attack kind;
  - incident-level detection;
  - **alarms per device per week**;
  - time-to-detection on the live set;
  - a **poisoning drill** (slow-ramp attacker over 7 days);
  - bytes per device; ops per event.
- **Pass:** a learned candidate beats DNA by **≥ 0.02 AUC at equal or fewer bytes** *and* does not
  raise alarms per device per week. Otherwise **DNA ships** and the learned cell is shelved, honestly
  reported.
- **Ship gate for whichever wins:**
  - **< 1 nuisance alarm per device per week**;
  - ≥ 0.9 incident detection on scans, new C&C and exfil;
  - every alarm names a driver.
- **Kill (whole temporal tier):** no configuration reaches < 1 alarm per device per week at ≥ 0.8
  incident detection. Stop and rethink before any kernel work.
- **Owner:** me.

### P3 — Correctness inside heqk, in QEMU (throwaway kernel copy, never committed)

- **Entry:** your approval of throwaway wiring (§3 item A1). It can start now with the DNA engine.
- **Work.** In a scratch worktree only:
  - add `el0-neuro` to `kernel/build.rs` behind a feature;
  - map it at the proposed range;
  - add a **test driver** in the kernel that feeds the golden event stream through the real ABI
    (`CMD_EVENTS` batches, `CMD_CLOSE_HOUR`) and compares every returned score with the golden file.

  This is the same idea as heqk's own `[P8-diff]` (JIT vs interpreter).
- **Measured (QEMU):**
  - golden agreement (must be 1,200/1,200);
  - excursion count and duration per batch and per hour-close;
  - kernel-side cycles per event (CNTVCT);
  - fault containment: malformed batch → `ST_BAD_INPUT`; forced panic → `ST_PANIC`, server reset,
    kernel survives;
  - `.bss` persistence across excursions.
- **Pass:** bit-exact through the real ABI; all fault cases contained; the full `validate.sh` is still
  GREEN with the feature on.
- **Output:** a report to HomePods with the exact patch as an attachment (not a PR). They decide how
  to integrate.
- **Owner:** me (throwaway); HomePods (decision).

### P4 — Cost and harmlessness in QEMU (same throwaway copy)

- **Entry:** P3 pass.
- **Work:** load at scale. 64 devices × realistic event rates (1K, 10K, 50K events/s), replayed through
  the driver. The data plane runs its existing self-tests and IDS bench concurrently.
- **Measured:**
  - engine CPU per event and per hour-close;
  - **main-loop worst gap with vs without the engine**;
  - IDS `[IDS-BENCH]` ns/pkt with vs without;
  - frame-pool use;
  - largest single excursion.
- **Pass (proxy, QEMU is not timing-faithful):**
  - no increase in the main-loop worst gap beyond boot-to-boot noise;
  - hour-close for 64 devices < 20 ms (fits the existing lansvc-class budget);
  - per-event cost < 1% of one core at 1K events/s.
- **Kill:** a budget-sized excursion cannot hold an hour-close. Redesign as incremental closes
  (N devices per excursion) before going further.
- **Owner:** me.

### P5 — The real chain (HomePods implements; QEMU then e2e)

- **Entry:** P2 decided the engine; P3/P4 passed; HomePods accepts the integration.
- **Work (HomePods):**
  - move `abi.rs` to `hal/neuroabi.rs`;
  - assign the address range;
  - **data-plane hooks:** device attribution, fingerprints, event batching, an hourly close timer;
  - evidence-graph node type "behaviour deviation" with the driver;
  - sealed snapshot of the per-device memory to the evidence store at shutdown and periodically, so
    reboots don't cold-start every device.
- **Work (HookProbe UI):**
  - Observe and Investigate show the deviation with its driver and L0 explanation;
  - an owner "this is normal" action feeds back to the engine.
- **Measured:**
  - `tools/mc-e2e.sh`, extended with a scenario: replay pcap through virtio-net, assert the deviation
    node appears with the right driver, assert **no enforcement action** was taken (separation matrix);
  - snapshot/restore round-trip.
- **Pass:**
  - e2e scenario green;
  - the separation matrix (ADR 0023) unchanged;
  - `/api/planner/*` still honest.
- **Owner:** HomePods (kernel), HookProbe (UI and scenario), me (scenario design and review).

### P6 — CM5 metal (HomePods bench)

- **Entry:** P5 merged behind a feature flag.
- **Measured on metal**, against the documented baselines:

  | Metric | Baseline |
  |---|---|
  | IDS ns/pkt | 398–441 |
  | Main-loop worst gap | 330–347 ms |
  | Wi-Fi throughput | 98–106 Mb/s |
  | Engine cycles per event on the A76 | — |
  | Hour-close time | — |
  | RAM | — |

  Plus a 7-day soak and thermal behaviour.
- **Pass:**
  - every baseline within its boot-to-boot spread (±5%);
  - no new drops at the bench line rate;
  - engine < 1% of a core at the real event rate.
- **Kill:** any protection metric outside its spread that pacing or batching cannot fix → feature
  stays off.
- **Owner:** HomePods (runs); me (analysis).

### P7 — Field pilot (consented home/SMB networks)

- **Entry:** P6 pass.
- **Work:**
  - ≥ 14 days on ≥ 2 networks;
  - owner feedback on every alarm (useful / noise / normal-change);
  - one scheduled live attack drill per network, with the owner's consent.
- **Measured:**
  - alarms per device per week;
  - owner-rated precision;
  - drill time-to-detection;
  - memory adaptation after "this is normal".
- **Pass:**
  - < 1 nuisance per device per week;
  - drill detected within 2 hours;
  - owner-rated precision ≥ 0.7.
- **Owner:** HookProbe + HomePods.

### Separate track — low-bit SIMD path (not needed for the temporal success criterion)

The "low-bit vs INT8" comparison only matters for larger models (the language tier).
- It **requires R2**: per-server FP/SIMD in heqk.
- Until then it stays a dev-host and kernel-analysis result (`02`).
- If a learned cell grows past what scalar int8 handles comfortably (> ~100K MACs per event), this
  track is pulled forward.

## 3. What I need to be successful

| # | Need | From | Why it matters | When |
|---|---|---|---|---|
| **D1** | **Real multi-day traffic with DNS**, ≥ 14 days, ≥ 20 devices. Best source: your HookProbe deployment's flow/DNS store (fortress001 keeps ClickHouse), **exported read-only as fingerprints, counts and hour-of-day**, by Andrei or by me with your explicit go-ahead for that one query | you / Andrei | every usefulness claim so far is synthetic or one 22 h honeypot; IoT-23 has no DNS | P1, now |
| D2 | **Consent** of the people whose network that is, for research use of the fingerprinted export | you | ethics and privacy; fingerprints are not anonymous against someone who can enumerate addresses | P1, now |
| D3 | A lab VLAN or two spare devices for scripted live attacks (scan, beacon, exfil, DGA) | you | the only source of true time-to-detection and ground truth for "new behaviour" | P1–P2 |
| D4 | Approval to install **NumPy** into an isolated venv in the session scratchpad (PyPI download, removed afterwards) | you | training even a tiny recurrent cell in pure-stdlib Python is impractically slow | P2 |
| **A1** | **Approval for throwaway heqk wiring** of `el0-neuro` in a scratch worktree, never committed, reported to HomePods as a patch | you | the only way to measure correctness, cost and fault containment inside heqk before HomePods invests | P3, can start now |
| **H1** | **HomePods agreement in principle** to the integration shape: an EL0 server, the ABI, the address range, data-plane hooks, sealed snapshots | Andrei | P5 is their work; P3/P4 are wasted if the shape is wrong | before P5; ideally after P3's report |
| H2 | R0 readouts from a CM5 (feature registers, eMMC MB/s, frame-pool high-water) | Andrei | cost baselines and memory headroom on metal | before P6 |
| H3 | CM5 bench time + the existing IDS bench and metal-evidence procedure | Andrei | P6 | P6 |
| P1′ | Two pilot networks with owners willing to rate alarms | you | P7 | later |

## 4. Order and parallelism

```
now ─┬─ P1 data (needs D1–D3) ──▶ P2 model choice (needs D4) ─┐
     └─ P3 heqk correctness (needs A1) ──▶ P4 cost (QEMU) ────┴─▶ report to HomePods ─▶ H1
                                                                 ─▶ P5 real chain ─▶ P6 metal ─▶ P7 field
```

- P3/P4 use the DNA engine that exists today. If P2 picks a learned cell, only the golden vectors and
  the engine change. The heqk plumbing and its measurements stay valid.
- **Fastest path to a decision for HomePods:** A1 now → P3 + P4 → a report with measured cost inside
  heqk and an integration patch. In parallel, D1 → P1 → P2 decides *what* runs there.

## 5. Risks that would end the plan early

| Risk | Early signal | Response |
|---|---|---|
| Real networks are too noisy for any per-device memory | P2 nuisance > 1/device/week at every setting | stop at P2; keep L0 rules only; publish the negative result |
| Learned cell does not beat statistics | P2 kill criterion | ship DNA; it is explainable, measured and tiny |
| Hour-close does not fit an excursion budget | P4 | incremental closes; or HomePods R7 (token-sized excursions) |
| Fingerprints leak identity | privacy review of D1 | salted, per-device-keyed fingerprints; never export from the device |
| DP hooks cost the packet path | P6 ns/pkt outside spread | sample events (every N-th flow) — re-validate usefulness under sampling in P2 |
| Engine memory lost at every reboot | P5 snapshot test | sealed snapshots are part of P5, not optional |
