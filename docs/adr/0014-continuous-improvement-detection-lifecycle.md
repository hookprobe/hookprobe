# ADR 0014 — Continuous-improvement detection lifecycle: how detection gets smarter over time without violating C9

**Status:** ✅ Accepted (2026-07-04) — policy accepted; deterministic tier turn #1 shipped (`dnsxai` lookalike + dictionary-DGA, `modules/dnsxai/src/lib.rs`, 29 tests). ML `dga-lm` tier + adjudication/label path remain ⬜ (implementation deferred, not blocking the decision). Proposed 2026-07-03.
**Deciders:** operator, product-steward, os-architect, telemetry-analyst.
**Relates to:** [ADR 0009](0009-soc-brain-edge-cloud.md) (evidence graph, SQLite-edge/ClickHouse-cloud, C9 — AI never in the enforcement path), [ADR 0011](0011-product-cortex.md) (Product Cortex, the `informed_by` field-feedback edge, Ring-1 roster), [ADR 0013](0013-cortex-evolution-apis.md) (event-driven lifecycle bus, roster raised to 11 incl. `retirement-agent`), [ADR 0005](0005-unified-ebpf-detection.md) (detection logic is compiled/verified CI-side, never mutated on the immutable edge), [ADR 0002](0002-crypto-agility-pqc.md) (signing / trust-nothing-unsigned). Worked example: the `dnsxai` deterministic lookalike + dictionary-DGA gap-close (`modules/dnsxai/src/lib.rs`, 29 tests, live-validated on Pi4, 2026-07-03) and the scoped `dga-lm` char-level ML classifier (prior os-architect feasibility report).

## Context

A direct operator question: **"does `dnsxai` auto-train from cumulated historical data? if not, use the Cortex to define a product lifecycle for continuous improvement."**

**Answer: no — and it must never.** `dnsxai` is a **deterministic** heuristic engine (Shannon entropy, vowel/consonant ratio, plus the new lookalike/dictionary detectors — `modules/dnsxai/src/lib.rs:464-476`, verdict thresholds 0.60/0.30). It holds no weights, does no on-device training, and produces the same verdict for the same input on every device. That is a **feature**, not a limitation: it is what makes verdicts explainable, reproducible, and signable — the properties C9 (ADR 0009) and trust-nothing-unsigned (ADR 0002) depend on.

But "no self-training" must not mean "never improves." A live Kali + iPhone attack campaign on the Pi (2026-07-03) **confirmed a real blind spot**: dictionary-DGA (`facilitycompany.net`) and lookalike/typosquat (`goog1e.com`, `paypa1-secure.com`) all scored *benign* — by construction, they use real letters/words so entropy tuning can never catch them (`modules/dnsxai/src/lib.rs:66-79`). That gap was captured into the evidence graph as an `informed_by` requirement (`ml-domain-classifier-dga-lm`), an agent authored two deterministic detectors (bounded edit-distance + leetspeak normalization; bounded word-segmentation DP), 29 tests, deployed and validated on the Pi (before→after: those three now malicious; `google.com`/`cloudflare.com` stay benign — `BENIGN_ALLOWLIST`, `modules/dnsxai/src/lib.rs:123-137`).

**That was one turn of a loop.** This ADR makes the loop **explicit and standing** — the requirement→retirement lifecycle (ADR 0013) applied to *detection specifically* — so improvement is a governed, repeatable product process, not a lucky one-off, and so no future "make it learn" pressure is ever answered by a hidden on-device auto-trainer.

## Decision

### D1 · Two tiers, one loop — neither self-trains in the enforcement path

Detection improves through **two tiers that share one lifecycle loop**; the loop's *learning* happens off the enforcement path, always.

| Tier | What it is | How it improves | Ships as |
|---|---|---|---|
| **(a) Deterministic** | `dnsxai` heuristics + curated detectors (entropy/vowel, lookalike, dictionary-DGA) — no weights | **Agents author rules/detectors from evidence** (the 2026-07-03 dnsxai fix is the reference turn); reviewed, tested, signed | signed **Wasm** module (`.wasm` → verify-before-run → AOT `.cwasm`, ADR 0009 step 1) |
| **(b) ML** | `dga-lm` — a char-level DGA/domain classifier (scoped, os-architect feasibility report) | The device's **accumulated labeled DNS history + external threat-intel become TRAINING DATA** fed to an **OFF-DEVICE** training pipeline → a **new signed model** | signed **OCI model artifact** pull (int8-quantized — the A72 has no SDOT, quantize for memory), digest-pinned, **model-carded** (SBOM); assistive/out-of-band; **9M `rule_id` band**; gated by a new **`ml_cpu`** capability token |

**Neither tier self-trains on-device in the enforcement path. Why (non-negotiable):**
- **C9 (ADR 0009):** AI plans/proposes; only the deterministic reconciler + gate ladder enforce. A detector that rewrites its own weights from live traffic *is* AI in the enforcement path — forbidden.
- **Explainability:** a verdict must trace to a fixed rule or a fixed, versioned model — not to an opaque, per-device, drifting weight state no one can reproduce or audit.
- **Trust-nothing-unsigned (ADR 0002) + immutable edge (ADR 0005):** detection logic is built and verified **CI/off-device**, signed, and shipped; the edge rootfs is immutable and carries no training toolchain. An on-device trainer would produce **unsigned, unattested, per-device detection logic** — the exact thing the supply chain forbids.
- **Poisoning:** an on-device auto-loop is directly steerable by an attacker who shapes the device's traffic. Off-device training over aggregated, adjudicated labels breaks that single-device feedback loop.

The `dga-lm` ML tier is **referenced, not redesigned here** — it is the ML *arm* of this one loop, already scoped by the prior feasibility report. This ADR governs the *loop*, not the model architecture.

### D2 · The evidence graph IS the training/improvement dataset

Every verdict + its outcome already lands in the evidence graph (edge SQLite → cloud ClickHouse offload, ADR 0009). That accumulating corpus **is** the dataset — no separate data pipeline. Four feedback signals are **mined from the graph** (by `telemetry-analyst`, read-only on live devices):

| Signal | Graph query shape | Feeds |
|---|---|---|
| **Miss** (false negative) | verdict=benign → later `informed_by`-linked to a confirmed-bad incident/IOC/CTI hit | new requirement (both tiers); a *hard* training label (bad) |
| **False positive** | verdict=malicious/suspicious → adjudicated/corroborated as good | rule tuning / allowlist entry (det.); a training label (good) |
| **Drift** | novel domain-pattern clusters with no matching rule/technique | `ideation-scout` candidate requirement; retrain trigger |
| **Coverage gap** | MITRE ATT&CK techniques with zero firing detections | requirement (which tier closes it) |

The `informed_by` edge (ADR 0011 D1) is the load-bearing primitive: it is *already* how the dnsxai gap became a requirement. This ADR names it as the standing corpus-to-roadmap link for detection.

### D3 · The loop, mapped to the 11-agent roster (ADR 0011/0013)

The requirement→retirement lifecycle applied to detection. Each stage is an agent + an event on the lifecycle bus (ADR 0013 D2); C9-bound (agents propose, gates enforce):

1. **Accumulate** — verdicts + outcomes stream into the evidence graph (edge SQLite → cloud ClickHouse).
2. **Observe** — **`telemetry-analyst`** mines the graph for misses / FPs / drift / coverage gaps (D2); emits `telemetry.anomaly_cluster` / draft requirements.
3. **Fuse external signal** — **`ideation-scout`** cross-references new DGA families / CVEs / ATT&CK moves against live telemetry → candidate `requirement.draft` (Amber).
4. **Improve** — **`code-developer`** authors the heuristic/detector (tier a — the dnsxai turn) **or** the **off-device pipeline retrains** the model (tier b — no on-device training).
5. **Gate** — **`verification-engineer`** (no-regression on a labeled corpus + an explicit **FP budget**) + **`security-auditor`** (signed, model-carded, poisoning review). A Red verdict is final.
6. **Ship** — **`release-engineer`** ships the signed Wasm (tier a) or the digest-pinned signed model OCI pull (tier b).
7. **Close the loop** — **`measured_on`** the device; **`informed_by`** edges link the outcome back to the originating requirement — evidence the fix worked (the dnsxai before→after is exactly this).
8. **Retire** — **`retirement-agent`** proposes pruning never-firing rules and superseded model versions (dead-detection EOL; ADR 0013 D3).

### D4 · Governance / C9 restated for learning — how a verdict becomes a trusted label

**AI proposes improvements; deterministic gates enforce.** Models are trained **off-device**, **signed**, **digest-pinned**, **model-carded (SBOM)**. The one genuinely new governance object is the **label**: raw history is not training data until a verdict is adjudicated into a *trusted label*. A verdict becomes a trusted label only via a **confirmed-label feedback path** — never an opaque auto-loop:

- **Operator/analyst adjudication** (Investigate workspace): an operator confirms a verdict right/wrong → a signed `adjudication` node → trusted label. Highest trust.
- **High-confidence corroboration**: an independent authority agrees — a CTI/IOC/CVE hit (HYDRA), a second detector, sandbox detonation → an auto-label at **lower** confidence, carried with its provenance.
- **Label discipline:** labels carry source + confidence; only the training pipeline (off-device) consumes them; a single device's traffic can never *by itself* promote a label (D1 anti-poisoning). Adjudication is **Amber** (operator-reviewed), never autonomous.

This is the seam that keeps "continuous improvement" from becoming "silent self-training": improvement flows only through **signed artifacts** produced from **adjudicated labels** behind the **gate ladder**.

### D5 · Honest limits

- **Cold-start:** a fresh standalone device has *no* history. It ships with the **baseline signed rules + baseline signed model** (both tiers seeded at build time). The loop *improves* a device; it never *gates* one — a day-one air-gapped box is fully functional on the baseline.
- **Label noise:** corroboration-labels are weaker than adjudication-labels; the pipeline must weight by confidence and the FP budget (D3.5) is the backstop. Garbage labels degrade the *next* model, never the *running* one (off-device + gated).
- **Standalone vs cloud split (respects "standalone by default, cloud is additive, never gates the device"):** a **standalone** device improves purely via **signed pulls it opts into** (new Wasm / new model OCI) — it needs no account and phones nothing home. The **training pipeline** needs *aggregated, opted-in* data (the ADR 0012 beacon is OFF by default; cloud/MSSP tenants opt in). A device that never opts in still gets every baseline + community-published signed improvement; it simply doesn't *contribute* its history. **Learning is a two-way street the operator can walk one-way.**

## Consequences

- **+** Answers the operator plainly: `dnsxai` does **not** auto-train, and now there is a *named, standing, governed* way it (and `dga-lm`) get smarter — the dnsxai turn was step one of it.
- **+** No new mechanism: reuses the evidence graph (ADR 0009), the `informed_by` edge + roster (ADR 0011), the lifecycle bus (ADR 0013), the gate ladder + signing (ADR 0005/0002). "One system."
- **+** Structurally immune to the "learning backdoor" risk: improvement can only enter via signed artifacts through the gates — there is *no code path* for a detector to mutate itself in the enforcement path.
- **−** The ML tier's real payoff needs opted-in aggregated data → **strongest on cloud-linked fleets, thinnest on a lone air-gapped box** (which still gets baselines + community signed pulls). Accepted, and honest.
- **−** The **adjudication/label path (D4) and the off-device training pipeline are ⬜** — not built by this ADR. What exists today: the deterministic tier's one proven turn (dnsxai), the `informed_by` edge, and the `dga-lm` scoping. This ADR is **the standing loop's definition, not its implementation.**
- **−** Label quality is a lasting operational burden (D5) — the loop is only as good as its adjudications; needs the Investigate-workspace adjudication UX (ux-architect, Phase-3/4).

## Build steps (small, sequenced)

1. 🟡 This ADR + BuildPlan Change Log + traceability touch (product-steward, 2026-07-03). Deterministic-tier turn #1 (dnsxai lookalike/dictionary) already ✅ (`modules/dnsxai/src/lib.rs`, 29 tests, on-metal Pi4).
2. ⬜ **Adjudication → trusted-label path (D4):** signed `adjudication` node + confidence/provenance on labels in `crates/hookprobe-evidence`; Investigate-workspace "confirm verdict" action (Amber) — code-developer + ux-architect.
3. ⬜ **Feedback-signal miners (D2):** `telemetry-analyst` graph queries for miss/FP/drift/coverage → `requirement.draft` events on the lifecycle bus (ADR 0013 D2).
4. ⬜ **`dga-lm` off-device training pipeline (D1b):** consumes opted-in aggregated labeled history + CTI → int8-quantized signed model-carded OCI artifact; `ml_cpu` capability token; 9M `rule_id` band — os-architect + release-engineer (per the feasibility report).
5. ⬜ **Retirement of dead detections (D3.8):** `retirement-agent` query for never-firing rules / superseded model versions → EOL proposals (Amber).

---

## Amendment (2026-07-15) — D6 · `dga-lm` is the first CPU-native detector: the A76 SDOT path retires the "needs an NPU" framing

**Status:** 🟡 Proposed (the ML tier D1b moves from "deferred, implicitly needs an off-device pipeline +
an NPU" toward a concrete first **CPU-native** increment). No model shipped yet — this is the build
contract, not the build. **Deciders:** os-architect (author), code-developer, verification-engineer,
security-auditor, telemetry-analyst. **Relates to:** [ADR 0021](0021-multiarch-native-artifact-digests.md)
D7 (the A76 `+dotprod`/`+fp16` compute tier + the determinism decision this depends on),
[ADR 0031](0031-dataplane-performance-strategy.md) (the base-tier framing that established stock A76 has
SDOT), [ADR 0009](0009-soc-brain-edge-cloud.md) (C9 — why `dga-lm`'s output stays advisory).

### The reframe

D1b scoped `dga-lm` as int8-quantized "**because the A72 has no SDOT**, quantize for memory," gated by
`ml_cpu`, 9M `rule_id` band, off-device-trained signed OCI model — and the roadmap implicitly read "real
ML" as needing the NPU tier. A hardware-acceleration review (ADR 0031 / 0021 D7) established that the
**flagship base tier — stock Pi 5 / CM5, BCM2712 Cortex-A76 — has FEAT_DotProd (SDOT) + FEAT_FP16
on-silicon.** So the int8 DGA classifier runs on the **CPU** at the A76 AOT compute tier: **zero BOM, no
NPU, no WASI-NN backend, no proprietary runtime.** This makes `dga-lm` the **first real, CPU-native,
WASI-NN-shaped detector**, and lets QSECBIT's `p_attack` term (today a stub returning `0.0`, capping the
composite score at ~AMBER) actually be fed on the flagship platform.

### D6 decision

1. **`dga-lm` ships as a signed Wasm module on the CPU path**, not gated on an NPU. On the **A76
   compute tier** (ADR 0021 D7) it uses the int8 SDOT lowering *where Cranelift emits it* (fp16 too),
   fits the 50 ms QSECBIT epoch comfortably, and is the intended home. On the **A72 / no-dotprod
   floor** it recompiles to a NEON widening-multiply sequence (SMULL/SADALP) with int8 weights kept
   L2-resident — **expected** to fit the epoch, but **budget-gated, not assumed**: if the A72 path
   misses the epoch deadline, `ml_cpu` is simply **not granted** on that tier (per the ADR 0003
   `grant = presence ∧ known-good ∧ policy` rule, resolving to `present_unsafe`/`absent`) and
   `p_attack` stays `0.0` there — the ML term is **scoped to where it fits**, not forced globally.
   This corrects the earlier draft's "the A72 always gets the same detection" over-claim (reconciled
   with base-tier consensus spec §4.2, 2026-07-15): one system, and the capability unlocks the term
   where the silicon can afford it — A76 always, A72 if-it-fits.
2. **`ml_cpu` capability token** gates **the model tier being runnable on this CPU within budget** —
   granted on the A76 tier, budget-gated on A72 (point 1). It gates a *CPU inference path*, not a
   hardware accelerator. (Canonical **flat** token per ADR 0003 Principle 5; the base-tier draft's
   dotted `inference.cpu_simd` is the same capability under a non-conforming namespaced spelling — see
   ADR 0003's 2026-07-15 base-tier token note.) The NPU tier (`wasi-nn: npu`, ADR 0031 §D) is an
   **optional accelerator** for `dga-lm` and future models on rpi5/rk3588 via the sidecar, **not a
   precondition** for any ML detection.
3. **Determinism / C9.** `dga-lm`'s output is an **advisory score** (observe-only; feeds QSECBIT
   `p_attack` and Detect alerts, **never an inline drop** — C9, ADR 0009). Per ADR 0021 D7 it **MAY** use
   fast non-deterministic relaxed-SIMD on the A76 tier, provided the score is documented tier/engine-
   dependent and any **persisted training label is re-scored off-device** (D4), never taken from the
   device's own fast-path number. Promoting `dga-lm`'s output into a *verdict* role later would force the
   deterministic dot (D7).
4. Everything else in this ADR is **unchanged**: still off-device-trained, signed, digest-pinned,
   model-carded OCI (D1b); still the evidence graph as corpus (D2); still adjudicated labels behind the
   gate ladder (D4); still **no on-device training in the enforcement path** (D1).

### Build-steps update (supersedes step 4's implicit "needs the NPU" assumption)

- ⬜ **Build** the `dga-lm` char-level classifier as a signed Wasm module (int8; deterministic base-SIMD
  dot for reproducibility, or relaxed-SIMD-advisory per D7) — code-developer. **This is a module
  *build*, not a one-line unstub.**
- ⬜ **Verify** the A76 `.a76.cwasm` int8 dot lowers to `SDOT` (disassembly gate, ADR 0021 D7);
  telemetry-analyst records A76-SDOT vs A72-NEON tick cost. If it lowers to a NEON sequence, the feature
  still ships; the "full SDOT throughput" claim waits.
- ⬜ **Wire** QSECBIT `p_attack` to the `dga-lm` score (removes the `0.0` stub / ~AMBER ceiling on
  platforms that carry the model).
- The off-device training pipeline (D1b) is **unchanged** — still the cloud / opted-in-fleet arm.

### Consequences

- **+** The ML tier is **no longer "thin on a lone air-gapped box":** a standalone $50 Pi 5 runs real
  CPU-native ML detection on the baseline signed model — no account, no NPU — strengthening
  standalone-by-default (D5).
- **+** Retires the "needs billions in ASIC silicon" framing: the **first** ML detector lands on stock
  CPU; the NPU is an **accelerator tier, not the ante**.
- **−** The SDOT payoff is **contingent on the Cranelift lowering** (ADR 0021 D7 verification gate); if
  it emits a NEON sequence the feature ships but the throughput claim waits.
- **−** Wiring `p_attack` means a `dga-lm` bug shifts the **composite** QSECBIT score — but **observe-only
  (C9)** means it never inline-drops, and the score is surfaced with provenance (the ADR 0011
  explanation panel: *why · confidence · evidence · model*).

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: NEUTRAL.** The two-tier (deterministic Wasm + off-device-trained signed ML) loop and the signed-artifact discipline survive; only the Wasm runtime *host* changes (heqk Wasm host or `.cwasm` AOT). A76-SDOT is a CPU feature, not Linux. → **Phase M5**.
