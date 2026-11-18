# NEURO_RESEARCH_001 — HookProbe Neuro Engine, Research Gate 001

> **Status:** research package for operator review, 2026-11-17. **Gate 7 is not passed:** this package
> authorises nothing. No inference runtime was built, no architecture was modified, no model was
> downloaded, no device was touched, and `os/kernel/**` (owned by HomePods) was read, never changed.

## The question

How can HookProbe deliver the most useful intelligence, security capability and autonomy per unit of
RAM, CPU, storage, power and cost on a Raspberry Pi CM5 — without ever compromising deterministic
network protection?

## The answer in five sentences

1. **On the product substrate today (CM5 on heqk), no neural inference can run on the device** — one
   core, FP/SIMD trapped, a 128 MiB pool for every EL0 server, no page cache — so any on-device
   generative AI depends on kernel work owned by HomePods (ADR 0060, ADR 0061, CORE-7).
2. **On CM5 silicon generally, generation is bandwidth-bound**: ~10 tok/s for a 1.7B model at Q4_0,
   ~2 tok/s for 8B, regardless of RAM size, while sharing an unpartitioned 32-bit DRAM bus with the
   data plane.
3. **The largest efficiency levers are therefore not model choices but system choices**: compile
   telemetry into evidence before any model sees it (≈ 323K → 500 tokens per hour with full incident
   recall, simulated), remember behaviour in ~0.6 KB per device without a model (AUC 0.999,
   simulated), and route each question to the cheapest level that can ground its answer.
4. **Recommended architecture: "Evidence-First, Model-Last" (D)** — an integer-only intelligence core
   that runs on heqk today, plus a pluggable, leased, bandwidth-paced, evidence-closed generative tier
   that can live on the device (larger SKUs, once kernel prerequisites land), on an NPU (RK3588 era),
   or on the owner's companion/PoP — with the product never depending on it.
5. **Phase 0 (2026-11-18) added the first independent evidence**: on 215 blind cases small models
   were significantly worse than the deterministic core at verdicts but nearly tripled explanation
   coverage when used as explainers; evidence cards reached 0.88 identity recall on held-out real
   malware traffic. **Nothing has yet been measured on a CM5.**

## Documents

| # | Document | Gate | Contents |
|---|---|---|---|
| 1 | `NEURO_RESEARCH_001.md` | — | this overview |
| 2 | [`NEURO_CM5_RESOURCE_BUDGET.md`](NEURO_CM5_RESOURCE_BUDGET.md) | 0 | heqk vs Linux-on-CM5, silicon facts, accelerators, availability budget in CPU/bandwidth/RAM/thermal, per-SKU budgets, unknowns |
| 3 | [`NEURO_LITERATURE_REVIEW.md`](NEURO_LITERATURE_REVIEW.md) | 1 | low-bit, compression (incl. what "CALIBRE" actually is), architectures, memory, adaptive compute, distillation, behavioural state, FL, runtimes, licences — 86 references |
| 4 | [`NEURO_INNOVATION_PROPOSALS.md`](NEURO_INNOVATION_PROPOSALS.md) | 2 | P1–P10 with prior art, feasibility, difficulty, kill criteria, measured (simulated) results; rejected ideas |
| 5 | [`NEURO_TECHNIQUE_MATRIX.md`](NEURO_TECHNIQUE_MATRIX.md) | 3 | 18 approaches, ranked for CM5; synergistic and incompatible combinations |
| 6 | [`NEURO_ARCHITECTURE_COMPARISON.md`](NEURO_ARCHITECTURE_COMPARISON.md) | 4 | BASE, A, B, C, D — diagrams, memory/execution/failure/security models; weighted value scoring + sensitivity |
| 7 | [`NEURO_EXPERIMENT_DESIGN.md`](NEURO_EXPERIMENT_DESIGN.md) | 5 | done vs planned experiments, kill criteria, load profiles, UIE metric, statistics, eval gate |
| 8 | [`NEURO_FINAL_RECOMMENDATION.md`](NEURO_FINAL_RECOMMENDATION.md) | 6–7 | decision, answers to the ten questions, what not to build, investment, roadmap awaiting approval |
| 9 | [`NEURO_PHASE0_RESULTS.md`](NEURO_PHASE0_RESULTS.md) | Phase 0 | blind evaluation of six models, real-traffic replays (IoT-23), CM5 speed projection — **the first non-simulated evidence** |

Raw outputs: [`data/`](data/). Scripts: [`tools/neuro-research/`](../../../tools/neuro-research/README.md).

## Evidence classes (used in every document)

| Class | Meaning | Examples in this package |
|---|---|---|
| Scientifically demonstrated | peer-reviewed result | KIVI (ICML 2024), T-MAC (EuroSys 2025), EACL 2026 speculative-decoding study |
| Demonstrated in an implementation | works in released software | llama.cpp json_schema, slot save/restore, TQ2_0 |
| Verified on ARM64 | published measurement on ARM CPUs | Arm Learning Path Pi 5 llama-bench; T-MAC on Pi 5 |
| **Verified on actual CM5** | measured on CM5 | **none — by anyone in this study** |
| Theoretical but plausible | arithmetic from specs | E-RF1 roofline |
| Simulated (this study) | synthetic data, dev host | E-SC1, E-BM1, E-EV0 |
| Original hypothesis | proposed here, untested | P2 quality impact, P4 benefit, P8, explain-to-learn |

## How this package changed along the way

The mission began as "pick the best local LLM for CM5", was redirected to "invent a resource-adaptive
engine", then to a research gate that forbids building one before approval, and finally to a
value-maximising decision. The branch name `agent/neuro-engine-research` reflects the second brief; the
content follows the last two. An earlier plan to prototype a Rust orchestration layer was **dropped**
in favour of the gate's instruction to wait for approval; no runtime code was written.

## What was run, on what

| Item | Where | Notes |
|---|---|---|
| Literature and model/licence research | web, primary sources | 5 parallel research passes, incl. a prior-art check |
| Repository investigation | this repo (read-only for `os/kernel/**`) | ADRs 0025, 0038, 0044, 0047, 0055, 0060, 0061, 0064; `mmu_cm5.rs`, `GAP_REGISTER.md`, `mcstate.rs`, `rulecat.rs`, `http.rs`, NAPSE/dnsxai model cards |
| Experiments E-SC1, E-BM1, E-RF1, E-EV0, decision matrix | Apple M5 Pro development host, Python stdlib | tokenizer: llama.cpp b12477 `llama-tokenize` (sha256-verified release) with vocab-only GGUFs (no weights) |
| CM5 measurements | **none** | `cm5_bench.sh` prepared |
