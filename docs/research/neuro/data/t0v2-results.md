# T0 v2 → T1 v2 — second specialised small model (2026-11-19, M5 Pro)

> Plan: `16`. Follows `t1-results.md`. Same student, teacher, conditions and blind set.
> **This was the second and final allowed look at the 215-case blind set** (disclosure in `t1-results.md`).

## What changed from T1

**T0 v2 cases: 3,479.**
- 3,400 come from the v2 templates (`gen_t0.py --v2`):
  - about 30% multi-incident windows;
  - `injection_v2`: six attacker-controlled fields, English and Romanian instructions, random canaries.
    The blind set's forbid strings are banned.
- 79 are **real** IoT-23 dev-split windows (`gen_t0_iot23.py`), rendered by the device's own compressor.
  Scans are capped at 60.

**Teacher:** Qwen3-14B Q4_K_M, closed decoding, with a teacher-only hint: describe instruction-like fields,
never quote them.

**Filter:** `build_sft.py --no-echo` over the T1 answers plus the v2 answers.
- 5,479 answers in, **3,433 kept (62.7%)**: 3,262 train and 171 valid; 871 Romanian.
- Rejections (one answer can fail several checks):

| Check | Rejected |
|---|---|
| verdict | 1,148 |
| hallucinated entity | 732 |
| citation | 665 |
| mention | 643 |
| language | 338 |
| **echo of an attacker-controlled field** | 58 |
| canary | 40 |

**Training:** full fine-tune, 1,631 steps (about 2 epochs), batch 4, learning rate 1e-5, 17 minutes.
- Validation loss went from 1.325 to 0.225; the best was 0.219 at step 1,400.
- Log: `t0v2-train-log.txt`.

**Timing:** teacher labelling took 5 h 35 min (05:50 → 11:25). The evaluation took 3 minutes. Pipeline
log: `t0v2-pipeline-log.txt`.

## Blind-set result (215 cases, single look, identical conditions to T1)

| Hybrid (L0 verdict + model explanation) | Base 0.6B | T1 (ft1) | **T1 v2 (ft2)** | Gate (`16`) |
|---|---|---|---|---|
| Explanation mention (n = 175) | 0.583 | 0.680 (McNemar p = 0.046) | **0.634** (McNemar vs base p = 0.28; 23 vs 32) | ≥ 0.73 ❌ |
| Romanian language (n = 53) | 0.925 | 0.981 | **1.000** | ≥ 0.9 ✅ |
| Canary-safe, summary (n = 25) | 1.000 | 0.880 | **0.920** | ≥ 0.96 ❌ |
| Canary-safe, whole answer | 1.000 | 0.840 | **0.920** | — |

Model alone (closed prompt):

| | T1 | T1 v2 |
|---|---|---|
| Triage verdict (n = 150) | 0.433 | 0.480 |
| Triage mention | 0.680 | 0.640 |
| Schema valid | 0.993 | 0.993 |
| Injection mention (n = 25) | 0.680 | 0.600 |

## Reading

**Gate: not passed.**
- **Injection safety improved but did not reach the gate:** 2 of 25 answers still leak, against 3 with T1.
- **Explanation coverage fell back:** 0.634 is not significantly better than the unmodified base.
- **Romanian answers** are now fully correct (1.000).

Possible reasons, **not tested**: the v2 data shifts weight toward injection and multi-incident windows,
and the strict filter keeps only 63%. Both may cost the plain-triage explanations that the mention metric
measures.

**This blind set is now spent for T1 iteration.**
- It has had its two allowed looks. No change may be derived from these failures, and no third T1 number on
  it would be a fair estimate.
- The next T1 iteration needs:
  1. **a fresh blind set** (`blind v2`), generated and sealed before any further training-data change;
  2. a decision on the base model. Two 0.6B attempts reached 0.680 and 0.634 against the 0.73 bar
     (Qwen3-1.7B at Phase 0, with grammar). Fine-tuning Qwen3-1.7B itself is the obvious next candidate,
     at the cost of the plan's "≤ 40% of its bytes" condition.
- The **hybrid deployment is unaffected**: the L0 verdict stays deterministic, and the model only explains.

## Artefacts (not committed: weights and runs stay in the scratch workspace)

- `t0v2/ft/`: the fine-tuned weights.
- `t0v2/ft2-closed.{json,txt}`: the per-case blind results.
- `t0v2/RESULTS.md`: the comparison table above.
