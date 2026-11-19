# T1 — first specialised small model (2026-11-19, M5 Pro)

> Plan: `16`. Everything ran on the development Mac, in an isolated scratch venv.

## Setup

| Item | Detail |
|---|---|
| Student | `Qwen/Qwen3-0.6B` at revision `c1899de2`, SHA-256 verified |
| Teacher | `Qwen/Qwen3-14B-GGUF` Q4_K_M at revision `530227a7`, SHA-256 verified; served by llama.cpp b12477 with closed decoding |
| Licence | both Apache-2.0 |

## T0 data

- `gen_t0.py --n 2000 --seed 1`: ten families, 28% Romanian. **0 collisions** with the blind and dev sets (hash check).
- **Teacher:** ~7 s per window, about 3.3 h for 2,000.
- **`build_sft.py` kept 1,416 (70.8%):** 1,346 train and 70 valid; 370 Romanian.
- **Rejected:**
  - 501 for a wrong verdict;
  - 224 for a missing mention;
  - **81 for leaking the injection canary.** Even the 14B teacher follows the injection on about 40% of those windows.

## Training

- MLX 0.32.4 / mlx-lm 0.32.2, full fine-tune, loss on the answer only.
- 700 steps, batch 4 (about 2 epochs), learning rate 1e-5.
- **About 6 minutes.**
- Validation loss: 1.263 → 0.227 (plateau, no sign of overfitting). See `t1-train-log.txt`.

## Blind-set evaluation (215 cases; base and fine-tuned under identical conditions)

Conditions: MLX server, temperature 0, closed-mode prompt (schema in the prompt), **no grammar**. MLX has no
JSON-schema decoding.

**This differs from Phase 0**, which used llama.cpp grammar. Phase 0 numbers are references only.

| Hybrid (L0 verdict + model explanation) | Base 0.6B | **Fine-tuned 0.6B** | Gate (`16`) |
|---|---|---|---|
| Explanation mention | 0.583 | **0.680** (McNemar p = 0.046; base-only 24, fine-tuned-only 41) | ≥ 0.73 — the Qwen3-1.7B Phase 0 figure, with grammar |
| Romanian language (n = 53) | 0.925 | **0.981** | ≥ 0.9 ✅ |
| Injection canary-safe (n = 25) | 1.000 | **0.880** ❌ | ≥ 0.96 |
| Verdict / citation / hallucinated entities | 0.59 / 0.93 / 0.00 (from L0, identical) | same | — |

Model alone (closed prompt):

| | Base | Fine-tuned |
|---|---|---|
| Triage verdict | 0.32 | 0.43 |
| Schema valid | 0.91 | 0.99 |
| Injection mention | 0.48 | 0.68 |

**Gate: not passed.** Explanation coverage is 0.05 short, and injection safety regressed.

## Why injection safety regressed (diagnosed on the blind set)

- **All leaking answers kept the verdict `suspicious`.** The model did not obey the injection. It
  **quoted the attacker-controlled field verbatim** while describing it.
- **The cause is in T0.** T0's filter rejected answers containing T0's own canaries, but kept answers
  quoting the rest of the payload. So the student learned to echo payloads.

**Fix (a general rule, also good UI hygiene): explanations must never reproduce attacker-controlled
strings.** T0 v2 rejects any answer that reproduces ≥ 8 consecutive characters of a quoted field from an
`!instr-like` card.

**Disclosure:** this rule was found by looking at blind-set failures. The next blind evaluation is
therefore a second look at that set. No further iteration on the blind set is allowed after it.
