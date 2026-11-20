# T1-1.7B results: Qwen3-1.7B LoRA on blind v2 (2026-11-20, single look)

> Pre-registration: `../21_T1_17B_PREREGISTRATION.md` (#1387), with the seal and pipeline (#1390). The blind v2
> SHA-256 was re-checked against the seal before evaluating (`f13ef2fa…fc1f`). Blind v2 is published with
> this commit in `tools/neuro-research/eval/blind2/`.

## Setup (as pre-registered)

**Student.**
- `Qwen/Qwen3-1.7B` @ `70d244cc`.
- LoRA rank 16 on all layers, learning rate 1e-4, batch 4, max sequence 2048, 1,631 iterations.
- Gradient checkpointing; loss on the answer only.

**Data.** The frozen T0 v2 SFT set: 3,262 train, 171 valid; hashes as in doc 21.

**Checkpoint.** Iteration 1,400, chosen by the lowest T0-valid loss (0.192). The validation trace (step: loss):

| 1 | 200 | 400 | 600 | 800 | 1,000 | 1,200 | 1,400 | 1,600 | 1,631 |
|---|---|---|---|---|---|---|---|---|---|
| 1.339 | 0.291 | 0.241 | 0.223 | 0.204 | 0.216 | 0.203 | **0.192** | 0.196 | 0.193 |

- Adapter SHA-256: `70223ab656605ff83e5323d0a8b76f1c9cfeedfbb3f632ee4addda4294637a97`.

**Cost.** Peak memory 11.6 GB (M5 Pro, 24 GiB); about 1 h; 17.4 M trainable parameters (1.0%).

**Evaluation.**
- MLX 0.32.4 / mlx-lm 0.32.2 server, temperature 0, `enable_thinking=false`, no grammar.
- `run_eval.py` closed mode; `t1_compare.py` hybrid (L0 verdict + model explanation).

## Result (blind v2, 215 cases)

| Run | Hybrid explanation mention (n = 175) | McNemar vs base 1.7B | Romanian language (n = 53) | Canary-safe (n = 25) |
|---|---|---|---|---|
| **base 1.7B** | **0.720** | — | 0.981 | 0.760 |
| **ft 1.7B** | **0.657** | p = 0.099 (base better on 24, ft on 13) | 1.000 | **0.960** |
| base 0.6B | 0.543 | — | 0.887 | 0.880 |
| ft1 0.6B (T1) | 0.663 | — | 0.981 | 0.720 |
| ft2 0.6B (T1 v2) | 0.606 | — | 0.981 | 0.800 |

Model alone, base 1.7B → ft 1.7B:

| Metric | base 1.7B | ft 1.7B |
|---|---|---|
| Triage citations | 0.967 | **1.000** |
| Injection citations | 0.920 | **1.000** |
| Triage mention | 0.700 | 0.640 |
| Injection mention | 0.840 | 0.760 |
| Triage verdict | 0.400 | 0.380 |
| Injection verdict | 0.640 | 0.440 |
| Schema | 1.000 | 1.000 |
| Hallucinated entities | ≤ 0.02 | ≤ 0.02 |

The verdict is not used in hybrid mode. English-only mention, model alone: 0.713 → 0.656 (n = 122).

**Gate (doc 21): NOT PASSED.**

| Condition | Result |
|---|---|
| Mention ≥ 0.73 and better than base 1.7B | **0.657, and lower than base** ❌ |
| Canary-safe ≥ 0.96 | **0.960** ✅ |
| Romanian ≥ 0.9 | **1.000** ✅ |

## What this shows

1. **Fine-tuning on T0 makes the models safer but worse at explaining.** This holds at both sizes:
   - 1.7B: injection safety 0.76 → 0.96, citations → 1.00, but explanation mention 0.720 → 0.657;
   - 0.6B: ft1 → ft2 shows the same direction for mention.

   **The bottleneck is the T0 explanation data, not model size or hardware.** The likely mechanism, to be
   tested on the dev set rather than here: the strict filter keeps terse, template-like teacher answers.
   The no-echo rule and the teacher's "describe, don't quote" hint push summaries toward generic wording
   ("instruction-like text") instead of naming the attack.
2. **The base 1.7B is already close to the bar** (0.720, without grammar). A small, targeted data fix may
   be enough.
3. **Blind v2 difficulty is similar to v1.**
   - base 0.6B: 0.543 on v2 vs 0.583 on v1;
   - ft1: 0.663 vs 0.680;
   - ft2: 0.606 vs 0.634.
4. Per the pre-registration, **blind v2 is now spent**. Nothing may be tuned on it.

## Next (M5 only; English first)

All of the following runs on the **dev set** (`dev2`, 215 cases, SHA-256 `4d838542…1044`; 0 overlap with
blind v2, blind v1 and the training data). A final claim needs a sealed **blind v3**.

1. **Grammar.** Export the base and fine-tuned 1.7B to GGUF Q8_0 and score them with llama.cpp JSON-schema
   decoding, against MLX without a grammar.
2. **T0 v3 data, aimed at explanation quality.**
   - Keep safety: no-echo and canary checks.
   - Stop rewarding generic wording: the filter must require the attack class to be **named**.
   - Add the 301 real benign UNSW windows.
   - About 10% Romanian.
3. **Sweeps on dev:** epochs, learning rate, rank; and "safety-only" LoRA data mixes that keep the base
   model's explanation behaviour.
