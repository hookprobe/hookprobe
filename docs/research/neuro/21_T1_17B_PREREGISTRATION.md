# 21 — T1-1.7B pre-registration: a fresh sealed blind set (v2), then Qwen3-1.7B specialised

> 2026-11-20. **Committed before blind v2 exists, before the 1.7B is downloaded, and before any number.**
> Operator decision: start blind v2 and fine-tune the 1.7B. Plan: `16` (T1).
>
> **Why.** Two 0.6B attempts failed the T1 gate on blind v1:
>
> | Metric | 0.6B results | Gate |
> |---|---|---|
> | Hybrid mention | 0.680 / 0.634 | ≥ 0.73 |
> | Canary-safe | 0.88 / 0.92 | ≥ 0.96 |
>
> Blind v1 is spent (`data/t0v2-results.md`).

## Frozen before blind v2 exists

**Training data.** T0 v2 SFT set (`data/t0v2-results.md`), unchanged:

| File | Examples | SHA-256 |
|---|---|---|
| `train.jsonl` | 3,262 | `cd7b173248bbd0f82b49954a52a73a633f8ad17ea97549449bbeecdf406b6d26` |
| `valid.jsonl` | 171 | `c80dd6a34bd8f45ca004d7cd6e939ff1bce9d6416174bc1c0af55103e3d2598f` |

The sources are `t0.jsonl` (`a8ee7900…f686`) and `v2.jsonl` (`c918d875…b158`). **No training-data change
is allowed after this commit.**

**Student.** `Qwen/Qwen3-1.7B`, revision `70d244cc86ccca08cf5af4e1e306ecf908b1ad5e`, Apache-2.0. File
SHA-256s are recorded at download.

**Recipe** (chosen by the memory budget of a 24 GiB M5 Pro, not by any result):

| Setting | Value |
|---|---|
| Framework | MLX 0.32.4 / mlx-lm 0.32.2 |
| Method | **LoRA** (`--fine-tune-type lora`) on all layers (`--num-layers -1`), rank 16, mlx-lm default scale and dropout |
| Learning rate | 1e-4 |
| Batch | 4 |
| Max sequence | 2048 |
| Flags | `--grad-checkpoint`, `--mask-prompt` |
| Iterations | 1,631 (≈ 2 epochs) |
| Validation | every 200 iterations, 25 batches; the adapter is saved at each evaluation |
| Checkpoint selection | the lowest **T0-valid** loss. Blind v2 never selects. |

A full fine-tune is excluded: weights, gradients and Adam state for 1.7B take about 20 GB.

**Out-of-memory ladder** (applied in order, only if the smoke run fails):
1. max sequence 1536;
2. batch 2 with gradient accumulation 2;
3. rank 8.

**Divergence stop.** If the validation loss at iteration 400 is above its iteration-1 value, stop and
report.

## Blind v2: how it is made and sealed

1. **Author.** A fresh agent with **no repository access** writes 215 cases by hand.
   - Its only input is `data/blind2-brief.md`.
   - It uses the same subset mix as v1 and new canary tokens. The v1 tokens are banned.
   - It works in a scratch directory outside the repository.
   - I do not read the cases.
2. **Second annotator.** Another fresh agent receives a **25% stratified sample** (54 cases): context and
   question only, without gold.
   - It labels verdict, `next_step`, and tool or copilot facts.
   - A script computes agreement against gold.
   - The author agent adjudicates disagreements and records notes in its README.
   - Agreement is reported, not gated, **unless it is below 0.6 on verdicts**. Then the set is returned to
     the author once for revision, before sealing.
3. **Seal checks** (scripts; any failure stops):
   - schema loads in `run_eval.py`;
   - 215 cases in the brief's mix;
   - **0** normalised-context hash collisions with `eval/cases.jsonl`, blind v1, `t0.jsonl` and `v2.jsonl`;
   - **no** blind v2 canary appears anywhere in the training files.
4. **Seal.** The file's SHA-256, its counts and the agreement rate are added to this document in a commit
   **before any model is evaluated**. The case file itself is committed after the evaluation.

## Evaluation: one session, one look

**Conditions.**
- `run_eval.py` unchanged: closed mode, `--max-tokens 700`.
- `mlx_lm.server` at temperature 0 with `enable_thinking=false`.
- No grammar, because MLX has none: the same conditions as T1.
- The pipeline re-hashes blind v2 and must match the seal.

**Runs, all on blind v2 in one session:**

| Model | Role |
|---|---|
| base 0.6B, ft1 0.6B, ft2 0.6B | difficulty calibration against v1 (reported, not gated) |
| **base 1.7B** | the comparison |
| **ft 1.7B** | the candidate |

`t1_compare.py` computes hybrid mention (L0 verdict + model explanation), Romanian language, canary-safe
(summary and whole answer), and McNemar.

**Gate. T1-1.7B passes only if all three hold:**
1. hybrid explanation mention **≥ 0.73**, **and** better than base 1.7B by McNemar p < 0.05;
2. canary-safe (summary) **≥ 0.96**;
3. Romanian language **≥ 0.9**.

**Stop rule.** One look. Whatever the result, blind v2 is not used to change anything afterwards. A
further attempt needs a blind v3.

## What a pass would and would not mean

**A pass:** a specialised 1.7B explains the deterministic core's verdicts well and safely enough to be
**the explainer**.

**What it does not mean:**
- **On-device.** At Q4, 1.7B is about 1.1 GB. It cannot run inside heqk's 4 MiB EL0 window. Until an
  on-device runtime exists it is an **off-device / companion-tier** explainer (ADR 0044 D3).
- **That the "≤ 40% of the 1.7B's bytes" goal of `16` is met.** It is dropped here, deliberately.
- **Field quality.** Blind v2 is synthetic and hand-written. A lived-in home (P7) is still needed.

## Notes added before blind v2 exists

**Seal-check self-test on blind v1** (spent, so it was safe to inspect). The script found two things:
1. Harmless look-alike injection cases legitimately carry no canary. The check was relaxed to allow them.
2. **One v1 canary, `VERIFIED-SAFE`, occurs in the T0 training files.** It is a generic phrase.
   - The blind v2 brief already bans it.
   - In the T1 / T1 v2 results it could only have **lowered** the 0.6B models' v1 canary-safe score,
     never raised it.
   - Disclosed here for completeness.

**Smoke run** (frozen recipe, 50 iterations; no blind v2):
- peak memory footprint 11.2 GB of 24 GiB, so no out-of-memory step was needed;
- 17.4 M trainable parameters (1.0%);
- about 2.1 s per iteration;
- T0-valid loss 1.339 → 0.439.

**Download.** `Qwen/Qwen3-1.7B` @ `70d244cc`: 12 files, each verified against Hugging Face's LFS SHA-256
or git blob SHA-1. Recorded in `provenance.json`.
