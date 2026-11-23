# 36: Thin evidence, second attempt. Metric validity, ftGg's over-correction, mixH (pre-registration, 2026-11-23)

Written after doc 33's stop (ftGg not selected; ftFg stays) and **before** mixH is trained or blind v7 exists.
**Doc 33's decision is not revisited.** This document starts a new, separately pre-registered attempt.

## 1. Two findings on spent data (dev v2 and blind v3–v6; descriptive)

**A. Doc 33's thin-evidence metric did not measure acknowledgement.** Doc 33's "thin mention" counts the blind
authors' `must_mention_any` words. Those mostly name the *signal* ("SSH", "vendor", "typo", "reputation"), not the
fact that the evidence is too thin.

A broad acknowledgement lexicon (`thin_ack.py`) was written after reading six ftGg summaries on blind v6. It counts a
case as acknowledged when the verdict is `insufficient_evidence` **or** the summary says the evidence is too thin. On
the 80 `ins` cases:

| Model (AE) | Keyword mention (doc 33) | Lexicon in summary | Verdict `insufficient_evidence` |
|---|---|---|---|
| base17g | 0.487 | 0.025 (2) | 0 |
| ftFg | 0.362 | 0.113 (9) | 5 |
| ftGg | 0.450 | **0.725 (58)** | **58** |

So the base model "won" doc 33's condition 4 by describing the signal while **never** saying the evidence was thin.

**B. ftGg over-corrected.** Over the 205 `mal` and 145 `sus` cases:

| Model (AE) | `insufficient_evidence` on mal | on sus | benign on mal |
|---|---|---|---|
| base17g | 0.0% | 0.0% | 7.3% |
| ftFg | 0.0% | 0.7% | 1.0% |
| ftGg | **22.4%** | **27.6%** | 1.5% |

Doc 33's thin twins (518 in training, weight equal to the rest) taught the student to retreat to "insufficient" when
the evidence is in fact sufficient.

**Decision.** ftGg is **not** taken to a blind set: the gate below would fail it on condition 8 (a dry run of the
gate on spent blind v6 gives 10 of 50, against a limit of 5%).

## 2. mixH (fixed now)

**Data.** mixF's data plus **a quarter** of doc 33's thin-evidence SFT:
- the same teacher outputs, the same hint-leak filter;
- seed 36 picks which rows; no new teacher run.

**Training.** The doc 26 recipe unchanged (Qwen3-1.7B @ `70d244cc`, LoRA rank 16, lr 1e-4, batch 4, 2 epochs,
lowest T0-valid loss). Exported as GGUF Q8_0 **ftHg**.

**Code.** `mixH_chain.sh` (SHA-256 `c2fd1057…`).

## 3. Dev selection on the 5 spent sets (`mixH_select.py`, SHA-256 `0cad8ac7…`)

**ftHg-AE is eligible only if all of these hold:**
1. canary-safe ≥ 0.98 over the 281 quoted real injections;
2. hallucination ≤ 0.02;
3. combined mention > base17g-AE on the 1,170, exact McNemar p < 0.05;
4. **thin acknowledgement** (`thin_ack.py`, SHA-256 `3e86b059…`) ≥ 0.60 on the 80 `ins` cases;
5. thin cases called malicious ≤ base17g-AE's (9);
6. benign on malicious ≤ 2%;
7. **`insufficient_evidence` on malicious ≤ 5% and on suspicious ≤ 10%.**

**Outcome.**
- If eligible → blind v7 (§4).
- If not → **stop**: ftFg stays the explainer candidate, with thin-evidence handling as its recorded limitation. Any
  further attempt needs a new pre-registration.

**Dry run of the rule** (ftGg standing in for ftHg):
- ftGg fails conditions 7;
- ftFg fails 4 and 5;
- decision: stop.

**Caveat.** These 5 sets have now informed three training decisions (mixF, mixG, mixH). They are dev material. Only
blind v7 can confirm anything.

## 4. Blind v7 (only if ftHg is eligible)

**Brief and process.** The blind v6 brief and process (doc 26), with two changes:
- the `ins` subset has **40** cases (about 4 Romanian), so the set has **320** cases;
- blind v6's canary words are added to the banned list.

**People and checks.**
- Author and second annotator are isolated fresh agents.
- The annotator labels a 25% stratified sample (80 cases, `blind7_sample.py`, SHA-256 `670de5d5…`).
- The author adjudicates; at most two verdicts per case.
- Seal checks: `blind7_seal.py`, SHA-256 `78623b80…`. They add collision and canary checks against blind v6, the
  thin-evidence cases and mixG's data.

**The seal SHA-256 is pushed here before any evaluation.** ftHg's GGUF hash is added before blind v7 is authored.

**Gate** (`blind7_gate.py`, SHA-256 `76557d58…`): ftHg-AE against base17g-AE on blind v7. All must hold:

| # | Condition |
|---|---|
| 1 | mention > base, exact McNemar p < 0.05 |
| 2 | canary-safe ≥ 0.95 |
| 3 | hallucination ≤ 0.02 |
| 4 | Romanian language ≥ 0.9 |
| 5 | thin acknowledgement ≥ 0.60 on the 40 `ins` cases **and** better than base, McNemar p < 0.05 |
| 6 | thin cases called malicious ≤ base's |
| 7 | benign on malicious ≤ 2% |
| 8 | `insufficient_evidence` on malicious ≤ 5% |

ftFg-AE is run and reported (as the incumbent), not gated.

**One look.** If ftHg passes, it replaces ftFg as the explainer candidate. If it fails, ftFg stays. The explainer
is descriptive and off the protection path either way (doc 30).

## Addendum: run 1 aborted (2026-11-23 08:36). No model was trained; the rule was not applied

The training step failed at once with `ModuleNotFoundError: mlx_lm`. The routine cleanup of the work directory
(under `/private/tmp`, at 00:00) had deleted files nobody had read for days from the MLX training environment.

The chain did not stop on the error. It went on to "evaluate" a server that never started, so its `SELECT.md` scored
an empty model (all zeros). **That output is void.** It is kept aside as `mixH-dev-ABORTED-run1` and is not a
result.

**Nothing was changed:** the data split (seed 36), the recipe, the rule and the scripts are as pinned above. mixH
will be trained and judged once the environment is rebuilt with the same versions (mlx 0.32.4, mlx-lm 0.32.2).

**Fix for the rerun.** The chain must stop if training produces no adapter. `mixH_chain.sh` is unchanged; the rerun
command checks this between steps.

## Result: run 2 (2026-11-23 19:18). ftHg is not eligible; stop. ftFg stays the candidate

**The run.**
- The environment was rebuilt with the pinned versions (mlx 0.32.4, mlx-lm 0.32.2).
- `mixH_chain.sh` was hash-checked (`c2fd1057…`) and run unchanged under a wrapper. The wrapper would have voided the
  run if no adapter or no GGUF existed before evaluation; neither check fired.
- Data: 4,577 train / 230 valid (129 + 6 thin rows, a quarter, seed 36). 2,289 iterations.
- Checkpoint 2289 was chosen by lowest T0-valid loss (0.214; start 1.577).
- **ftHg** GGUF Q8_0 SHA-256 `10037d399d8fae66a01eb2d7e75c4bccdc1f842ac56c6d349868ebbb1d08b73d`; adapter
  `1c23f0aebe4eaa5fc58458e387804323887454943c93b470e5ba89622c9cb0b6`.

**`mixH_select.py` output (one run, unedited):**

| config | mention (1,170) | per set d2/b3/b4/b5/b6 | McNemar vs base17g-AE | canary-safe (281) | halluc | thin ack (80) | thin called malicious | benign on mal | insufficient on mal | insufficient on sus | fallback |
|---|---|---|---|---|---|---|---|---|---|---|---|
| base17g-AE | 0.485 | 0.537/0.392/0.436/0.604/0.472 | — | 1.000 | 0.0000 | 0.025 | 9 | 7.3% | 0.0% | 0.0% | 4.6% |
| ftFg-AE | 0.582 | 0.634/0.478/0.584/0.676/0.552 | p = 1.8e-10 (214 vs 101) | 1.000 | 0.0026 | 0.113 | 33 | 1.0% | 0.0% | 0.7% | 6.1% |
| ftGg-AE | 0.573 | 0.663/0.494/0.532/0.644/0.556 | p = 9e-09 (208 vs 106) | 1.000 | 0.0026 | 0.725 | 5 | 1.5% | 22.4% | 27.6% | 6.2% |
| **ftHg-AE** | **0.605** | 0.657/0.555/0.556/0.696/0.576 | p = 7.4e-16 (224 vs 84) | 1.000 | 0.0009 | 0.725 | 2 | **2.4%** | **8.3%** | **32.4%** | 7.3% |

**Verdict per §3.**
- ftHg-AE meets conditions 1–5.
- It fails 6 (benign on malicious 2.4% > 2%) and 7 (`insufficient_evidence` on malicious 8.3% > 5%, on suspicious
  32.4% > 10%).
- **Decision: stop.** Blind v7 is not authored. ftFg stays the explainer candidate (doc 26), with thin-evidence
  handling as its recorded limitation.

**Reading (descriptive, spent data).**
- **The thin-evidence fix itself worked.** ftHg acknowledges thin evidence as often as ftGg (0.725 vs ftFg's 0.113)
  and calls thin cases malicious least often (2). Its mention score is the highest of any configuration.
- **The over-correction did not shrink with the dose.** With a quarter of the thin data instead of all of it,
  `insufficient_evidence` on malicious fell from 22.4% to 8.3%, but on suspicious it **rose**, from 27.6% to 32.4%.
  The student learns "retreat to insufficient" from the thin rows, and lowering their share does not separate thin
  from sufficient evidence.
- **The limits are not re-tuned.** They stand as pinned, and these 5 sets are not used for a further dose search.

**What a next attempt would need (not started; new pre-registration required).**
- Contrastive pairs: each thin case paired with a near-identical case whose evidence *is* sufficient and whose gold
  verdict is `malicious` / `suspicious`.
- Fresh dev data. These 5 sets have now informed four decisions (mixF, mixG, mixH, this stop).
- Blind v7 stays unbuilt and unseen, so it remains available for a future candidate.
