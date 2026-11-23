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
