# mixG dev results: doc 33 selection rule (2026-11-22)

**Outcome: STOP.** Neither candidate is eligible. There is no blind v7, and ftFg stays the explainer candidate (doc
26) with its thin-evidence limitation recorded.

Dev data: the 5 spent sets (dev v2 and blind v3–v6). All runs use guard AE.

`tools/neuro-research/mixG_select.py` output, unedited:

| config | mention (n) | per set d2/b3/b4/b5/b6 | McNemar vs base17g-AE | canary quoted | halluc | thin mention (80) | thin called malicious | benign on mal | fallback |
|---|---|---|---|---|---|---|---|---|---|
| base17g-AE | 0.485 (1170) | 0.537/0.392/0.436/0.604/0.472 | — | 1.000 (281) | 0.0000 | 0.487 | 9 | 7.3% | 4.6% |
| ftFg-AE | 0.582 (1170) | 0.634/0.478/0.584/0.676/0.552 | p=1.8e-10 (214 vs 101) | 1.000 (281) | 0.0026 | 0.362 | 33 | 1.0% | 6.1% |
| ftGg-AE | 0.573 (1170) | 0.663/0.494/0.532/0.644/0.556 | p=9e-09 (208 vs 106) | 1.000 (281) | 0.0026 | 0.450 | 5 | 1.5% | 6.2% |
ftGg-AE: NOT eligible (thin 0.450 < base 0.487)
ftFg-AE: NOT eligible (thin 0.362 < base 0.487)
selected: NONE
decision: STOP: no blind v7; ftFg stays the candidate (doc 26) with its limitation recorded

## Reading

**Why it stopped.** ftGg fails exactly one condition: thin-evidence mention is **0.450 (36/80)** against base17g's
**0.487 (39/80)**. Every other condition passes:
- combined mention 0.573, p = 9e-09 vs base;
- canary 1.000 over 281;
- hallucination 0.0026;
- benign verdict on malicious cases 1.5%.

**Thin windows: verdict changed, explanation did not.** Verdict distribution on the 80 `ins` cases, from the JSON
`verdict` field (reported, not part of the rule):

| Model | insufficient_evidence | suspicious | benign | malicious |
|---|---|---|---|---|
| base17g-AE | 0 | 65 | 6 | 9 |
| ftFg-AE | 5 | 38 | 4 | 33 |
| ftGg-AE | **58** | 14 | 3 | **5** |

- The thin twins fixed the over-calling: malicious verdicts dropped from 33 to 5.
- They did not fix the written explanation. The pre-registered metric is the summary naming the thin-evidence
  reasons, and that stayed below base.
- **The rule is applied as written.** It is not reinterpreted after seeing this.

**ftGg vs ftFg elsewhere.**
- Combined mention is slightly lower for ftGg (0.573 vs 0.582).
- E fallbacks are similar (6.2% vs 6.1%).

## Artefacts

| Item | SHA-256 |
|---|---|
| ftGg GGUF Q8_0 (`gguf-mixG-q8_0.gguf`) | `bee88b53e1e29d287591e47148b4e30e9a33ced6d67d3195bb0ef61392a544e8` |
| ft-mixG adapter (checkpoint 2200, valid 0.226) | `91e06eb6704189a62d76555389d84eb1ac9ecd70c09681047a23fd7771097d5c` |
| thin-evidence cases `t0v3t_cases.jsonl` (600; seed 3303) | `11d02c4cbb816f266aa64c0592c334e78c4d27df88e8ce21f028a56bfe30379e` |
| mixG train (4,966) | `fe8c5348c16af16ec82f51c350d2a4b2c30db294bfc61a6ed3be4e54859aa709` |
| mixG valid (251) | `dc049c61c2a983bb650f91b0d2dd77c3d76265280ce4c1fde3bfec2e42f78902` |
| `mixG_select.py`, identical to the committed copy | `4026fa004abf1c174acbf6c39fb8d6408c51e575d57e999027779b01da930849` |

**Data and training.**
- Teacher: Qwen3-14B Q4_K_M, guard A, with the teacher-only hint.
- The hint-leak filter kept 518/520 train and 27/27 valid.
- Prompts with a raw quoted value: 0.
- Recipe as doc 26: 2,483 iterations, best checkpoint 2200 by T0-valid loss.
- E fallbacks per set: d2 4/215, b3 16/300, b4 20/300, b5 27/300, b6 21/300.
