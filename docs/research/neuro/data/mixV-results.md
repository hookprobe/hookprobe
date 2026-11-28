# mixV results (doc 56): router plus Rule P's stop rule

**Verdict: PASS.** Pre-registration:
[`56_INVESTIGATION_ROUTER_STOP_RULE_PREREGISTRATION.md`](../56_INVESTIGATION_ROUTER_STOP_RULE_PREREGISTRATION.md).
Inv-blind v8 was looked at once, by script, on 2026-11-28. It is now spent. No model was trained.

## Gate (inv-blind v8, 175 cases, 65 with a RESULT line, guard A)

| model | next+multi (80) | next (45) | multi (35) | clears (30) | alert (25) | decoy (25) | invisible (15) | CVE / T-id / policy on decoy | tool calls |
|---|---|---|---|---|---|---|---|---|---|
| base17g | 0.237 | 0.311 | 0.143 | 0.733 | 0.160 | 0.520 | 0.600 | 0 / 0 / 0 | 95 |
| ftMg | 0.487 | 0.778 | 0.114 | 0.833 | 0.760 | 0.880 | 1.000 | 0 / 0 / 0 | 95 |
| ftTg (reported) | 0.588 | 0.689 | 0.457 | 0.533 | 0.720 | 0.880 | 1.000 | 0 / 0 / 0 | 103 |
| router, doc 55 (reported) | 0.637 | 0.778 | 0.457 | 0.533 | 0.760 | 0.880 | 1.000 | 0 / 0 / 0 | 110 |
| **system** | **0.637** | 0.778 | **0.457** | **0.967** | 0.760 | 0.880 | 1.000 | 0 / 0 / 0 | 97 |

| # | Condition | system | |
|---|---|---|---|
| 1 | multi > ftM and next+multi > ftM | 0.457 > 0.114; 0.637 > 0.487 | PASS |
| 2 | clears ≥ ftM − 0.05 | 0.967 vs 0.783 | PASS |
| 3 | equal to its route (ftM without a RESULT line, ftT with one and no `clears`) | identical (checked) | PASS |
| 4 | grounding / policy on decoy | 0 / 0 / 0 | PASS |
| 5 | stop rule fires on ≤ 2 multi cases | 0 | PASS |

- McNemar system vs ftMg on next+multi (reported): **p = 0.0018** (13 vs 1).
- **Typed outcomes by kind (reported):**
  - clears cases: 30 `clears`, 1 `none`;
  - multi cases: 33 `supports`, 13 `none`, 0 `clears`.
- **Where the stop rule fired:** 29 of the 30 clears cases, and nowhere else.

## What it means

- **The two halves combine as designed.**
  - ftT takes the step after a supporting result: multi 0.114 → 0.457 (+12 cases).
  - The stop rule takes the step after a clearing result: clears 0.533 (ftT alone) → 0.967.
  - Everything without a RESULT line is ftM's, byte for byte.
- **The doc 55 failure is fixed exactly where doc 55 placed it.** The router alone scored 0.533 on clears here (0.700 on
  v7). With the stop rule it scores 0.967, above ftM's 0.833.
- **The typed outcomes split cleanly by kind.** The labeller never marked a result in a multi case as `clears`. That
  supports R13's premise: a result sentence on its own says whether it explains the signal away. But the author wrote
  clears sentences to explain the signal away (doc 56 §5), so real tool outcomes may be noisier. **This result is an
  upper bound until tools return typed outcomes themselves.**
- **Also reported, not gated:** ftT alone scored next 0.689, below ftM's 0.778. The router keeps ftM there.

## Chain note

The chain ran from a copy of `tools/neuro-research` under `~/.cache/hookprobe-neuro/w/mixV/tools`. The three model
runs completed, but the gate stopped before printing anything: `eval/grounding.py` finds `attack-ids.json` by a
path relative to the repository. The same pinned `mixV_gate.py` (SHA-256 `b8019f94…`, identical in both places) was
then run once from the repository checkout, on the same run files, after re-checking both seal hashes. That run is
the one look reported above.

## E2E (operator rule)

No model changed. The fixture's investigation turn has no RESULT line, so the system answers with ftM: run 7's calls,
by construction (condition 3 checks this routing on all 110 cases without a RESULT line). A multi-turn E2E needs the
harness turn loop with typed tool results. It is reported when that exists.
