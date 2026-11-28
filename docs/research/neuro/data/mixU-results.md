# mixU results (doc 55): routing by turn

**Verdict: FAIL** (condition 2: clears). ftM alone stays. Pre-registration:
[`55_INVESTIGATION_ROUTING_BY_TURN_PREREGISTRATION.md`](../55_INVESTIGATION_ROUTING_BY_TURN_PREREGISTRATION.md).
Inv-blind v7 was looked at once, by script, on 2026-11-28. It is now spent. No model was trained.

## Gate (inv-blind v7, 175 cases, 65 with a RESULT line, guard A)

| model | next+multi (80) | next (45) | multi (35) | clears (30) | alert (25) | decoy (25) | invisible (15) | CVE / T-id / policy on decoy | tool calls |
|---|---|---|---|---|---|---|---|---|---|
| base17g | 0.100 | 0.156 | 0.029 | 0.600 | 0.080 | 0.400 | 1.000 | 0 / 0 / 0 | 105 |
| ftMg | 0.438 | 0.756 | 0.029 | **0.833** | 0.880 | 0.840 | 1.000 | 0 / 0 / 0 | 106 |
| ftTg (reported) | 0.537 | 0.733 | 0.286 | 0.700 | 0.920 | 0.880 | 1.000 | 0 / 0 / 0 | 100 |
| **router** | **0.550** | 0.756 | **0.286** | **0.700** | 0.880 | 0.840 | 1.000 | 0 / 0 / 0 | 104 |

| # | Condition | router | |
|---|---|---|---|
| 1 | multi > ftM and next+multi > ftM | 0.286 > 0.029; 0.550 > 0.438 | PASS |
| 2 | clears ≥ ftM − 0.05 | **0.700** vs 0.783 | **FAIL** |
| 3 | without a RESULT line, identical to ftM | identical (checked) | PASS |
| 4 | grounding / policy on decoy | 0 / 0 / 0 | PASS |

McNemar router vs ftMg on next+multi (reported): **p = 0.012** (10 vs 1). This is the first significant gain on the
investigation step in docs 43–55.

## What it means

- **Routing works where it was aimed.**
  - The first check, alerts, decoys and invisible cases are ftM's by construction (checked byte for byte).
  - The step after a supporting result is ftT's: multi 0.029 → 0.286 (+9 cases).
- **ftT is worse at stopping.** When a result **clears** the signal, ftT checks again more often than ftM (0.700 vs
  0.833, 4 cases). That is the price that failed the gate.
- **The two remaining decisions after a result are complementary:**
  - "cleared → stop" is exactly Rule P's first rule (doc 52), deterministic once the tool says `clears`;
  - "supported → next check or policy" is what ftT now does better than ftM.

  So **router + Rule P's stop rule** would keep ftT's multi gain without its clears loss. That needs typed tool outcomes
  (doc 53 R13), a pre-registration and a fresh set. Inv-blind v7 is spent.
- **Also reported, not gated:** ftT alone scored next 0.733 here (within 0.05 of ftM's 0.756), against 0.644 on
  inv-blind v6. Per-set swings of several cases are normal at n = 45.

## E2E

The fixture's investigation turn has no RESULT line, so the router answers with ftM: run 7's calls (`query_flows` H1,
`lookup_reputation` R1) by construction. No new model, so no new run. A multi-turn E2E needs the harness turn loop
with real tool results.

## Run

2026-11-28, 03:07 → 03:25, frozen worktree `4137dde3` (the pre-registration commit). ftMg `9576cfac…` and ftTg
`40fd46d4…` were checked by the chain.
