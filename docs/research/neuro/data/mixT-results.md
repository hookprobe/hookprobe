# mixT results (doc 54): doc 51 re-run with the generator's move-on targets fixed

**Verdict: FAIL** (condition 2 only). ftM stays the investigation adapter. Pre-registration:
[`54_INVESTIGATION_FIXED_TARGETS_PREREGISTRATION.md`](../54_INVESTIGATION_FIXED_TARGETS_PREREGISTRATION.md).
Inv-blind v6 was looked at once, by script, on 2026-11-28. It is now spent.

## Gate (inv-blind v6, 175 cases, guard A)

| model | next+multi (80) | next (45) | multi (35) | alert (25) | decoy exact (25) | invisible (15) | grounding | policy on decoy | tool calls |
|---|---|---|---|---|---|---|---|---|---|
| base17g | 0.100 | 0.156 | 0.029 | 0.120 | 0.440 | 0.933 | clean | 0 | 107 |
| ftMg (incumbent) | 0.463 | 0.733 | 0.114 | 0.720 | 0.720 | 0.933 | clean | 0 | 112 |
| **ftTg** | **0.487** | **0.644** | **0.286** | 0.720 | 0.720 | 0.933 | clean | 0 | 105 |

| # | Condition | ftTg | |
|---|---|---|---|
| 1 | multi > ftM **and** next+multi > ftM | 0.286 > 0.114; 0.487 > 0.463 | PASS |
| 2 | next ≥ ftM − 0.05 | **0.644** vs 0.683 | **FAIL** |
| 3 | alert ≥ ftM − 0.05 | 0.720 = 0.720 | PASS |
| 4 | decoy ≥ ftM − 0.05 | 0.720 = 0.720 | PASS |
| 5 | invisible ≥ 0.80 | 0.933 | PASS |
| 6 | grounding / policy on decoy | 0 / 0 / 0 | PASS |

McNemar ftTg vs ftMg on next+multi (reported): p = 0.82 (11 vs 9).

## What it means

| | first check lost (of 45) | multi gained (of 35) | next+multi vs ftM |
|---|---|---|---|
| doc 51, wrong targets (ftS, inv-blind v5) | 7 | 2 | lower |
| **doc 54, fixed targets (ftT, inv-blind v6)** | **4** | **6** | **higher** |

- **The defect mattered.** With correct targets the multi-step gain tripled, from 2 to 6 cases, and the first-check
  loss fell from 7 to 4 cases. Docs 49/51's "multi-step training itself costs the first check" was largely the
  defect.
- **A residual cost remains.** Four first checks were lost, just over the pre-registered 0.05 margin. This is the first
  candidate whose next+multi beats ftM's. Alert, decoy and invisible are unchanged.
- **Where it points:** the first check and the step after a result can be separated by construction, so neither can
  cost the other.
  - Either Rule P (doc 52; typed outcomes needed, doc 53 R13),
  - or routing by turn: ftM when the context has no RESULT line, ftT when it has one. This needs no kernel change,
    because the harness knows whether it is writing a RESULT.

  Either needs its own pre-registration and a fresh set. Inv-blind v6 is spent and cannot choose between them.

## Training

- **Data:** ftM's adapter (`5cc933ba…`, re-export checked) continued on 1,165 train / 62 valid rows.
  - 595 + 32 are ftM's own rows without a RESULT line, byte for byte.
  - 570 + 30 are gen v7 multi/clears rows (seed 5401; 148 move-on cases, 0 contradicting the playbook).
- **Training:** 1 epoch, 292 iterations, learning rate 5e-5. Selected checkpoint: 200 (valid 0.018; 0.429 at step
  1).
- **Artefacts:** adapter `2cfa410388984d617be3f0f5f1f871feac765fac097010e15bf5878fd6d13b39`; GGUF q8_0
  `40fd46d4730a4c63defb8dbb90e445b6cb4374eb307d3ef15490428d06b765ea`.
- **Run:** 02:45 → 03:04 on 2026-11-28, from the frozen worktree at `1e00053c` (the pre-registration commit).

## End to end: run 13 (ftFg triage, ftTg investigation)

| Alert | run 7 (ftM) | run 12 (ftS) | run 13 (ftT) | Expected |
|---|---|---|---|---|
| Telnet scan | `query_flows` H1 | `query_flows` H1 | **`query_flows` H1** | ✅ |
| SSH brute force | `lookup_reputation` R1 | `lookup_reputation` R1 | **`lookup_reputation` R1** | ✅ |

The investigation turn's median is 0.37 s.
