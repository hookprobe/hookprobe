# 55: Routing by turn: ftM for the first check, ftT after a result (pre-registration, 2026-11-28)

Written **before** inv-blind v7 exists. **No new model:** ftM (doc 44) and ftT (doc 54) are used as they are.

## 1. Why

Doc 54 ([`data/mixT-results.md`](data/mixT-results.md)), inv-blind v6, spent:

| | next (45) | multi (35) | next+multi |
|---|---|---|---|
| ftM | 0.733 | 0.114 | 0.463 |
| ftT | 0.644 | 0.286 | 0.487 |

ftT is better after a result and worse at the first check. The two decisions can be separated by construction. The
harness knows whether it is writing a RESULT line into the context (#1615), so it can route without a model:

> **router(context)** = ftT if the context has a line starting `RESULT `, otherwise ftM.

- **No RESULT line** (first checks, alerts, decoys, invisible): the answer is ftM's, so it cannot regress.
- **A RESULT line** (multi, clears): the answer is ftT's.
- **On the device:** two LoRA adapters on one base (llama.cpp loads several and picks per request), or two GGUFs.
  That is a Conductor and operator decision if this passes.

**Disclosure:** the gate script's mechanics dry run on doc 54's **spent** inv-blind v6 outputs prints PASS (the verdict
line was the only output read). That is post-hoc on a spent set and is **not evidence**; it is why this doc exists.
The test is the fresh, sealed inv-blind v7.

## 2. Gate (`mixU_gate.py`, one look, the router against ftMg)

| # | Condition |
|---|---|
| 1 | `multi` (35): router > ftMg **and** next+multi (80): router > ftMg |
| 2 | `clears` (30): router ≥ ftMg − 0.05 (clears have a RESULT line, so ftT answers them) |
| 3 | on every case without a RESULT line, the router's answer equals ftMg's, byte for byte (checked) |
| 4 | 0 unreturned CVE ids; invented technique ids ≤ 2%; no policy proposal on a decoy |

Reported: base17g, ftMg, ftTg and the router on every row; McNemar router vs ftMg on next+multi.

**Pass:** routing by turn is proposed to the Conductor (harness) and the operator (two adapters). **Fail:** ftM
alone stays.

**E2E (operator rule):** the fixture's investigation turn has no RESULT line, so the router answers with ftM: run 7's
calls by construction. A multi-turn E2E needs the harness turn loop (#1615) with real tool results. It is reported
when that exists.

## 3. inv-blind v7

- **Brief:** `data/inv-brief-v7.md`, SHA-256 `382a45f19dfa4aa128bfce65654ddd36a5be604d8fbaaeb7d47d12960bdd55c5`. It is
  v6's brief, unchanged except for the title.
- **People:** a new isolated author and a new isolated annotator (44-case sample).
- **Seal:** collisions are checked against inv-blind v1–v6 and the gen v4–v7 case files.

## 4. Pinned

| File | SHA-256 |
|---|---|
| `mixU_chain.sh` | `7171e2ea9ec3490ea9c1ff11edce480c04ff83be1b359c1f8dd1361180381d79` |
| `mixU_gate.py` | `b04c51311c4061730f34e021b3fbf76445f565111e159da853cf895516354396` |
| `data/inv-brief-v7.md` | `382a45f19dfa4aa128bfce65654ddd36a5be604d8fbaaeb7d47d12960bdd55c5` |
| ftMg / ftTg GGUF | `9576cfac…` / `40fd46d4…` (checked by the chain) |
| `inv_eval.py`, `inv_seal.py` | unchanged since doc 44 / doc 49 |

## 5. Limits

- **Two adapters cost memory or a swap on the device.** Cost and latency are not measured here.
- **The route trusts the RESULT line.** Telemetry that forged a `RESULT ` line would switch adapters. The harness
  writes RESULT lines itself after guard A, and card text never starts a line with `RESULT`, so the route must be
  taken from the harness's own state, not by parsing the context. The gate parses it only because the cases are text.
- multi is 35 cases and clears is 30.

## 6. Seal (2026-11-28, before any model has seen the set)

- `blind_cases.jsonl` SHA-256 **`d96660dbfebe7c2e89fa3fc2748eccf97adb1bc18d7f33a154150bd71085607d`**.
- **Mix:** next 45, multi 35, clears 30, decoy 25, invisible 15, alert 25 (175 cases); 21 Romanian (12.0%).
- **Seal checks: PASS.** 0 collisions with inv-blind v1–v6 and the gen v4–v7 case files.
- **Second annotator** (isolated, 44-case sample): **44/44**, so nothing needed adjudication. It flagged 8 cases as
  genuinely ambiguous.

## 7. Result (2026-11-28, one look)

**VERDICT: FAIL** (condition 2: clears 0.700, below the floor of 0.783).
- Passed:
  - multi 0.286 vs ftM's 0.029;
  - next+multi 0.550 vs 0.438, McNemar p = 0.012 (10 vs 1);
  - the router equals ftM on every case without a RESULT line;
  - grounding clean.
- ftT stops less often when a result clears the signal.
- The next design is the router plus Rule P's deterministic "cleared → stop" rule, which needs typed tool outcomes
  (doc 53 R13).

ftM stays. Full tables: [`data/mixU-results.md`](data/mixU-results.md).
