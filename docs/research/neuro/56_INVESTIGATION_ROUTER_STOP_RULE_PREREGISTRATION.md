# 56: Router plus Rule P's stop rule (pre-registration, 2026-11-28)

Written **before** inv-blind v8 exists. **No new model:** ftM (doc 44) and ftT (doc 54) are used as they are. Typed
tool outcomes (doc 53 R13) are not decided yet; here they are simulated by a labeller (§3), so a PASS shows what the
design is worth **if** tools return them.

## 1. Why

Doc 55 ([`data/mixU-results.md`](data/mixU-results.md)), inv-blind v7, spent:

| | multi (35) | next+multi (80) | clears (30) |
|---|---|---|---|
| ftM | 0.029 | 0.438 | 0.833 |
| router (ftT after a RESULT line) | 0.286 | 0.550 (p = 0.012) | 0.700 |

The router failed only because ftT checks again too often after a result that **clears** the signal. That case is
exactly Rule P's first rule (doc 52, [`l0_playbook.py`](../../../tools/neuro-research/l0_playbook.py)): any result
that clears it → stop. It is deterministic once the tool says `clears`. So:

> **system(context)** =
> - no tool call, if any RESULT line's typed outcome is `clears`;
> - otherwise ftT, if the context has a RESULT line;
> - otherwise ftM.

- **Only rule 1 of Rule P is used.** Rules 2–3 also need the playbook id, which for L1 alerts comes from `dev=`
  (doc 53 R10); they are not tested here.
- **No RESULT line:** the answer is ftM's, as in doc 55.
- **On the device:** the harness writes RESULT lines itself, after guard A, and would hold each tool's typed outcome
  beside it. The stop decision is taken from that state, never by parsing context text (doc 55 §5).

**Disclosure:** the gate's mechanics were dry-run on the **spent** inv-blind v7 with **random** outcome labels, with
all output discarded. Only the exit codes and the presence of a verdict line were read. No result from v7 informs
this design beyond doc 55's published table.

## 2. Gate (`mixV_gate.py`, one look, the system against ftMg)

| # | Condition |
|---|---|
| 1 | `multi` (35): system > ftMg **and** next+multi (80): system > ftMg |
| 2 | `clears` (30): system ≥ ftMg − 0.05 |
| 3 | without a RESULT line the system's answer equals ftMg's, and with one and no `clears` outcome it equals ftTg's, byte for byte (checked) |
| 4 | 0 unreturned CVE ids; invented technique ids ≤ 2%; no policy proposal on a decoy |
| 5 | the stop rule fires on at most 2 of the 35 `multi` cases |

- Condition 5 is new. A labeller that marked supporting results as `clears` would win the clears row by losing
  multi cases. The gate refuses that trade even when condition 1 still holds.
- **Reported, not gated:**
  - base17g, ftMg, ftTg, the doc 55 router and the system on every row;
  - McNemar system vs ftMg on next+multi;
  - outcome labels by kind, and where the stop rule fired.

**Pass:** router plus stop rule is proposed to the Conductor (harness) and to HomePods and the operator. That makes
R13 a concrete requirement: each read-only tool returns `supports`, `clears` or `none` beside its sentence.
**Fail:** ftM alone stays.

**E2E (operator rule):** the fixture's investigation turn has no RESULT line, so the system answers with ftM: run 7's
calls by construction. A multi-turn E2E needs the harness turn loop with real typed tool results. It is reported when
that exists.

## 3. inv-blind v8 and its typed outcomes

- **Author brief:** [`data/inv-brief-v8.md`](data/inv-brief-v8.md), SHA-256
  `a7a9f8f53eefd1ef62a249ea8ad87e3d07eef89037228441c9696440737db10c`. It is v7's brief, unchanged except for the
  title, so the set is drawn the same way as the one doc 55 failed on.
- **People:** a new isolated author and a new isolated annotator (44-case sample), as for v7.
- **Typed outcomes:** a third isolated agent, the labeller, briefed by
  [`data/inv-outcome-brief-v1.md`](data/inv-outcome-brief-v1.md) (SHA-256
  `f2dccf1764bae4877dc9270e25a736f1857c058ba166e49696f9943db7c43a15`).
  - `inv_outcomes.py extract` gives it each RESULT line **alone**: tool, alias and sentence, under a random key,
    shuffled.
  - It never sees the case id (which names the kind), the rest of the context, the question or the gold. That is how a
    tool would type its own result.
  - `inv_outcomes.py merge` refuses unless every line has exactly one valid label.
- **Seal:** `SEALED` holds two SHA-256 values, of `blind_cases.jsonl` and of `outcomes.json`. Both are recorded here
  before any model sees the set. Collisions are checked against inv-blind v1–v7 and the gen v4–v7 case files.

## 4. Pinned

| File | SHA-256 |
|---|---|
| `mixV_chain.sh` | `f5245fc00a43f0e5be65fc93026d28714c04d0e10aa1608c0668136b9aa32a6e` |
| `mixV_gate.py` | `b8019f9489d6a2178e0b5d41f791b8c21d8d1ef92fdc29f307cf36269a49d276` |
| `inv_outcomes.py` | `549a5361a1691d7ba2a7e4d043b64c7443d3930d707cba92d756fc2508706608` |
| `data/inv-brief-v8.md` | `a7a9f8f53eefd1ef62a249ea8ad87e3d07eef89037228441c9696440737db10c` |
| `data/inv-outcome-brief-v1.md` | `f2dccf1764bae4877dc9270e25a736f1857c058ba166e49696f9943db7c43a15` |
| ftMg / ftTg GGUF | `9576cfac…` / `40fd46d4…` (checked by the chain) |
| `inv_eval.py`, `inv_seal.py`, `l0_playbook.py` | unchanged since doc 44 / doc 49 / doc 52 |

## 5. Limits

- **The outcomes are a labeller's, not a tool's.** A real tool types its result from its own data (a blocklist hit,
  a vendor-range match, an owner-confirmed job). Whether tools can do that as reliably is R13's question, not this
  gate's. If real outcomes are noisier, this result is an upper bound.
- **The author wrote the result sentences knowing the kind.** A clears case's sentence is written to explain the
  signal away, so it may be easier to type than a real tool's output. The labeller's blindness to kind and context
  limits that, but does not remove it.
- **Rule P's stop is all or nothing.** One `clears` anywhere stops the investigation, even after supporting results.
  The labels-by-kind report shows how often that happens on multi cases. Condition 5 caps it.
- **Two adapters** (ftM, ftT) cost memory or a swap on the device. Not measured here.
- multi is 35 cases and clears is 30.

## 6. Seal (2026-11-28, before any model has seen the set)

- `blind_cases.jsonl` SHA-256 **`4b5e3511ef13d9eeed7b22ad741fe263d2de75fd7765035dd90e8a5da50f4e72`**.
- `outcomes.json` SHA-256 **`4c831b2d74a5b070b3da58df5d70454890e9a4a132f011a58c9b4c7b3852eafc`**.
- **Mix:** next 45, multi 35, clears 30, decoy 25, invisible 15, alert 25 (175 cases); 21 Romanian (12.0%).
- **Seal checks: PASS.** 0 collisions with inv-blind v1–v7 and the gen v4–v7 case files.
- **Second annotator** (isolated, 44-case sample): 43/44. The author adjudicated the one disagreement and added
  the annotator's answer to that case's acceptable answers (only that case's gold changed; all 77 RESULT lines were
  checked unchanged by script). After adjudication: 44/44. The annotator marked 17 of the 44 as genuinely ambiguous.
- **Typed outcomes** (isolated labeller, 77 RESULT lines in 65 cases, each seen alone): supports 33, clears 30,
  none 14. How they fall by kind is reported only by the gate.
