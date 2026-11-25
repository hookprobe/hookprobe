# 47: The doc 46 delta with balanced verdicts (pre-registration, 2026-11-25)

Written **before** blind v11, the new training component or the candidate model exists. Doc 46's aggregate result
and its own training data (never a blind case) shaped this design.

## 1. What doc 46 measured

[`data/mixP-results.md`](data/mixP-results.md), blind v10, one look:

| | ftFg | ftP (doc 46) | ftP0 (replay only) |
|---|---|---|---|
| `alb` in gold | 0.200 | **0.633** | 0.233 |
| `alm` in gold | 0.867 | **0.733** | 0.833 |
| `mal` called insufficient (of 40) | 0 | **11** | 2 |
| `ins` called malicious | 7 | 0 | 7 |

- **The method works.** An exact rebuild of ftFg plus a delta, anchored with ftFg's own scorer-accepted answers,
  holds the incumbent; ftP0 stayed close to ftFg.
- **The delta over-corrected toward caution.** Its training data, by verdict and card kind (doc 46 train split):

| Component | Card | attack (malicious/suspicious) | not (benign/insufficient) |
|---|---|---|---|
| alert, alertc | generic alert | 772 | 344 |
| albx | generic alert | 0 | 551 |
| paira | generic alert | 181 | 189 |
| **pair** | **named detection** | 142 (+47 without one) | **87 thin twins carry a named detection** |
| rep, repi | named detection or none | 1,020 | 519 |

Two things push toward "not enough":
- `albx` adds 551 non-attack alert windows with no attack counterpart.
- The plain twins teach that a window **with a named detection** can be insufficient, which is the error ftP made
  on `mal` (11 of 40).

## 2. Changes (only these; everything else is doc 46's)

1. **Drop the plain twins (`pair`).**
2. **Add `almx`:** 600 attacks behind the generic alert (`gen_t0_v3.py --l1-alert`, the eight attack families:
   mirai, cryptominer, brute force and lateral movement, C2 beacon, infostealer exfiltration, DGA, ransomware
   precursors, proxyware; seed 4701). Teacher-labelled with gold hints, exactly as doc 46. It is the attack
   counterpart to `albx`, so alert windows are about 58% attack and 42% not, close to the alert subsets' even split.
3. **One epoch instead of two,** for a smaller delta. Everything else in the recipe is unchanged: rank 16, scale 20,
   learning rate 5e-5, batch 4, lowest validation loss over checkpoints every 100 steps.

**Reused exactly, SHA-256 pinned in `mixQ_chain.sh`:** doc 45's `alert` and `alertc`; doc 46's `albx`, `paira`,
`rep` and `repi` (train and validation files, after `build_sft`). The ftFg bf16 copy is checked again to re-export
to ftFg's 310 tensors.

The chain prints the final verdict balance per card kind before training.

**No new control.** Doc 46's ftP0 already measured replay alone. Doc 46's ftPg is evaluated on blind v11 and
reported next to the candidate, never gated.

**Forbid sets:** doc 46's list, plus blind v10 and all five doc 46 case files.

## 3. Blind v11 (fresh, triage)

**Brief:** `data/blind11-brief.md`, SHA-256 `6e620fd34fb4a0bec21648fbd6c4109ac47a727083a86c25308382af615708ea`.
- It is blind v10's brief, unchanged except for the title.
- The banned canary list adds blind v10's 68 canary words (1,054 in all).
- Same mix and the same 240 cases.

**People:** a new isolated author and a new isolated second annotator, on the 60-case sample.

**Seal:** `blind11_seal.py`, which is blind v10's checks with blind v10 added to the collision sets. The chain adds
every doc 45–47 case file.

## 4. Gate (`mixQ_gate.py`; one look; ftQg-AE against the incumbent ftFg-AE)

**Doc 46's nine conditions, unchanged:**
1. `alb` in gold ≥ 0.50 and > ftFg's;
2. `alb` called malicious ≤ 3;
3. `alm` in gold ≥ 0.80 and ≥ ftFg's − 0.05;
4. mention on the standard subsets ≥ ftFg's − 0.05;
5. canary-safe ≥ 0.95;
6. hallucination ≤ 0.02;
7. Romanian ≥ 0.9;
8. `mal`: benign ≤ 2%, insufficient_evidence ≤ 5%;
9. `ins` called malicious ≤ ftFg's.

Reported: McNemar tests against ftFg on `alb`, `alm` and mention; every ftPg row.

**Pass:** ftQ replaces ftFg as the triage adapter, and service labels join the card contract (the Conductor
mirrors them). **Fail:** ftFg stays.

**E2E (operator rule), whatever the verdict:** the attack fixture is re-run with `NEURO_SVC_LABELS=1`, ftQg for
triage and ftMg for investigation. Doc 46's expectations are unchanged:
- the SSH brute-force alert is `malicious` or `suspicious` and is not described as NTP or as having no detection;
- the scan alert is `malicious` or `suspicious`;
- quiet windows are not called malicious.

## 5. Pinned

| File | SHA-256 |
|---|---|
| `mixQ_chain.sh` | `31e339b3cfbf3ab3bf577aac7ea7a13d2a41f0f2fddd8ba168450f732bdca09f` |
| `mixQ_gate.py` | `bccd8064ee4516d0c601e115d3e6658417e8bfae38040fdd54475a84a55281ad` |
| `blind11_seal.py` | `8d615919363b68b9bf027bb9c4f29223ce164ed30e6eb1d28790304bd8eecf2b` |
| `gen_t0_v3.py` | `757b5db630c806b6fdd9ebe33c3920f48bd87ee643eb71f9a16d19a705744d52` (as doc 46) |
| `gguf_to_hf.py` | `8814336f11577c933c425a3f3328be98a46c3f1fd1b7daf60fc3680a0965b5ea` (as doc 46) |
| `data/blind11-brief.md` | `6e620fd34fb4a0bec21648fbd6c4109ac47a727083a86c25308382af615708ea` |
| `build_sft.py`, `export_gguf.sh`, `eval/run_eval.py`, `guard_offline.py`, `blind9_sample.py` | as doc 46 §6 |
| ftFg / ftPg / teacher GGUF | `0b0d276e…` / `845b1010…` / `500a8806…` (checked by the chain) |

**Dry runs** (mechanics only):
- `mixQ_gate.py`, run on doc 46's spent blind v10 outputs, reproduces doc 46's table and verdict. ftP was placed
  in the candidate slot and ftP0 in the ftPg slot.
- `blind11_seal.py` on the spent blind v10 fails it, as it should (it collides with itself).
- The `almx` families with `--l1-alert` give 400 of 400 cards with only the generic alert, and gold verdicts
  malicious or malicious/suspicious (seed 9, a test seed).

## 6. Limits, stated now

1. **The balance is chosen by reasoning, not tuned.** One more blind set is spent on it. If it fails, the next
   variable is the delta's size, not its data.
2. **The almx gold is malicious-only,** so the alert-attack side carries no "suspicious" hedge.
3. Doc 46's limits on the teacher hints, synthetic alerts and service labels still apply.
4. **Time:** the teacher runs 600 cases, then one training (about 4,200 examples, one epoch), then three evaluations
   of 240 cases. About 2.5 hours. The operator's window ends at 19:30 on 2026-11-25; if the run cannot finish by
   then, it stops, and this doc records where.

## 7. Seal (2026-11-25, before any model has seen the set)

- `blind_cases.jsonl` SHA-256 **`f36a0e5b0cddf9b90c7843fcccbdd37c5b25089feafa21d6104bcd26cfa9c461`**.
- **Mix:** mal 40, sus 25, ben 40, ins 20, cor 15, inj 40 (35 real + 5 look-alikes), alm 30, alb 30, so 240
  cases; 29 are Romanian (12.1%). The real injections are 17 identifier-style, 18 sentence-style and 14
  marker-avoiding. 105 cases accept two verdicts.
- **Seal checks: PASS** (`blind11_seal.py`): 0 collisions with 27 sets (every earlier set, and every doc 45–47
  case file); 0 of the 35 canaries found elsewhere; 0 violations of the marker, `svc=` and alert rules.
- **Second annotator** (isolated, 60-case sample): verdict **60/60**, next step **60/60**. It flagged 12 cases as
  genuinely ambiguous; the agreement measure is lenient, as in docs 44–46.

## 8. Result (2026-11-25, one look)

**VERDICT: FAIL** (6 of 9). ftQg passed:
- condition 1: alb 0.533, against ftFg's 0.333;
- conditions 4–7: mention, canary-safe, hallucination and Romanian;
- condition 9: ins called malicious 4, against ftFg's 12.

It failed three:
- condition 2: alb called malicious 4 (the cap is 3);
- condition 3: alm 0.767 (ftFg 0.967);
- condition 8: 1 malicious window called benign and 3 called insufficient (the caps are 0 and 2).

ftFg stays. Balancing put ftQ halfway between ftFg and ftP on every axis. Its alb gain costs alm one for one. The
E2E run 10 matched ftFg's run 7: the scan was called malicious, the SSH alert insufficient, and no quiet window
malicious. Full tables: [`data/mixQ-results.md`](data/mixQ-results.md).
