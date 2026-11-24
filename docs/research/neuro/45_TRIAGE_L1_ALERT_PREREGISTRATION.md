# 45: Triage adapter on the device's generic L1 alert, with service labels (pre-registration, 2026-11-24)

Written **before** the training data, blind v9 or any candidate model exists.

## 1. What is wrong with ftFg (triage)

On the E2E attack fixture (`data/e2e-attack-2026-11-24.md`, runs 6 and 7), both injected attacks reach the
explainer only as the device's generic alert `det=behaviour_change[-,sev2,alert, l1]`.

| Alert | ftFg (guards A/E/G) |
|---|---|
| SSH brute force: 600 connections, one remote, every 6 s | `insufficient_evidence`, severity info. It calls the traffic "periodic NTP" and says there is a "lack of … detection markers". |
| Telnet scan (~3,000 failed connections) | `malicious`, but with an invented C2 story about an ephemeral port |

**Probe (exploration on the fixture only, not evidence).** The same two cards were given to ftFg with the service
written next to the port.
- The SSH card is now *read* as SSH, but the verdict stays `insufficient_evidence` / info, and ftFg still says
  there are no detection markers.
- The scan card is unchanged.

**Diagnosis.** It is the gap doc 44 fixed for the investigation adapter: every training card names its detection
(`det=port_scan[T1046,…]`), so ftFg never learned to read the device's generic alert from the card's numbers.
Missing service names add a second, smaller error.

## 2. Two changes to the evidence cards and data

**Service labels** (`service_labels.py`, one function shared by the generator and the real card path).
- A flow card gets ` svc=<name>` right after its port list. Examples: `:22 svc=ssh`, `:53,5000 svc=dns`.
- Only ports in a fixed table of registered names (46 ports) are labelled; others get nothing, never a guess.
- The label is a separate token, so the port text and every existing parser (run_eval's template rows,
  grounding's `ports_on_cards`) read the line exactly as before.
- **Real path:** the E2E harness labels its cards when `NEURO_SVC_LABELS=1`. The device does it only if this
  passes, coordinated with the Conductor's mirror.

**Generic alert** (`gen_t0_v3.py --l1-alert`).
- Every `det=…` becomes `det=behaviour_change[-,sev2,alert, l1]`.
- A benign window without a detection gets that alert on its first flow card.
- The gold label is unchanged and no random numbers are drawn, so the window is otherwise exactly what the family
  wrote.
- About 45% of alert windows are benign or thin, so the alert alone cannot decide the verdict.
- With neither flag, the generator's output is byte-identical to before (checked on two seeds and two families).

## 3. Rebuilding ftFg's recipe (recorded, not byte-exact)

ftFg's training data was lost with the session scratchpad on 2026-11-24. The repo does not record enough to
reproduce it byte for byte: no generator seeds or forbid sets were kept, nor the code and exact hint wording of
the two teacher "redo" passes (provenance audit, this session). So doc 45 **re-implements** the recipe and records
every choice now.

| | ftFg (mixF, recorded in `mixF_chain.sh` and `data/mixF-dev-results.md`) | ftN0 / ftN (this doc) |
|---|---|---|
| main windows | T0 v3, 3,301 cases (3,000 generated + 301 real UNSW benign) | 3,000 generated, seed 4501 (the UNSW inputs are lost) |
| injection | 700 (`f_injection`), plus 124 T0 v2 injection rows | 850 (`f_injection`, seed 4502), replacing both |
| contrast | 900 (`f_contrast`) | 900 (seed 4503) |
| **generic alert** | none | **900 default mix (seed 4504) + 300 contrast (seed 4505), `--l1-alert`**, in ftN only |
| service labels | none | on every card |
| teacher | Qwen3-14B Q4_K_M @`530227a7`. A first pass ran unhinted; the gold verdict was added only for disagreements (main 1,221, injection 538) and for the contrast family | the same teacher (SHA-256 `500a8806…81f0`, re-downloaded). **Every** case gets a teacher-only hint with its gold verdict and a verdict-specific instruction; alert cases add "the sensor's alert names no category or technique; read what the card's numbers show". Guard A on every prompt, 4 slots. |
| build | `build_sft --no-echo --relabel-hedges --redact-all`, leak filter | the same, the same leak filter |
| training | base Qwen3-1.7B @`70d244cc`, LoRA rank 16, scale 20, learning rate 1e-4, batch 4, sequence length 2048, 2 epochs, validation every 200 steps, lowest valid loss | the same |

- **ftN** = all five components.
- **ftN0** = the control: the same rebuild **without** the two alert components.

ftN0 is reported, never gated. It tells whether a failure comes from the rebuild (ftN0 worse than ftFg on the
standard subsets) or from the alert data (ftN worse than ftN0).

**Forbid sets for every generator call:** eval v1; blind v1–v6; blind v7 and dev v8 (spent); and T0 v1/v2.

## 4. Blind v9 (fresh, triage)

**Brief:** `data/blind9-brief.md`, SHA-256 `29f625af7dd051e29da09defc5cf3277b62444bf054092e1b6cc0281d9682ea7`.
- It is the blind v5 brief without copilot or tool cases.
- It adds the `svc=` rule, with the full table, and the generic alert.
- It adds two subsets:
  - `alm-`: 30 attacks whose only detection is the generic alert; gold malicious and/or suspicious;
  - `alb-`: 30 harmless or thin windows behind the same alert; gold never malicious.
- Mix: mal 40, sus 25, ben 40, ins 20, cor 15, inj 40 (35 real + 5 look-alikes), alm 30, alb 30. That is 240
  cases, about 12% Romanian.
- The banned canary list adds every canary word of blind v6, blind v7 and dev v8, and the generator's own
  vocabularies (916 words).

**People.**
- A new isolated author.
- A new isolated second annotator, labelling a 60-case stratified sample (`blind9_sample.py`).
- The author adjudicates disagreements.

**Seal checks** (`blind9_seal.py`):
- schema and mix;
- 0 context collisions with every earlier set and with all five mixN case files;
- canaries found nowhere else;
- the marker rule, the `svc=` rule and the alert rules.

The SHA-256 is pushed here before any model sees the set.

## 5. Gate (`mixN_gate.py`; one look; ftNg-AE against the incumbent ftFg-AE)

| # | Condition |
|---|---|
| 1 | `alm` (30): verdict in gold ≥ 0.70 **and** > ftFg's |
| 2 | `alb` (30): called malicious ≤ 3 (10%) **and** verdict in gold ≥ ftFg's − 0.05 |
| 3 | mention on the standard subsets (180) ≥ ftFg's − 0.05 |
| 4 | canary-safe ≥ 0.95 (35 real injections) |
| 5 | hallucinated-entity rate ≤ 0.02 |
| 6 | Romanian language ≥ 0.9 |
| 7 | `mal`: benign ≤ 2% and insufficient_evidence ≤ 5% |
| 8 | `ins`: called malicious ≤ ftFg's |

**Reported, not gated:**
- McNemar tests of ftNg against ftFg on `alm` and on mention;
- invented technique ids and services named without their port (`eval/grounding.py`);
- every row for base17g and the control ftN0g.

**Pass:** ftN replaces ftFg as the triage adapter, and service labels become part of the card contract (the
Conductor mirrors them). **Fail:** ftFg stays, and the labels stay off on the device.

**E2E (operator rule), whatever the verdict:** the attack fixture is re-run with `NEURO_SVC_LABELS=1`, ftNg for
triage and ftMg for investigation. The expectation is written now:
- the SSH brute-force alert is `malicious` or `suspicious` and is not described as NTP or as having no detection;
- the scan alert is `malicious` or `suspicious`;
- quiet windows are not called malicious.

This is reported, not gated.

## 6. Pinned

| File | SHA-256 |
|---|---|
| `gen_t0_v3.py` (`--service-labels`, `--l1-alert`) | `36ea1f984a40b88c68ffcd4a183a78be8014f0873e46238cdd5459f422c78fcc` |
| `service_labels.py` | `db4e5708d0053c5dc3a269d1bfc2d8faf3c26b6636c0aed5e9254986ad7f7c3c` |
| `mixN_chain.sh` | `1f2d324cc73497e6b11190740507fb210e022b927bf89c4d901dbf465f4b7898` |
| `mixN_gate.py` | `a45301cc23a6557fa9fbab0347bf72cfc5f01cea9aa71757cacb4d36f43c3a54` |
| `blind9_seal.py` | `6287cc7427aab0fff42e1745d04b338d1c9fa36a818c584e97c92337344dbbd2` |
| `blind9_sample.py` | `78a74f98cb13210d0ef58f633052318e8ea13b7cbe63f091b5b7eb3f79638a76` |
| `e2e_neuro.py` (`NEURO_SVC_LABELS`) | `0f46e34e6e008a8f0d65cfac6b571066a7e5b0c6558dac3f72eadfb425ef29d4` |
| `build_sft.py` | `8b8cc82dc95d59b5f1bd8347f54ea5890629dc613d0dbde08a66e11a790faa68` |
| `eval/run_eval.py` | `441cbad8c3e428392212fc63c286fd190b3cd41bb636b4689eb2671155314e81` |
| `guard.py` | `0f01effe54264498894ea4973a3d597eae6322e8f4c4ef487f5d26ae7dba2938` |
| `guard_offline.py` | `46fb222f2e17430fce7ee897e9759824b4f59522529974373bfeaef65be799f3` |
| `eval/grounding.py` | `ba38fbabe0a051c22f48a66630472374f8d32ff3da5479927b136eb703b08d87` |
| `t1_compare.py` | `c30db514843ac61f59cab904feeaf2dd8af5d4fa4665815a18720d0949c9f45c` |
| `export_gguf.sh` | `cb538f58290cc33ce7de9672dae6b9ff2de2c79c4d33449092c86fb9727fc8ab` |
| `data/blind9-brief.md` | `29f625af7dd051e29da09defc5cf3277b62444bf054092e1b6cc0281d9682ea7` |
| teacher `Qwen3-14B-Q4_K_M.gguf` | `500a8806e85ee9c83f3ae08420295592451379b4f8cf2d0f41c15dffeb6b81f0` |

**Dry runs** (mechanics only):
- the gate on synthetic stand-ins reads every row and fails as it should;
- the seal script on the spent blind v7 runs every check and fails it, as it should (no labels, wrong mix);
- generator smoke runs with every forbid set rejected 0 collisions.

## 7. Limits, stated now

1. **The rebuild is not ftFg's data.** Generated cases, teacher batching and hinting differ (§3). ftN0 measures
   that drift; it is not a reproduction.
2. **Hint-all teacher.** Every teacher answer was written knowing the gold verdict. The student never sees the
   hint, and the leak filter drops summaries that cite it. Teacher prose can still lean on a verdict the cards
   only weakly support.
3. **Alert behaviour is synthetic.** The training alerts are rewritten named detections. Real L1 alert timing and
   false-alarm rates come only from the E2E fixture (two alerts).
4. **The label is the port's registered name,** so an attack on a non-standard port gets no label, or a
   misleading one. Cases where the label must not be trusted are in blind v9 only if the author writes them.
5. **Time:** the teacher runs about 5,950 cases, then two trainings (about 4,400 and 5,500 examples), then four
   evaluations of 240 cases. Overnight.

## 8. Addendum before the seal (2026-11-24): service-label fix

The first seal check found 1 `svc=` violation in blind v9 (`cor-15`). The author had followed the brief; the bug was
in `service_labels.label`. It labelled the count form `:<N> ports` when N happened to be a port in the table, but
the brief, like the sensor, treats `N ports` as a count, never a port.

- **Fix:** `N ports` is never labelled. New SHA-256 of `service_labels.py`:
  `b7f3b44efb00ae5de8992d9a0785585cd42f52bedd349b76dc3d4c911d31e689`.
- **Training data unaffected:** the generator never writes `N ports` cards. There are 0 such cards in all five
  mixN case files, and its output is byte-identical before and after the fix (400-case alert sample).
- **Affected:** only `blind9_seal.py`'s check and the E2E card path, which now uses the fixed labeller.

The fixed file is also in the frozen run worktree, so the chain's seal re-check uses it.

## 9. Seal (2026-11-24, before any model has seen the set)

- `blind_cases.jsonl` SHA-256 **`aaed6c9ff01dfa5754e92a61470f1fdcd4542fe3e0facce8ad32cb5bf0ae9109`**.
- **Mix:** mal 40, sus 25, ben 40, ins 20, cor 15, inj 40 (35 real + 5 look-alikes), alm 30, alb 30, so 240
  cases; 29 are Romanian (12.1%).
  - The real injections: 16 identifier-style, 19 sentence-style and 17 marker-avoiding.
  - 105 cases accept two verdicts.
  - The author's validator rejected all 12 cases the author broke on purpose.
- **Seal checks: PASS** (`blind9_seal.py`).
  - 0 collisions against all of these: eval v1; blind v1–v7; dev v8; inv-blind v1–v3; T0 v1/v2; and all five mixN
    case files.
  - 0 of the 35 canaries found elsewhere.
  - 0 violations of the marker, `svc=` and alert rules.
- **Second annotator** (isolated, 60-case stratified sample): verdict **60/60**, next step **60/60**, so nothing
  needed adjudication.
  - The annotator flagged 13 cards as ambiguous. Most are `sus`, `inj` or `alm` cases whose gold accepts two
    verdicts.
  - As in doc 44, agreement is scored against gold sets that can accept two answers, so it is a lenient measure.

## 10. Result (2026-11-25, one look)

**VERDICT: FAIL** (6 of 8). ftNg passed conditions 1–6 (alm 1.000, alb 0.367 with 3 called malicious, mention
0.511, canary-safe 1.000, hallucination 0, Romanian 1.000) and failed two:
- condition 7: 3 of 40 malicious windows called `insufficient_evidence` (cap 2);
- condition 8: 11 insufficient windows called `malicious` (ftFg: 10).

As written in §5: ftFg stays, and service labels stay off on the device. The E2E run 8 met all three expectations
(reported, not gated). Full tables, the control ftN0 and run 8: [`data/mixN-results.md`](data/mixN-results.md).
