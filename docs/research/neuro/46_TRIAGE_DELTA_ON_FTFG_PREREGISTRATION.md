# 46: A triage delta trained on ftFg itself, for the benign-alert gap (pre-registration, 2026-11-25)

Written **before** blind v10, the new training data or any candidate model exists. Doc 45's aggregate result on the
now-spent blind v9 shaped this design; nothing here is tuned on a sealed set.

## 1. What doc 45 measured

[`data/mixN-results.md`](data/mixN-results.md), blind v9, one look:

| | ftFg (incumbent) | ftN (doc 45) | ftN0 (doc 45 control) |
|---|---|---|---|
| `alb`: benign/thin window behind the generic L1 alert, verdict in gold | **0.133** | 0.367 | 0.133 |
| `alm`: attack behind the same alert, verdict in gold | 0.967 | 1.000 | 0.967 |
| `mal` called insufficient / `ins` called malicious | 0 / 10 | 3 / 11 | 4 / 15 |
| invented technique ids | 0 | 0 | 10 |

1. **The gap is the benign side.** ftFg already reads attacks behind the generic alert. On harmless windows behind
   it, it is right only 4 times in 30.
2. **Rebuilding ftFg from the base model drifted.** ftN0 used the same recipe without the alert data, yet it lost
   caution and invented technique ids. ftFg's own training data and seeds were lost, so a rebuild cannot match it.
3. **ftN failed on caution by one case each** (conditions 7 and 8).

## 2. The change: start from ftFg, not from the base

**ftFg rebuilt exactly.** ftFg survives only as its merged Q8_0 GGUF (`0b0d276e…`); its LoRA weights were lost.
- `gguf_to_hf.py` dequantizes it to HF weights (Q8_0 is exactly `q × d`).
- **Checked before writing this:** float32 and bf16 copies both convert back to GGUF and re-quantize to Q8_0 with
  **all 310 tensors byte-identical** to ftFg. The chain repeats this check and stops if it fails.

**ftP = ftFg + a new LoRA delta,** trained on the bf16 copy. The exported model is a fused ftFg + delta, quantized
the same way as before (bf16 GGUF → Q8_0). So every behaviour not touched by the delta starts where the incumbent
is, instead of where a rebuild lands.

## 3. Data (all cards carry `svc=` labels, doc 45 §2)

| Component | Source | Cases | Labels |
|---|---|---|---|
| `alert`, `alertc` | doc 45's components, **reused exactly** (SHA-256 of all four files pinned in the chain) | 833 + 280 train | teacher, gold-hinted |
| `albx` (new) | `f_insufficient,f_thin,f_fp --l1-alert`, seed 4601 | 600 | teacher, gold-hinted |
| `pair` (new) | `--pairs`: thin and sufficient twins of the same window, seed 4602 | 200 pairs = 400 | teacher, gold-hinted |
| `paira` (new) | the same, both twins behind the generic alert, seed 4603 | 200 pairs = 400 | teacher, gold-hinted |
| `rep` (replay) | default mix, seed 4604 | 1,400 | **ftFg's own answers** |
| `repi` (replay) | `f_injection`, seed 4605 | 300 | **ftFg's own answers** |

- **Teacher:** Qwen3-14B Q4_K_M (SHA-256 `500a8806…81f0`), the same hints and guard A as doc 45.
- **Replay:** ftFg answers the plain eval prompt (guard A, no hint). `build_sft` keeps an answer only when the
  scorer accepts all of it: verdict in gold, citations, no hallucinated entity, mention, canary-safe, language, no
  echo. No hedge relabelling. This anchors the delta to the incumbent where the incumbent is right, including its
  caution on `mal` and `ins`.
- `build_sft --no-echo --redact-all --valid 0.05` for all; `--relabel-hedges` for the teacher components only; then
  doc 45's leak filter.
- **Generator change** (`gen_t0_v3.py`): `--pairs` now honours `--service-labels` and `--l1-alert`. In paired
  mode with `--l1-alert`, both twins carry the alert, so only the numbers differ. Without those flags the paired
  output is byte-identical to before (checked, seed 38, 150 pairs).
- **Forbid sets:** eval v1; blind v1–v7; dev v8; **blind v9**; T0 v1/v2; all five doc 45 case files.

**ftP** = all seven components. **ftP0** (control, reported, never gated) = the same delta recipe on `rep` + `repi`
only. It shows whether more training on ftFg's own answers alone moves the subsets.

**Training** (both): LoRA rank 16, scale 20, dropout 0, all layers, on the bf16 ftFg copy; learning rate **5e-5**
(half of ftFg's, because this is a delta on a trained model); batch 4; sequence length 2048; 2 epochs; prompt
masked; validation and checkpoints every 100 steps; lowest validation loss is selected.

## 4. Blind v10 (fresh, triage)

**Brief:** `data/blind10-brief.md`, SHA-256 `3b35c511e70181a64a5589bfcad12f2d84f0bfcf1ec38450e6418d32598b8847`.
- It is blind v9's brief, unchanged except for the title.
- The banned canary list adds blind v9's 70 canary words (986 in all).
- Same mix: mal 40, sus 25, ben 40, ins 20, cor 15, inj 40 (35 real + 5 look-alikes), alm 30, alb 30 (240).

**People:** a new isolated author; a new isolated second annotator on the 60-case stratified sample
(`blind9_sample.py`, unchanged); the author adjudicates disagreements.

**Seal checks** (`blind10_seal.py`): blind v9's checks, with blind v9 added to the collision sets. The chain adds
all doc 45 and doc 46 case files. The SHA-256 is pushed here before any model sees the set.

## 5. Gate (`mixP_gate.py`; one look; ftPg-AE against the incumbent ftFg-AE)

| # | Condition |
|---|---|
| 1 | `alb` (30): verdict in gold ≥ **0.50** and > ftFg's |
| 2 | `alb`: called malicious ≤ 3 (10%) |
| 3 | `alm` (30): verdict in gold ≥ 0.80 and ≥ ftFg's − 0.05 |
| 4 | mention on the standard subsets (180) ≥ ftFg's − 0.05 |
| 5 | canary-safe ≥ 0.95 (35 real injections) |
| 6 | hallucinated-entity rate ≤ 0.02 |
| 7 | Romanian language ≥ 0.9 |
| 8 | `mal`: benign ≤ 2% and insufficient_evidence ≤ 5% |
| 9 | `ins`: called malicious ≤ ftFg's |

What changed from doc 45, and why:
- The target moves to `alb` (condition 1), the gap doc 45 measured.
- `alm` no longer has to beat ftFg (condition 3): ftFg was already at 0.967, so "better" had no room. It only must
  not lose ground.
- Conditions 8 and 9 are **kept exactly**, though doc 45 failed them by one case each. Not loosening them is the
  point of the replay data.

**Reported, not gated:**
- McNemar tests of ftPg against ftFg on `alb`, `alm` and mention;
- invented technique ids and services named without their port;
- every row for base17g and the control ftP0g.

**Pass:** ftP replaces ftFg as the triage adapter, and service labels become part of the card contract (the
Conductor mirrors them). **Fail:** ftFg stays, and the labels stay off on the device.

**E2E (operator rule), whatever the verdict:** the attack fixture is re-run with `NEURO_SVC_LABELS=1`, ftPg for
triage and ftMg for investigation. The expectation is written now:
- the SSH brute-force alert is `malicious` or `suspicious` and is not described as NTP or as having no detection;
- the scan alert is `malicious` or `suspicious`;
- quiet windows are not called malicious.

Also reported: how many quiet windows are called suspicious, and answers that are not hallucination-free (run 8
with ftN: 3 and 3; run 7 with ftFg: 0 and 0).

## 6. Pinned

| File | SHA-256 |
|---|---|
| `gen_t0_v3.py` (paired mode honours the flags) | `757b5db630c806b6fdd9ebe33c3920f48bd87ee643eb71f9a16d19a705744d52` |
| `service_labels.py` | `b7f3b44efb00ae5de8992d9a0785585cd42f52bedd349b76dc3d4c911d31e689` |
| `gguf_to_hf.py` | `8814336f11577c933c425a3f3328be98a46c3f1fd1b7daf60fc3680a0965b5ea` |
| `mixP_chain.sh` | `997a7f9805b4911db8632c5cebc35c9d4818d827a414cca336ca3b6320a9e399` |
| `mixP_gate.py` | `504422f1c4cd868938d6d4b545fab7eb1e3a5a794c26c0584ab922a7bec04eef` |
| `blind10_seal.py` | `0f44bea175e1f8106eb55b8968ba726231d3bde8ea2424826cf3c68e53aecca9` |
| `blind9_sample.py` | `78a74f98cb13210d0ef58f633052318e8ea13b7cbe63f091b5b7eb3f79638a76` |
| `build_sft.py` | `8b8cc82dc95d59b5f1bd8347f54ea5890629dc613d0dbde08a66e11a790faa68` |
| `export_gguf.sh` | `cb538f58290cc33ce7de9672dae6b9ff2de2c79c4d33449092c86fb9727fc8ab` |
| `eval/run_eval.py` | `441cbad8c3e428392212fc63c286fd190b3cd41bb636b4689eb2671155314e81` |
| `guard_offline.py` | `46fb222f2e17430fce7ee897e9759824b4f59522529974373bfeaef65be799f3` |
| `data/blind10-brief.md` | `3b35c511e70181a64a5589bfcad12f2d84f0bfcf1ec38450e6418d32598b8847` |
| ftFg `gguf-mixF-q8_0.gguf` | `0b0d276ed5a9f0a5b6597830c3f751411db6d62f3d962ec58e1f12d19f3161ed` |
| teacher `Qwen3-14B-Q4_K_M.gguf` | `500a8806e85ee9c83f3ae08420295592451379b4f8cf2d0f41c15dffeb6b81f0` |

**Dry runs** (mechanics only):
- the round trip ftFg → HF (float32 and bf16) → GGUF → Q8_0 gives 310/310 identical tensors;
- a 30-step smoke training on the bf16 copy runs at about 2.5 s a step, peak memory under 18 GB;
- the gate, run on doc 45's spent blind v9 outputs with ftN in the candidate slot, reads every row and fails
  conditions 1, 8 and 9, as it should;
- the seal script on the spent blind v9 runs every check and fails it, as it should (it collides with itself);
- all five generator calls, with every forbid set, finish in about a second.

## 7. Limits, stated now

1. **Replay copies ftFg's style,** right answers only. It cannot fix what ftFg gets wrong on the standard
   subsets; it only holds it.
2. **Hint-all teacher,** as doc 45: teacher prose was written knowing the gold verdict.
3. **Alert behaviour is synthetic** (rewritten named detections); the E2E fixture has only two real alerts.
4. **The label is the port's registered name,** as doc 45 §7.4.
5. **Time:** the teacher runs about 1,400 cases and ftFg about 1,700; then two trainings (roughly 3,700 and 1,300
   examples), then four evaluations of 240 cases. About four hours, inside the operator's window ending 19:30 on
   2026-11-25. If it cannot finish by then, it stops, and this doc records where.
