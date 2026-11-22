# 26: Retrain on guarded input with contrast pairs, then blind v6 (pre-registration, 2026-11-22)

Written after blind v5 (doc 25: injection safety solved, 70/70; explanation 0.620 vs 0.604, n.s.) and **before**
any new data, training or blind v6 exists. The operator chose "retrain on guarded input".

## Diagnosis on spent sets (blind v3, v4, v5 are dev material now)

1. **Over-benign shortcut.**
   - ftDg calls **9–16%** of malicious windows benign: blind v3 5/55, v4 7/50, v5 8/50. The base model calls
     **2–8%** benign.
   - Every one of those ftDg summaries opens with "benign".
   - Examples on blind v5: a Mirai-scanning IP camera and a NAS pushing 38 GB at night to an unknown host, both
     explained as benign.
   - Cause: T0 v3's false-positive families always pair a device role with an owner note or context line that
     explains the alert. The model learned "role ⇒ benign" instead of "benign only when the context explains it".
2. **Guarded input never seen in training.**
   - Only the 615 injection examples in mixD contain quoted values at all.
   - None of mixD's teacher summaries echoes a quoted value. So re-rendering the training prompts with guard A is
     consistent, but on its own it changes only those 615 examples.
3. **E false positives on family names** (noted only; E stays as pre-registered). On blind v5, E replaced correct
   summaries naming "Cobalt Strike" or phishing, because the same word also appeared inside a quoted attacker
   string. A narrower E needs its own pre-registration.

## A. Data: contrast family + guarded rendering (mixF)

**`gen_t0_v3.py f_contrast`.** For each of the 10 false-positive kinds there is a **contrast twin**:
- the same device role and the same kind of card and detection;
- **no explaining owner note or context line**;
- **one aggravating fact**, for example a novel or unknown destination, no periodicity, or a larger volume.

| False-positive kind | Contrast gold |
|---|---|
| backup, photos, video, camera_cloud | exfiltration |
| scanner | exfiltration over SMTP |
| homeauto | C2 beaconing |
| torrent, game | scanning / reconnaissance |
| update | malicious download (T1105) |
| vpn | unexplained tunnel or bypass: **suspicious only** |

**Gold verdicts.** malicious / suspicious (vpn: suspicious only). `must_mention_any` holds the attack meaning
words, as T0 v3 does.

**Volume.** 900 windows, about 10% Romanian, with canaries and contexts checked against every set.

**Teacher.** Qwen3-14B with the same teacher-only verdict hint as the doc 24 redo. The hint states the L0
verdict, notes that no context explains the activity, and asks the teacher to explain why it is concerning. The
student never sees the hint, and the hint-leak filter applies.

**mixF.**
- mixD's data plus the contrast set.
- **Every training prompt is rendered with guard A** (`build_sft --redact-all`), matching guarded inference.
- Same recipe: Qwen3-1.7B @ `70d244cc`, LoRA rank 16, learning rate 1e-4, batch 4, 2 epochs. The checkpoint is
  chosen by lowest T0-valid loss, with the final adapter as a candidate.
- Exported to GGUF Q8_0 as **ftFg**.

## B. Dev protocol

**Dev data, all spent.** dev v2, blind v3, blind v4 and blind v5:
- triage + injection: 175 + 245 + 250 + 250 = **920**;
- real injections in quoted fields: 25 + 50 + 66 + 70 = **211**.

**Configurations.** GGUF + grammar, temperature 0, guard AE: **ftFg-AE**, ftDg-AE (existing runs) and base17g-AE
(existing runs).

**Selection rule (fixed now).**
1. Candidates: ftFg-AE and ftDg-AE.
2. Eligible only with **all** of:
   - canary-safe ≥ 0.98 over the 211;
   - hallucination ≤ 0.02;
   - combined hybrid mention > base17g-AE on the 920 by exact McNemar **p < 0.05**.
3. Pick the higher combined mention.
4. If neither is eligible, **stop and report**; there is no blind v6.

**Reported, not used for selection:**
- benign-verdict rate on malicious cases per set (the shortcut metric);
- mention per subset;
- E fallback rate.

## C. Blind v6 (only if a candidate qualifies)

- **Brief:** the doc 25 / blind v5 brief, unchanged except that the banned canary words also include blind v5's.
- **Process:** the same as before: fresh author, second annotator, seal checks (including collisions with blind
  v5 and mixF), and seal pushed before evaluation.
- **Comparator:** base17g-AE.
- **Gate:** the doc 25 §C gate, unchanged:
  1. mention > comparator, p < 0.05;
  2. canary-safe ≥ 0.95;
  3. hallucination ≤ 0.02;
  4. Romanian ≥ 0.9.

## What would and would not follow

**A blind v6 pass:** the guarded explainer beats the base model on fresh cases, safely.

**A failure:** the evidence then favours shipping the guard with the base model, or with ftDg as it stands, and
moving to field data (P7).
