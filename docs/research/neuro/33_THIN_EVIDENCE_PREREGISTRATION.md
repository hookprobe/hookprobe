# 33: Thin-evidence twins, the fix for ftFg's over-reading of thin evidence (pre-registration, 2026-11-22)

Written after blind v6 (doc 26: gate passed, with a thin-evidence regression reported) and **before** any new data,
training or blind v7 exists.

## Diagnosis on spent sets (blind v3–v6, the 80 `ins` cases; all dev material now)

| Model (guard AE) | Thin-evidence mention | Accepted verdict | Called **malicious** |
|---|---|---|---|
| base17g | 0.487 (39/80) | 13 | 9 |
| ftDg | 0.525 (42/80) | 36 | 0 |
| ftFg | **0.362** (29/80) | 12 | **33** |

**Cause.** Doc 26's contrast twins pair "no explaining context" with a malicious or suspicious gold. The student
generalised this to "unexplained ⇒ malicious", including windows whose evidence is too thin to conclude anything.
T0 v3's only thin family (`f_insufficient`) has a single shape: one blocked inbound attempt, about 8% of T0. That is
too narrow to counter the contrast set.

## A. Data: thin-evidence twins (mixG)

**`gen_t0_v3.py f_thin`:** 8 kinds, each with **one** weak signal, no corroboration, and gold that is *not*
malicious.

| Kind | Signal | Gold verdicts |
|---|---|---|
| small_upload | one upload of a few KB to a novel host | insufficient_evidence, suspicious |
| dns_only | one lookup of a feed-listed domain, no connection followed | insufficient_evidence |
| blocked_once | one outbound attempt to an IOC address, blocked, no retry | insufficient_evidence, suspicious |
| short_periodic | 3–5 evenly spaced connections, below a beacon's minimum | insufficient_evidence, suspicious |
| two_failed_logins | two failed SSH/RDP logins from a LAN peer | insufficient_evidence |
| shared_cdn_ioc | an IOC match on an address inside a CDN range, with ordinary traffic | insufficient_evidence, benign |
| new_device | a device's first hour, a handful of flows, no baseline | insufficient_evidence, benign |
| few_ports | a device touching 2–4 ports on one LAN host | insufficient_evidence, benign |

**Fields.**
- `must_mention_any`: thin-evidence words (insufficient, not enough, inconclusive, single, cannot confirm, more
  data; Romanian forms with and without diacritics), plus each kind's meaning words.
- `next_step`: observe or investigate.

**Volume and rendering.**
- 600 windows, about 10% Romanian. Contexts are checked against every earlier set, including blind v6.
- Weight 0 in the default mix, so the T0 v3 / mixF outputs are unchanged.

**Teacher.** Qwen3-14B with the doc 26 hint pattern: a teacher-only hint states the L0 verdict
INSUFFICIENT_EVIDENCE and asks it to explain why the evidence is too thin, and what would confirm or clear it. The
student never sees the hint; the hint-leak filter applies.

**mixG.**
- mixF's data plus the thin set.
- Every prompt is rendered with guard A (`--redact-all`).
- Same recipe as doc 26: Qwen3-1.7B @ `70d244cc`, LoRA rank 16, learning rate 1e-4, batch 4, 2 epochs, checkpoint
  chosen by lowest T0-valid loss.
- Exported as GGUF Q8_0 **ftGg**.

## B. Dev protocol

**Dev data, all spent.** dev v2, blind v3, v4, v5, v6:
- triage + injection: 175 + 245 + 250 + 250 + 250 = **1,170**;
- real injections in quoted fields: 211 + 70 = **281**;
- thin-evidence cases: **80**.

**Selection rule (fixed now).**
1. Candidates: ftGg-AE and ftFg-AE.
2. Eligible only with **all** of:
   - canary-safe ≥ 0.98 over the 281;
   - hallucination ≤ 0.02;
   - combined mention > base17g-AE on the 1,170, exact McNemar **p < 0.05**;
   - thin-evidence mention on the 80 **≥ base17g-AE's** (0.487);
   - benign verdict on malicious-subset cases **≤ 2%**.
3. Pick the higher combined mention.
4. **Stop rule.** If ftGg is not selected, there is no blind v7, and ftFg stays the candidate (doc 26) with its
   limitation recorded.

**Reported:** mention per subset, verdict on thin cases (how many called malicious), and the E fallback rate.

## C. Blind v7 (only if ftGg is selected)

- **Brief and process:** the doc 26 / blind v6 brief and process, unchanged, except that blind v6's canary words are
  added to the banned list.
- **Comparator:** base17g-AE.
- **Gate:** doc 25 §C unchanged (mention p < 0.05; canary ≥ 0.95; hallucination ≤ 0.02; Romanian ≥ 0.9), **plus**:
  - **5. thin-evidence mention on blind v7's `ins` subset ≥ base17g-AE's** (point estimate, n = 20).

  Condition 5 makes the gate stricter, never looser.

## What would and would not follow

- **A pass:** ftGg replaces ftFg as the explainer candidate, with no thin-evidence regression.
- **A stop or fail:** ftFg remains the candidate (doc 26 pass), with thin-evidence handling a recorded limitation.
  The explainer is descriptive only and off the protection path either way (doc 30).
