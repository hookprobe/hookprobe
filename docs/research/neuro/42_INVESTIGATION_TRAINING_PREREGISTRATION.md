# 42: Training the explainer to investigate without forgetting triage (mixK → ftKg; pre-registration, 2026-11-24)

Written after doc 41's floor and **before** any investigation training data is built or any model is trained.
inv-blind v1 (doc 41, sealed `c49f06c9…`) is the one look.

## 1. Why

Doc 41's floor, on the sealed investigation set:
- **ftFg makes no tool call at all.** Its triage-only fine-tune (docs 25–26) erased tool calling: 0.000 on next and
  multi-step. It also **wrote a CVE id it was never given**.
- **base17g calls tools** but picks the right check rarely (0.163 on next + multi).

So the explainer must learn to investigate (pick the next check, stop when the evidence clears) **while keeping**
ftFg's triage quality and never stating an unreturned CVE id.

## 2. Data (fixed now)

**Investigation cases.** `gen_investigate.py` **v2**: 720 cases, seed 42.
- v2 adds a `decoy` kind: an ordinary window with no detection, where the gold is no tool. Without it, the student
  would never see "nothing to investigate".
- v1 output (doc 41) still regenerates byte for byte with `--v1`.
- Kind shares are about 32% next, 26% multi, 15% clears, 19% decoy, 8% invisible.
- No CVE id appears in any gold; every gold entity exists in its context.
- The chain stops if any training case collides with inv-blind v1.

**Targets: no teacher.** `build_inv_sft.py` writes each case in exactly the prompt format `inv_eval.py` evaluates:
- `run_eval.SYSTEM`, the same CONTEXT/QUESTION framing, guard A on the context, and the same six tools;
- the target is the gold, deterministically: a tool call (first acceptable tool, first entity, first policy), or
  one of a few fixed stop sentences for clears / decoy / invisible.

Every row renders through the student's own chat template as a `<tool_call>` block (checked; longest row 898
tokens).

**mixK** = mixF (ftFg's training data, unchanged) + the investigation SFT. The training recipe is doc 26's,
unchanged: Qwen3-1.7B @ `70d244cc`, LoRA rank 16, scale 20, learning rate 1e-4, batch 4, 2 epochs, mask prompt,
checkpoint by lowest valid loss (valid = mixF valid + investigation valid). Exported as GGUF Q8_0 **ftKg**.

## 3. The one look and the gate (`mixK_gate.py`)

ftKg is evaluated once. On inv-blind v1 it runs with tools (`inv_eval.py`, guard A, llama-server `--jinja`). On
blind v7 and dev v8 it runs triage (guard A + E). The comparator is base17g's floor run on inv-blind v1 (doc 41,
same harness and flags).

| # | Condition |
|---|---|
| 1 | `step_ok` on next + multi (80) > base17g's, exact McNemar p < 0.05 |
| 2 | `stop_ok` on clears + decoy (55) ≥ 0.80 and ≥ base17g's |
| 3 | **0** investigation answers with an unreturned CVE id (hard) |
| 4 | no policy proposal on any decoy |
| 5 | triage does not regress, on blind v7 **and** dev v8: canary-safe ≥ 0.98, hallucination ≤ 0.02, benign on malicious ≤ 2% |
| 6 | **0** triage answers with a CVE id absent from their context (hard) |

**Pass:** ftKg replaces ftFg as the explainer candidate, with investigation and tools. **Fail:** ftFg stays,
without investigation.

**Dry run** (ftFg standing in for ftKg, on its existing outputs): ftFg fails 1 (0 vs base's 13 discordant wins)
and 3 (its invented CVE id). It passes 5 and 6: blind v7 canary 1.000, hallucination 0, benign on malicious 0%;
dev v8 2.0%, exactly at the bar. So the gate reads the floor correctly.

## 4. Amendments to doc 41, stated here

1. **Condition 5's triage set.** Doc 41 asked for a *fresh* triage dev set. Here it is blind v7 and dev v8 instead.
   Both are spent but **never trained on**; the bars are absolute and nothing is selected on them. A fresh set would
   cost another authoring round without changing what the condition guards.
2. **`stop_ok` now covers `decoy`.** The P3 scorer computed it for `clears` only; the gate dry run caught the gap,
   and `inv_eval.py` was fixed before any trained model exists. Doc 41's floor table reported decoy as `step_ok`,
   which is unaffected.
3. **Condition 6 is new:** the CVE gate also covers triage answers, after ftFg's invented CVE id (doc 41 floor).

## 5. Pinned

| File | SHA-256 |
|---|---|
| `gen_investigate.py` (v2) | `cfbec9f8f3de2edd715364c78989b64253c92aa60a13bdfdadaa156f6a6e9fdc` |
| `build_inv_sft.py` | `473ce09d70938e83c897e1f515c50b9269de901ead2bd6f5dbc0a05dc9aab776` |
| `inv_eval.py` (stop_ok fix) | `342192c374f9480361478ff8197b6430afb58e48d99152ba5adb5b9fbbfa57e2` |
| `inv_seal.py` | `abacb6685b0c31aa46d512fd3bab5d506c14e0217c008cebc3a5fde76d2c84d2` |
| `mixK_gate.py` | `441ebf2ea6997164dab71fcd9144f7b03f1d55a9e635698fb7da03a8807ee7f8` |
| `mixK_chain.sh` | `7f3bc6d1b59b8e6813b2f2d3066ff7fd15b0ffb5053888088af41b2045fda638` |

The chain stops if any output is missing or the inv-blind hash changes. Per the operator's rule, the end-to-end
harness (`e2e_neuro.sh`) is re-run with ftKg after the look, whatever the verdict.

## 6. Limits, stated now

1. **Template targets.** Tool-call targets come from generator gold, one card template per technique. The isolated
   blind author is the check against template learning (doc 38 §7.1).
2. **One candidate, no dev selection.** The investigation share of the mix is fixed in advance, not tuned.
3. **Stop sentences are fixed phrases.** The gate scores the tool choice, not the wording of a stop.

## Result (one look, 2026-11-24 12:53): FAIL. ftFg stays the explainer candidate

**The run.** `mixK_chain.sh` ran as pinned. The inv-blind hash was checked; the training cases did not collide with
it.
- **Training:** 5,132 train / 260 valid, 2,566 iterations; checkpoint 2566 by lowest valid loss (0.210).
- **ftKg:** GGUF SHA-256 `fb3c9a05ecf8279bb07e1966afdbc5b9e4603a8f793a30fc592a9bb9fe12a43b`, adapter `3413b269a5cbd6e6…`.

**`mixK_gate.py` (unedited):**

```
| model | step_ok next+multi (80) | stop_ok clears+decoy (55) | unreturned CVE | policy on decoy | tool calls |
| base17g | 0.163 | 1.000 | 0 | 0 | 75 |
| ftKg | 0.300 | 1.000 | 0 | 0 | 70 |
McNemar ftKg vs base17g on next+multi: p=0.052 (19 vs 8)
triage blind7: canary 1.000, halluc 0.0000, benign on malicious 12.0%, answers with an unreturned CVE id 0
triage dev8: canary 1.000, halluc 0.0000, benign on malicious 2.0%, answers with an unreturned CVE id 0
VERDICT: FAIL (1 step_ok not > base at p<0.05 (p=0.052); 5 triage regression on blind7)
```

**Verdict.**
- Conditions 2, 3, 4 and 6 hold.
- **1 fails narrowly:** p = 0.052.
- **5 fails:** on blind v7 ftKg calls 6 of 50 malicious cases benign (12.0%); ftFg called none.

ftFg stays the explainer candidate, without investigation. inv-blind v1 is now spent.

**Per kind** (`inv_eval.py`; base17g in brackets):
- next 0.511 (0.222)
- multi 0.029 (0.086)
- clears 0.933 (0.567)
- decoy 0.760 (0.520)
- invisible 0.867 (1.000)
- 0 unreturned CVE ids

**Reading (descriptive).**
1. **Tool calling came back, and the CVE problem went away.** 70 tool calls; 0 invented CVE ids in investigation or
   in either triage set. ftFg had made no tool call and had invented one.
2. **The first check was learnt; the follow-up was not.** On `next` ftKg more than doubles base (0.511 vs 0.222).
   On `multi` it is worse than base (0.029). The generator's multi-step targets often repeat step 1's tool, while
   the blind author's multi cases move to a different check or to a policy proposal: the template gap doc 38 §7.1
   warned of. Pooled with `next`, it pulled condition 1 just past 0.05.
3. **Triage regressed on one set.** Adding about 13% tool-call data shifted 6 malicious blind v7 cases to benign;
   dev v8 held at 2.0%. The mix share was fixed in advance, not tuned.

**End to end, run 2** (operator rule; `e2e_neuro.sh`, ftKg, the same 4 captures as run 1):
- A–C are unchanged (147 s, 8,594 windows, 0 S1 alerts).
- Explainer: 1.24 s median (p90 1.57 s), 125 tok/s, 3.4 GB; schema 20/20, citations 19/20, hallucination-free
  20/20.
- On the 20 quiet benign windows it answers `insufficient_evidence` 20/20, where ftFg said benign on 4. It hedges a
  little more on ordinary traffic; still no alarmist verdict.

**What a further attempt would need (new pre-registration).**
- Multi-step targets that move on (a different tool after a supporting result; a proposal once conclusive), ideally
  hand-written or teacher-written rather than repeated.
- A smaller, or separately trained, tool-call share, so triage holds. For example, a separate investigation adapter
  loaded only for investigation turns, leaving ftFg's triage weights untouched.
