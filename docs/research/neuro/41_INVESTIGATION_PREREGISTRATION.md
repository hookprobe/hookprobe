# 41: Investigation skill: tools, cases and the blind benchmark (doc 39 P3, pre-registration, 2026-11-24)

Written **before** any investigation blind set, investigation training data or trained candidate exists. This
document builds on doc 39 (design), the entry-path graph (#1539) and the 16 playbooks (#1560).

## 1. What is being tested

Given a window (and any earlier step results), does the explainer choose the right **next check**: which tool, on
which entity? Does it **stop** when the evidence clears the suspicion? And does it never state a CVE id it did not
receive from `lookup_exposure`?

## 2. Built in this phase

| Piece | What | Checked |
|---|---|---|
| `exposure.py` | `lookup_exposure(entity)`: read-only, deterministic. Known-exploited, network-reachable KEV entries for the device's class (and product, when known), from `data/entry-paths.json`. Always carries the caveat "devices like this", never "this device is vulnerable". An unknown class gets no claim | outputs inspected for NAS, QNAP NAS, Hikvision camera, TP-Link Archer router, and an unknown class |
| `inv_eval.py` | the investigation task. It reuses `run_eval.py`'s model call unchanged (as its `tool` task, with `lookup_exposure` added for that process only) and guard A. It scores `step_ok` (tool + entity + policy), `stop_ok` (no policy change when the evidence clears) and `cve_ok` (every CVE id in the answer appears in the context) | unit-tested on 7 hand-made answers, including an unreturned vs a returned CVE id |
| `gen_investigate.py` | training cases from the playbooks: next / multi-step (with a RESULT line) / clears (the result rules it out, so stop) / invisible (the gateway cannot see it) | 600 cases, 16 techniques; 0 CVE ids in gold; every gold entity is present in its context |

`run_eval.py` is not modified, so every earlier score stands.

## 3. The blind investigation set (inv-blind v1)

**Author.** An isolated fresh agent from `inv-brief.md` (SHA-256 `a0be71ec464b86827b6a30f77ebd80dd750418fea2fe6f4cbf374a8f835fafeb`; committed after the look, as the earlier briefs were). The author never
sees the playbooks, the generator, or any earlier set.

**Mix: 150 cases, about 12% Romanian, English first.**

| Kind | n | Gold |
|---|---|---|
| `next` | 45 | the right first check (tool + entity) for the window's sign |
| `multi` | 35 | the context includes an earlier step's RESULT; gold is the next check, or a policy proposal when the evidence is already conclusive |
| `clears` | 30 | an earlier RESULT explains the sign away; gold is no further action (no policy change) |
| `decoy` | 25 | an ordinary window that needs no investigation; gold is no tool |
| `invisible` | 15 | the question is about something a gateway cannot observe (host-side activity); gold is no tool, or one flow query |

**Checks.** Schema, alias definitions, `.example` / RFC 1918 / RFC 5737 only, gold entities present in the context,
and 0 context collisions with every earlier set (dev v1–v8, blind v1–v7, all T0 parts, the doc 38 pairs, the
generator's output). A second isolated annotator labels a 25% stratified sample; the author adjudicates; the set is
then sealed by SHA-256 in this document **before** any model sees it.

## 4. Gate (one look, for a trained candidate; written now, applied in P4)

The candidate is compared with **base17g** (Qwen3-1.7B base, Q8_0), both with the same five tools and guard A, on
inv-blind v1. **All must hold:**

| # | Condition |
|---|---|
| 1 | `step_ok` on `next` + `multi` (80 cases) > base's, exact McNemar p < 0.05 |
| 2 | `stop_ok` on `clears` + `decoy` (55 cases) ≥ 0.80 **and** ≥ base's |
| 3 | **0 answers with an unreturned CVE id** (hard) |
| 4 | no policy proposal on any `decoy` case |
| 5 | triage does not regress: on a fresh triage dev set, the doc 36 conditions 1, 2 and 6 (canary ≥ 0.98, hallucination ≤ 0.02, benign on malicious ≤ 2%) still hold |

**Before any training,** base17g and ftFg (zero-shot, with tools) are measured once on inv-blind v1 and reported as
the floor. That look is descriptive; the set stays usable for the gate, because no training or selection uses it.

## 5. What P4 will need (not decided here)

- A tool-call SFT format for the student (Qwen3's chat template supports tool calls), teacher answers with tools,
  and a recipe. That needs its own pre-registration (doc 42) before training.
- A fresh triage dev set for condition 5.

## 6. Limits, stated now

1. The training cases are synthetic, one card template per technique. The isolated blind author is the check
   against template learning (doc 38 §7.1).
2. `lookup_exposure` rests on KEV, which is thin for home device classes (doc 39 §6.1). The tool says so through
   its counts.
3. One step per turn. Multi-step investigation is simulated by RESULT lines, not by a live tool loop.

## Addendum: inv-blind v1 sealed (2026-11-24), before any model has seen it

- **SHA-256** `c49f06c94f75b74e453d6943d6605ede8cd5b0ae6e79d41317cc156d8cb68ade`. 150 cases: next 45, multi 35, clears 30, decoy 25, invisible 15; 18 Romanian (12.0%).
- **Author:** isolated, from `inv-brief.md` (`a0be71ec…`). Its validator passes, and it rejected 16
  deliberately broken cases and 2 broken full sets.
- **Seal checks** (`inv_seal.py check`, `abacb6685b0c31aa…`): PASS. Exact mix, schema, address and domain ranges, gold
  entities in context, RESULT-line form, no CVE id. 0 context collisions with all 19 earlier sets and training
  files: dev v1–v2, v8; blind v1–v7; T0 v1, v2 templates and v3 parts; the doc 38 pairs; and the 600 generated
  investigation training cases (`gen_investigate.py`, seed 39).
- **Second annotator** (isolated, 38-case stratified sample, no gold): 38/38 within the gold's acceptable answers;
  no adjudication needed. Gold sets accept one or two answers, which makes agreement easier than a single-answer
  match.
- Nobody but the author has read the case content.

## Floor (descriptive, one run, 2026-11-24): base17g and ftFg, zero-shot, with tools

`inv_eval.py`, guard A, llama-server with `--jinja` for tool-call parsing. The earlier triage runs without that
flag did parse tool calls (base17g made real calls on dev v8 and blind v7), so earlier `tool` scores stand.

| | base17g | ftFg |
|---|---|---|
| `step_ok` on next (45) | 0.222 | **0.000** |
| `step_ok` on multi (35) | 0.086 | **0.000** |
| `step_ok` on clears (30) / decoy (25) / invisible (15) | 0.567 / 0.520 / 1.000 | 1.000 / 1.000 / 1.000 |
| tool calls made (of 150) | 75 (2 policy proposals, both on multi) | **0** |
| answers with an unreturned CVE id | 0 | **1** (clears-005: free text naming a CVE id absent from the context) |

**Reading.**
1. **ftFg has lost tool calling.** Fine-tuned on triage JSON alone (docs 25–26), it answers without a tool on every
   case. Its dev v8 and blind v7 `tool` subsets show the same: 25 of 25 answers without a call, scoring only where
   "no call" was gold. Its perfect stop score here is the absence of tool use, not judgement.
2. **The hard CVE gate is needed.** ftFg wrote a CVE id it was never given. This is the failure doc 39 §1 predicted.
3. **base17g investigates, but poorly** (next 0.22, multi 0.09), and calls tools on about half the decoys.

**Consequence for P4 (doc 42).** Training must restore tool calling. A triage-only student forgets it. Mixing
tool-call SFT with the triage mix, and condition 5 (no triage regression), are both necessary. The CVE gate must
also apply to triage answers, not only to investigation.
