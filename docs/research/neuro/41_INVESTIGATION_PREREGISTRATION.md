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
