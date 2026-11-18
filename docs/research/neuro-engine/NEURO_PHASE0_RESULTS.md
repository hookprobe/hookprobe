# NEURO_PHASE0_RESULTS — first evidence beyond simulation

> HookProbe Neuro Engine, Phase 0 (approved 2026-11-17, run 2026-11-17/18). This document reports what
> was **measured**, on what, and what it changes. Labels: **real-traffic** (IoT-23 replay),
> **blind** (independently written cases), **dev-host** (model quality and token counts on an Apple
> M5 Pro; quality and token counts transfer to CM5, timings do not), **projection** (CM5 time from
> token counts + calibrated bandwidth model). **Still nothing was measured on a CM5** — no reachable
> bench unit was available.

## 0. Summary

| Question | Phase 0 answer | Evidence |
|---|---|---|
| Should a small LLM decide verdicts? | **No.** Every candidate (0.35–2B) was **significantly worse** than the deterministic L0 baseline on independent cases (best model 0.50 vs L0 0.59; McNemar p ≤ 0.04 for all). | blind |
| Does a small LLM add value as an *explainer*? | **Yes.** L0 verdict + model explanation keeps L0's verdict accuracy and raises explanation coverage from **0.27 to 0.56–0.73** (non-overlapping 95% CIs). | blind |
| Is grammar-closed decoding necessary? | **Yes, below ~2B.** Free decoding was worse on verdict, citation and injection safety for every model; Qwen3.5-0.8B produced **0% valid outputs** free vs 44% closed verdicts. | blind |
| Do evidence cards hold on real traffic? | **Partly.** Held-out real IoT malware: **0.88 identity / 0.65 evidence recall** from 256 tokens (vs 1.00 / 1.00 on synthetic data); misses concentrate on C&C. | real-traffic |
| Does the behavioural memory hold on real traffic? | **Not yet.** Peer novelty is quiet on a real benign device and flags real malware behaviour; the hour-of-day statistics **fail cold-start** (alarm every hour with < 1 day of history). | real-traffic / semi-synthetic |
| How fast is the explainer tier on CM5? | Projected **2.4–13.4 s per incident** (≈ 4.5–25 incidents/min per stream) for 0.35–2B models; hybrid models lose prompt-cache reuse in llama.cpp and pay 2–3× more prefill. | projection |

## 1. Blind evaluation (E-EV1) — 215 independent cases

**Set.** Written by a separate agent that never saw the compressor, the rules or the earlier cases
(`tools/neuro-research/eval/blind/`, README there): 150 triage, 25 injection, 20 copilot, 20 tool;
31% Romanian; deliberate traps (wrong detector severities, misleading owner context, unrelated cards,
4 injections without the `!instr-like` flag, 7 harmless look-alikes). One author, no second
annotator — inter-annotator agreement is still missing.

**Models** (all Apache-2.0, Q4_0 GGUF, SHA-256 verified against the Hugging Face LFS record by
`fetch_models.py`; llama.cpp b12477, `--reasoning off`, Metal on the dev host): Granite-4.0-H-350M,
Qwen3-0.6B, Qwen3.5-0.8B, Granite-4.0-H-1B, Qwen3-1.7B, Qwen3.5-2B.

### 1.1 Models alone (triage + injection, n = 175; full table `data/e-ev1-models.md`)

| Model | Mode | Verdict | Citation valid | Halluc. entities / case | Injection canary safe | Explanation mention | RO language |
|---|---|---|---|---|---|---|---|
| **L0 rules + templates (no model)** | — | **0.59** (CI 0.52–0.67) | 0.93 | 0.00 | 1.00 | 0.27 (CI 0.21–0.34) | 0.88 |
| Granite-4.0-H-1B | closed | 0.50 (0.42–0.57) | 0.97 | 0.00 | 0.92 | 0.72 | 0.78 |
| Qwen3.5-2B | closed | 0.47 (0.40–0.55) | 0.94 | 0.01 | 1.00 | 0.64 | 1.00 |
| Qwen3.5-0.8B | closed | 0.44 (0.37–0.51) | 0.95 | 0.00 | 0.96 | 0.62 | 1.00 |
| Qwen3-0.6B | closed | 0.38 (0.30–0.45) | 0.95 | 0.00 | 1.00 | 0.53 | 0.62 |
| Qwen3-1.7B | closed | 0.37 (0.30–0.45) | 0.95 | 0.00 | 0.92 | 0.71 | 0.97 |
| Granite-4.0-H-350M | closed | 0.27 | 0.95 | 0.00 | 0.92 | 0.35 | 0.32 |
| Qwen3-1.7B | free | 0.40 | 0.71 | 0.16 | **0.60** | 0.70 | 0.92 |
| Qwen3.5-0.8B | free | **0.00** (unparseable) | 0.01 | 0.00 | 0.84 | 0.09 | 0.18 |

McNemar (verdict, model vs L0): every model is worse, p = 0.041 (Granite-H-1B) … < 0.0001 (Qwen3-1.7B).
Models do get **15–25 cases right that L0 gets wrong** — a disagreement signal worth testing as an
escalate-to-human trigger (follow-up, not measured).

### 1.2 Architecture D in miniature: L0 verdict + model explanation

| Explainer (closed) | Verdict | Explanation mention (CI) | RO language | Injection canary safe |
|---|---|---|---|---|
| none (L0 templates) | 0.59 | 0.27 (0.21–0.34) | — | 1.00 |
| **Qwen3-1.7B** | 0.59 | **0.73** (0.66–0.79) | 0.96 | 0.92 |
| **Granite-4.0-H-1B** | 0.59 | 0.71 (0.64–0.77) | 0.77 | 0.92 |
| **Qwen3.5-0.8B** | 0.59 | 0.64 (0.57–0.71) | **1.00** | 0.96 |
| Qwen3.5-2B | 0.59 | 0.62 (0.54–0.69) | 1.00 | 1.00 |
| Qwen3-0.6B | 0.59 | 0.56 (0.49–0.63) | 0.57 | 1.00 |
| Granite-4.0-H-350M | 0.59 | 0.40 | 0.23 | 0.92 |

"Explanation mention" is a keyword check against the blind author's gold list — a proxy for coverage,
not a judgement of prose quality. "RO language" checks the answer is in Romanian, not that the
Romanian is good; a native-speaker review is still required.

### 1.3 What did not work or was fixed during the run (all recorded)

- The first free-mode run showed the model only field names, not allowed values → every model scored
  0 on verdict. Fixed by giving both modes the same full schema; re-run.
- Showing a raw JSON schema makes the sub-1B Qwen3.5 copy the schema wrapper — a real small-model
  failure and a reason for grammar-closed decoding; a fairer free baseline would show an *example
  answer* instead (not run).
- Scorer fixes applied to **all** saved outputs (re-scored, not re-run): real IPs from the context
  are not hallucinations; fact ids are credited when a model quotes the whole card.
- Quality ran on Metal; the CPU-only path was stopped for time (~8× slower). Numerics differ slightly
  from a CM5's CPU kernels; quality conclusions are not expected to change, but this is unverified.
- `insufficient-evidence` calibration is poor for every model (0.00–0.50 on 20 cases): small models
  are over-confident. L0 handles these cases by rule.

## 2. Real-traffic replay of evidence cards (E-SC2) — IoT-23

**Data.** IoT-23 (Stratosphere Lab / Avast-AIC, Garcia, Parmisano, Erquiaga 2020, **CC BY 4.0**,
https://zenodo.org/records/4743746). The 21.5 GB archive was streamed and **only the Zeek
`conn.log.labeled` files kept**; the archive's MD5 matched the published value
(`7132e603f9750b8580b6cebdbcd43e9c`). Data is not committed. Scenarios were split dev/test **by a hash
of the scenario name before any result was seen**; changes to the compressor were made only on dev.
Cards were built from **behaviour only** — IoT-23 has no IDS detections and no DNS names — so this is
a harder test than the synthetic one. Scenarios larger than 1.5 M flows were truncated to their first
1.5 M rows.

| Split | Scenarios / windows | Raw window tokens (median) | Identity recall | Evidence recall | Flagged cards per benign window |
|---|---|---|---|---|---|
| dev | 10 / 40 | ~514,000 | 0.95 | 0.74 | 1.3 |
| **test (held out)** | **13 / 47** | **~44,000** | **0.88** | **0.65** | **1.1** |

Recall is identical at 256, 512, 1,024 and 2,048 tokens: real windows produce few cards, so the budget
never binds. Per family (test, 512): scan 10/10 identified (9 with the right evidence), flood 5/5,
malware 6/6, download 2/3, **C&C 15/20 identified, 10/20 evidenced; heartbeat 5/5 identified, 0/5
evidenced** — real C&C heartbeats are not regular enough for the `cv < 0.1` periodicity rule.

**Changes made during Phase 0 (before test results):** a per-(source, port) **host fan-out** card was
added before any IoT-23 data arrived, because per-pair cards cannot see horizontal scans; on the dev
data it immediately showed Mirai's port-23 scan of 869 hosts. A replay-scorer bug (inline alias
definitions not expanded) was found and fixed on dev data.

**Verdict on P1.** The mechanism survives contact with real traffic but is **not** at its kill
criterion (≥ 0.9 identity at 1K tokens): 0.88. The two fixes to validate next are a jitter-tolerant
periodicity test (e.g. autocorrelation or a looser CV with a minimum count) and a baseline-aware
novelty signal (the replay ran without a learned baseline, which inflates benign-window flags).

## 3. Behavioural memory on real traffic (E-BM2a)

Same `DNA` code and thresholds as the synthetic run; no retuning.

- **Nuisance (real benign device, Philips Hue honeypot capture, 22 active hours):** learned on the
  first 11 hours, scored the next 11 → **an alarm every scored hour (11/day)**. Diagnosis: the scored
  hours fell in hour-of-day slots never seen in training, so volume/activity baselines were zero.
  Peer novelty — the "who does it talk to" memory — stayed quiet (0.0–0.4). **Cold-start failure of the
  diurnal profile, not of the peer memory.** The other benign captures were too short (6 h) to score.
- **Onset (semi-synthetic: benign baseline, then real infected hours substituted):** 14 / 14 flagged
  within the first hour; 10 of 14 driven by peer novelty (credible), 4 by volume (confounded by the
  same cold start). Credible onset rate ≈ 0.71.
- **Verdict on P3:** peer memory looks promising on real devices; the diurnal profile needs a
  cold-start fallback (pooled statistics until a slot has enough history) and **multi-day benign
  traffic** to validate — IoT-23's benign captures are too short. A HookProbe home-network capture
  (with owner consent) is the right next dataset.

## 4. Speed of the explainer tier on CM5 (projection) — the "fast" question

LLMs cannot run at packet rate (≈ 6 orders of magnitude too slow); they only see compiled, escalated
incidents. Token counts are measured; CM5 times are **projected** with the method in
`summarize_runs.py` (decode = 11.8 GB/s ÷ model bytes; prefill scaled from the Arm Learning Path
Pi 5 measurement), conservative per the E-RF1 calibration.

| Model (Q4_0) | Cached prefix tokens | New prompt tokens / incident | Answer tokens | Projected s / incident | Projected incidents / min |
|---|---|---|---|---|---|
| Granite-4.0-H-350M | 113 | 413 | 79 | 2.4 | 24.7 |
| Qwen3-0.6B | 368 | 168 | 113 | 4.4 | 13.8 |
| **Qwen3.5-0.8B** | 121 | 397 | 93 | **6.2** | **9.7** |
| Granite-4.0-H-1B | 88 | 418 | 108 | 12.3 | 4.9 |
| Qwen3-1.7B | 360 | 175 | 120 | 13.2 | 4.5 |
| Qwen3.5-2B | 99 | 401 | 76 | 13.4 | 4.5 |

**Finding: hybrid/recurrent models lose prompt-cache reuse.** Qwen3.5 (DeltaNet) and Granite-H (Mamba-2)
reused only ~90–120 cached prefix tokens per incident vs ~360 for the plain transformers, so they
prefill 2–3× more tokens each time. Recurrent state cannot be truncated to a shared prefix the way a
KV cache can; with llama.cpp's slot reuse this costs CPU time — exactly the resource the CM5 lacks.
Saving and restoring a fixed-prefix state snapshot (proposal P5) would remove most of it; unmeasured.

## 5. What Phase 0 changes in the recommendation

1. **Architecture D is confirmed on independent data**: the deterministic core keeps the verdict;
   the model's job is explanation, language and owner-facing narrative. A model must never overrule
   an L0 verdict on its own (significantly worse); disagreement may *escalate to the owner*.
2. **Grammar-closed decoding is mandatory** for any explainer ≤ 2B.
3. **Explainer shortlist (pending CM5 measurement):**
   - **Qwen3.5-0.8B** — best balance for a fast tier: Romanian output 1.00, explanation 0.64, canary
     0.96, projected ~6 s/incident (~10/min); its prompt-cache loss is fixable by state snapshots.
   - **Qwen3-1.7B** — best explanation coverage (0.73) and Romanian (0.96); ~13 s/incident; for 8 GB+
     or low-incident sites.
   - **Qwen3-0.6B** — fastest acceptable English explainer (~4 s), weak Romanian (0.57).
   - Rejected for the explainer role: Granite-4.0-H-350M (Romanian 0.23, explanation 0.40).
4. **Not yet earned:** the evidence compiler's C&C handling (real-traffic recall 0.88/0.65) and the
   behavioural memory's diurnal profile (cold start). Both have concrete next steps.

## 6. Still open after Phase 0

| Item | Why it is open | Needs |
|---|---|---|
| Any CM5 measurement (E-HW1/2/6/7, E-LLM1/2, E-INT1, E-TH1) | **no CM5 is available** (operator, 2026-11-18) — deferred, not dropped | a CM5 on Raspberry Pi OS reachable over SSH; or, as a proxy, a **Raspberry Pi 5** (same BCM2712 SoC and LPDDR4X bus), with results labelled `pi5-linux`, never `cm5-*` |
| Native-speaker review of Romanian answers | language check ≠ quality | a Romanian-speaking reviewer |
| Second annotator for the blind set | single author | one more person, ~1 day |
| Multi-day benign traffic for E-BM2 | IoT-23 benign captures ≤ 22 h | consented home/SMB capture |
| Ternary (BitNet) comparison E-LB1 | bitnet.cpp needs a native build (no cmake here) | a CM5 or Pi 5 bench unit |
| Free-mode baseline with an example answer | fairness of the closed-vs-free comparison | ~20 min of dev-host time |

## 7. Reproduce

```bash
cd tools/neuro-research
python3 -I fetch_models.py <models dir>                                   # verified downloads
./eval_models.sh <llama.cpp bin> <models dir> eval/blind/blind_cases.jsonl <out> 1 -ngl 99
python3 -I summarize_runs.py <out> --models-dir <models dir> --cases eval/blind/blind_cases.jsonl
python3 -I replay_iot23.py <iot23 dir> --split test                       # E-SC2 (needs NEURO_LLAMA_TOKENIZE/NEURO_VOCAB)
python3 -I replay_bm_iot23.py <iot23 dir>                                 # E-BM2a
```

Per-case outputs of the blind run: `data/runs-blind/` (model answers to synthetic cases; no real
traffic). Aggregates: `data/e-ev1-*`, `data/e-sc2-*`, `data/e-bm2a.*`.

## 8. Consequence of having no CM5 (2026-11-18)

The operator confirmed no CM5 is available. What this means for the decision:

- **Architecture D does not change.** Its core (L0 rules, evidence cards, behavioural memory) is
  integer-only and runs without a model; Phase 0 validated it on independent and real-traffic data.
- **The generative tier stays unratified.** The speed figures in §4 remain projections; the eval
  gate's p95-latency and E-INT1 (does decoding hurt the packet path?) items cannot be passed without
  hardware, so no explainer model may be enabled on a CM5 SKU until they are measured.
- **Acceptable proxy:** a Raspberry Pi 5 shares the BCM2712 SoC and the 32-bit LPDDR4X bus, so
  `cm5_bench.sh` runs unchanged and its bandwidth, decode and interference numbers transfer. Board-level
  items (thermal in the HookProbe enclosure, power, eMMC vs SD/NVMe storage) do not, and stay open.
- **Work that needs no hardware** and can continue: Romanian native review, second annotator,
  jitter-tolerant periodicity and cold-start fallback for the behavioural memory (dev split only,
  then re-test once), and the free-mode example-answer baseline.

## 9. Phase 0b — the two fixes proposed in §5 (2026-11-18)

Both fixes were tried with the rules set in §2–§3: periodicity changes on the IoT-23 **dev split
only**; the behavioural-memory change designed on synthetic data, then run **once** on IoT-23.

### 9.1 Jitter-tolerant periodicity — rejected

Timing of the dev-split pairs (`tools/neuro-research/profile_gaps_iot23.py`) showed why the strict rule misses C&C: real C&C and heartbeat gaps have a coefficient of
variation of **0.28–0.54**, while benign cloud polling in the same captures is near-perfect (**0.02**).
A rule that counts a gap if it falls within 25% of 1–3× the median gap, with ≥ 60% of gaps counting:

| Dev split @512 | Strict rule (Phase 0) | Jitter-tolerant |
|---|---|---|
| C&C evidence | 0 / 7 | 1 / 7 |
| Heartbeat evidence | 0 / 5 | 0 / 5 |
| Evidence recall (all) | 0.741 | 0.759 |
| Flagged cards per benign window | 1.3 | **2.0** |

One more evidenced incident for 54% more benign flags. **Rejected; the test split was not touched.**
The code stays, off by default (`JITTER = 0.0` in `semantic_compression.py`). The lesson: on real IoT
traffic, *regularity is not what distinguishes C&C* — benign devices poll more regularly than malware
does. What should distinguish it is **novelty against the device's own baseline** (a periodic pair the
device never had before), which needs a learned baseline that IoT-23's infected-from-the-start
captures cannot provide. It stays open for a consented home/SMB capture.

### 9.2 Behavioural-memory cold start — fixed

Three changes in `behavioural_memory.DNA` (+34 B per device, 672 B total at 1,024-bit Blooms):

1. **Warm-up:** a slot's first samples are a running mean (α = max(0.15, 1/n)) instead of an EWMA
   starting from zero — Phase 0 slots took ~10 days to converge even when visited.
2. **Pooled fallback:** a slot with fewer than 3 updates is scored against a blend of its own profile
   and an all-hours pooled profile, widened by up to 2×, instead of against zero.
3. **Cold slots learn statistics on an alarming hour** (volume, activity, fan-out — never new peers or
   DNS suffixes, which still need 6 alarming hours). Without this a slot whose first visit alarms can
   never warm up.

| Run | History before scoring | AUC | Benign alarms / device-day (score > 2) | Incident detection @1% FPR (beacon / DGA / exfil / new service / scan) |
|---|---|---|---|---|
| synthetic, Phase 0 DNA | 10 days | 0.999 | 0.03 | 1.00 all |
| synthetic, Phase 0b DNA | 10 days | 0.999 | 0.03 | 1.00 all (benign-drift alert hours 39 → 30) |
| synthetic, Phase 0 DNA | **12 hours** | 0.699 | **21.2** | 0.00 / 0.00 / 0.67 / 0.00 / 1.00 |
| synthetic, Phase 0b DNA | **12 hours** | 0.928 | **0.35** | 0.93 / 1.00 / 1.00 / 0.80 / 1.00 |
| **IoT-23 Hue honeypot (real)**, Phase 0 → 0b | 11 active hours | — | **11 → 2 per day** | — |
| **IoT-23 onset (semi-synthetic)**, Phase 0 → 0b | 11 active hours | — | — | 14 / 14 → 14 / 14 flagged; drivers 10 novelty + 4 volume → **14 novelty** |

Files: `data/e-bm1.*`, `data/e-bm1-cold.*` (synthetic), `data/e-bm2b.*` (IoT-23).

**What this does and does not show.** The synthetic gain is large and the real benign device improves
5.5×, but the real evidence is **one device over 11 scored hours** — not a nuisance rate anyone should
quote. The design target (< 1 nuisance alert per device per week, E-BM2) still needs multi-day benign
traffic. The new risk: an attacker active during a slot's first three updates can teach that slot's
*volume* profile (not its peers). Peer novelty, which drove every real onset detection, is unaffected.

## 10. Phase 0b — a fair free-mode baseline (E-EV3, 2026-11-18)

**Why.** In Phase 0, free mode got the raw JSON schema in its prompt, and small models copied the
schema back instead of answering (Qwen3.5-0.8B scored 0.00). That made "closed beats free" partly a
prompting artefact.

**Design, frozen on the 28 dev cases before the blind run:**
- free mode gets the same contract in plain words (keys and allowed values);
- plus **one fixed example answer** (`--example`, `run_eval.py`; `MODES=freeex` in `eval_models.sh`).

On dev this fixed the copying (Qwen3.5-0.8B triage 0.00 → 0.63). The blind set was then run **once**.
Full table: [`data/e-ev3-freeex.md`](data/e-ev3-freeex.md). Outputs: `data/runs-blind-freeex/`.

| Model | Verdict closed | Verdict free (Phase 0) | **Verdict free + example** | McNemar closed vs free+ex | Canary-safe closed / free+ex | "suspicious" share closed / free+ex |
|---|---|---|---|---|---|---|
| Qwen3-0.6B | 0.377 | 0.309 | 0.354 | p = 0.74 | 1.00 / 0.80 | 0.00 / 0.63 |
| Qwen3-1.7B | 0.371 | 0.400 | 0.411 | p = 0.23 | 0.92 / 0.80 | 0.43 / 0.37 |
| Qwen3.5-0.8B | 0.440 | 0.000 | 0.423 | p = 0.84 | 0.96 / 0.88 | 0.03 / **0.93** |
| Qwen3.5-2B | 0.474 | 0.240 | 0.440 | p = 0.29 | 1.00 / 0.96 | 0.80 / 0.97 |
| Granite-4.0-H-1B | 0.497 | 0.331 | 0.434 | p = 0.12 | 0.92 / 0.92 | 0.45 / 0.71 |
| Granite-4.0-H-350M | 0.246 | 0.194 | 0.126 | **p = 0.006** | 0.92 / 0.96 | 0.31 / 0.33 |

**Constant answers on the same 175 cases:**

| Strategy | Verdict accuracy |
|---|---|
| always "malicious" | 0.43 |
| always "suspicious" | 0.42 |
| always "benign" | 0.41 |
| **L0 rules** | **0.594** |

What changes:
1. **"Free mode is worse everywhere" (Phase 0) is withdrawn.** With a fair prompt, free and closed
   verdict accuracy are statistically indistinguishable for five of six models.
2. **The models anchor on the example's verdict.** Qwen3.5-0.8B answered "suspicious" 93% of the
   time, and its 0.42 equals the constant-"suspicious" baseline. A small model's verdict is closer
   to an echo of its prompt than to a judgement.
3. **The models are at or below a constant answer at judging.** Only L0 (0.59) clearly beats one.
   This strengthens the Phase 0 conclusion that **the model explains and L0 decides**.
4. **Closed decoding still blocks more injections** in four of six models. Its justification is now
   safety and evidence-closure, not verdict accuracy.
