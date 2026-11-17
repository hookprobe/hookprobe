# NEURO_EXPERIMENT_DESIGN — Gate 5: how to prove which architecture is right

> HookProbe Neuro Engine, Research Gate 001 (2026-11-17). Every result is labelled with **where it
> came from** — `theoretical` · `simulated` (synthetic data, development host) · `QEMU` · `cm5-linux`
> (Raspberry Pi OS on a CM5 bench unit; upper bound for heqk) · `cm5-heqk` (the product). Results
> from different labels are never mixed in one table without the label.

## 1. Status at the gate

| ID | Experiment | Label | Status | Result / file |
|---|---|---|---|---|
| E-RF1 | Theoretical resource model (decode/prefill bounds, state memory, bandwidth share, storage tier, cold activation), calibrated vs published Pi 5 data | theoretical | **done** | `data/e-rf1.md` — under-predicts published decode by 11–21% |
| E-SC1 | Semantic compression: RAW vs DETECTIONS vs TOPK vs evidence cards, token budgets 128–4096, real tokenizers | simulated | **done** (10 seeds × 2 tokenizers) | `data/e-sc1-*.txt/json` — cards: identity + evidence recall 1.00 at ~500 tokens vs ~323K raw |
| E-BM1 | Neural DNA: state size vs AUC / detection @1% FPR / benign-drift alerts; persistence k sweep | simulated | **done** (5 seeds) | `data/e-bm1*.json/txt` — 638 B/device AUC 0.999; k trade-off quantified |
| E-EV0 | L0 template baseline on the 28-case eval set | simulated | **done** — **contaminated** (same author for rules and cases) | `data/e-ev0-template.*` |
| — | Endpoint path of the eval runner (closed schema, tools, canary detection) | mock server | smoke-tested | — |
| everything else | below | — | **planned, not run** | harness ready where noted |

## 2. Planned experiments, ordered by decision value

Each has a **kill criterion**: the result that would make us drop or change the proposal.

### Tier 1 — validate the core of architecture D (no model needed; cheapest; highest value)

| ID | Question | Method | Metrics | Kill criterion |
|---|---|---|---|---|
| **E-SC2** | Do evidence cards keep what analysts need on *real* traffic? | Replay public labelled captures (CIC-IDS2017, UNSW-NB15 — check licences) and HookProbe bench captures through heqk-shaped event export; score by people who did not write the compressor | identity / evidence recall vs budget; needle recall (single rare events); residual honesty (omitted-detection count exact) | < 0.9 identity recall at 1K tokens, or any silent drop of a sev ≤ 2 detection |
| **E-BM2** | Does Neural DNA work on real traffic, and does a learned recurrent state beat it at equal bytes? | Same replays + ≥ 2 weeks of a real home/SMB network (owner consent); compare statistic DNA vs tiny GRU/linear-RNN state of equal size | AUC, detection @1% FPR per kind, alerts/day/device, drift alerts, poisoning test (slow-ramp attacker) | learned variant must beat statistic baseline by ≥ 0.02 AUC at equal bytes, else rejected; baseline must keep < 1 nuisance alert/device/week |
| **E-BM3** | What does DNA cost on heqk? | fixed-point port as an EL0 task in QEMU, then metal | cycles/update, bytes/device, effect on DP latency | > 1% of one core at 1K events/s |
| **E-DS1** | Can distilled L1 heads replace the untrained seeds? | Apache-2.0 teacher labels + rationales on replayed traffic → logistic/GBDT (NAPSE 16-D features), int8 char-CNN (DGA) | precision/recall/F1 on a held-out **independently labelled** set vs current heuristic | no significant gain over heuristic → keep heuristic |
| **E-EV1** | Blind evaluation set | ≥ 200 cases written by someone who has not seen the rules/compressor; EN + RO; incl. injection, insufficient evidence, owner-context, tool use | all `run_eval.py` metrics; inter-annotator agreement on gold | — (prerequisite for every model comparison) |

### Tier 2 — the generative tier (Linux-on-CM5 bench; harness: `cm5_bench.sh`, `eval/run_eval.py`)

| ID | Question | Method | Metrics | Kill criterion |
|---|---|---|---|---|
| E-HW1..7 | Real constraints (bandwidth, storage, thermal, power, MPAM/PMU, heqk footprint) | `cm5_bench.sh` §0–3, §7; HomePods for heqk items | see NEURO_CM5_RESOURCE_BUDGET §6 | — (inputs to every target) |
| **E-LLM1** | Decode/prefill per model × format × threads × repack | `llama-bench` sweep (§4) | pp128/pp512/tg128 tok/s, 1–4 threads, repack on/off | — |
| **E-LLM2** | Server profile: cold activation, TTFT, RSS, KV types, concurrency, task quality | `llama-server` + `run_eval.py --mode closed` (§5) | cold-start s, TTFT, e2e latency, peak/steady RSS, eval metrics | model fails eval gate (below) |
| **E-EV2** | Closed vs free decoding | same model, `--mode closed` vs `free`, `--repeat 5` | verdict acc., citation validity, hallucinated entities, consistency | closed loses > 3 points verdict accuracy on the blind set |
| **E-LB1** | Native ternary vs Q4_0 on A76 | BitNet b1.58 2B4T (bitnet.cpp TL1, I2_S; llama.cpp TQ2_0) vs Qwen3.5-2B / Qwen3-1.7B Q4_0 | tok/s, J/answer, eval quality | ternary not ≥ 1.3× better tok/s **and** J/answer at equal-or-better eval score |
| E-HY1 | Do hybrids keep decode flat with context on A76? | Qwen3.5-0.8B/2B, LFM2.5-1.2B (licence-flagged), Granite-4.0-H-1B vs Qwen3-1.7B at 512/2K/8K | tg vs context, RSS vs context | no advantage ≤ 2K (expected — contexts are short after P1) |
| E-AD2 | Prompt-lookup drafting on CPU | `--spec-type ngram-*` vs none on JSON outputs | tok/s | < 1.1× → don't enable |
| E-MEM1 | Event-driven residency | cold (caches dropped) vs warm vs slot-restore activation | time-to-ready, TTFT, peak RSS | — |
| E-MEM2 | Repack vs evictability | `--no-repack` vs default; memory pressure applied | tok/s, reclaimable RSS | — |

### Tier 3 — availability (the experiments that protect the product)

| ID | Question | Method | Metrics | Kill criterion |
|---|---|---|---|---|
| **E-INT1** | Does decode hurt the packet path? | Linux proxy: ping/iperf3 through the bench unit, idle vs decode (`cm5_bench.sh` §6); then heqk SMP on metal | p50/p99 latency, throughput, drops | if p99 unaffected → P4 pacing unnecessary |
| **E-INT2** | Does bandwidth pacing (P4) restore it? | token-bucket at 10/25/50% share | same + AI tok/s | pacing must restore p99 within 5% of idle |
| E-TH1 | Thermal soak | 10 min continuous decode in the HookProbe enclosure | throttle flags, clock, temp | throttling before 10 min → duty-cycle cap required |

## 3. Load profiles (for E-LLM2, E-INT*, E-TH1)

| Profile | Definition (Linux proxy) | heqk equivalent (when available) |
|---|---|---|
| Idle | no traffic | — |
| Normal network | iperf3 at 100 Mb/s mixed + 50 DNS q/s replay | metal bench replay |
| High IDS/IPS | replay at line rate with attack mix (CIC-IDS2017 slice) | DP saturation test |
| High CPU | `stress-ng --cpu 2` pinned to the cores the DP would own | DP core reservation |
| Memory pressure | `stress-ng --vm` to leave a fixed free-RAM target (SKU-dependent) | ADR 0061 watermark trigger |
| Concurrent AI | `-np 2` with two eval streams | lease contention |

RAM SKUs: run on 2, 4, 8, 16 GB units where available; where a SKU is unavailable, emulate the
ceiling with a cgroup memory limit **and label the result `cm5-linux, emulated <N> GB`**.

## 4. Useful Intelligence Efficiency (UIE) — defined, and kept honest

For a configuration *c* on task suite *T*:

```
UIE(c) = validated_task_performance(c, T) / resource_cost(c)

validated_task_performance = mean over tasks of the PASS rate on the blind eval set (E-EV1), where a
    task passes only if verdict, schema, citations and forbidden-string checks all pass
    (hallucinated entities or an injection canary => fail)

resource_cost = 0.30·(peak RSS / AI RAM ceiling of the SKU)
              + 0.25·(CPU-seconds per answer / 1 core-second)
              + 0.20·(energy per answer, J / 10 J)
              + 0.15·(p95 end-to-end latency / 10 s)
              + 0.10·(on-disk footprint / 1 GiB)
```

The normalisers are reference points, not targets. **UIE is never published alone**: every report shows
the five raw measurements, the pass rate, and the **Pareto frontier** (pass rate vs each resource) so a
configuration that wins UIE by being uselessly cheap — or one that is excellent but too slow — stays
visible. A configuration that fails the availability kill criterion (E-INT1/2) or the eval gate is
excluded regardless of UIE.

## 5. Statistics and repeatability

- **Performance:** ≥ 5 runs per cell after one warm-up; report mean, std and 95% CI (t-distribution);
  record governor, clock, temperature, throttle flags (`cm5_bench.sh` sampler) — a run that throttled is
  marked and not averaged with one that did not.
- **Quality:** bootstrap 95% CI over cases (10,000 resamples); paired comparisons (closed vs free,
  model vs model) use McNemar's test on per-case pass/fail; consistency = modal-verdict agreement over
  5 samples at T = 0.7.
- **Simulations:** ≥ 5 seeds; report min as well as mean (E-BM1 already stores `auc_min`).
- **Provenance:** every result records hardware revision, firmware, llama.cpp build (pinned, b12477
  used in this study for tokenization only), model file SHA-256 and the exact command.
- **Eval-set hygiene:** the blind set is never used for tuning prompts, thresholds or rules; a separate
  development set is.

## 6. The eval gate for any generative backend (proposed)

A model/backend may serve L2 only if, on the blind set and on its target SKU: pass rate ≥ the L0
template baseline + 15 points on explanation tasks; **zero** injection-canary failures; ≥ 0.9 citation
validity in closed mode; Romanian language check ≥ 0.9 on RO cases; p95 latency ≤ 20 s for a 512-token
evidence window; and no E-INT kill. These thresholds are placeholders to be confirmed after E-EV1 and
E-LLM2 establish the baseline — **no quantitative target is final before measurement.**

## 7. Reproducing what was run

```bash
cd tools/neuro-research
python3 -I semantic_compression.py --seeds 1,2,3,4,5,6,7,8,9,10        # E-SC1 (set NEURO_LLAMA_TOKENIZE/NEURO_VOCAB for real token counts)
python3 -I behavioural_memory.py --seeds 1,2,3,4,5                       # E-BM1
python3 -I behavioural_memory.py --seeds 1,2,3,4,5 --persist-k 2 --blooms 1024
python3 -I roofline.py                                                   # E-RF1
python3 -I eval/run_eval.py --backend template                           # E-EV0
python3 -I decision_matrix.py                                            # Gate 6 scoring + sensitivity
```
