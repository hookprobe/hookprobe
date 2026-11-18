# 11 — Benchmark plan (Gate 11)

> Native Inference Research Programme, 2026-11-18. **No result in this programme comes from a CM5.**
> Every result is labelled by where it ran:
>
> | Label | Where |
> |---|---|
> | `devhost` | Apple M5 Pro |
> | `cm5-linux` | Raspberry Pi OS on a CM5 bench unit |
> | `pi5-linux` | Raspberry Pi 5, same SoC |
> | `qemu-heqk` | heqk under QEMU |
> | `cm5-heqk` | the product |
>
> A Linux result is **never** presented as a heqk result. Statistics follow
> `NEURO_EXPERIMENT_DESIGN.md` §5: ≥ 5 runs, 95% CI, McNemar for paired quality, throttle flags recorded.

## 1. Experiments, ordered by decision value

| ID | Question | Label | Needs | Method | Metrics | Kill / decision criterion |
|---|---|---|---|---|---|---|
| **E-N0** | Does the temporal/specialist tier fit heqk as-is? | qemu-heqk → cm5-heqk | R1 only (an EL0 crate) | fixed-point port of DNA + int8 heads; replay IoT-23 and bench captures through the detection ring | cycles/event, excursion time, bytes/device, AUC parity with the Python reference | **> 1% of one core at 1K events/s**, or AUC drift > 0.005 vs reference → redesign |
| **E-N1** | Do the kernels hit the `02` model? | pi5/cm5-linux | a bench unit | `kernels/bench` built with `-mcpu=cortex-a76`, 1–4 threads, matrices ≫ L3 | GEMV Gweights/s, GB/s, per kernel; perf counters if available | if packed-LUT < Q4_0 speed **and** bytes, drop ternary from the plan |
| **E-N2** | Does a learned per-device recurrent cell beat the statistical DNA at equal bytes? | devhost | none | tiny int8 GRU/minimal-RNN per device on IoT-23 (dev/test split by scenario) + multi-day benign capture | AUC, detection @1% FPR, alarms/device/day, poisoning (slow ramp) | **< +0.02 AUC at equal bytes → reject** (E-BM2 rule) |
| **E-N3** | Does a recurrent LM explain as well as a transformer? | devhost (quality), pi5/cm5-linux (speed) | RWKV-7 0.4B / 1.5B GGUF (Apache-2.0) | blind set, closed mode, L0-verdict hybrid; same scorer | explanation mention, RO language, canary safety, citations; tok/s; state bytes | if worse than Qwen3.5-0.8B hybrid by > 0.05 mention at equal or larger size → keep transformer/hybrid |
| **E-N4** | Ternary language model on CM5 | pi5/cm5-linux | BitNet 2B4T via bitnet.cpp (I2_S, TL1) vs Qwen3-1.7B Q4_0 | blind set + `llama-bench`-style speed | quality, tok/s, J/answer, DRAM GB/s during decode | ternary not ≥ 1.3× better on tok/s **and** J/answer at equal-or-better quality → not worth a native port (E-LB1) |
| **E-N5** | Does decode hurt the packet path? | cm5-linux proxy, later cm5-heqk | bench unit + traffic generator | packets through the unit, idle vs decode at 1/2/4 threads, per format | p50/p99 latency, Mpps, drops; DRAM GB/s | p99 unaffected → pacing unnecessary; else E-N5b |
| E-N5b | Does open-loop pacing (bytes/token budget) restore it? | same | same | budgets 10/25/50% of the bus | same + tok/s | must restore p99 within 5% of idle |
| **E-N6** | How much does grammar-sparse logits save? | devhost | Phase 0 outputs | count, per answer, the tokens generated under an enum/ID constraint vs free text; compute the head FLOPs saved | % of head bytes avoided per answer | < 10% → not worth the engine complexity |
| E-N7 | Vocabulary trimming EN/RO/security | devhost | Qwen3.5-0.8B / Qwen3-0.6B | trim with `vocabtrimmer`-style method, re-run the blind set | quality delta, head size | > 0.02 loss in mention or RO language → keep the full vocabulary |
| E-N8 | Model load and verification | cm5-heqk | R3–R5 | load a 300 MiB HNX from DataVolume, hash and verify | s to ready, MB/s, CPU during load | > 60 s on 4 GB SKU → load-at-boot only |
| E-N9 | Worst-case interference and recovery on heqk | cm5-heqk | R2–R8 | inference at max lease + line-rate replay + fault injection in the engine | main-loop worst gap, DP p99, engine restart time | any increase of the main-loop worst gap above its 330–347 ms baseline → fail |
| E-N10 | Thermal and energy | cm5-linux | enclosure, power meter | 10 min sustained decode | throttle flags, clock, W, J/answer | throttle before 10 min → duty-cycle cap |

## 2. The comparison grid (identical tasks and data)

Formats: FP16 baseline (devhost only), INT8, INT4, ternary. Architectures:
- recurrent (RWKV-7);
- specialists;
- the hybrid (Qwen3.5);
- transformer (Qwen3).

All are evaluated on:
- **Security quality:**
  - the blind set (215 cases; closed mode; L0 hybrid);
  - IoT-23 replays (test split, scenario-hashed);
  - a consented multi-day home/SMB capture with a temporal split, per Arp et al. [R131];
  - metrics: precision, recall, FPR, calibration (reliability of `confidence`), time-to-detection.
- **Language quality:** explanation mention, RO language, citation validity, canary safety. The
  constant-answer baselines (0.42–0.43 verdict) are always printed next to model scores.
- **Resources:** peak and steady RAM, arena, state bytes, storage footprint, load and verify time, TTFT,
  tok/s, per-event latency, CPU-s per answer, J per answer, DRAM GB/s.
- **Protection:** DP p99, Mpps and drops under each configuration (E-N5).

## 3. Pareto frontier

Configurations are plotted on **validated quality × each resource**: RAM, CPU-s, J, p95 latency,
DRAM GB/s and DP p99 impact. Any configuration that fails E-N5/E-N9 is removed **before** plotting.
The frontier is published with the raw numbers. No single "efficiency score" replaces it (the UIE
rule in `NEURO_EXPERIMENT_DESIGN.md` §4).

## 4. What can run now, without hardware

| Experiment | Status |
|---|---|
| E-N2 | devhost; needs a multi-day benign capture for the nuisance part |
| E-N3 quality | devhost; RWKV-7 GGUF download needs approval (Phase 0 approved 3–4 Apache-2.0 models; RWKV-7 would be a new download) |
| E-N6 | devhost; can run on the existing Phase 0 outputs, nothing to download |
| E-N7 | devhost |
| Everything else | needs a CM5 or Pi 5 bench unit, or HomePods R0–R8 |
