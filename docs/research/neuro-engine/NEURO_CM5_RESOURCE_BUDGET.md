# NEURO_CM5_RESOURCE_BUDGET — Gate 0: the real constraints

> HookProbe Neuro Engine, Research Gate 001. Status: research, 2026-11-17. Nothing in this document
> was measured on a CM5 by this study. Every number carries its source and an evidence class:
> **[S]** official spec / datasheet · **[P]** published third-party measurement (conditions given) ·
> **[R]** read from this repository's code or ADRs · **[T]** theoretical estimate (our arithmetic) ·
> **[U]** unknown, needs metal.

## 1. Two CM5s, not one

The research has to distinguish two very different platforms that share the same silicon:

| | **CM5 running heqk** (the product, ADR 0044/0047) | **CM5 running Linux** (a bench proxy) |
|---|---|---|
| Who runs it | every HookProbe CM5 device | a lab unit only |
| Cores available to software | **1** — hboot parks cores 1–3 (`hboot/src/boot.s:28-30`, ADR 0060 S1) **[R]** | 4 |
| FP / SIMD (NEON) | **trapped** — `CPACR_EL1.FPEN` never set; no q-register save (GAP_REGISTER CORE-7, remediation A5) **[R]** | available, incl. dotprod |
| RAM mapped | first 4 GiB only (`mmu_cm5.rs`, `NORMAL_GBS = 4`; ADR 0061 M1) **[R]** | all |
| Memory a new EL0 server can get | **≤ 128 MiB**: the runtime frame pool is `0x3000_0000..0x3800_0000`, bump-allocated, never freed (`mmu_cm5.rs:405-425`, ADR 0061 M3) **[R]** | gigabytes |
| Demand paging / page cache / mmap | none **[R]** | yes |
| Storage | eMMC (driver in-tree); **no NVMe driver** (no `nvme` in `os/kernel`) **[R]** | eMMC + NVMe |
| Memory-pressure signal | none (ADR 0061 M9) **[R]** | PSI |
| RAM size known to the OS | no — not read from the DTB (ADR 0061 M2/M10) **[R]** | yes |

**Consequence (the most important Gate-0 finding).** On the product substrate *today*, no neural
inference of any size can run on the device: one core that belongs to the data plane, no SIMD, no
floating point, and 128 MiB for every EL0 server combined. Every claim in this package about running
models "on CM5" is therefore about a **future heqk** that has landed ADR 0060 (SMP + core roles),
ADR 0061 (memory discovery + budgets) and a decision on CORE-7/A5 (FP/SIMD policy). Those are
kernel changes owned by **HomePods**; this study proposes nothing that modifies them and lists them
as **prerequisites** in `NEURO_FINAL_RECOMMENDATION.md`.

What *can* run on heqk today: scalar-integer code in an EL0 task — deterministic rules, the
evidence-card compressor (P1), and a fixed-point "Neural DNA" behavioural memory (P3). That is why
those three are designed integer-only.

Linux-on-CM5 measurements (the harness in `tools/neuro-research/cm5_bench.sh`) are an **upper bound**
for what a native heqk EL0 inference server could reach on the same silicon, never a product claim.

## 2. Silicon facts (BCM2712 / CM5)

| Item | Value | Class / source |
|---|---|---|
| CPU | 4 × Cortex-A76 @ 2.4 GHz, Armv8.2-A, NEON + **dotprod** + fp16; **no i8mm, no SVE, no SME** | [S] Raspberry Pi processors docs; Arm Cortex-A76 TRM |
| Caches | 64 KB L1-I + 64 KB L1-D per core; **512 KB L2 per core**; **2 MB shared L3** | [S] processors docs |
| RAM | 2 / 4 / 8 / 16 GB LPDDR4X-4267, **ECC**, **32-bit** bus | [S] CM5 product brief, datasheet |
| Peak DRAM bandwidth | 32 bit × 4267 MT/s = **17.07 GB/s** | [S] / [T] |
| Measured DRAM bandwidth (Pi 5, same SoC + memory type) | **11.82 GB/s** overall; 13.78 GB/s best single-thread read; 10.7 GB/s at 4 threads | [P] Arm Learning Path `llm-decode-roofline` (Pi 5 2 GB, ondemand governor, not throttled) |
| eMMC | 0 (Lite) / 16 / 32 / 64 GB | [S] brief |
| PCIe | **Gen 2 ×1** (5 GT/s); Gen 3 "possible… unsupported" | [S] datasheet §2.3 |
| GPU | VideoCore VII; Vulkan via v3dv. **Not usable for LLMs**: upstream llama.cpp Vulkan fails on V3D's 16 KB shared-memory limit; a patched run was ~80× slower than CPU | [P] llama.cpp #9801, #26213, PR #26214 (closed unmerged) |
| Thermal | progressive Arm throttling 80–85 °C; at 85 °C Arm cores + GPU throttle; CM5 has less passive heatsinking than Pi 5 | [S] Pi frequency-management docs |
| Power | idle ~400 mA, typical ~900 mA (at 5 V) → ~2 W / ~4.5 W; PSU design 5 V / 2.5 A | [S] datasheet §3.3 |
| Power under LLM load | CM5 dev kit, Ollama, DeepSeek-R1 1.5B: **10.2–10.6 W at the wall** | [P] CNX Software review (Jan 2026), secondary |
| MPAM (cache/bandwidth partitioning) | almost certainly **absent** (Armv8.4 optional feature; A76 is v8.2) | [U] verify `ID_AA64PFR0_EL1[43:40]` on metal |
| Production lifetime | until at least January 2036 | [S] brief |

## 3. Accelerators — do they change the answer?

| Option | LLM? | On heqk? | Verdict |
|---|---|---|---|
| VideoCore VII GPU | no (see above) | no driver | **rejected** |
| Hailo-8 / 8L (AI HAT+) | **no LLMs** (vision; only a VLM *encoder*) | no driver | not relevant to language |
| **Hailo-10H** (AI HAT+ 2 / M.2; 8 GB on-module LPDDR4X, 2.5 W typ.) | yes, ≤ ~6B, 2K context. Hailo's own figures (host unstated): Llama-3.2-1B 9.8 tok/s, TTFT 0.35 s; Qwen3-1.7B 4.7 tok/s; Qwen3-4B 2.1 tok/s | needs a PCIe endpoint driver + HailoRT on heqk — **none exists**, and the driver is GPL-2.0 Linux code | **interesting for the RK3588 board era, not for CM5-on-heqk** |
| | Raspberry Pi: prefill 96 tokens on Qwen2.5-1.5B **320 ms on Hailo-10H vs 2039 ms on Pi 5 CPU** **[P]**; CNX: decode **slower** than CM5 CPU (6.7 vs 11.7 tok/s on Qwen2.5-1.5B) **[P]** | | it buys prefill/TTFT and frees the CPU and DRAM; it does not buy decode speed |
| Axelera Metis, DeepX DX-M1 | experimental / roadmap for LLMs | no driver | not evaluable |
| Google Coral | cannot run LLMs | — | rejected |

An NPU's most valuable property for HookProbe is not speed — it is **isolation**: its own DRAM and
its own power envelope, so inference stops competing with the packet path for the 32-bit LPDDR4X bus
(§5). ADR 0064's RK3588 board has an on-chip NPU plus an M.2 slot, which is where this belongs.

## 4. What the hardware means for generative inference (theoretical, calibrated)

From `tools/neuro-research/roofline.py` (full output: `data/e-rf1.md`) **[T]**, calibrated against
two published Pi 5 measurements (Arm Learning Path: Qwen2.5-0.5B Q4_0 33.8 tok/s, Qwen2.5-1.5B Q4_0
12.4 tok/s). The model *under*-predicts by 11–21%, so treat its bounds as conservative.

- **Decode is memory-bandwidth-bound.** tok/s ≈ effective bandwidth ÷ bytes read per token. At
  11.8 GB/s: a 0.6B model at Q4_0 ≈ 35 tok/s; 1.7B ≈ 10; 4B ≈ 5; 8B ≈ 2. **More RAM does not make a
  bigger model fast**: 16 GB buys context, concurrency and caching — not speed.
- **Prefill is compute-bound.** int8-dotprod peak ≈ 307 G MAC/s on 4 cores; the published
  Qwen2.5-0.5B pp512 of 290 tok/s is ~47% of that peak.
- **Decode wants 2 threads, prefill wants 4.** Published: decode peaks at 2 threads (33.8 tok/s) and
  falls at 4 (27.3) because the bus is saturated; prefill scales to 4 **[P]**.
- **Storage is not a RAM tier for decode.** A dense 1.7B Q4_0 model re-read from eMMC every token
  costs 3.6–10.9 s/token; from NVMe on Gen2 ×1 ≈ 2.7–3.1 s/token **[T]**. Storage is the *cold*
  tier only: load once, decode from RAM.

## 5. The availability budget — what AI must never take

The packet path and the model share one 32-bit LPDDR4X bus with no hardware partitioning (§2). The
literature is unambiguous that a bandwidth-heavy co-runner degrades packet processing: co-located
network functions lost up to 44.3% throughput and 24.5% p95 latency until cache partitioning was
applied (ResQ, NSDI 2018) **[P]**; a concurrent on-device LLM raised smartphone UI jank by 153%
while losing only ~1–2% of its own throughput (Sereno, OSDI 2026) **[P]**. **The model barely notices
the interference; the victim does.** On CM5 the victim is the data plane.

So the budget is set in **four** currencies, not one:

| Currency | Rule (proposed) | Why |
|---|---|---|
| **CPU** | AI is an MG-role, best-effort tenant (ADR 0060 D4). It never runs on a DP core. Gateway profile (DP ≥ 60% of cores) leaves **≤ 1 core** for MG + AI on a 4-core CM5; SASE PoP leaves none. | ADR 0060 D5 floors |
| **DRAM bandwidth** | AI decode is paced to a bandwidth share: `tok/s ≤ share × BW_eff ÷ bytes_per_token` (proposal P4). Default share 25%, dropped to 0 when the DP reports pressure. | no MPAM; ResQ / Sereno |
| **RAM** | AI lives in its own ADR 0061 budget, admitted at configuration time, with watermarks. AI is the **first** budget shed under pressure. | ADR 0061 D2/D5 |
| **Thermal / power** | AI duty cycle is cut before the SoC reaches 80 °C; no sustained decode above a temperature threshold. | throttle points [S] |

### Illustrative RAM budgets per SKU (planning assumptions, not measurements)

The core reserve (heqk + data-plane pools + detection + Mission Control + TLS + telemetry + headroom)
has **not been measured** on any SKU **[U]** — today heqk does not even know the RAM size. The table
uses a placeholder reserve of 1 GiB so the arithmetic can be read; replace it with the measured value
from experiment E-HW3.

| SKU | Core reserve (placeholder) | AI ceiling (proposed) | What fits in the AI ceiling (weights Q4_0 + state, from E-RF1) |
|---|---|---|---|
| 2 GB | 1 GiB [U] | **≤ 256 MiB**, on demand | Level 0/1 only (rules, Neural DNA, tiny classifiers / embeddings ≤ ~50 MB). No resident generative model. Level 2/3 via an optional PoP. |
| 4 GB | 1 GiB [U] | **≤ 1 GiB**, on demand | + one compact generative model activated on demand: ~0.6–1.2B at Q4_0 (≈ 320–660 MiB weights + ≤ 60 MiB state at 2K context) |
| 8 GB | 1 GiB [U] | **≤ 2.5 GiB** | + a 2–4B model on demand (≈ 1.1–2.2 GiB at Q4_0), or a 1B model resident |
| 16 GB | 1 GiB [U] | **≤ 6 GiB** | + longer contexts / prefix caches / two models resident. 8B fits but decodes at ~2 tok/s **[T]** — a latency limit, not a RAM limit |

Recurrent/hybrid models change the *state* column, not the weights column (E-RF1): at 8K context
Qwen3-1.7B needs ~896 MiB of f16 KV; Gemma-3-1B (1 KV head + 512-token sliding window) needs
~43 MiB; RWKV-7 1.5B a flat ~12 MiB. **Attention design (GQA/MQA width + sliding windows) moves
memory more than "transformer vs recurrent" does.**

## 6. Unknowns that block quantitative targets (measure before setting any target)

| ID | Unknown | How to measure | Owner |
|---|---|---|---|
| E-HW1 | Effective DRAM bandwidth on *our* CM5 SKUs (1/2/4 threads) | `cm5_bench.sh` §2 (Linux bench unit) | research |
| E-HW2 | eMMC (and NVMe) sequential/random read on our boards | `cm5_bench.sh` §3; heqk eMMC driver throughput separately | research / HomePods |
| E-HW3 | heqk's real memory footprint per subsystem, per SKU | needs ADR 0061 budgets + telemetry | HomePods |
| E-HW4 | Data-plane latency/throughput sensitivity to a DRAM-bandwidth co-runner | Linux proxy in `cm5_bench.sh` §6; real number only on heqk SMP | HomePods + research |
| E-HW5 | MPAM / PMU counters available for bandwidth regulation | read `ID_AA64PFR0_EL1`, PMU event list on metal | HomePods |
| E-HW6 | Thermal headroom of the HookProbe enclosure with sustained decode | `cm5_bench.sh` §7 soak | research |
| E-HW7 | Wall power at idle / decode / prefill | external meter + PMIC ADC (`vcgencmd pmic_read_adc`) | research |

## 7. N100 / x86 (future, ADR 0047 D1)

Single-channel DDR5-4800 = 38.4 GB/s theoretical **[S]** — roughly 2.2–3.2× CM5's bandwidth, so the
same model decodes ~2–3× faster; AVX2 (no AVX-512) **[S]**; AVX-VNNI, RDT (CAT/MBA) **[U]**. The
architecture in this package is backend-neutral: the router, budgets and validation are identical;
only the execution backend (bitnet.cpp TL2 vs TL1, KleidiAI vs AVX2 kernels) and the measured
`bytes_per_token → tok/s` calibration differ.

## References

1. Raspberry Pi CM5 product brief — https://datasheets.raspberrypi.com/cm5/cm5-product-brief.pdf
2. Raspberry Pi CM5 datasheet — https://datasheets.raspberrypi.com/cm5/cm5-datasheet.pdf
3. BCM2712 processors documentation — https://www.raspberrypi.com/documentation/computers/processors.html
4. Frequency management / thermal — https://www.raspberrypi.com/documentation/computers/raspberry-pi.html
5. Arm Learning Path, LLM decode roofline on Pi 5 — https://learn.arm.com/learning-paths/cross-platform/llm-decode-roofline/
6. llama.cpp Vulkan on V3D — https://github.com/ggml-org/llama.cpp/issues/9801 , /issues/26213 , /pull/26214
7. Hailo Model Zoo GenAI, MODELS.rst (v5.5.0) — https://github.com/hailo-ai/hailo_model_zoo_genai/blob/main/docs/MODELS.rst
8. Raspberry Pi, "When and why you might need the AI HAT+ 2" — https://www.raspberrypi.com/news/when-and-why-you-might-need-the-raspberry-pi-ai-hat-plus-2/
9. CNX Software, AI HAT+ 2 review (2026-01-20) — https://www.cnx-software.com/2026/01/20/raspberry-pi-ai-hat-2-review-a-40-tops-ai-accelerator-tested-with-computer-vision-llm-and-vlm-workloads/
10. Tootoonchian et al., ResQ, NSDI 2018 — https://www.usenix.org/conference/nsdi18/presentation/tootoonchian
11. Xin et al., Sereno, OSDI 2026 — https://www.usenix.org/conference/osdi26/presentation/xin
12. Yun et al., MemGuard, RTAS 2013 — https://experts.illinois.edu/en/publications/memguard-memory-bandwidth-reservation-system-for-efficient-perfor/
13. Repository: ADR 0060 (SMP, core roles), ADR 0061 (memory budgets), ADR 0064 (hardware programme), `os/kernel/GAP_REGISTER.md` (CORE-7), `os/kernel/arch-aarch64/src/mmu_cm5.rs`.
