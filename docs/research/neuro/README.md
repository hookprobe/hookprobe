# HookProbe Neuro: native inference research programme

> 2026-11-18. **Research only. It authorises nothing.** `os/kernel/**` (HomePods) was read and
> never changed. Nothing here was measured on a CM5.
>
> It follows on from the Neuro Engine research gate (`../neuro-engine/`, Phase 0 and 0b). The
> documents live under `docs/research/` per the repo's layout, not in a top-level `research/`.

| # | Document | Gate | One-line result |
|---|---|---|---|
| 00 | [System capability audit](00_SYSTEM_CAPABILITY_AUDIT.md) | 0 | heqk can host a ≤ 4 MiB, scalar-integer EL0 engine today. No FP/SIMD, no large regions, no load path, single core. |
| 01 | [Model to machine code](01_MODEL_TO_MACHINE_CODE.md) | 1 | Decode is GEMV plus the output head plus KV. Small ops are < 1% of the work. Real A76 assembly for 5 kernels. |
| 02 | [Cortex-A76 analysis](02_CORTEX_A76_ANALYSIS.md) | 2 | SDOT and TBL run at 2 per cycle; there is no i8mm, bf16 or SVE. Q8 is bus-bound, Q4 is at balance, packed-LUT ternary is compute-bound at half Q4's bandwidth. |
| 03 | [Model representations](03_MODEL_REPRESENTATION_RESEARCH.md) | 3 | Use 4-bit post-training now. Use ternary only for models trained ternary. Packed ternary is consumed directly via TBL. |
| 04 | [Architecture comparison](04_ARCHITECTURE_COMPARISON.md) | 4 | Recurrence saves context memory, not weight bandwidth. A per-device state must be bytes, not MiB. |
| 05 | [Native runtime design](05_NATIVE_RUNTIME_DESIGN.md) | 5 | A no_std Rust plan interpreter over a closed kernel table. No existing runtime fits heqk. |
| 06 | [HNX format proposal](06_HNX_FORMAT_PROPOSAL.md) | 6 | A signed, per-target, offline-compiled package. Its resource manifest drives kernel admission. It contains no code. |
| 07 | [Memory and storage model](07_MEMORY_AND_STORAGE_MODEL.md) | 7 | Per-SKU budgets. The output head is 25–40% of per-token bytes. eMMC on heqk means minutes to load. |
| 08 | [heqk co-design opportunities](08_HEQK_CODESIGN_OPPORTUNITIES.md) | 8 | 15 capabilities, each with exists / missing / why / without / gain / minimal interface. |
| 09 | [Security intelligence](09_HOOKPROBE_SECURITY_INTELLIGENCE.md) | 9 | Specialists and temporal state decide. The language model only explains. Weights, state, intel and policy are kept separate. |
| 10 | [Innovation and prior art](10_INNOVATION_AND_PRIOR_ART.md) | 10 | 6 architectures. Grammar-sparse logits not found anywhere. References R87–R176. |
| 11 | [Benchmark plan](11_BENCHMARK_PLAN.md) | 11 | E-N0..E-N10 with kill criteria; Pareto, not a single score. |
| 12 | [HomePods kernel requirements](12_HOMEPODS_KERNEL_REQUIREMENTS.md) | 8 | R0 readouts. R1 is nothing. R2 FP/SIMD. R3–R6 model region, load, verify, admit. R7–R8 CPU and pressure. |
| 13 | [Final architecture decision](13_FINAL_ARCHITECTURE_DECISION.md) | 12 | Temporal engine first (no kernel change). HNX plus admission as the spine. Language tier leased later, format by measurement. |

**Data:** [`data/`](data/) contains:
- memory-model outputs;
- the dev-host kernel bench.

**Tools:** under `tools/neuro-research/`:
- `memory_model.py`;
- `kernels/` (C with NEON intrinsics, A76 assembly, bench);
- `compare_freeex.py`.
