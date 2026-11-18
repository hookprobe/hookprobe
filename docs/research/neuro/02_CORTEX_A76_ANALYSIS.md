# 02 — The Cortex-A76 as an inference engine (Gate 2)

> Native Inference Research Programme, 2026-11-18. Evidence classes:
> - **primary-source** — Arm documents, Raspberry Pi docs, a published CM5 `/proc/cpuinfo`;
> - **compiled** — real `-mcpu=cortex-a76` assembly from `tools/neuro-research/kernels/`;
> - **theoretical** — cycle estimates from the pipe tables;
> - **dev-host measured** — Apple M5 Pro, *not* an A76.
>
> **No instruction was executed on a CM5.** Verifying the feature registers on heqk itself is HomePods
> request R0 (`12`).

## 1. What the CPU has, and what heqk lets us use

| Feature | Present on BCM2712 A76? | Source | Usable on heqk today? |
|---|---|---|---|
| AArch64 Armv8.2-A, 4 cores @ 2.4 GHz | yes | Raspberry Pi processors doc | 1 core (`00` §3.2) |
| AdvSIMD (NEON), FP, FP16 arithmetic (`asimdhp`, `fphp`) | yes | TRM 100798 r4p1 §13.67 (PFR0 AdvSIMD = FP = 1); CM5 cpuinfo (pigpio #621, 2024-12-02) | **no** — softfloat toolchain, no CPACR policy |
| **SDOT/UDOT** (`asimddp`) | **yes** | TRM §13.62: ISAR0.DP = 1; cpuinfo `asimddp` | no (needs NEON) |
| I8MM (SMMLA), BF16, FHM (FMLAL), SVE | **no** | TRM §13.62–13.67: RES0 fields; cpuinfo lacks them | — |
| AES, PMULL, SHA1, SHA2, CRC32 | yes (on the one unit dumped) | cpuinfo; MB23 | crypto instructions are also SIMD-register instructions |
| LSE atomics, RCpc, DC CVAP | yes | cpuinfo; TRM ISAR1 | yes (integer) |
| Caches | L1I 64 KB, L1D 64 KB (4-way, 64 B lines), **L2 512 KB per core, L3 2 MB shared** | TRM; Raspberry Pi doc | yes (MMU on, write-back, `00` §3.3) |
| DRAM | 32-bit LPDDR4X, "up to 17 GB/s"; **11.8 GB/s measured** on a Pi 5 | Raspberry Pi doc; Arm Learning Path (`NEURO_CM5_RESOURCE_BUDGET`) | — |
| PMU | architectural; access unknown | — | no (`00` §3.5) |
| MPAM | unknown for BCM2712 (A76 predates it) | — | — |

**Kernel design rule for CM5:**
- **use:** SDOT, TBL (1–2 registers), and FMLA only where unavoidable;
- **never use:** SMMLA, BFDOT or FMLAL; they are absent.

## 2. Pipe facts that decide kernel design (Arm Cortex-A76 Software Optimization Guide, PJDOC-466751330-7215 v11.0)

- **Pipes:** two vector pipes, V0 and V1; two load pipes; dispatch of 4 macro-ops and up to 8 µops
  per cycle.
- **Pipe restrictions:**
  - integer multiply and FP convert run **only on V0**;
  - ASIMD shifts run **only on V1**.

| Instruction | Latency | Throughput / cycle | Pipe | Consequence |
|---|---|---|---|---|
| **SDOT/UDOT** | 2 | **2** | V0/V1 | 32 int8 MACs per cycle → **76.8 GMAC/s per core** (derived) |
| SMLAL / MLA Q-form | 4–5 | 1 or ½ | V0 only | ~4× worse than SDOT for int8 |
| FMLA vector | 4 (2 chained) | 2 | V | 19.2 GFMA/s fp32 per core |
| **TBL, 1–2 table registers** | 2 | **2** | V | LUT kernels issue at SDOT rate |
| TBL, 3–4 registers | 4 | ½–⅔ | V | keep tables ≤ 32 bytes |
| **SCVTF / FCVTZS Q-form** | 4 | **½** | **V0 only** | an int→float convert per block costs 2 V0 cycles: **block scales are expensive** |
| FCVTL / FCVTN (f16↔f32) | 4 | ½ | V0 | avoid f16 scale conversion in the inner loop |
| ADDV 16B | 6 | ½ | V1 | horizontal reductions belong outside the loop |
| LD1 / LDR Q | 5 (+1 to forward to V) | 2 | L | 32 B per cycle from L1 |

## 3. From instructions to cycles (theoretical, single core, 2.4 GHz)

Inputs:
- instruction mixes from the compiled loops in `01` §4;
- pipe costs from §2.

Method: the loop's cycle count is the largest of three bounds:
1. dispatch (Mops / 4);
2. vector-pipe occupancy (sum of V-µop costs / 2, with V0-only and V1-only µops checked separately);
3. load-pipe occupancy (loads / 2).

This ignores cache misses and latency chains. The loops are unrolled by the out-of-order core across
iterations, so the bounds are **upper bounds on speed**.

| Kernel | Weights per loop | V-pipe cycles | Load cycles | Dispatch cycles | **Cycles / loop** | **Weights / cycle** | Gweights/s per core | Bytes/weight (ggml-style f16 scales) | **DRAM demand per core** |
|---|---|---|---|---|---|---|---|---|---|
| Q8_0 × Q8_0 | 32 | 7/2 = 3.5 (scvtf 2 on V0) | 3 | 3.5 | 3.5 | 9.1 | 21.9 | 1.06 | **23 GB/s → bus-bound on 1 core** |
| Q4_0 × Q8_0 | 32 | 10/2 = 5 | 2.5 | 4.5 | 5 | 6.4 | 15.4 | 0.56 | 8.6 GB/s → ~73% of the bus on 1 core |
| Ternary unpack + SDOT | 32 | 17/2 = 8.5 | 2.5 | 5.75 | 8.5 | 3.8 | 9.0 | 0.31 | 2.8 GB/s → compute-bound |
| Ternary LUT, unpacked indices | 64 | 12/2 = 6 | 2 | 5.75 | 6 | 10.7 | 25.6 | 0.50 | 12.8 GB/s → bus-bound |
| **Ternary LUT, packed 2-bit** | 64 | 18/2 = 9 | 2 | 7.25 | 9 | 7.1 | **17.1** | **0.25** | **4.3 GB/s → compute-bound** |

What the table says:
1. **On one A76 core, 8-bit weights are memory-bound, 4-bit weights are near balance, and ternary
   is compute-bound.**
2. **Packed ternary-LUT is ~11% faster than Q4_0 per core and uses half the DRAM bandwidth per
   weight.** On a device whose DRAM bus is shared with the packet path, *bandwidth per token* matters
   as much as speed (`08` C10). Ternary's real advantage on CM5 is that it **leaves the bus to the
   data plane**, not that it decodes faster.
3. **The per-block float scale is the hidden tax.** In Q8_0 and Q4_0 the `scvtf` plus `fmla` per
   32 weights takes 2–3 of the 3.5–5 V-cycles. Options:
   - per-row scales: accumulate int32 across the whole row, convert once;
   - larger blocks;
   - ggml's interleaved `q4_0_4x4` repack, which amortises the convert over 4 rows.

   The interleaved repack is exactly what llama.cpp selects on A76 (`ggml_repack_get_optimal_repack_type`
   → `q4_0_4x4_q8_0`, `ggml/src/ggml-cpu/repack.cpp`). A native engine must do at least as well.
4. **The compiler wasted 9 of 23 instructions on the ternary unpack.** Lane inserts (`mov v.d[1]`)
   and a `ushl` came from the intrinsic shape. A hand-written or layout-changed version could
   halve that. This is the clearest case for hand assembly (§5).

**Projected decode, weights only, 2.4 GHz, theoretical:**

| Model, format | Cores | Bound | Decode time per token | tok/s | DRAM use |
|---|---|---|---|---|---|
| Qwen3-0.6B, Q4_0 (Q8 head) | 1 | compute | ≈ 39 ms | **≈ 25** | ~8.6 GB/s, ≈ 73% of the bus |
| BitNet 2B4T, packed-LUT ternary (Q8 head) | 1 | — | ≈ 115 ms | **≈ 9** | ~4.5 GB/s |
| BitNet 2B4T, packed-LUT ternary (Q8 head) | 2 | — | — | **≈ 17** | ~9 GB/s |

These ceilings ignore attention, norms and cache effects. They are to be compared with measurements
(`11` E-N1), not quoted as performance.

## 4. Dev-host sanity check (Apple M5 Pro, single thread — NOT an A76)

`tools/neuro-research/kernels/bench`, a 2,048 × 32,768 GEMV per format, every format on the same
ternary matrix, correctness checked (0 mismatches). Output in
[`data/kernels-bench-devhost.txt`](data/kernels-bench-devhost.txt).

| Kernel | ms per GEMV | Relative to Q4 |
|---|---|---|
| Q8 | 1.25 | 0.96 |
| Q4 | 1.30 | 1.00 |
| Ternary unpack | 1.58 | 1.22 (slower) |
| Ternary LUT unpacked | 0.75 | 0.58 |
| **Ternary LUT packed** | **1.08** | **0.83** |

The ordering matches the A76 model in §3:
- the LUT is the fastest ternary kernel;
- unpack-to-int8 is the slowest;
- packed LUT is a little faster than Q4.

Absolute numbers do not transfer. The M5 has far more bandwidth and wider issue.

## 5. Three implementation strategies (Gate 2 A/B/C)

| Strategy | What it means here | Performance (evidence) | Safety / auditability | Verdict |
|---|---|---|---|---|
| **A. Portable Rust** | `core` iterators on `i8`/`i32` slices; rely on LLVM auto-vectorisation | LLVM can emit SDOT from plain loops only in narrow patterns; **untested here** (no Rust toolchain on the dev host, `00`); expect 2–10× below B | best | **reference implementation and test oracle**, not the fast path |
| **B. Rust intrinsics** (`core::arch::aarch64`: `vdotq_s32`, `vqtbl1q_u8`, …) | same LLVM intrinsics as the C in `kernels/`, so the **assembly in `01` §4 is what B produces** | = the compiled results above | good: `unsafe` blocks are local; layout is explicit | **default fast path** |
| **C. Hand-written assembly** (`global_asm!` / `.S`) | for the 2–3 hottest kernels only | can remove the compiler's waste: unpack lane inserts (§3 point 4); multi-row register blocking | harder to review; needs a differential test against A and B | **only where B is measurably short**, starting with ternary unpack/LUT |

**Per-model kernel generation:**
- T-MAC (TVM-generated) and bitnet.cpp (`utils/codegen_tl1.py`, tile sizes per model) both generate
  LUT kernels **per model shape**.
- For HNX (`06`) this suggests the offline compiler choose among a **small fixed set of signed
  kernels** with tile parameters as *data*. It should not emit code. Generated code would put
  executable content in packages, which `06` forbids.

## 6. Questions only hardware can answer (→ `11`, `12`)

- Single-core and multi-core GEMV rates for each kernel. This tests the §3 model.
- Effective single-core DRAM bandwidth on CM5 (the Pi 5 figure is 13.8 GB/s single-thread read).
- L2/L3 behaviour while the data plane runs: does weight streaming evict flow tables? (E-INT1)
- Thermal throttling under sustained SDOT load in the enclosure (E-TH1).
- Feature registers as heqk sees them (R0).
