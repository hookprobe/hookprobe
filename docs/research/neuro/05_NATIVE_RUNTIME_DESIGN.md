# 05 — A native heqk inference runtime (Gate 5, design for review)

> Native Inference Research Programme, 2026-11-18. **Design only. No runtime code was written**
> (the research gate forbids it before approval). Reference runtimes were studied from primary
> sources; details are in §1.

## 1. What the reference runtimes teach (and what does not transfer)

| Runtime | Lesson to take | What does not fit heqk |
|---|---|---|
| **ExecuTorch** (BSD-3, v1.6.0) | an export-time **execution plan** ("a simple loop over an array of instructions") and **memory plan** (`AllocationDetails` offsets into numbered arenas, `non_const_buffer_sizes`); a 7-function PAL (`et_pal_*`); core < 50 kB, no threads, no malloc | C++17 runtime; the fast Arm path (XNNPACK + KleidiAI) pulls in `pthreadpool`/`cpuinfo`; no signatures |
| **TFLM** (Apache-2.0) | one caller-supplied static **tensor arena**; optional offline plan (`"OfflineMemoryAllocation"` metadata) | **no Cortex-A kernels** (reference C only on A76); CMSIS-NN is Cortex-M |
| **ggml / llama.cpp** (MIT) | the **A76-specific layout** (`q4_0_4x4_q8_0` repack, `vdotq_laneq_s32`); per-architecture graphs in code | needs libc, `posix_memalign`, OpenMP/pthreads; no freestanding build: **port the kernels' ideas, not the library** |
| **bitnet.cpp** (MIT) | TL1 LUT (`vqtbl1q_s8`, int16 accumulation) and I2_S SDOT for ternary; per-model kernel tiles generated offline | depends on llama.cpp; Arm results only on Apple M2 |
| **T-MAC** (MIT) | bit-plane LUT with mirror consolidation; Pi 5: BitNet-3B 1.37 → 8.03 tok/s single thread versus 2024 llama.cpp | TVM-generated; TVM's microTVM/AOT path was removed in 2024–2026 |
| **IREE** (Apache-2.0) | `local-sync` HAL, embedded-ELF executables, a min-peak-memory partitioning flag; `IREE_PLATFORM_GENERIC` | VM bytecode plus compiled executables in an unsigned `.vmfb`; executables in the package conflict with `06` |
| **RWKV reference** | the recurrent state is a fixed-size tensor per layer; inference is a straight-line loop | — |
| Rust crates | **burn** is no_std (with alloc), NEON via `macerator`; **microflow** is no_std with AOT from `.tflite` via a proc macro | burn defaults to std/rayon and has no int8-SDOT or LUT LLM kernels; **tract and candle are not no_std** |

**Conclusion:** no existing runtime can be dropped into heqk. The closest *design* is ExecuTorch's
split between an export-time plan and a tiny loop executor. The closest *kernels* are ggml's A76
repack and bitnet.cpp/T-MAC's LUTs. HookProbe should write a **small Rust no_std engine** in that
image. It would carry its own kernels and no external runtime dependency, and could reuse `safetensors`
(no_std) only on the build host.

## 2. Architecture: compiler, runtime, heqk integration

```
 BUILD HOST                                     DEVICE (heqk)
┌─────────────────────────────┐   signed HNX   ┌─────────────────────────────────────────────┐
│ hnx-compile (std Rust)      │ ─────────────▶ │ heqk kernel (HomePods)                      │
│  · load safetensors/GGUF    │                │  · verify package (R5) · admit (R6)          │
│  · quantise/convert, trim   │                │  · map weights RO, arena RW (R3)             │
│  · choose kernel ids+tiles  │                │  · lease CPU (R7), pressure page (R8)        │
│  · repack for target        │                └───────────────┬─────────────────────────────┘
│  · liveness → memory plan   │                                │ excursions / scheduled TCB
│  · eval on reference engine │                ┌───────────────▼─────────────────────────────┐
│  · sign (Ed25519+SLH-DSA)   │                │ el0-neuro (EL0 server, no_std Rust)          │
└─────────────────────────────┘                │  · plan executor (loop over steps)           │
                                               │  · kernel table: SDOT GEMV, LUT GEMV, int8   │
                                               │    specialists, norms, RoPE, WKV7 update,    │
                                               │    grammar-sparse head, argmax               │
                                               │  · sessions: KV or recurrent state slots     │
                                               │  · evidence-closed decoding (token automata) │
                                               │  · pacing: bytes/token budget, pressure page │
                                               └─────────────────────────────────────────────┘
```

### 2.1 The runtime's contract

| Property | How |
|---|---|
| No Linux dependency | `#![no_std]`, no `alloc` in the inference path; host interface = 5 functions (§3) |
| No dynamic allocation during inference | every buffer is an offset from the HNX memory plan into the admitted arena |
| Deterministic resource limits | arena, state slots and max tokens are fixed at admission; a request that would exceed them is refused, never partially served |
| AArch64-specific kernels | a closed table of kernel ids (`kernel_id → fn`); strategy B (intrinsics) by default, C (assembly) where measured to pay (`02` §5) |
| Multiple model backends | architecture ids `transformer-gqa`, `rwkv7`, `gdn-hybrid`, `specialist-*`; each is a plan over the same kernel table, never a separate engine |
| Integrity | done by the kernel before mapping (R5); the engine never sees unverified bytes |
| Interruptible | the plan is a list of steps; the engine yields at step or layer boundaries and keeps its cursor; fits bounded excursions (R7 b) |
| Resource-aware scheduling | before each layer: check the pressure page (R8) and the bytes-per-token budget; pause if exceeded |
| Controlled heqk capabilities | the server holds only: its region mappings, a request/response ring, the pressure page, a counter. **No network, no storage, no policy capability.** |

### 2.2 Static graph interpreter, bytecode VM, or ahead-of-time code?

| Option | Performance | Memory | Security | Complexity | Extensibility | Verdict |
|---|---|---|---|---|---|---|
| **Static plan interpreter** (list of `(kernel_id, slots, params)`) | dispatch cost per step ≈ 100s of ns against ms per GEMV: negligible | plan is KBs | **packages contain no code**; bounds checked once at admission | low | new architectures = new plan shapes + maybe new kernel ids (an engine update) | **choose** |
| Bytecode VM (IREE VMVX-like, Wasm) | interpretation overhead on element-wise ops; kernels still native | small | VM is attack surface; still needs native kernels | high | high | reject: complexity without benefit at this size |
| Ahead-of-time compiled model code (TinyEngine, X-CUBE-AI, microflow) | best, no dispatch, specialised tiles | smallest | **code inside the package**: every model update is a code update, needing the same review as kernel code | medium | each model = new code | reject for models shipped as data; **acceptable for specialists compiled *into* the engine** (they ship with the engine's signature anyway) |

### 2.3 The smallest runtime that does something useful

| Level | Contents | Est. code | Needs from heqk |
|---|---|---|---|
| **N0 — temporal/specialist engine** | fixed-point DNA scoring; int8 dense + GRU-cell kernels (scalar); plan executor; no tokenizer | ~2–4 kLoC | **nothing new** (R1) |
| N1 — + SIMD | the same with SDOT kernels | + ~1 kLoC | R2 |
| N2 — language tier | + tokenizer (BPE, trimmed), GQA attention or WKV7, LUT/SDOT GEMV, RoPE, norms, grammar automata, sparse head, sessions | ~8–15 kLoC (estimate) | R2–R8 |

Sizes are estimates for planning, not measurements.

## 3. Host interface (what heqk provides the engine; ExecuTorch-PAL-like)

| Function | Provided by | Exists today? |
|---|---|---|
| `region(kind) → &[u8] / &mut [u8]` for weights (RO), arena (RW), state (RW) | kernel mapping (R3) | no (window is 4 MiB) |
| `rx_request() / tx_response()` | the existing kernel↔EL0 ring (`hal/src/el0ring.rs`) | **yes** |
| `now_ticks()` | CNTVCT access for EL0 | QEMU yes; CM5 unknown (R0) |
| `pressure() → epoch, occupancy` | pressure page (R8) | no |
| `yield_point()` | ending the current excursion with the cursor saved (`SYS_EXIT_USER`) | **yes** (the excursion model) |

## 4. Verification of the engine itself

- **Reference engine (strategy A, std, build host)** runs every HNX package before signing. Its
  blind-set result is recorded in the package's provenance (`06` §2).
- **Differential tests:** the device engine (B/C kernels) must match the reference within a stated
  tolerance on fixed inputs. This is the same discipline heqk already uses for the BPF JIT
  (`[P8-diff]`).
- **QEMU gate:** a `qemu-virt` HNX specialist admitted and run in `validate.sh` (a request to
  HomePods, `12`).
