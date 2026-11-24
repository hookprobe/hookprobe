# os/conductor — HookProbe Conductor, C0 spike

> **Status: C0, restricted research spike (approved 2026-11-24).** Not wired into `os/kernel`. Not for
> publication before the ADR 0067 D12 decision (file first / publish defensively / keep unpublished).
> Wire formats are **prototypes** built from primitives heqk already ships; they are not a production
> protocol. Design: *heqk Conductor* design review v2/v3 (private artifact).

heqk keeps the authority (identity, keys, policy, evidence, capability issuance, verification, ledger);
remote workers only compute. C0 is the device-side core: the protocol, the HP-EXEC capability, data classes,
typed tools, the verifier, placement and a sans-IO harness state machine, tested against a mock kernel and a
scripted, misbehaving mock worker.

## C0 boundaries (as approved)

No change to `os/kernel` · no x86 dependency · no cloud deployment · no change to packet enforcement · no new
production crypto protocol · no public disclosure · no remote application execution · mock worker only.

## No Linux, no Python (enforced)

Everything here is Rust. `conductor-mock/tests/no_linux_no_python.rs` fails if a non-Rust source appears
under `os/conductor`, if a device crate stops being `no_std` or names std, alloc, libc or a POSIX API, or
if the device binary gains a dependency. Checked on the built device binary (`el0-harness`): 10 Rust
crates compiled for the target, 0 imported symbols, no dynamic section, one syscall (heqk's
`SYS_EXIT_USER`), 0 FP/SIMD instructions.

| Crate | Runs on | Linux at run time? |
|---|---|---|
| `conductor-core`, `el0-harness`, `runtime-proof` (lib) | heqk (EL0) | **no** |
| `conductor-mock` (tests, fuzz, `measure`, `stack_bound`) | the build host only (ADR 0047 D3) | not shipped |

There is no Linux-hosted component. A reference worker for a Linux GPU machine was built and then removed
on 2026-11-24 (operator decision: everything stays heqk-native). The worker-side acceptance rules remain
as `no_std` protocol code (`conductor-core/src/worker.rs`) for a future heqk-native worker, and are
exercised by the mock in the tests. The two kernel requests that make neural computation and applications
native are in [`KERNEL_REQUESTS.md`](KERNEL_REQUESTS.md).

## neuro-engine, step 1 (N0): an integer specialist engine

A model is a data package (prototype layout `HNX0`, after Neuro doc 06): memory plan, execution plan over a
closed kernel table, weights, SHA-256 root. Admission checks everything once, including a worst-case bound
that no accumulator can overflow for any input; after that a run cannot fail, allocates nothing and does a
known amount of work. The plan is interruptible step by step.

| Gate | Result |
|---|---|
| The frozen S1 specialist shipped as a 212-byte package gives bit-identical scores and alerts to `neuro_l1`'s compiled-in code (200,003 inputs) | pass |
| 300 random 1–3 layer int8 models × 20 inputs match an independently written reference; stepping equals running | pass |
| Malformed packages refused for the right reason (17 cases, incl. overflow bound, in-place misuse, trailing byte) | pass |
| 3,000,000 mutated packages (most re-hashed so they pass integrity): no panic; 384,725 admitted and run | pass |
| Runtime Proof 001 runs S1 through the engine: identical findings to the compiled-in run | pass |

`el0-engine` (aarch64 softfloat, runs on today's heqk, no FP/SIMD grant): `.text` 8,796 B, `.data` 0,
`.bss` 131,080 B (64 KiB package buffer + 64 KiB arena, sized for the limits, not for S1), stack bound
10,880 B, 0 imports, 0 FP/SIMD instructions. Not wired into `os/kernel`.

Not in step 1: package signature verification (the kernel's job, R5), a recurrent cell, SIMD kernels
(step 2, needs KR-1 to run on the device), a language model.

## neuro-kernels, step 2: 4-bit GEMV, scalar and NEON

Signed 4-bit weights × int8 activations, in a 4-row interleaved layout fixed at pack time (Neuro docs 02
and 03), int32 accumulation per row and one integer rescale per row: no float anywhere. The engine gains
the kernel `GEMV_Q4_I8`.

| Gate | Result |
|---|---|
| Host: 200 random Q4 layers (with padding rows and columns) × 10 inputs match a reference on the unpacked matrix; unpadded shapes and negative multipliers refused | pass |
| **Bare metal, emulated Cortex-A76** (`neon-proof`, no OS): NEON + DotProd kernel identical to the scalar reference on 20,000 groups (42,251,520 MACs), edge values included | pass |
| Bare metal, through the engine: a packaged 64×256 Q4 layer, 2,000 runs, scalar output == NEON output | pass |
| The same binary on a CPU without DotProd (emulated Cortex-A57) reads the ID register and refuses | pass |
| Softfloat device build (`el0-engine`): NEON module not compiled, 0 FP/SIMD instructions, `.text` 10,084 B | pass |

The NEON path exists only in hard-float builds (`aarch64-unknown-none`) and is reached only through a token
whose construction is the caller's promise that the CPU has the features and FP/SIMD is enabled: on heqk,
the KR-1 grant. Until KR-1 lands it cannot run on a device.

Not measured: speed. An emulator's timing means nothing; tokens per second need a real Cortex-A76 (CM5 after
KR-1, or a Pi 5 bench). Not built: attention, normalisation, tokenizer, sampling, the HNX loader (step 3).

```bash
cd os/conductor/neon-proof && cargo build --release && qemu-system-aarch64 -M virt -cpu cortex-a76 -m 64M -nographic -nic none -semihosting -kernel target/aarch64-unknown-none/release/neon-proof
```

## neuro-hnx, step 3: the HNX model container and streaming loader

Neuro doc 06 implemented: a 256-byte header (target, required CPU features, engine ABI, model id and SVN,
the resource manifest admission reads, SPDX licence of the weights, source and evaluation-report hashes,
an RFC 6962 Merkle root over the segments), the segment table, a signature over `SHA-256(tag ‖ header)`,
then the segments, whose concatenation is a `neuro-engine` package. The loader follows doc 06 §4 in order:
header policy → signature (the platform's; heqk: hybrid via boot-abi) → manifest to admission → segments
streamed into the reserved region, each hashed against its leaf, any order, each once → engine admission
plus a check that the manifest told the truth. `no_std`, no alloc, no `unsafe`; written for the kernel to
lift (Neuro requests R4, R5).

| Gate | Result |
|---|---|
| RFC 6962 tree: 1, 2, 3 and 5-leaf vectors; allocation-free fold | pass |
| A 512×2048 Q4 layer (528,492 B, 130 segments) streamed in order and scrambled, admitted, run: output identical to the payload admitted directly | pass |
| Refused at the right step: wrong target, missing FP/SIMD grant, engine ABI, non-allowed licence (CC-BY-NC), no evaluation report, SVN rollback; changed leaf (root); another signer; trailing byte; wrong region size, duplicate and out-of-range segments; tampered segment (load failed, region wiped, later feeds refused); a manifest that under-declares arena or work; a verified payload that is not an engine package | pass |
| **Every one of the 2,048 single-bit flips of the header**, and all 2,832 of a small prefix, refused | pass |
| 1,000,000 fuzzed prefixes and segment streams: no panic, and every prefix that differs in any byte refused | pass |
| Builds for `aarch64-unknown-none-softfloat` | pass |

Host timing (x86, not CM5): load, verify and admit 528 KB in about 1.1 ms. On CM5 the eMMC read rate
(roughly 3–12 MB/s with today's driver, Neuro doc 07) will dominate, not hashing.

Not built: the hybrid signature check (heqk's own `boot-abi` verifier is the platform's job), the kernel
side that streams segments from storage into a reserved, read-only region (R3, R4), the `hnx-compile`
converter from real model files, and the A/B update channel for models (an open question in doc 06).

## neuro-lm: the language-model pieces

Integer-only, `no_std`, no allocation, no `unsafe`, no float (enforced by test). Kernels in
`neuro-kernels::lm`, composed in `neuro-lm` into a decoder-only transformer: RMSNorm, grouped-query
attention with RoPE over an int8 KV cache, integer softmax, table-driven SiLU, SwiGLU feed-forward, 4-bit
weights with per-row integer rescale, greedy decoding; plus a byte-level BPE tokenizer. Fixed-point scheme:
residual Q8 (`i32`), activations Q5 (`i8`), gains Q12, rotations and probabilities Q15. KV cache and all
scratch come from the caller. Float tables (exp, SiLU, RoPE) are generated on the build host by
`neuro-build` and embedded as integers.

| Gate | Result |
|---|---|
| Kernels vs f64: RMSNorm and RoPE ≤ 1 LSB; softmax worst probability error 1.7×10⁻⁴; attention ≤ 2 LSB; SiLU table exact | pass |
| Tokenizer: identical to an independently written reference on 503 texts (random bytes and corpus slices); every text round-trips; table validation refuses later-token merges, unsorted or wrong-rank indexes | pass |
| **Whole decoder vs an independent f64 model with the same dequantised weights** (8 random 2-layer models, 256 steps): logit cosine mean 0.998, min 0.975; greedy token equal in 214 of 222 steps where f64 has a clear winner (96%). Thresholds (min cosine 0.97, agreement 95%) were set before the first run | pass |
| KV cache: incremental decoding bit-identical to recomputation from scratch, with a garbage-filled fresh cache, at prefix lengths 1–48 | pass |
| Bounds: full context, unknown token, wrong cache or scratch size → errors; shape errors caught by `check()` before any run | pass |
| **Bare metal, emulated Cortex-A76:** the same decoder (40 KB of 4-bit weights) run with the scalar path and with NEON + DotProd for 48 positions: every logit equal | pass |

What these numbers are: agreement with a float model of the SAME random weights, which isolates the error
the integer arithmetic adds. They say nothing about language quality: no trained model has been run. That
needs `hnx-compile` (converting a real small model, e.g. an Apache-licensed Qwen3.5-0.8B or RWKV-7) and then
the same comparison against the reference implementation, then the blind evaluation (Neuro doc 13).

Not built: a recurrent cell (RWKV-7; doc 13 leaves the choice to measurement), sampling beyond greedy,
grammar-constrained decoding, the engine-plan integration (the decoder is composed in Rust, not yet run from
an HNX plan with persistent state slots), and any speed number (needs a real A76 after KR-1).

## The 8-bit path and Qwen3 (Neuro's explainer architecture)

Neuro's explainer (ftFg) is a Qwen3-1.7B fine-tune that passed its gates as **GGUF `Q8_0`**, so the engine
now runs that format directly. The 4-bit Q5 path above stays for small specialists; it would clip the
activation outliers of real pretrained models.

- **`neuro-kernels::q8`**: `Q8_0` rows in the GGUF block layout, byte for byte (34-byte blocks: binary16
  scale + 32 int8). The converter will copy these bytes, not re-quantise them, so the device runs the exact
  weights Neuro validated. Activations are quantised per block of 32 (`amax/127`), as llama.cpp's CPU
  path does. The binary16 scales are decoded with integer operations. Accumulation provably cannot
  overflow (see "Packed `Q8_0` layout" for the grid that both layouts share). Scalar reference plus NEON +
  DotProd (SDOT).
- **`neuro-kernels::hp`**: 64-bit fixed point with 16 fraction bits for everything else. RMSNorm with
  binary32 gains and eps, NEOX ("rotate half") RoPE from a Q30 table, `exp` (2^(k/256) table built at
  compile time by integer square roots, linear interpolation), fused SwiGLU, and attention over an
  `i16` KV cache with a per-vector shift (15 significant bits per vector; binary16 has 11). Still no
  floating point on the device.
- **`neuro-lm::qwen3`**: the Qwen3 decoder. Per-head QK-norm, GQA, NEOX RoPE (θ from the model), SwiGLU,
  no biases, tied or separate output head, greedy generation with stop tokens. `check()` refuses wrong
  shapes and any infinite or NaN scale or gain. All memory is caller-supplied.

| Gate | Result |
|---|---|
| Every one of the 65,536 binary16 values and 200,000 random binary32 values decode exactly | pass |
| `Q8_0` GEMV: 3,000 rows (32–2,048 columns, activations from 10⁻³ to 6×10⁵ with outlier channels) equal f64 on the same quantised operands; activation scale within 3×10⁻⁵ of `amax/127` | pass |
| Fixed point vs f64: exp worst relative error 2.7×10⁻⁶; RMSNorm ≤ 1.5 LSB + 10⁻⁶; RoPE at θ = 10⁶ ≤ 1 LSB; SwiGLU ≤ 2 LSB + 10⁻⁵; attention worst error 5.5×10⁻⁶ of the largest \|V\| | pass |
| **Whole Qwen3-shaped model vs an f64 runtime on the SAME `Q8_0` weights** (3 random 3-layer models with outlier channels, 144 steps; the f64 side keeps every activation and the KV cache in f64, like a float runtime): logit 1 − cosine mean 1.9×10⁻⁸, worst 2.3×10⁻⁷; greedy token equal in 144 of 144 steps | pass |
| Refused: NaN gain, infinite weight scale, short matrix, wrong RoPE table, infinite eps; bad token, full context, wrong cache size; generation deterministic and stops on a stop token | pass |
| **Bare metal, emulated Cortex-A76:** `Q8_0` kernel scalar == NEON on 6,000 rows across every binary16 exponent; a whole 2-layer Qwen3-shaped decoder (113 KB of `Q8_0` weights), 32 positions, every logit equal | pass |
| Device crates still contain no floating point, no `std`, no Linux and no Python (`no_linux_no_python.rs`) | pass |

What this does and does not show. It shows that the integer engine computes what a floating-point runtime
computes from the same `Q8_0` weights, to about 10⁻⁷ in logits, on random Qwen3-shaped models. It does not
show quality on Neuro's model. That is the fidelity check in `NEURO_ALIGNMENT.md`: Neuro's exported GGUF,
its dev set only, against llama.cpp on the same file. One known difference: llama.cpp on a Mac runs Metal,
which does not quantise activations (its CPU path does). The tolerance for that check must cover this, and
the test above suggests the effect is small.

Not built yet: the converter (`hnx-compile`, waiting on Neuro's GGUF and answers), and any measured speed
(needs a real A76 after KR-1). The 4-row kernel is below.

### 4-row NEON `Q8_0` kernel

`q8::rows4` runs four rows at once over the GGUF layout unchanged. Each activation block is loaded once
for the four rows, and the four dot products are reduced with three pairwise adds instead of four
horizontal sums. `q8::matvec` uses it for every group of four rows, with the 1-row kernel for the
remainder. The shared scale-combine got a fast path: when the block shift is 0–16, the shifted term
provably fits an i64 and only the add is 128-bit. Proven-bounded operations in that loop use wrapping
arithmetic, so they skip overflow checks (the release profile keeps checks everywhere else). Results are
bit-identical to before: same exact sum, same real-model numbers.

No ARM hardware is available, so speed is given as **executed instructions** on the emulated Cortex-A76.
`qemu -icount shift=0` makes the generic timer count instructions; this is deterministic, but it is not
cycles, and memory bandwidth is not modelled. Measured on a 512×2048 matrix with realistic scales:

| Kernel | Instructions per multiply-add |
|---|---|
| scalar reference | 9.26 |
| NEON 1-row, strict alignment (bare-metal default) | 6.19 |
| NEON 1-row, unaligned loads allowed | 1.41 |
| **NEON 4-row, unaligned loads allowed** | **1.17** |

The big step is alignment, not the fourth row. GGUF blocks are 34 bytes, and under strict alignment the
compiler splits each 16-byte load into 16 byte loads. `neon-proof` now sets up an identity MMU (device
memory for the UART, normal cacheable memory for RAM, `SCTLR_EL1.A` clear), as heqk does for EL0 servers,
and builds without `strict-align`. KR-1 now asks heqk to clear A explicitly (`KERNEL_REQUESTS.md`). What
remains per row-block is about 6 instructions of dot product and about 20 of scale arithmetic; the packed
layout below removes most of the latter.

Rough estimate, not a measurement: Qwen3-1.7B is 1.7 × 10⁹ multiply-adds per token, about 2 × 10⁹
instructions at 1.17. On one A76 core at 2.4 GHz that is about 0.3–0.4 s per token, in the same range as
reading the 1.8 GB of weights once per token from LPDDR4X. The real number needs the device.

| Gate | Result |
|---|---|
| Bare metal, emulated A76: 4-row kernel scalar == NEON on 1,676 groups; `matvec` on 3,000 matrices of 1–7 rows (4-row groups plus remainder), extreme and realistic scales, equal to the 1-row reference; a short matrix refused | pass |
| Whole Qwen3 decoder through the new `matvec`, scalar == NEON, every logit | pass |
| Real Qwen3-1.7B smoke test unchanged (same logits to the printed digit; "Paris") | pass |

### Packed `Q8_0` layout (lossless)

The scale arithmetic was the remaining cost, so weights can now also run from a packed layout
(`q8::pack`):
- **Layout:** rows in groups of four. Per group and per 32 columns there is one 144-byte record: the four
  rows' int8 weights (128 bytes), then the four binary16 scales pre-decoded to an integer mantissa and
  exponent (`i16` each).
- **Aligned:** records are 16-byte aligned, so every load is aligned and the kernel also works on
  strict-alignment targets.
- **Cheap scale arithmetic:** for four rows it is about ten vector instructions. These are an integer
  multiply, two widening multiplies, and a rounding shift (`SRSHL`) into two i64 accumulator vectors.

**Lossless and checkable.** Mantissa and exponent represent each binary16 scale exactly (−0 included).
`q8::unpack_row` rebuilds the GGUF bytes of any row exactly. So a device can keep only the packed form and
still verify it against the GGUF file's hash. Packing is the load-time step: `Mat::pack_into`, `no_std`,
no allocation. Size: +5.9 %.

**One arithmetic for both layouts.** The packed kernel needed a 64-bit accumulator. So both layouts now
compute each block term exactly and place it, with one rounding, on a per-call grid
`2^-(L − ce_max − wexp)`. Here `L = 16 − ⌈log2(blocks)⌉`, and `wexp` is the matrix's largest weight
exponent: computed once, stored with the matrix, verified by `check()`. Every term is below `2^(46+L)`
and every row sum below `2^62`, so nothing can overflow for any input. The GGUF and packed layouts give
the same numbers bit for bit.

Accuracy: on 3,000 GEMV rows (activations from 10⁻³ to 6×10⁵ with outlier channels), the worst error
against f64 is 0.500 output LSB. That is only the final rounding to 2^-16. Sizing the grid from the
matrix's real weight exponent matters: a first version sized it from the largest possible binary16 scale
and lost up to 2,883 LSB on large outputs. That was caught by the test and fixed before commit.

Executed instructions per multiply-add, same 512×2048 benchmark (`qemu -icount`, emulated Cortex-A76;
instructions, not cycles):

| Kernel | Instructions per multiply-add |
|---|---|
| scalar reference | 9.47 |
| NEON 1-row, GGUF layout | 1.62 |
| NEON 4-row, GGUF layout | 1.02 |
| **NEON 4-row, packed layout** | **0.37** |

That is about 12 instructions per four rows × 32 columns, scales included. With 0.37 instructions per
multiply-add, Qwen3-1.7B needs about 0.6 × 10⁹ instructions per token. On an A76 that is no longer the
limit: reading about 1.9 GB of weights per token is. Rough estimate, not a measurement: about
0.2–0.3 s/token, set by LPDDR4X bandwidth.

| Gate | Result |
|---|---|
| All 63,488 finite binary16 scales (both signs, subnormals, ±0) pack and unpack byte-exact | pass |
| Packed `matvec` == GGUF `matvec` bit for bit: 2,890 rows over 400 random matrices of 1–13 rows (padding), embedding lookups equal | pass |
| Refused: infinite scale (pack), non-canonical packed scales (5 kinds), short packed matrix, a `wexp` off by ±1 | pass |
| Whole Qwen3-shaped model: packed logits == GGUF logits at every step (host) | pass |
| **Bare metal, emulated A76**: packed (scalar and NEON) == GGUF on 3,000 matrices; whole Qwen3 decoder, GGUF scalar == GGUF NEON == packed NEON, every logit, 32 positions | pass |
| **Real Qwen3-1.7B**: 1.83 GB packed into 1.94 GB in 2.5 s; every row of every matrix unpacks to the exact GGUF bytes; packed logits == GGUF logits at all 25 steps ("Paris") | pass |

## The Qwen tokenizer

`neuro-lm::tok` is the Qwen2/Qwen3 tokenizer on the device: byte-level BPE with 32-bit ids, added tokens
(`<|im_start|>`, `<tool_call>`, `<think>`, …) matched leftmost-longest on the raw text, NFC normalisation,
and the Qwen2 pre-tokenizer pattern implemented by hand (no regex engine). `no_std`, no allocation, no
floating point, no Unicode library: the vocabulary, merges and Unicode tables (letter, number, whitespace,
NFC quick check, combining class, 2,081 decompositions, 961 compositions; Hangul is algorithmic) come in
one blob built on the build host by `tok-build` and validated at load. Every merge is checked to equal the
concatenation of its parts, so a blob cannot make a merge produce a different text.

Source for the test: Qwen3-1.7B `tokenizer.json` at revision 70d244cc (SHA-256 `aeb13307…dae4`,
Apache-2.0), kept outside the repo. The converter will read the same tables from Neuro's GGUF instead.
The reference is HF `tokenizers` (Rust, pure-Rust regex backend); nothing here uses Python.

| Gate | Result |
|---|---|
| Pre-tokenizer: 40,029 texts (random Unicode across every branch of the pattern, plus edge cases) split exactly as the model's regex | pass |
| **Whole encoder vs HF `tokenizers` on the real Qwen3 vocabulary**: 25,011 texts (chat-template prompts, tool calls, JSON evidence, code, 12 scripts, emoji, odd whitespace, glued real tokens, random text): **every id equal**, 0 refused; decoding gives back the NFC form of each text | pass |
| NFC on the device equals `unicode-normalization` on 200,000 combining-heavy texts (123,354 changed by NFC) and on all 2,081 decomposable characters | pass |
| Long pieces (16 KB of spaces, one letter, punctuation, CJK): equal to HF, 3–9 ms each on the build host | pass |
| Blob: 4.06 MB for 151,669 ids, validated in 5 ms. Refused: wrong magic, truncated, trailing byte, wrong byte token, a merge whose result is not its parts, unsorted merges; 200,000 single-bit corruptions never panic | pass |
| Builds for `aarch64-unknown-none-softfloat`; no floating point in the device crate | pass |

What validation does not do: it does not prove the blob is the right one. 73,155 of the 200,000 corrupted
blobs are still internally consistent (a changed Unicode class, an unused token's bytes). Integrity is the
HNX signature and Merkle root, as for the weights.

Known difference to plan for: llama.cpp (the runtime Neuro measured with) has its own implementation of this
pre-tokenizer and its own Unicode tables. The fidelity check should compare token ids with llama.cpp on the
dev set, not only with HF.

## GGUF reader, and the first real model on the integer engine

`neuro-gguf` reads GGUF v3 files, the format Neuro's models are exported in, directly on the device:
zero-copy over the admitted model region, `no_std`, no allocation, no `unsafe`, no floating point.
`Gguf::open` validates the whole header once:
- every length, count, type and dimension is checked, with checked arithmetic;
- tensors must be aligned, inside the data section, in increasing order and non-overlapping;
- keys and tensor names must be unique.

`neuro_gguf::qwen3` binds a Qwen3 GGUF to the integer decoder. Every matrix must be `Q8_0` and every norm
binary32, with exactly the shapes the hyperparameters imply. Anything else is refused, never converted.
The attention scale is computed with integers and is bit-identical to llama.cpp's `1.0f/sqrtf(head_dim)`.
The tokenizer is read from the same file's metadata (`tok_build::from_gguf`). So weights and vocabulary
both come from the one file Neuro hands over, and the weight bytes the device multiplies are that file's
bytes. Not taken from the GGUF: the RoPE table, which is built on the build host from
`qwen3.rope.freq_base` and shipped in the signed package.

| Gate | Result |
|---|---|
| Synthetic GGUF with every value type (u8 … f64, strings, string and integer arrays) and tensors read back exactly | pass |
| Refused for the right reason: magic, versions 1/2/4, truncation anywhere, absurd counts, unknown value or tensor type, nested array, duplicate key or tensor name, partial block, 0 or 5 dimensions, non-UTF-8 key, misaligned / overlapping / out-of-range tensor, bad alignment value | pass |
| 500,000 mutated files: no panic | pass |
| Integer `1/sqrt(n)` equals IEEE `1.0f/sqrtf(n)` for every n up to 65,536 | pass |
| Binder refuses: wrong architecture, missing layer, a well-formed `Q4_0` matrix where `Q8_0` is required, context beyond training, wrong RoPE table | pass |
| The tokenizer read from the GGUF has the same bytes for all 151,669 ids as `tokenizer.json`, and the same encoding on 20,000 texts | pass |
| Builds for `aarch64-unknown-none-softfloat`; in the no-float / no-Linux / no-Python gate | pass |

**Converter smoke test on a real model** (`tok-build` binary `qwen3-smoke`; NOT a model track, and Neuro
owns models and evaluation). Input: public Qwen3-1.7B Q8_0 GGUF, revision 90862c4b, SHA-256
`061b54da…cb1a`, Apache-2.0, kept outside the repo. The real 1.8 GB file is opened (header validated in
64 ms) and bound. A chat prompt goes through the device tokenizer and is run greedily on the integer
engine. Every step is compared with an independent f64 runtime that dequantises the same bytes.

| Prompt | Integer engine answer | Greedy token = f64 | Logit 1 − cosine (mean / worst) |
|---|---|---|---|
| "What is the capital of France? Answer in one word." | `Paris` + `<\|im_end\|>` | 24 / 25 (the miss is inside the prompt: "\n" vs "\n\n" after `<\|im_end\|>`, f64 gap 0.24) | 5.4×10⁻⁴ / 1.4×10⁻³ |
| A port-scan description (40 attempts on 22/23/80/443 in 2 s) | a fluent one-sentence answer | 81 / 81 | 3.1×10⁻⁴ / 1.4×10⁻³ |

Where the 10⁻³ comes from (`REF_DIAG=1`): llama.cpp's own CPU path is no closer to pure float. Quantising
activations exactly as it does moves the f64 runtime's logits up to 2.6×10⁻³ from float, more than the
integer engine's 1.4×10⁻³. Any two 8-bit-activation implementations differ at this level, because
per-block rounding amplifies 10⁻⁶ differences upstream. Consequence for the fidelity check with Neuro: it
must be stated in token agreement and margins on the dev set, not bit-exactness.

The answer to the security prompt is the generic public model's; this says nothing about ftFg's quality.
Speed on the build host: 1.2 s/token, scalar, one thread. That is not a device number: no SIMD, no 4-row
kernel, and x86.

## Crates

| Crate | What | Target |
|---|---|---|
| [`conductor-core/`](conductor-core/) | protocol, HP-EXEC v1, classes, tools, strict JSON, verifier, placement, ledger, harness, worker gate; signer behind `--features signer` | `no_std`, no alloc, `forbid(unsafe_code)`; clippy denies indexing, unwrap/expect/panic, unchecked arithmetic, truncating casts |
| [`conductor-mock/`](conductor-mock/) | mock kernel + mock worker, the C0 gate tests, fuzzing, host timing | host only |
| [`el0-harness/`](el0-harness/) | the harness as an EL0 excursion server (no signer, no key) | `aarch64-unknown-none-softfloat`, pinned heqk nightly |

The crypto crates are the kernel's own, pinned to the kernel's versions: `sha2 =0.10.9`,
`ed25519-compact =2.3.1`.

## C0 gate — results (main @ 1ce96d52 + this branch)

| Gate item | Evidence | Result |
|---|---|---|
| Capability refusal | `gate.rs`: remote off by default; required Fingerprint without owner opt-in; Raw/Secret on any tier; P3 public-only; P4 public-only until C3b; P2 refused (fleet_mesh unbuilt); unpaired worker; signer refuses Raw, unapproved classes, wrong egress profile, P2, unknown ops, KV persistence; harness refuses a blob the signer did not sign | pass |
| Replay rejection | worker gate: same capability twice → Replay (ADR 0069 counter pattern); wrong session, wrong worker, wrong tier, altered request, not-yet-valid, expired, tampered body, revoked epoch; device: frames replayed from a previous call → CapabilityMismatch | pass |
| Budget exhaustion | step budget ends a tool loop; output-unit budget caps the capability and rejects an overrun; deadline aborts even while frames arrive; silent worker times out | pass |
| Malformed responses | bad result signature, bad output hash, wrong capability id, skipped sequence, usage lie, garbage, oversize, error frame, double FINAL; 15 strict-schema cases (unknown/duplicate/reordered keys, trailing bytes, leading zeros, tab, `\u` escape, bidi override, raw control char, negative/float numbers, unknown tool, non-object) | pass |
| Fault containment | `fuzz.rs`: 2,000,000 random/mutated inputs through every decoder, no panic (panic=abort, overflow checks on); 30,000 end-to-end runs where worker frames are altered in flight: **an altered frame never produced a Verified outcome**, and every lease was ended exactly once | pass |
| Injection / data flow | ungranted tool, out-of-scope evidence → refused, counted, model told; 3 refusals → REJECTED; tool result of a class the tier may not see never reaches the worker; optional Address card withheld from P1 | pass |
| Verifier statuses | VALID (L0 decides / descriptive), CONFLICT (shows L0 verdict, never the model's), INCOMPLETE, UNVERIFIED (model verdict not shown), REJECTED (fabricated citation) | pass |
| Kill switch | cancel mid-call ends the lease; epoch bump revokes older capabilities at the worker | pass |

Lease invariant: every `StartLease` is matched by exactly one `EndLease` in every gate and fuzz run.

## Built ahead of C1/C2 (still no kernel change, mock only)

| Piece | What it stops | Evidence | Result |
|---|---|---|---|
| **Hash-chained ledger** (`chain.rs`): HMAC chain + sealed anchor + power-loss recovery | edited, removed, reordered, truncated or rewritten history; torn writes | `c1_prep.rs`: every byte edit caught; removed / swapped entries; tail cut caught only via the anchor; history rewritten with the real key caught by the anchor; roll-forward of one unanchored entry; torn tail discarded; tampering before the anchor reported, never repaired; a real job's ledger verifies | pass |
| **Owner pairing** (`pairing.rs`): commit-then-reveal, six-digit comparison, owner-signed record with revision and expiry | a LAN attacker substituting its worker key; a compromised harness pairing a worker; replaying an old pairing to undo a revocation | MITM key/late-nonce fail the commitment; codes spread uniformly; forged and wrong-purpose owner signatures refused; stale revision refused; P2 refused; lapsed pairing stops signing | pass |
| **Signed epoch announcement** (kill switch, part 2) | a captured but unused capability surviving the kill switch | announcement revokes an outstanding epoch-1 capability at the worker; forged / other-device announcements refused; epoch never lowered | pass |
| **SLO admission quotes** (Select-N style; heqk is the upper-level scheduler) | sending data to a worker that cannot meet the time targets; forged or replayed quotes | data-free fixed-size quote request (no evidence or intent bytes); slow worker (NVMe-streaming profile) skipped for the next tier without ever receiving a capability or prompt; nobody meets the SLO → refused with only quote requests sent; wrong nonce or wrong key → REJECTED; a broken promise is recorded (SloMiss code 2) | pass |

Fuzzing now also covers events, quote requests and quotes (1,000,000 decoder inputs) and runs half of the
20,000 end-to-end mutation runs with SLO admission: an altered frame or quote never produced a Verified
outcome.

## Measurements

EL0 binary (`el0-harness`, release, opt-level "s", ed25519-compact at "z"):

| | Bytes |
|---|---|
| `.text` | 74,772 |
| `.rodata` | 2,936 |
| `.data` | 0 |
| `.bss` (whole job state, in place) | 47,792 |
| Worst-case stack from `_start` (static bound: no indirect calls, no register-based sp adjustment) | 13,280 |
| FP/SIMD instructions | 0 (runs on today's softfloat heqk; no R2 needed) |

Findings fixed during measurement:
- **47 KB of `.data`**: niche-encoded `Option`s made the empty harness non-zero, so the compiler stored the
  state in the image (which the kernel embeds; its headroom is about 33 KB). The state is now all-zero by
  construction and lives in `.bss`.
- **Ed25519 verify was 137 KB of 171 KB `.text`** (`double_scalarmult_vartime` unrolls to ~95 KB at "s").
  Building that one crate at "z" cut `.text` to 72 KB; verification gets slower (measure on CM5 in C1).
- **Clock bug**: the harness clock only advanced on ticks, so a deadline could be overrun while frames
  arrived. Every event now carries the time.

Host timing (x86-64, NOT CM5): a two-call job end to end ≈ 0.93 ms including the mock signer and worker;
device-side crypto per call ≈ 0.10 ms (two Ed25519 verifies) + 8 µs (SHA-256 of an 8 KiB request).

## Run

```bash
cd os/conductor && cargo test --release -p conductor-mock
```

```bash
cd os/conductor && FUZZ_ITERS=2000000 cargo test --release -p conductor-mock --test fuzz
```

```bash
cd os/conductor && cargo clippy -p conductor-core --features signer
```

```bash
cd os/conductor && cargo run --release -p conductor-mock --bin measure
```

```bash
cd os/conductor/el0-harness && cargo build --release
```

## Not in C0 (next)

- **C1** (HomePods): lift `signer.rs` and `chain.rs` into EL1 with purpose-separated keys (delegation,
  cache salt, ledger) derived from the sealed root; persist the counter and the ledger anchor in the sealed
  store (ADR 0069 pattern); broadcast epoch announcements; wire `el0-harness` behind a feature; assign its
  address range; time Ed25519 verify at opt-level "z" on CM5.
- **Remote workers**: only as heqk-native nodes (heqk on the worker machine), after ADR 0068 and the
  kernel requests. No Linux-hosted worker.
- Third-party applications (containers / microVMs on a companion host) are outside C0 and need their own
  ADR.

## Next engine item (alignment with `origin/main` @ `4d7ad4f`)

Doc 42 failed ftKg, so **ftFg stays the explainer**: one shot, no tools. Neuro validated it with **evidence-closed
decoding**: a per-request JSON schema whose `evidence` and `entities` enums are exactly the fact ids and aliases
in the context, compiled by llama-server into a grammar. Temperature is 0 and reasoning is off. To claim fidelity
with that configuration, the engine needs the same constraint: a fixed-shape schema automaton that masks logits
before the argmax, integer only, with no regex engine. Not built yet. Details and the updated questions are in
`NEURO_ALIGNMENT.md`.
