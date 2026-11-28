# os/conductor — HookProbe Conductor, C0 spike

> **Status: C0, restricted research spike (approved 2026-11-24).** Not wired into `os/kernel`. Published by
> operator decision under ADR 0067 D12 (2026-11-24; see the D12 record in ADR 0067).
> Wire formats are **prototypes** built from primitives heqk already ships; they are not a production
> protocol. Design: *heqk Conductor* design review v2/v3 (private artifact).

heqk keeps the authority (identity, keys, policy, evidence, capability issuance, verification, ledger);
remote workers only compute. C0 is the device-side core: the protocol, the HP-EXEC capability, data classes,
typed tools, the verifier, placement and a sans-IO harness state machine, tested against a mock kernel and a
scripted, misbehaving mock worker.

## The direction

One sentence, and everything here follows it: **a model runs on any heqk device from one signed file, through one
load path, on one integer engine, with no Linux, no Python and no other runtime underneath.** The same harness,
verifier and ledger govern the job whether the model runs on the device or on a worker the device directs.

Why it matters to the product:
- **The device explains its own alerts with nothing else installed.** A home or a branch gets a local SOC from
  first boot, air-gapped if it wants, with no account, no cloud and no GPU box. That is the "standalone by
  default" promise, and a runtime that needs Linux and Python breaks it.
- **One thing to sign, admit and audit.** A model is data with a manifest: the device knows what it will cost
  before it loads a byte, refuses what it cannot afford, and can prove afterwards which model answered.
  A general-purpose runtime on the device is a second operating system to patch and to trust.
- **Speed where it can be had.** A token is limited by memory bandwidth, so the gains are bytes not read
  (a packed layout, a pruned output head, verified drafts) and calls not made (rules decide, the model
  explains). None of that needs another runtime; all of it is measured below.
- **The same authority when the model is elsewhere.** Compute beyond the device comes from other heqk nodes
  only (the owner's, a fleet's, a heqk node in a cloud), each directed under a capability and a network lease.
  There is no external model and no API tier (operator decision 2026-11-26, ADR 0071 amendment), so this engine
  is the product's only engine.

What is decided and not reopened here: no tensor work in the kernel; FP/SIMD for one isolated server only
(ADR 0072); greedy decoding under Neuro's grammar at temperature 0; the kernel's own crypto crates; no
Linux-hosted worker. `EXTERNAL_REVIEW.md` records an outside review against these.

## C0 boundaries (as approved)

No change to `os/kernel` · no x86 dependency · no cloud deployment · no change to packet enforcement · no new
production crypto protocol · no remote application execution · mock worker only. (The original "no public
disclosure" boundary ended with the ADR 0067 D12 decision to publish, 2026-11-24.) Architecture record:
[ADR 0071](../../docs/adr/0071-heqk-conductor-directed-execution.md).

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
converter for specialist models, and the A/B update channel for models (an open question in doc 06).

### One load path: a language model from the same container

The container now carries a language model too, so there is one way a model reaches the engine.

- **Payload kind** (header byte 208; earlier files have 0 there and are engine packages): `ENGINE`, or `GGUF_LM`,
  a GGUF file the integer engine binds. A language-model payload may be up to 8 GiB.
- **No staging copy:** `Loader::accept_in_place` verifies a segment the storage driver read straight into its
  place in the reserved region. A load needs no memory beyond the region and the loader.
- **Admission cannot be lied to:** `neuro_gguf::hnx::admit` opens the verified file and recomputes the manifest
  from it (context, KV state, scratch arena, tensor bytes). A signed header that under-declares any of them is
  refused. The build side uses the same function.
- **Build host tool:** `tok-build --bin hnx-lm`: `pack` wraps a GGUF file (as a bundle, below) and signs it; `run` does what a heqk
  server would: verify, reserve, read and verify in place, admit, bind, answer.

| Gate | Result |
|---|---|
| A signed language model (tiny Qwen3) loads segment by segment in place, is admitted, and the engine produces the same tokens as from the file | pass |
| A manifest under-declaring the arena, the KV state, the bytes per token or the sessions; a context beyond training; another architecture | refused |
| Not every segment; one changed byte (the load fails and the region is wiped); the wrong payload kind in either direction; another signer; an unknown kind byte | refused |
| In-place verification: any order, each once, mixed with copied segments; same refusals as the copying path | pass |

**Neuro's ftFg (Qwen3-1.7B, Q8_0, 1.83 GB) through this path, on the build host** (Apple M5 Pro, NEON; a test
key; not a device number): packed into 875 segments of 2 MiB in 7 s. Opened and signature-checked in under
1 ms; 1,749 MiB read and verified in place in 3.2 s (hashing at 583 MiB/s, the plain `sha2` crate); admitted at
context 4,096 (KV state 472 MB, arena 25 MB); asked the capital of France, it answers `Paris` in its JSON
habit. 0.06 s per token in the GGUF layout and 0.03 s in the packed layout, prompt included. One changed
weight byte: segment 429 refused and the region wiped. A changed header byte or another key: refused at open.

**The bundle (payload kind `LM_BUNDLE`, `neuro_gguf::bundle`): nothing derived on the device.** A GGUF file is
not enough on a device with no float and no build tools: the tokenizer needs its Unicode and merge tables and
the decoder needs the RoPE table, which takes trigonometry. The bundle carries both beside the model under the
same signature: four sections in a fixed order (model file, tokenizer tables, RoPE pairs, packed matrices; the
last may be empty), each starting on a 64-byte boundary. Admission checks that the tables fit the model (RoPE rows for the context and head
size; tokenizer tables that parse and have the model's vocabulary). The tokenizer is read where it lies; the
RoPE table is copied into the arena admission already counts. `hnx-lm pack` builds a bundle by default.

| Gate | Result |
|---|---|
| A signed bundle loads in place, is admitted, and the engine runs from its tables: same tokens as from the plain file with the same table | pass |
| RoPE rows for another context; a tokenizer with another vocabulary; bytes that are not a tokenizer; an under-declared manifest | refused |
| Layout: wrong magic, version, section count, kind or order; a non-zero reserved field; a non-canonical offset; a wrong length; bytes after the last section; non-zero padding; a RoPE table that is not whole pairs | refused |
| A bundle labelled as a bare GGUF payload, and the reverse | refused |

ftFg as a bundle on the build host: the tokenizer tables add 4.07 MB and the RoPE table 2.10 MB to 1.83 GB;
878 segments; read and verified in place in 3.2 s; the run uses no build-host helper and answers `Paris` at
0.05 s per token (GGUF layout) and 0.03 s (packed).

**P0 as a session (`neuro_gguf::p0`): one forward pass per call.** ADR 0060's amendment (W3, stage S2) puts
the engine on a compute-role worker core that never allocates, gets its memory from core 0 before it starts and
is driven over rings. `p0::sizes` says from the model's hyperparameters exactly what memory a session needs;
`Session::open` binds an admitted bundle into that memory; `Session::advance` does one pass over the weights
(a prompt batch fed, or one token generated) and returns, so a job can be paced, preempted or cancelled between
passes. Greedy decoding; the tokens are those of `Model::generate`.

| Gate | Result |
|---|---|
| A session's answer equals whole-answer generation, token for token, at prompt batches 1, 2, 4 and 16; a prompt of n tokens takes ceil(n / batch) passes, then one pass per token | pass |
| A second job on the same session and memory; a cancelled job stops and keeps what it produced | pass |
| Any one of the nine memory slices one element short, a batch of 0 or 17, an empty prompt, a prompt that fills the context, a bare GGUF payload (no tables) | refused |
| The manifest's KV state equals what the session takes; its arena covers the session's scratch and RoPE table | pass |

ftFg as a session on the build host (NEON, batch 16; not a device number): 24 prompt tokens in 2 passes, then
one pass per token at a median of 66.9 ms, p99 69.1 ms, max 69.8 ms over 47 passes. What the model needs
besides its 1.83 GB of weights, assigned up front:

| Context | KV state | Scratch and RoPE | 
|---|---|---|
| 4,096 | 449.8 MiB | 23.4 MiB |
| 2,048 | 224.9 MiB | 22.4 MiB |
| 1,024 | 112.4 MiB | 21.9 MiB |

The context is the lever on memory: Neuro's cards are budgeted at 512 tokens, so a triage job fits a context of
1,024 with room for the system prompt and the answer only if that prompt is short; the right cap is to be set
with Neuro, not assumed.

**Under the answer contract, pass by pass.** `neuro_lm::decode::ClosedRun` makes at most one pass per call, with
the pruned head and verified drafts; `generate_closed` is now that run looped to the end, so every earlier test
of it stands, and `tok-build/tests/decode.rs` also drives it pass by pass (same tokens and counters in five
option sets). `p0::Session::start_closed` runs such a job in the session's memory (tested against
`generate_closed` on a tiny model).

**One triage job as the device runs it (`hnx-lm triage`), ftFg on the build host.** One of Neuro's synthetic
windows (10 fact cards, 1,202 bytes of context) through guard A, Neuro's contract prompt, the session under the
contract, and back through the contract parser and guard E:

| | Plain | Pruned head + drafts |
|---|---|---|
| Answer | 236 tokens; verdict `suspicious`, 8 facts and 8 aliases cited; **valid under the contract**; guard E finds no carried text | the same count |
| Prompt | 1,115 tokens in 70 passes, 88 s | the same |
| Answer passes over the weights | 235 | 168 (20 with a pruned head; 67 of 260 drafts accepted) |
| One pass | median 140 ms, p99 149 ms, max 156 ms | median 140 ms, p99 1,084 ms (a draft pass computes eight full heads) |
| Whole job | 121 s | 145 s |

Apple M5 Pro with NEON, a test key, not a device number. What it shows that a device number will not change:
- **The prompt is most of the job.** 1,115 tokens for 1,202 bytes of context: Neuro's system prompt and the
  closed schema with its id lists. About 264 of them come before the first per-request id and are the same in
  every job, so their KV state could be computed once and kept. The rest is per request. Any change to the
  prompt is Neuro's, because the prompt is what was measured.
- **A pass costs more as the context fills** (67 ms at 24 tokens of context, 140 ms at about 1,200): attention
  reads the KV cache.
- **Drafts cost more than they save where compute is the limit**, as measured before on x86, and they make one
  pass eight times longer. For a job that must be paced between passes, the plain mode has the tight bound.
  Whether drafts pay on a memory-bound A76 is still to be measured there.

**Agreed with Neuro on this evidence (2026-11-28):**
- **The admitted context is 2,048.** Neuro's largest measured prompts are about 700 tokens with answers of up to
  700; this denser window is 1,115. A job whose prompt leaves less room than the answer bound is refused
  (`start_closed`), never cut short. At 2,048 the session takes 247 MiB up front besides the weights.
- **The prompt's text does not change** (the schema's place in it was trained and gated). What is the same in
  every job is not fed twice: a session keeps the tokens its KV cache was computed from, and a job that starts
  with the same tokens begins after them (`Session::reused`). Position i of the cache depends only on tokens
  0 to i, so the answer is exactly that of a fresh session (tested on five consecutive jobs).

Three of Neuro's windows, one after another in one session at context 2,048 (pruned head, no drafts): each answer
valid under the contract, no carried text. The first job feeds 1,115 prompt tokens in 87 s; the next two find
293 tokens already in the cache and feed 657 and 892 in 54 s and 80 s. Whole jobs: 120 s, 83 s, 113 s; an answer
pass stays between 129 and 143 ms at the median and under 160 ms at worst.

**The packed layout is the stored form.** A bundle's fourth section holds the model's matrices in the packed
layout (`neuro_kernels::q8`), in a fixed order, each on a 64-byte boundary; the GGUF section then keeps only the
metadata, the tokenizer's source and the norm vectors. The device runs the fast kernels with no packing at load:
packing 1.9 GB there would need both copies in memory. Admission checks that the section is exactly this
model's matrices; the engine's own check validates every record when the model is bound.
`hnx-lm pack --packed` builds it.

| Gate | Result |
|---|---|
| A packed bundle of the tiny model gives the tokens of the unpacked one; the file left has the metadata and norms and none of the eight matrices | pass |
| A packed section 64 bytes short or long; a file with no matrices and no packed section | refused |

ftFg packed (build host, context 2,048): the model file shrinks to 6.4 MB and the packed section is 1.94 GB
(929 segments, read and verified in place in 3.3 s). One pass per token at short context: 32 ms, against 67 ms
in the GGUF layout. The three windows above: 85 s, 60 s and 85 s, against 120 s, 83 s and 113 s; an answer
pass at about 1,200 tokens of context takes 97 to 111 ms at the median (attention over the KV cache is now the
larger part). The answer to the second window is byte for byte the answer of the unpacked layout in a fresh
session.

Still open in this path: the
signature is Ed25519 with a test key; release signing and the hybrid scheme are the platform's. The tables are
covered by the signature and are not re-derived: the device cannot compute a cosine.

### The worker's compute is the engine (`conductor-p0`)

`conductor-worker` checks the capability, makes its replay mark durable and signs the result; what it runs is an
`Executor`. `conductor-p0::P0Executor` is that executor on a heqk node: one admitted model in one P0 session.

- It serves one model digest and `infer` only. Anything else gets an ERROR frame.
- The answer is closed over the facts and aliases of the context the device sent. The executor reads them from
  the prompt (between the user framing's head and its question) with the device's own rule
  (`neuro_contract::context_ids`). A prompt without that block, or with no fact, is refused: the node never
  decodes outside the contract.
- An answer that does not fit the output the capability allows is an error, not a cut answer.
- The session keeps the prompt's identical start between jobs, so a second job feeds only what differs.

`conductor-mock/tests/p0_worker.rs` runs the whole path with no scripted answer: the device harness, a signed
capability, the worker, a signed bundle loaded in place and admitted, the engine session, the signed result, and
the device's verifier. The model there is a one-block test model whose weights are all equal, so the contract
alone shapes its answer. A job that requires no citation verifies as valid; the same answer on a job with a
required fact is held back by the verifier as incomplete; a second job reuses the cached prompt start; another
model digest is refused before anything is decoded.

**The engine as a worker-core job (`conductor_p0::core_job`, ADR 0060 stage S2).** HomePods' worker executive
(`os/kernel/worker`, draft #1644) gives a worker core a closed job vocabulary, `Job { id, op, a, b }` in and
`Done { id, status, value }` out, and leaves the compute engine to be added as a new op. This is that op's body,
written against slices, with no address arithmetic and no `unsafe`: `ENGINE_INFER` takes the prompt at offset
`a`, length `b` of the read window core 0 granted, writes a 16-byte header of counters and then the answer to
the result window, and returns the answer's length. Core 0 does not wait inside the job: it reads a progress
word (answer tokens so far) and may set a cancel word, both looked at after every pass over the weights. A
cancelled job returns nothing of its answer, and the core serves the next job normally. A range outside the
window, bytes that are not a prompt and an answer that does not fit are refused with a status. The test checks
all of that and that the answer equals, byte for byte, the one the capability path gives on other kernels. The
crate is `no_std` with no allocation, no float and no `unsafe` (it is in the no-Linux gate); its bare-metal
build was not run on this host, which has no bare-metal target installed. What remains is kernel side: calling it from the executive's
loop on a core with FP/SIMD enabled, and granting the model region and the windows.

**Exact agreement, with the real engine.** The fleet's verified redundancy (`conductor_core::quorum`, ADR 0071
amendment A3) compares signed output hashes for equality, so it stands on nodes giving the same bytes. The same
file checks that on a test model with seeded weights (tokens score differently, so the answer depends on every
pass): a node on scalar kernels, a node on this host's NEON kernels, and a node that reuses a cached prompt
start from another job give byte-identical answers, and their signed votes reach agreement. A node with other
weights gives another answer and is a conflict with re-verifiable evidence that names it. This is the
host-side form of the proposed `[P-fleet-exact]` gate; across real core counts it needs the worker cores
(ADR 0060 S2).

**The real model through the same path** (`hnx-lm job`, build host, test key; 2026-11-28). ftFg from its signed
packed bundle, two jobs with the same two facts, the device's L0 verdict "suspicious":

| | Job 1 | Job 2 |
|---|---|---|
| Whole job | 26.1 s | 11.0 s |
| Prompt tokens not fed again | 0 | 453 |
| Prefill passes / answer tokens | 29 / 181 | 1 / 181 |
| Verifier | Valid, verdict suspicious, decided by L0 | the same; the same answer text |
| Ledger records; leases started/ended; worker high-water mark | 4; 1/1; 1 | 4; 1/1; 2 |

That run uses the harness's fact form of the request. With `--context FILE` the job carries a window context
as Neuro's cards write it (the window job, #1645), one job per file. Three of Neuro's synthetic windows, same
bundle, same host:

| | Window 1 | Window 2 | Window 3 |
|---|---|---|---|
| Whole job | 84.7 s | 82.2 s | 59.3 s |
| Prompt tokens not fed again | 0 | 306 | 293 |
| Prefill passes / answer tokens | 70 / 236 | 55 / 229 | 42 / 226 |
| Verifier | Valid, decided by L0 | Valid, decided by L0 | Valid, decided by L0 |

This is the path, not an evaluation: three synthetic windows say nothing about ftFg's quality. Host numbers, not
device numbers. One limit showed up: a capability allows at most 120 s of compute per call
(`limits::MAX_COMPUTE_MS`). A job fits on this host; on a CM5-class core it will not, so that limit has to be set
from the first device measurement.

The tests above are host tests. The node's EL0 wiring, block device
and kernel-held key are still kernel work (below).

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
| [`conductor-p0/`](conductor-p0/) | the worker's `Executor` over the native engine session: a heqk node's `infer` | `no_std`, no alloc, no float, `forbid(unsafe_code)` |
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
| **Sealed state** (`durable.rs`): delegation counter and revocation epoch on a block device, ADR 0069 record scheme (two alternating sectors, newest valid wins, write + read-back before use) | a counter reused after power loss (replay); a kill switch undone by a reboot (the epoch was in RAM in C0) | `c1.rs`: drift gate against the kernel's `g19ctr.rs`; 324 crash points (every write, 9 torn lengths): no counter handed out twice, no confirmed epoch lost; signer on a crashing disk: counters strictly increase over 10 boots; epoch survives reboot and the worker refuses the old capability as `Revoked`; unreadable store signs nothing. Kernel side: `KERNEL_REQUESTS.md` KR-3 | pass |
| **SLO admission quotes** (Select-N style; heqk is the upper-level scheduler) | sending data to a worker that cannot meet the time targets; forged or replayed quotes | data-free fixed-size quote request (no evidence or intent bytes); slow worker (NVMe-streaming profile) skipped for the next tier without ever receiving a capability or prompt; nobody meets the SLO → refused with only quote requests sent; wrong nonce or wrong key → REJECTED; a broken promise is recorded (SloMiss code 2) | pass |

Fuzzing now also covers events, quote requests and quotes (1,000,000 decoder inputs) and runs half of the
20,000 end-to-end mutation runs with SLO admission: an altered frame or quote never produced a Verified
outcome.

## C2, host part: the P1 worker on the owner's LAN (no kernel change, mock only)

Two halves, each a sans-IO `no_std` library that builds for `aarch64-unknown-none`. Workers are heqk nodes only.

| Piece | What it stops | Evidence | Result |
|---|---|---|---|
| **Reference worker** (`conductor-worker`): the worker side of HP-EXEC v1. It accepts a call only through the shared `WorkerGate`, makes its replay mark and epoch durable (ADR 0069 record, new `durable::raise`) **before** computing, runs `infer` / `embed` / `classify` through an `Executor` (on a node: the native engine), enforces the output budget itself, and signs results and quotes with a `ResultKey` its kernel holds | a capability executed twice after a power cut; the kill switch forgotten by a rebooted worker; an engine overrunning the budget or its buffer | `c2_worker.rs`: the real worker behind the device harness and verifier gives Verified/Valid; 36 crash points (every write, 9 torn lengths): no capability ever runs twice (a crash can burn one, never repeat it); the epoch survives the worker's reboot and the old capability is refused as `Revoked`; over-budget and lying engines produce an ERROR frame; quotes are signed by the worker key; an unreadable store serves nothing | pass |
| **Compute-segment lease filter** (`lease.rs`): heqk as the segment's only gateway. Passes ARP for the gateway, the control channel, DNS via heqk, and, while a lease is active, only that lease's owner-approved destinations. Every other frame is dropped as evidence, and the first one suspends the worker until the owner resumes it | a compromised, root-owned worker reaching anything it was not leased | `c2_lease.rs`: **31 attack paths** are stopped, each recorded as evidence and suspending the worker. They include direct internet, other LAN hosts, the wrong port or protocol, DNS and DoT bypass, L2 bypass, MAC, IP and ARP spoofing, ICMP tunnels, GRE, IPv6, VLAN and Q-in-Q hops, fragments, IP options, broadcast and mDNS, oversize, truncated and length-lying frames. All 6 honest flows pass. Expiry (2 s linger for TCP tails, no suspension), EndLease, and the kill switch (no linger; an old epoch cannot start a lease) are covered, and inbound traffic passes only as replies from lease destinations. 300,000 mutated frames: every frame that passed is an allowed shape (independent fixed-offset oracle). 14.2 ns per frame on the build host (x86-64, not CM5), worst case | pass |

The metal half of the C2 gate (ADR 0071) needs KR-3 item 5 (the lease filter in the data plane):
- the same red-team frames on the CM5's segment port;
- the 33-row separation matrix unchanged;
- the main-loop impact measured.

## Measurements

EL0 binary (`el0-harness`, release, opt-level "s", ed25519-compact at "z"):

| | Bytes |
|---|---|
| `.text` | 90,736 |
| `.rodata` | 8,408 |
| `.data` | 0 |
| `.bss` (whole job state, in place) | 52,408 |
| Worst-case stack from `_start` (static bound: no indirect calls, no register-based sp adjustment) | 10,912 |
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

Fidelity against llama.cpp on the same GGUF (on the Neuro Mac, where the models are): see `FIDELITY.md`.

```bash
cd os/conductor && cargo run --release -p tok-build --bin fidelity -- --dir DIR --model FILE.gguf --set CASES.jsonl --url http://127.0.0.1:8080 --free-run
```

## Not in C0 (next)

- **C1** (HomePods): lift `signer.rs` and `chain.rs` into EL1 with purpose-separated keys (delegation,
  cache salt, ledger) derived from the sealed root; persist the counter and the ledger anchor in the sealed
  store (the record layer is built and power-loss tested: `durable.rs`, KR-3); broadcast epoch announcements; wire `el0-harness` behind a feature; assign its
  address range; time Ed25519 verify at opt-level "z" on CM5.
- **Remote workers**: only as heqk-native nodes (heqk on the worker machine), after ADR 0068 and the
  kernel requests. No Linux-hosted worker. The worker side is built (`conductor-worker`, C2 host part), and its
  compute is bound to the engine (`conductor-p0`). The
  node still needs its own EL0 wiring, its block device and its key held by its kernel.
- Third-party applications (containers / microVMs on a companion host) are outside C0 and need their own
  ADR.

## Next engine item (alignment with `origin/main` @ `cbbf56f`)

**Update (Neuro's answers, `cbbf56f`):** the explainer is now two models. **ftFg** handles triage: one shot, no
tools. **ftL** handles investigation: one tool call or none per turn (doc 43 PASS). Both are Qwen3-1.7B LoRA
fine-tunes. Guards A, E and G run on the device, and **rule T is dropped** (doc 40 failed). Guard G is built
(below). The engine's tool loop is needed for ftL only.

Doc 42 failed ftKg, so **ftFg stays the explainer**: one shot, no tools. Neuro validated it with **evidence-closed
decoding**: a per-request JSON schema whose `evidence` and `entities` enums are exactly the fact ids and aliases
in the context, compiled by llama-server into a grammar. Temperature is 0 and reasoning is off. To claim fidelity
with that configuration, the engine needs the same constraint: a fixed-shape schema automaton that masks logits
before the argmax, integer only, with no regex engine. Not built yet. Details and the updated questions are in
`NEURO_ALIGNMENT.md`.

## Evidence-closed decoding, from one contract

**One source of truth.** `neuro-contract` (`no_std`, no allocation, no float) is the only place on the device
side that defines the explainer's answer. It mirrors Neuro's `tools/neuro-research/eval/run_eval.py`:
- the enums, bounds and key order;
- the system prompts (en, ro) and the user framing;
- the rule that takes fact ids and aliases from the context;
- the closed-mode schema text, byte for byte as Python's `json.dumps` prints it;
- the Qwen3 ChatML wrapping with reasoning off;
- **one byte automaton** for the answer language. It mirrors what llama.cpp's grammar for that schema
  accepts, including its whitespace rule, its lenient UTF-8 and integers without leading zeros.

The same automaton masks tokens in the engine (`neuro-lm::decode`) and parses replies in Conductor's verifier.
Conductor's own invented answer shape (`{"answer":{"cites":["ev:N"],…}}`) is gone, and the harness now builds
Neuro's prompt from the contract.

**Drift gate.** `neuro-contract/tests/drift.rs` reads `run_eval.py` as text and fails on any difference in
the 3 enums, the 2 system prompts or 17 exact source fragments: the id regexes, the schema bounds, the framing
and the `json_schema` call. Changing `maxLength` 600 → 500 in Neuro's file made it fail, naming the line.

**Exact speed-ups.**
- **One batched forward pass** (`Model::forward`) serves the one-token step, prompt prefill in batches, and
  speculative verification. Matrices are read in 4-row groups, and each group computes every column while it
  is in cache, so weights come from memory once per batch. Each column runs the same integer code as a
  single token.
- **Head pruning.** Outside free text, only the head rows of tokens the grammar allows are computed. On those
  rows the result is identical to the full head.
- **Verified speculation.** Drafts come from text the grammar forces (key names, the rest of an enum or id)
  and from n-gram lookup in the prompt and answer so far. A draft is kept only if it is the masked greedy
  choice, so the output equals sequential decoding.

| Gate | Result |
|---|---|
| Id rule equals a regex reference on 50,000 random contexts; gathering ids line by line equals the joined context on 20,000 | pass |
| Schema text equals Python's `json.dumps`, byte for byte | pass |
| Automaton accepts valid answers (compact, spaced, escapes, multi-byte, 600-character limit exact) and refuses fabricated ids, reordered or duplicate or extra keys, out-of-enum values, confidence 101 or `07`, a 9th list item, raw tabs, bad escapes, whitespace beyond the rule, trailing text | pass |
| Drift gate against `run_eval.py`, and it fails on a deliberate change | pass |
| Batched forward == one-token steps, every logit, batches 3/8/16, GGUF and packed (host); packed NEON, 4 per pass, 32 positions (bare-metal A76) | pass |
| Pruned head == full head on its rows | pass |
| 12 runs on random models (both layouts): plain, pruned, speculative and both give **identical tokens**; every answer parses under the contract | pass |
| Conductor on the contract: all 28 C0 gate tests, C1-prep, fuzz, quotes, Runtime Proof 001. A fabricated id cannot be written; a card that injects its own `F9 …` line is caught by the verifier; a bidi override hidden as `‮` is refused after unescaping | pass |
| EL0 harness: `.text` 82,716 B (+7.9 KB for the contract and Neuro's prompt text), `.bss` 52,392 B, **stack bound 10,912 B** (was 13,280), 0 FP/SIMD. `stack_bound` now also recognises half-word and byte jump tables | pass |
| **Guard G and grounding (Neuro's answers, 2026-11-24).** `neuro_contract::grounding` mirrors `guard_ground.py` and `grounding.py`: 1,518 vectors from Neuro's own functions match exactly. The ATT&CK 20.1 table (867 ids, 3.5 KB) has a drift gate against `attack-ids.json`. The harness runs G on the decoded summary before the verifier, against the cards and the earlier tool results, and records every edit in the ledger (`GroundingEdit`). The verifier applies Neuro's severities: an invented technique or an unreturned CVE → REJECTED; a service without its port on the cards → UNVERIFIED, and L0's verdict stands. Harness cost: `.text` +8.0 KB, `.rodata` +4.1 KB (90,736 / 8,408 B); stack bound unchanged | pass |
| **Evidence cards (Neuro's `semantic_compression.py`).** `neuro_contract::cards::build_context` turns a window's flows and detections into the context text: fan-out, periodic, volume and reset flags, novelty against the baseline, detection notes, ranking, entity aliases, the budget fill and the `REST` line. No float and no allocation: the caller's flows are sorted in place and the working memory is the caller's. Python's two float results that real traffic meets are reproduced exactly in integers (the mean gap, and the `out=…GB` rounding). Follows Neuro's d65431e5c: the 2-3 port match is `min(ports)`, one `REST` line when one card is dropped, the 5 s floor on the mean rounded to ms. 120 committed windows from Neuro's own functions match byte for byte, as do 6,400 more generated windows and Neuro's 22 windows of the E2E fixture (run locally; that file has real addresses). A drift gate reads 48 fragments of Neuro's two sources. Since 2026-11-28 it takes every event kind (`build_window`): DNS groups and behaviour records too, equal on Neuro's 64 synthetic contexts, 104 committed contexts and 6,000 more generated windows; entropy is computed in fixed point, with no float | pass |
| **Guards A and E (Neuro docs 24 and 25).** `neuro_contract::guard` mirrors `guard.py` and the template sentence of `run_eval.py`'s `template_backend`: 718 committed vectors from Neuro's own functions match exactly, and so do 15,018 more generated cases and the contexts of the spent sets dev v8 and blind v7 (run on the Neuro host, not committed). A drift gate reads `guard.py`, `semantic_compression.py` and `run_eval.py`. In the harness, guard A replaces every quoted value on a card or in a tool result by its description before a provider sees it, and the schema ids come from that shown context, as in `run_eval.py`. Guard E replaces an answer's prose that repeats 8 or more characters of a quoted value, of a card or of a tool result as received, by the template sentence and records it in the ledger (`EchoFallback`), before guard G. Cost: the harness keeps the cards as written and the tool results as received next to the prompt, two more `MAX_PROMPT` buffers (16,400 B of `.bss` by their size). The EL0 harness's `.text`, `.bss` and stack bound were **not** re-measured: no bare-metal toolchain on the host this was built on | pass (host) |
| **The investigation turn (Neuro's `inv_contract.json`, adapter ftM).** `neuro_contract::inv` writes the request as llama-server renders it (`--jinja --reasoning off`): Neuro's system prompt, the five tools in the model's own template, the user framing. A drift gate reads `tools/neuro-research/inv_contract.json`. On Neuro's 3 test vectors the prompt bytes equal llama-server's rendering, and with ftM's GGUF (`QWEN3_INV_GGUF`, run on the Neuro host) all 2,137 token ids equal llama-server's. `parse_answer` is the device's strict reading of the answer: free text, or ONE call of one of the five tools with exactly its typed arguments and an entity alias from the context; 22 malformed or out-of-scope calls are refused. **Not built:** constrained decoding of the tool call in the engine, the harness wiring of these tools, and the ftM fidelity run | pass (host) |
| **Decoding the investigation answer (Neuro's `inv_contract_gen.json`).** `neuro_contract::inv::ToolMachine` is llama-server's lazy tool-call grammar as a byte automaton (6 bytes of state): free text until the generated text contains `<tool_call>` and a newline, then the grammar the server derives from the five tools. The test reads the GBNF text the server reports and interprets it with an independent matcher: 1,500 random answers are accepted by both, and 18,000 one-byte changes get the same verdict from both. `neuro_lm::decode::generate_tool` decodes under it. With ftM's GGUF (`QWEN3_INV_GGUF`, run on the Neuro host) against llama.cpp b12477's CPU backend on Neuro's 3 vectors: raw top-1 and the constrained choice are equal on all 57 teacher-forced steps (no near-ties; top-2 margin error mean 0.048, max 0.191 nats), and the engine's own decoding gives the same token ids in all three. Three synthetic vectors, not an evaluation. **Not built:** head pruning and speculation for this path, the harness wiring of the five tools, the run on the spent investigation sets | pass (host) |
| **The investigation turn in the harness.** A job granted any of Neuro's five tools (bits 2 to 6 of the job's tool byte; never mixed with Conductor's own two) is an investigation job. The prompt is `neuro_contract::inv`'s, with nothing added, and always offers all five tools, as measured; the grant acts on the call. `inv::parse_answer` reads the answer and `tools::authorize_inv` authorizes it again on its own. A read tool becomes `Action::RunTool(ToolCall::Investigate)`; the device's one-line result joins the context as Neuro's `RESULT <tool> <alias>: <text>` line, after guard A, for the next call. `propose_policy_change` becomes `Action::Propose` and ends the job: nothing is applied. It stops a model (or an injection through it) running a tool the job was not granted, naming a device it was not shown, or changing a policy, and a tool result forging a card. `conductor-mock/tests/investigate.rs`, 14 tests: the prompt equals Neuro's; an ungranted call is refused and recorded; 13 malformed or out-of-contract calls are rejected and none is acted on; a proposal never reaches the tool executor; a result with a line break, a bidi override or no text aborts the job; a result of a class the provider may not see stays on the device; the step budget ends a chain; the `RESULT` line is checked against one of Neuro's vectors; the host ABI carries the alias | pass |
| **Cards built in the harness (operator decision 2026-11-28, Neuro doc 53 R12).** `conductor_core::window` decodes a window of events from the kernel (string table, flows, DNS queries, detections, behaviour records, baseline) and builds the context with `neuro_contract::cards`, in caller-provided memory. A job carries that context in place of cards; its shape is checked at load (fact lines in order, at most one closing `REST` line, nothing else). The provider is shown exactly it after guard A, with `RESULT` lines before `REST` in an investigation. `conductor-mock/tests/window.rs`: 86 vector windows through the wire format give Neuro's context byte for byte (104 contexts); 40 go on through the harness to the worker unchanged; answers are closed over the context; a window with no fact card is not sent; 14 malformed contexts and truncated, oversized or forged windows are refused | pass |

Random models repeat characters, which flatters n-gram drafts (0.49 passes per token there). The real-model
numbers are below.

**On the real Qwen3-1.7B** (`qwen3-closed`; public Q8_0 GGUF, packed; a synthetic context written for this
check, not a Neuro set). The 514-token prompt is built only from the contract; its closed enums are F1–F4 and
H1, R1, R2.

| | Plain | Pruning + speculation |
|---|---|---|
| Output | 122 tokens | **identical, token for token** |
| Forward passes after the prompt | 121 (0.99 per token) | **92 (0.75 per token)** |
| Pruned passes | none | 27, averaging **74 of 151,936** head rows |
| Drafts accepted | none | 29 of 70 |
| Prompt | 65 batched passes for 514 tokens (8 per pass) | same |
| Host time (x86, scalar, 1 thread) | 364 s | 378 s |

The answer is valid under the contract: verdict `suspicious`, confidence 75, evidence `F3, F1, F4`, entities
`H1, R1, R2`. Its wording is the public base model's and says nothing about ftFg.

**What these numbers mean.**
- **Device:** decode is bound by memory bandwidth, so what counts is how often the weights are read. The
  speed-ups cut the passes by 24 %. The pruned passes also skip about 18 % of their bytes (the output head),
  so weight traffic per generated token falls by about 28 %. That is an estimate from pass counts; the real
  figure needs a CM5.
- **Prompt:** 514 tokens cost 65 passes over the weights instead of 514.
- **Host:** this machine is compute-bound, so a batch costs as much as its tokens, and rejected drafts are
  extra work. That is why the sped-up run is 4 % slower here.
- **Not a win everywhere:** on a compute-bound target, speculation should be turned off (`draft_max = 0`).
  Pruning helps either way.
