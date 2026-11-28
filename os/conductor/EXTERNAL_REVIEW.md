# External review of design review v6: what is taken, what exists, what conflicts

An outside review of the Conductor design (2026-11-25) proposed data-flow fixes, a CM5 memory map, a streaming
model loader, a latency test plan and several pieces of `no_std` Rust. This file records how each point stands
against the repository, so the same suggestions are not re-argued. Rule used: an accepted ADR or a measured
result wins over the review; anything in `os/kernel` is HomePods' to decide.

The review's direction agrees with the design: authority on the device, untrusted compute, no Linux, no Python,
fixed memory, memory bandwidth as the limit. The differences are below.

## Taken

| Point | What was done |
|---|---|
| Load model segments without a staging copy (read straight into the region, verify there) | `neuro_hnx::Loader::accept_in_place` (measured on the 1.83 GB model: 3.2 s to read and verify in place on the build host): a segment the storage driver read into its place is hashed there. No copy; the load needs no memory beyond the region and the loader. Same refusals as `feed`; a mismatch fails the load and `abort` wipes the region. `neuro-hnx/tests/hnx.rs` |
| The evidence-card builder is missing on the device | Built the same day: `neuro_contract::cards` (hookprobe/hookprobe#1617), byte-equal to Neuro's builder. `CONTEXT` lines and who calls it are still open (`NEURO_ALIGNMENT.md`) |
| A job with nothing to ground on must not reach a model | `Refused(NoEvidence)` in the harness (hookprobe/hookprobe#1615) |
| Measure on real CM5 hardware, not only `qemu -icount`: packet latency alone, load throughput, decode slice time, then all three together | Agreed and already the stated limit of every engine number in `README.md`. The four experiments are a good shape for the metal gate. They need KR-1 and a board; nothing here can run them |

## Already in the repository

| Review's point | Where it is |
|---|---|
| Verify the model as it streams; never buffer the whole image; fail closed and wipe | `neuro-hnx`: header and signature first, admission reserves exactly the payload, each segment is hashed against its leaf as it arrives, `abort` zeroes the region. 2 MiB segments are allowed so a segment can be one block mapping |
| Per-chunk Merkle inclusion proofs | Not needed. HNX carries the table of leaf hashes; the signed root covers the table, so a segment is checked with one hash and no audit path. An inclusion-proof verifier would add code and a second way to be wrong |
| Monotonic counter and revocation epoch that survive power loss; two alternating slots; no regression on a torn write | `conductor_core::durable`, the kernel's own ADR 0069 record. 324 crash points tested; a drift gate reads the kernel source |
| Fixed-layout binary records across the harness, signer and ledger; hashes over resident buffers | `cap.rs`, `frame.rs`, `ledger.rs`, `abi.rs`. The ledger holds hashes and codes, never prompt or output text |
| Fixed job state machine, fixed timeouts and buffers | `conductor_core::harness`: about 52 KB of state, no allocator, every event carries the time |
| No secret in the harness | The harness has no key and no signing code (the `signer` feature is off in its build). The external-API tier the review assumes was removed on 2026-11-26 (ADR 0071 amendment): compute comes from heqk nodes only |
| Redaction happens where the request is built, not by convention in the prompt | Guard A is applied by the harness to every card and tool result before the prompt exists. Entities are aliases (`H1`, `R1`) assigned per request; data classes are checked per card and per tool result against the tier |
| Typed tool arguments, per-call authorization, model output never enforces | `tools.rs`, `authorize_inv`; a policy change is only ever a proposal for the owner |
| A bounded, static KV cache with a hard context cap | `neuro_lm::qwen3`: the KV cache is carved from a fixed arena sized by `max_ctx`; nothing grows |
| Admission decides local or remote; an oversized model is not squeezed in | ADR 0061 (proposed) and placement in `place.rs`. Today no LLM runs locally at all |
| Self-test of SIMD against scalar before use | `neon-proof`: scalar and NEON agree on every kernel and on a whole decoder, bare metal under emulation |

## Conflicts with accepted decisions: not taken

| Review's proposal | Why not |
|---|---|
| `CPACR_EL1.FPEN = 0b11`: FP/SIMD for EL1 and all of EL0 at bring-up | ADR 0072 (proposed) grants FP/SIMD to **one** isolated server and makes a second grant fail the build. The kernel stays soft-float. A global enable removes the property that every other server provably runs no vector code |
| An HP-EXEC v1 body of 299 bytes | The capability in the repository is 333 bytes: it also carries the time targets, the affinity id, cache scope and salt, KV persistence, offload hints and energy policy, each tested. The review's layout would drop the cache-poisoning and quote defences |
| A hand-written SHA-256 in the loader and self-test | The rule is the kernel's own crypto crates at its pinned versions (`sha2 0.10.9`). A second implementation is a second thing to audit |
| `unsafe` raw-pointer writes in the benchmark log and page-table code | The Conductor's device crates forbid `unsafe`. Page tables, TLB invalidation and system registers are `os/kernel` code and HomePods' to write; the sequences shown are a reasonable reference for them, not something to land from here |
| Non-greedy sampling (temperature, top-k, top-p) | Neuro measured both adapters at temperature 0 under a grammar. Sampling would be an unmeasured decoder and would break the token-for-token fidelity result. Not planned |
| The model loader and Merkle gate in EL1 | Neuro doc 08 and the design keep the kernel to memory, time and signature verification; the loader is `no_std` library code an isolated server runs, with the kernel verifying the signature and mapping the region |
| "Decode in token-sized slices on the packet core" as the plan | Whether an LLM shares a core with the packet path is ADR 0060's decision (core roles). The design does not assume it; "directing comes first" exists because local decode competes for the memory bus |

## Open, and whose it is

| Point | State |
|---|---|
| eMMC read speed (3 to 12 MB/s today) makes a 1.9 GB load take minutes | Real. It is the storage driver's transfer mode (Neuro R4), kernel side. `accept_in_place` removes the copy on this side, not the bus limit |
| 64-byte alignment of weight rows and KV strides | Partly. The packed layout exists for alignment (unaligned loads cost 4x under strict alignment, measured in instructions). Whether rows sit on cache-line boundaries in the mapped region depends on where the region is mapped; to be measured on metal, not assumed |
| The signed container could not carry the LLM (found while checking the review, not in it) | Fixed in the same change: payload kind `GGUF_LM`, an 8 GiB cap, manifest truth check in `neuro_gguf::hnx`, and the 1.7B model run end to end from a signed file on the build host (`README.md`). The tokenizer and RoPE tables are in the signed payload since the bundle (`neuro_gguf::bundle`). Left: the packed layout is still produced after load |
| A slice budget and a packet-queue high-water rule for local decode | Kernel scheduling (ADR 0060). The engine side can stop between forward passes; no budget interface is defined |
| Clock before SNTP | Stated in the design: only the device lease counts before SNTP. Kernel side for the lease; nothing to add here |
| The 128 MiB pool against a 2 GiB model | ADR 0061, proposed. The design already says so in its table of what is missing |

## Not relevant to this design

The review's section on how another vendor could use the architecture, and its closing self-assessment, change
nothing here.
