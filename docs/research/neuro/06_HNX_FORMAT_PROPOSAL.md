# 06 — HNX: HookProbe Neural Executable (Gate 6, proposal)

> Native Inference Research Programme, 2026-11-18. **A research proposal, not a decision.** Nothing
> here is implemented. Comparisons with existing formats are in `03` and `10`.

## 1. The idea in one paragraph

GGUF, safetensors and ONNX describe **what a model is**: tensors, plus metadata or a graph. A
runtime still has to decide at load time how to lay the model out, which kernels to use and how
much memory it needs. On heqk that decision should be made **offline, on the build host**, and
shipped as data the device can check without trusting it. An HNX package is a model compiled for one
target:
- weights already packed in the exact layout the target kernels stream;
- a static execution plan;
- a precomputed memory plan;
- a resource manifest the kernel's admission control can read (ADR 0061 D4);
- a hybrid signature verified against the same trust root as the boot image.

The device never compiles, JITs or interprets an untrusted graph. It **checks**, **admits**, maps
read-only and runs a fixed sequence of **known kernel IDs** from the engine's own signed code.

## 2. What HNX contains — and what it must not

| Section | Contents | Why |
|---|---|---|
| Header | magic, HNX version, target triple (`cm5-a76`, `aarch64-generic`, `x86_64-v3`, `qemu-virt`), engine ABI version | refuse anything the engine cannot run, before reading further |
| **Capability requirements** | required CPU features (`asimddp` / SDOT; never i8mm/SVE on CM5), FP/SIMD lease, core count min/max | admission can refuse with a reason (`/api/capabilities`) |
| **Resource manifest** | weights bytes; arena bytes; per-session state bytes (KV per token or fixed recurrent state); max context; max sessions; expected bytes per token; CPU-time per token class | **ADR 0061 D4 admission reads these numbers**; it never trusts a running process to report them |
| Architecture & tokenizer | architecture id (closed enum: `transformer-gqa`, `rwkv7`, `gdn-hybrid`, `specialist-gru`, `specialist-mlp`), dimensions, tokenizer tables (trimmed vocabulary, `10`) | the engine has one code path per architecture id |
| **Execution plan** | ordered list of steps `(kernel_id, input slots, output slot, weight ref, params)`; kernel ids name **kernels compiled into the signed engine** | no code in the package: a plan is data |
| **Memory plan** | arena offsets for every slot (liveness-analysed offline); state layout | zero allocation during inference; bounds-checked once at admission |
| Weights | packed per target: Q4 repacked for 4×/8× interleaved SDOT, ternary bit-planes for the LUT kernel, int8 for specialists; 2 MiB-aligned segments | the device maps it read-only and streams it; no unpack at load |
| Quantisation metadata | scale granularity per tensor (block/row/tensor), zero points | kernels know their scale mode from the kernel id, not at run time |
| Constraint tables | the output schemas this model may be asked to fill (closed-decoding grammars as token automata); allowed-token sets for sparse logits | evidence-closed decoding (P2) without a runtime grammar compiler |
| Provenance | source model id, source file SHA-256, licence SPDX id, compiler version, eval report hash (the blind-set gate result) | a model without a passing eval report is not admissible |
| **Integrity** | per-segment SHA-256 (or BLAKE3) Merkle tree; root hash in a signed footer | verify streaming, segment by segment |
| Signature | Ed25519 + SLH-DSA-SHA2-128s over the root — the scheme heqk already uses for images (`os/build/heqk-sign`, `boot-abi/src/verify.rs`; status in `00`) | one trust model for code and models |

**Must not contain:** executable code, shaders or JIT input; any pointer, address or offset that is
not checked against a size; tool permissions (a model never grants itself capabilities; C9).

## 3. One source model, several packages

```
source (safetensors / GGUF, licence-checked)
   │  hnx-compile  (build host, deterministic, reproducible)
   │    ├─ quantise or convert (ternary only for models TRAINED ternary)
   │    ├─ trim vocabulary (optional), build constraint tables
   │    ├─ choose kernels per target, repack weights for them
   │    ├─ liveness analysis → memory plan, resource manifest
   │    └─ run the blind eval on the PACKAGE (reference engine) → eval report hash
   ▼
cm5-a76.hnx      aarch64-generic.hnx      x86_64-v3.hnx      qemu-virt.hnx
(SDOT, 2 MiB)    (NEON baseline)          (AVX2/VNNI)        (= generic, for gates)
```

`qemu-virt` matters for HomePods' gates: `os/kernel/validate.sh` could admit and run a tiny HNX
(a specialist) as a smoke test without hardware. That is a request, not something we change (`12`).

## 4. Verification on the device (proposed order)

1. Read the header and capability block (a few KiB). Refuse an unknown version, target or feature.
2. Verify the signature over the root hash. Refuse an untrusted key.
3. Present the resource manifest to admission. cfgd reserves or refuses (ADR 0061 D4, no
   overcommit).
4. Stream segments from eMMC into the reserved region, hashing each against the Merkle tree. A
   mismatch aborts and releases the reservation.
5. Remap the weight region **read-only** to the engine (`12`); bounds-check every plan step against
   the memory plan once.
6. Run. No further allocation; every step is a known kernel on checked offsets.

## 5. Comparison with existing formats (summary; references in `03`/`10`)

| Format | Weights | Graph / plan | Memory plan | Resource manifest | Signature | Target-specific packing |
|---|---|---|---|---|---|---|
| GGUF | yes | architecture name + hyperparameters (graph is in the runtime) | no | no | no | partly (some quant types are layout-specific; ARM repack happens at load) |
| safetensors | yes | no | no | no | no (separate signing tools exist) | no |
| ONNX | yes | yes (operator graph) | no | no | no | no |
| TFLite / LiteRT flatbuffer | yes | yes | **arena size planned at init** (TFLM) | no | no | partly (delegates) |
| ExecuTorch `.pte` | yes | yes (lowered program) | **yes, planned at export** | no | no | yes (backend-lowered) |
| **HNX (proposed)** | yes | **plan of signed kernel ids** | **yes, offline** | **yes, for kernel admission** | **hybrid PQ** | **yes, per target** |

The closest existing design is ExecuTorch's `.pte`: ahead-of-time lowering plus export-time memory
planning. What HNX adds is the coupling to **an OS admission-control and capability system**
(manifest → kernel reservation → read-only mapping) and **hybrid post-quantum signing** on the
same root as the OS image. Whether that coupling is novel is checked in `10`. It is not claimed
here.

## 6. Open questions

- Is a Merkle tree worth it versus a single hash, given loads are sequential? It is worth it
  if loading is ever partial (MoE experts, specialists sharing a backbone).
- How are model updates rolled out: same A/B and rollout rings as images (ADR 0047), or a separate
  channel? The update channel is a security decision for `security-auditor`.
- The licence field must block non-commercial or regionally restricted models at compile time
  (LFM, Hunyuan, OpenLLM-Ro were excluded in Phase 0 for this reason).
