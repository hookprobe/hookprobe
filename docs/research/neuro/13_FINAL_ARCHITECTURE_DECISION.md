# 13 — Final architecture decision (Gate 12)

> Native Inference Research Programme, 2026-11-18. **A recommendation for operator review. It
> authorises nothing.** Implementation waits for approval. Kernel work is HomePods' to accept or
> decline (`12`).

## The decision

**Build HookProbe Native Intelligence as a staged, heqk-guest engine, with temporal intelligence
first:**
- **Stage 1 runs today, with no kernel change:** an integer-only **temporal security engine**
  (`el0-neuro` N0) inside one EL0 server. It runs the Neural DNA (measured), int8 specialists, and,
  only if E-N2 earns it, a tiny learned recurrent cell per device.
- **The spine of every later stage is a signed, offline-compiled model package (HNX)** that the
  kernel verifies, admits and maps read-only.
- **A language tier comes later, leased and paced**, used only to explain. Its format (Q4 transformer
  or hybrid, RWKV-7, or trained-ternary) is decided by measurement, not now.

This is architecture **A6** in `10`. The user's suggested first experiment, "native recurrent
security inference", is kept. It is moved to **the scale that fits the evidence**:
- **a per-device recurrent state of tens to hundreds of bytes**, not an LM-scale recurrent model;
- one RWKV-7 0.1B state is 2.3 MiB (`04` §4), about 3,500× the measured DNA.

## Ranking (practical value, evidence, feasibility, security, long-term differentiation)

| Rank | Opportunity | Value | Evidence today | Feasibility on heqk | Security | Differentiation | Verdict |
|---|---|---|---|---|---|---|---|
| 1 | **A2 temporal engine (N0)** | high: every device, every minute; explainable alarms | **real traffic**: peer novelty 14/14 onsets; Hue nuisance 11 → 2/day after Phase 0b | **today** (R1) | strong | medium; open gap in prior art for on-gateway per-device learned state | **build first** |
| 2 | **HNX + admission (A3 + A4 spine)** | high: makes every later model safe to ship | design; prior art covers parts only | needs R2–R6 | **strongest** | high (combination not found) | design now; implement with the first model > 3 MiB |
| 3 | **Grammar-sparse logits + vocabulary trimming** | medium–high for small LMs (head = 25–40% of bytes) | prior-art search found no engine doing GSL; E-N6 runs on existing data | engine-side only | neutral | **highest originality signal** | measure (E-N6, E-N7) before claiming |
| 4 | **Language tier, leased and paced** | medium: explanations nearly triple coverage (blind set) | Phase 0 blind evaluation | needs R2–R8 | strong if closed decoding | low (everyone has LMs) | after stage 1; off-device fallback meanwhile |
| 5 | Native ternary engine (A1) | medium: halves bus use per token | kernel model + dev-host bench; no CM5 run | needs R2–R4 | good | low (bitnet.cpp, T-MAC) | only if E-N1 and E-N4 pass |
| 6 | Distributed mesh (A5) | medium for fleets | none | control plane only | **poisoning risk** | low | after stage 2, with signing and quorum |

## Answers to the thirteen questions

1. **What should we build?**
   - `el0-neuro` N0: a no_std Rust temporal and specialist engine, fixed-point, in one EL0 server.
   - `hnx-compile`: the offline compiler and signer on the build host.
   - The HNX format, specified and versioned.

   Later, under approval: N1 (SIMD) and N2 (language tier).
2. **Why is it better than conventional LLM inference for HookProbe?**
   - On the blind set the small models judged worse than the deterministic core (0.37–0.50 vs 0.59),
     no better than always answering "malicious" (0.43), and they anchor on example verdicts.
   - Temporal per-device intelligence costs bytes and microseconds. It runs on every SKU including
     2 GB, needs no kernel change, and every alarm names its cause.
   - Language is a rare explainer, not a constant judge.
3. **Which model architecture first?**
   - **Temporal tier:** statistical DNA (shipping candidate), then a tiny int8 recurrent cell **only
     if** it beats DNA by ≥ 0.02 AUC at equal bytes (E-N2).
   - **Language tier candidates, by measurement:** Qwen3.5-0.8B (measured best fast explainer) vs
     RWKV-7 0.4B/1.5B (best memory fit, unmeasured) vs BitNet 2B4T (best bandwidth fit, unmeasured).
4. **Which quantisation?**
   - Specialists and recurrent cells: **int8, per-tensor scales**.
   - Language tier now: **4-bit, stored in the A76 interleaved layout**, so no load-time repack.
   - Ternary **only for models trained ternary**, via the packed bit-plane LUT kernel, if E-N1/E-N4
     confirm the `02` model (≈ +11% speed, −50% bus per weight against Q4).
   - KV at 8 bits.
5. **Native Rust runtime, or adapt an existing one?**
   - **Native.** No existing runtime fits:
     - ggml needs libc and threads;
     - TFLM has no Cortex-A kernels;
     - ExecuTorch's fast Arm path needs pthreadpool;
     - tract and candle are not no_std;
     - TVM's bare-metal path was removed.
   - Borrow ExecuTorch's plan/arena split, ggml's A76 layout, and bitnet.cpp/T-MAC's LUT method.
6. **Which AArch64 kernels?**
   - **N0 (scalar):** int8 dense, GRU/minimal-RNN cell, fixed-point log2/sqrt/exp, top-k.
   - **N1/N2 (NEON):**
     - SDOT GEMV in the 4-row interleaved layout with per-row scales;
     - packed bit-plane LUT GEMV;
     - int8 activation quantise fused with RMSNorm;
     - RoPE (Q15);
     - online softmax;
     - SiLU/ReLU² LUT;
     - WKV7 state update (if RWKV);
     - grammar-sparse head with argmax.
   - **Hand assembly** only for the ternary paths (`02` §5).
7. **What does heqk support today?**
   - One 4 MiB EL0 server, scalar integer only, in bounded excursions with fault containment.
   - Kernel↔EL0 rings; read-only page mappings; W^X.
   - Hybrid PQ verification, but only for images.
   - The data plane at ~400 ns/packet on metal.
   - No FP/SIMD, no large regions, no load path, no admission, no SMP, no pressure signal (`00`).
8. **What must HomePods expose?**
   - **R0 readouts first.**
   - Nothing for stage 1.
   - Then R2 (per-server FP/SIMD with save/scrub).
   - Then R3–R6 (model region, extent load, package verify, admission).
   - Then R7–R8 (CPU lease, either token-sized excursions or ADR 0060; and a pressure page).

   All are listed with evidence in `12`.
9. **What must HookProbe OS integrate?**
   - Detection-ring input to `el0-neuro`.
   - DNA alarms as evidence-graph nodes with named drivers.
   - The explanation panel filled L0-first, model-second.
   - `/api/planner/*` staying honestly `not_configured` until a lease exists.
   - Lease state and AI cost in `/api/capabilities`.
   - HNX upload through the owner-authenticated upload channel.
   - Owner confirmation as the fast path from "deviation" to "normal".
10. **What is the minimum viable experiment?**
    - **E-N0:** port DNA scoring to fixed-point Rust in an EL0 server under QEMU-heqk, replay the
      IoT-23 test split through the detection ring, then measure on CM5 metal.
    - **Success:** AUC within 0.005 of the Python reference, < 1% of one core at 1K events/s,
      no increase in the main loop's worst gap.
11. **What resources are expected?**
    - **N0:** ≤ 1 MiB code plus 672 B per device (≈ 0.7 MiB per 1,000 devices). It fits the existing
      4 MiB window on every SKU.
    - **N2 language tier** (theoretical, `07`): 0.3–1 GiB per model; 4 GB SKU and up; load 25–133 s
      on today's eMMC path.
12. **What are the major technical risks?**
    - The temporal tier's nuisance rate on real multi-day traffic is unproven (one benign device so
      far).
    - The learned cell may not beat statistics.
    - FP/SIMD context handling is a security-sensitive kernel change.
    - eMMC throughput may make on-device language models load-at-boot only.
    - Single-core heqk cannot host decode without stretching the main loop unless excursions are
      token-sized.
    - Ternary gains are a model, not a measurement.
    - The language tier may never beat the off-device fallback on cost and benefit for small SKUs.
13. **What should explicitly NOT be built?**
    - Inference inside the kernel (33 KB of image headroom; boundary).
    - A port of llama.cpp/ggml.
    - A Wasm-hosted inference path.
    - Demand-paged or storage-streamed weights during decode.
    - MoE on CM5.
    - LM-scale recurrent state per device.
    - Transformer traffic classifiers from the literature (they fail leakage-free evaluation).
    - Ternary conversion of models not trained ternary.
    - Code inside model packages.
    - Any path where a model's output is an enforcement decision.

## What kind of claim each part is

| Class | Items |
|---|---|
| **Existing proven technology** | SDOT int8 GEMV; GGUF/ggml A76 repack; ExecuTorch-style plans and arenas; Ed25519 + SLH-DSA signing (already in heqk); statistical behaviour baselines (Kitsune-class) |
| **Existing technology adapted to heqk** | bit-plane LUT ternary kernels (T-MAC/bitnet.cpp) in no_std Rust; static plan interpreter; evidence-closed decoding via token automata in the package |
| **New engineering proposals** | `el0-neuro` and its heqk host interface (`05` §3); HNX with manifest-driven admission (`06`); token-sized excursion decoding (R7 b); pressure-page pacing (R8) |
| **Unverified hypotheses** | ternary is faster than Q4 on A76 (`02` §3); RWKV-7 explains as well as a hybrid (E-N3); a learned per-device cell beats DNA (E-N2); open-loop pacing protects DP p99 (E-N5b) |
| **Potential original research** | grammar-sparse logits (`10` §3 rank 1); OS admission of signed model packages (rank 2); on-gateway per-device learned recurrent state with measured cost (rank 3). **Novelty is not claimed; each needs a professional search.** |

## Approval requested

1. **Stage 1 implementation:** `el0-neuro` N0 plus the E-N0 harness, on a new branch, as an EL0 crate.
   This is HookProbe code. Wiring the crate into `kernel/build.rs` behind a feature is a HomePods
   decision, so we would hand them a ready crate rather than touch `os/kernel`.
2. **Experiments that need no hardware:** E-N2, E-N6, E-N7; plus E-N3 if you approve downloading
   RWKV-7 GGUF files (Apache-2.0).
3. **HomePods:** send `12` to HomePods, R0 first.
