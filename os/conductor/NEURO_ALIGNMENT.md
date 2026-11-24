# Conductor / heqk-native engine ↔ Neuro: alignment (2026-11-24)

> Written by the Conductor session after reading Neuro's work up to `origin/main` @ `e478bca` (docs 30, 39–42,
> `data/e2e-2026-11-24.md`, `tools/neuro-research`). The Neuro session was not reachable from this cloud
> session; this note is the hand-off. Nothing here changes Neuro's decisions.

## Who owns what

| Area | Owner | Conductor's role |
|---|---|---|
| Which models, training, fine-tunes (ftFg, mixK → ftKg), LoRA recipes | **Neuro** (docs 16, 25–26, 42) | none. Conductor trains nothing |
| Evaluation sets, pre-registrations, gates (blind v7, dev v8, inv-blind v1 sealed) | **Neuro** | none. No parallel quality evaluation |
| Prompt format, tools (the six tools, `lookup_exposure`), playbooks, guards A/E, rule T | **Neuro** (docs 25, 39–41, 40) | **adopt**, not invent |
| End-to-end quality and cost of the pipeline (run 1, Mac) | **Neuro** (`e2e_neuro.sh`) | reuse its numbers; do not re-measure |
| Detection tier on device (DNA, S1, neuro-dp) | Neuro + HomePods (metal) | compose only |
| heqk-native execution of the explainer: engine, kernels, model package (HNX), loader, admission | **Conductor** (with HomePods for kernel R2–R8) | build |
| Delegation, capabilities, ledger, verifier around a model call | **Conductor** | build, using Neuro's contracts |

## Where the Conductor work overlapped, and what changes

1. **Model.** Conductor started converting SmolLM2-135M (a generic Llama-family model) to test its engine.
   Neuro's explainer is **ftFg = Qwen3-1.7B fine-tune, GGUF Q8_0, ≈ 1.8 GB** (doc 30, run 1). Change: the
   converter's input becomes **Neuro's exported GGUF** (ftFg now, ftKg if doc 42 passes); SmolLM2 is dropped
   as a target (at most a private converter smoke test, never a model track). Consequences for the engine:
   Qwen3 architecture (per-head QK RMSNorm, RoPE θ = 1e6, Qwen2 tokenizer, 151,936 ids) and **Q8_0 weights**:
   Neuro's gates passed at Q8_0, so the engine must run Q8 first. A Q4 version is only shippable if it passes
   Neuro's gates again.
2. **Prompt, tools, answer schema.** The Conductor harness (C0) invented its own JSON answer schema and two
   tools (`evidence.get`, `flows.count`). Change: adopt Neuro's `run_eval.SYSTEM` framing, the six tools with
   their argument types, the `<tool_call>` format of the model's chat template, guard A on the context, guard E
   and rule T on the answer. Conductor keeps what Neuro does not cover: per-call capability, typed-argument
   authorization, data-class flow checks, the five verifier statuses, the ledger.
3. **Runtime Proof 001 vs e2e run 1.** Not the same thing, but overlapping. Run 1 measures quality and cost
   (Python + llama-server on the Mac). Proof 001 shows the device-side Rust crates compose in one `no_std`
   pipeline. Change: Proof 001 drops its own evidence cards and uses Neuro's compressor format; it reports
   composition and footprint only, and cites run 1 for cost and quality.
4. **Placement.** Doc 30: explainer = language tier, 4 GB SKU and up, off the protection path. The heqk-native
   engine is how that tier runs without Linux; it needs kernel R2 (KR-1), R3–R6. Until then run 1's
   "off-device or companion tier" stands.

## What Conductor will build next (proposal)

- `hnx-compile` reads **GGUF** (Q8_0 first) as exported by Neuro, converts to HNX for the engine.
- `neuro-lm`: Q8 GEMV kernel (scalar + NEON SDOT), Qwen3 QK-norm, the Qwen2 pre-tokenizer. **Status
  2026-11-24: the `Q8_0` kernels and the Qwen3 decoder are built and verified (README, "The 8-bit path and
  Qwen3"); the tokenizer is not yet.** Nothing was trained or evaluated.
- **Fidelity, not quality:** the integer engine's logits and greedy outputs against llama.cpp on the SAME GGUF,
  on Neuro's **dev** set only (never a sealed set). If the outputs match within a stated tolerance, Neuro's
  quality results carry over; if they do not, that is a bug report, not a new evaluation.

## Questions for Neuro

1. Can the ftFg (and later ftKg) GGUF be made available to the build host, with its SHA-256 and licence record?
2. Which dev set may the fidelity check use, so it never touches a sealed set?
3. Is the evidence-card compressor format (run 1, stage C) the contract the device side should emit?
