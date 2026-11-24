# Conductor / heqk-native engine ↔ Neuro: alignment (2026-11-24)

> Written by the Conductor session after reading Neuro's work up to `origin/main` @ `e478bca`; updated at `4d7ad4f` (end of file) (docs 30, 39–42,
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
  Qwen3"); the Qwen tokenizer is built and equal to HF `tokenizers` on the Qwen3 vocabulary (README, "The Qwen
  tokenizer").** **The GGUF reader is built: a public Qwen3-1.7B Q8_0 GGUF runs end to end on the
  integer engine (converter smoke test only). Plugging in ftFg needs only its GGUF (question 1).** Note for
  question 2: fidelity must be judged by token agreement and margins, since llama.cpp's own CPU path differs
  from float by about as much as this engine does. Nothing was trained or evaluated.
- **Fidelity, not quality:** the integer engine's logits and greedy outputs against llama.cpp on the SAME GGUF,
  on Neuro's **dev** set only (never a sealed set). If the outputs match within a stated tolerance, Neuro's
  quality results carry over; if they do not, that is a bug report, not a new evaluation.

## Questions for Neuro

1. Can the ftFg (and later ftKg) GGUF be made available to the build host, with its SHA-256 and licence record?
2. Which dev set may the fidelity check use, so it never touches a sealed set?
3. Is the evidence-card compressor format (run 1, stage C) the contract the device side should emit?

## Update: re-aligned with `origin/main` @ `4d7ad4f` (2026-11-24, afternoon)

Two commits landed since `e478bca`. The Conductor branch is rebased onto `4d7ad4f` (no file under
`os/conductor` changed upstream; all gates still pass).

### What changed on the Neuro side, and what it changes here

1. **Doc 42: ftKg failed (p = 0.052; triage regression on blind v7, 12 % of malicious cases called benign).**
   **ftFg stays the explainer, without investigation.** For the device engine this settles the target:
   ftFg only. ftKg's GGUF hash (`fb3c9a05…`) is recorded in doc 42, but it is not a target.
   - The explainer turn is **one shot**: evidence in, one JSON answer out, no tool calls. The Conductor harness
     runs it without the tool loop. The typed tools stay built for a later investigation model.
   - Doc 42 suggests a **separate investigation adapter**, loaded only for investigation turns. If Neuro pursues
     it, the engine needs two packed models sharing one base, or LoRA merged at load. Not built; noted so it is
     not designed twice.
2. **ftFg's file identity is in the repo** (doc 26, `data/mixF-dev-results.md`): `gguf-mixF-q8_0.gguf`, SHA-256
   `0b0d276ed5a9f0a5b6597830c3f751411db6d62f3d962ec58e1f12d19f3161ed`. That answers half of question 1. **Still
   needed:** the file itself (it lives on the Neuro build host, not in the repo) and the licence record for the
   LoRA weights. The base model, Qwen3-1.7B, is Apache-2.0.
3. **The configuration Neuro validated is more than the weights.** From `run_eval.py`, `mixF_chain.sh` and doc 26:
   - llama.cpp `b12477`, `--reasoning off`, temperature 0;
   - **evidence-closed decoding** (`--mode closed`): a per-request JSON schema whose `evidence` and `entities` items
     are enums of exactly the fact ids (`F1…`) and aliases (`H1`, `R1`, `D1…`) present in the context. It has
     closed enums for verdict, severity and next step, and an integer confidence of 0–100. llama-server compiles
     it to a grammar, so a hallucinated entity cannot be emitted;
   - guard A on the input, echo filter E and rule T (doc 40) on the output.

   **Consequence for the engine:** to claim fidelity with ftFg-AE, the engine must decode under the same
   constraint. **New engine item: evidence-closed constrained decoding.** At each step, the schema's automaton
   masks the logits before the argmax. Integer only; no regex engine is needed, because the schema shape is fixed
   and only the enums change per request. Until it exists, the fidelity check can cover the free mode only.
4. **Reference numbers for comparison (not re-measured here).** E2E run 1 (ftFg, Mac, llama-server on Metal):
   1.34 s median per answer, 122 tok/s, 3.4 GB RSS. Run 2 (ftKg): 1.24 s median, 125 tok/s. Metal does not
   quantise activations, so the engine-vs-llama.cpp comparison should use llama.cpp's CPU backend, or allow for
   the difference (README, "GGUF reader").

### What changed on the HomePods side

- **ADR 0069's msg1 counter is proven on CM5 metal and the live S0 PoP** (`docs/design/metal-evidence/
  20261124-adr69-g19-counter-cm5.md`). All 17 checks hold:
  - a recorded msg1 replayed after a PoP restart is refused;
  - the counter is durable across restart and reboot (`G19Ctr` on the DataVolume);
  - there is no downgrade path.
- HP-EXEC's anti-replay is the same pattern: a monotonic sealed counter on the device and a persisted high-water
  mark on the worker. So C1's counter can reuse a metal-proven mechanism instead of a new one. No change to the
  C0 design.

### Updated questions for Neuro

1. The ftFg file `gguf-mixF-q8_0.gguf` (SHA-256 `0b0d276e…61ed`) on the build host, plus the LoRA licence record.
2. Which dev set the fidelity check may use. Unchanged; it never touches a sealed set, and inv-blind v1 is spent.
3. Is the evidence card from the run 1 compressor (stage C) the contract the device side should emit? Unchanged.
4. **New:** for the device, is `closed` mode (the per-request enum schema) part of the explainer contract? If yes,
   the engine implements it before the fidelity check. And which of guard A, filter E and rule T run on the device
   or in the harness, and which stay off-device?
