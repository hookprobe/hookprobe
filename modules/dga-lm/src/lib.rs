//! # dga-lm — int8 char-level DGA classifier
//!
//! base-tier-build-ticket.md Phase 4 (ADR 0014 D6, ADR 0021 D7, ADR 0031). A pure-CPU,
//! signed Wasm module — **no NPU, no WASI-NN** — that scores a domain name's likelihood
//! of being algorithmically generated (a DGA — Domain Generation Algorithm, the classic
//! C2 rendezvous technique) using a small int8 embed -> conv1d -> global-max-pool ->
//! dense network. The hot conv dot-product goes through [`dot::dot_i8`], whose compiled
//! kernel is chosen at BUILD TIME per CPU tier (see `dot.rs`):
//!
//! - **A76 tier** (`+dotprod`, `relaxed-dot` Cargo feature): the EXPLICIT
//!   `core::arch::wasm32::i32x4_relaxed_dot_i8x16_i7x16_add` intrinsic, lowering to a
//!   single `SDOT` instruction on real Cortex-A76 hardware (must-fix #2 — plain
//!   `core::simd` never emits this opcode, so this crate deliberately never routes
//!   through it).
//! - **A72 / portable tier** (default build, ships as `dga-lm.wasm`): standard
//!   (non-relaxed) WASM SIMD widening-multiply-add — the NEON SMULL/SMLAL-equivalent
//!   fallback, correct on every host.
//!
//! **This is honestly a SEED/BASELINE model, not a validated DGA detector** — see
//! `model/MODEL_CARD.md`. Per ADR 0014, real training happens OFF-DEVICE; this crate
//! ships a small, hand-derived, documented placeholder that exercises the full compute
//! + dot-kernel path end to end.
//!
//! ## C9 — advisory / observe-only
//!
//! `dga-lm`'s score is NEVER in the enforcement path (ADR 0023 — only a single `decide()`
//! enforces, and it is not this module). It feeds QSECBIT's `p_attack` component
//! (`modules/qsecbit`), which is itself one of four heuristic inputs to a composite risk
//! SCORE shown to the operator — not a block/drop decision. Any persisted training label
//! is re-scored off-device, never taken from this module's on-device fast-path number.
//!
//! ## Protocol
//!
//! One domain name per stdin line -> one JSON line on stdout (see `main.rs`).

#![forbid(unsafe_code)]

pub mod dot;
pub mod model;
pub mod tokenizer;

use model::OwnedWeights;

/// Score for one domain: raw logits, a softmax-normalized DGA probability, and the
/// model identity (surfaced downstream so an operator/QSECBIT breakdown panel can
/// always tell "which model produced this number" — never silently swapped).
#[derive(Debug, Clone, PartialEq)]
pub struct DgaScore {
    pub domain: String,
    /// `[benign_logit, dga_logit]`, raw i32 (pre-softmax), for debugging/audit.
    pub logits: [i32; 2],
    /// Softmax-normalized probability the domain is DGA-generated, in `[0.0, 1.0]`.
    pub p_dga: f64,
    /// Model identity string — e.g. `"dga-lm-seed-v0.1"`. See `model/MODEL_CARD.md`.
    pub model_id: &'static str,
}

/// Model identity string, bumped whenever `ci/quantize.py`'s seed weights change shape
/// or values. Kept as a constant (not derived from the blob hash) so it's human-legible
/// in JSON output and logs; the blob's own digest (module.yaml artifact entry) is the
/// cryptographic identity for signing/provenance purposes.
pub const MODEL_ID: &str = "dga-lm-seed-v0.1";

/// A loaded scorer — parses the embedded seed model once, then scores many domains.
pub struct Scorer {
    weights: OwnedWeights,
}

impl Scorer {
    /// Load the embedded seed model (`model::SEED_MODEL_BYTES`). Infallible in
    /// practice (the blob is `include_bytes!`-embedded and covered by
    /// `model::tests::seed_model_parses_cleanly`) but returns `Result` so a future
    /// swap to a runtime-supplied model path can reuse this exact signature.
    pub fn load_seed() -> Result<Self, model::ParseError> {
        Ok(Self { weights: OwnedWeights::parse(model::SEED_MODEL_BYTES)? })
    }

    /// Score one domain. Never panics on malformed/empty/oversized input — the
    /// tokenizer truncates/pads (see `tokenizer::tokenize`).
    pub fn score(&self, domain: &str) -> DgaScore {
        let logits = self.weights.forward(domain);
        let p_dga = softmax_p1(logits[0], logits[1]);
        DgaScore { domain: domain.to_string(), logits, p_dga, model_id: MODEL_ID }
    }
}

/// 2-class softmax, returning P(class 1) = dga. Uses f64 (not part of the int8 hot
/// loop — called once per domain, on two scalars, not per-SIMD-lane) for numerically
/// stable normalization; this does NOT reintroduce float into the dot-product kernels
/// (must-fix #2 is about the dot loop, not the final 2-element softmax).
fn softmax_p1(logit0: i32, logit1: i32) -> f64 {
    let a = logit0 as f64;
    let b = logit1 as f64;
    let m = a.max(b);
    let ea = (a - m).exp();
    let eb = (b - m).exp();
    (eb / (ea + eb)).clamp(0.0, 1.0)
}

// ─── QSECBIT connector (base-tier-build-ticket.md Phase 4 / ADR 0014 D6) ───────────
//
// **What this is.** A small, pure, unit-tested mapping from this module's own output
// (`DgaScore::p_dga`) to the value an orchestrator should place in QSECBIT's `p_attack`
// input field (`modules/qsecbit/src/main.rs`'s documented optional 5th CSV field —
// `cpu_norm,memory_norm,network_norm,disk_io_norm[,p_attack]`). It is the "output path"
// half of the wiring described in `main.rs`'s "Wiring into QSECBIT" doc comment above.
//
// **What this is NOT (the honest remaining gap).** This function does not, by itself,
// make `p_attack` live on any device. Two pieces of real plumbing are still missing,
// and both are OUTSIDE this crate's ownership per this pass's scope:
//   1. **dga-lm is not yet a registered/loadable module.** There is no
//      `modules/dga-lm/module.yaml`, no `modules/dga-lm/units/*.service`, and no
//      signature (`module.sig`/`module.mldsa.sig`) — the ADR 0016 signing gate and the
//      ADR 0015 unit registry (see `builder/lint-units.sh`'s comment: "modules/*/units
//      are already governed by the ADR 0015 registry gate") would refuse to stage or
//      load it as-is. Registering it (module.yaml, capability token wiring, signing) is
//      an os-architect/release-engineer concern per this task's explicit scope fence.
//   2. **No process merges the two live streams.** Today, on a running device, two
//      independent producers already exist and are proven live (see
//      `base/scripts/telemetry-export.sh` -> `qsecbit.service`'s `tail -F telemetry`
//      pipe for the 5s host-metric CSV tick, and `base/scripts/dnsxai-feed.sh` ->
//      `dnsxai.service`'s `tail -F flows` pipe for the event-driven bare-domain
//      stream already consumed by `dnsxai`, in exactly the shape this module's own
//      `main.rs` also expects on stdin). Nothing today runs dga-lm over that domain
//      stream, holds its most recent (or windowed) `p_dga`, and appends it as the 5th
//      field of the CSV line `qsecbit.service` tails — that merge stage (cadence:
//      event-driven `p_dga` vs. the 5s telemetry tick) has no design in ADR 0014 /
//      `docs/base-tier-build-ticket.md` yet (checked: neither document specifies a
//      windowing/decay policy), so this pass does not invent one; it ships the
//      mapping function that merge stage will call once module registration lands.
//
// **The gate this function DOES enforce**: `ml_cpu` is a scoped capability
// (`platforms/*.yaml`, `crates/hookprobe-manifest/src/capabilities.rs` — A76 tier
// granted, A72 tier budget-gated per ADR 0014 D6). Per
// `docs/base-tier-build-ticket.md` Phase 4's acceptance gate, "if the A72 NEON path
// misses the epoch, `ml_cpu` is not granted there ... and `p_attack` stays 0.0 —
// scoped, not global." The caller passes in whether `ml_cpu` was granted (read once
// from the signed Platform Manifest, the same source every other capability-gated
// module already uses); this function never reads the manifest itself, keeping it a
// pure/testable mapping with zero I/O.
//
// **C9 — advisory/observe-only.** Like every other consumer of `p_dga`
// (`modules/qsecbit`'s own doc, `main.rs`'s "Wiring into QSECBIT" section), the value
// this function returns only ever feeds a displayed composite score — it is never in
// the enforcement path.

/// Map this module's DGA probability to the value an orchestrator should place in
/// QSECBIT's `p_attack` input (`modules/qsecbit/src/main.rs`'s optional 5th CSV
/// field).
///
/// - When `ml_cpu_granted` is `true`: returns `p_dga` clamped to `[0.0, 1.0]` (defensive
///   — `Scorer::score`'s softmax already produces a clamped value, but a connector at a
///   trust boundary should never assume its input is well-formed).
/// - When `ml_cpu_granted` is `false`: always returns `0.0`, regardless of `p_dga` —
///   this is the ADR 0014 D6 "scoped, not global" rule: on a CPU tier that can't run the
///   model within its epoch budget (or where the manifest simply never granted the
///   token), QSECBIT's ML term must stay neutral, not silently degrade to a stale or
///   partial score.
///
/// See the module-level "QSECBIT connector" doc block above for what is and is not
/// wired yet.
pub fn p_attack_for_qsecbit(p_dga: f64, ml_cpu_granted: bool) -> f64 {
    if !ml_cpu_granted {
        return 0.0;
    }
    if p_dga.is_nan() {
        return 0.0; // fail closed on a malformed upstream score, never propagate NaN
    }
    p_dga.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_seed_model() {
        Scorer::load_seed().expect("seed model must load");
    }

    #[test]
    fn benign_word_domain_scores_low() {
        let s = Scorer::load_seed().unwrap();
        let out = s.score("google.com");
        assert!(out.p_dga < 0.5, "expected a recognizable word domain to score < 0.5, got {}", out.p_dga);
    }

    #[test]
    fn digit_heavy_low_vowel_domain_scores_high() {
        // A synthetic "genuine DGA input" shape per the acceptance gate: dense digits,
        // sparse vowels, no recognizable word structure.
        let s = Scorer::load_seed().unwrap();
        let out = s.score("xkj4q9zvw2fh7bqm1.example");
        assert!(
            out.p_dga > 0.5,
            "expected a digit-heavy/low-vowel domain to score > 0.5 (AMBER-driving), got {}",
            out.p_dga
        );
    }

    #[test]
    fn dga_shaped_domain_scores_above_benign() {
        let s = Scorer::load_seed().unwrap();
        let benign = s.score("google.com");
        let dga = s.score("xkj4q9zvw2fh7bqm1.example");
        assert!(dga.p_dga > benign.p_dga, "dga={} should exceed benign={}", dga.p_dga, benign.p_dga);
    }

    #[test]
    fn softmax_sums_to_one_complement() {
        // p_dga + p_benign should always be 1.0 by construction (2-class softmax).
        let (p_dga, p_benign) = (softmax_p1(3, 7), softmax_p1(7, 3));
        assert!((p_dga - (1.0 - p_benign)).abs() < 1e-12);
    }

    #[test]
    fn score_carries_model_id() {
        let s = Scorer::load_seed().unwrap();
        let out = s.score("example.com");
        assert_eq!(out.model_id, MODEL_ID);
    }

    #[test]
    fn empty_and_pathological_inputs_never_panic() {
        let s = Scorer::load_seed().unwrap();
        for d in ["", ".", "-", "...", &"9".repeat(500), "\u{1F600}.com"] {
            let _ = s.score(d);
        }
    }

    // ── QSECBIT connector (`p_attack_for_qsecbit`) ───────────────────────────────

    /// The core ADR 0014 D6 gate: when `ml_cpu` is NOT granted, `p_attack` must stay
    /// `0.0` no matter how confidently malicious `p_dga` is — "scoped, not global."
    #[test]
    fn ungranted_ml_cpu_always_yields_zero_p_attack() {
        for p_dga in [0.0, 0.5, 0.83, 1.0] {
            assert_eq!(
                p_attack_for_qsecbit(p_dga, false),
                0.0,
                "ml_cpu not granted must force p_attack=0.0 regardless of p_dga={p_dga}"
            );
        }
    }

    /// When granted, a well-formed `p_dga` in `[0,1]` passes through unchanged.
    #[test]
    fn granted_ml_cpu_passes_through_p_dga() {
        assert_eq!(p_attack_for_qsecbit(0.0, true), 0.0);
        assert_eq!(p_attack_for_qsecbit(0.83, true), 0.83);
        assert_eq!(p_attack_for_qsecbit(1.0, true), 1.0);
    }

    /// Defensive clamping at the trust boundary: out-of-range or NaN input never
    /// escapes as an out-of-range or NaN `p_attack`, even though `Scorer::score`'s
    /// softmax should never itself produce one.
    #[test]
    fn granted_ml_cpu_clamps_out_of_range_and_nan_input() {
        assert_eq!(p_attack_for_qsecbit(1.5, true), 1.0);
        assert_eq!(p_attack_for_qsecbit(-0.2, true), 0.0);
        assert_eq!(p_attack_for_qsecbit(f64::NAN, true), 0.0);
    }

    /// End-to-end: a genuinely DGA-shaped domain, scored by the real seed model, maps
    /// to a high `p_attack` when granted and to exactly `0.0` when not — proving the
    /// full `domain -> Scorer::score -> p_attack_for_qsecbit` path, not just the
    /// connector in isolation.
    #[test]
    fn dga_domain_end_to_end_drives_p_attack_only_when_granted() {
        let s = Scorer::load_seed().unwrap();
        let out = s.score("xkj4q9zvw2fh7bqm1.example");
        assert!(out.p_dga > 0.5, "fixture domain must score as DGA-shaped; got {}", out.p_dga);

        let granted = p_attack_for_qsecbit(out.p_dga, true);
        assert_eq!(granted, out.p_dga.clamp(0.0, 1.0));
        assert!(granted > 0.5, "granted p_attack must carry the DGA signal through");

        let ungranted = p_attack_for_qsecbit(out.p_dga, false);
        assert_eq!(ungranted, 0.0, "ungranted p_attack must stay neutral even for a confirmed-DGA-shaped domain");
    }

    /// A benign domain's low `p_dga` still passes through when granted — the gate is
    /// on capability, not on score magnitude.
    #[test]
    fn benign_domain_end_to_end_p_attack_stays_low_when_granted() {
        let s = Scorer::load_seed().unwrap();
        let out = s.score("google.com");
        let granted = p_attack_for_qsecbit(out.p_dga, true);
        assert_eq!(granted, out.p_dga.clamp(0.0, 1.0));
        assert!(granted < 0.5, "benign domain must not spuriously drive p_attack high");
    }
}
