//! # Tabular-ML detection seam (roadmap C) over NAPSE's 16-D entity feature vector.
//!
//! This is the generic model seam the 2026-07 audit found missing (GAP-1) plus a real
//! SEED implementation over `EntityState::feature_vector()` (GAP-3) — a small logistic
//! model, not a fabricated trained detector. It mirrors `modules/dga-lm`'s honesty
//! contract EXACTLY (see `dga-lm/src/model.rs:26-28` and `dga-lm/model/MODEL_CARD.md`):
//!
//! **This is honestly a SEED/BASELINE model, not a validated attack classifier.** The
//! weight vector below is hand-derived from the same domain intuition that already backs
//! `EntityState::heuristic_deviation()` (port entropy, connection rate, alert count) plus
//! a few more of the 16 already-computed features (failed connections, DNS volume, byte
//! ratio, port-scan indicator). Real training is off-device, per ADR 0014's precedent for
//! `dga-lm`; see `modules/napse/MODEL_CARD-tabular.md` for the full model card. It exists
//! to exercise the full model-seam + capability-gate + QSECBIT-connector path end to end
//! on real, already-live features — not to claim state-of-the-art detection accuracy.
//!
//! ## C9 — advisory / observe-only
//!
//! Like `dga-lm::p_attack_for_qsecbit`, [`p_attack_for_qsecbit`]'s output only ever feeds
//! a displayed composite score (QSECBIT's `p_attack` term, itself one of four heuristic
//! inputs to a risk SCORE — ADR 0023) or the HMM's `deviation` input inside NAPSE's own
//! non-enforcing signal-fusion step ([`gated_deviation`], consumed by `viterbi_step` via
//! `EntityState::deviation`). Neither is ever in the ADR 0023 `decide()` enforcement path.

/// A generic tabular-ML scorer over NAPSE's 16-D entity feature vector
/// (`EntityState::feature_vector()`, layout documented at `lib.rs:568-586`).
///
/// This is the reusable seam (audit GAP-1): any scorer — the seed logistic model below,
/// or a future WASI-NN-backed model sharing the same 16-D input contract — can implement
/// this trait and be dropped into [`crate::NapseSynthesizer`] without touching the ingest
/// pipeline.
pub trait TabularScorer {
    /// Score a 16-D feature vector, returning an attack probability in `[0.0, 1.0]`.
    /// Must be deterministic and must never panic, including on non-finite input.
    fn score(&self, features: &[f64; 16]) -> f64;

    /// Model identity string (e.g. `"napse-tabular-seed-v0.1"`), surfaced downstream so
    /// an operator/QSECBIT breakdown panel can always tell which model produced a number
    /// — mirrors `dga_lm::DgaScore::model_id`.
    fn model_id(&self) -> &str;
}

/// Model identity string. Bump whenever `SEED_WEIGHTS`/`SEED_BIAS` change value or shape.
pub const MODEL_ID: &str = "napse-tabular-seed-v0.1";

/// Hand-derived SEED weights, one per `feature_vector()` index (`lib.rs:568-586`).
///
/// **Directional intuition (see `MODEL_CARD-tabular.md` for the full rationale):**
/// - Indices 2/3 (`n_protocols`/`n_services`) are always `1.0` in the current feature
///   vector (no signal yet) — weight `0.0`, kept explicit rather than omitted so this
///   array's shape always matches `feature_vector()`'s 16 slots one-for-one.
/// - Port entropy (9), port-scan indicator (13), and unique dest ports (0) carry the
///   heaviest positive weight — direct scanning signals.
/// - Alert count (7) / has_alerts (12) carry heavy positive weight — an entity that
///   already tripped a signature rule is disproportionately likely to be genuinely bad.
/// - Failed connections (6) and connection rate (14) are brute-force / automated-tool
///   signals — matches `heuristic_deviation()`'s own weighting intent.
/// - Bytes received (11) and hours active (15) carry small NEGATIVE weight — a
///   long-lived, mostly-inbound entity (e.g. a server being talked to normally) trends
///   more benign than a fresh, bursty, mostly-outbound one.
const SEED_WEIGHTS: [f64; 16] = [
    1.0,  // 0  n_unique_dst_ports
    0.5,  // 1  n_unique_dst_ips
    0.0,  // 2  n_unique_protocols (constant 1.0 today — no signal)
    0.0,  // 3  n_unique_services  (constant 1.0 today — no signal)
    0.4,  // 4  bytes_sent / bytes_received ratio (log-compressed)
    0.5,  // 5  dns_query_count
    0.9,  // 6  failed_conn_count
    1.2,  // 7  alert_count
    0.6,  // 8  event_rate
    1.0,  // 9  port_entropy
    0.3,  // 10 MB sent
    -0.1, // 11 MB received
    0.8,  // 12 has_alerts
    1.0,  // 13 port_scan_indicator
    0.9,  // 14 connection_rate
    -0.3, // 15 hours_active
];

/// Seed bias — chosen so an all-quiet entity (near-zero normalized features) scores well
/// under 0.5 (see `MODEL_CARD-tabular.md`'s worked example).
const SEED_BIAS: f64 = -2.6;

/// Per-feature normalization caps, chosen to align with rule thresholds already used
/// elsewhere in this module (port-scan rule 1000003's 50-port threshold, DNS-tunneling
/// rule 1000002's 100-query threshold, `heuristic_deviation()`'s own `/10.0`/`/5.0`
/// divisors for port entropy / alert count) rather than invented numbers — see
/// `MODEL_CARD-tabular.md`.
fn normalize(f: &[f64; 16]) -> [f64; 16] {
    [
        (f[0] / 50.0).clamp(0.0, 1.0),
        (f[1] / 50.0).clamp(0.0, 1.0),
        0.0,
        0.0,
        (f[4].max(0.0).ln_1p() / 10.0).clamp(0.0, 1.0),
        (f[5] / 100.0).clamp(0.0, 1.0),
        (f[6] / 20.0).clamp(0.0, 1.0),
        (f[7] / 5.0).clamp(0.0, 1.0),
        (f[8] / 20.0).clamp(0.0, 1.0),
        (f[9] / 10.0).clamp(0.0, 1.0),
        (f[10] / 1000.0).clamp(0.0, 1.0),
        (f[11] / 1000.0).clamp(0.0, 1.0),
        f[12].clamp(0.0, 1.0),
        f[13].clamp(0.0, 1.0),
        (f[14] / 10.0).clamp(0.0, 1.0),
        (f[15] / 24.0).clamp(0.0, 1.0),
    ]
}

/// Numerically-safe sigmoid. Returns `0.0` (neutral) instead of `NaN`/panicking on
/// non-finite input — the same fail-closed-to-neutral posture `dga_lm`/`qsecbit` already
/// use for malformed upstream scores.
fn sigmoid(z: f64) -> f64 {
    if !z.is_finite() {
        return 0.0;
    }
    // Clamp before exponentiating — defensive against a pathological weight/feature
    // product that is finite but enormous; `exp()` of anything past ~700 already
    // overflows f64, this keeps well inside safe range without changing the result for
    // any realistic input (real z values here live in roughly [-10, 10]).
    let z = z.clamp(-50.0, 50.0);
    1.0 / (1.0 + (-z).exp())
}

/// The seed logistic-regression scorer. Real forward pass, real normalization, real
/// sigmoid — deterministic and `#![forbid(unsafe_code)]`-compatible (pure `f64` math,
/// no allocation, no I/O). See the module-level doc for the honesty contract.
pub struct SeedLogisticScorer {
    weights: [f64; 16],
    bias: f64,
}

impl SeedLogisticScorer {
    /// Load the embedded seed weights. Infallible (no I/O, no parsing) — kept as an
    /// associated function (not a `Default`-only type) so a future runtime-supplied
    /// weight set can reuse this exact call shape (mirrors `dga_lm::Scorer::load_seed`).
    pub fn new() -> Self {
        Self { weights: SEED_WEIGHTS, bias: SEED_BIAS }
    }
}

impl Default for SeedLogisticScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl TabularScorer for SeedLogisticScorer {
    fn score(&self, features: &[f64; 16]) -> f64 {
        let n = normalize(features);
        let z = self
            .weights
            .iter()
            .zip(n.iter())
            .fold(self.bias, |acc, (w, x)| acc + w * x);
        sigmoid(z)
    }

    fn model_id(&self) -> &str {
        MODEL_ID
    }
}

// ─── Capability gate + QSECBIT connector (mirrors dga_lm::p_attack_for_qsecbit) ───────

/// Gate the tabular model's deviation signal on the `ml_cpu` capability, falling back to
/// the existing [`crate::EntityState::heuristic_deviation`] when NOT granted — this is
/// the internal HMM-facing gate (`viterbi_step`'s `deviation` input must always get a
/// value, so the fallback is the heuristic, not neutral `0.0`; contrast with
/// [`p_attack_for_qsecbit`] below, whose contract IS "stay `0.0` when ungranted").
///
/// - `model_p`: the tabular scorer's raw output for this entity.
/// - `heuristic`: `EntityState::heuristic_deviation()` for the same entity — the
///   ungated fallback, unconditionally still computed by the caller (never removed).
/// - `ml_cpu_granted`: read once from the signed Platform Manifest by the caller; this
///   function never reads the manifest itself (same pure/testable shape as
///   `dga_lm::p_attack_for_qsecbit`).
pub fn gated_deviation(model_p: f64, heuristic: f64, ml_cpu_granted: bool) -> f64 {
    if !ml_cpu_granted {
        return heuristic;
    }
    if model_p.is_nan() {
        return heuristic; // fail safe to the heuristic on a malformed model output
    }
    model_p.clamp(0.0, 1.0)
}

/// Map the tabular model's output to the value that should populate QSECBIT's
/// `p_attack` input (`modules/qsecbit/src/main.rs`'s optional 5th CSV field) —
/// mirrors `dga_lm::p_attack_for_qsecbit` field-for-field, including its NaN handling.
///
/// - When `ml_cpu_granted` is `true`: returns `model_p` clamped to `[0.0, 1.0]`.
/// - When `ml_cpu_granted` is `false`: always returns `0.0` — the ADR 0014 D6
///   "scoped, not global" rule, applied identically here.
pub fn p_attack_for_qsecbit(model_p: f64, ml_cpu_granted: bool) -> f64 {
    if !ml_cpu_granted {
        return 0.0;
    }
    if model_p.is_nan() {
        return 0.0;
    }
    model_p.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zeros() -> [f64; 16] {
        [0.0; 16]
    }

    // ── SeedLogisticScorer: bounds, determinism, panic-safety ────────────────────

    #[test]
    fn score_is_always_in_unit_interval() {
        let s = SeedLogisticScorer::new();
        let cases: [[f64; 16]; 4] = [
            zeros(),
            [1.0; 16],
            [1_000_000.0; 16],
            [-1_000_000.0; 16],
        ];
        for f in cases {
            let p = s.score(&f);
            assert!((0.0..=1.0).contains(&p), "p_attack={p} out of [0,1] for {f:?}");
        }
    }

    #[test]
    fn score_is_deterministic() {
        let s = SeedLogisticScorer::new();
        let f = [3.0, 2.0, 1.0, 1.0, 4.0, 10.0, 5.0, 2.0, 6.0, 4.5, 12.0, 3.0, 1.0, 0.6, 3.0, 0.5];
        assert_eq!(s.score(&f), s.score(&f));
    }

    #[test]
    fn quiet_entity_scores_low() {
        let s = SeedLogisticScorer::new();
        // Near-silent entity: one port, one dest, no failures/alerts/dns.
        let f = [1.0, 1.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.01, 0.0, 0.01, 0.01, 0.0, 0.01, 0.01, 0.1];
        let p = s.score(&f);
        assert!(p < 0.3, "quiet entity should score low, got {p}");
    }

    #[test]
    fn high_threat_entity_scores_high() {
        let s = SeedLogisticScorer::new();
        // Saturated scan-shaped entity: wide port spread, high entropy, many failed
        // conns, prior alerts, high rate, fresh burst (low hours_active).
        let f = [
            80.0, // dst ports (> 50 rule threshold)
            40.0, // dst ips
            1.0, 1.0,
            3.0,   // byte ratio (more sent than received)
            50.0,  // dns queries
            18.0,  // failed conns
            4.0,   // alert count
            15.0,  // event rate
            6.5,   // port entropy (log2(90)~6.5)
            50.0,  // MB sent
            0.0,   // MB received
            1.0,   // has_alerts
            0.8,   // port_scan_indicator
            9.0,   // connection_rate
            0.05,  // hours_active (fresh)
        ];
        let p = s.score(&f);
        assert!(p > 0.85, "high-threat entity should score high, got {p}");
    }

    #[test]
    fn high_threat_scores_above_quiet() {
        let s = SeedLogisticScorer::new();
        let quiet = [1.0, 1.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.01, 0.0, 0.01, 0.01, 0.0, 0.01, 0.01, 0.1];
        let loud = [80.0, 40.0, 1.0, 1.0, 3.0, 50.0, 18.0, 4.0, 15.0, 6.5, 50.0, 0.0, 1.0, 0.8, 9.0, 0.05];
        assert!(s.score(&loud) > s.score(&quiet));
    }

    /// Direction check requested by the spec: high port-entropy + high failed-conn +
    /// high connection-rate must each independently push p_attack up (monotonicity).
    #[test]
    fn increasing_port_entropy_increases_score() {
        let s = SeedLogisticScorer::new();
        let mut low = [2.0, 2.0, 1.0, 1.0, 1.0, 0.0, 1.0, 0.0, 1.0, 1.0, 1.0, 1.0, 0.0, 0.1, 1.0, 1.0];
        let mut high = low;
        low[9] = 1.0;
        high[9] = 8.0;
        assert!(s.score(&high) > s.score(&low), "higher port_entropy must increase p_attack");
    }

    #[test]
    fn increasing_failed_conn_count_increases_score() {
        let s = SeedLogisticScorer::new();
        let low = [2.0, 2.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 0.0, 0.1, 1.0, 1.0];
        let mut high = low;
        high[6] = 15.0;
        assert!(s.score(&high) > s.score(&low), "higher failed_conn_count must increase p_attack");
    }

    #[test]
    fn increasing_connection_rate_increases_score() {
        let s = SeedLogisticScorer::new();
        let low = [2.0, 2.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 0.0, 0.1, 1.0, 1.0];
        let mut high = low;
        high[14] = 9.0;
        assert!(s.score(&high) > s.score(&low), "higher connection_rate must increase p_attack");
    }

    #[test]
    fn model_id_is_stable() {
        let s = SeedLogisticScorer::new();
        assert_eq!(s.model_id(), MODEL_ID);
        assert_eq!(s.model_id(), "napse-tabular-seed-v0.1");
    }

    /// Panic-safety: NaN/Infinity/extreme values anywhere in the vector must never panic
    /// and must always yield a finite `[0,1]` score.
    #[test]
    fn extreme_and_nan_inputs_never_panic() {
        let s = SeedLogisticScorer::new();
        let cases: Vec<[f64; 16]> = vec![
            [f64::NAN; 16],
            [f64::INFINITY; 16],
            [f64::NEG_INFINITY; 16],
            [f64::MAX; 16],
            [f64::MIN; 16],
            {
                let mut f = zeros();
                f[9] = f64::NAN;
                f
            },
            {
                let mut f = zeros();
                f[7] = f64::INFINITY;
                f
            },
        ];
        for f in cases {
            let p = s.score(&f);
            assert!(p.is_finite(), "score must be finite for {f:?}, got {p}");
            assert!((0.0..=1.0).contains(&p), "score must stay in [0,1] for {f:?}, got {p}");
        }
    }

    // ── Capability gate: gated_deviation ──────────────────────────────────────────

    #[test]
    fn gated_deviation_ungranted_falls_back_to_heuristic() {
        for model_p in [0.0, 0.42, 0.99] {
            assert_eq!(gated_deviation(model_p, 0.33, false), 0.33);
        }
    }

    #[test]
    fn gated_deviation_granted_uses_model_output() {
        assert_eq!(gated_deviation(0.0, 0.9, true), 0.0);
        assert_eq!(gated_deviation(0.75, 0.1, true), 0.75);
        assert_eq!(gated_deviation(1.0, 0.0, true), 1.0);
    }

    #[test]
    fn gated_deviation_granted_but_nan_model_falls_back_to_heuristic() {
        assert_eq!(gated_deviation(f64::NAN, 0.55, true), 0.55);
    }

    #[test]
    fn gated_deviation_granted_clamps_out_of_range() {
        assert_eq!(gated_deviation(1.7, 0.2, true), 1.0);
        assert_eq!(gated_deviation(-0.3, 0.2, true), 0.0);
    }

    // ── Capability gate: p_attack_for_qsecbit (dga_lm-parity contract) ────────────

    #[test]
    fn p_attack_ungranted_always_zero() {
        for model_p in [0.0, 0.5, 0.83, 1.0] {
            assert_eq!(p_attack_for_qsecbit(model_p, false), 0.0);
        }
    }

    #[test]
    fn p_attack_granted_passes_through() {
        assert_eq!(p_attack_for_qsecbit(0.0, true), 0.0);
        assert_eq!(p_attack_for_qsecbit(0.83, true), 0.83);
        assert_eq!(p_attack_for_qsecbit(1.0, true), 1.0);
    }

    #[test]
    fn p_attack_granted_clamps_and_rejects_nan() {
        assert_eq!(p_attack_for_qsecbit(1.5, true), 1.0);
        assert_eq!(p_attack_for_qsecbit(-0.2, true), 0.0);
        assert_eq!(p_attack_for_qsecbit(f64::NAN, true), 0.0);
    }

    /// End-to-end: a genuinely high-threat feature vector, scored by the real seed
    /// model, drives `p_attack` high enough (mirrors
    /// `qsecbit::tests::red_reachable_with_ml_p_attack`'s intent — QSECBIT's
    /// `beta=0.30` weight on `p_attack`, combined with a comparably elevated drift/qdrift,
    /// is enough to cross the RED threshold) when granted, and to exactly `0.0` when not.
    #[test]
    fn high_threat_vector_end_to_end_drives_p_attack_only_when_granted() {
        let s = SeedLogisticScorer::new();
        let f = [80.0, 40.0, 1.0, 1.0, 3.0, 50.0, 18.0, 4.0, 15.0, 6.5, 50.0, 0.0, 1.0, 0.8, 9.0, 0.05];
        let model_p = s.score(&f);
        assert!(model_p > 0.85, "fixture must be high-threat-shaped; got {model_p}");

        let granted = p_attack_for_qsecbit(model_p, true);
        assert_eq!(granted, model_p.clamp(0.0, 1.0));
        assert!(granted > 0.85, "granted p_attack must carry the high-threat signal through");

        let ungranted = p_attack_for_qsecbit(model_p, false);
        assert_eq!(ungranted, 0.0, "ungranted p_attack must stay neutral even for a high-threat vector");
    }
}
