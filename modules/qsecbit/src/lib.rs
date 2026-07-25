//! # QSECBIT — Composite Cyber-Resilience Scorer
//!
//! A pure-Rust port of V1 `core/qsecbit/qsecbit.py` — the composite
//! cyber-resilience score that underpins the **Organism Status** orb in
//! Mission Control (see `docs/MissionControl.md`).
//!
//! ## What V1 QSECBIT computed
//!
//! V1 combined four signals into a single risk score R ∈ \[0, 1\]:
//!
//! ```text
//! R = α·drift + β·p_attack + γ·decay + δ·qdrift
//! ```
//!
//! | Component | Symbol | Weight | V1 source |
//! |---|---|---|---|
//! | **Mahalanobis drift** | `drift` | α = 0.30 | `Qsecbit._drift()` |
//! | **ML attack probability** | `p_attack` | β = 0.30 | `AttackClassifier` (Random Forest / VAE) |
//! | **Classifier confidence decay** | `decay` | γ = 0.20 | `Qsecbit._classifier_decay()` |
//! | **Entropy deviation (quantum drift)** | `qdrift` | δ = 0.20 | `Qsecbit._quantum_drift()` |
//!
//! **Score bands (same as V1 `QsecbitConfig`):**
//! - `GREEN`  : R < 0.45 — healthy / protected
//! - `AMBER`  : 0.45 ≤ R < 0.70 — at-risk
//! - `RED`    : R ≥ 0.70 — critical
//!
//! **Inputs (4-element telemetry vector):** `[cpu_norm, memory_norm, network_norm, disk_io_norm]`
//! each normalized to \[0, 1\] (e.g. 0.80 = 80 % utilization).
//!
//! ## V2 approach — deterministic first cut, WASI-NN upgrade path
//!
//! This crate is **pure-Rust deterministic math** — no model file, no inference
//! runtime dependency. It compiles to a small Wasm binary and is exactly faithful
//! to V1's Mahalanobis + entropy math.
//!
//! **This is honestly heuristic, not ML.** Two components are stubs:
//! - `p_attack` defaults to `0.0` (neutral) — see `TODO(wasi-nn)` below.
//! - `decay` requires the caller to pass a previous confidence vector; without
//!   it (first tick or stateless call) it is `0.0`.
//!
//! Without the ML component, the effective scoring formula is:
//! ```text
//! R ≈ 0.30·drift + 0.20·qdrift   (max R ≈ 0.50 = AMBER ceiling)
//! ```
//! This is sufficient to detect severe Mahalanobis outliers (AMBER) and gives
//! a truthful GREEN for normal telemetry, but **cannot reach RED without the
//! ML component**. The band commentary in each output documents this.
//!
//! ## Update (2026-07-15, ADR 0014 D6 / base-tier Phase 4): `p_attack` has a CPU-native source
//!
//! `modules/dga-lm` (a signed int8 char-level DGA classifier Wasm module) now produces a
//! DGA probability on the plain CPU — no NPU, no WASI-NN — on any device that grants the
//! `ml_cpu` capability (A76 tier via the relaxed-dot/`SDOT` path; A72 via the portable-SIMD
//! fallback, budget-gated per ADR 0014 D6). Its `p_dga` is the intended feed for the
//! `p_attack` component below, lifting the achievable score past the ~0.50 AMBER ceiling on
//! the flagship. `dga-lm` is advisory/observe-only (C9) — it never enters the enforcement
//! path. **OPEN GAP:** the live pipeline that assembles a [`QsecbitInput`] from telemetry and
//! injects dga-lm's `p_dga` as `p_attack` is not yet wired (qsecbit is fed via the streaming
//! wasm path today with `p_attack: 0.0`); this is the remaining Phase-4 integration item. The
//! generic WASI-NN path below stays as the accelerator-tier alternative (`edge_ai`), never a
//! precondition for the CPU path.
//!
//! ## TODO(wasi-nn): Upgrade to a trained model
//!
//! Export V1's `ml/classifier.py` (Random Forest → ONNX) or `ml/vae_anomaly.py`
//! (VAE → ONNX), then load via WASI-NN:
//!
//! ```ignore
//! // WASI-NN upgrade path — runs when `edge_ai` capability is granted.
//! //
//! // V1 NetworkFeatures has 50+ fields; the minimal 8-float subset (packets/sec,
//! // bytes/sec, tcp_ratio, udp_ratio, icmp_ratio, syn_ratio, fin_ratio,
//! // unique_dst_ports) already covers the main classifier signals.
//! //
//! // Feature vector layout (must match V1 classifier input):
//! // [cpu_norm, memory_norm, network_norm, disk_io_norm,
//! //  packets_per_second_norm, bytes_per_second_norm,
//! //  tcp_ratio, udp_ratio, icmp_ratio, syn_flag_ratio, ... ]
//! //
//! // use wasi_nn::{GraphBuilder, GraphEncoding, ExecutionTarget};
//! // let graph = GraphBuilder::new(GraphEncoding::Onnx, ExecutionTarget::CPU)
//! //     .build_from_bytes([&model_bytes])
//! //     .expect("load ONNX model");
//! // let ctx = graph.init_execution_context().expect("init ctx");
//! // ctx.set_input(0, wasi_nn::TensorType::F32, &[1, N_FEATURES], &feature_vec)?;
//! // ctx.compute()?;
//! // let mut logits = vec![0f32; N_CLASSES];
//! // ctx.get_output(0, &mut logits)?;
//! // // logits[1] (or the attack-class index) → p_attack in [0, 1]
//! ```
//!
//! Until then, pass `p_attack: 0.0` in [`QsecbitInput`] and accept that the
//! maximum achievable score is ≈ 0.50 (AMBER), not 1.0 (RED).
//!
//! ## Note (2026-07-05, ADR 0020 Phase-1a) — crypto-boundary-under-L2-instability is a deferred
//! ## validation concern, not something this crate probes
//! The operator asked whether this device's crypto boundaries (module signing verification, the
//! hybrid ML-DSA-65 + Ed25519 posture, ADR 0002) hold up while the link layer is under stress
//! (mac-flood / ARP-storm / broadcast-storm conditions — see
//! `hookprobe_manifest::l2_responder`/`napse_loader::l2guard`, ADR 0020's DEFENSIVE Phase-1a). That
//! is a legitimate question, but it is a **live-attack VALIDATION concern for the ROE-gated,
//! offensive adversarial-resilience harness** (ADR 0020 Phase-1b — `security/redteam/`, which does
//! not exist yet and is gated on the six threat-model conditions landing first), not something
//! this deterministic scorer builds a probe for. This crate only ever CONSUMES a resilience-
//! evidence input from a completed `attack_run` (ADR 0020 D7 — "never attacked" must read as
//! unknown, never as 1.0/perfectly-resilient) — it does not generate load, send traffic, or run
//! any offensive code itself. Recorded here so the concern isn't lost, not actioned.

#![forbid(unsafe_code)]

// ─── Baseline constants (from V1 demo / reference calibration) ───────────────

/// Baseline telemetry mean vector: \[cpu_norm, memory_norm, network_norm, disk_io_norm\].
///
/// Source: V1 `qsecbit.py` demo: `mu = np.array([0.1, 0.2, 0.15, 0.33])`.
/// Represents a lightly loaded node under normal operation.
pub const BASELINE_MU: [f64; 4] = [0.10, 0.20, 0.15, 0.33];

/// Inverse of the baseline covariance matrix (row-major, 4×4).
///
/// V1 uses a diagonal covariance `cov = I × 0.02` (σ² = 0.02 per dimension),
/// giving `inv_cov = I × 50.0`. This models tight clustering in normal operation
/// (±≈0.14 per dimension at 1σ). A non-diagonal `inv_cov` can be substituted
/// for correlated telemetry (e.g. CPU and memory tend to co-spike).
pub const BASELINE_INV_COV: [[f64; 4]; 4] = [
    [50.0, 0.0, 0.0, 0.0],
    [0.0, 50.0, 0.0, 0.0],
    [0.0, 0.0, 50.0, 0.0],
    [0.0, 0.0, 0.0, 50.0],
];

/// Baseline Shannon entropy of the normalized telemetry mean vector (nats).
///
/// Computed from `BASELINE_MU = [0.10, 0.20, 0.15, 0.33]`:
///   `probs = mu / sum(mu) = [0.1282, 0.2564, 0.1923, 0.4231]`
///   `H = -Σ p·ln(p) ≈ 1.293 nats`
///
/// **Calibration note:** V1's `quantum_anchor = 6.144` was computed from a
/// full augmented system vector (per-core CPU, memory details, network bytes)
/// with many more features. This value is recalibrated to the 4-element
/// portable WASI input contract.
pub const BASELINE_Q_ANCHOR: f64 = 1.293;

// ─── Score configuration ──────────────────────────────────────────────────────

/// Configuration parameters for the QSECBIT score computation.
///
/// All defaults reproduce V1 `QsecbitConfig` exactly.
#[derive(Debug, Clone)]
pub struct QsecbitConfig {
    // Component weights — must sum to 1.0 when ML is active (β × 0.0 = 0.0 today).
    /// Mahalanobis drift weight. V1 default: 0.30.
    pub alpha: f64,
    /// ML attack probability weight. V1 default: 0.30 (stub: β × 0.0 = 0.0).
    pub beta: f64,
    /// Classifier confidence decay weight. V1 default: 0.20.
    pub gamma: f64,
    /// Entropy (quantum drift) weight. V1 default: 0.20.
    pub delta: f64,

    /// Logistic slope `k` in `logistic(k·(d − θ))`. V1 default: 3.5.
    pub drift_slope: f64,
    /// Logistic center `θ`. V1 default: 2.0.
    /// At d=2.0 (two standard deviations from baseline), `drift` = 0.50.
    pub drift_center: f64,

    /// Baseline system entropy in nats. V1 calibrated via `_calculate_baseline_entropy()`.
    pub q_anchor: f64,
    /// Critical entropy deviation; deviations ≥ this → `qdrift` = 1.0.
    /// V1 default: 0.25.
    pub q_crit: f64,

    /// Critical classifier-confidence drift rate; rates ≥ this → `decay` = 1.0.
    /// V1 default: 0.15.
    pub lambda_crit: f64,

    /// AMBER threshold. V1 default: 0.45.
    pub amber_threshold: f64,
    /// RED threshold. V1 default: 0.70.
    pub red_threshold: f64,
}

impl Default for QsecbitConfig {
    fn default() -> Self {
        Self {
            alpha: 0.30,
            beta: 0.30,
            gamma: 0.20,
            delta: 0.20,
            drift_slope: 3.5,
            drift_center: 2.0,
            q_anchor: BASELINE_Q_ANCHOR,
            q_crit: 0.25,
            lambda_crit: 0.15,
            amber_threshold: 0.45,
            red_threshold: 0.70,
        }
    }
}

// ─── Public types ─────────────────────────────────────────────────────────────

/// RAG (Red / Amber / Green) status band.
///
/// Matches V1 `_classify_rag()` thresholds (AMBER ≥ 0.45, RED ≥ 0.70).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Band {
    /// R < 0.45 — healthy / protected.
    Green,
    /// 0.45 ≤ R < 0.70 — at-risk.
    Amber,
    /// R ≥ 0.70 — critical.
    Red,
}

impl Band {
    pub fn as_str(&self) -> &'static str {
        match self {
            Band::Green => "GREEN",
            Band::Amber => "AMBER",
            Band::Red => "RED",
        }
    }
}

/// Input to the QSECBIT scorer: one telemetry tick.
///
/// All normalized fields are expected in `[0.0, 1.0]`.
#[derive(Debug, Clone)]
pub struct QsecbitInput {
    // ── 4-element system telemetry vector (feeds Mahalanobis + entropy) ──────
    /// CPU utilization, normalized: 0.0 = idle, 1.0 = fully saturated.
    pub cpu_norm: f64,
    /// Memory utilization, normalized: 0.0 = free, 1.0 = fully consumed.
    pub memory_norm: f64,
    /// Network I/O throughput, normalized to device max (bytes/sec or pps).
    pub network_norm: f64,
    /// Disk I/O, normalized to device max (IOPS or bytes/sec).
    pub disk_io_norm: f64,

    // ── ML attack probability (β component) ──────────────────────────────────
    /// Attack probability from the ML classifier, in `[0.0, 1.0]`.
    ///
    /// **TODO(wasi-nn):** supply the output of the ONNX model loaded via WASI-NN.
    /// Set to `0.0` (neutral) until the model is available — see module docs.
    pub p_attack: f64,

    // ── Classifier confidence decay (γ component) ─────────────────────────────
    /// Current classifier confidence vector.
    ///
    /// Pass the softmax output of the attack classifier (any length).
    /// Without a model, pass an empty slice → `decay` = 0.0.
    pub classifier_confidence: Vec<f64>,
    /// Previous tick's confidence vector (for decay rate computation).
    ///
    /// Pass the `classifier_confidence` from the preceding call.
    /// If `None` (first tick or stateless caller), `decay` = 0.0.
    pub prev_classifier_confidence: Option<Vec<f64>>,
    /// Time elapsed since the previous tick (seconds). Default: 1.0.
    pub dt: f64,
}

impl QsecbitInput {
    /// Convenience constructor for the common 4-value case (no ML, stateless).
    ///
    /// Sets `p_attack = 0.0`, `decay = 0.0`, `dt = 1.0`.
    pub fn from_telemetry(cpu: f64, memory: f64, network: f64, disk_io: f64) -> Self {
        Self {
            cpu_norm: cpu,
            memory_norm: memory,
            network_norm: network,
            disk_io_norm: disk_io,
            p_attack: 0.0,
            classifier_confidence: Vec::new(),
            prev_classifier_confidence: None,
            dt: 1.0,
        }
    }

    /// Return the telemetry as a 4-element array for math operations.
    pub fn telemetry_array(&self) -> [f64; 4] {
        [self.cpu_norm, self.memory_norm, self.network_norm, self.disk_io_norm]
    }
}

/// Per-component score breakdown exposed by [`compute`].
///
/// Mirrors V1 `QsecbitSample.components` plus the raw helper values needed
/// for the Mission Control "QSecBit breakdown" panel.
#[derive(Debug, Clone)]
pub struct QsecbitBreakdown {
    /// Normalized Mahalanobis drift in `[0, 1]`.
    /// Source: `logistic(slope·(d − center))`. Increases as the telemetry
    /// vector moves away from the baseline cluster.
    pub mahalanobis_drift: f64,

    /// Normalized entropy deviation (quantum drift) in `[0, 1]`.
    /// Source: `min(1, |H(x) − q_anchor| / q_crit)`.
    pub entropy_deviation: f64,

    /// ML attack probability in `[0, 1]`. **Stub: always 0.0 until WASI-NN.**
    ///
    /// TODO(wasi-nn): replace with the ONNX-model output; see module docs.
    pub attack_probability: f64,

    /// Classifier confidence decay rate in `[0, 1]`.
    /// `0.0` when no previous confidence vector is available (first tick).
    pub classifier_decay: f64,

    // ── Raw values (display / debug) ─────────────────────────────────────────
    /// Raw Mahalanobis distance (before logistic normalization).
    /// At the `drift_center` (default 2.0), `mahalanobis_drift` = 0.50.
    pub raw_mahalanobis_distance: f64,

    /// Shannon entropy of the telemetry vector (nats, natural log).
    /// `q_anchor` is subtracted to produce `entropy_deviation`.
    pub telemetry_entropy_nats: f64,
}

/// Full result returned by [`compute`].
#[derive(Debug, Clone)]
pub struct QsecbitOutput {
    /// Composite risk score R ∈ `[0.0, 1.0]`. **Lower = healthier.**
    ///
    /// Mission Control displays this with the RAG band (GREEN = protected).
    /// A resilience percentage can be derived as `(1.0 − score) * 100.0`.
    pub score: f64,

    /// RAG status band derived from `score` and configured thresholds.
    pub band: Band,

    /// Per-component scores for the Mission Control "QSecBit breakdown" panel.
    pub breakdown: QsecbitBreakdown,
}

// ─── Math primitives (public for unit tests) ──────────────────────────────────

/// Mahalanobis distance between `x` and `mu` given the inverse covariance.
///
/// Formula: `d = sqrt((x − μ)ᵀ · Σ⁻¹ · (x − μ))`.
///
/// Mirrors V1 `scipy.spatial.distance.mahalanobis(u, v, VI)`.
/// Handles numerical edge cases (negative d² due to floating-point) by clamping.
pub fn mahalanobis_distance_4d(
    x: &[f64; 4],
    mu: &[f64; 4],
    inv_cov: &[[f64; 4]; 4],
) -> f64 {
    // delta = x - mu
    let delta: [f64; 4] = [
        x[0] - mu[0],
        x[1] - mu[1],
        x[2] - mu[2],
        x[3] - mu[3],
    ];

    // tmp = inv_cov * delta
    let mut tmp = [0.0f64; 4];
    for i in 0..4 {
        for j in 0..4 {
            tmp[i] += inv_cov[i][j] * delta[j];
        }
    }

    // d² = delta^T * tmp
    let d_sq: f64 = delta[0] * tmp[0]
        + delta[1] * tmp[1]
        + delta[2] * tmp[2]
        + delta[3] * tmp[3];

    // Guard against small negative d² from floating-point rounding
    d_sq.max(0.0).sqrt()
}

/// Logistic sigmoid: `1 / (1 + exp(−x))`.
///
/// Mirrors V1 `scipy.special.expit(x)`.
/// Numerically stable: guards against overflow on very negative inputs.
pub fn logistic_sigmoid(x: f64) -> f64 {
    // Stable form: avoids overflow of exp(-x) for very large x.
    if x >= 0.0 {
        1.0 / (1.0 + (-x).exp())
    } else {
        let ex = x.exp();
        ex / (1.0 + ex)
    }
}

/// Shannon entropy of `values` using natural log (nats).
///
/// Mirrors V1 `Qsecbit._system_entropy()`:
/// - Filters to strictly positive values (V1: `v for v in augmented if v > 0`).
/// - Normalizes: `probs = values / sum(values)`.
/// - Computes: `H = −Σ p·ln(p)`.
///
/// Returns `0.0` for fewer than 2 positive values (degenerate distribution).
pub fn shannon_entropy_nats(values: &[f64]) -> f64 {
    // Filter to positive values (matching V1 scipy.stats.entropy convention)
    let pos: Vec<f64> = values.iter().copied().filter(|&v| v > 0.0).collect();
    if pos.len() < 2 {
        return 0.0; // degenerate: all weight on one event → p=1, H=0
    }
    let total: f64 = pos.iter().sum();
    if total <= 0.0 {
        return 0.0;
    }
    pos.iter()
        .map(|&v| {
            let p = v / total;
            if p > 0.0 {
                -p * p.ln()
            } else {
                0.0
            }
        })
        .sum()
}

/// Normalized Mahalanobis drift in `[0, 1]`.
///
/// Formula: `logistic(slope · (d − center))` where `d = mahalanobis(x, μ, Σ⁻¹)`.
/// Mirrors V1 `Qsecbit._drift()`. At `d = center` (default 2.0), result = 0.50.
pub fn compute_drift(
    x: &[f64; 4],
    mu: &[f64; 4],
    inv_cov: &[[f64; 4]; 4],
    slope: f64,
    center: f64,
) -> (f64, f64) {
    let d = mahalanobis_distance_4d(x, mu, inv_cov);
    (logistic_sigmoid(slope * (d - center)), d)
}

/// Normalized entropy deviation (quantum drift) in `[0, 1]`.
///
/// Formula: `min(1.0, |H(x) − q_anchor| / q_crit)`.
/// Mirrors V1 `Qsecbit._quantum_drift()`.
pub fn compute_quantum_drift(q_t: f64, q_anchor: f64, q_crit: f64) -> f64 {
    let deviation = (q_t - q_anchor).abs();
    (deviation / q_crit.max(f64::EPSILON)).min(1.0)
}

/// Normalized classifier confidence decay rate in `[0, 1]`.
///
/// Formula: `min(1.0, ‖c_t − c_prev‖₂ / (dt · λ_crit))`.
/// Mirrors V1 `Qsecbit._classifier_decay()`.
///
/// Returns `0.0` when `c_prev` is empty (first tick or caller has no prior state).
pub fn compute_classifier_decay(
    c_t: &[f64],
    c_prev: &[f64],
    dt: f64,
    lambda_crit: f64,
) -> f64 {
    if c_prev.is_empty() || c_t.is_empty() {
        return 0.0;
    }
    // Pad the shorter slice with zeros to align lengths (V1 never needed this
    // since both slices come from the same model, but be safe).
    let len = c_t.len().max(c_prev.len());
    let norm_sq: f64 = (0..len)
        .map(|i| {
            let a = c_t.get(i).copied().unwrap_or(0.0);
            let b = c_prev.get(i).copied().unwrap_or(0.0);
            (a - b).powi(2)
        })
        .sum();
    let delta_rate = norm_sq.sqrt() / dt.max(f64::EPSILON);
    (delta_rate / lambda_crit.max(f64::EPSILON)).min(1.0)
}

// ─── Composite scorer ─────────────────────────────────────────────────────────

/// Compute the composite QSECBIT score for one telemetry tick.
///
/// This is the primary entry point for the WASI binary and for unit tests.
///
/// The formula (V1 `Qsecbit.calculate()`):
/// ```text
/// R = α·drift + β·p_attack + γ·decay + δ·qdrift
/// ```
///
/// With `p_attack = 0.0` (ML stub) and `decay = 0.0` (first tick), the
/// effective formula is `R = α·drift + δ·qdrift`, reaching AMBER (≥ 0.45)
/// only for severe Mahalanobis outliers combined with high entropy deviation.
/// RED (≥ 0.70) requires the ML component (β term).
pub fn compute(input: &QsecbitInput, cfg: &QsecbitConfig) -> QsecbitOutput {
    let x = input.telemetry_array();

    // ── Component 1: Mahalanobis drift (α) ───────────────────────────────────
    let (drift, raw_d) =
        compute_drift(&x, &BASELINE_MU, &BASELINE_INV_COV, cfg.drift_slope, cfg.drift_center);

    // ── Component 2: ML attack probability (β) — STUB ────────────────────────
    // TODO(wasi-nn): replace input.p_attack with ONNX model inference output.
    // The caller must supply p_attack from the trained classifier once available.
    // Until then, beta * 0.0 = 0.0 contribution.
    let p_attack = input.p_attack.clamp(0.0, 1.0);

    // ── Component 3: Classifier confidence decay (γ) ─────────────────────────
    let decay = match &input.prev_classifier_confidence {
        Some(prev) => compute_classifier_decay(
            &input.classifier_confidence,
            prev,
            input.dt,
            cfg.lambda_crit,
        ),
        None => 0.0, // first tick or stateless caller
    };

    // ── Component 4: Entropy deviation / quantum drift (δ) ───────────────────
    let q_t = shannon_entropy_nats(&x);
    let qdrift = compute_quantum_drift(q_t, cfg.q_anchor, cfg.q_crit);

    // ── Weighted combination ──────────────────────────────────────────────────
    let r_raw =
        cfg.alpha * drift + cfg.beta * p_attack + cfg.gamma * decay + cfg.delta * qdrift;

    // Clamp to [0, 1]: external p_attack may exceed 1.0 in edge cases (V1 does this).
    let score = r_raw.clamp(0.0, 1.0);

    // ── Band classification ───────────────────────────────────────────────────
    let band = if score >= cfg.red_threshold {
        Band::Red
    } else if score >= cfg.amber_threshold {
        Band::Amber
    } else {
        Band::Green
    };

    QsecbitOutput {
        score,
        band,
        breakdown: QsecbitBreakdown {
            mahalanobis_drift: drift,
            entropy_deviation: qdrift,
            attack_probability: p_attack,
            classifier_decay: decay,
            raw_mahalanobis_distance: raw_d,
            telemetry_entropy_nats: q_t,
        },
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> QsecbitConfig {
        QsecbitConfig::default()
    }

    // ── Mahalanobis distance helper ──────────────────────────────────────────

    /// Exact baseline: the baseline mean maps to distance zero.
    #[test]
    fn mahalanobis_at_baseline_is_zero() {
        let d = mahalanobis_distance_4d(&BASELINE_MU, &BASELINE_MU, &BASELINE_INV_COV);
        assert!(
            d.abs() < 1e-10,
            "distance from mu to itself should be 0, got {d}"
        );
    }

    /// Diagonal inv_cov = 50·I: shifting one dimension by Δ gives d = sqrt(50·Δ²).
    #[test]
    fn mahalanobis_one_dimension_known_value() {
        let mut x = BASELINE_MU;
        x[0] += 0.1; // Δ = 0.1 along dim-0
        let d = mahalanobis_distance_4d(&x, &BASELINE_MU, &BASELINE_INV_COV);
        // d² = 50 · 0.1² = 0.5, d = sqrt(0.5) ≈ 0.7071
        let expected = (50.0_f64 * 0.01_f64).sqrt();
        assert!(
            (d - expected).abs() < 1e-8,
            "expected d ≈ {expected:.6}, got {d:.6}"
        );
    }

    /// Symmetric: distance(a, b) == distance(b, a) for this diagonal matrix.
    #[test]
    fn mahalanobis_is_symmetric() {
        let x = [0.45, 0.68, 0.55, 0.62];
        let d1 = mahalanobis_distance_4d(&x, &BASELINE_MU, &BASELINE_INV_COV);
        let d2 = mahalanobis_distance_4d(&BASELINE_MU, &x, &BASELINE_INV_COV);
        assert!((d1 - d2).abs() < 1e-12, "Mahalanobis must be symmetric: {d1} vs {d2}");
    }

    // ── Logistic sigmoid helper ───────────────────────────────────────────────

    #[test]
    fn logistic_at_zero_is_half() {
        assert!((logistic_sigmoid(0.0) - 0.5).abs() < 1e-12);
    }

    #[test]
    fn logistic_positive_large_approaches_one() {
        assert!(logistic_sigmoid(100.0) > 0.9999);
    }

    #[test]
    fn logistic_negative_large_approaches_zero() {
        assert!(logistic_sigmoid(-100.0) < 1e-4);
    }

    // ── Shannon entropy helper ────────────────────────────────────────────────

    /// Uniform 4-element distribution → maximum entropy = ln(4) ≈ 1.386 nats.
    #[test]
    fn entropy_uniform_is_ln4() {
        let h = shannon_entropy_nats(&[1.0, 1.0, 1.0, 1.0]);
        let expected = (4.0_f64).ln(); // ln(4) ≈ 1.3863
        assert!(
            (h - expected).abs() < 1e-6,
            "uniform 4-element entropy should be ln(4)={expected:.6}, got {h:.6}"
        );
    }

    /// All-zeros → degenerate (< 2 positive values) → 0.0.
    #[test]
    fn entropy_all_zeros_is_zero() {
        assert_eq!(shannon_entropy_nats(&[0.0, 0.0, 0.0, 0.0]), 0.0);
    }

    /// Single positive value → p = 1.0 → H = 0 (pos.len() < 2 guard).
    #[test]
    fn entropy_single_value_is_zero() {
        assert_eq!(shannon_entropy_nats(&[1.0, 0.0, 0.0, 0.0]), 0.0);
    }

    /// More diverse distributions have strictly higher entropy.
    #[test]
    fn entropy_diverse_exceeds_concentrated() {
        let h_diverse = shannon_entropy_nats(&[1.0, 1.0, 1.0, 1.0]);
        let h_concentrated = shannon_entropy_nats(&[0.9, 0.01, 0.01, 0.01]);
        assert!(
            h_diverse > h_concentrated,
            "diverse H={h_diverse:.4} should exceed concentrated H={h_concentrated:.4}"
        );
    }

    // ── compute() end-to-end ─────────────────────────────────────────────────

    /// Benign / near-baseline telemetry → GREEN, low risk score.
    ///
    /// Vector [0.12, 0.21, 0.16, 0.34] is very close to the baseline mean
    /// [0.10, 0.20, 0.15, 0.33]. Expected:
    ///   d ≈ 0.187, drift ≈ 0.0018, entropy ≈ 1.31 nats, qdrift ≈ 0.07
    ///   R ≈ 0.30·0.0018 + 0.20·0.07 ≈ 0.015 → GREEN
    #[test]
    fn benign_baseline_is_green() {
        let input = QsecbitInput::from_telemetry(0.12, 0.21, 0.16, 0.34);
        let out = compute(&input, &cfg());
        eprintln!(
            "benign: score={:.4} band={} drift={:.4} qdrift={:.4} d={:.4} H={:.4}",
            out.score,
            out.band.as_str(),
            out.breakdown.mahalanobis_drift,
            out.breakdown.entropy_deviation,
            out.breakdown.raw_mahalanobis_distance,
            out.breakdown.telemetry_entropy_nats,
        );
        assert_eq!(out.band, Band::Green, "near-baseline telemetry must be GREEN");
        assert!(
            out.score < 0.20,
            "benign score should be well below AMBER; got {:.4}",
            out.score
        );
    }

    /// Anomalous telemetry (CPU spike, near-zero on others) → AMBER.
    ///
    /// Vector [0.9, 0.01, 0.01, 0.01]:
    ///   d ≈ 6.32, drift ≈ 1.0 (logistic(3.5·4.32) ≈ 1.0)
    ///   entropy ≈ 0.18 nats → qdrift = |0.18 − 1.293| / 0.25 = 4.45 → 1.0
    ///   R = 0.30·1.0 + 0.20·1.0 = 0.50 → AMBER
    #[test]
    fn anomalous_cpu_spike_is_amber() {
        let input = QsecbitInput::from_telemetry(0.9, 0.01, 0.01, 0.01);
        let out = compute(&input, &cfg());
        eprintln!(
            "anomalous: score={:.4} band={} drift={:.4} qdrift={:.4} d={:.4} H={:.4}",
            out.score,
            out.band.as_str(),
            out.breakdown.mahalanobis_drift,
            out.breakdown.entropy_deviation,
            out.breakdown.raw_mahalanobis_distance,
            out.breakdown.telemetry_entropy_nats,
        );
        assert!(
            out.band == Band::Amber || out.band == Band::Red,
            "anomalous telemetry should be AMBER or RED; got {}",
            out.band.as_str()
        );
        assert!(
            out.score >= 0.40,
            "anomalous score should approach AMBER (≥0.45); got {:.4}",
            out.score
        );
    }

    /// Anomalous score is strictly higher than benign score.
    #[test]
    fn anomalous_score_exceeds_benign_score() {
        let benign = compute(&QsecbitInput::from_telemetry(0.12, 0.21, 0.16, 0.34), &cfg());
        let anomalous = compute(&QsecbitInput::from_telemetry(0.9, 0.01, 0.01, 0.01), &cfg());
        assert!(
            anomalous.score > benign.score,
            "anomalous ({:.4}) must exceed benign ({:.4})",
            anomalous.score,
            benign.score
        );
    }

    /// Far-from-baseline vector drives Mahalanobis drift to near 1.0.
    #[test]
    fn large_mahalanobis_drift_approaches_one() {
        // Very far from baseline: all dimensions at extreme value
        let input = QsecbitInput::from_telemetry(0.9, 0.95, 0.9, 0.9);
        let out = compute(&input, &cfg());
        eprintln!(
            "far-from-baseline: d={:.2}, drift={:.4}",
            out.breakdown.raw_mahalanobis_distance,
            out.breakdown.mahalanobis_drift,
        );
        assert!(
            out.breakdown.mahalanobis_drift > 0.99,
            "very far from baseline should yield drift ≈ 1.0, got {:.4}",
            out.breakdown.mahalanobis_drift
        );
    }

    /// High entropy deviation (concentrated distribution) drives qdrift to 1.0.
    #[test]
    fn concentrated_distribution_drives_qdrift_to_one() {
        // [0.99, 0.01, 0.01, 0.01]: most weight on one metric → low entropy → large deviation
        let x = [0.99_f64, 0.01, 0.01, 0.01];
        let q_t = shannon_entropy_nats(&x);
        let qdrift = compute_quantum_drift(q_t, BASELINE_Q_ANCHOR, 0.25);
        eprintln!("H={q_t:.4} qdrift={qdrift:.4}");
        assert!(
            qdrift >= 1.0 - 1e-9,
            "highly concentrated distribution should saturate qdrift; got {qdrift:.4}"
        );
    }

    /// Classifier decay is 0 with no previous state (first tick).
    #[test]
    fn decay_is_zero_on_first_tick() {
        let d = compute_classifier_decay(&[0.8, 0.1, 0.1], &[], 1.0, 0.15);
        assert_eq!(d, 0.0, "no prev state → decay must be 0.0");
    }

    /// Classifier decay is nonzero when confidence changes significantly.
    #[test]
    fn decay_detects_confidence_shift() {
        let c_prev = vec![0.95, 0.03, 0.02]; // high confidence (stable)
        let c_curr = vec![0.45, 0.35, 0.20]; // shifted (less confident)
        let d = compute_classifier_decay(&c_curr, &c_prev, 1.0, 0.15);
        eprintln!("decay={d:.4}");
        assert!(d > 0.0, "significant confidence shift → decay > 0");
    }

    /// With an injected p_attack = 1.0, the RED threshold is reachable.
    ///
    /// R = 0.30·drift + 0.30·1.0 + 0.20·qdrift ≥ 0.30 + 0.30 = 0.60 → approaches RED.
    #[test]
    fn red_reachable_with_ml_p_attack() {
        let mut input = QsecbitInput::from_telemetry(0.9, 0.01, 0.01, 0.01);
        input.p_attack = 1.0; // simulate a fully loaded ML model output
        let out = compute(&input, &cfg());
        eprintln!(
            "with ML p_attack=1.0: score={:.4} band={}",
            out.score,
            out.band.as_str()
        );
        // 0.30·1.0 + 0.30·1.0 + 0.20·1.0 = 0.80 → RED
        assert!(
            out.score >= 0.70,
            "with drift=1.0, p_attack=1.0, qdrift=1.0, score should reach RED; got {:.4}",
            out.score
        );
        assert_eq!(out.band, Band::Red);
    }
}
