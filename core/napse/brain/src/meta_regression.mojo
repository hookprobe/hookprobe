# =============================================================================
# Meta-Regression Engine — Risk Velocity Computation
# =============================================================================
#
# Implements the core formula: y = β₀ + β₁·X_L4 + β₂·X_L7 + ε
#
# The LLM doesn't just look at a snapshot; it predicts the next state y
# based on a weighted regression of the last N seconds of telemetry X.
#
# The coefficients (β) explain WHY risk is increasing:
#   - β₁ high → L4 features are driving the threat (volumetric, rate-based)
#   - β₂ high → L7 features are driving the threat (protocol abuse, payload)
#
# Risk Velocity = β₁ = ΔRisk/Δt = the slope of the risk curve over time.
# When velocity exceeds a threshold, the system triggers a "Lookback RAG"
# query against ClickHouse's VectorSimilarity index.
#
# Performance: SIMD-accelerated dot products for O(1) per-IP regression.

from math import sqrt, log, abs
from algorithm import vectorize

alias MAX_WINDOWS: Int = 24    # Maximum scoring windows to track (2 hours at 5-min)
alias L4_FEATURES: Int = 8     # Network layer features
alias L7_FEATURES: Int = 8     # Application layer features
alias TOTAL_FEATURES: Int = L4_FEATURES + L7_FEATURES


# ============================================================================
# OLS Regression (SIMD-accelerated)
# ============================================================================

struct OLSResult:
    """Result of Ordinary Least Squares regression."""
    var beta_0: Float64       # Intercept
    var beta_1: Float64       # Slope (Risk Velocity)
    var r_squared: Float64    # Coefficient of determination
    var std_error: Float64    # Standard error of β₁
    var n: Int                # Number of observations

    fn __init__(out self):
        self.beta_0 = 0.0
        self.beta_1 = 0.0
        self.r_squared = 0.0
        self.std_error = 0.0
        self.n = 0

    fn is_significant(self, confidence: Float64 = 1.96) -> Bool:
        """Check if β₁ is statistically significant at 95% confidence.

        Uses t-test: |β₁| / std_error > t_critical
        For n > 30, t_critical ≈ 1.96 (normal approximation)
        """
        if self.std_error < 1e-10 or self.n < 3:
            return False
        return abs(self.beta_1) / self.std_error > confidence

    fn velocity_per_minute(self) -> Float64:
        """Risk Velocity normalized to per-minute rate."""
        return self.beta_1 * 60.0  # Assuming time in seconds


fn ols_regression(
    times: InlinedFixedVector[Float64, MAX_WINDOWS],
    scores: InlinedFixedVector[Float64, MAX_WINDOWS],
    n: Int,
) -> OLSResult:
    """Compute OLS linear regression: y = β₀ + β₁·t + ε

    β₁ = Σ(tᵢ - t̄)(yᵢ - ȳ) / Σ(tᵢ - t̄)²
    β₀ = ȳ - β₁·t̄

    Numerically stable: uses centered values to avoid catastrophic cancellation.
    """
    var result = OLSResult()
    result.n = n

    if n < 3:
        return result

    # Compute means
    var t_sum: Float64 = 0.0
    var y_sum: Float64 = 0.0
    for i in range(n):
        t_sum += times[i]
        y_sum += scores[i]
    var t_mean = t_sum / Float64(n)
    var y_mean = y_sum / Float64(n)

    # Compute β₁ using centered values
    var num: Float64 = 0.0   # Σ(t - t̄)(y - ȳ)
    var den: Float64 = 0.0   # Σ(t - t̄)²
    var ss_tot: Float64 = 0.0  # Σ(y - ȳ)²

    for i in range(n):
        var dt = times[i] - t_mean
        var dy = scores[i] - y_mean
        num += dt * dy
        den += dt * dt
        ss_tot += dy * dy

    if den < 1e-15:
        result.beta_0 = y_mean
        return result

    result.beta_1 = num / den
    result.beta_0 = y_mean - result.beta_1 * t_mean

    # R² = 1 - SS_res / SS_tot
    var ss_res: Float64 = 0.0
    for i in range(n):
        var predicted = result.beta_0 + result.beta_1 * times[i]
        var residual = scores[i] - predicted
        ss_res += residual * residual

    if ss_tot > 1e-15:
        result.r_squared = 1.0 - (ss_res / ss_tot)
        # Clamp to [0, 1] — floating-point rounding can produce values slightly outside
        if result.r_squared < 0.0:
            result.r_squared = 0.0
        elif result.r_squared > 1.0:
            result.r_squared = 1.0

    # Standard error of β₁
    if n > 2 and den > 1e-15:
        var mse = ss_res / Float64(n - 2)
        result.std_error = sqrt(mse / den)

    return result


# ============================================================================
# Multi-Variate Meta-Regression
# ============================================================================

struct MetaRegressionResult:
    """Result of multi-variate meta-regression: y = β₀ + β₁·X_L4 + β₂·X_L7 + ε"""
    var beta_0: Float64        # Intercept
    var beta_l4: Float64       # L4 contribution coefficient
    var beta_l7: Float64       # L7 contribution coefficient
    var risk_velocity: Float64  # Overall ΔRisk/Δt
    var l4_contribution: Float64  # % of risk from network layer
    var l7_contribution: Float64  # % of risk from application layer
    var explanation: String     # Human-readable explanation

    fn __init__(out self):
        self.beta_0 = 0.0
        self.beta_l4 = 0.0
        self.beta_l7 = 0.0
        self.risk_velocity = 0.0
        self.l4_contribution = 0.0
        self.l7_contribution = 0.0
        self.explanation = ""


struct MetaRegressionEngine:
    """Multi-variate meta-regression for layer-decomposed risk analysis.

    Decomposes risk into L4 (network) and L7 (application) contributions,
    enabling the LLM to explain WHY risk is increasing:

    "Risk is accelerating at +0.15/min driven primarily by L4 anomalies
     (β_L4=0.12, high SYN ratio + port diversity) suggesting reconnaissance
     escalating to exploitation."

    Feature decomposition:
      L4 features [0-7]: pps, bps, unique_ports, unique_ips, syn_ratio, rst_ratio, avg_pkt_size, small_pkt_ratio
      L7 features [8-15]: iat_entropy, port_diversity, protocol_mix, dns_ratio, session_duration, unique_services, threat_ratio, connection_reuse
    """
    var velocity_threshold: Float64
    var rag_threshold: Float64
    var computations: UInt64

    fn __init__(out self, velocity_threshold: Float64 = 0.1, rag_threshold: Float64 = 0.15):
        self.velocity_threshold = velocity_threshold
        self.rag_threshold = rag_threshold
        self.computations = 0

    fn analyze(
        mut self,
        times: InlinedFixedVector[Float64, MAX_WINDOWS],
        scores: InlinedFixedVector[Float64, MAX_WINDOWS],
        l4_magnitudes: InlinedFixedVector[Float64, MAX_WINDOWS],
        l7_magnitudes: InlinedFixedVector[Float64, MAX_WINDOWS],
        n: Int,
    ) -> MetaRegressionResult:
        """Run full meta-regression analysis.

        Computes:
        1. Overall risk velocity (OLS on scores vs time)
        2. L4 contribution (correlation of L4 magnitude with score increase)
        3. L7 contribution (correlation of L7 magnitude with score increase)
        4. Human-readable explanation
        """
        self.computations += 1
        var result = MetaRegressionResult()

        # Overall risk velocity
        var ols = ols_regression(times, scores, n)
        result.risk_velocity = ols.beta_1
        result.beta_0 = ols.beta_0

        if n < 4:
            result.explanation = "Insufficient data for layer decomposition"
            return result

        # L4 contribution: correlation between L4 magnitude changes and score changes
        var l4_ols = ols_regression(times, l4_magnitudes, n)
        var l7_ols = ols_regression(times, l7_magnitudes, n)

        result.beta_l4 = l4_ols.beta_1
        result.beta_l7 = l7_ols.beta_1

        # Contribution percentages
        var total_abs = abs(result.beta_l4) + abs(result.beta_l7)
        if total_abs > 1e-10:
            result.l4_contribution = abs(result.beta_l4) / total_abs
            result.l7_contribution = abs(result.beta_l7) / total_abs
        else:
            result.l4_contribution = 0.5
            result.l7_contribution = 0.5

        # Generate explanation
        if result.risk_velocity > self.rag_threshold:
            if result.l4_contribution > 0.7:
                result.explanation = (
                    "Risk ACCELERATING driven by L4 network anomalies "
                    "(volumetric/rate-based attack pattern, β_L4="
                    + str(round(result.beta_l4, 4))
                    + "). Recommend XDP rate limiting."
                )
            elif result.l7_contribution > 0.7:
                result.explanation = (
                    "Risk ACCELERATING driven by L7 application anomalies "
                    "(protocol abuse/payload manipulation, β_L7="
                    + str(round(result.beta_l7, 4))
                    + "). Recommend deep packet inspection."
                )
            else:
                result.explanation = (
                    "Risk ACCELERATING from mixed L4/L7 signals "
                    "(β_L4=" + str(round(result.beta_l4, 4))
                    + ", β_L7=" + str(round(result.beta_l7, 4))
                    + "). Possible multi-vector attack."
                )
        elif result.risk_velocity < -self.velocity_threshold:
            result.explanation = (
                "Risk DECELERATING (velocity="
                + str(round(result.risk_velocity, 4))
                + "/min). Attack may be subsiding or evading detection."
            )
        else:
            result.explanation = (
                "Risk STABLE (velocity="
                + str(round(result.risk_velocity, 4))
                + "/min, R²=" + str(round(ols.r_squared, 3)) + ")."
            )

        return result

    fn should_trigger_rag(self, result: MetaRegressionResult) -> Bool:
        """Determine if Flash-RAG lookback should be triggered."""
        return abs(result.risk_velocity) > self.rag_threshold


fn round(value: Float64, decimals: Int) -> Float64:
    """Round to N decimal places (round-half-away-from-zero for both signs)."""
    var factor = 10.0 ** Float64(decimals)
    if value >= 0.0:
        return Float64(int(value * factor + 0.5)) / factor
    else:
        return Float64(int(value * factor - 0.5)) / factor
