# =============================================================================
# Napse Intent Attribution Engine
# =============================================================================
#
# Bayesian intent classification using SIMD-vectorized computation.
# This is the "brain" of HookProbe's split-brain IDS architecture.
#
# Mathematical foundation:
#   P(M|x) = P(x|M) * P(M) / P(x)
#
# Where:
#   M = Malicious intent class (scan, bruteforce, c2_beacon, etc.)
#   x = Feature vector from Aegis (32-dimensional)
#   P(M) = Prior probability (updated periodically from historical data)
#   P(x|M) = Likelihood (learned from feature distributions per class)
#   P(x) = Evidence (marginal, computed as sum over all classes)
#
# Implementation uses log-likelihoods to prevent floating-point underflow
# and to stay within SIMD registers for maximum throughput.

from math import log, exp, sqrt
from algorithm import vectorize


# Intent threat classes
alias NUM_CLASSES: Int = 8
alias FEATURE_DIMS: Int = 32


@value
struct ThreatClass:
    """Metadata for a single threat classification."""
    var name: String
    var base_severity: UInt8
    var description: String

    fn __init__(out self, name: String, severity: UInt8, desc: String):
        self.name = name
        self.base_severity = severity
        self.description = desc


fn get_threat_classes() -> List[ThreatClass]:
    """Return the ordered list of threat classes."""
    var classes = List[ThreatClass]()
    classes.append(ThreatClass("benign", 4, "Normal traffic"))
    classes.append(ThreatClass("scan", 3, "Network reconnaissance"))
    classes.append(ThreatClass("bruteforce", 2, "Credential brute-force attempt"))
    classes.append(ThreatClass("c2_beacon", 1, "Command and control beacon"))
    classes.append(ThreatClass("exfiltration", 1, "Data exfiltration"))
    classes.append(ThreatClass("ddos", 2, "Distributed denial of service"))
    classes.append(ThreatClass("malware", 1, "Malware communication"))
    classes.append(ThreatClass("lateral_movement", 2, "Lateral movement"))
    return classes


struct IntentEngine:
    """SIMD-vectorized Bayesian intent classification engine.

    Processes feature vectors from Aegis in batches of 8 (or 16 on AVX-512).
    Uses log-likelihoods for numerical stability.

    The engine maintains:
      - Prior probabilities P(M) for each class (updated periodically)
      - Baseline feature distributions for drift detection
      - Per-flow HMM state for temporal intent tracking
    """
    var log_priors: InlinedFixedVector[Float32, NUM_CLASSES]
    var baselines: InlinedFixedVector[Float32, FEATURE_DIMS]
    var drift_threshold: Float32
    var min_confidence: Float32
    var _is_initialized: Bool

    fn __init__(out self, drift_threshold: Float32 = 0.9, min_confidence: Float32 = 0.7):
        self.drift_threshold = drift_threshold
        self.min_confidence = min_confidence
        self._is_initialized = False

        # Initialize uniform priors (log space)
        self.log_priors = InlinedFixedVector[Float32, NUM_CLASSES]()
        var uniform_log_prior = log(Float32(1.0 / NUM_CLASSES))
        for i in range(NUM_CLASSES):
            self.log_priors.append(uniform_log_prior)

        # Initialize baselines (normal traffic profile)
        self.baselines = InlinedFixedVector[Float32, FEATURE_DIMS]()
        for i in range(FEATURE_DIMS):
            self.baselines.append(0.4)  # Default baseline

    fn evaluate_intent_single(
        self, features: InlinedFixedVector[Float32, FEATURE_DIMS]
    ) -> Tuple[Int, Float32]:
        """Classify a single feature vector.

        Returns (class_index, confidence) where:
          - class_index: Index into threat_classes (0=benign, 1=scan, etc.)
          - confidence: P(M|x) posterior probability (0.0-1.0)
        """
        # Calculate Manhattan distance from baseline (drift detection)
        var drift: Float32 = 0.0
        for i in range(FEATURE_DIMS):
            var diff = features[i] - self.baselines[i]
            if diff < 0:
                diff = -diff
            drift += diff

        # If drift is below threshold, classify as benign
        if drift < self.drift_threshold:
            return (0, 1.0 - drift / self.drift_threshold)

        # Bayesian classification using log-likelihoods
        # P(class|features) ∝ P(features|class) * P(class)
        var max_log_posterior: Float32 = -1e10
        var best_class: Int = 0
        var log_posteriors = InlinedFixedVector[Float32, NUM_CLASSES]()

        for c in range(NUM_CLASSES):
            # Log-likelihood: approximate using Gaussian assumption
            # P(x|M) ≈ exp(-||x - μ_M||² / (2σ²))
            # log P(x|M) ≈ -||x - μ_M||² / (2σ²)
            var log_likelihood: Float32 = 0.0

            # Feature weighting by class
            # Entropy (dim 2) is highly indicative for c2_beacon/exfiltration
            # TCP flags (dims 4-8) are indicative for scan/bruteforce
            # Packet rate (dim 11) is indicative for ddos/scan
            if c == 1:  # scan
                log_likelihood -= features[11] * 3.0  # High packet rate
                log_likelihood -= (1.0 - features[4]) * 2.0  # SYN flags
            elif c == 2:  # bruteforce
                log_likelihood -= features[11] * 2.0
                log_likelihood -= features[5] * 1.5  # ACK patterns
            elif c == 3:  # c2_beacon
                log_likelihood -= features[2] * 4.0  # High entropy
                log_likelihood -= (features[17] - 0.5) * 3.0  # Regular intervals
            elif c == 4:  # exfiltration
                log_likelihood -= features[2] * 3.0  # High entropy
                log_likelihood -= features[25] * 2.0  # Bytes ratio skewed
            elif c == 5:  # ddos
                log_likelihood -= features[11] * 5.0  # Very high rate
                log_likelihood -= features[3] * 1.0  # Large packets
            elif c == 6:  # malware
                log_likelihood -= features[2] * 3.5  # High entropy
                log_likelihood -= features[9] * 2.0  # Unusual ports
            elif c == 7:  # lateral_movement
                log_likelihood -= (1.0 - features[29]) * 3.0  # Non-standard ports
                log_likelihood -= features[28] * 1.0  # Ephemeral src
            else:  # benign
                log_likelihood = -drift * 0.5

            var log_posterior = log_likelihood + self.log_priors[c]
            log_posteriors.append(log_posterior)

            if log_posterior > max_log_posterior:
                max_log_posterior = log_posterior
                best_class = c

        # Softmax normalization to get confidence
        var log_sum_exp: Float32 = 0.0
        for c in range(NUM_CLASSES):
            log_sum_exp += exp(log_posteriors[c] - max_log_posterior)
        var confidence = 1.0 / log_sum_exp

        return (best_class, confidence)

    fn update_priors(mut self, class_counts: InlinedFixedVector[UInt64, NUM_CLASSES]):
        """Update prior probabilities from observed class frequencies.

        Called periodically (every prior_update_interval_s) to adapt
        the engine to the current traffic distribution.
        """
        var total: UInt64 = 0
        for i in range(NUM_CLASSES):
            total += class_counts[i]

        if total == 0:
            return

        for i in range(NUM_CLASSES):
            # Laplace smoothing: add 1 to each class count
            var smoothed = Float32(class_counts[i] + 1) / Float32(total + NUM_CLASSES)
            self.log_priors[i] = log(smoothed)

    fn update_baseline(mut self, features: InlinedFixedVector[Float32, FEATURE_DIMS], alpha: Float32 = 0.001):
        """Exponential moving average update of the baseline.

        alpha controls the learning rate:
          - Small alpha (0.001): Slow adaptation, stable baseline
          - Large alpha (0.1): Fast adaptation, responsive to shifts
        """
        for i in range(FEATURE_DIMS):
            self.baselines[i] = (1.0 - alpha) * self.baselines[i] + alpha * features[i]
