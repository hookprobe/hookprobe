"""
Deterministic Replay Engine - Cloud Validator

Simulates edge weight evolution from TER sequence to verify authenticity.
Critical: Must produce bit-for-bit identical results to edge.
"""

import numpy as np
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from ..neural.engine import NeuralEngine, WeightState
from ..neural.fixedpoint import FixedPoint, FixedPointArray
from .ter import TER, TERValidator


@dataclass
class ReplayResult:
    """Result of deterministic replay simulation."""
    W_final: WeightState
    W_initial: WeightState
    ter_count: int
    total_time_seconds: float
    divergence_detected: bool
    integrity_violations: int
    anomalies: List[str]


class DeterministicReplay:
    """
    Cloud validator's deterministic replay engine.

    Simulates edge weight evolution from TER sequence.
    Verifies edge weights match simulation (authentication).
    """

    def __init__(self, W_initial: WeightState, config: dict):
        """
        Args:
            W_initial: Last known edge weight state
            config: Axon-Z configuration (learning rates, coefficients)
        """
        self.W_initial = W_initial.copy()
        self.config = config

        # Extract configuration parameters
        self.eta_base = config.get('base_learning_rate', 0.0001)
        self.tau = config.get('decay_constant_seconds', 7200)
        self.C_integral = config.get('base_coefficient', 5.0)

    def simulate_edge_evolution(self, ter_sequence: List[TER]) -> ReplayResult:
        """
        Simulate edge weight evolution from TER sequence.

        Args:
            ter_sequence: Sequence of TERs from edge dream log

        Returns:
            ReplayResult with final weights and diagnostics
        """
        # Validate TER sequence first
        validation = TERValidator.validate_sequence(ter_sequence)
        if not validation['valid']:
            return ReplayResult(
                W_final=self.W_initial,
                W_initial=self.W_initial,
                ter_count=0,
                total_time_seconds=0.0,
                divergence_detected=True,
                integrity_violations=0,
                anomalies=validation['errors']
            )

        # Initialize simulation
        W_current = self.W_initial.copy()
        engine = NeuralEngine(W_current)

        integrity_violations = 0
        anomalies = validation['warnings'].copy()

        # Track initial integrity hash
        prev_h_integrity = None

        # Simulate each TER
        for i, ter in enumerate(ter_sequence):
            # Calculate time delta
            if i == 0:
                delta_t = 0.0
            else:
                delta_t = (ter.timestamp - ter_sequence[i-1].timestamp) / 1e6  # seconds

            # Check for integrity violations
            if prev_h_integrity is not None and ter.h_integrity != prev_h_integrity:
                integrity_violations += 1
                anomalies.append(f"Integrity hash changed at TER {i}")

            prev_h_integrity = ter.h_integrity

            # Calculate modified learning rate (time-decayed)
            eta_mod = self._calculate_learning_rate(delta_t)

            # Calculate threat score from integrity hash
            sigma_threat = ter.calculate_threat_score()

            # Modified loss coefficient
            integrity_coeff = FixedPoint(self.C_integral * sigma_threat)

            # Perform gradient descent step (deterministic)
            engine.gradient_descent_step(
                ter_bytes=ter.to_bytes(),
                learning_rate=eta_mod,
                integrity_coeff=integrity_coeff
            )

        # Calculate total time span
        if len(ter_sequence) > 1:
            total_time = (ter_sequence[-1].timestamp - ter_sequence[0].timestamp) / 1e6
        else:
            total_time = 0.0

        return ReplayResult(
            W_final=engine.W,
            W_initial=self.W_initial,
            ter_count=len(ter_sequence),
            total_time_seconds=total_time,
            divergence_detected=False,
            integrity_violations=integrity_violations,
            anomalies=anomalies
        )

    def verify_edge_weights(
        self,
        W_edge: WeightState,
        ter_sequence: List[TER],
        tolerance: float = 0.0
    ) -> Tuple[bool, ReplayResult]:
        """
        Verify edge weights match simulated evolution.

        Args:
            W_edge: Reported edge weight state
            ter_sequence: TER sequence from edge
            tolerance: Maximum allowed divergence (0.0 = bit-for-bit match)

        Returns:
            (is_valid, replay_result) tuple
        """
        # Simulate evolution
        result = self.simulate_edge_evolution(ter_sequence)

        # Compare weight fingerprints
        edge_fingerprint = W_edge.fingerprint()
        simulated_fingerprint = result.W_final.fingerprint()

        # Bit-for-bit comparison (default)
        if tolerance == 0.0:
            is_valid = (edge_fingerprint == simulated_fingerprint)
        else:
            # Calculate divergence for tolerance check
            divergence = self._calculate_weight_divergence(W_edge, result.W_final)
            is_valid = (divergence <= tolerance)

        return is_valid, result

    def detect_tampering(
        self,
        W_edge: WeightState,
        ter_sequence: List[TER]
    ) -> Dict[str, any]:
        """
        Detect if edge was tampered with offline.

        Returns:
            Detection report with verdict and evidence
        """
        is_valid, result = self.verify_edge_weights(W_edge, ter_sequence, tolerance=0.0)

        report = {
            'verdict': 'AUTHENTICATED' if is_valid else 'QUARANTINE',
            'reason': None,
            'evidence': {},
            'ter_count': result.ter_count,
            'time_offline_seconds': result.total_time_seconds,
            'integrity_violations': result.integrity_violations,
            'anomalies': result.anomalies
        }

        if not is_valid:
            # Determine reason for quarantine
            if result.integrity_violations > 0:
                report['reason'] = f'INTEGRITY_VIOLATION ({result.integrity_violations} detected)'
                report['evidence']['integrity_hash_changes'] = result.integrity_violations
            elif result.divergence_detected:
                report['reason'] = 'TER_VALIDATION_FAILED'
                report['evidence']['ter_errors'] = result.anomalies
            else:
                # Weight divergence without clear integrity violation
                divergence = self._calculate_weight_divergence(W_edge, result.W_final)
                report['reason'] = f'UNEXPLAINED_DRIFT (divergence: {divergence:.6f})'
                report['evidence']['weight_divergence'] = divergence

        return report

    def _calculate_learning_rate(self, delta_t: float) -> FixedPoint:
        """
        Calculate time-decayed learning rate.

        η_mod = η_base × exp(-Δt / τ)

        Args:
            delta_t: Time since last TER (seconds)

        Returns:
            Modified learning rate (fixed-point)
        """
        from ..neural.fixedpoint import fp_exp

        # Calculate exponent: -Δt / τ
        exponent_val = -delta_t / self.tau
        exponent_fp = FixedPoint(exponent_val)

        # exp(-Δt / τ)
        decay_factor = fp_exp(exponent_fp)

        # η_base × decay_factor
        eta_base_fp = FixedPoint(self.eta_base)
        eta_mod = eta_base_fp * decay_factor

        return eta_mod

    def _calculate_weight_divergence(self, W1: WeightState, W2: WeightState) -> float:
        """
        Calculate L2 norm of weight difference.

        ||W1 - W2||
        """
        W1_bytes = W1.to_bytes()
        W2_bytes = W2.to_bytes()

        # Convert to numpy arrays
        W1_array = np.frombuffer(W1_bytes, dtype=np.int32)
        W2_array = np.frombuffer(W2_bytes, dtype=np.int32)

        # L2 norm of difference
        diff = W1_array.astype(np.float64) - W2_array.astype(np.float64)
        divergence = np.linalg.norm(diff)

        return divergence


class ReplayCache:
    """
    Cache simulation results to avoid re-simulating identical TER sequences.
    """

    def __init__(self, max_cache_size: int = 1000):
        """
        Args:
            max_cache_size: Maximum number of cached simulations
        """
        self.cache = {}
        self.max_cache_size = max_cache_size

    def get(self, ter_sequence_hash: bytes) -> Optional[ReplayResult]:
        """Get cached replay result."""
        return self.cache.get(ter_sequence_hash)

    def put(self, ter_sequence_hash: bytes, result: ReplayResult):
        """Cache replay result."""
        # Simple LRU: remove oldest if cache full
        if len(self.cache) >= self.max_cache_size:
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]

        self.cache[ter_sequence_hash] = result

    def hash_ter_sequence(self, ter_sequence: List[TER]) -> bytes:
        """Create hash of TER sequence for cache key."""
        import hashlib

        hasher = hashlib.sha256()
        for ter in ter_sequence:
            hasher.update(ter.to_bytes())

        return hasher.digest()


# Example usage
if __name__ == '__main__':
    from ..neural.engine import create_initial_weights
    from .ter import TERGenerator

    print("=== Testing Deterministic Replay Engine ===\n")

    # Create initial weights (shared between edge and cloud)
    W0 = create_initial_weights(seed=42)
    print(f"Initial weight fingerprint: {W0.fingerprint().hex()[:32]}...")

    # Edge: Generate TER sequence (simulate 10 minutes offline)
    edge_ter_gen = TERGenerator()
    edge_ter_sequence = []

    print("\nEdge: Generating TER sequence (10 TERs)...")
    for i in range(10):
        ter = edge_ter_gen.generate()
        edge_ter_sequence.append(ter)
        print(f"  TER {i}: seq={ter.sequence}, threat={ter.calculate_threat_score():.4f}")

    # Edge: Evolve weights
    from ..neural.engine import NeuralEngine
    edge_engine = NeuralEngine(W0.copy())

    config = {
        'base_learning_rate': 0.0001,
        'decay_constant_seconds': 7200,
        'base_coefficient': 5.0
    }

    print("\nEdge: Evolving weights...")
    for i, ter in enumerate(edge_ter_sequence):
        if i == 0:
            delta_t = 0.0
        else:
            delta_t = 60.0  # 1 minute between TERs

        eta_mod = FixedPoint(config['base_learning_rate']) * FixedPoint(1.0)  # Simplified
        integrity_coeff = FixedPoint(config['base_coefficient'] * ter.calculate_threat_score())

        edge_engine.gradient_descent_step(ter.to_bytes(), eta_mod, integrity_coeff)

    W_edge_final = edge_engine.W
    print(f"Edge final weight fingerprint: {W_edge_final.fingerprint().hex()[:32]}...")

    # Cloud: Simulate edge evolution
    print("\nCloud: Simulating edge evolution...")
    replay_engine = DeterministicReplay(W0, config)

    is_valid, result = replay_engine.verify_edge_weights(W_edge_final, edge_ter_sequence)

    print(f"\nReplay Result:")
    print(f"  TER count: {result.ter_count}")
    print(f"  Total time: {result.total_time_seconds:.2f}s")
    print(f"  Integrity violations: {result.integrity_violations}")
    print(f"  Simulated fingerprint: {result.W_final.fingerprint().hex()[:32]}...")

    if is_valid:
        print("\n✓ AUTHENTICATED: Edge weights match simulation")
    else:
        print("\n❌ QUARANTINE: Weight divergence detected")

        # Get tampering report
        report = replay_engine.detect_tampering(W_edge_final, edge_ter_sequence)
        print(f"\nTampering Report:")
        print(f"  Verdict: {report['verdict']}")
        print(f"  Reason: {report['reason']}")
        print(f"  Evidence: {report['evidence']}")
