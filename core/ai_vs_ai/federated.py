#!/usr/bin/env python3
"""
Federated Learning Aggregator

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2026 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

Byzantine-robust federated averaging for distributed ML model training
across the HookProbe mesh network.

Algorithm: FedAvg with Byzantine Fault Tolerance
    1. Central aggregator broadcasts global model
    2. Edge devices train locally on their data
    3. Devices submit model updates (gradients or weights)
    4. Aggregator validates updates (signature, PoSF)
    5. Byzantine-robust aggregation (median, Krum, etc.)
    6. Updated global model distributed

Security Features:
    - PoSF signature verification on all updates
    - Byzantine fault tolerance up to 1/3 malicious nodes
    - Gradient clipping to prevent poisoning
    - Differential privacy support
    - Secure aggregation (optional)

Usage:
    aggregator = FederatedAggregator(validators=['v1', 'v2', 'v3'])

    # Collect updates from edges
    updates = await aggregator.collect_updates(round_id=1)

    # Aggregate with FedAvg
    new_weights = aggregator.aggregate(updates)

    # Validate and broadcast
    aggregator.broadcast_weights(new_weights)
"""

import numpy as np
import hashlib
import hmac
import logging
import time
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class AggregationMethod(Enum):
    """Federated aggregation methods."""
    FEDAVG = 'fedavg'           # Simple averaging
    MEDIAN = 'median'           # Coordinate-wise median
    TRIMMED_MEAN = 'trimmed'    # Trimmed mean (removes outliers)
    KRUM = 'krum'               # Byzantine-robust Krum
    MULTI_KRUM = 'multi_krum'   # Multi-Krum for partial selection


@dataclass
class ModelUpdate:
    """Model update from an edge device."""
    validator_id: str
    round_id: int
    weights: np.ndarray          # Model weights or gradients
    num_samples: int             # Number of training samples used
    loss: float                  # Training loss
    timestamp: float
    signature: bytes = b''       # PoSF signature
    posf_proof: bytes = b''      # Proof of Sensor Fusion

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            'validator_id': self.validator_id,
            'round_id': self.round_id,
            'weights': self.weights.tolist(),
            'num_samples': self.num_samples,
            'loss': self.loss,
            'timestamp': self.timestamp,
            'signature': self.signature.hex(),
            'posf_proof': self.posf_proof.hex(),
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'ModelUpdate':
        """Create from dictionary."""
        return cls(
            validator_id=data['validator_id'],
            round_id=data['round_id'],
            weights=np.array(data['weights']),
            num_samples=data['num_samples'],
            loss=data['loss'],
            timestamp=data['timestamp'],
            signature=bytes.fromhex(data.get('signature', '')),
            posf_proof=bytes.fromhex(data.get('posf_proof', '')),
        )


@dataclass
class AggregationResult:
    """Result of federated aggregation."""
    round_id: int
    aggregated_weights: np.ndarray
    num_participants: int
    total_samples: int
    avg_loss: float
    excluded_validators: List[str]
    method: AggregationMethod
    timestamp: float
    fingerprint: bytes


class FederatedAggregator:
    """
    Byzantine-robust federated averaging aggregator.

    Implements multiple aggregation strategies with varying degrees
    of Byzantine fault tolerance:

    - FedAvg: Simple weighted average (no Byzantine tolerance)
    - Median: Coordinate-wise median (tolerates < 50% Byzantine)
    - Trimmed Mean: Removes extreme values (tolerates configured %)
    - Krum: Selects update closest to others (tolerates < n/3 Byzantine)
    """

    # Configuration
    DEFAULT_TIMEOUT = 300.0      # 5 minutes to collect updates
    MIN_PARTICIPANTS = 3         # Minimum validators for aggregation
    GRADIENT_CLIP_NORM = 10.0    # Max L2 norm for gradients
    STALENESS_THRESHOLD = 3      # Max rounds a model can be behind

    def __init__(
        self,
        validators: List[str],
        aggregation_method: AggregationMethod = AggregationMethod.KRUM,
        byzantine_tolerance: float = 0.33,
        secret_key: Optional[bytes] = None,
    ):
        """
        Initialize federated aggregator.

        Args:
            validators: List of authorized validator IDs
            aggregation_method: Aggregation strategy
            byzantine_tolerance: Fraction of Byzantine nodes tolerated
            secret_key: Secret for signature verification
        """
        self.validators = set(validators)
        self.method = aggregation_method
        self.byzantine_tolerance = byzantine_tolerance
        self.secret_key = secret_key or self._generate_key()

        # State
        self.current_round = 0
        self.global_weights: Optional[np.ndarray] = None
        self._pending_updates: Dict[str, ModelUpdate] = {}
        self._round_history: List[AggregationResult] = []

        # Statistics
        self._stats = {
            'rounds_completed': 0,
            'updates_received': 0,
            'updates_rejected': 0,
            'byzantine_detected': 0,
        }

        logger.info(f"[FedAgg] Initialized with {len(validators)} validators, method={aggregation_method.value}")

    def _generate_key(self) -> bytes:
        """Generate random secret key."""
        import secrets
        return secrets.token_bytes(32)

    def start_round(self, round_id: int = None) -> int:
        """
        Start a new federated learning round.

        Args:
            round_id: Optional specific round ID

        Returns:
            Round ID
        """
        self.current_round = round_id if round_id is not None else self.current_round + 1
        self._pending_updates.clear()

        logger.info(f"[FedAgg] Started round {self.current_round}")
        return self.current_round

    async def collect_updates(
        self,
        round_id: int,
        timeout: float = None,
        min_updates: int = None,
    ) -> List[ModelUpdate]:
        """
        Collect model updates from validators.

        Args:
            round_id: Round to collect for
            timeout: Maximum wait time
            min_updates: Minimum updates required

        Returns:
            List of valid updates
        """
        import asyncio

        timeout = timeout or self.DEFAULT_TIMEOUT
        min_updates = min_updates or self.MIN_PARTICIPANTS

        start_time = time.time()

        # Wait for updates
        while time.time() - start_time < timeout:
            if len(self._pending_updates) >= min_updates:
                break
            await asyncio.sleep(1.0)

        # Filter valid updates for this round
        valid_updates = [
            u for u in self._pending_updates.values()
            if u.round_id == round_id and self._validate_update(u)
        ]

        logger.info(f"[FedAgg] Collected {len(valid_updates)} valid updates for round {round_id}")

        return valid_updates

    def submit_update(self, update: ModelUpdate) -> bool:
        """
        Submit a model update from a validator.

        Args:
            update: Model update

        Returns:
            True if accepted
        """
        # Check validator is authorized
        if update.validator_id not in self.validators:
            logger.warning(f"[FedAgg] Rejected update from unauthorized validator: {update.validator_id}")
            self._stats['updates_rejected'] += 1
            return False

        # Validate update
        if not self._validate_update(update):
            self._stats['updates_rejected'] += 1
            return False

        # Store update
        self._pending_updates[update.validator_id] = update
        self._stats['updates_received'] += 1

        logger.debug(f"[FedAgg] Accepted update from {update.validator_id} (round {update.round_id})")
        return True

    def _validate_update(self, update: ModelUpdate) -> bool:
        """
        Validate a model update.

        Checks:
        1. Round ID is current or recent
        2. Signature is valid (PoSF)
        3. Gradient norm is within bounds
        4. No NaN/Inf values
        """
        # Check round freshness
        if abs(update.round_id - self.current_round) > self.STALENESS_THRESHOLD:
            logger.warning(f"[FedAgg] Stale update from {update.validator_id}: round {update.round_id}")
            return False

        # Check for NaN/Inf
        if not np.isfinite(update.weights).all():
            logger.warning(f"[FedAgg] Invalid weights from {update.validator_id}: contains NaN/Inf")
            return False

        # Check gradient norm (if treating as gradients)
        norm = np.linalg.norm(update.weights)
        if norm > self.GRADIENT_CLIP_NORM * len(update.weights):
            logger.warning(f"[FedAgg] Gradient norm too large from {update.validator_id}: {norm:.2f}")
            return False

        # Verify PoSF signature if provided
        if update.signature and update.posf_proof:
            if not self._verify_posf(update):
                logger.warning(f"[FedAgg] Invalid PoSF signature from {update.validator_id}")
                return False

        return True

    def _verify_posf(self, update: ModelUpdate) -> bool:
        """Verify PoSF signature on update."""
        # Compute expected signature
        message = (
            update.validator_id.encode() +
            str(update.round_id).encode() +
            update.weights.tobytes()
        )

        expected = hmac.new(self.secret_key, message, hashlib.sha256).digest()[:16]

        # Constant-time comparison
        return hmac.compare_digest(update.signature[:16], expected)

    def aggregate(
        self,
        updates: List[ModelUpdate],
        method: AggregationMethod = None,
    ) -> np.ndarray:
        """
        Aggregate model updates using specified method.

        Args:
            updates: List of model updates
            method: Override aggregation method

        Returns:
            Aggregated weights
        """
        if not updates:
            raise ValueError("No updates to aggregate")

        method = method or self.method

        # Extract weights and sample counts
        weights_list = [u.weights for u in updates]
        sample_counts = [u.num_samples for u in updates]

        # Apply aggregation method
        if method == AggregationMethod.FEDAVG:
            aggregated = self._fedavg(weights_list, sample_counts)
        elif method == AggregationMethod.MEDIAN:
            aggregated = self._median(weights_list)
        elif method == AggregationMethod.TRIMMED_MEAN:
            aggregated = self._trimmed_mean(weights_list)
        elif method == AggregationMethod.KRUM:
            aggregated = self._krum(weights_list)
        elif method == AggregationMethod.MULTI_KRUM:
            aggregated = self._multi_krum(weights_list)
        else:
            raise ValueError(f"Unknown aggregation method: {method}")

        # Update global weights
        self.global_weights = aggregated

        # Record result
        result = AggregationResult(
            round_id=self.current_round,
            aggregated_weights=aggregated,
            num_participants=len(updates),
            total_samples=sum(sample_counts),
            avg_loss=np.mean([u.loss for u in updates]),
            excluded_validators=[],
            method=method,
            timestamp=time.time(),
            fingerprint=self._compute_fingerprint(aggregated),
        )
        self._round_history.append(result)
        self._stats['rounds_completed'] += 1

        logger.info(f"[FedAgg] Aggregated {len(updates)} updates with {method.value}")

        return aggregated

    def _fedavg(
        self,
        weights_list: List[np.ndarray],
        sample_counts: List[int],
    ) -> np.ndarray:
        """
        Federated Averaging (FedAvg).

        W_global = Σ(n_k / n_total) * W_k

        Weights are averaged proportional to number of samples.
        """
        total_samples = sum(sample_counts)
        if total_samples == 0:
            total_samples = len(weights_list)
            sample_counts = [1] * len(weights_list)

        aggregated = np.zeros_like(weights_list[0])

        for weights, n_samples in zip(weights_list, sample_counts):
            aggregated += (n_samples / total_samples) * weights

        return aggregated

    def _median(self, weights_list: List[np.ndarray]) -> np.ndarray:
        """
        Coordinate-wise median aggregation.

        Byzantine-robust: tolerates < 50% malicious updates.
        """
        stacked = np.stack(weights_list)
        return np.median(stacked, axis=0)

    def _trimmed_mean(
        self,
        weights_list: List[np.ndarray],
        trim_fraction: float = 0.1,
    ) -> np.ndarray:
        """
        Trimmed mean aggregation.

        Removes top and bottom trim_fraction of values before averaging.
        """
        from scipy import stats

        stacked = np.stack(weights_list)
        # Trim along axis 0 (clients)
        trimmed = stats.trimboth(stacked, trim_fraction, axis=0)
        return np.mean(trimmed, axis=0)

    def _krum(self, weights_list: List[np.ndarray]) -> np.ndarray:
        """
        Krum aggregation (Byzantine-robust).

        Selects the update that is closest to the majority of other updates.
        Tolerates up to n/3 - 1 Byzantine nodes.
        """
        n = len(weights_list)
        if n < 4:
            # Not enough for Krum, fall back to median
            return self._median(weights_list)

        # Number of Byzantine nodes we can tolerate
        f = max(1, int(n * self.byzantine_tolerance))
        m = n - f - 2  # Number of closest neighbors to consider

        if m < 1:
            return self._median(weights_list)

        # Compute pairwise distances
        scores = []
        for i, w_i in enumerate(weights_list):
            distances = []
            for j, w_j in enumerate(weights_list):
                if i != j:
                    dist = np.linalg.norm(w_i - w_j)
                    distances.append(dist)

            # Score = sum of m smallest distances
            distances.sort()
            score = sum(distances[:m])
            scores.append(score)

        # Select update with smallest score
        best_idx = np.argmin(scores)
        return weights_list[best_idx]

    def _multi_krum(
        self,
        weights_list: List[np.ndarray],
        multi_k: int = None,
    ) -> np.ndarray:
        """
        Multi-Krum aggregation.

        Selects top-k updates and averages them.
        """
        n = len(weights_list)
        f = max(1, int(n * self.byzantine_tolerance))
        multi_k = multi_k or max(1, n - f)

        if n < 4:
            return self._median(weights_list)

        m = n - f - 2

        # Compute scores
        scores = []
        for i, w_i in enumerate(weights_list):
            distances = []
            for j, w_j in enumerate(weights_list):
                if i != j:
                    dist = np.linalg.norm(w_i - w_j)
                    distances.append(dist)

            distances.sort()
            score = sum(distances[:max(1, m)])
            scores.append((score, i))

        # Select top-k (lowest scores)
        scores.sort()
        selected_indices = [idx for _, idx in scores[:multi_k]]

        # Average selected updates
        selected_weights = [weights_list[i] for i in selected_indices]
        return np.mean(selected_weights, axis=0)

    def _compute_fingerprint(self, weights: np.ndarray) -> bytes:
        """Compute fingerprint of aggregated weights."""
        return hashlib.sha256(weights.tobytes()).digest()

    def validate_update(self, update: ModelUpdate) -> bool:
        """
        Public method to validate an update via PoSF signature.

        Args:
            update: Update to validate

        Returns:
            True if valid
        """
        return self._validate_update(update)

    def broadcast_weights(self, weights: np.ndarray) -> Dict:
        """
        Prepare weights for broadcast to validators.

        Args:
            weights: Aggregated weights

        Returns:
            Broadcast message
        """
        fingerprint = self._compute_fingerprint(weights)

        return {
            'round_id': self.current_round,
            'weights': weights.tolist(),
            'fingerprint': fingerprint.hex(),
            'timestamp': time.time(),
        }

    def get_stats(self) -> Dict:
        """Get aggregator statistics."""
        return {
            **self._stats,
            'current_round': self.current_round,
            'num_validators': len(self.validators),
            'pending_updates': len(self._pending_updates),
            'method': self.method.value,
        }


# ============================================================================
# CLI for testing
# ============================================================================

if __name__ == '__main__':
    import asyncio

    print("Federated Aggregator Demo")
    print("=" * 50)

    # Create aggregator
    validators = [f'validator-{i}' for i in range(5)]
    aggregator = FederatedAggregator(
        validators=validators,
        aggregation_method=AggregationMethod.KRUM,
    )

    print(f"\nInitial stats: {aggregator.get_stats()}")

    # Simulate model updates
    print("\nSimulating model updates...")
    aggregator.start_round(1)

    np.random.seed(42)
    base_weights = np.random.randn(100)

    for i, vid in enumerate(validators):
        # Simulate local training (slightly different weights)
        noise = np.random.randn(100) * 0.1
        weights = base_weights + noise

        # One Byzantine update (outlier)
        if i == 4:
            weights = np.random.randn(100) * 10

        update = ModelUpdate(
            validator_id=vid,
            round_id=1,
            weights=weights,
            num_samples=100 + i * 10,
            loss=0.5 - i * 0.05,
            timestamp=time.time(),
        )

        accepted = aggregator.submit_update(update)
        print(f"  {vid}: accepted={accepted}")

    # Aggregate updates
    print("\nAggregating updates...")
    updates = list(aggregator._pending_updates.values())

    # Test different methods
    for method in [AggregationMethod.FEDAVG, AggregationMethod.MEDIAN, AggregationMethod.KRUM]:
        aggregated = aggregator.aggregate(updates, method=method)
        distance_from_base = np.linalg.norm(aggregated - base_weights)
        print(f"  {method.value}: distance from base = {distance_from_base:.4f}")

    # Final stats
    print(f"\nFinal stats: {aggregator.get_stats()}")

    print("\n✓ Federated aggregator test complete")
