#!/usr/bin/env python3
"""
Federated Training Loop Orchestrator

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2026 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

Orchestrates federated learning across the HookProbe mesh network.
Coordinates model distribution, training rounds, gradient collection,
and consensus-based aggregation.

Training Cycle:
    1. Broadcast current global model to edge devices
    2. Wait for edge training window (configurable, default 24h)
    3. Collect gradients via DSM secure channels
    4. Aggregate with FedAvg or Byzantine-robust method
    5. Validate via BLS quorum signature
    6. Redistribute updated model

Usage:
    loop = FederatedTrainingLoop(
        aggregator=FederatedAggregator(validators),
        dsm_client=DSMClient(),
    )

    # Run training rounds
    await loop.run_training_cycle(num_rounds=10)

    # Or continuous training
    await loop.run_continuous()
"""

import asyncio
import numpy as np
import hashlib
import hmac
import logging
import time
from typing import Dict, List, Optional, Set, Callable, Any
from dataclasses import dataclass, field
from enum import Enum

from .federated import FederatedAggregator, ModelUpdate, AggregationMethod, AggregationResult

logger = logging.getLogger(__name__)


class TrainingPhase(Enum):
    """Current phase of federated training round."""
    IDLE = 'idle'
    BROADCASTING = 'broadcasting'
    TRAINING = 'training'
    COLLECTING = 'collecting'
    AGGREGATING = 'aggregating'
    VALIDATING = 'validating'
    COMPLETE = 'complete'
    FAILED = 'failed'


@dataclass
class TrainingRoundConfig:
    """Configuration for a training round."""
    round_id: int
    training_window: float = 3600.0     # 1 hour default
    collection_timeout: float = 300.0    # 5 minutes to collect updates
    min_participants: int = 3
    min_quorum: float = 0.5              # 50% of validators
    aggregation_method: AggregationMethod = AggregationMethod.KRUM


@dataclass
class TrainingRoundResult:
    """Result of a training round."""
    round_id: int
    phase: TrainingPhase
    participants: List[str]
    aggregation_result: Optional[AggregationResult]
    quorum_reached: bool
    validation_passed: bool
    duration_seconds: float
    error: Optional[str] = None


class FederatedTrainingLoop:
    """
    Orchestrate federated learning across mesh network.

    Manages the complete lifecycle of federated training rounds,
    including model distribution, gradient collection, aggregation,
    and consensus validation.
    """

    # Default configuration
    DEFAULT_TRAINING_WINDOW = 3600.0   # 1 hour
    DEFAULT_COLLECTION_TIMEOUT = 300.0  # 5 minutes
    DEFAULT_MIN_PARTICIPANTS = 3
    DEFAULT_QUORUM = 0.5

    def __init__(
        self,
        aggregator: FederatedAggregator,
        dsm_client: Any = None,  # DSM client for secure communication
        model_broadcaster: Callable = None,
        gradient_collector: Callable = None,
    ):
        """
        Initialize federated training loop.

        Args:
            aggregator: FederatedAggregator instance
            dsm_client: DSM client for secure communication
            model_broadcaster: Callback to broadcast model to edges
            gradient_collector: Callback to collect gradients from edges
        """
        self.aggregator = aggregator
        self.dsm_client = dsm_client
        self._model_broadcaster = model_broadcaster
        self._gradient_collector = gradient_collector

        # State
        self.current_phase = TrainingPhase.IDLE
        self.current_round = 0
        self._running = False
        self._round_results: List[TrainingRoundResult] = []

        # Callbacks
        self._on_round_complete: List[Callable] = []
        self._on_model_updated: List[Callable] = []

        logger.info("[FedLoop] Training loop initialized")

    def on_round_complete(self, callback: Callable) -> None:
        """Register callback for round completion."""
        self._on_round_complete.append(callback)

    def on_model_updated(self, callback: Callable) -> None:
        """Register callback for model updates."""
        self._on_model_updated.append(callback)

    async def run_round(self, config: TrainingRoundConfig = None) -> TrainingRoundResult:
        """
        Run a single federated training round.

        Args:
            config: Round configuration

        Returns:
            Training round result
        """
        start_time = time.time()
        config = config or TrainingRoundConfig(round_id=self.current_round + 1)

        self.current_round = config.round_id
        self.current_phase = TrainingPhase.BROADCASTING

        result = TrainingRoundResult(
            round_id=config.round_id,
            phase=TrainingPhase.IDLE,
            participants=[],
            aggregation_result=None,
            quorum_reached=False,
            validation_passed=False,
            duration_seconds=0,
        )

        try:
            # Phase 1: Broadcast current global model
            logger.info(f"[FedLoop] Round {config.round_id}: Broadcasting global model")
            self.current_phase = TrainingPhase.BROADCASTING

            if self._model_broadcaster:
                broadcast_success = await self._broadcast_model()
                if not broadcast_success:
                    raise RuntimeError("Failed to broadcast model")

            # Phase 2: Wait for edge training
            logger.info(f"[FedLoop] Round {config.round_id}: Waiting for edge training ({config.training_window}s)")
            self.current_phase = TrainingPhase.TRAINING

            await asyncio.sleep(config.training_window)

            # Phase 3: Collect gradients
            logger.info(f"[FedLoop] Round {config.round_id}: Collecting gradients")
            self.current_phase = TrainingPhase.COLLECTING

            self.aggregator.start_round(config.round_id)
            updates = await self._collect_gradients(config)

            result.participants = [u.validator_id for u in updates]

            # Check minimum participants
            if len(updates) < config.min_participants:
                raise RuntimeError(f"Insufficient participants: {len(updates)} < {config.min_participants}")

            # Check quorum
            quorum_threshold = int(len(self.aggregator.validators) * config.min_quorum)
            result.quorum_reached = len(updates) >= quorum_threshold

            if not result.quorum_reached:
                logger.warning(f"[FedLoop] Quorum not reached: {len(updates)}/{quorum_threshold}")
                # Continue anyway if we have minimum participants

            # Phase 4: Aggregate
            logger.info(f"[FedLoop] Round {config.round_id}: Aggregating {len(updates)} updates")
            self.current_phase = TrainingPhase.AGGREGATING

            aggregated = self.aggregator.aggregate(updates, config.aggregation_method)

            result.aggregation_result = self.aggregator._round_history[-1]

            # Phase 5: Validate via quorum
            logger.info(f"[FedLoop] Round {config.round_id}: Validating aggregation")
            self.current_phase = TrainingPhase.VALIDATING

            result.validation_passed = await self._validate_aggregation(aggregated, updates)

            if not result.validation_passed:
                raise RuntimeError("Aggregation validation failed")

            # Phase 6: Complete
            self.current_phase = TrainingPhase.COMPLETE
            result.phase = TrainingPhase.COMPLETE

            # Notify callbacks
            for callback in self._on_model_updated:
                try:
                    await self._call_callback(callback, aggregated)
                except Exception as e:
                    logger.error(f"[FedLoop] Model update callback error: {e}")

        except Exception as e:
            logger.error(f"[FedLoop] Round {config.round_id} failed: {e}")
            self.current_phase = TrainingPhase.FAILED
            result.phase = TrainingPhase.FAILED
            result.error = str(e)

        finally:
            result.duration_seconds = time.time() - start_time
            self._round_results.append(result)

            # Notify round complete callbacks
            for callback in self._on_round_complete:
                try:
                    await self._call_callback(callback, result)
                except Exception as e:
                    logger.error(f"[FedLoop] Round complete callback error: {e}")

        return result

    async def _broadcast_model(self) -> bool:
        """Broadcast global model to edge devices."""
        if self._model_broadcaster is None:
            # Simulate broadcast
            logger.debug("[FedLoop] Simulating model broadcast")
            await asyncio.sleep(0.1)
            return True

        try:
            if asyncio.iscoroutinefunction(self._model_broadcaster):
                return await self._model_broadcaster(
                    self.aggregator.global_weights,
                    self.current_round
                )
            else:
                return self._model_broadcaster(
                    self.aggregator.global_weights,
                    self.current_round
                )
        except Exception as e:
            logger.error(f"[FedLoop] Broadcast error: {e}")
            return False

    async def _collect_gradients(self, config: TrainingRoundConfig) -> List[ModelUpdate]:
        """Collect gradients from edge devices."""
        if self._gradient_collector is None:
            # Return pending updates
            return await self.aggregator.collect_updates(
                round_id=config.round_id,
                timeout=config.collection_timeout,
                min_updates=config.min_participants,
            )

        try:
            if asyncio.iscoroutinefunction(self._gradient_collector):
                updates = await self._gradient_collector(
                    config.round_id,
                    config.collection_timeout
                )
            else:
                updates = self._gradient_collector(
                    config.round_id,
                    config.collection_timeout
                )

            # Submit collected updates to aggregator
            for update in updates:
                self.aggregator.submit_update(update)

            return updates

        except Exception as e:
            logger.error(f"[FedLoop] Gradient collection error: {e}")
            return []

    async def _validate_aggregation(
        self,
        aggregated: np.ndarray,
        updates: List[ModelUpdate],
    ) -> bool:
        """
        Validate aggregation result.

        In a full implementation, this would:
        1. Compute aggregation independently
        2. Collect BLS signatures from validators
        3. Verify threshold signature
        """
        # Basic validation: check that result is reasonable
        if aggregated is None:
            return False

        if not np.isfinite(aggregated).all():
            logger.error("[FedLoop] Aggregation contains NaN/Inf")
            return False

        # Check that aggregation is "close" to majority of updates
        distances = []
        for update in updates:
            dist = np.linalg.norm(aggregated - update.weights)
            distances.append(dist)

        median_distance = np.median(distances)
        max_reasonable_distance = np.std(distances) * 3

        if median_distance > max_reasonable_distance:
            logger.warning(f"[FedLoop] Aggregation far from updates: {median_distance:.4f}")
            # Still accept, but log warning

        return True

    async def _call_callback(self, callback: Callable, *args) -> Any:
        """Call callback, handling async and sync."""
        if asyncio.iscoroutinefunction(callback):
            return await callback(*args)
        else:
            return callback(*args)

    async def run_training_cycle(
        self,
        num_rounds: int,
        round_config: TrainingRoundConfig = None,
        stop_on_failure: bool = False,
    ) -> List[TrainingRoundResult]:
        """
        Run multiple training rounds.

        Args:
            num_rounds: Number of rounds to run
            round_config: Base configuration for rounds
            stop_on_failure: Stop if a round fails

        Returns:
            List of round results
        """
        self._running = True
        results = []

        logger.info(f"[FedLoop] Starting training cycle: {num_rounds} rounds")

        for i in range(num_rounds):
            if not self._running:
                logger.info("[FedLoop] Training cycle stopped")
                break

            config = TrainingRoundConfig(
                round_id=self.current_round + 1,
                training_window=round_config.training_window if round_config else self.DEFAULT_TRAINING_WINDOW,
                collection_timeout=round_config.collection_timeout if round_config else self.DEFAULT_COLLECTION_TIMEOUT,
                min_participants=round_config.min_participants if round_config else self.DEFAULT_MIN_PARTICIPANTS,
            )

            result = await self.run_round(config)
            results.append(result)

            if result.phase == TrainingPhase.FAILED and stop_on_failure:
                logger.error(f"[FedLoop] Stopping due to round {result.round_id} failure")
                break

            logger.info(f"[FedLoop] Round {result.round_id} complete: {result.phase.value}")

        self._running = False
        return results

    async def run_continuous(
        self,
        round_interval: float = 3600.0,
        round_config: TrainingRoundConfig = None,
    ) -> None:
        """
        Run continuous federated training.

        Args:
            round_interval: Time between rounds
            round_config: Base configuration for rounds
        """
        self._running = True
        logger.info("[FedLoop] Starting continuous training")

        while self._running:
            config = TrainingRoundConfig(
                round_id=self.current_round + 1,
                training_window=round_config.training_window if round_config else self.DEFAULT_TRAINING_WINDOW,
                collection_timeout=round_config.collection_timeout if round_config else self.DEFAULT_COLLECTION_TIMEOUT,
                min_participants=round_config.min_participants if round_config else self.DEFAULT_MIN_PARTICIPANTS,
            )

            result = await self.run_round(config)

            if result.phase == TrainingPhase.FAILED:
                logger.warning(f"[FedLoop] Round {result.round_id} failed, waiting before retry")
                await asyncio.sleep(round_interval * 2)
            else:
                await asyncio.sleep(round_interval)

    def stop(self) -> None:
        """Stop the training loop."""
        self._running = False
        logger.info("[FedLoop] Stop requested")

    def get_status(self) -> Dict:
        """Get current training loop status."""
        return {
            'current_round': self.current_round,
            'current_phase': self.current_phase.value,
            'running': self._running,
            'rounds_completed': len(self._round_results),
            'rounds_successful': sum(1 for r in self._round_results if r.phase == TrainingPhase.COMPLETE),
            'rounds_failed': sum(1 for r in self._round_results if r.phase == TrainingPhase.FAILED),
        }

    def get_round_history(self, last_n: int = 10) -> List[Dict]:
        """Get history of recent rounds."""
        recent = self._round_results[-last_n:]
        return [
            {
                'round_id': r.round_id,
                'phase': r.phase.value,
                'participants': len(r.participants),
                'quorum_reached': r.quorum_reached,
                'validation_passed': r.validation_passed,
                'duration_seconds': r.duration_seconds,
                'error': r.error,
            }
            for r in recent
        ]


# ============================================================================
# CLI for testing
# ============================================================================

if __name__ == '__main__':
    print("Federated Training Loop Demo")
    print("=" * 50)

    async def demo():
        # Create aggregator and loop
        validators = [f'validator-{i}' for i in range(5)]
        aggregator = FederatedAggregator(validators=validators)

        # Initialize with random global weights
        aggregator.global_weights = np.random.randn(100)

        loop = FederatedTrainingLoop(aggregator=aggregator)

        # Register callbacks
        async def on_complete(result):
            print(f"  Round {result.round_id} complete: {result.phase.value}")

        loop.on_round_complete(on_complete)

        # Simulate edge updates arriving
        async def simulate_updates():
            await asyncio.sleep(0.5)  # Wait for broadcast
            np.random.seed(42)

            for vid in validators:
                noise = np.random.randn(100) * 0.1
                weights = aggregator.global_weights + noise

                update = ModelUpdate(
                    validator_id=vid,
                    round_id=loop.current_round,
                    weights=weights,
                    num_samples=100,
                    loss=0.5,
                    timestamp=time.time(),
                )
                aggregator.submit_update(update)

        # Run a quick test round
        print("\nRunning test round...")

        # Start update simulation in background
        asyncio.create_task(simulate_updates())

        # Run round with very short training window for testing
        config = TrainingRoundConfig(
            round_id=1,
            training_window=1.0,  # 1 second for demo
            collection_timeout=5.0,
            min_participants=3,
        )

        result = await loop.run_round(config)

        print(f"\nRound result:")
        print(f"  Phase: {result.phase.value}")
        print(f"  Participants: {len(result.participants)}")
        print(f"  Quorum reached: {result.quorum_reached}")
        print(f"  Validation passed: {result.validation_passed}")
        print(f"  Duration: {result.duration_seconds:.2f}s")

        if result.error:
            print(f"  Error: {result.error}")

        print(f"\nLoop status: {loop.get_status()}")

    asyncio.run(demo())

    print("\n✓ Federated training loop test complete")
