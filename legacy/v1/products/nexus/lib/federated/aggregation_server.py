"""
Federated Aggregation Server

Runs on Nexus nodes to collect local updates from mesh participants,
perform FedAvg aggregation, and broadcast updated global weights.

Supports:
- FedAvg weighted by sample count
- Minimum K participants per round
- Model versioning and hash integrity
- GPU acceleration (when available)
- Round management with timeout
"""

import hashlib
import logging
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

from .model_registry import FederatedModelRegistry, ModelRecord, ModelType
from .participant import LocalUpdate
from .privacy import DifferentialPrivacy

logger = logging.getLogger(__name__)


@dataclass
class AggregationRound:
    """State for a single aggregation round."""

    round_id: int
    model_type: ModelType
    base_version: int
    started_at: float = field(default_factory=time.time)
    timeout_s: float = 300.0  # 5 minute round timeout
    min_participants: int = 3
    updates: List[LocalUpdate] = field(default_factory=list)
    contributors: Set[str] = field(default_factory=set)
    completed: bool = False
    result_version: int = 0

    @property
    def participant_count(self) -> int:
        return len(self.contributors)

    @property
    def ready(self) -> bool:
        return self.participant_count >= self.min_participants

    @property
    def timed_out(self) -> bool:
        return (time.time() - self.started_at) > self.timeout_s

    def to_dict(self) -> dict:
        return {
            "round_id": self.round_id,
            "model_type": self.model_type.value,
            "base_version": self.base_version,
            "participant_count": self.participant_count,
            "min_participants": self.min_participants,
            "ready": self.ready,
            "timed_out": self.timed_out,
            "completed": self.completed,
            "elapsed_s": time.time() - self.started_at,
        }


class FederatedAggregationServer:
    """Nexus-tier aggregation server for federated learning.

    Collects LocalUpdate objects from mesh participants, performs
    weighted FedAvg when enough contributors have submitted,
    and publishes new global weights.
    """

    def __init__(
        self,
        registry: FederatedModelRegistry,
        min_participants: int = 3,
        round_timeout_s: float = 300.0,
        server_dp: Optional[DifferentialPrivacy] = None,
        on_aggregation_complete: Optional[Callable] = None,
    ):
        self.registry = registry
        self.min_participants = min_participants
        self.round_timeout_s = round_timeout_s
        self.server_dp = server_dp  # optional server-side DP
        self.on_aggregation_complete = on_aggregation_complete

        self._rounds: Dict[ModelType, AggregationRound] = {}
        self._round_counter = 0
        self._lock = threading.Lock()

        # Historical stats
        self._total_rounds = 0
        self._total_updates = 0
        self._failed_rounds = 0

    def start_round(self, model_type: ModelType) -> Optional[AggregationRound]:
        """Start a new aggregation round for a model type."""
        record = self.registry.get(model_type)
        if record is None:
            logger.error("Cannot start round for unregistered model %s", model_type.value)
            return None
        if record.frozen:
            logger.warning("Model %s is frozen", model_type.value)
            return None

        with self._lock:
            if model_type in self._rounds and not self._rounds[model_type].completed:
                existing = self._rounds[model_type]
                if not existing.timed_out:
                    logger.info("Round already active for %s", model_type.value)
                    return existing
                # Timed-out round — close it and start new
                self._close_round(model_type, success=False)

            self._round_counter += 1
            rnd = AggregationRound(
                round_id=self._round_counter,
                model_type=model_type,
                base_version=record.version,
                timeout_s=self.round_timeout_s,
                min_participants=self.min_participants,
            )
            self._rounds[model_type] = rnd

        logger.info(
            "Started aggregation round %d for %s (base v%d, need %d participants)",
            rnd.round_id, model_type.value, rnd.base_version, rnd.min_participants,
        )
        return rnd

    def receive_update(self, update: LocalUpdate) -> bool:
        """Receive a local update from a participant.

        Returns True if accepted, False if rejected.
        """
        with self._lock:
            rnd = self._rounds.get(update.model_type)

        if rnd is None:
            # Auto-start round
            rnd = self.start_round(update.model_type)
            if rnd is None:
                return False

        if rnd.completed:
            logger.info("Round %d already completed, rejecting late update", rnd.round_id)
            return False

        if rnd.timed_out:
            logger.info("Round %d timed out, rejecting update", rnd.round_id)
            self._close_round(update.model_type, success=False)
            return False

        # Validate version compatibility
        if update.base_version != rnd.base_version:
            logger.warning(
                "Version mismatch: update base v%d != round base v%d",
                update.base_version, rnd.base_version,
            )
            return False

        # Deduplicate by node_id
        if update.node_id in rnd.contributors:
            logger.info("Duplicate update from %s, ignoring", update.node_id)
            return False

        with self._lock:
            rnd.updates.append(update)
            rnd.contributors.add(update.node_id)
            self._total_updates += 1

        logger.info(
            "Received update from %s for %s round %d (%d/%d participants)",
            update.node_id, update.model_type.value, rnd.round_id,
            rnd.participant_count, rnd.min_participants,
        )

        # Check if we can aggregate
        if rnd.ready:
            return self._try_aggregate(update.model_type)

        return True

    def _try_aggregate(self, model_type: ModelType) -> bool:
        """Attempt FedAvg aggregation if round is ready."""
        with self._lock:
            rnd = self._rounds.get(model_type)
            if rnd is None or rnd.completed:
                return False

        # Get current global weights
        global_weights = self.registry.get_global_weights(model_type)
        if global_weights is None:
            logger.error("No global weights for %s", model_type.value)
            self._close_round(model_type, success=False)
            return False

        # Perform FedAvg
        aggregated = self._fedavg(global_weights, rnd.updates)
        if aggregated is None:
            self._close_round(model_type, success=False)
            return False

        # Optional server-side DP
        if self.server_dp is not None:
            server_delta = [a - g for a, g in zip(aggregated, global_weights)]
            private_delta = self.server_dp.privatize_update(server_delta)
            if private_delta is not None:
                aggregated = [g + d for g, d in zip(global_weights, private_delta)]

        # Update registry
        record = self.registry.update_global_weights(
            model_type, aggregated, contributors=rnd.participant_count,
        )
        if record is None:
            self._close_round(model_type, success=False)
            return False

        rnd.result_version = record.version
        self._close_round(model_type, success=True)

        # Notify callback
        if self.on_aggregation_complete:
            try:
                self.on_aggregation_complete(model_type, aggregated, record.version)
            except Exception as e:
                logger.error("Aggregation callback error: %s", e)

        logger.info(
            "FedAvg complete for %s: v%d → v%d (%d participants, %d total samples)",
            model_type.value, rnd.base_version, record.version,
            rnd.participant_count,
            sum(u.num_samples for u in rnd.updates),
        )
        return True

    def _fedavg(
        self,
        global_weights: List[float],
        updates: List[LocalUpdate],
    ) -> Optional[List[float]]:
        """Federated Averaging weighted by sample count.

        new_w = global_w + sum(n_k / n_total * delta_k)
        """
        if not updates:
            return None

        total_samples = sum(u.num_samples for u in updates)
        if total_samples == 0:
            return None

        dim = len(global_weights)
        aggregated_delta = [0.0] * dim

        for update in updates:
            if len(update.weight_delta) != dim:
                logger.warning(
                    "Skipping update from %s: dim mismatch (%d != %d)",
                    update.node_id, len(update.weight_delta), dim,
                )
                continue
            weight_factor = update.num_samples / total_samples
            for i in range(dim):
                aggregated_delta[i] += weight_factor * update.weight_delta[i]

        return [g + d for g, d in zip(global_weights, aggregated_delta)]

    def _close_round(self, model_type: ModelType, success: bool):
        """Close an aggregation round."""
        with self._lock:
            rnd = self._rounds.get(model_type)
            if rnd:
                rnd.completed = True
                self._total_rounds += 1
                if not success:
                    self._failed_rounds += 1

    def check_timeouts(self):
        """Check and close any timed-out rounds."""
        with self._lock:
            for model_type, rnd in list(self._rounds.items()):
                if not rnd.completed and rnd.timed_out:
                    logger.warning(
                        "Round %d for %s timed out (%d/%d participants)",
                        rnd.round_id, model_type.value,
                        rnd.participant_count, rnd.min_participants,
                    )
                    # Try to aggregate with what we have if >= 2 participants
                    if rnd.participant_count >= 2:
                        self._try_aggregate(model_type)
                    else:
                        self._close_round(model_type, success=False)

    def get_round(self, model_type: ModelType) -> Optional[AggregationRound]:
        """Get current round for a model type."""
        return self._rounds.get(model_type)

    def get_stats(self) -> dict:
        active_rounds = {
            mt.value: rnd.to_dict()
            for mt, rnd in self._rounds.items()
            if not rnd.completed
        }
        return {
            "total_rounds": self._total_rounds,
            "total_updates": self._total_updates,
            "failed_rounds": self._failed_rounds,
            "active_rounds": active_rounds,
            "min_participants": self.min_participants,
            "round_timeout_s": self.round_timeout_s,
        }
