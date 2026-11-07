"""
Federated Model Registry

Tracks model types, versions, hashes, and update counts for all
federated-learning-capable models across the HookProbe mesh.
"""

import hashlib
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ModelType(Enum):
    """Supported federated model types."""

    DNSXAI_CLASSIFIER = "dnsxai_classifier"
    SIA_GRAPH_EMBEDDER = "sia_graph_embedder"
    SIA_INTENT_DECODER = "sia_intent_decoder"
    QSECBIT_ML = "qsecbit_ml"
    BEHAVIORAL_CLUSTERING = "behavioral_clustering"


@dataclass
class ModelRecord:
    """Metadata for a registered federated model."""

    model_type: ModelType
    version: int = 0
    weight_hash: str = ""
    weight_count: int = 0  # number of scalar weights
    update_count: int = 0
    contributors: int = 0  # nodes that contributed to current version
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    frozen: bool = False  # if True, no further updates accepted

    def bump_version(self, weight_hash: str, contributors: int):
        """Advance to a new global version after aggregation."""
        self.version += 1
        self.weight_hash = weight_hash
        self.update_count += 1
        self.contributors = contributors
        self.updated_at = time.time()

    def to_dict(self) -> dict:
        return {
            "model_type": self.model_type.value,
            "version": self.version,
            "weight_hash": self.weight_hash,
            "weight_count": self.weight_count,
            "update_count": self.update_count,
            "contributors": self.contributors,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "frozen": self.frozen,
        }


class FederatedModelRegistry:
    """Central registry of all federated models.

    Provides version tracking, hash validation, and model lifecycle
    management for the aggregation server and participants.
    """

    def __init__(self):
        self._models: Dict[ModelType, ModelRecord] = {}
        self._global_weights: Dict[ModelType, List[float]] = {}

    def register(
        self,
        model_type: ModelType,
        initial_weights: Optional[List[float]] = None,
    ) -> ModelRecord:
        """Register a new model type for federated learning."""
        if model_type in self._models:
            logger.warning("Model %s already registered, returning existing", model_type.value)
            return self._models[model_type]

        weight_hash = ""
        weight_count = 0
        if initial_weights is not None:
            weight_hash = self._hash_weights(initial_weights)
            weight_count = len(initial_weights)
            self._global_weights[model_type] = list(initial_weights)

        record = ModelRecord(
            model_type=model_type,
            version=1 if initial_weights else 0,
            weight_hash=weight_hash,
            weight_count=weight_count,
        )
        self._models[model_type] = record
        logger.info(
            "Registered model %s (v%d, %d weights)",
            model_type.value, record.version, weight_count,
        )
        return record

    def get(self, model_type: ModelType) -> Optional[ModelRecord]:
        """Get model record by type."""
        return self._models.get(model_type)

    def get_global_weights(self, model_type: ModelType) -> Optional[List[float]]:
        """Get current global weights for a model."""
        return self._global_weights.get(model_type)

    def update_global_weights(
        self,
        model_type: ModelType,
        weights: List[float],
        contributors: int,
    ) -> Optional[ModelRecord]:
        """Store new global weights after aggregation round."""
        record = self._models.get(model_type)
        if record is None:
            logger.error("Cannot update unregistered model %s", model_type.value)
            return None
        if record.frozen:
            logger.warning("Model %s is frozen, rejecting update", model_type.value)
            return None

        weight_hash = self._hash_weights(weights)
        record.bump_version(weight_hash, contributors)
        record.weight_count = len(weights)
        self._global_weights[model_type] = list(weights)

        logger.info(
            "Updated model %s to v%d (%d contributors, hash=%s…)",
            model_type.value, record.version, contributors, weight_hash[:12],
        )
        return record

    def validate_update(
        self,
        model_type: ModelType,
        expected_version: int,
        weight_count: int,
    ) -> bool:
        """Validate that an incoming update is compatible."""
        record = self._models.get(model_type)
        if record is None:
            return False
        if record.frozen:
            return False
        if record.version != expected_version:
            logger.warning(
                "Version mismatch for %s: expected %d, got %d",
                model_type.value, record.version, expected_version,
            )
            return False
        if record.weight_count > 0 and weight_count != record.weight_count:
            logger.warning(
                "Weight count mismatch for %s: expected %d, got %d",
                model_type.value, record.weight_count, weight_count,
            )
            return False
        return True

    def freeze(self, model_type: ModelType):
        """Freeze a model to prevent further updates."""
        record = self._models.get(model_type)
        if record:
            record.frozen = True
            logger.info("Froze model %s at v%d", model_type.value, record.version)

    def unfreeze(self, model_type: ModelType):
        """Unfreeze a model to allow updates."""
        record = self._models.get(model_type)
        if record:
            record.frozen = False

    def list_models(self) -> List[dict]:
        """List all registered models."""
        return [r.to_dict() for r in self._models.values()]

    def get_stats(self) -> dict:
        return {
            "registered_models": len(self._models),
            "total_updates": sum(r.update_count for r in self._models.values()),
            "frozen_models": sum(1 for r in self._models.values() if r.frozen),
            "models": {mt.value: r.to_dict() for mt, r in self._models.items()},
        }

    @staticmethod
    def _hash_weights(weights: List[float]) -> str:
        """SHA-256 hash of weight vector for integrity checking."""
        import struct
        raw = struct.pack(f">{len(weights)}f", *weights)
        return hashlib.sha256(raw).hexdigest()
