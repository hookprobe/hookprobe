"""
Federated Learning Participant

Each mesh node runs a FederatedParticipant that:
1. Computes local weight updates from training data
2. Applies differential privacy (clip + noise)
3. Quantizes to int8 for bandwidth efficiency
4. Receives global updates and applies them locally
"""

import hashlib
import logging
import math
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .model_registry import ModelType
from .privacy import DifferentialPrivacy

logger = logging.getLogger(__name__)


@dataclass
class LocalUpdate:
    """A local model update ready for transmission to the aggregation server."""

    model_type: ModelType
    base_version: int
    weight_delta: List[float]  # difference from global weights
    num_samples: int  # local training samples used
    node_id: str = ""
    timestamp: float = field(default_factory=time.time)
    quantized: bool = False

    def to_bytes(self) -> bytes:
        """Serialize for mesh transport."""
        header = {
            "model_type": self.model_type.value,
            "base_version": self.base_version,
            "num_samples": self.num_samples,
            "node_id": self.node_id,
            "timestamp": self.timestamp,
            "quantized": self.quantized,
            "weight_count": len(self.weight_delta),
        }
        import json
        header_bytes = json.dumps(header).encode("utf-8")
        header_len = struct.pack(">I", len(header_bytes))

        if self.quantized:
            weight_bytes = self._pack_int8(self.weight_delta)
        else:
            weight_bytes = struct.pack(f">{len(self.weight_delta)}f", *self.weight_delta)

        return header_len + header_bytes + weight_bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "LocalUpdate":
        """Deserialize from mesh transport."""
        import json
        header_len = struct.unpack(">I", data[:4])[0]
        header = json.loads(data[4:4 + header_len].decode("utf-8"))

        weight_data = data[4 + header_len:]
        weight_count = header["weight_count"]

        if header.get("quantized", False):
            weight_delta = cls._unpack_int8(weight_data, weight_count)
        else:
            weight_delta = list(struct.unpack(f">{weight_count}f", weight_data))

        return cls(
            model_type=ModelType(header["model_type"]),
            base_version=header["base_version"],
            weight_delta=weight_delta,
            num_samples=header["num_samples"],
            node_id=header.get("node_id", ""),
            timestamp=header.get("timestamp", time.time()),
            quantized=header.get("quantized", False),
        )

    def _pack_int8(self, weights: List[float]) -> bytes:
        """Pack float weights to int8 with scale factor."""
        if not weights:
            return struct.pack(">f", 0.0)
        max_abs = max(abs(w) for w in weights)
        scale = max_abs / 127.0 if max_abs > 0 else 1.0
        quantized = [max(-127, min(127, int(round(w / scale)))) for w in weights]
        return struct.pack(">f", scale) + struct.pack(f">{len(quantized)}b", *quantized)

    @staticmethod
    def _unpack_int8(data: bytes, count: int) -> List[float]:
        """Unpack int8 weights back to float."""
        scale = struct.unpack(">f", data[:4])[0]
        ints = struct.unpack(f">{count}b", data[4:4 + count])
        return [i * scale for i in ints]


class FederatedParticipant:
    """Mesh node participant in federated learning.

    Manages local training, privacy-preserving updates, int8 quantization,
    and global weight application. Works with any model type registered
    in the FederatedModelRegistry.
    """

    def __init__(
        self,
        node_id: str,
        privacy: Optional[DifferentialPrivacy] = None,
        quantize: bool = True,
        min_samples: int = 10,
    ):
        self.node_id = node_id
        self.privacy = privacy or DifferentialPrivacy()
        self.quantize = quantize
        self.min_samples = min_samples

        # Local weights per model type
        self._local_weights: Dict[ModelType, List[float]] = {}
        self._base_versions: Dict[ModelType, int] = {}
        self._sample_counts: Dict[ModelType, int] = {}

        # Stats
        self._updates_sent = 0
        self._updates_received = 0

    def set_local_weights(
        self,
        model_type: ModelType,
        weights: List[float],
        version: int,
    ):
        """Set local weights (usually from global model download)."""
        self._local_weights[model_type] = list(weights)
        self._base_versions[model_type] = version
        self._sample_counts[model_type] = 0

    def record_training(self, model_type: ModelType, num_samples: int):
        """Record that local training occurred with N samples."""
        self._sample_counts[model_type] = (
            self._sample_counts.get(model_type, 0) + num_samples
        )

    def compute_local_update(
        self,
        model_type: ModelType,
        trained_weights: List[float],
        num_samples: Optional[int] = None,
    ) -> Optional[LocalUpdate]:
        """Compute a privacy-preserving local update.

        Args:
            model_type: Which model was trained.
            trained_weights: Weights after local training.
            num_samples: Training samples used (overrides recorded count).

        Returns:
            LocalUpdate ready for transmission, or None if insufficient data.
        """
        base_weights = self._local_weights.get(model_type)
        if base_weights is None:
            logger.warning("No base weights for %s — call set_local_weights first", model_type.value)
            return None

        if len(trained_weights) != len(base_weights):
            logger.error(
                "Weight count mismatch for %s: base=%d, trained=%d",
                model_type.value, len(base_weights), len(trained_weights),
            )
            return None

        samples = num_samples or self._sample_counts.get(model_type, 0)
        if samples < self.min_samples:
            logger.info(
                "Insufficient samples for %s: %d < %d",
                model_type.value, samples, self.min_samples,
            )
            return None

        # Compute delta
        delta = [t - b for t, b in zip(trained_weights, base_weights)]

        # Apply differential privacy
        private_delta = self.privacy.privatize_update(
            delta, sample_rate=min(1.0, samples / 1000.0),
        )
        if private_delta is None:
            logger.warning("Privacy budget exhausted for %s", model_type.value)
            return None

        update = LocalUpdate(
            model_type=model_type,
            base_version=self._base_versions.get(model_type, 0),
            weight_delta=private_delta,
            num_samples=samples,
            node_id=self.node_id,
            quantized=False,
        )

        # Quantize for bandwidth
        if self.quantize:
            update = self._quantize_update(update)

        self._updates_sent += 1
        return update

    def apply_global_update(
        self,
        model_type: ModelType,
        global_weights: List[float],
        new_version: int,
    ) -> bool:
        """Apply a new global model received from the aggregation server.

        Validates version progression before applying.
        """
        current_version = self._base_versions.get(model_type, 0)
        if new_version <= current_version:
            logger.warning(
                "Stale global update for %s: v%d <= v%d",
                model_type.value, new_version, current_version,
            )
            return False

        expected_count = len(self._local_weights.get(model_type, []))
        if expected_count > 0 and len(global_weights) != expected_count:
            logger.error(
                "Weight count mismatch in global update for %s: %d != %d",
                model_type.value, len(global_weights), expected_count,
            )
            return False

        self._local_weights[model_type] = list(global_weights)
        self._base_versions[model_type] = new_version
        self._sample_counts[model_type] = 0
        self._updates_received += 1

        logger.info(
            "Applied global update for %s: v%d → v%d",
            model_type.value, current_version, new_version,
        )
        return True

    def _quantize_update(self, update: LocalUpdate) -> LocalUpdate:
        """Quantize weight delta to int8 for bandwidth reduction."""
        if not update.weight_delta:
            return update

        max_abs = max(abs(w) for w in update.weight_delta)
        if max_abs == 0:
            return update

        scale = max_abs / 127.0
        quantized = [round(w / scale) * scale for w in update.weight_delta]

        return LocalUpdate(
            model_type=update.model_type,
            base_version=update.base_version,
            weight_delta=quantized,
            num_samples=update.num_samples,
            node_id=update.node_id,
            timestamp=update.timestamp,
            quantized=True,
        )

    def get_stats(self) -> dict:
        return {
            "node_id": self.node_id,
            "models_loaded": list(mt.value for mt in self._local_weights.keys()),
            "updates_sent": self._updates_sent,
            "updates_received": self._updates_received,
            "quantization_enabled": self.quantize,
            "privacy": self.privacy.get_stats(),
        }
