#!/usr/bin/env python3
"""
Nexus Connector for Globe Visualization

Connects the Nexus product tier (ML/AI compute node with 16GB+ RAM) to the
globe digital twin visualization.

The Nexus is the most powerful edge node, designed for:
- Running full ML models (threat classification, anomaly detection)
- Training federated learning updates
- High-throughput traffic analysis
- Regional mesh coordination

Integration points:
- products/nexus/ - Nexus product
- core/qsecbit/ - Full Qsecbit with ML components
- shared/dnsXai/ - ML DNS classifier
- core/neuro/ - Neural resonance protocol
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

from .base import (
    ProductConnector,
    ConnectorConfig,
    ProductTier,
    ThreatEvent,
)

logger = logging.getLogger(__name__)


@dataclass
class NexusConnectorConfig(ConnectorConfig):
    """Nexus-specific connector configuration."""

    tier: ProductTier = field(default=ProductTier.NEXUS)

    # Nexus-specific settings
    ml_models: List[str] = field(default_factory=lambda: [
        "threat_classifier",
        "anomaly_detector",
        "dnsxai_classifier",
    ])
    federated_learning_enabled: bool = True
    neuro_protocol_enabled: bool = True
    dsm_validator: bool = True        # Full DSM validator

    # Resource allocation
    max_memory_mb: int = 16384        # 16GB+
    gpu_enabled: bool = False
    ml_thread_count: int = 4

    # Coordination
    subordinate_fortresses: List[str] = field(default_factory=list)

    # Heartbeat (Nexus is datacenter-class, very stable)
    heartbeat_interval: float = 60.0  # 1 minute
    qsecbit_report_interval: float = 10.0


class NexusConnector(ProductConnector):
    """
    Connector for Nexus tier products.

    The Nexus (16GB+ RAM) is the ML/AI compute node that:
    - Runs sophisticated threat detection models
    - Coordinates federated learning across the mesh
    - Participates in Neural Resonance Protocol
    - Acts as a full DSM validator

    Globe visualization shows:
    - Largest node size (1.2 radius)
    - Neural network visual effect
    - Federated learning status
    - Regional coordination boundaries
    """

    def __init__(self, config: NexusConnectorConfig):
        super().__init__(config)
        self.nexus_config = config

        # Nexus-specific state
        self._ml_models_status: Dict[str, Dict[str, Any]] = {}
        self._federated_learning = {
            "rounds_participated": 0,
            "last_aggregation": None,
            "peers_contributed": 0,
        }
        self._neuro_state = {
            "resonance_score": 0.0,
            "weight_version": 0,
            "sync_peers": 0,
        }
        self._subordinate_fortresses: Dict[str, Dict[str, Any]] = {}
        self._inference_stats = {
            "total": 0,
            "by_model": {},
            "avg_latency_ms": 0.0,
        }

    async def collect_qsecbit(self) -> float:
        """Collect Qsecbit from ML-enhanced Qsecbit calculator."""
        try:
            from core.qsecbit.qsecbit import QsecbitCalculator
            calculator = QsecbitCalculator(
                ml_enabled=True,
                energy_monitoring=True,
            )
            return calculator.calculate()
        except ImportError:
            pass
        except Exception as e:
            logger.error(f"Qsecbit calculation failed: {e}")

        return self._estimate_qsecbit()

    async def collect_qsecbit_components(self) -> Dict[str, float]:
        """Collect detailed Qsecbit components including ML metrics."""
        try:
            from core.qsecbit.qsecbit import QsecbitCalculator
            calculator = QsecbitCalculator(ml_enabled=True)
            components = calculator.get_components()

            # Add Nexus-specific components
            components["federated_learning"] = (
                0.05 if self._federated_learning["rounds_participated"] > 0 else 0.0
            )
            components["neuro_resonance"] = self._neuro_state["resonance_score"] * 0.1

            return components
        except ImportError:
            pass
        except Exception:
            pass

        return {
            "threats": 0.0,
            "ml_anomaly": 0.0,
            "network": 0.0,
            "ids": 0.0,
            "xdp": 0.0,
            "dnsxai": 0.0,
            "energy": 0.0,
            "federated_learning": 0.0,
            "neuro_resonance": 0.0,
        }

    async def collect_statistics(self) -> Dict[str, Any]:
        """Collect Nexus-specific statistics."""
        stats = {
            "ml_models_loaded": len(self._ml_models_status),
            "ml_models_status": self._ml_models_status,
            "inference_total": self._inference_stats["total"],
            "inference_avg_latency_ms": self._inference_stats["avg_latency_ms"],
            "federated_learning": self._federated_learning,
            "neuro_state": self._neuro_state,
            "subordinate_fortresses": len(self._subordinate_fortresses),
            "gpu_enabled": self.nexus_config.gpu_enabled,
            "max_memory_mb": self.nexus_config.max_memory_mb,
        }

        self.state.metadata = {
            "product": "nexus",
            "version": "5.0",
            "capabilities": {
                "ml_models": self.nexus_config.ml_models,
                "federated_learning": self.nexus_config.federated_learning_enabled,
                "neuro_protocol": self.nexus_config.neuro_protocol_enabled,
                "dsm_validator": self.nexus_config.dsm_validator,
                "gpu": self.nexus_config.gpu_enabled,
            },
            **stats,
        }

        return stats

    async def get_recent_threats(self) -> List[ThreatEvent]:
        """Get ML-detected threats from Nexus."""
        threats = []

        # Check ML models for detected threats
        for model_name, model_status in self._ml_models_status.items():
            if "recent_detections" in model_status:
                for detection in model_status["recent_detections"]:
                    threats.append(ThreatEvent(
                        source_ip=detection.get("source_ip", ""),
                        attack_type=f"ml_{model_name}",
                        severity=detection.get("confidence", 0.5),
                        description=detection.get("classification", ""),
                        timestamp=datetime.fromisoformat(detection["timestamp"])
                        if "timestamp" in detection else None,
                    ))

        return threats

    def _estimate_qsecbit(self) -> float:
        """Estimate Qsecbit based on Nexus state."""
        base = 0.1  # Nexus baseline is very low (well-protected)

        # Factor in ML model health
        model_health = 0.0
        for status in self._ml_models_status.values():
            if status.get("healthy", False):
                model_health += 0.01

        # Factor in federated learning activity
        fl_factor = 0.05 if self._federated_learning["rounds_participated"] > 0 else 0.0

        # Factor in neural resonance
        neuro_factor = (1.0 - self._neuro_state["resonance_score"]) * 0.1

        return min(1.0, base + model_health + fl_factor + neuro_factor)

    # =========================================================================
    # Nexus-specific methods
    # =========================================================================

    def register_ml_model(self, model_name: str, status: Dict[str, Any]) -> None:
        """Register an ML model's status."""
        self._ml_models_status[model_name] = {
            "loaded": True,
            "healthy": True,
            "last_inference": None,
            "recent_detections": [],
            **status,
        }

    def report_inference(self, model_name: str, latency_ms: float, result: Dict[str, Any]) -> None:
        """Report an ML inference result."""
        self._inference_stats["total"] += 1
        self._inference_stats["by_model"][model_name] = (
            self._inference_stats["by_model"].get(model_name, 0) + 1
        )

        # Update rolling average latency
        current_avg = self._inference_stats["avg_latency_ms"]
        total = self._inference_stats["total"]
        self._inference_stats["avg_latency_ms"] = (
            (current_avg * (total - 1) + latency_ms) / total
        )

        if model_name in self._ml_models_status:
            self._ml_models_status[model_name]["last_inference"] = datetime.utcnow()

    def report_federated_round(self, round_id: int, peers: int) -> None:
        """Report participation in a federated learning round."""
        self._federated_learning["rounds_participated"] += 1
        self._federated_learning["last_aggregation"] = datetime.utcnow()
        self._federated_learning["peers_contributed"] = peers

    def update_neuro_state(self, resonance: float, weight_version: int, peers: int) -> None:
        """Update Neural Resonance Protocol state."""
        self._neuro_state["resonance_score"] = resonance
        self._neuro_state["weight_version"] = weight_version
        self._neuro_state["sync_peers"] = peers

    def register_fortress(self, fortress_id: str, state: Dict[str, Any]) -> None:
        """Register a subordinate Fortress."""
        self._subordinate_fortresses[fortress_id] = {
            "state": state,
            "last_seen": datetime.utcnow(),
        }


def create_nexus_connector(
    node_id: str,
    lat: float,
    lng: float,
    label: str = "",
    **kwargs
) -> NexusConnector:
    """Factory function to create a Nexus connector."""
    config = NexusConnectorConfig(
        node_id=node_id,
        lat=lat,
        lng=lng,
        label=label or f"Nexus {node_id}",
        **kwargs
    )
    return NexusConnector(config)
