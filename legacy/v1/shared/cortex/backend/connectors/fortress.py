#!/usr/bin/env python3
"""
Fortress Connector for Globe Visualization

Connects the Fortress product tier (edge router with 4GB RAM) to the globe
digital twin visualization.

The Fortress is a higher-capacity edge router that can:
- Handle multiple upstream connections (WAN failover)
- Run more intensive ML models
- Coordinate multiple Guardian devices
- Participate in DSM consensus

Integration points:
- products/fortress/setup.sh - Fortress setup
- core/qsecbit/ - Full Qsecbit implementation
- shared/dsm/ - DSM consensus participation
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
class FortressConnectorConfig(ConnectorConfig):
    """Fortress-specific connector configuration."""

    tier: ProductTier = field(default=ProductTier.FORTRESS)

    # Fortress-specific settings
    dsm_enabled: bool = True          # DSM consensus participation
    ml_models_enabled: bool = True    # Local ML threat detection
    wan_failover_enabled: bool = True # Multiple uplinks

    # Network interfaces
    wan_interfaces: List[str] = field(default_factory=lambda: ["eth0", "eth1"])
    lan_interfaces: List[str] = field(default_factory=lambda: ["eth2", "wlan0"])

    # Subordinate Guardians (Fortress coordinates these)
    guardian_endpoints: List[str] = field(default_factory=list)

    # Heartbeat (Fortress is stationary, less frequent)
    heartbeat_interval: float = 30.0
    qsecbit_report_interval: float = 10.0

    # Resource allocation
    max_memory_mb: int = 4096
    ml_thread_count: int = 2


class FortressConnector(ProductConnector):
    """
    Connector for Fortress tier products.

    The Fortress (4GB RAM) is an edge router that:
    - Has higher processing capacity than Guardian
    - Can coordinate multiple Guardians in a home/office
    - Participates in DSM consensus
    - Runs more sophisticated ML models

    Globe visualization shows:
    - Larger node size (0.8 radius)
    - Network of connected Guardians
    - Higher throughput statistics
    - DSM consensus participation indicator
    """

    def __init__(self, config: FortressConnectorConfig):
        super().__init__(config)
        self.fortress_config = config

        # Fortress-specific state
        self._subordinate_guardians: Dict[str, Dict[str, Any]] = {}
        self._dsm_participation = {
            "active": False,
            "last_consensus": None,
            "blocks_validated": 0,
        }
        self._wan_status: Dict[str, bool] = {}
        self._ml_inference_count = 0
        self._throughput_mbps = 0.0

    async def collect_qsecbit(self) -> float:
        """Collect Qsecbit from local Qsecbit calculator."""
        try:
            # Import Qsecbit calculator
            from core.qsecbit.qsecbit import QsecbitCalculator
            calculator = QsecbitCalculator()
            return calculator.calculate()
        except ImportError:
            pass
        except Exception as e:
            logger.error(f"Qsecbit calculation failed: {e}")

        # Fallback estimation
        return self._estimate_qsecbit()

    async def collect_qsecbit_components(self) -> Dict[str, float]:
        """Collect Qsecbit component breakdown."""
        try:
            from core.qsecbit.qsecbit import QsecbitCalculator
            calculator = QsecbitCalculator()
            return calculator.get_components()
        except ImportError:
            pass
        except Exception:
            pass

        # Return Fortress-typical components
        return {
            "threats": 0.0,
            "network": 0.0,
            "ids": 0.0,
            "xdp": 0.0,
            "dnsxai": 0.0,
            "dsm": 0.0 if not self._dsm_participation["active"] else 0.1,
        }

    async def collect_statistics(self) -> Dict[str, Any]:
        """Collect Fortress-specific statistics."""
        stats = {
            "subordinate_guardians": len(self._subordinate_guardians),
            "dsm_active": self._dsm_participation["active"],
            "dsm_blocks_validated": self._dsm_participation["blocks_validated"],
            "wan_interfaces": self.fortress_config.wan_interfaces,
            "wan_status": self._wan_status,
            "ml_inferences": self._ml_inference_count,
            "throughput_mbps": self._throughput_mbps,
            "max_memory_mb": self.fortress_config.max_memory_mb,
        }

        self.state.metadata = {
            "product": "fortress",
            "version": "5.0",
            "capabilities": {
                "dsm": self.fortress_config.dsm_enabled,
                "ml": self.fortress_config.ml_models_enabled,
                "wan_failover": self.fortress_config.wan_failover_enabled,
            },
            **stats,
        }

        return stats

    async def get_recent_threats(self) -> List[ThreatEvent]:
        """Get recent threats from Fortress and subordinate Guardians."""
        threats = []

        # Collect threats from subordinate Guardians
        for guardian_id, guardian_state in self._subordinate_guardians.items():
            if "recent_threats" in guardian_state:
                for t in guardian_state["recent_threats"]:
                    t["source_label"] = f"via {guardian_id}"
                    threats.append(ThreatEvent(**t))

        return threats

    def _estimate_qsecbit(self) -> float:
        """Estimate Qsecbit based on Fortress state."""
        base = 0.15

        # Factor in DSM participation
        if self._dsm_participation["active"]:
            base += 0.05

        # Factor in connected Guardians (more = more attack surface)
        guardian_factor = min(0.2, len(self._subordinate_guardians) * 0.03)

        return min(1.0, base + guardian_factor)

    # =========================================================================
    # Fortress-specific methods
    # =========================================================================

    def register_guardian(self, guardian_id: str, state: Dict[str, Any]) -> None:
        """Register a subordinate Guardian."""
        self._subordinate_guardians[guardian_id] = {
            "state": state,
            "last_seen": datetime.utcnow(),
            "recent_threats": [],
        }
        logger.info(f"Guardian {guardian_id} registered with Fortress {self.config.node_id}")

    def update_guardian_state(self, guardian_id: str, state: Dict[str, Any]) -> None:
        """Update state of a subordinate Guardian."""
        if guardian_id in self._subordinate_guardians:
            self._subordinate_guardians[guardian_id]["state"] = state
            self._subordinate_guardians[guardian_id]["last_seen"] = datetime.utcnow()

    def report_dsm_consensus(self, block_hash: str) -> None:
        """Report participation in DSM consensus."""
        self._dsm_participation["active"] = True
        self._dsm_participation["last_consensus"] = datetime.utcnow()
        self._dsm_participation["blocks_validated"] += 1

    def update_wan_status(self, interface: str, online: bool) -> None:
        """Update WAN interface status."""
        self._wan_status[interface] = online

    def report_ml_inference(self, model_name: str, result: Dict[str, Any]) -> None:
        """Report an ML inference result."""
        self._ml_inference_count += 1


def create_fortress_connector(
    node_id: str,
    lat: float,
    lng: float,
    label: str = "",
    **kwargs
) -> FortressConnector:
    """Factory function to create a Fortress connector."""
    config = FortressConnectorConfig(
        node_id=node_id,
        lat=lat,
        lng=lng,
        label=label or f"Fortress {node_id}",
        **kwargs
    )
    return FortressConnector(config)
