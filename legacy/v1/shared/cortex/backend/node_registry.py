#!/usr/bin/env python3
"""
Node Registry - Digital Twin State Management

Maintains the state of all mesh nodes for the globe visualization.
Each node has a "twin" representation with geographic, health, and liveness data.

This is the source of truth for what the browser sees.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from enum import Enum

logger = logging.getLogger(__name__)


class NodeTier(Enum):
    """HookProbe node tiers."""
    SENTINEL = "sentinel"
    GUARDIAN = "guardian"
    FORTRESS = "fortress"
    NEXUS = "nexus"


class QsecbitStatus(Enum):
    """Qsecbit RAG status."""
    GREEN = "green"    # < 0.45
    AMBER = "amber"    # 0.45 - 0.70
    RED = "red"        # > 0.70


@dataclass
class NodeTwin:
    """
    Digital twin state for a single mesh node.

    This is what the browser knows about a node.
    Updated from HTP heartbeats, Qsecbit reports, and mesh events.
    """

    # Identity
    node_id: str
    tier: NodeTier

    # Geographic (from registration or geolocation)
    lat: float = 0.0
    lng: float = 0.0
    label: str = ""
    country_code: str = ""

    # Health (from Qsecbit)
    qsecbit_score: float = 0.0
    qsecbit_status: QsecbitStatus = QsecbitStatus.GREEN
    qsecbit_history: List[float] = field(default_factory=list)
    qsecbit_history_max: int = 60  # Keep last 60 readings (5 min at 5s interval)

    # Liveness (from HTP heartbeats)
    last_heartbeat: Optional[datetime] = None
    heartbeat_interval_ms: int = 30000  # Expected 30s for most nodes
    online: bool = False

    # Neural (from Neuro protocol)
    neural_resonance: float = 0.0
    weight_version: int = 0

    # Visual state (for synchronized animations)
    pulse_phase: float = 0.0
    attention_level: float = 0.0  # 0=normal, 1=under active attack

    def update_qsecbit(self, score: float) -> Optional[str]:
        """
        Update Qsecbit score and return status change event if threshold crossed.

        Returns:
            Event type if threshold crossed, None otherwise
        """
        old_status = self.qsecbit_status
        self.qsecbit_score = score

        # Update history
        self.qsecbit_history.append(score)
        if len(self.qsecbit_history) > self.qsecbit_history_max:
            self.qsecbit_history.pop(0)

        # Determine new status
        if score < 0.45:
            self.qsecbit_status = QsecbitStatus.GREEN
        elif score < 0.70:
            self.qsecbit_status = QsecbitStatus.AMBER
        else:
            self.qsecbit_status = QsecbitStatus.RED

        # Return event if status changed
        if old_status != self.qsecbit_status:
            return f"qsecbit_{self.qsecbit_status.value}"
        return None

    def update_heartbeat(self) -> bool:
        """
        Record a heartbeat and return whether node came online.

        Returns:
            True if node transitioned from offline to online
        """
        was_online = self.online
        self.last_heartbeat = datetime.utcnow()
        self.online = True
        return not was_online  # Return True if just came online

    def check_liveness(self, timeout_multiplier: float = 3.0) -> bool:
        """
        Check if node is still alive based on heartbeat timeout.

        Args:
            timeout_multiplier: How many heartbeat intervals before offline

        Returns:
            True if node went offline (state changed)
        """
        if not self.last_heartbeat:
            return False

        timeout = timedelta(milliseconds=self.heartbeat_interval_ms * timeout_multiplier)
        if datetime.utcnow() - self.last_heartbeat > timeout:
            if self.online:
                self.online = False
                return True  # State changed to offline
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for WebSocket transmission."""
        return {
            "id": self.node_id,
            "tier": self.tier.value,
            "lat": self.lat,
            "lng": self.lng,
            "label": self.label,
            "country_code": self.country_code,
            "qsecbit": round(self.qsecbit_score, 4),
            "status": self.qsecbit_status.value,
            "online": self.online,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            "resonance": round(self.neural_resonance, 4),
            "attention": round(self.attention_level, 2),
        }


@dataclass
class MeshEdge:
    """Connection between two nodes (for topology visualization)."""

    source_id: str
    target_id: str

    # Quality metrics
    latency_ms: float = 0.0
    bandwidth_kbps: float = 0.0
    packet_loss_pct: float = 0.0

    # Connection type
    connection_type: str = "direct"  # direct | relay | tunnel

    # State
    active: bool = True
    last_traffic: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for WebSocket transmission."""
        return {
            "source": self.source_id,
            "target": self.target_id,
            "latency_ms": self.latency_ms,
            "bandwidth_kbps": self.bandwidth_kbps,
            "type": self.connection_type,
            "active": self.active,
        }


class NodeRegistry:
    """
    Central registry of all node twins.

    Provides:
    - Node state management
    - Liveness monitoring
    - Event callbacks for state changes
    - Snapshot generation for new browser connections
    """

    def __init__(self):
        self.nodes: Dict[str, NodeTwin] = {}
        self.edges: Dict[str, MeshEdge] = {}  # Key: "source_id:target_id"
        self.event_callbacks: List[Callable[[Dict[str, Any]], None]] = []
        self._liveness_task: Optional[asyncio.Task] = None

    def register_node(
        self,
        node_id: str,
        tier: NodeTier,
        lat: float,
        lng: float,
        label: str = "",
        country_code: str = ""
    ) -> NodeTwin:
        """Register a new node or update existing."""
        if node_id in self.nodes:
            node = self.nodes[node_id]
            node.lat = lat
            node.lng = lng
            node.label = label or node.label
            node.country_code = country_code or node.country_code
        else:
            node = NodeTwin(
                node_id=node_id,
                tier=tier,
                lat=lat,
                lng=lng,
                label=label,
                country_code=country_code,
            )
            self.nodes[node_id] = node
            logger.info(f"Registered new node: {node_id} ({tier.value}) at {lat}, {lng}")

        return node

    def get_node(self, node_id: str) -> Optional[NodeTwin]:
        """Get a node by ID."""
        return self.nodes.get(node_id)

    def on_heartbeat(self, node_id: str) -> None:
        """Process a heartbeat from a node."""
        node = self.nodes.get(node_id)
        if node:
            came_online = node.update_heartbeat()
            if came_online:
                self._emit_event({
                    "type": "node_online",
                    "node_id": node_id,
                    "node": node.to_dict(),
                    "timestamp": datetime.utcnow().isoformat(),
                })

    def on_qsecbit_update(self, node_id: str, score: float) -> None:
        """Process a Qsecbit score update."""
        node = self.nodes.get(node_id)
        if node:
            event_type = node.update_qsecbit(score)
            if event_type:
                self._emit_event({
                    "type": "qsecbit_threshold",
                    "node_id": node_id,
                    "new_status": node.qsecbit_status.value,
                    "score": score,
                    "timestamp": datetime.utcnow().isoformat(),
                })

    def on_attack_event(
        self,
        target_id: str,
        source_ip: str,
        source_lat: float,
        source_lng: float,
        source_label: str,
        attack_type: str,
        severity: float,
        repelled: bool = False
    ) -> None:
        """Process an attack detection or repulsion event."""
        node = self.nodes.get(target_id)
        if node:
            # Increase attention level
            node.attention_level = min(1.0, node.attention_level + 0.3)

            event = {
                "type": "attack_repelled" if repelled else "attack_detected",
                "source": {
                    "lat": source_lat,
                    "lng": source_lng,
                    "label": source_label,
                    "ip": source_ip,
                },
                "target": {
                    "lat": node.lat,
                    "lng": node.lng,
                    "label": node.label,
                    "node_id": target_id,
                },
                "attack_type": attack_type,
                "severity": severity,
                "timestamp": datetime.utcnow().isoformat(),
            }
            self._emit_event(event)

    def add_event_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Register a callback for node events."""
        self.event_callbacks.append(callback)

    def _emit_event(self, event: Dict[str, Any]) -> None:
        """Emit an event to all registered callbacks."""
        for callback in self.event_callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Event callback error: {e}")

    def get_snapshot(self) -> Dict[str, Any]:
        """Get full state snapshot for new browser connections."""
        return {
            "type": "snapshot",
            "nodes": [node.to_dict() for node in self.nodes.values()],
            "edges": [edge.to_dict() for edge in self.edges.values()],
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def start_liveness_monitor(self, check_interval: float = 10.0) -> None:
        """Start background task to check node liveness."""
        self._liveness_task = asyncio.create_task(
            self._liveness_loop(check_interval)
        )

    async def stop_liveness_monitor(self) -> None:
        """Stop the liveness monitor."""
        if self._liveness_task:
            self._liveness_task.cancel()
            try:
                await self._liveness_task
            except asyncio.CancelledError:
                pass

    async def _liveness_loop(self, interval: float) -> None:
        """Check node liveness periodically."""
        while True:
            await asyncio.sleep(interval)
            for node_id, node in self.nodes.items():
                went_offline = node.check_liveness()
                if went_offline:
                    self._emit_event({
                        "type": "node_offline",
                        "node_id": node_id,
                        "timestamp": datetime.utcnow().isoformat(),
                    })

                # Decay attention level over time
                if node.attention_level > 0:
                    node.attention_level = max(0, node.attention_level - 0.1)

    # =========================================
    # Cluster Support Methods
    # =========================================

    def get_nodes_by_region(self, bounds: Dict[str, float]) -> List[NodeTwin]:
        """
        Get nodes within geographic bounds.

        Args:
            bounds: Dict with west, south, east, north coordinates

        Returns:
            List of nodes within bounds
        """
        result = []
        for node in self.nodes.values():
            if (bounds.get('west', -180) <= node.lng <= bounds.get('east', 180) and
                bounds.get('south', -90) <= node.lat <= bounds.get('north', 90)):
                result.append(node)
        return result

    def get_cluster_stats(self) -> Dict[str, Any]:
        """
        Get statistics for clustering visualization.

        Returns:
            Dict with node counts, tier distribution, and geographic coverage
        """
        stats = {
            "total_nodes": len(self.nodes),
            "online_nodes": sum(1 for n in self.nodes.values() if n.online),
            "by_tier": {
                "sentinel": 0,
                "guardian": 0,
                "fortress": 0,
                "nexus": 0,
            },
            "by_status": {
                "green": 0,
                "amber": 0,
                "red": 0,
            },
            "by_country": {},
            "avg_qsecbit": 0.0,
            "geographic_bounds": {
                "north": -90,
                "south": 90,
                "east": -180,
                "west": 180,
            },
        }

        total_qsecbit = 0.0

        for node in self.nodes.values():
            # Count by tier
            stats["by_tier"][node.tier.value] += 1

            # Count by status
            stats["by_status"][node.qsecbit_status.value] += 1

            # Count by country
            if node.country_code:
                stats["by_country"][node.country_code] = (
                    stats["by_country"].get(node.country_code, 0) + 1
                )

            # Sum Qsecbit
            total_qsecbit += node.qsecbit_score

            # Update geographic bounds
            stats["geographic_bounds"]["north"] = max(
                stats["geographic_bounds"]["north"], node.lat
            )
            stats["geographic_bounds"]["south"] = min(
                stats["geographic_bounds"]["south"], node.lat
            )
            stats["geographic_bounds"]["east"] = max(
                stats["geographic_bounds"]["east"], node.lng
            )
            stats["geographic_bounds"]["west"] = min(
                stats["geographic_bounds"]["west"], node.lng
            )

        # Calculate average Qsecbit
        if self.nodes:
            stats["avg_qsecbit"] = round(total_qsecbit / len(self.nodes), 4)

        return stats

    def get_nodes_for_clustering(self) -> List[Dict[str, Any]]:
        """
        Get nodes in a format optimized for frontend clustering.

        Returns:
            List of node dicts with clustering-relevant fields
        """
        return [
            {
                "id": node.node_id,
                "lat": node.lat,
                "lng": node.lng,
                "tier": node.tier.value,
                "qsecbit": round(node.qsecbit_score, 4),
                "status": node.qsecbit_status.value,
                "label": node.label,
                "online": node.online,
                "country_code": node.country_code,
            }
            for node in self.nodes.values()
        ]

    def get_snapshot_with_stats(self) -> Dict[str, Any]:
        """
        Get full state snapshot with clustering statistics.

        Enhanced version of get_snapshot() that includes cluster-relevant stats.
        """
        snapshot = self.get_snapshot()
        snapshot["stats"] = self.get_cluster_stats()
        return snapshot


# Global registry instance
_registry: Optional[NodeRegistry] = None


def get_registry() -> NodeRegistry:
    """Get or create the global node registry."""
    global _registry
    if _registry is None:
        _registry = NodeRegistry()
    return _registry
