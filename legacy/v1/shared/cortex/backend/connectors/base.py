#!/usr/bin/env python3
"""
Base Product Connector for Globe Visualization

This module defines the base class that all product connectors must implement.
Each HookProbe product (Guardian, Fortress, Nexus) has its own connector
that inherits from this base class.

The connector is responsible for:
1. Collecting product-specific metrics
2. Maintaining connection to the globe bridge
3. Reporting heartbeats, Qsecbit scores, and threat events
4. Providing geographic location for the globe
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List, Callable
from enum import Enum

logger = logging.getLogger(__name__)


class ProductTier(Enum):
    """HookProbe product tiers."""
    SENTINEL = "sentinel"
    GUARDIAN = "guardian"
    FORTRESS = "fortress"
    NEXUS = "nexus"


class QsecbitStatus(Enum):
    """Qsecbit RAG status."""
    GREEN = "green"
    AMBER = "amber"
    RED = "red"


@dataclass
class ConnectorConfig:
    """Configuration for a product connector."""

    # Identity
    node_id: str                     # Unique node identifier
    tier: ProductTier                # Product tier

    # Geographic (for globe placement)
    lat: float = 0.0                 # Latitude
    lng: float = 0.0                 # Longitude
    label: str = ""                  # Human-readable location
    country_code: str = ""           # ISO country code

    # Connection to globe bridge
    bridge_host: str = "localhost"   # Globe bridge host
    bridge_port: int = 8765          # Globe bridge WebSocket port
    bridge_api_port: int = 8766      # Globe bridge REST API port

    # Heartbeat settings
    heartbeat_interval: float = 30.0  # Seconds between heartbeats
    qsecbit_report_interval: float = 5.0  # Seconds between Qsecbit reports

    # Capabilities
    can_report_threats: bool = True   # Can detect and report threats
    can_mitigate: bool = False        # Can automatically mitigate
    participates_in_dsm: bool = False # Participates in DSM consensus


@dataclass
class NodeState:
    """Current state of a node for globe visualization."""

    # Identity
    node_id: str
    tier: ProductTier

    # Geographic
    lat: float
    lng: float
    label: str

    # Health
    qsecbit_score: float = 0.0
    qsecbit_status: QsecbitStatus = QsecbitStatus.GREEN
    qsecbit_components: Dict[str, float] = field(default_factory=dict)

    # Liveness
    online: bool = True
    last_heartbeat: Optional[datetime] = None
    uptime_seconds: int = 0

    # Statistics
    threats_detected: int = 0
    threats_mitigated: int = 0
    bytes_protected: int = 0

    # Product-specific metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for transmission to globe bridge."""
        return {
            "node_id": self.node_id,
            "tier": self.tier.value,
            "lat": self.lat,
            "lng": self.lng,
            "label": self.label,
            "qsecbit": round(self.qsecbit_score, 4),
            "status": self.qsecbit_status.value,
            "components": self.qsecbit_components,
            "online": self.online,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            "uptime_seconds": self.uptime_seconds,
            "threats_detected": self.threats_detected,
            "threats_mitigated": self.threats_mitigated,
            "bytes_protected": self.bytes_protected,
            "metadata": self.metadata,
        }


@dataclass
class ThreatEvent:
    """A threat event detected by a product."""

    # Source of threat
    source_ip: str
    source_lat: Optional[float] = None
    source_lng: Optional[float] = None
    source_label: str = ""

    # Threat details
    attack_type: str = "unknown"
    severity: float = 0.5  # 0.0 - 1.0
    description: str = ""

    # Mitigation
    repelled: bool = False
    mitigation_method: str = ""
    response_time_ms: int = 0

    # Metadata
    timestamp: Optional[datetime] = None
    ioc_type: str = ""  # ip, domain, hash, etc.
    ioc_value: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for transmission."""
        return {
            "source_ip": self.source_ip,
            "source_lat": self.source_lat,
            "source_lng": self.source_lng,
            "source_label": self.source_label,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "description": self.description,
            "repelled": self.repelled,
            "mitigation_method": self.mitigation_method,
            "response_time_ms": self.response_time_ms,
            "timestamp": (self.timestamp or datetime.utcnow()).isoformat(),
            "ioc_type": self.ioc_type,
            "ioc_value": self.ioc_value,
        }


class ProductConnector(ABC):
    """
    Abstract base class for product connectors.

    Each HookProbe product implements this interface to report its state
    to the globe visualization.

    Usage:
        class GuardianConnector(ProductConnector):
            def collect_qsecbit(self) -> float:
                return self.guardian_agent.get_qsecbit_score()

            def collect_state(self) -> NodeState:
                # ... collect Guardian-specific state
    """

    def __init__(self, config: ConnectorConfig):
        self.config = config
        self.state = NodeState(
            node_id=config.node_id,
            tier=config.tier,
            lat=config.lat,
            lng=config.lng,
            label=config.label,
        )
        self.running = False
        self._start_time = None
        self._tasks: List[asyncio.Task] = []
        self._event_callbacks: List[Callable[[Dict[str, Any]], None]] = []

    # =========================================================================
    # Abstract methods - must be implemented by each product
    # =========================================================================

    @abstractmethod
    async def collect_qsecbit(self) -> float:
        """
        Collect current Qsecbit score from the product.

        Returns:
            float: Qsecbit score between 0.0 and 1.0
        """
        pass

    @abstractmethod
    async def collect_qsecbit_components(self) -> Dict[str, float]:
        """
        Collect Qsecbit component breakdown.

        Returns:
            dict: Component name -> score mapping
            Example: {"threats": 0.30, "mobile": 0.20, "ids": 0.25, ...}
        """
        pass

    @abstractmethod
    async def collect_statistics(self) -> Dict[str, Any]:
        """
        Collect product-specific statistics.

        Returns:
            dict: Statistics including threats_detected, bytes_protected, etc.
        """
        pass

    @abstractmethod
    async def get_recent_threats(self) -> List[ThreatEvent]:
        """
        Get recent threat events from the product.

        Returns:
            list: Recent ThreatEvent objects
        """
        pass

    # =========================================================================
    # Lifecycle methods
    # =========================================================================

    async def start(self) -> None:
        """Start the connector."""
        if self.running:
            return

        self.running = True
        self._start_time = datetime.utcnow()
        logger.info(f"Starting {self.config.tier.value} connector: {self.config.node_id}")

        # Start background tasks
        self._tasks.append(asyncio.create_task(self._heartbeat_loop()))
        self._tasks.append(asyncio.create_task(self._qsecbit_loop()))
        self._tasks.append(asyncio.create_task(self._threat_monitor_loop()))

        # Report initial state
        await self._report_online()

    async def stop(self) -> None:
        """Stop the connector."""
        self.running = False

        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        self._tasks.clear()
        await self._report_offline()
        logger.info(f"Stopped {self.config.tier.value} connector: {self.config.node_id}")

    # =========================================================================
    # Event reporting
    # =========================================================================

    def on_event(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Register a callback for connector events."""
        self._event_callbacks.append(callback)

    def _emit_event(self, event: Dict[str, Any]) -> None:
        """Emit an event to all registered callbacks."""
        for callback in self._event_callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Event callback error: {e}")

    async def report_threat(self, threat: ThreatEvent) -> None:
        """Report a threat event to the globe."""
        self.state.threats_detected += 1
        if threat.repelled:
            self.state.threats_mitigated += 1

        event = {
            "type": "attack_repelled" if threat.repelled else "attack_detected",
            "source": {
                "ip": threat.source_ip,
                "lat": threat.source_lat,
                "lng": threat.source_lng,
                "label": threat.source_label,
            },
            "target": {
                "node_id": self.config.node_id,
                "lat": self.config.lat,
                "lng": self.config.lng,
                "label": self.config.label,
            },
            "attack_type": threat.attack_type,
            "severity": threat.severity,
            "mitigation": threat.mitigation_method if threat.repelled else None,
            "response_ms": threat.response_time_ms if threat.repelled else None,
            "timestamp": datetime.utcnow().isoformat(),
        }

        self._emit_event(event)

    # =========================================================================
    # Background loops
    # =========================================================================

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats."""
        while self.running:
            try:
                await self._send_heartbeat()
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")

            await asyncio.sleep(self.config.heartbeat_interval)

    async def _qsecbit_loop(self) -> None:
        """Periodically collect and report Qsecbit score."""
        while self.running:
            try:
                score = await self.collect_qsecbit()
                components = await self.collect_qsecbit_components()
                await self._update_qsecbit(score, components)
            except Exception as e:
                logger.error(f"Qsecbit collection error: {e}")

            await asyncio.sleep(self.config.qsecbit_report_interval)

    async def _threat_monitor_loop(self) -> None:
        """Monitor for new threats and report them."""
        last_check = datetime.utcnow()

        while self.running:
            try:
                threats = await self.get_recent_threats()
                for threat in threats:
                    if threat.timestamp and threat.timestamp > last_check:
                        await self.report_threat(threat)
                last_check = datetime.utcnow()
            except Exception as e:
                logger.error(f"Threat monitor error: {e}")

            await asyncio.sleep(1.0)  # Check every second

    # =========================================================================
    # Internal methods
    # =========================================================================

    async def _send_heartbeat(self) -> None:
        """Send heartbeat to globe bridge."""
        self.state.last_heartbeat = datetime.utcnow()
        if self._start_time:
            self.state.uptime_seconds = int(
                (datetime.utcnow() - self._start_time).total_seconds()
            )

        event = {
            "type": "heartbeat",
            "node_id": self.config.node_id,
            "tier": self.config.tier.value,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._emit_event(event)

    async def _update_qsecbit(self, score: float, components: Dict[str, float]) -> None:
        """Update Qsecbit score and emit event if threshold crossed."""
        old_status = self.state.qsecbit_status
        self.state.qsecbit_score = score
        self.state.qsecbit_components = components

        # Determine new status
        if score < 0.45:
            self.state.qsecbit_status = QsecbitStatus.GREEN
        elif score < 0.70:
            self.state.qsecbit_status = QsecbitStatus.AMBER
        else:
            self.state.qsecbit_status = QsecbitStatus.RED

        # Emit event if status changed
        if old_status != self.state.qsecbit_status:
            event = {
                "type": "qsecbit_threshold",
                "node_id": self.config.node_id,
                "old_status": old_status.value,
                "new_status": self.state.qsecbit_status.value,
                "score": score,
                "timestamp": datetime.utcnow().isoformat(),
            }
            self._emit_event(event)

        # Always emit score update
        event = {
            "type": "qsecbit_update",
            "node_id": self.config.node_id,
            "score": score,
            "status": self.state.qsecbit_status.value,
            "components": components,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._emit_event(event)

    async def _report_online(self) -> None:
        """Report node coming online."""
        self.state.online = True
        event = {
            "type": "node_online",
            "node_id": self.config.node_id,
            "tier": self.config.tier.value,
            "lat": self.config.lat,
            "lng": self.config.lng,
            "label": self.config.label,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._emit_event(event)

    async def _report_offline(self) -> None:
        """Report node going offline."""
        self.state.online = False
        event = {
            "type": "node_offline",
            "node_id": self.config.node_id,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._emit_event(event)

    def get_state(self) -> NodeState:
        """Get current node state."""
        return self.state
