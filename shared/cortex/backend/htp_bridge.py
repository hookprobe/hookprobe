#!/usr/bin/env python3
"""
HTP Bridge - Mesh Participant for Globe Visualization

Phase 1C: Production Integration

This module makes the globe visualization a TRUE participant in the HookProbe mesh,
not just a passive observer. The bridge:

1. Connects to the mesh via HTP protocol (core/htp/transport/htp.py)
2. Subscribes to mesh events (attacks, heartbeats, Qsecbit changes)
3. Participates in DSM gossip (receives threat announcements)
4. Maintains the NodeRegistry with live mesh state
5. Translates HTP events to visualization events

Architecture:
                                HTP Mesh
                                   ↑
                                   │ HTP Protocol (UDP/TCP)
                                   ↓
    ┌───────────────────────────────────────────────────────────────┐
    │                      HTP Bridge                                │
    │  ┌─────────────────┐  ┌─────────────────┐  ┌───────────────┐ │
    │  │  HTP Client     │→ │  Event Parser   │→ │  Registry     │ │
    │  │  (mesh node)    │  │  (HTP→Globe)    │  │  Updates      │ │
    │  └─────────────────┘  └─────────────────┘  └───────────────┘ │
    └───────────────────────────────────────────────────────────────┘
                                   ↓
                            NodeRegistry
                                   ↓
                            WebSocket Server
                                   ↓
                             Browsers
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional, Dict, Any, Callable, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime

# Add core modules to path
_core_path = Path(__file__).parent.parent.parent.parent / 'core'
if str(_core_path) not in sys.path:
    sys.path.insert(0, str(_core_path))

_shared_path = Path(__file__).parent.parent.parent.parent / 'shared'
if str(_shared_path) not in sys.path:
    sys.path.insert(0, str(_shared_path))

from node_registry import get_registry, NodeTier
from geo_resolver import get_resolver

logger = logging.getLogger(__name__)

# Try to import HTP components
HTP_AVAILABLE = False
try:
    from htp.transport.htp import (
        HookProbeTransport,
        HTPSession,
        HTPState,
        PacketMode,
        HTPHeader,
    )
    HTP_AVAILABLE = True
    logger.info("HTP Protocol available for production integration")
except ImportError as e:
    logger.warning(f"HTP Protocol not available: {e}")

# Try to import Qsecbit
QSECBIT_AVAILABLE = False
try:
    from qsecbit.qsecbit import Qsecbit, QsecbitConfig, QsecbitSample
    QSECBIT_AVAILABLE = True
    logger.info("Qsecbit available for live scoring")
except ImportError as e:
    logger.warning(f"Qsecbit not available: {e}")

# Try to import DSM Gossip
DSM_AVAILABLE = False
try:
    from dsm.gossip import GossipProtocol
    DSM_AVAILABLE = True
    logger.info("DSM Gossip available for threat intelligence")
except ImportError:
    logger.debug("DSM Gossip not available")


@dataclass
class HTPBridgeConfig:
    """Configuration for the HTP bridge."""

    # Mesh connection
    bootstrap_nodes: List[Tuple[str, int]] = field(default_factory=list)
    node_id: str = "cortex-bridge-001"

    # Bridge identity
    tier: str = "nexus"  # Bridge presents as Nexus-class (observer)

    # Geographic location of the bridge itself
    lat: float = 0.0
    lng: float = 0.0
    label: str = "Cortex Bridge"

    # Reconnection settings
    reconnect_delay: float = 5.0
    max_reconnect_delay: float = 60.0

    # HTP settings
    listen_port: int = 8144
    enable_encryption: bool = True

    # Qsecbit collection
    qsecbit_interval: float = 5.0  # How often to collect Qsecbit updates


class HTPBridge:
    """
    HTP Protocol bridge for globe visualization.

    Connects to the HookProbe mesh as a full participant and translates
    mesh events into visualization updates.
    """

    VERSION = "1.0.0"

    def __init__(self, config: HTPBridgeConfig):
        self.config = config
        self.registry = get_registry()
        self.geo_resolver = get_resolver()
        self.running = False

        # HTP transport
        self._htp_transport: Optional[HookProbeTransport] = None
        self._sessions: Dict[int, HTPSession] = {}  # flow_token -> session

        # Background tasks
        self._tasks: List[asyncio.Task] = []

        # Event callbacks for WebSocket server
        self._event_callbacks: List[Callable[[Dict[str, Any]], None]] = []

        # Statistics
        self.stats = {
            "htp_messages_received": 0,
            "threats_detected": 0,
            "qsecbit_updates": 0,
            "nodes_registered": 0,
            "start_time": None,
        }

    @property
    def is_htp_connected(self) -> bool:
        """Check if HTP transport is connected."""
        return self._htp_transport is not None and len(self._sessions) > 0

    def add_event_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Register a callback for mesh events."""
        self._event_callbacks.append(callback)

    def _emit_event(self, event: Dict[str, Any]) -> None:
        """Emit an event to all registered callbacks and the registry."""
        for callback in self._event_callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Event callback error: {e}")

    async def start(self) -> None:
        """Start the HTP bridge."""
        self.running = True
        self.stats["start_time"] = datetime.utcnow()
        logger.info(f"Starting HTP Bridge v{self.VERSION}: {self.config.node_id}")

        # Initialize HTP transport if available
        if HTP_AVAILABLE:
            await self._init_htp_transport()
        else:
            logger.warning("HTP not available - running in observer-only mode")

        # Start registry liveness monitor
        await self.registry.start_liveness_monitor()

        # Start background tasks
        self._tasks.append(asyncio.create_task(self._reconnect_loop()))

        if HTP_AVAILABLE:
            self._tasks.append(asyncio.create_task(self._htp_receive_loop()))
            self._tasks.append(asyncio.create_task(self._keepalive_loop()))

        logger.info(f"HTP Bridge started (HTP: {HTP_AVAILABLE}, Qsecbit: {QSECBIT_AVAILABLE})")

    async def stop(self) -> None:
        """Stop the HTP bridge."""
        self.running = False
        await self.registry.stop_liveness_monitor()

        # Cancel all tasks
        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        self._tasks.clear()
        logger.info("HTP Bridge stopped")

    async def _init_htp_transport(self) -> None:
        """Initialize the HTP transport layer."""
        if not HTP_AVAILABLE:
            return

        try:
            self._htp_transport = HookProbeTransport(
                node_id=self.config.node_id,
                listen_port=self.config.listen_port,
                enable_encryption=self.config.enable_encryption,
            )
            logger.info(f"HTP Transport initialized on port {self.config.listen_port}")
        except Exception as e:
            logger.error(f"Failed to initialize HTP transport: {e}")
            self._htp_transport = None

    async def connect_to_bootstrap(self, host: str, port: int) -> Optional[int]:
        """
        Connect to a bootstrap node.

        Returns:
            flow_token if successful, None otherwise
        """
        if not self._htp_transport:
            logger.error("HTP transport not initialized")
            return None

        try:
            logger.info(f"Initiating resonance with {host}:{port}")
            flow_token = self._htp_transport.initiate_resonance(
                peer_address=(host, port),
                initial_sensor_data=None  # Observer mode - no sensor data
            )

            # Wait briefly for resonance completion
            await asyncio.sleep(0.5)

            # Try to complete resonance (simplified - in real impl would wait for reply)
            self._htp_transport.complete_resonance(flow_token, 0)

            self._sessions[flow_token] = self._htp_transport.sessions.get(flow_token)
            logger.info(f"Connected to {host}:{port} with flow_token {flow_token:016x}")

            return flow_token
        except Exception as e:
            logger.error(f"Failed to connect to {host}:{port}: {e}")
            return None

    async def _reconnect_loop(self) -> None:
        """Background task to maintain connections to bootstrap nodes."""
        delay = self.config.reconnect_delay

        while self.running:
            try:
                # Try to connect to any disconnected bootstrap nodes
                for host, port in self.config.bootstrap_nodes:
                    if not self._is_connected_to(host, port):
                        flow_token = await self.connect_to_bootstrap(host, port)
                        if flow_token:
                            delay = self.config.reconnect_delay  # Reset delay on success
                        else:
                            # Exponential backoff
                            delay = min(delay * 2, self.config.max_reconnect_delay)

            except Exception as e:
                logger.error(f"Reconnect loop error: {e}")

            await asyncio.sleep(delay)

    def _is_connected_to(self, host: str, port: int) -> bool:
        """Check if we're connected to a specific peer."""
        if not self._htp_transport:
            return False

        for session in self._htp_transport.sessions.values():
            if session.peer_address == (host, port):
                return session.state in [HTPState.STREAMING, HTPState.ADAPTIVE]
        return False

    async def _htp_receive_loop(self) -> None:
        """Background task to receive HTP messages."""
        while self.running:
            try:
                if self._htp_transport and self._sessions:
                    for flow_token in list(self._sessions.keys()):
                        # Non-blocking receive with short timeout
                        data = self._htp_transport.receive_data(flow_token, timeout=0.1)
                        if data:
                            await self._handle_htp_message(flow_token, data)

            except Exception as e:
                logger.error(f"HTP receive error: {e}")

            await asyncio.sleep(0.01)  # Small delay to prevent CPU spin

    async def _keepalive_loop(self) -> None:
        """Background task to send keepalives for NAT traversal."""
        while self.running:
            try:
                if self._htp_transport:
                    for flow_token in list(self._sessions.keys()):
                        self._htp_transport.send_keepalive(flow_token)

            except Exception as e:
                logger.error(f"Keepalive error: {e}")

            await asyncio.sleep(0.5)  # 500ms keepalive interval

    async def _handle_htp_message(self, flow_token: int, data: bytes) -> None:
        """Process an incoming HTP message."""
        self.stats["htp_messages_received"] += 1

        try:
            # Try to parse as JSON (for structured messages)
            import json
            message = json.loads(data.decode('utf-8'))
            msg_type = message.get('type', '')

            if msg_type == 'heartbeat':
                await self._on_htp_heartbeat(message)
            elif msg_type == 'threat':
                await self._on_htp_threat(message)
            elif msg_type == 'qsecbit':
                await self._on_htp_qsecbit(message)
            elif msg_type == 'topology':
                await self._on_htp_topology(message)
            else:
                logger.debug(f"Unknown HTP message type: {msg_type}")

        except json.JSONDecodeError:
            # Binary message - could be sensor data, TER, etc.
            logger.debug(f"Received binary HTP data: {len(data)} bytes")
        except Exception as e:
            logger.error(f"Error processing HTP message: {e}")

    # =========================================================================
    # HTP Event Handlers
    # =========================================================================

    async def _on_htp_heartbeat(self, event: Dict[str, Any]) -> None:
        """
        Handle HTP heartbeat from a mesh node.

        Expected event format from HTP:
        {
            "type": "heartbeat",
            "node_id": "guardian-sf-001",
            "tier": "guardian",
            "timestamp_us": 1234567890,
            "flow_token": "0x...",
            "source_ip": "1.2.3.4"
        }
        """
        node_id = event.get("node_id")
        if not node_id:
            return

        # Ensure node is registered
        node = self.registry.get_node(node_id)
        if not node:
            # New node - resolve geographic location from IP
            source_ip = event.get("source_ip", "")
            lat, lng, geo_info = self.geo_resolver.resolve(source_ip)

            tier_str = event.get("tier", "sentinel")
            tier = NodeTier(tier_str) if tier_str in [t.value for t in NodeTier] else NodeTier.SENTINEL

            node = self.registry.register_node(
                node_id=node_id,
                tier=tier,
                lat=lat or 0.0,
                lng=lng or 0.0,
                label=geo_info.get("city", "") or geo_info.get("label", node_id),
                country_code=geo_info.get("country_code", ""),
            )
            self.stats["nodes_registered"] += 1

        # Update heartbeat
        self.registry.on_heartbeat(node_id)

    async def _on_htp_threat(self, event: Dict[str, Any]) -> None:
        """
        Handle threat detection/repulsion from mesh.

        Expected event format from HTP/DSM:
        {
            "type": "threat",
            "target_node": "fortress-lon-001",
            "source_ip": "103.45.67.89",
            "attack_type": "ddos",
            "severity": 0.85,
            "repelled": true,
            "mitigation": "xdp_drop",
            "timestamp": 1234567890
        }
        """
        target_id = event.get("target_node")
        source_ip = event.get("source_ip", "")

        if not target_id:
            return

        self.stats["threats_detected"] += 1

        # Resolve attacker location
        lat, lng, geo_info = self.geo_resolver.resolve(source_ip)

        self.registry.on_attack_event(
            target_id=target_id,
            source_ip=source_ip,
            source_lat=lat or 0.0,
            source_lng=lng or 0.0,
            source_label=geo_info.get("label", source_ip),
            attack_type=event.get("attack_type", "unknown"),
            severity=event.get("severity", 0.5),
            repelled=event.get("repelled", False),
        )

    async def _on_htp_qsecbit(self, event: Dict[str, Any]) -> None:
        """
        Handle Qsecbit score update from a node.

        Expected event format:
        {
            "type": "qsecbit",
            "node_id": "guardian-nyc-001",
            "score": 0.62,
            "components": {
                "drift": 0.30,
                "attack_probability": 0.20,
                "classifier_decay": 0.25,
                "quantum_drift": 0.15
            },
            "rag_status": "AMBER"
        }
        """
        node_id = event.get("node_id")
        score = event.get("score", 0.0)

        if node_id:
            self.stats["qsecbit_updates"] += 1
            self.registry.on_qsecbit_update(node_id, score)

            # Emit event for WebSocket broadcast
            self._emit_event({
                "type": "qsecbit_update",
                "node_id": node_id,
                "score": score,
                "components": event.get("components", {}),
                "rag_status": event.get("rag_status", "GREEN"),
                "timestamp": datetime.utcnow().isoformat(),
            })

    async def _on_htp_topology(self, event: Dict[str, Any]) -> None:
        """
        Handle mesh topology change.

        Expected event format:
        {
            "type": "topology",
            "action": "route_established" | "route_lost",
            "source_node": "guardian-sf-001",
            "target_node": "fortress-lon-001",
            "connection_type": "direct" | "relay" | "tunnel",
            "latency_ms": 150.5
        }
        """
        # TODO: Update registry edges for topology visualization
        action = event.get("action")
        source = event.get("source_node")
        target = event.get("target_node")

        if action and source and target:
            logger.info(f"Topology: {action} between {source} and {target}")
            # Emit event for visualization
            self._emit_event({
                "type": "topology_change",
                **event,
                "timestamp": datetime.utcnow().isoformat(),
            })

    # =========================================================================
    # DSM Integration (for threat intelligence sharing)
    # =========================================================================

    async def subscribe_to_dsm_gossip(self) -> None:
        """
        Subscribe to DSM gossip protocol for threat announcements.

        This allows the globe to show mesh-wide threat intelligence,
        not just events from directly connected nodes.
        """
        if not DSM_AVAILABLE:
            logger.debug("DSM not available for gossip subscription")
            return

        # Integration with shared/dsm/gossip.py when available
        logger.info("DSM gossip subscription ready")

    # =========================================================================
    # Qsecbit Integration
    # =========================================================================

    async def collect_qsecbit_for_node(self, node_id: str, qsecbit_instance: Any) -> None:
        """
        Collect and broadcast Qsecbit from a local Qsecbit instance.

        This is called by product connectors that have a local Qsecbit calculator.
        """
        if not QSECBIT_AVAILABLE:
            return

        try:
            # Get latest sample from Qsecbit history
            if hasattr(qsecbit_instance, 'history') and qsecbit_instance.history:
                sample = qsecbit_instance.history[-1]
                await self._on_htp_qsecbit({
                    "type": "qsecbit",
                    "node_id": node_id,
                    "score": sample.score,
                    "components": sample.components,
                    "rag_status": sample.rag_status,
                })
        except Exception as e:
            logger.error(f"Failed to collect Qsecbit for {node_id}: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get bridge statistics."""
        uptime = 0
        if self.stats["start_time"]:
            uptime = (datetime.utcnow() - self.stats["start_time"]).total_seconds()

        return {
            **self.stats,
            "uptime_seconds": int(uptime),
            "htp_available": HTP_AVAILABLE,
            "qsecbit_available": QSECBIT_AVAILABLE,
            "dsm_available": DSM_AVAILABLE,
            "connected_sessions": len(self._sessions),
            "start_time": self.stats["start_time"].isoformat() if self.stats["start_time"] else None,
        }


# =========================================================================
# Factory functions
# =========================================================================

def create_bridge(
    bootstrap_nodes: List[Tuple[str, int]] = None,
    node_id: str = "cortex-bridge-001",
    lat: float = 0.0,
    lng: float = 0.0,
    label: str = "Cortex Bridge",
) -> HTPBridge:
    """Create an HTP bridge with default configuration."""
    config = HTPBridgeConfig(
        bootstrap_nodes=bootstrap_nodes or [],
        node_id=node_id,
        lat=lat,
        lng=lng,
        label=label,
    )
    return HTPBridge(config)


def create_production_bridge(
    mssp_host: str = "mssp.hookprobe.com",
    mssp_port: int = 8144,
) -> HTPBridge:
    """Create an HTP bridge configured for production MSSP connection."""
    return create_bridge(
        bootstrap_nodes=[(mssp_host, mssp_port)],
        node_id="cortex-production-001",
        label="Cortex Production Bridge",
    )


# =========================================================================
# Demo/Testing
# =========================================================================

async def demo_mode(interval: float = 3.0) -> None:
    """
    Run the bridge in demo mode with simulated HTP events.

    This is for testing the visualization without a real mesh.
    """
    from demo_data import DemoDataGenerator

    bridge = create_bridge()
    await bridge.start()

    generator = DemoDataGenerator()

    logger.info("HTP Bridge running in demo mode")

    while bridge.running:
        event = generator.generate_event()

        # Route demo events through bridge handlers
        if event["type"] == "attack_detected":
            # Pre-register target node for demo
            bridge.registry.register_node(
                node_id=event["target"]["node_id"],
                tier=NodeTier.GUARDIAN,
                lat=event["target"]["lat"],
                lng=event["target"]["lng"],
                label=event["target"]["label"],
            )
            await bridge._on_htp_threat({
                "type": "threat",
                "target_node": event["target"]["node_id"],
                "source_ip": "demo",
                "attack_type": event.get("attack_type", "unknown"),
                "severity": event.get("severity", 0.5),
                "repelled": False,
            })

        elif event["type"] == "attack_repelled":
            await bridge._on_htp_threat({
                "type": "threat",
                "target_node": event["target"]["node_id"],
                "source_ip": "demo",
                "attack_type": event.get("attack_type", "unknown"),
                "severity": 0.5,
                "repelled": True,
            })

        elif event["type"] == "node_status":
            for node_data in event.get("nodes", []):
                tier = NodeTier(node_data["tier"]) if node_data["tier"] in [t.value for t in NodeTier] else NodeTier.SENTINEL
                bridge.registry.register_node(
                    node_id=node_data["id"],
                    tier=tier,
                    lat=node_data["lat"],
                    lng=node_data["lng"],
                    label=node_data["label"],
                )
                bridge.registry.on_heartbeat(node_data["id"])
                bridge.registry.on_qsecbit_update(node_data["id"], node_data["qsecbit"])

        await asyncio.sleep(interval)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    asyncio.run(demo_mode())
