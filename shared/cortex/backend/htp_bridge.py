#!/usr/bin/env python3
"""
HTP Bridge - Mesh Participant for Globe Visualization

This module makes the globe visualization a TRUE participant in the HookProbe mesh,
not just a passive observer. The bridge:

1. Connects to the mesh via HTP protocol
2. Subscribes to mesh events (attacks, heartbeats, Qsecbit changes)
3. Participates in DSM gossip (receives threat announcements)
4. Maintains the NodeRegistry with live mesh state
5. Translates HTP events to visualization events

Architecture:
                                HTP Mesh
                                   ↑
                                   │ HTP Protocol (UDP/TCP)
                                   ↓
    ┌───────────────────────────────────────────────────────────┐
    │                      HTP Bridge                            │
    │  ┌─────────────────┐  ┌─────────────────┐  ┌───────────┐ │
    │  │  HTP Client     │→ │  Event Parser   │→ │  Registry │ │
    │  │  (mesh node)    │  │  (HTP→Globe)    │  │  Updates  │ │
    │  └─────────────────┘  └─────────────────┘  └───────────┘ │
    └───────────────────────────────────────────────────────────┘
                                   ↓
                            NodeRegistry
                                   ↓
                            WebSocket Server
                                   ↓
                             Browsers
"""

import asyncio
import logging
from typing import Optional, Dict, Any, Callable
from dataclasses import dataclass
from datetime import datetime

from node_registry import get_registry, NodeTier
from geo_resolver import get_resolver

logger = logging.getLogger(__name__)


@dataclass
class HTPBridgeConfig:
    """Configuration for the HTP bridge."""

    # Mesh connection
    bootstrap_nodes: list  # List of (host, port) tuples to connect to
    node_id: str = "globe-bridge-001"

    # Bridge identity
    tier: str = "nexus"  # Bridge presents as Nexus-class (observer)

    # Geographic location of the bridge itself
    lat: float = 0.0
    lng: float = 0.0
    label: str = "Globe Bridge"

    # Reconnection settings
    reconnect_delay: float = 5.0
    max_reconnect_delay: float = 60.0


class HTPBridge:
    """
    HTP Protocol bridge for globe visualization.

    Connects to the HookProbe mesh as a full participant and translates
    mesh events into visualization updates.
    """

    def __init__(self, config: HTPBridgeConfig):
        self.config = config
        self.registry = get_registry()
        self.geo_resolver = get_resolver()
        self.running = False
        self._htp_client = None
        self._tasks: list = []

    async def start(self) -> None:
        """Start the HTP bridge."""
        self.running = True
        logger.info(f"Starting HTP Bridge: {self.config.node_id}")

        # TODO: Initialize HTP client
        # This will be implemented when integrating with real HTP
        # For now, we'll document the integration points

        """
        Integration with core/htp/transport/htp.py:

        from core.htp.transport.htp import HTPSession, HTPState

        # Create HTP session as an observer node
        self._htp_client = HTPSession(
            mode="observer",  # Don't generate sensor data
            qsecbit_source=None,  # No local Qsecbit
        )

        # Connect to bootstrap nodes
        for host, port in self.config.bootstrap_nodes:
            await self._htp_client.connect(host, port)

        # Subscribe to mesh events
        self._htp_client.on_event("heartbeat", self._on_htp_heartbeat)
        self._htp_client.on_event("threat", self._on_htp_threat)
        self._htp_client.on_event("qsecbit", self._on_htp_qsecbit)
        self._htp_client.on_event("topology", self._on_htp_topology)
        """

        # Start registry liveness monitor
        await self.registry.start_liveness_monitor()

        logger.info("HTP Bridge started (skeleton mode - HTP integration pending)")

    async def stop(self) -> None:
        """Stop the HTP bridge."""
        self.running = False
        await self.registry.stop_liveness_monitor()

        if self._htp_client:
            # await self._htp_client.disconnect()
            pass

        for task in self._tasks:
            task.cancel()

        logger.info("HTP Bridge stopped")

    # =========================================================================
    # HTP Event Handlers (to be connected to real HTP client)
    # =========================================================================

    async def _on_htp_heartbeat(self, event: Dict[str, Any]) -> None:
        """
        Handle HTP heartbeat from a mesh node.

        Expected event format from HTP:
        {
            "node_id": "guardian-sf-001",
            "tier": "guardian",
            "timestamp_us": 1234567890,
            "flow_token": 0x...,
            "entropy_echo": 0x...,
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

        # Update heartbeat
        self.registry.on_heartbeat(node_id)

    async def _on_htp_threat(self, event: Dict[str, Any]) -> None:
        """
        Handle threat detection/repulsion from mesh.

        Expected event format from HTP/DSM:
        {
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
            "node_id": "guardian-nyc-001",
            "qsecbit": 0.62,
            "components": {
                "threats": 0.30,
                "mobile": 0.20,
                "ids": 0.25,
                ...
            }
        }
        """
        node_id = event.get("node_id")
        score = event.get("qsecbit", 0.0)

        if node_id:
            self.registry.on_qsecbit_update(node_id, score)

    async def _on_htp_topology(self, event: Dict[str, Any]) -> None:
        """
        Handle mesh topology change.

        Expected event format:
        {
            "type": "route_established" | "route_lost",
            "source_node": "guardian-sf-001",
            "target_node": "fortress-lon-001",
            "connection_type": "direct" | "relay" | "tunnel",
            "latency_ms": 150.5
        }
        """
        # TODO: Update registry edges
        pass

    # =========================================================================
    # DSM Integration (for threat intelligence sharing)
    # =========================================================================

    async def subscribe_to_dsm_gossip(self) -> None:
        """
        Subscribe to DSM gossip protocol for threat announcements.

        This allows the globe to show mesh-wide threat intelligence,
        not just events from directly connected nodes.
        """

        """
        Integration with shared/dsm/gossip.py:

        from shared.dsm.gossip import GossipSubscriber

        subscriber = GossipSubscriber(
            node_id=self.config.node_id,
            topics=["threats", "alerts", "consensus"],
        )

        subscriber.on_message("threats", self._on_dsm_threat)
        subscriber.on_message("alerts", self._on_dsm_alert)

        await subscriber.start()
        """
        pass

    # =========================================================================
    # Neuro Integration (for neural resonance visualization)
    # =========================================================================

    async def subscribe_to_neuro_events(self) -> None:
        """
        Subscribe to Neuro protocol events for neural weight sync visualization.

        This shows when nodes achieve/lose neural resonance.
        """

        """
        Integration with core/neuro/neural/engine.py:

        from core.neuro.neural.engine import NeuralWeightBroadcast

        broadcast = NeuralWeightBroadcast(observer=True)

        broadcast.on_event("resonance_achieved", self._on_resonance_achieved)
        broadcast.on_event("weight_sync", self._on_weight_sync)

        await broadcast.subscribe()
        """
        pass


# =========================================================================
# Factory function
# =========================================================================

def create_bridge(
    bootstrap_nodes: list = None,
    node_id: str = "globe-bridge-001",
) -> HTPBridge:
    """Create an HTP bridge with default configuration."""

    config = HTPBridgeConfig(
        bootstrap_nodes=bootstrap_nodes or [],
        node_id=node_id,
    )

    return HTPBridge(config)


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
            await bridge._on_htp_threat({
                "target_node": event["target"]["node_id"],
                "source_ip": "demo",
                "attack_type": event.get("attack_type", "unknown"),
                "severity": event.get("severity", 0.5),
                "repelled": False,
            })
            # Pre-register target node for demo
            bridge.registry.register_node(
                node_id=event["target"]["node_id"],
                tier=NodeTier.GUARDIAN,
                lat=event["target"]["lat"],
                lng=event["target"]["lng"],
                label=event["target"]["label"],
            )

        elif event["type"] == "attack_repelled":
            await bridge._on_htp_threat({
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
    logging.basicConfig(level=logging.INFO)
    asyncio.run(demo_mode())
