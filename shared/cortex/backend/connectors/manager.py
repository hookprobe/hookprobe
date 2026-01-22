#!/usr/bin/env python3
"""
Connector Manager - Aggregates all product connectors for Globe Visualization

The ConnectorManager:
1. Manages multiple product connectors (Guardian, Fortress, Nexus)
2. Aggregates events from all products
3. Forwards events to the globe HTP bridge
4. Provides unified API for the globe backend

Usage:
    from connectors import ConnectorManager
    from connectors.guardian import GuardianConnector

    manager = ConnectorManager()
    manager.register(GuardianConnector(config))
    await manager.start()
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime

from .base import ProductConnector, NodeState, ProductTier

logger = logging.getLogger(__name__)


class ConnectorManager:
    """
    Manages all product connectors and aggregates their events.

    This is the central hub that connects all HookProbe products
    to the globe visualization.
    """

    def __init__(self):
        self.connectors: Dict[str, ProductConnector] = {}
        self.running = False
        self._event_callbacks: List[Callable[[Dict[str, Any]], None]] = []
        self._stats = {
            "total_events": 0,
            "events_by_type": {},
            "events_by_tier": {},
            "start_time": None,
        }

    def register(self, connector: ProductConnector) -> None:
        """
        Register a product connector.

        Args:
            connector: ProductConnector instance
        """
        node_id = connector.config.node_id

        if node_id in self.connectors:
            logger.warning(f"Replacing existing connector: {node_id}")

        self.connectors[node_id] = connector

        # Subscribe to connector events
        connector.on_event(self._handle_connector_event)

        logger.info(
            f"Registered {connector.config.tier.value} connector: {node_id} "
            f"at ({connector.config.lat}, {connector.config.lng})"
        )

    def unregister(self, node_id: str) -> bool:
        """
        Unregister a product connector.

        Args:
            node_id: Node identifier to unregister

        Returns:
            bool: True if connector was found and removed
        """
        if node_id in self.connectors:
            del self.connectors[node_id]
            logger.info(f"Unregistered connector: {node_id}")
            return True
        return False

    def on_event(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        Register a callback for aggregated events.

        The callback will receive events from ALL registered connectors.
        """
        self._event_callbacks.append(callback)

    async def start(self) -> None:
        """Start all registered connectors."""
        if self.running:
            return

        self.running = True
        self._stats["start_time"] = datetime.utcnow()

        logger.info(f"Starting ConnectorManager with {len(self.connectors)} connectors")

        # Start all connectors concurrently
        await asyncio.gather(
            *[connector.start() for connector in self.connectors.values()],
            return_exceptions=True
        )

    async def stop(self) -> None:
        """Stop all connectors."""
        self.running = False

        # Stop all connectors
        await asyncio.gather(
            *[connector.stop() for connector in self.connectors.values()],
            return_exceptions=True
        )

        logger.info("ConnectorManager stopped")

    def _handle_connector_event(self, event: Dict[str, Any]) -> None:
        """Handle an event from a connector."""
        # Update statistics
        self._stats["total_events"] += 1
        event_type = event.get("type", "unknown")
        self._stats["events_by_type"][event_type] = (
            self._stats["events_by_type"].get(event_type, 0) + 1
        )

        # Track by tier if node_id present
        node_id = event.get("node_id")
        if node_id and node_id in self.connectors:
            tier = self.connectors[node_id].config.tier.value
            self._stats["events_by_tier"][tier] = (
                self._stats["events_by_tier"].get(tier, 0) + 1
            )

        # Forward to all registered callbacks
        for callback in self._event_callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Event callback error: {e}")

    def get_all_states(self) -> List[Dict[str, Any]]:
        """Get current state of all connectors."""
        return [
            connector.get_state().to_dict()
            for connector in self.connectors.values()
        ]

    def get_state(self, node_id: str) -> Optional[NodeState]:
        """Get state of a specific connector."""
        connector = self.connectors.get(node_id)
        return connector.get_state() if connector else None

    def get_snapshot(self) -> Dict[str, Any]:
        """Get full snapshot for globe initialization."""
        nodes_by_tier = {tier.value: [] for tier in ProductTier}

        for connector in self.connectors.values():
            state = connector.get_state().to_dict()
            nodes_by_tier[connector.config.tier.value].append(state)

        return {
            "type": "snapshot",
            "nodes": self.get_all_states(),
            "nodes_by_tier": nodes_by_tier,
            "stats": {
                "total_nodes": len(self.connectors),
                "by_tier": {
                    tier.value: sum(
                        1 for c in self.connectors.values()
                        if c.config.tier == tier
                    )
                    for tier in ProductTier
                },
                "online": sum(
                    1 for c in self.connectors.values()
                    if c.get_state().online
                ),
            },
            "timestamp": datetime.utcnow().isoformat(),
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get manager statistics."""
        uptime = 0
        if self._stats["start_time"]:
            uptime = int((datetime.utcnow() - self._stats["start_time"]).total_seconds())

        return {
            **self._stats,
            "uptime_seconds": uptime,
            "registered_connectors": len(self.connectors),
            "start_time": (
                self._stats["start_time"].isoformat()
                if self._stats["start_time"] else None
            ),
        }

    def get_connectors_by_tier(self, tier: ProductTier) -> List[ProductConnector]:
        """Get all connectors of a specific tier."""
        return [
            c for c in self.connectors.values()
            if c.config.tier == tier
        ]


# Global manager instance
_manager: Optional[ConnectorManager] = None


def get_manager() -> ConnectorManager:
    """Get or create the global connector manager."""
    global _manager
    if _manager is None:
        _manager = ConnectorManager()
    return _manager
