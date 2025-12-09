#!/usr/bin/env python3
"""
Guardian Connector for Globe Visualization

Connects the Guardian product tier (travel/portable security gateway)
to the globe digital twin visualization.

Integration points:
- products/guardian/lib/guardian_agent.py - Main Guardian agent
- products/guardian/lib/mesh_integration.py - Mesh connectivity
- products/guardian/lib/layer_threat_detector.py - L2-L7 detection
- products/guardian/web/app.py - Flask web UI

Usage (standalone):
    from connectors.guardian import GuardianConnector, GuardianConnectorConfig

    config = GuardianConnectorConfig(
        node_id="guardian-sf-001",
        lat=37.7749,
        lng=-122.4194,
        label="San Francisco Guardian",
    )

    connector = GuardianConnector(config)
    await connector.start()

Usage (Flask integration):
    # In products/guardian/web/app.py
    from visualization.globe.backend.connectors.guardian import create_flask_connector

    globe_connector = create_flask_connector(app)
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

from .base import (
    ProductConnector,
    ConnectorConfig,
    ProductTier,
    ThreatEvent,
    QsecbitStatus,
)

logger = logging.getLogger(__name__)

# Try to import Guardian components
try:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent / 'products' / 'guardian' / 'lib'))
    from guardian_agent import GuardianAgent, GuardianMetrics
    GUARDIAN_AGENT_AVAILABLE = True
except ImportError:
    GUARDIAN_AGENT_AVAILABLE = False
    logger.debug("GuardianAgent not available - using simulation mode")

try:
    from mesh_integration import GuardianMeshAgent
    MESH_AVAILABLE = True
except ImportError:
    MESH_AVAILABLE = False


@dataclass
class GuardianConnectorConfig(ConnectorConfig):
    """Guardian-specific connector configuration."""

    tier: ProductTier = field(default=ProductTier.GUARDIAN)

    # Guardian-specific settings
    guardian_agent_path: str = ""     # Path to guardian_agent.py
    flask_app_host: str = "127.0.0.1" # Flask app host for API queries
    flask_app_port: int = 5000        # Flask app port

    # Network interfaces
    wan_interface: str = "eth0"       # WAN interface
    lan_interface: str = "wlan0"      # LAN interface (AP)

    # Feature flags
    mobile_protection_enabled: bool = True
    ids_enabled: bool = True          # Suricata/Zeek
    xdp_enabled: bool = True          # XDP/eBPF

    # Heartbeat (Guardian is portable, more frequent updates)
    heartbeat_interval: float = 15.0  # 15 seconds (portable device, more responsive)
    qsecbit_report_interval: float = 5.0


class GuardianConnector(ProductConnector):
    """
    Connector for Guardian tier products.

    The Guardian is a portable security gateway (1.5GB RAM) designed for
    travelers. It creates a secure WiFi hotspot and protects connected devices.

    Key features reported to globe:
    - Connected client count
    - Layer 2-7 threat detection
    - Mobile network protection status
    - XDP/eBPF statistics
    - IDS alerts (Suricata/Zeek)
    """

    def __init__(self, config: GuardianConnectorConfig):
        super().__init__(config)
        self.guardian_config = config

        # Guardian-specific state
        self._guardian_agent: Optional[Any] = None
        self._mesh_agent: Optional[Any] = None
        self._threat_cache: List[ThreatEvent] = []
        self._last_metrics: Optional[Any] = None

        # Statistics
        self._connected_clients = 0
        self._blocked_domains = 0
        self._xdp_drops = 0

        # Initialize Guardian agent if available
        if GUARDIAN_AGENT_AVAILABLE:
            try:
                self._guardian_agent = GuardianAgent()
                logger.info("GuardianAgent initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize GuardianAgent: {e}")

    async def collect_qsecbit(self) -> float:
        """Collect Qsecbit score from Guardian agent."""
        if self._guardian_agent and hasattr(self._guardian_agent, 'get_qsecbit_score'):
            try:
                return self._guardian_agent.get_qsecbit_score()
            except Exception as e:
                logger.error(f"Failed to get Qsecbit from GuardianAgent: {e}")

        # Fallback: Query Flask API
        if self.guardian_config.flask_app_host:
            try:
                return await self._query_flask_qsecbit()
            except Exception as e:
                logger.debug(f"Flask API query failed: {e}")

        # Last resort: Generate based on state
        return self._estimate_qsecbit()

    async def collect_qsecbit_components(self) -> Dict[str, float]:
        """Collect Qsecbit component breakdown."""
        if self._guardian_agent and hasattr(self._guardian_agent, 'get_metrics'):
            try:
                metrics = self._guardian_agent.get_metrics()
                self._last_metrics = metrics
                return metrics.components if hasattr(metrics, 'components') else {}
            except Exception as e:
                logger.error(f"Failed to get metrics: {e}")

        # Return default Guardian components
        return {
            "threats": 0.0,
            "mobile": 0.0,
            "ids": 0.0,
            "xdp": 0.0,
            "network": 0.0,
            "dnsxai": 0.0,
        }

    async def collect_statistics(self) -> Dict[str, Any]:
        """Collect Guardian-specific statistics."""
        stats = {
            "connected_clients": self._connected_clients,
            "blocked_domains": self._blocked_domains,
            "xdp_drops": self._xdp_drops,
            "ids_alerts": 0,
            "wan_interface": self.guardian_config.wan_interface,
            "ap_active": True,  # WiFi AP status
        }

        if self._guardian_agent:
            try:
                # Get detailed stats from agent
                if hasattr(self._guardian_agent, 'get_stats'):
                    agent_stats = self._guardian_agent.get_stats()
                    stats.update(agent_stats)
            except Exception:
                pass

        # Update node metadata
        self.state.metadata = {
            "product": "guardian",
            "version": "5.0",
            "features": {
                "mobile_protection": self.guardian_config.mobile_protection_enabled,
                "ids": self.guardian_config.ids_enabled,
                "xdp": self.guardian_config.xdp_enabled,
            },
            **stats,
        }

        return stats

    async def get_recent_threats(self) -> List[ThreatEvent]:
        """Get recent threats detected by Guardian."""
        threats = []

        if self._guardian_agent:
            try:
                # Query agent for recent threats
                if hasattr(self._guardian_agent, 'get_recent_threats'):
                    raw_threats = self._guardian_agent.get_recent_threats()
                    for t in raw_threats:
                        threat = ThreatEvent(
                            source_ip=t.get('source_ip', ''),
                            attack_type=t.get('threat_type', 'unknown'),
                            severity=t.get('severity', 5) / 10.0,
                            repelled=t.get('blocked', False),
                            mitigation_method=t.get('action', ''),
                            timestamp=datetime.fromisoformat(t['timestamp']) if 'timestamp' in t else None,
                        )
                        threats.append(threat)
            except Exception as e:
                logger.error(f"Failed to get threats: {e}")

        return threats

    # =========================================================================
    # Guardian-specific methods
    # =========================================================================

    async def _query_flask_qsecbit(self) -> float:
        """Query Qsecbit from Guardian Flask API."""
        import aiohttp

        url = f"http://{self.guardian_config.flask_app_host}:{self.guardian_config.flask_app_port}/api/qsecbit"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=2)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return float(data.get('score', 0.0))
        except Exception:
            pass

        return 0.0

    def _estimate_qsecbit(self) -> float:
        """Estimate Qsecbit based on current state."""
        # Simple estimation based on threat cache and statistics
        base_score = 0.2  # Baseline

        # Increase score based on recent threats
        threat_factor = min(0.4, len(self._threat_cache) * 0.05)

        # Consider client count (more clients = more attack surface)
        client_factor = min(0.2, self._connected_clients * 0.02)

        return min(1.0, base_score + threat_factor + client_factor)

    def update_client_count(self, count: int) -> None:
        """Update connected client count (called from Flask app)."""
        self._connected_clients = count

    def report_dns_block(self, domain: str) -> None:
        """Report a DNS block (called from dnsXai integration)."""
        self._blocked_domains += 1

    def report_xdp_drop(self, source_ip: str, reason: str) -> None:
        """Report an XDP packet drop."""
        self._xdp_drops += 1

        # Create threat event for significant drops
        if reason in ["ddos", "scan", "malicious"]:
            threat = ThreatEvent(
                source_ip=source_ip,
                attack_type=reason,
                severity=0.6,
                repelled=True,
                mitigation_method="xdp_drop",
                timestamp=datetime.utcnow(),
            )
            self._threat_cache.append(threat)

            # Keep cache bounded
            if len(self._threat_cache) > 100:
                self._threat_cache.pop(0)


def create_guardian_connector(
    node_id: str,
    lat: float,
    lng: float,
    label: str = "",
    **kwargs
) -> GuardianConnector:
    """Factory function to create a Guardian connector."""
    config = GuardianConnectorConfig(
        node_id=node_id,
        lat=lat,
        lng=lng,
        label=label or f"Guardian {node_id}",
        **kwargs
    )
    return GuardianConnector(config)


def create_flask_connector(flask_app, node_id: str = None, lat: float = 0, lng: float = 0, label: str = "") -> GuardianConnector:
    """
    Create a Guardian connector integrated with a Flask app.

    Usage in products/guardian/web/app.py:
        from visualization.globe.backend.connectors.guardian import create_flask_connector

        globe_connector = create_flask_connector(
            app,
            node_id="guardian-home-001",
            lat=37.7749,
            lng=-122.4194,
            label="Home Guardian"
        )

        @app.before_first_request
        async def start_globe():
            await globe_connector.start()
    """
    import socket

    # Auto-generate node_id if not provided
    if not node_id:
        hostname = socket.gethostname()
        node_id = f"guardian-{hostname}"

    config = GuardianConnectorConfig(
        node_id=node_id,
        lat=lat,
        lng=lng,
        label=label or f"Guardian ({socket.gethostname()})",
        flask_app_host=flask_app.config.get('HOST', '127.0.0.1'),
        flask_app_port=flask_app.config.get('PORT', 5000),
    )

    connector = GuardianConnector(config)

    # Register Flask context hooks if possible
    try:
        @flask_app.before_request
        def update_connector_stats():
            # Update stats on each request
            pass

        logger.info(f"Guardian connector registered with Flask app: {node_id}")
    except Exception as e:
        logger.warning(f"Could not register Flask hooks: {e}")

    return connector
