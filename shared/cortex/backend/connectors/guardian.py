#!/usr/bin/env python3
"""
Guardian Connector for Globe Visualization 

Connects the Guardian product tier (travel/portable security gateway)
to the globe digital twin visualization using Qsecbit UnifiedThreatEngine.

Integration points:
- core/qsecbit/unified_engine.py - UnifiedThreatEngine
- core/qsecbit/mesh_bridge.py - Mesh threat intelligence bridge
- products/guardian/lib/guardian_agent.py - Main Guardian agent
- products/guardian/web/app.py - Flask web UI

Unified Features:
- AI/ML threat classification across L2-L7
- Real-time energy-based anomaly detection
- Mesh consciousness integration for collective defense
- Attack chain correlation and MITRE ATT&CK mapping

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
    from shared.cortex.backend.connectors.guardian import create_flask_connector

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
    ThreatEvent as CortexThreatEvent,
    QsecbitStatus,
)

logger = logging.getLogger(__name__)

#  Try to import Qsecbit Unified Engine components
UNIFIED_ENGINE_AVAILABLE = False
UnifiedThreatEngine = None
UnifiedEngineConfig = None
DeploymentType = None
QsecbitMeshBridge = None
create_mesh_bridge = None
ThreatEvent = None
ThreatSeverity = None
ResponseAction = None

try:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent / 'core'))
    from qsecbit import (
        UnifiedThreatEngine,
        UnifiedEngineConfig,
        DeploymentType,
        QsecbitMeshBridge,
        create_mesh_bridge,
        ThreatEvent,
        ThreatSeverity,
        ResponseAction,
    )
    UNIFIED_ENGINE_AVAILABLE = True
    logger.info("Qsecbit UnifiedThreatEngine loaded successfully")
except ImportError as e:
    logger.warning(f"Qsecbit Unified not available: {e} - using legacy mode")

# Legacy: Try to import Guardian components
GUARDIAN_AGENT_AVAILABLE = False
try:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent / 'products' / 'guardian' / 'lib'))
    from guardian_agent import GuardianAgent, GuardianMetrics
    GUARDIAN_AGENT_AVAILABLE = True
except ImportError:
    logger.debug("GuardianAgent not available - using simulation mode")

# Try to import mesh consciousness
MESH_AVAILABLE = False
MeshConsciousness = None
try:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'mesh'))
    from consciousness import MeshConsciousness
    MESH_AVAILABLE = True
except ImportError:
    logger.debug("MeshConsciousness not available")


@dataclass
class GuardianConnectorConfig(ConnectorConfig):
    """Guardian-specific connector configuration ."""

    tier: ProductTier = field(default=ProductTier.GUARDIAN)

    # Guardian-specific settings
    guardian_agent_path: str = ""     # Path to guardian_agent.py
    flask_app_host: str = "127.0.0.1" # Flask app host for API queries
    flask_app_port: int = 5000        # Flask app port
    data_dir: str = "/opt/hookprobe/guardian/data"  # Data directory

    # Network interfaces
    wan_interface: str = "eth0"       # WAN interface
    lan_interface: str = "wlan0"      # LAN interface (AP)

    # Unified Feature flags
    use_unified_engine: bool = True   # Use UnifiedThreatEngine
    enable_ml_classification: bool = True  # AI/ML attack classification
    enable_response_orchestration: bool = True  # Automated mitigation
    enable_mesh_reporting: bool = True  # Report threats to mesh
    enable_attack_chain_correlation: bool = True  # Attack chain detection

    # Legacy feature flags
    mobile_protection_enabled: bool = True
    ids_enabled: bool = True          # Suricata/Zeek
    xdp_enabled: bool = True          # XDP/eBPF

    # Heartbeat (Guardian is portable, more frequent updates)
    heartbeat_interval: float = 15.0  # 15 seconds (portable device, more responsive)
    qsecbit_report_interval: float = 5.0


class GuardianConnector(ProductConnector):
    """
    Connector for Guardian tier products .

    The Guardian is a portable security gateway (1.5GB RAM) designed for
    travelers. It creates a secure WiFi hotspot and protects connected devices.

    Unified Features:
    - UnifiedThreatEngine for AI/ML threat detection across L2-L7
    - 27 attack types with MITRE ATT&CK mapping
    - Mesh consciousness integration for collective defense
    - Real-time energy-based anomaly detection
    - Attack chain correlation

    Key metrics reported to globe:
    - Connected client count
    - Layer 2-7 threat detection with ML classification
    - Energy anomaly indicators
    - XDP/eBPF blocking statistics
    - Mesh collective score
    """

    def __init__(self, config: GuardianConnectorConfig):
        super().__init__(config)
        self.guardian_config = config

        # Unified Unified Engine
        self._unified_engine: Optional[Any] = None
        self._mesh_bridge: Optional[Any] = None
        self._mesh_consciousness: Optional[Any] = None

        # Legacy Guardian agent (fallback)
        self._guardian_agent: Optional[Any] = None
        self._threat_cache: List[CortexThreatEvent] = []
        self._last_unified_score: Optional[Any] = None

        # Statistics
        self._connected_clients = 0
        self._blocked_domains = 0
        self._xdp_drops = 0
        self._threats_detected_by_layer = {
            'L2': 0, 'L3': 0, 'L4': 0, 'L5': 0, 'L7': 0
        }
        self._attack_chains_detected = 0

        # Initialize UnifiedThreatEngine if available and enabled
        if UNIFIED_ENGINE_AVAILABLE and config.use_unified_engine:
            self._init_unified_engine()
        elif GUARDIAN_AGENT_AVAILABLE:
            # Fallback to legacy Guardian agent
            try:
                self._guardian_agent = GuardianAgent(data_dir=config.data_dir)
                logger.info("GuardianAgent (legacy) initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize GuardianAgent: {e}")

    def _init_unified_engine(self) -> None:
        """Initialize the UnifiedThreatEngine."""
        try:
            # Create engine configuration
            engine_config = UnifiedEngineConfig(
                deployment_type=DeploymentType.GUARDIAN,
                enable_ml_classification=self.guardian_config.enable_ml_classification,
                enable_response_orchestration=self.guardian_config.enable_response_orchestration,
            )

            # Initialize the unified engine
            self._unified_engine = UnifiedThreatEngine(
                config=engine_config,
                data_dir=self.guardian_config.data_dir
            )

            # Initialize mesh bridge for threat sharing
            if self.guardian_config.enable_mesh_reporting:
                self._mesh_bridge = create_mesh_bridge(
                    tier='guardian',
                    enable_mesh=MESH_AVAILABLE,
                    enable_cortex=True,
                    min_severity='MEDIUM'
                )

                # Connect mesh bridge to Cortex events
                if self._mesh_bridge:
                    self._mesh_bridge.register_cortex_callback(self._handle_mesh_cortex_event)

            logger.info("Qsecbit UnifiedThreatEngine initialized for Guardian")

        except Exception as e:
            logger.error(f"Failed to initialize UnifiedThreatEngine: {e}")
            # Fallback to legacy agent
            if GUARDIAN_AGENT_AVAILABLE:
                self._guardian_agent = GuardianAgent(data_dir=self.guardian_config.data_dir)

    def _handle_mesh_cortex_event(self, event: Dict[str, Any]) -> None:
        """Handle Cortex events from mesh bridge."""
        # Convert mesh event to Cortex threat event
        threat = CortexThreatEvent(
            source_ip=event.get('source', {}).get('ip', ''),
            source_lat=event.get('source', {}).get('lat'),
            source_lng=event.get('source', {}).get('lng'),
            attack_type=event.get('attack_type', 'unknown'),
            severity=event.get('severity', 0.5),
            repelled=event.get('type') == 'attack_repelled',
            mitigation_method=event.get('mitigation', ''),
            timestamp=datetime.utcnow(),
        )
        self._threat_cache.append(threat)

        # Keep cache bounded
        if len(self._threat_cache) > 100:
            self._threat_cache.pop(0)

        # Emit to globe visualization
        self._emit_event(event)

    async def collect_qsecbit(self) -> float:
        """Collect Qsecbit score using UnifiedThreatEngine."""
        #  Use unified engine for detection
        if self._unified_engine:
            try:
                # Run threat detection cycle
                unified_score = self._unified_engine.detect()
                self._last_unified_score = unified_score

                # Report threats to mesh if bridge is connected
                if self._mesh_bridge and unified_score.threats:
                    self._mesh_bridge.report_threats(unified_score.threats)

                    # Update layer statistics
                    for threat in unified_score.threats:
                        layer_name = threat.layer.name if threat.layer else 'UNKNOWN'
                        if layer_name in self._threats_detected_by_layer:
                            self._threats_detected_by_layer[layer_name] += 1

                # Check for attack chains
                if unified_score.attack_chains:
                    self._attack_chains_detected += len(unified_score.attack_chains)

                return unified_score.unified_score

            except Exception as e:
                logger.error(f"Failed to run UnifiedThreatEngine: {e}")

        # Fallback: Legacy Guardian agent
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
        """Collect Qsecbit Unified component breakdown by OSI layer."""
        #  Get layer scores from unified engine
        if self._unified_engine and self._last_unified_score:
            try:
                components = {}
                for layer_score in self._last_unified_score.layer_scores:
                    layer_name = layer_score.layer.name
                    components[f"layer_{layer_name.lower()}"] = layer_score.score

                # Add additional Unified components
                components['energy_anomaly'] = self._last_unified_score.energy_anomaly_score
                components['behavioral'] = self._last_unified_score.behavioral_score
                components['chain_correlation'] = self._last_unified_score.chain_correlation_score

                # Add mesh collective score if available
                if self._mesh_bridge:
                    collective = self._mesh_bridge.get_collective_score()
                    if collective.get('collective_score') is not None:
                        components['mesh_collective'] = collective['collective_score']

                return components

            except Exception as e:
                logger.error(f"Failed to get Unified components: {e}")

        # Fallback: Legacy components
        if self._guardian_agent and hasattr(self._guardian_agent, 'get_metrics'):
            try:
                metrics = self._guardian_agent.get_metrics()
                return metrics.components if hasattr(metrics, 'components') else {}
            except Exception as e:
                logger.error(f"Failed to get metrics: {e}")

        # Return default Guardian Unified components
        return {
            "layer_l2": 0.0,
            "layer_l3": 0.0,
            "layer_l4": 0.0,
            "layer_l5": 0.0,
            "layer_l7": 0.0,
            "energy_anomaly": 0.0,
            "behavioral": 0.0,
            "chain_correlation": 0.0,
            "mesh_collective": 0.0,
        }

    async def collect_statistics(self) -> Dict[str, Any]:
        """Collect Guardian Unified statistics."""
        stats = {
            "connected_clients": self._connected_clients,
            "blocked_domains": self._blocked_domains,
            "xdp_drops": self._xdp_drops,
            "ids_alerts": 0,
            "wan_interface": self.guardian_config.wan_interface,
            "ap_active": True,  # WiFi AP status
        }

        # Unified statistics
        if self._unified_engine and self._last_unified_score:
            stats["v6_enabled"] = True
            stats["threats_by_layer"] = self._threats_detected_by_layer.copy()
            stats["attack_chains_detected"] = self._attack_chains_detected
            stats["ml_classification_enabled"] = self.guardian_config.enable_ml_classification
            stats["total_threats"] = len(self._last_unified_score.threats)

            # Attack type breakdown
            attack_types = {}
            for threat in self._last_unified_score.threats:
                attack_name = threat.attack_type.name
                attack_types[attack_name] = attack_types.get(attack_name, 0) + 1
            stats["attack_type_breakdown"] = attack_types

        # Mesh statistics
        if self._mesh_bridge:
            mesh_stats = self._mesh_bridge.get_statistics()
            stats["mesh_threats_reported"] = mesh_stats.get('threats_reported', 0)
            stats["mesh_threats_received"] = mesh_stats.get('threats_received', 0)
            stats["mesh_connected"] = mesh_stats.get('mesh_connected', False)

        # Legacy Guardian agent stats
        if self._guardian_agent:
            try:
                if hasattr(self._guardian_agent, 'get_stats'):
                    agent_stats = self._guardian_agent.get_stats()
                    stats.update(agent_stats)
            except Exception:
                pass

        # Update node metadata
        self.state.metadata = {
            "product": "guardian",
            "version": "6.0",
            "engine": "UnifiedThreatEngine" if self._unified_engine else "Legacy",
            "features": {
                "unified_engine": self._unified_engine is not None,
                "ml_classification": self.guardian_config.enable_ml_classification,
                "mesh_reporting": self.guardian_config.enable_mesh_reporting,
                "attack_chain_detection": self.guardian_config.enable_attack_chain_correlation,
                "mobile_protection": self.guardian_config.mobile_protection_enabled,
                "ids": self.guardian_config.ids_enabled,
                "xdp": self.guardian_config.xdp_enabled,
            },
            **stats,
        }

        return stats

    async def get_recent_threats(self) -> List[CortexThreatEvent]:
        """Get recent threats detected by Guardian."""
        threats = []

        #  Get threats from unified engine
        if self._unified_engine and self._last_unified_score:
            try:
                for qsecbit_threat in self._last_unified_score.threats[-20:]:
                    # Convert Qsecbit ThreatEvent to Cortex ThreatEvent
                    severity_value = qsecbit_threat.severity.value if qsecbit_threat.severity else 3
                    repelled = bool(
                        qsecbit_threat.response_actions and
                        any(a in [ResponseAction.BLOCK_IP, ResponseAction.BLOCK_MAC, ResponseAction.RATE_LIMIT]
                            for a in qsecbit_threat.response_actions)
                    )

                    threat = CortexThreatEvent(
                        source_ip=qsecbit_threat.source_ip or '',
                        attack_type=qsecbit_threat.attack_type.name if qsecbit_threat.attack_type else 'unknown',
                        severity=1.0 - (severity_value / 5.0),  # Convert 1-5 to 0-1 (inverted)
                        description=f"MITRE: {qsecbit_threat.mitre_attack_id or 'N/A'}",
                        repelled=repelled,
                        mitigation_method=qsecbit_threat.response_actions[0].name if qsecbit_threat.response_actions else '',
                        timestamp=qsecbit_threat.timestamp,
                        ioc_type='ip' if qsecbit_threat.source_ip else 'pattern',
                        ioc_value=qsecbit_threat.source_ip or qsecbit_threat.attack_type.name,
                    )
                    threats.append(threat)

            except Exception as e:
                logger.error(f"Failed to get Unified threats: {e}")

        # Include cached threats from mesh
        threats.extend(self._threat_cache[-10:])

        # Legacy: Query Guardian agent
        if not threats and self._guardian_agent:
            try:
                if hasattr(self._guardian_agent, 'get_recent_threats'):
                    raw_threats = self._guardian_agent.get_recent_threats()
                    for t in raw_threats:
                        threat = CortexThreatEvent(
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
    use_unified_engine: bool = True,
    enable_ml: bool = True,
    enable_mesh: bool = True,
    **kwargs
) -> GuardianConnector:
    """
    Factory function to create a Guardian connector with Unified support.

    Args:
        node_id: Unique identifier for this Guardian node
        lat: Latitude for globe placement
        lng: Longitude for globe placement
        label: Human-readable label
        use_unified_engine: Use UnifiedThreatEngine (default: True)
        enable_ml: Enable AI/ML classification (default: True)
        enable_mesh: Enable mesh threat reporting (default: True)
        **kwargs: Additional GuardianConnectorConfig options

    Returns:
        Configured GuardianConnector instance
    """
    config = GuardianConnectorConfig(
        node_id=node_id,
        lat=lat,
        lng=lng,
        label=label or f"Guardian {node_id}",
        use_unified_engine=use_unified_engine,
        enable_ml_classification=enable_ml,
        enable_mesh_reporting=enable_mesh,
        **kwargs
    )
    return GuardianConnector(config)


def create_flask_connector(
    flask_app,
    node_id: str = None,
    lat: float = 0,
    lng: float = 0,
    label: str = "",
    use_unified_engine: bool = True,
    enable_ml: bool = True,
    enable_mesh: bool = True
) -> GuardianConnector:
    """
    Create a Guardian connector integrated with a Flask app .

    This factory function creates a GuardianConnector that:
    - Uses Qsecbit UnifiedThreatEngine for AI/ML threat detection
    - Reports threats to the mesh consciousness for collective defense
    - Publishes events to Cortex visualization for real-time globe display

    Usage in products/guardian/web/app.py:
        from shared.cortex.backend.connectors.guardian import create_flask_connector

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

    Args:
        flask_app: Flask application instance
        node_id: Unique node identifier (auto-generated if not provided)
        lat: Latitude for globe placement
        lng: Longitude for globe placement
        label: Human-readable label
        use_unified_engine: Use UnifiedThreatEngine (default: True)
        enable_ml: Enable AI/ML classification (default: True)
        enable_mesh: Enable mesh threat reporting (default: True)

    Returns:
        Configured GuardianConnector instance with Unified features
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
        use_unified_engine=use_unified_engine,
        enable_ml_classification=enable_ml,
        enable_mesh_reporting=enable_mesh,
    )

    connector = GuardianConnector(config)

    # Register Flask context hooks if possible
    try:
        @flask_app.before_request
        def update_connector_stats():
            # Update stats on each request
            pass

        logger.info(f"Guardian Unified connector registered with Flask app: {node_id}")
        if use_unified_engine and UNIFIED_ENGINE_AVAILABLE:
            logger.info("  -> UnifiedThreatEngine: ENABLED")
            logger.info("  -> ML Classification: " + ("ENABLED" if enable_ml else "DISABLED"))
            logger.info("  -> Mesh Reporting: " + ("ENABLED" if enable_mesh else "DISABLED"))
    except Exception as e:
        logger.warning(f"Could not register Flask hooks: {e}")

    return connector
