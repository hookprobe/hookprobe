"""
HookProbe Fortress Library

Core modules for the Fortress small business security gateway.
Extends Guardian capabilities with:
- PostgreSQL database integration
- VLAN management
- Device tracking with network segmentation
- SDN Autopilot for automatic device classification
- AI-powered device fingerprinting (99% accuracy)
- Ecosystem Bubble - Atmospheric Presence networking
- Business reporting
"""

from .config import FortressConfig, VLANConfig, load_config, get_config
from .database import Database, get_db

# Lazy imports to avoid circular dependencies
def get_device_manager():
    """Get the device manager singleton."""
    from .device_manager import get_device_manager as _get_dm
    return _get_dm()

def get_vlan_manager():
    """Get the VLAN manager singleton."""
    from .vlan_manager import get_vlan_manager as _get_vm
    return _get_vm()

def get_sdn_autopilot(ovs_bridge: str = 'FTS'):
    """Get the SDN autopilot singleton."""
    from .sdn_autopilot import get_sdn_autopilot as _get_sdn
    return _get_sdn(ovs_bridge)

def get_network_policy_manager():
    """Get the network policy manager singleton."""
    from .network_policy_manager import NetworkPolicyManager
    return NetworkPolicyManager()

def get_device_data_manager():
    """Get the device data manager singleton (file-based CRUD)."""
    from .device_data_manager import get_device_data_manager as _get_ddm
    return _get_ddm()


# ============================================================
# AI-POWERED DEVICE FINGERPRINTING (Proprietary)
# ============================================================

def get_ml_fingerprint_classifier():
    """Get the ML fingerprint classifier singleton.

    XGBoost-based device classifier with active learning
    for 99%+ device identification accuracy.
    """
    from .ml_fingerprint_classifier import get_classifier
    return get_classifier()

def get_ja3_fingerprinter():
    """Get the JA3 TLS fingerprinter.

    Passive TLS fingerprinting for OS/application detection.
    """
    from .ja3_fingerprint import JA3Fingerprinter
    return JA3Fingerprinter()

def get_unified_fingerprint_engine():
    """Get the unified fingerprint engine singleton.

    Combines all fingerprinting signals with weighted ensemble voting:
    - DHCP Option 55 fingerprinting
    - MAC OUI lookup
    - Hostname analysis
    - mDNS service discovery
    - JA3/TLS fingerprinting
    - TCP stack analysis
    - Fingerbank API enrichment
    """
    from .unified_fingerprint_engine import get_fingerprint_engine
    return get_fingerprint_engine()


# ============================================================
# ECOSYSTEM BUBBLE - ATMOSPHERIC PRESENCE (Proprietary)
# ============================================================

def get_presence_sensor():
    """Get the multi-modal presence sensor.

    Detects device presence through:
    - mDNS/Bonjour service discovery
    - BLE proximity signatures
    - Spatial/temporal correlation
    """
    from .presence_sensor import get_presence_sensor as _get_ps
    return _get_ps()

def get_behavior_clustering_engine():
    """Get the behavioral clustering engine.

    DBSCAN-based unsupervised clustering for detecting
    "user bubbles" - devices belonging to the same person.
    """
    from .behavior_clustering import get_clustering_engine
    return get_clustering_engine()

def get_ecosystem_bubble_manager():
    """Get the ecosystem bubble manager singleton.

    Orchestrates presence sensing, behavioral clustering, and
    SDN policy enforcement for same-user device groups.
    """
    from .ecosystem_bubble import get_bubble_manager
    return get_bubble_manager()


def get_d2d_connection_graph():
    """Get the D2D connection graph analyzer.

    Parses Zeek conn.log to detect device-to-device communication
    patterns and calculate affinity scores for bubble detection.

    Affinity Score Formula:
    S_aff = (Discovery Hits × 10) + (D2D Flows × 5) + (Temporal Sync × 2)
    """
    from .connection_graph import get_connection_analyzer
    return get_connection_analyzer()


# ============================================================
# INTEGRATION MODULES (Gap Implementations)
# ============================================================

def get_clickhouse_graph_store():
    """Get ClickHouse graph storage for AI learning.

    Persists device relationships to ClickHouse for:
    - Trend analysis over time
    - AI model training
    - Grafana dashboards
    """
    from .clickhouse_graph import get_clickhouse_store
    return get_clickhouse_store()


def get_n8n_webhook_client():
    """Get n8n webhook client for automation.

    Sends events to n8n for workflow automation:
    - Bubble changes
    - Device joins/leaves
    - Manual corrections
    """
    from .n8n_webhook import get_webhook_client
    return get_webhook_client()


def get_reinforcement_feedback_engine():
    """Get reinforcement learning feedback engine.

    Learns from user manual corrections to improve
    automatic bubble assignment over time.
    """
    from .reinforcement_feedback import get_feedback_engine
    return get_feedback_engine()


# ============================================================
# AI AUTOPILOT - EVENT-DRIVEN EFFICIENCY (Proprietary)
# ============================================================

def get_efficiency_engine():
    """Get the AI Autopilot efficiency engine singleton.

    Central coordinator for event-driven device identification.
    Orchestrates DHCP sentinel, MAC watcher, and on-demand probes.
    """
    from .autopilot.efficiency_engine import get_efficiency_engine as _get_ee
    return _get_ee()


def get_dhcp_sentinel():
    """Get the DHCP sentinel singleton.

    Low-power hook into dnsmasq DHCP events for new device detection.
    """
    from .autopilot.dhcp_sentinel import get_dhcp_sentinel as _get_ds
    return _get_ds()


def get_mac_watcher():
    """Get the OVS MAC watcher singleton.

    Monitors OVS MAC table for unknown devices.
    """
    from .autopilot.mac_watcher import get_mac_watcher as _get_mw
    return _get_mw()


def get_probe_service():
    """Get the on-demand probe service singleton.

    Performs burst packet capture for device fingerprinting.
    """
    from .autopilot.probe_service import get_probe_service as _get_ps
    return _get_ps()


def get_ipfix_collector():
    """Get the IPFIX collector singleton.

    Collects sampled flow data for D2D relationship detection.
    """
    from .autopilot.ipfix_collector import get_ipfix_collector as _get_ic
    return _get_ic()


__all__ = [
    # Config
    'FortressConfig',
    'VLANConfig',
    'load_config',
    'get_config',
    # Database
    'Database',
    'get_db',
    # Device management
    'get_device_manager',
    'get_vlan_manager',
    'get_sdn_autopilot',
    'get_network_policy_manager',
    'get_device_data_manager',
    # AI-Powered Device Fingerprinting (Proprietary)
    'get_ml_fingerprint_classifier',
    'get_ja3_fingerprinter',
    'get_unified_fingerprint_engine',
    # Ecosystem Bubble - Atmospheric Presence (Proprietary)
    'get_presence_sensor',
    'get_behavior_clustering_engine',
    'get_ecosystem_bubble_manager',
    'get_d2d_connection_graph',
    # Integration modules
    'get_clickhouse_graph_store',
    'get_n8n_webhook_client',
    'get_reinforcement_feedback_engine',
    # AI Autopilot - Event-Driven Efficiency (Proprietary)
    'get_efficiency_engine',
    'get_dhcp_sentinel',
    'get_mac_watcher',
    'get_probe_service',
    'get_ipfix_collector',
]

__version__ = '5.6.0'
