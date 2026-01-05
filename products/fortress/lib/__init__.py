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
    from .connection_graph import D2DConnectionGraph
    return D2DConnectionGraph()


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
]

__version__ = '5.5.0'
