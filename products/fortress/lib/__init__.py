"""
HookProbe Fortress Library

Core modules for the Fortress small business security gateway.
Extends Guardian capabilities with:
- PostgreSQL database integration
- VLAN management
- Device tracking with network segmentation
- SDN Autopilot for automatic device classification
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
]

__version__ = '5.5.0'
