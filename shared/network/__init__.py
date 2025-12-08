"""
HookProbe Shared Network Module

Provides network infrastructure components used across multiple product tiers:
- Network segmentation (VLAN, nftables)
- SDN/OpenFlow control

Author: HookProbe Team
Version: 5.0.0
License: AGPL-3.0 - see LICENSE file
"""

from .segmentation import (
    NetworkSegmentation,
    NFTablesManager,
    VLANConfig,
    FirewallRule,
    SegmentationPolicy,
    VLANCategory,
    SecurityZone,
    TrafficAction,
    SERVICE_PORTS,
    IOT_VENDOR_VLANS,
    get_vlan_for_mac
)
from .sdn.openflow_controller import (
    OpenFlowController,
    FlowEntry,
    FlowMatch,
    FlowAction,
    SwitchFeatures,
    OVSBridge,
    VLANRange,
    OFP_CONSTANTS
)

__all__ = [
    # Segmentation
    "NetworkSegmentation",
    "NFTablesManager",
    "VLANConfig",
    "FirewallRule",
    "SegmentationPolicy",
    "VLANCategory",
    "SecurityZone",
    "TrafficAction",
    "SERVICE_PORTS",
    "IOT_VENDOR_VLANS",
    "get_vlan_for_mac",
    # SDN
    "OpenFlowController",
    "FlowEntry",
    "FlowMatch",
    "FlowAction",
    "SwitchFeatures",
    "OVSBridge",
    "VLANRange",
    "OFP_CONSTANTS"
]

__version__ = "5.0.0"
