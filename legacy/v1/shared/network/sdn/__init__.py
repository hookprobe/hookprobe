"""
HookProbe SDN (Software-Defined Networking) Module

Provides OpenFlow 1.3 controller with OVS integration for:
- Dynamic traffic management
- VLAN segmentation
- Threat-based flow control
- QoS enforcement

Author: HookProbe Team
Version: 5.0.0
License: AGPL-3.0 - see LICENSE file
"""

from .openflow_controller import (
    OpenFlowController,
    FlowEntry,
    FlowMatch,
    FlowAction,
    SwitchFeatures,
    OVSBridge,
    VLANRange,
    OFP_CONSTANTS,
    # Protocol enums for extensions
    OFPType,
    OFPActionType,
    OFPFlowModCommand,
    OFPPort,
    OFP_VERSION,
    OFP_HEADER_SIZE
)

__all__ = [
    "OpenFlowController",
    "FlowEntry",
    "FlowMatch",
    "FlowAction",
    "SwitchFeatures",
    "OVSBridge",
    "VLANRange",
    "OFP_CONSTANTS",
    # Protocol enums
    "OFPType",
    "OFPActionType",
    "OFPFlowModCommand",
    "OFPPort",
    "OFP_VERSION",
    "OFP_HEADER_SIZE"
]

__version__ = "5.0.0"
