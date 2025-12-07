"""
HookProbe Guardian Library

Provides L2-L7 threat detection, mobile network protection, SDN control,
network segmentation, HTP file transfer, and QSecBit integration for the
Guardian security appliance.

Modules:
- layer_threat_detector: OSI layer-based threat detection engine
- mobile_network_protection: Hotel/public WiFi security
- guardian_agent: QSecBit integration and unified reporting
- htp_client: HookProbe Transport Protocol client for MSSP communication
- htp_file: HTP-based secure file transfer (replaces WebSocket VPN)
- openflow_controller: OpenFlow 1.3 SDN controller with OVS integration
- network_segmentation: nftables-based network segmentation and firewall
- mesh_integration: HTP mesh network for device tracking (replaces RADIUS)
- config: Unified configuration management with sensible defaults

Author: HookProbe Team
Version: 5.0.0 Liberty
License: MIT
"""

from .layer_threat_detector import (
    LayerThreatDetector,
    ThreatEvent,
    ThreatSeverity,
    OSILayer,
    LayerThreatStats
)

from .mobile_network_protection import (
    MobileNetworkProtection,
    NetworkProfile,
    NetworkTrustLevel,
    CaptivePortalStatus,
    SecurityCheck
)

from .guardian_agent import (
    GuardianAgent,
    GuardianMetrics
)

from .htp_client import (
    GuardianHTPClient,
    GuardianHTPService,
    HTPConfig,
    HTPPacket,
    HTPPacketType
)

# HTP File Transfer - imported from core (single source of truth)
from core.htp.transport.htp_file import (
    HTPFileTransfer,
    HTPFileServer,
    FileOperation,
    FileFlags,
    FileErrorCode,
    FileTransferHeader,
    FileMetadata,
    DirectoryEntry,
    TransferState,
    HTPFileError,
    IntegrityError,
    TransferError
)

from .openflow_controller import (
    OpenFlowController,
    OVSManager,
    FlowEntry,
    FlowMatch,
    FlowAction,
    SwitchFeatures,
    GuardianVLAN,
    OFPType,
    OFPActionType,
    OFPFlowModCommand,
    OFPPort
)

# RADIUS integration removed - Guardian now uses HTP mesh for device tracking
# See mesh_integration.py for the new approach

from .network_segmentation import (
    NFTablesManager,
    NetworkSegmentationService,
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

from .config import (
    GuardianConfig,
    OpenFlowConfig,
    HTPConfig as HTPConfigSettings,
    HTPFileConfig,
    NetworkConfig,
    SecurityConfig,
    WebUIConfig,
    LoggingConfig,
    ConfigManager,
    ConfigValidationError,
    get_config,
    load_config,
    generate_default_config,
    DEFAULT_CONFIG_TEMPLATE,
    DEFAULT_CONFIG_PATH
)

__all__ = [
    # Layer Threat Detector
    'LayerThreatDetector',
    'ThreatEvent',
    'ThreatSeverity',
    'OSILayer',
    'LayerThreatStats',

    # Mobile Network Protection
    'MobileNetworkProtection',
    'NetworkProfile',
    'NetworkTrustLevel',
    'CaptivePortalStatus',
    'SecurityCheck',

    # Guardian Agent
    'GuardianAgent',
    'GuardianMetrics',

    # HTP Client
    'GuardianHTPClient',
    'GuardianHTPService',
    'HTPConfig',
    'HTPPacket',
    'HTPPacketType',

    # HTP File Transfer
    'HTPFileTransfer',
    'HTPFileServer',
    'FileOperation',
    'FileFlags',
    'FileErrorCode',
    'FileTransferHeader',
    'FileMetadata',
    'DirectoryEntry',
    'TransferState',
    'HTPFileError',
    'IntegrityError',
    'TransferError',

    # OpenFlow Controller
    'OpenFlowController',
    'OVSManager',
    'FlowEntry',
    'FlowMatch',
    'FlowAction',
    'SwitchFeatures',
    'GuardianVLAN',
    'OFPType',
    'OFPActionType',
    'OFPFlowModCommand',
    'OFPPort',

    # RADIUS Integration removed - using HTP mesh instead

    # Network Segmentation
    'NFTablesManager',
    'NetworkSegmentationService',
    'VLANConfig',
    'FirewallRule',
    'SegmentationPolicy',
    'VLANCategory',
    'SecurityZone',
    'TrafficAction',
    'SERVICE_PORTS',
    'IOT_VENDOR_VLANS',
    'get_vlan_for_mac',

    # Configuration
    'GuardianConfig',
    'OpenFlowConfig',
    'HTPConfigSettings',
    'HTPFileConfig',
    'NetworkConfig',
    'SecurityConfig',
    'WebUIConfig',
    'LoggingConfig',
    'ConfigManager',
    'ConfigValidationError',
    'get_config',
    'load_config',
    'generate_default_config',
    'DEFAULT_CONFIG_TEMPLATE',
    'DEFAULT_CONFIG_PATH',
]

__version__ = '5.0.0'
