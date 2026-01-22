"""
HookProbe Guardian Library

Provides L2-L7 threat detection, mobile network protection, SDN control,
network segmentation, HTP file transfer, and QSecBit integration for the
Guardian security appliance.

Modules:
- layer_threat_detector: OSI layer-based threat detection engine (from core)
- mobile_network_protection: Hotel/public WiFi security (from shared)
- guardian_agent: QSecBit integration and unified reporting
- htp_client: HookProbe Transport Protocol client for mesh communication
- htp_file: HTP-based secure file transfer (replaces WebSocket VPN)
- openflow_controller: OpenFlow 1.3 SDN controller with OVS integration (from shared)
- network_segmentation: nftables-based network segmentation and firewall (from shared)
- wifi_channel_scanner: WiFi channel analysis (from shared)
- mesh_integration: HTP mesh network for device tracking (replaces RADIUS)
- config: Unified configuration management with sensible defaults

Author: HookProbe Team
Version: 5.0.0 Cortex
License: AGPL-3.0 - see LICENSE in this directory
"""

# Core modules - shared across all products
from core.threat_detection import (
    LayerThreatDetector,
    ThreatEvent,
    ThreatSeverity,
    OSILayer,
    LayerThreatStats
)

# Shared mobile security module
from shared.mobile_security import (
    MobileNetworkProtection,
    MobileProtectionConfig,
    NetworkProfile,
    NetworkThreat,
    SecurityCheck,
    ThreatType,
    ProtectionStatus,
    NetworkTrustLevel,
    CaptivePortalStatus
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

# Shared SDN/OpenFlow controller
from shared.network.sdn import (
    OpenFlowController,
    FlowEntry,
    FlowMatch,
    FlowAction,
    SwitchFeatures,
    OVSBridge,
    VLANRange,
    OFP_CONSTANTS
)

# Guardian-specific OpenFlow extensions
from .openflow_controller import (
    OVSManager,
    GuardianVLAN,
    OFPType,
    OFPActionType,
    OFPFlowModCommand,
    OFPPort
)

# RADIUS integration removed - Guardian now uses HTP mesh for device tracking
# See mesh_integration.py for the new approach

# Shared network segmentation
from shared.network import (
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

# Alias for backwards compatibility
NetworkSegmentationService = NetworkSegmentation

# Shared wireless channel scanner
from shared.wireless import (
    WiFiChannelScanner,
    ScanResult,
    ChannelInfo,
    DetectedNetwork,
    Band
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
    # Layer Threat Detector (from core)
    'LayerThreatDetector',
    'ThreatEvent',
    'ThreatSeverity',
    'OSILayer',
    'LayerThreatStats',

    # Mobile Network Protection (from shared)
    'MobileNetworkProtection',
    'MobileProtectionConfig',
    'NetworkProfile',
    'NetworkThreat',
    'SecurityCheck',
    'ThreatType',
    'ProtectionStatus',
    'NetworkTrustLevel',
    'CaptivePortalStatus',

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

    # OpenFlow Controller (from shared + Guardian extensions)
    'OpenFlowController',
    'OVSManager',
    'OVSBridge',
    'FlowEntry',
    'FlowMatch',
    'FlowAction',
    'SwitchFeatures',
    'GuardianVLAN',
    'VLANRange',
    'OFP_CONSTANTS',
    'OFPType',
    'OFPActionType',
    'OFPFlowModCommand',
    'OFPPort',

    # RADIUS Integration removed - using HTP mesh instead

    # Network Segmentation (from shared)
    'NetworkSegmentation',
    'NetworkSegmentationService',  # Backwards compatibility alias
    'NFTablesManager',
    'VLANConfig',
    'FirewallRule',
    'SegmentationPolicy',
    'VLANCategory',
    'SecurityZone',
    'TrafficAction',
    'SERVICE_PORTS',
    'IOT_VENDOR_VLANS',
    'get_vlan_for_mac',

    # WiFi Channel Scanner (from shared)
    'WiFiChannelScanner',
    'ScanResult',
    'ChannelInfo',
    'DetectedNetwork',
    'Band',

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
