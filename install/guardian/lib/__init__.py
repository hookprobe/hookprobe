"""
HookProbe Guardian Library

Provides L2-L7 threat detection, mobile network protection, SDN control,
RADIUS integration, network segmentation, WebSocket VPN, and QSecBit
integration for the Guardian security appliance.

Modules:
- layer_threat_detector: OSI layer-based threat detection engine
- mobile_network_protection: Hotel/public WiFi security
- guardian_agent: QSecBit integration and unified reporting
- htp_client: HookProbe Transport Protocol client for MSSP communication
- openflow_controller: OpenFlow 1.3 SDN controller with OVS integration
- radius_integration: RADIUS/FreeRADIUS MAC authentication and VLAN assignment
- network_segmentation: nftables-based network segmentation and firewall
- config: Unified configuration management with sensible defaults
- websocket_vpn: WebSocket VPN with Noise Protocol encryption via MSSP

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

from .radius_integration import (
    RADIUSClient,
    RADIUSServer,
    RADIUSClientConfig,
    RADIUSPacket,
    MACAuthService,
    MACAuthEntry,
    RADIUSCode,
    RADIUSAttribute,
    TunnelType,
    TunnelMedium,
    NASPortType,
    ServiceType
)

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
    RADIUSConfig,
    OpenFlowConfig,
    HTPConfig as HTPConfigSettings,
    WebSocketVPNConfig,
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

from .websocket_vpn import (
    WebSocketVPNClient,
    WebSocketVPNService,
    NoiseState,
    VPNMessage,
    MessageType,
    ErrorCode,
    FileInfo
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

    # RADIUS Integration
    'RADIUSClient',
    'RADIUSServer',
    'RADIUSClientConfig',
    'RADIUSPacket',
    'MACAuthService',
    'MACAuthEntry',
    'RADIUSCode',
    'RADIUSAttribute',
    'TunnelType',
    'TunnelMedium',
    'NASPortType',
    'ServiceType',

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
    'RADIUSConfig',
    'OpenFlowConfig',
    'HTPConfigSettings',
    'WebSocketVPNConfig',
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

    # WebSocket VPN
    'WebSocketVPNClient',
    'WebSocketVPNService',
    'NoiseState',
    'VPNMessage',
    'MessageType',
    'ErrorCode',
    'FileInfo'
]

__version__ = '5.0.0'
