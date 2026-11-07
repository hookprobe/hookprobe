"""
HookProbe Guardian Library

Provides L2-L7 threat detection, mobile network protection, SDN control,
network segmentation, HTP file transfer, and QSecBit integration for the
Guardian security appliance.

All external imports are wrapped in try/except so Guardian starts even if
optional modules (core.threat_detection, shared.mobile_security, etc.) are
not installed on the target device.

Author: HookProbe Team
Version: 5.1.0
License: AGPL-3.0 - see LICENSE in this directory
"""

import logging as _log

_logger = _log.getLogger(__name__)

# ---- Core modules - shared across all products ----
try:
    from core.threat_detection import (
        LayerThreatDetector,
        ThreatEvent,
        ThreatSeverity,
        OSILayer,
        LayerThreatStats
    )
except ImportError:
    _logger.debug("core.threat_detection not available")
    LayerThreatDetector = ThreatEvent = ThreatSeverity = OSILayer = LayerThreatStats = None

# ---- Shared mobile security module ----
try:
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
except ImportError:
    _logger.debug("shared.mobile_security not available")
    MobileNetworkProtection = MobileProtectionConfig = NetworkProfile = None
    NetworkThreat = SecurityCheck = ThreatType = ProtectionStatus = None
    NetworkTrustLevel = CaptivePortalStatus = None

# ---- Guardian core modules ----
try:
    from .guardian_agent import (
        GuardianAgent,
        GuardianMetrics
    )
except ImportError:
    _logger.debug("guardian_agent not available")
    GuardianAgent = GuardianMetrics = None

try:
    from .htp_client import (
        GuardianHTPClient,
        GuardianHTPService,
        HTPConfig,
        HTPPacket,
        HTPPacketType
    )
except ImportError:
    _logger.debug("htp_client not available")
    GuardianHTPClient = GuardianHTPService = HTPConfig = HTPPacket = HTPPacketType = None

# ---- HTP File Transfer - imported from core ----
try:
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
except ImportError:
    _logger.debug("core.htp.transport.htp_file not available")
    HTPFileTransfer = HTPFileServer = FileOperation = FileFlags = FileErrorCode = None
    FileTransferHeader = FileMetadata = DirectoryEntry = TransferState = None
    HTPFileError = IntegrityError = TransferError = None

# ---- Shared SDN/OpenFlow controller ----
try:
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
except ImportError:
    _logger.debug("shared.network.sdn not available")
    OpenFlowController = FlowEntry = FlowMatch = FlowAction = None
    SwitchFeatures = OVSBridge = VLANRange = OFP_CONSTANTS = None

# ---- Guardian-specific OpenFlow extensions ----
try:
    from .openflow_controller import (
        OVSManager,
        GuardianVLAN,
        OFPType,
        OFPActionType,
        OFPFlowModCommand,
        OFPPort
    )
except ImportError:
    _logger.debug("openflow_controller not available")
    OVSManager = GuardianVLAN = OFPType = OFPActionType = OFPFlowModCommand = OFPPort = None

# ---- Shared network segmentation ----
try:
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
except ImportError:
    _logger.debug("shared.network not available")
    NetworkSegmentation = NFTablesManager = VLANConfig = FirewallRule = None
    SegmentationPolicy = VLANCategory = SecurityZone = TrafficAction = None
    SERVICE_PORTS = IOT_VENDOR_VLANS = get_vlan_for_mac = None
    NetworkSegmentationService = None

# ---- Shared wireless channel scanner ----
try:
    from shared.wireless import (
        WiFiChannelScanner,
        ScanResult,
        ChannelInfo,
        DetectedNetwork,
        Band
    )
except ImportError:
    _logger.debug("shared.wireless not available")
    WiFiChannelScanner = ScanResult = ChannelInfo = DetectedNetwork = Band = None

# ---- Configuration (always required) ----
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

    # Network Segmentation (from shared)
    'NetworkSegmentation',
    'NetworkSegmentationService',
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

__version__ = '5.1.0'
