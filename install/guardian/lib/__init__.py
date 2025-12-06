"""
HookProbe Guardian Library

Provides L2-L7 threat detection, mobile network protection,
and QSecBit integration for the Guardian security appliance.

Modules:
- layer_threat_detector: OSI layer-based threat detection engine
- mobile_network_protection: Hotel/public WiFi security
- guardian_agent: QSecBit integration and unified reporting

Author: HookProbe Team
Version: 1.0.0
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
    'GuardianMetrics'
]

__version__ = '1.0.0'
