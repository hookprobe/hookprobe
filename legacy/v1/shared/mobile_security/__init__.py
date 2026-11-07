"""
HookProbe Mobile Security Module

Provides protection for devices on untrusted networks:
- Captive portal detection
- Evil twin AP detection
- SSL stripping protection
- DNS security verification
- Network reconnaissance detection

Author: HookProbe Team
Version: 5.0.0
License: AGPL-3.0 - see LICENSE file
"""

from .mobile_network_protection import (
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

__all__ = [
    "MobileNetworkProtection",
    "MobileProtectionConfig",
    "NetworkProfile",
    "NetworkThreat",
    "SecurityCheck",
    "ThreatType",
    "ProtectionStatus",
    "NetworkTrustLevel",
    "CaptivePortalStatus"
]

__version__ = "5.0.0"
