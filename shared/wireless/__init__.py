"""
HookProbe Shared Wireless Module

Provides WiFi/wireless utilities used across product tiers:
- Channel scanning and congestion analysis
- RF environment assessment
- Optimal channel selection

Author: HookProbe Team
Version: 5.0.0
License: AGPL-3.0 - see LICENSE file
"""

from .channel_scanner import (
    WiFiChannelScanner,
    ScanResult,
    ChannelInfo,
    DetectedNetwork,
    Band
)

__all__ = [
    "WiFiChannelScanner",
    "ScanResult",
    "ChannelInfo",
    "DetectedNetwork",
    "Band"
]

__version__ = "5.0.0"
