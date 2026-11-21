"""
HookProbe Shared Wireless Module

Provides WiFi/wireless utilities used across product tiers:
- Channel scanning and congestion analysis
- RF environment assessment
- Optimal channel selection
- DFS intelligence with ML-powered channel scoring
- Radar event tracking and NOP management

Author: HookProbe Team
Version: 5.1.0
License: AGPL-3.0 - see LICENSE file
"""

from .channel_scanner import (
    WiFiChannelScanner,
    ScanResult,
    ChannelInfo,
    DetectedNetwork,
    Band
)

# DFS Intelligence module exports
from .dfs_intelligence import (
    DFSDatabase,
    ChannelScorer,
    DFSMLTrainer,
    RadarMonitor,
    RadarEvent,
    ChannelScore,
    ChannelFeatures,
    CHANNEL_INFO,
    DEFAULT_WEIGHTS,
    HAS_SKLEARN,
    HAS_NUMPY,
    NOP_DURATION_SEC,
    CSA_BEACON_COUNT
)

__all__ = [
    # Channel scanner
    "WiFiChannelScanner",
    "ScanResult",
    "ChannelInfo",
    "DetectedNetwork",
    "Band",
    # DFS intelligence
    "DFSDatabase",
    "ChannelScorer",
    "DFSMLTrainer",
    "RadarMonitor",
    "RadarEvent",
    "ChannelScore",
    "ChannelFeatures",
    "CHANNEL_INFO",
    "DEFAULT_WEIGHTS",
    "HAS_SKLEARN",
    "HAS_NUMPY",
    "NOP_DURATION_SEC",
    "CSA_BEACON_COUNT"
]

__version__ = "5.1.0"
