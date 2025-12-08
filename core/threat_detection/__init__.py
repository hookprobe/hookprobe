"""
HookProbe Core Threat Detection Module

Provides OSI layer-based threat detection engine (L2-L7) that can be used
across all HookProbe product tiers.

Components:
- LayerThreatDetector: Main detection engine for L2-L7 threats
- ThreatEvent: Threat event data structure
- ThreatSeverity: Severity levels aligned with CVSS
- OSILayer: OSI layer enumeration
- LayerThreatStats: Per-layer threat statistics

Usage:
    from core.threat_detection import LayerThreatDetector, ThreatEvent

    detector = LayerThreatDetector(data_dir="/opt/hookprobe/data")
    report = detector.detect_all_threats()
    score = detector.get_qsecbit_threat_score()

Author: HookProbe Team
Version: 5.0.0
License: AGPL-3.0 - see LICENSE file
"""

from .layer_threat_detector import (
    LayerThreatDetector,
    ThreatEvent,
    ThreatSeverity,
    OSILayer,
    LayerThreatStats
)

__all__ = [
    "LayerThreatDetector",
    "ThreatEvent",
    "ThreatSeverity",
    "OSILayer",
    "LayerThreatStats"
]

__version__ = "5.0.0"
__author__ = "HookProbe Team"
__license__ = "AGPL-3.0"
