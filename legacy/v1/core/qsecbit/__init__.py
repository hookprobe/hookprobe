"""
Qsecbit Package - Quantum Security Bit: Cyber Resilience Metric

A unified cyber resilience metric for AI-driven threat detection.
Provides single-source-of-truth protection across OSI layers L2-L7.

Author: Andrei Toma
License: Proprietary - see LICENSE in this directory
Version: 5.0.0
"""

# Core v5.0 classes (backward compatibility)
from .qsecbit import (
    Qsecbit,
    QsecbitConfig,
    QsecbitSample
)

from .nic_detector import (
    NICDetector,
    NICCapability,
    XDPMode,
    NIC_CAPABILITY_MATRIX
)

from .xdp_manager import (
    XDPManager,
    XDPStats,
    XDP_DDOS_PROGRAM
)

from .energy_monitor import (
    EnergyMonitor,
    SystemEnergySnapshot,
    PIDEnergyStats,
    NetworkEnergyStats,
    DeploymentRole
)

# Unified Threat Detection Engine
from .threat_types import (
    AttackType,
    ThreatSeverity,
    OSILayer,
    ResponseAction,
    ThreatEvent,
    LayerScore,
    QsecbitUnifiedScore,
    ATTACK_TO_LAYER,
    MITRE_ATTACK_MAPPING,
    DEFAULT_SEVERITY_MAP,
    DEFAULT_RESPONSE_MAP
)

from .unified_engine import (
    UnifiedThreatEngine,
    UnifiedEngineConfig,
    DeploymentType
)

# Layer-specific detectors
from .detectors import (
    BaseDetector,
    L2DataLinkDetector,
    L3NetworkDetector,
    L4TransportDetector,
    L5SessionDetector,
    L7ApplicationDetector
)

# ML classification
from .ml import (
    AttackClassifier,
    FeatureExtractor
)

# Response orchestration
from .response import (
    ResponseOrchestrator
)

# Mesh bridge for distributed threat sharing
from .mesh_bridge import (
    QsecbitMeshBridge,
    MeshBridgeConfig,
    create_mesh_bridge
)

__version__ = "5.0.0"
__author__ = "Andrei Toma"
__license__ = "Proprietary"

__all__ = [
    # Core qsecbit classes (backward compatible)
    "Qsecbit",
    "QsecbitConfig",
    "QsecbitSample",

    # NIC detection
    "NICDetector",
    "NICCapability",
    "XDPMode",
    "NIC_CAPABILITY_MATRIX",

    # XDP/eBPF management
    "XDPManager",
    "XDPStats",
    "XDP_DDOS_PROGRAM",

    # Energy monitoring
    "EnergyMonitor",
    "SystemEnergySnapshot",
    "PIDEnergyStats",
    "NetworkEnergyStats",
    "DeploymentRole",

    # Threat types
    "AttackType",
    "ThreatSeverity",
    "OSILayer",
    "ResponseAction",
    "ThreatEvent",
    "LayerScore",
    "QsecbitUnifiedScore",
    "ATTACK_TO_LAYER",
    "MITRE_ATTACK_MAPPING",
    "DEFAULT_SEVERITY_MAP",
    "DEFAULT_RESPONSE_MAP",

    # Unified Engine
    "UnifiedThreatEngine",
    "UnifiedEngineConfig",
    "DeploymentType",

    # Layer detectors
    "BaseDetector",
    "L2DataLinkDetector",
    "L3NetworkDetector",
    "L4TransportDetector",
    "L5SessionDetector",
    "L7ApplicationDetector",

    # ML classification
    "AttackClassifier",
    "FeatureExtractor",

    # Response orchestration
    "ResponseOrchestrator",

    # Mesh bridge
    "QsecbitMeshBridge",
    "MeshBridgeConfig",
    "create_mesh_bridge",
]
