"""
Qsecbit Package - Quantum Security Bit: Cyber Resilience Metric

A modular cyber resilience metric for AI-driven threat detection.

Author: Andrei Toma
License: MIT
Version: 5.0
"""

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
    PIDEnergyStats
)

__version__ = "5.0.0"
__author__ = "Andrei Toma"
__license__ = "MIT"

__all__ = [
    # Core qsecbit classes
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
]
