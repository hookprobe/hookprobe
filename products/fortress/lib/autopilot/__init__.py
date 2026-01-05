#!/usr/bin/env python3
"""
AI Autopilot - Event-Driven Efficiency Architecture for Fortress.

This module implements "Sleep-and-Wake" architecture where low-power sentinels
trigger deep analysis only when something changes, instead of continuous
monitoring that wastes CPU/RAM.

Architecture:
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                        AI AUTOPILOT (Event-Driven)                       │
    ├─────────────────────────────────────────────────────────────────────────┤
    │                                                                          │
    │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                 │
    │  │    DHCP     │    │     OVS     │    │    IPFIX    │  ALWAYS-ON     │
    │  │  SENTINEL   │    │ MAC WATCHER │    │  SAMPLER    │  SENTINELS     │
    │  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘  (<1% CPU)     │
    │         │                  │                  │                        │
    │         └────────────┬─────┴────────┬────────┘                        │
    │                      │              │                                  │
    │                      ▼              ▼                                  │
    │              ┌─────────────┐ ┌─────────────┐                          │
    │              │ EFFICIENCY  │ │    n8n      │                          │
    │              │   ENGINE    │─│  WORKFLOWS  │                          │
    │              └──────┬──────┘ └─────────────┘                          │
    │                     │                                                  │
    │                     ▼                                                  │
    │              ┌─────────────┐                                          │
    │              │  ON-DEMAND  │  BURST ANALYSIS                          │
    │              │    PROBE    │  (60s capture)                           │
    │              └──────┬──────┘                                          │
    │                     │                                                  │
    │                     ▼                                                  │
    │              ┌─────────────┐                                          │
    │              │   BUBBLE    │  SDN RULE                                │
    │              │ ASSIGNMENT  │  UPDATE                                  │
    │              └─────────────┘                                          │
    │                                                                        │
    └─────────────────────────────────────────────────────────────────────────┘

Resource Comparison:
    - Continuous Monitoring: 15-40% CPU, 2GB+ RAM
    - AI Autopilot: 1% idle / 10% burst, <200MB RAM

Copyright (c) 2024-2026 HookProbe Security
License: Proprietary - Commercial license required for SaaS/OEM use
"""

from .dhcp_sentinel import (
    DHCPSentinel,
    DHCPEvent,
    DHCPEventType,
    get_dhcp_sentinel,
)

from .mac_watcher import (
    OVSMACWatcher,
    MACEvent,
    MACEventType,
    get_mac_watcher,
)

from .probe_service import (
    OnDemandProbe,
    ProbeResult,
    ProbeConfig,
    get_probe_service,
)

from .ipfix_collector import (
    IPFIXCollector,
    D2DFlow,
    get_ipfix_collector,
)

from .efficiency_engine import (
    EfficiencyEngine,
    AutopilotState,
    AutopilotConfig,
    get_efficiency_engine,
)

__all__ = [
    # DHCP Sentinel
    'DHCPSentinel',
    'DHCPEvent',
    'DHCPEventType',
    'get_dhcp_sentinel',
    # MAC Watcher
    'OVSMACWatcher',
    'MACEvent',
    'MACEventType',
    'get_mac_watcher',
    # Probe Service
    'OnDemandProbe',
    'ProbeResult',
    'ProbeConfig',
    'get_probe_service',
    # IPFIX Collector
    'IPFIXCollector',
    'D2DFlow',
    'get_ipfix_collector',
    # Efficiency Engine
    'EfficiencyEngine',
    'AutopilotState',
    'AutopilotConfig',
    'get_efficiency_engine',
]

__version__ = '1.0.0'
