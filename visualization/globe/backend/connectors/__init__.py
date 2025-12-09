#!/usr/bin/env python3
"""
Product Connectors for HookProbe Globe Visualization

This package provides connectors that allow each HookProbe product tier
(Sentinel, Guardian, Fortress, Nexus, MSSP) to report their state to
the globe digital twin visualization.

Architecture:
                     ┌─────────────────────────────────────────┐
                     │           Globe HTP Bridge              │
                     │  (visualization/globe/backend/)         │
                     └────────────────┬────────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        │                             │                             │
        ▼                             ▼                             ▼
┌───────────────┐           ┌───────────────┐           ┌───────────────┐
│   Guardian    │           │   Fortress    │           │     MSSP      │
│   Connector   │           │   Connector   │           │   Connector   │
│  (Flask app)  │           │ (edge router) │           │ (Django app)  │
└───────────────┘           └───────────────┘           └───────────────┘

Each connector:
1. Collects product-specific metrics (Qsecbit, threats, status)
2. Translates to globe event format
3. Sends to the HTP bridge via internal API or direct connection
"""

from .base import ProductConnector, ConnectorConfig, NodeState
from .manager import ConnectorManager

__all__ = [
    'ProductConnector',
    'ConnectorConfig',
    'NodeState',
    'ConnectorManager',
]
