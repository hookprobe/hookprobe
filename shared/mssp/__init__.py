"""
HookProbe Shared MSSP Client

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2026 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

Universal MSSP client for all product tiers (Sentinel, Guardian, Fortress, Nexus).
Handles threat finding submission, recommendation retrieval, and execution feedback.

Architecture:
    Edge Node → MSSP Dashboard (mssp.hookprobe.com) → Nexus AI → Edge Node
    - All tiers share this client for MSSP communication
    - ThreatFindings flow UP to MSSP
    - RecommendedActions flow DOWN from MSSP (via webhook or poll)
    - ExecutionFeedback flows UP for continuous learning
"""

from .types import (
    ThreatFinding,
    RecommendedAction,
    ExecutionFeedback,
    DeviceMetrics,
    IntelligenceReport,
    FindingStatus,
    ActionType,
    ActionPriority,
)
from .client import HookProbeMSSPClient, get_mssp_client
from .auth import verify_recommendation_signature
from .recommendation_handler import RecommendationHandler
from .webhook_receiver import MSSPWebhookReceiver
from .mesh_propagation import MeshPropagator

__version__ = '1.2.0'

__all__ = [
    # Types
    'ThreatFinding',
    'RecommendedAction',
    'ExecutionFeedback',
    'DeviceMetrics',
    'IntelligenceReport',
    'FindingStatus',
    'ActionType',
    'ActionPriority',
    # Client
    'HookProbeMSSPClient',
    'get_mssp_client',
    # Auth
    'verify_recommendation_signature',
    # Recommendation handling
    'RecommendationHandler',
    'MSSPWebhookReceiver',
    # Mesh propagation
    'MeshPropagator',
]
