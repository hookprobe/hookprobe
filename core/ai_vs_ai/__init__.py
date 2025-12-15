"""
HookProbe AI vs AI Module

Unified framework for adversarial AI-based threat detection and response.
Provides IoC generation, defense orchestration, and compute routing
between Fortress (lite) and Nexus (advanced) deployments.

Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                    AI VS AI FRAMEWORK                        │
    ├─────────────────────────────────────────────────────────────┤
    │                                                              │
    │  ThreatPredictor ──► IoCGenerator ──► DefenseOrchestrator   │
    │       (LSTM)           (Create)         (n8n + AI)          │
    │                           │                  │               │
    │                           ▼                  ▼               │
    │                    ComputeEvaluator ───► Route Task         │
    │                    (Fortress/Nexus)                          │
    │                                                              │
    └─────────────────────────────────────────────────────────────┘

Products:
    - Fortress: Lite version (4GB RAM, basic predictions)
    - Nexus: Advanced version (16GB+ RAM, deep analysis)

Author: HookProbe Team
Version: 1.0.0
License: AGPL-3.0
"""

from .models import (
    IoC,
    IoCType,
    ThreatPrediction,
    DefenseStrategy,
    DefenseAction,
    ComputeTask,
    ComputeTier,
    AIConsultationRequest,
    AIConsultationResponse,
)

from .ioc_generator import IoCGenerator
from .threat_predictor import ThreatPredictor
from .defense_orchestrator import DefenseOrchestrator
from .compute_evaluator import ComputeEvaluator

__all__ = [
    # Models
    'IoC',
    'IoCType',
    'ThreatPrediction',
    'DefenseStrategy',
    'DefenseAction',
    'ComputeTask',
    'ComputeTier',
    'AIConsultationRequest',
    'AIConsultationResponse',
    # Core classes
    'IoCGenerator',
    'ThreatPredictor',
    'DefenseOrchestrator',
    'ComputeEvaluator',
]

__version__ = '1.0.0'
