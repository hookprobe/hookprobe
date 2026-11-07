"""
HookProbe SLA AI - Intelligent Network Continuity

Proprietary SLA monitoring, fault prediction, and switching automation
for maximizing Business Continuity while minimizing costs.

Core Philosophy: Feel, Sense, Adapt, Learn, Optimize

Components:
    - MetricsCollector: Real-time network health metrics
    - Predictor: LSTM-based fault prediction
    - FailbackIntelligence: Cost-aware failback decisions
    - DNSIntelligence: Adaptive DNS failover
    - CostTracker: Metered connection usage tracking
    - SLAEngine: Central coordinator

License: Proprietary (HookProbe Commercial)
"""

__version__ = "1.0.0"
__author__ = "HookProbe"

from .config import SLAAIConfig, load_config
from .database import SLAAIDatabase
from .metrics_collector import MetricsCollector, WANMetrics
from .predictor import LSTMPredictor, Prediction, FeatureExtractor
from .failback import FailbackIntelligence, FailbackPolicy, FailbackDecision, FailbackState
from .cost_tracker import CostTracker, UsageStatus, UsageBudget
from .dns_intelligence import DNSIntelligence, DNSProvider, DNSHealth
from .engine import SLAEngine, SLAState, SLAStatus

__all__ = [
    # Config
    "SLAAIConfig",
    "load_config",
    # Database
    "SLAAIDatabase",
    # Metrics
    "MetricsCollector",
    "WANMetrics",
    # Predictor
    "LSTMPredictor",
    "Prediction",
    "FeatureExtractor",
    # Failback
    "FailbackIntelligence",
    "FailbackPolicy",
    "FailbackDecision",
    "FailbackState",
    # Cost
    "CostTracker",
    "UsageStatus",
    "UsageBudget",
    # DNS
    "DNSIntelligence",
    "DNSProvider",
    "DNSHealth",
    # Engine
    "SLAEngine",
    "SLAState",
    "SLAStatus",
]
