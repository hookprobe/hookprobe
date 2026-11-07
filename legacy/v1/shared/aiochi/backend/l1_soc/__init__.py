"""
AIOCHI L1 SOC - Physical Layer Security Operations Center

This module transforms L1 (Physical Layer) cellular telemetry into security events.
Based on Trio+ validated architecture:
- Gemini 3 Flash: Technical validation
- Nemotron: Security audit
- Devstral: Algorithm verification

Core Components:
- L1TrustScore: Calculate trust score from cellular metrics
- TowerReputation: OpenCellID integration + whitelist management
- CellularMonitor: MBIM/QMI modem telemetry collection
- AnomalyDetector: IMSI catcher, jamming, rogue tower detection
- SurvivalMode: Emergency response when L1 compromised
"""

from .trust_score import L1TrustScore, TrustState
from .tower_reputation import TowerReputation, TowerSource
from .cellular_monitor import CellularMonitor, CellularMetrics
from .anomaly_detector import L1AnomalyDetector, AnomalyType
from .survival_mode import SurvivalMode, SurvivalAction
from .autonomous_agent import L1AutonomousAgent, DecisionConfidence, UserPrompt

__all__ = [
    # Trust Score
    'L1TrustScore',
    'TrustState',
    # Tower Reputation
    'TowerReputation',
    'TowerSource',
    # Cellular Monitor
    'CellularMonitor',
    'CellularMetrics',
    # Anomaly Detection
    'L1AnomalyDetector',
    'AnomalyType',
    # Survival Mode
    'SurvivalMode',
    'SurvivalAction',
    # Autonomous AI Agent
    'L1AutonomousAgent',
    'DecisionConfidence',
    'UserPrompt',
]

__version__ = '1.0.0'
