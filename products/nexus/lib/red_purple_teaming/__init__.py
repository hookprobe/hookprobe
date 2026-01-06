"""
Nexus Red & Purple Teaming System

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2025 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

The "AI vs AI" simulation module that enables:
- Red Team: Nexus attacks Fortress digital twin
- Blue Team: Fortress defends with SDN Autopilot
- Purple Team: Validation webhook loop for continuous improvement

Architecture:
    Nexus (Red) "shadows" Fortress (Blue) by creating a digital twin
    and launching simulated attacks to verify QSECBIT/NEURO protocols.

Key Components:
- PurpleTeamOrchestrator: Main orchestrator for red/purple teaming
- DigitalTwinSimulator: Creates virtual OVS/SDN replicas
- NSEHeartbeat: Neural Synaptic Encryption for D2D verification
- MetaRegressor: Bubble accuracy optimization engine
- BubbleAttackVectors: SDN-specific attack simulations
"""

from .orchestrator import (
    PurpleTeamOrchestrator,
    PurpleTeamConfig,
    SimulationResult,
    ValidationResult,
    AttackPhase,
    DetectionPhase,
    ValidationPhase,
)

from .digital_twin import (
    DigitalTwinSimulator,
    TwinConfig,
    VirtualOVS,
    VirtualDevice,
    VirtualBubble,
)

from .nse_heartbeat import (
    NSEHeartbeat,
    HeartbeatToken,
    NSEValidator,
    ResonanceState,
)

from .meta_regressor import (
    MetaRegressor,
    BubbleAccuracyModel,
    EffectSizeAnalyzer,
    RegressionResult,
)

from .bubble_attacks import (
    BubbleAttackVector,
    TERReplayBubbleAttack,
    EntropyPoisoningBubbleAttack,
    TimingCorrelationAttack,
    WeightPredictionBubbleAttack,
    MACImpersonationAttack,
    MDNSSpoofingAttack,
    TemporalMimicryAttack,
    DHCPFingerprintSpoofAttack,
    D2DAffinityInjectionAttack,
)

__all__ = [
    # Orchestrator
    'PurpleTeamOrchestrator',
    'PurpleTeamConfig',
    'SimulationResult',
    'ValidationResult',
    'AttackPhase',
    'DetectionPhase',
    'ValidationPhase',

    # Digital Twin
    'DigitalTwinSimulator',
    'TwinConfig',
    'VirtualOVS',
    'VirtualDevice',
    'VirtualBubble',

    # NSE Heartbeat
    'NSEHeartbeat',
    'HeartbeatToken',
    'NSEValidator',
    'ResonanceState',

    # Meta Regression
    'MetaRegressor',
    'BubbleAccuracyModel',
    'EffectSizeAnalyzer',
    'RegressionResult',

    # Bubble Attacks
    'BubbleAttackVector',
    'TERReplayBubbleAttack',
    'EntropyPoisoningBubbleAttack',
    'TimingCorrelationAttack',
    'WeightPredictionBubbleAttack',
    'MACImpersonationAttack',
    'MDNSSpoofingAttack',
    'TemporalMimicryAttack',
    'DHCPFingerprintSpoofAttack',
    'D2DAffinityInjectionAttack',
]

__version__ = '1.0.0'
