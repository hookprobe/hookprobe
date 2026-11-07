"""
HookProbe Adversarial Security Framework

AI vs AI security testing where HookProbe is both the defender AND the attacker.
Proactively discovers vulnerabilities in NSE before external threats do.

Components:
- AdversarialTestEngine: Orchestrates attack simulations
- AttackVector: Base class for attack strategies
- VulnerabilityAnalyzer: Evaluates attack success/failure
- MitigationSuggester: AI-generated improvement recommendations
- SecurityAlertSystem: Designer notifications

Usage:
    from core.neuro.adversarial import AdversarialTestEngine

    engine = AdversarialTestEngine(target_stack=neuro_stack)
    report = engine.run_full_assessment()
    print(report.summary())
"""

from .engine import AdversarialTestEngine, AdversarialConfig
from .attack_vectors import (
    AttackVector,
    AttackResult,
    TERReplayAttack,
    TimingAttack,
    EntropyPoisoningAttack,
    WeightPredictionAttack,
    RDVCollisionAttack,
    PoSFForgeryAttack,
    CollectiveEntropyBypassAttack,
    MemoryExtractionAttack,
    SideChannelAttack,
)
from .analyzer import VulnerabilityAnalyzer, Vulnerability, VulnerabilitySeverity
from .mitigator import MitigationSuggester, Mitigation, MitigationPriority
from .alerts import SecurityAlertSystem, SecurityAlert, AlertLevel

__all__ = [
    'AdversarialTestEngine',
    'AdversarialConfig',
    'AttackVector',
    'AttackResult',
    'TERReplayAttack',
    'TimingAttack',
    'EntropyPoisoningAttack',
    'WeightPredictionAttack',
    'RDVCollisionAttack',
    'PoSFForgeryAttack',
    'CollectiveEntropyBypassAttack',
    'MemoryExtractionAttack',
    'SideChannelAttack',
    'VulnerabilityAnalyzer',
    'Vulnerability',
    'VulnerabilitySeverity',
    'MitigationSuggester',
    'Mitigation',
    'MitigationPriority',
    'SecurityAlertSystem',
    'SecurityAlert',
    'AlertLevel',
]
