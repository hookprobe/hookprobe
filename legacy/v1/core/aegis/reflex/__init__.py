"""
AEGIS Reflex — Surgical Interference System

Graduated response engine that replaces binary block/allow with
'Degraded Reality' — 4 levels of interference that inflame
proportionally to threat severity and self-heal via Bayesian recovery.

Level 0 (OBSERVE):    Q=0.00–0.30 — Pass-through, baseline monitoring
Level 1 (JITTER):     Q=0.30–0.60 — Stochastic delay injection (10–500ms)
Level 2 (SHADOW):     Q=0.60–0.85 — Redirect to Mirage honeypot
Level 3 (DISCONNECT): Q=0.85–1.00 — Surgical SIGKILL + TCP_RST

Author: Andrei Toma
License: Proprietary - see LICENSE in this directory
Version: 2.0.0
"""

from typing import Optional

from .bridge import ReflexBridge
from .engine import ReflexEngine
from .recovery import BayesianRecoveryEngine
from .types import (
    LEVEL_THRESHOLDS,
    ReflexDecision,
    ReflexLevel,
    ReflexTarget,
    ScoreVelocity,
)

# ------------------------------------------------------------------
# Singleton registry for cross-module access
# ------------------------------------------------------------------
# The QSecBit response orchestrator needs to call the ReflexEngine
# but lives in a different module tree. This registry avoids tight
# coupling while ensuring a single engine instance is used.

_engine_instance: Optional[ReflexEngine] = None


def register_engine(engine: ReflexEngine) -> None:
    """Register the global ReflexEngine instance.

    Called by BridgeManager when it creates the engine.
    """
    global _engine_instance
    _engine_instance = engine


def get_engine() -> Optional[ReflexEngine]:
    """Get the registered ReflexEngine, or None if not yet created."""
    return _engine_instance


__all__ = [
    "ReflexEngine",
    "BayesianRecoveryEngine",
    "ReflexBridge",
    "ReflexLevel",
    "ReflexTarget",
    "ReflexDecision",
    "ScoreVelocity",
    "LEVEL_THRESHOLDS",
    "register_engine",
    "get_engine",
]
