"""
AIOCHI - AI Eyes (AI OCHII in Romanian)
Cognitive Network Layer for HookProbe

This module transforms raw network data into human-understandable narratives.
It is the "nervous system" that feels the network and speaks human.

The Three Pillars:
    1. PRESENCE - Who's home (device bubbles)
    2. PRIVACY - What's happening (narrative feed)
    3. PERFORMANCE - How fast (health score)

Usage:
    from shared.aiochi import IdentityEngine, NarrativeEngine, PresenceTracker

    # Initialize engines
    identity = IdentityEngine(clickhouse_host="localhost")
    narrative = NarrativeEngine(persona="parent")
    presence = PresenceTracker()

    # Enrich a device
    device = identity.enrich(mac="AA:BB:CC:DD:EE:FF")

    # Generate a narrative
    story = narrative.translate(event, device)

    # Check presence
    bubbles = presence.get_bubbles()

License: Proprietary - Commercial License Required for SaaS/OEM use
"""

__version__ = "1.0.0"
__author__ = "HookProbe Team"
__license__ = "Proprietary"

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .backend.identity_engine import IdentityEngine
    from .backend.narrative_engine import NarrativeEngine
    from .backend.presence_tracker import PresenceTracker
    from .backend.performance_scorer import PerformanceScorer
    from .backend.ambient_state import AmbientState, AmbientStateManager
    from .backend.quick_actions import QuickActionExecutor

__all__ = [
    "IdentityEngine",
    "NarrativeEngine",
    "PresenceTracker",
    "PerformanceScorer",
    "AmbientState",
    "AmbientStateManager",
    "QuickActionExecutor",
]


def __getattr__(name: str):
    """Lazy import for heavy modules."""
    if name == "IdentityEngine":
        from .backend.identity_engine import IdentityEngine
        return IdentityEngine
    elif name == "NarrativeEngine":
        from .backend.narrative_engine import NarrativeEngine
        return NarrativeEngine
    elif name == "PresenceTracker":
        from .backend.presence_tracker import PresenceTracker
        return PresenceTracker
    elif name == "PerformanceScorer":
        from .backend.performance_scorer import PerformanceScorer
        return PerformanceScorer
    elif name == "AmbientState":
        from .backend.ambient_state import AmbientState
        return AmbientState
    elif name == "AmbientStateManager":
        from .backend.ambient_state import AmbientStateManager
        return AmbientStateManager
    elif name == "QuickActionExecutor":
        from .backend.quick_actions import QuickActionExecutor
        return QuickActionExecutor
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
