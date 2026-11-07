"""
AIOCHI - AI Eyes (AI OCHII in Romanian)
Cognitive Network Layer for HookProbe

This module transforms raw network data into human-understandable narratives.
It is the "nervous system" that feels the network and speaks human.

The Four Pillars:
    1. PRESENCE - Who's home (device bubbles)
    2. PRIVACY - What's happening (narrative feed)
    3. PERFORMANCE - How fast (health score)
    4. POLICY - What's allowed (network policies)

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

    # Bubble management (NEW - unified architecture)
    from shared.aiochi.bubble import (
        BubbleType, NetworkPolicy, Bubble,
        get_bubble_manager, get_policy_resolver
    )

    manager = get_bubble_manager()
    resolver = get_policy_resolver()

    # Create a bubble and set device-specific policies
    bubble = manager.create_bubble(name="Dad", bubble_type=BubbleType.FAMILY)
    manager.add_device(bubble.bubble_id, "AA:BB:CC:DD:EE:FF")
    manager.set_device_policy(bubble.bubble_id, "AA:BB:CC:DD:EE:FF", NetworkPolicy.FULL_ACCESS)

License: Proprietary - Commercial License Required for SaaS/OEM use
"""

__version__ = "1.1.0"
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
    # Bubble types
    from .bubble.types import BubbleType, BubbleState, NetworkPolicy, Bubble
    from .bubble.manager import EcosystemBubbleManager
    from .bubble.policy_resolver import PolicyResolver, PolicyResolution

__all__ = [
    # Backend modules
    "IdentityEngine",
    "NarrativeEngine",
    "PresenceTracker",
    "PerformanceScorer",
    "AmbientState",
    "AmbientStateManager",
    "QuickActionExecutor",
    # Bubble types and classes
    "BubbleType",
    "BubbleState",
    "NetworkPolicy",
    "Bubble",
    "EcosystemBubbleManager",
    "PolicyResolver",
    "PolicyResolution",
    # Bubble singletons
    "get_bubble_manager",
    "get_policy_resolver",
]


def __getattr__(name: str):
    """Lazy import for heavy modules."""
    # Backend modules
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
    # Bubble types
    elif name == "BubbleType":
        from .bubble.types import BubbleType
        return BubbleType
    elif name == "BubbleState":
        from .bubble.types import BubbleState
        return BubbleState
    elif name == "NetworkPolicy":
        from .bubble.types import NetworkPolicy
        return NetworkPolicy
    elif name == "Bubble":
        from .bubble.types import Bubble
        return Bubble
    # Bubble managers
    elif name == "EcosystemBubbleManager":
        from .bubble.manager import EcosystemBubbleManager
        return EcosystemBubbleManager
    elif name == "PolicyResolver":
        from .bubble.policy_resolver import PolicyResolver
        return PolicyResolver
    elif name == "PolicyResolution":
        from .bubble.policy_resolver import PolicyResolution
        return PolicyResolution
    # Bubble singletons
    elif name == "get_bubble_manager":
        from .bubble import get_bubble_manager
        return get_bubble_manager
    elif name == "get_policy_resolver":
        from .bubble import get_policy_resolver
        return get_policy_resolver
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
