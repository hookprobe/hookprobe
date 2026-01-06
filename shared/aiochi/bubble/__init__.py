"""
AIOCHI Bubble Management Module
Unified ecosystem bubble management for HookProbe.

This module provides:
- EcosystemBubbleManager: Core bubble lifecycle management
- PolicyResolver: Maps bubbles to OpenFlow network policies
- PresenceSensor: mDNS/BLE presence detection
- BehaviorClustering: DBSCAN device clustering
- ConnectionGraph: D2D affinity analysis via Zeek

The bubble system groups devices by owner (Dad, Mom, Kids) using
behavioral signals and provides per-device policy overrides.

Architecture:
    Bubble Type (FAMILY, GUEST, etc.)
         |
         v
    Default Network Policy (smart_home, internet_only, etc.)
         |
         v
    Device-Specific Override (optional)
         |
         v
    Effective Policy -> OpenFlow Rules

License: Proprietary - See LICENSING.md
"""

__version__ = "1.0.0"
__author__ = "HookProbe Team"

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .types import (
        BubbleType, BubbleState, NetworkPolicy, Bubble,
        BUBBLE_TYPE_TO_POLICY, POLICY_INFO
    )
    from .manager import EcosystemBubbleManager, get_bubble_manager
    from .policy_resolver import PolicyResolver, PolicyResolution, get_policy_resolver

__all__ = [
    # Core Types
    "BubbleType",
    "BubbleState",
    "NetworkPolicy",
    "Bubble",
    # Constants
    "BUBBLE_TYPE_TO_POLICY",
    "POLICY_INFO",
    # Manager
    "EcosystemBubbleManager",
    "get_bubble_manager",
    # Policy Resolution
    "PolicyResolver",
    "PolicyResolution",
    "get_policy_resolver",
]


def __getattr__(name: str):
    """Lazy import for heavy modules."""
    if name in ("BubbleType", "BubbleState", "NetworkPolicy", "Bubble",
                "BUBBLE_TYPE_TO_POLICY", "POLICY_INFO"):
        from .types import (
            BubbleType, BubbleState, NetworkPolicy, Bubble,
            BUBBLE_TYPE_TO_POLICY, POLICY_INFO
        )
        return locals()[name]
    elif name in ("EcosystemBubbleManager", "get_bubble_manager"):
        from .manager import EcosystemBubbleManager, get_bubble_manager
        return locals()[name]
    elif name in ("PolicyResolver", "PolicyResolution", "get_policy_resolver"):
        from .policy_resolver import PolicyResolver, PolicyResolution, get_policy_resolver
        return locals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
