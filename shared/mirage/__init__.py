"""
Mirage Module — Active Deception for HookProbe

Turns passive detection into active intelligence gathering through
auto-deployed adaptive honeypots, attacker profiling, and
intelligence feedback loops.

Integration:
    NAPSE EventBus → MirageOrchestrator → AdaptiveHoneypot
                                        → IntelligenceFeedback → QSecBit / Mesh
                                        → MirageBridge → AEGIS SCOUT agent

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

from .orchestrator import MirageOrchestrator, MirageState
from .adaptive_honeypot import AdaptiveHoneypot, InteractionLevel, SophisticationLevel
from .intelligence_feedback import IntelligenceFeedback
from .mirage_bridge import MirageBridge

__all__ = [
    "MirageOrchestrator",
    "MirageState",
    "AdaptiveHoneypot",
    "InteractionLevel",
    "SophisticationLevel",
    "IntelligenceFeedback",
    "MirageBridge",
]

__version__ = "1.0.0"
