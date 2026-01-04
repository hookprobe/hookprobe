"""
AIOCHI Backend - Core Intelligence Engines
Cognitive Network Layer for HookProbe Fortress

The Three Pillars:
- PRESENCE: Who's Home (device bubbles, ecosystem detection)
- PRIVACY: What's Happening (narrative feed of events)
- PERFORMANCE: How Fast (network health score)
"""

from .identity_engine import IdentityEngine, DeviceIdentity
from .narrative_engine import NarrativeEngine, Narrative
from .presence_tracker import PresenceTracker, Bubble
from .performance_scorer import PerformanceScorer, HealthScore
from .ambient_state import AmbientState, AmbientStateManager
from .quick_actions import QuickActionExecutor, QuickAction
from .time_patterns import TimePatternLearner, PatternAnomaly
from .trust_heatmap import TrustHeatmap, TrustLevel
from .whisper_mode import WhisperMode, WhisperPhase
from .family_profiles import FamilyProfile, FamilyProfileManager, Persona

__all__ = [
    # Core Engines
    "IdentityEngine",
    "DeviceIdentity",
    "NarrativeEngine",
    "Narrative",
    "PresenceTracker",
    "Bubble",
    "PerformanceScorer",
    "HealthScore",
    "AmbientState",
    "AmbientStateManager",
    "QuickActionExecutor",
    "QuickAction",
    # Intelligence Modules
    "TimePatternLearner",
    "PatternAnomaly",
    "TrustHeatmap",
    "TrustLevel",
    "WhisperMode",
    "WhisperPhase",
    # Family Profiles
    "FamilyProfile",
    "FamilyProfileManager",
    "Persona",
]
