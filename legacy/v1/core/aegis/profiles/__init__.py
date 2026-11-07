"""
AEGIS Tier Profiles

Defines per-tier AEGIS configurations that control which components
are loaded, inference mode, memory layers, and resource budgets.

Profiles:
    pico  — Sentinel (256MB): No LLM, template-only, 2-layer memory
    lite  — Guardian (1.5GB): Cloud LLM, 3-layer memory
    full  — Fortress (4GB):   Local + cloud LLM, 5-layer memory (default)
    deep  — Nexus (16GB+):    GPU LLM, 5-layer memory, large context
"""

from .pico import PICO_PROFILE
from .lite import LITE_PROFILE
from .full import FULL_PROFILE
from .deep import DEEP_PROFILE

# Profile registry
PROFILES = {
    "pico": PICO_PROFILE,
    "lite": LITE_PROFILE,
    "full": FULL_PROFILE,
    "deep": DEEP_PROFILE,
}

# Tier-to-profile mapping
TIER_PROFILES = {
    "sentinel": "pico",
    "guardian": "lite",
    "fortress": "full",
    "nexus": "deep",
}


def get_profile(tier: str) -> dict:
    """Get the AEGIS profile for a product tier.

    Args:
        tier: Product tier name (sentinel, guardian, fortress, nexus)
              or profile name directly (pico, lite, full, deep).

    Returns:
        Profile configuration dict.
    """
    profile_name = TIER_PROFILES.get(tier, tier)
    return PROFILES.get(profile_name, FULL_PROFILE)


__all__ = [
    "PROFILES",
    "TIER_PROFILES",
    "get_profile",
    "PICO_PROFILE",
    "LITE_PROFILE",
    "FULL_PROFILE",
    "DEEP_PROFILE",
]
