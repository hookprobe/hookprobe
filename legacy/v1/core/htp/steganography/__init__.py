"""
HTP Steganographic Transport Module

Makes HTP mesh traffic indistinguishable from normal application traffic
(Netflix streaming, Zoom video, HTTPS browsing) using statistical shaping,
cover traffic generation, and CDN domain fronting.

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

from .profile_library import (
    TrafficProfile,
    ProfileType,
    PROFILES,
    get_profile,
)
from .traffic_shaper import TrafficShaper
from .decoy_generator import DecoyGenerator
from .domain_fronting import DomainFronter

__all__ = [
    "TrafficProfile",
    "ProfileType",
    "PROFILES",
    "get_profile",
    "TrafficShaper",
    "DecoyGenerator",
    "DomainFronter",
]

__version__ = "1.0.0"
