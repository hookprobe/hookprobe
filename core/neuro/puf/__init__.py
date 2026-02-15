"""
PUF (Physical Unclonable Function) — Hardware-Anchored Identity

Derives cryptographic identity from physical device characteristics that
cannot be cloned or extracted. Even if software keys are stolen, an
attacker cannot spoof a node's PUF-based identity.

Three PUF sources:
1. SRAM PUF: Startup bit patterns from uninitialized memory
2. Clock Drift PUF: TSC vs RTC timing differences
3. Cache Timing PUF: L1/L2 access timing variations

Combined via CompositeIdentity with reliability-weighted XOR,
then bound to Ed25519 keys via HKDF.

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

from .sram_puf import SRAMPuf, FuzzyExtractor
from .clock_drift_puf import ClockDriftPuf
from .cache_timing_puf import CacheTimingPuf
from .composite_identity import CompositeIdentity, PufResponse
from .puf_ter_binding import PufTerBinding

__all__ = [
    "SRAMPuf",
    "FuzzyExtractor",
    "ClockDriftPuf",
    "CacheTimingPuf",
    "CompositeIdentity",
    "PufResponse",
    "PufTerBinding",
]

__version__ = "1.0.0"
