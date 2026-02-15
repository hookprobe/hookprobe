"""
Traffic Profile Library — Pre-built application traffic profiles.

Each profile defines the statistical characteristics of a target application's
traffic: packet size distribution, inter-packet timing, burst patterns, and
bandwidth envelope. The TrafficShaper uses these to mold HTP traffic.

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import random
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ProfileType(Enum):
    """Available traffic profile types."""
    NETFLIX = auto()        # Netflix-style video streaming
    ZOOM_VIDEO = auto()     # Zoom video conferencing (bimodal)
    HTTPS_BROWSE = auto()   # General HTTPS web browsing
    GAMING = auto()         # Online gaming (low latency, small packets)
    SSH_INTERACTIVE = auto()  # SSH interactive session
    CUSTOM = auto()         # User-defined profile


class BurstPattern(Enum):
    """Traffic burst behavior patterns."""
    STEADY = auto()         # Constant bitrate (streaming)
    BURSTY = auto()         # Periodic bursts (web browsing)
    BIMODAL = auto()        # Two distinct modes (video + audio)
    INTERACTIVE = auto()    # Keystroke-driven, irregular


@dataclass
class SizeDistribution:
    """Packet size distribution specification.

    Uses a mixture of normal distributions to model real traffic.
    Each component: (mean_bytes, std_bytes, weight).
    """
    components: List[Tuple[float, float, float]]  # [(mean, std, weight), ...]
    min_size: int = 64       # Minimum packet size (Ethernet min)
    max_size: int = 1500     # Maximum packet size (MTU)

    def sample(self) -> int:
        """Sample a packet size from the distribution."""
        # Select component by weight
        total = sum(w for _, _, w in self.components)
        r = random.random() * total
        cumulative = 0.0
        for mean, std, weight in self.components:
            cumulative += weight
            if r <= cumulative:
                size = int(random.gauss(mean, std))
                return max(self.min_size, min(self.max_size, size))
        # Fallback to last component
        mean, std, _ = self.components[-1]
        size = int(random.gauss(mean, std))
        return max(self.min_size, min(self.max_size, size))

    def sample_batch(self, n: int) -> List[int]:
        """Sample n packet sizes."""
        return [self.sample() for _ in range(n)]


@dataclass
class TimingDistribution:
    """Inter-packet timing distribution specification.

    Models the delay between consecutive packets in milliseconds.
    """
    mean_ms: float           # Mean inter-packet delay
    std_ms: float            # Standard deviation
    min_ms: float = 1.0      # Minimum delay
    max_ms: float = 5000.0   # Maximum delay
    # Burst parameters
    burst_probability: float = 0.0   # Probability of entering burst mode
    burst_interval_ms: float = 5.0   # Inter-packet delay during burst
    burst_length: int = 10           # Number of packets per burst

    def sample(self) -> float:
        """Sample an inter-packet delay in milliseconds."""
        if self.burst_probability > 0 and random.random() < self.burst_probability:
            # In burst mode, use tight spacing
            delay = max(self.min_ms, random.gauss(self.burst_interval_ms, 1.0))
        else:
            delay = random.gauss(self.mean_ms, self.std_ms)
        return max(self.min_ms, min(self.max_ms, delay))


@dataclass
class TrafficProfile:
    """Complete traffic profile for an application type.

    Defines all statistical characteristics needed for the TrafficShaper
    to mold HTP traffic into the target application's traffic pattern.
    """
    name: str
    profile_type: ProfileType
    description: str

    # Packet size distribution
    size_distribution: SizeDistribution

    # Inter-packet timing
    timing: TimingDistribution

    # Bandwidth envelope
    target_bandwidth_kbps: float   # Target average bandwidth
    bandwidth_tolerance: float     # Acceptable deviation (0.0-1.0)

    # Burst pattern
    burst_pattern: BurstPattern = BurstPattern.STEADY

    # TLS/QUIC wrapping
    wrap_tls: bool = True          # Wrap in TLS Application Data
    tls_record_sizes: Optional[List[int]] = None  # Common TLS record sizes

    # Identification
    stealth_score: float = 0.9     # How well this blends (0.0-1.0)

    # Protocol-specific headers
    protocol_port: int = 443       # Expected destination port
    protocol_name: str = "TLS"     # Protocol identifier

    def get_target_packet_rate(self) -> float:
        """Calculate target packets per second from bandwidth and mean size."""
        mean_size = sum(m * w for m, _, w in self.size_distribution.components)
        mean_size /= sum(w for _, _, w in self.size_distribution.components)
        if mean_size <= 0:
            return 0.0
        bytes_per_sec = self.target_bandwidth_kbps * 1000 / 8
        return bytes_per_sec / mean_size


# =========================================================================
# Pre-built Traffic Profiles
# =========================================================================

NETFLIX_PROFILE = TrafficProfile(
    name="Netflix 4K Stream",
    profile_type=ProfileType.NETFLIX,
    description="Netflix adaptive bitrate streaming (4K tier)",
    size_distribution=SizeDistribution(
        components=[
            (1300.0, 80.0, 0.85),    # Video data: large packets
            (200.0, 50.0, 0.10),     # Audio data: medium packets
            (80.0, 20.0, 0.05),      # Control: small packets
        ],
        min_size=64,
        max_size=1460,
    ),
    timing=TimingDistribution(
        mean_ms=8.0,        # ~125 packets/sec for 15 Mbps
        std_ms=3.0,
        min_ms=1.0,
        max_ms=100.0,
        burst_probability=0.1,
        burst_interval_ms=2.0,
        burst_length=20,
    ),
    target_bandwidth_kbps=15000,  # 15 Mbps (Netflix 4K)
    bandwidth_tolerance=0.3,
    burst_pattern=BurstPattern.STEADY,
    wrap_tls=True,
    tls_record_sizes=[1200, 1300, 1400, 1460],
    stealth_score=0.95,
    protocol_port=443,
    protocol_name="TLS",
)


ZOOM_VIDEO_PROFILE = TrafficProfile(
    name="Zoom Video Call",
    profile_type=ProfileType.ZOOM_VIDEO,
    description="Zoom video conferencing with audio (bimodal distribution)",
    size_distribution=SizeDistribution(
        components=[
            (1100.0, 100.0, 0.60),    # Video frames: large
            (200.0, 40.0, 0.30),      # Audio frames: small
            (100.0, 30.0, 0.10),      # Signaling: tiny
        ],
        min_size=64,
        max_size=1400,
    ),
    timing=TimingDistribution(
        mean_ms=20.0,       # ~50 packets/sec (30fps video + audio)
        std_ms=8.0,
        min_ms=5.0,
        max_ms=200.0,
        burst_probability=0.05,
        burst_interval_ms=3.0,
        burst_length=5,
    ),
    target_bandwidth_kbps=3500,  # 3.5 Mbps (Zoom HD)
    bandwidth_tolerance=0.4,
    burst_pattern=BurstPattern.BIMODAL,
    wrap_tls=True,
    tls_record_sizes=[200, 1100, 1200],
    stealth_score=0.90,
    protocol_port=443,
    protocol_name="TLS",
)


HTTPS_BROWSE_PROFILE = TrafficProfile(
    name="HTTPS Web Browsing",
    profile_type=ProfileType.HTTPS_BROWSE,
    description="General HTTPS web browsing with page loads and idle periods",
    size_distribution=SizeDistribution(
        components=[
            (1400.0, 60.0, 0.40),     # Large resources (images, JS)
            (600.0, 200.0, 0.30),     # Medium resources
            (150.0, 80.0, 0.20),      # Small requests/headers
            (80.0, 20.0, 0.10),       # ACKs, keepalives
        ],
        min_size=64,
        max_size=1460,
    ),
    timing=TimingDistribution(
        mean_ms=50.0,       # Bursty: fast during load, idle between
        std_ms=100.0,       # High variance
        min_ms=1.0,
        max_ms=5000.0,
        burst_probability=0.3,
        burst_interval_ms=5.0,
        burst_length=30,
    ),
    target_bandwidth_kbps=2000,  # 2 Mbps average
    bandwidth_tolerance=0.8,     # High tolerance (bursty)
    burst_pattern=BurstPattern.BURSTY,
    wrap_tls=True,
    tls_record_sizes=[150, 600, 1400],
    stealth_score=0.85,
    protocol_port=443,
    protocol_name="TLS",
)


GAMING_PROFILE = TrafficProfile(
    name="Online Gaming",
    profile_type=ProfileType.GAMING,
    description="Low-latency online gaming (FPS/MOBA style)",
    size_distribution=SizeDistribution(
        components=[
            (120.0, 30.0, 0.70),      # Game state updates: small
            (300.0, 80.0, 0.20),      # Position/action: medium
            (800.0, 200.0, 0.10),     # Asset loading: occasional large
        ],
        min_size=64,
        max_size=1200,
    ),
    timing=TimingDistribution(
        mean_ms=16.0,       # ~60 updates/sec (60Hz tick rate)
        std_ms=4.0,
        min_ms=5.0,
        max_ms=100.0,
        burst_probability=0.02,
        burst_interval_ms=2.0,
        burst_length=5,
    ),
    target_bandwidth_kbps=500,  # 500 Kbps
    bandwidth_tolerance=0.2,
    burst_pattern=BurstPattern.INTERACTIVE,
    wrap_tls=False,           # Games often use UDP directly
    stealth_score=0.75,
    protocol_port=443,
    protocol_name="DTLS",
)


SSH_INTERACTIVE_PROFILE = TrafficProfile(
    name="SSH Interactive",
    profile_type=ProfileType.SSH_INTERACTIVE,
    description="SSH interactive session with typing and command output",
    size_distribution=SizeDistribution(
        components=[
            (80.0, 20.0, 0.50),       # Keystroke echo: tiny
            (400.0, 200.0, 0.30),     # Command output: variable
            (1200.0, 200.0, 0.20),    # Large output (ls, cat): big
        ],
        min_size=64,
        max_size=1400,
    ),
    timing=TimingDistribution(
        mean_ms=200.0,      # Typing speed + think time
        std_ms=500.0,       # Very high variance (typing bursts)
        min_ms=10.0,
        max_ms=5000.0,
        burst_probability=0.15,
        burst_interval_ms=10.0,
        burst_length=5,
    ),
    target_bandwidth_kbps=50,  # 50 Kbps
    bandwidth_tolerance=0.9,
    burst_pattern=BurstPattern.INTERACTIVE,
    wrap_tls=True,
    stealth_score=0.80,
    protocol_port=22,
    protocol_name="SSH",
)


# =========================================================================
# Profile Registry
# =========================================================================

PROFILES: Dict[ProfileType, TrafficProfile] = {
    ProfileType.NETFLIX: NETFLIX_PROFILE,
    ProfileType.ZOOM_VIDEO: ZOOM_VIDEO_PROFILE,
    ProfileType.HTTPS_BROWSE: HTTPS_BROWSE_PROFILE,
    ProfileType.GAMING: GAMING_PROFILE,
    ProfileType.SSH_INTERACTIVE: SSH_INTERACTIVE_PROFILE,
}


def get_profile(profile_type: ProfileType) -> TrafficProfile:
    """Get a traffic profile by type.

    Raises KeyError if profile_type is not registered.
    """
    if profile_type not in PROFILES:
        raise KeyError(f"Unknown profile type: {profile_type}")
    return PROFILES[profile_type]


def list_profiles() -> List[Dict[str, str]]:
    """List all available profiles with summary info."""
    return [
        {
            "name": p.name,
            "type": p.profile_type.name,
            "bandwidth_kbps": str(p.target_bandwidth_kbps),
            "stealth_score": f"{p.stealth_score:.2f}",
        }
        for p in PROFILES.values()
    ]
