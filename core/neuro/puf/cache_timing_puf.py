"""
Cache Timing PUF — PUF from CPU cache access timing variations.

Measures L1/L2 cache access timing differences that arise from
manufacturing variations in cache SRAM cells and interconnects.
Produces a 128-bit (16-byte) supplementary PUF response.

This PUF has lower uniqueness than SRAM or Clock Drift PUFs but
provides additional entropy when combined via CompositeIdentity.

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import hashlib
import logging
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Constants
DEFAULT_CACHE_SIZE = 32768      # 32KB L1 cache test region
DEFAULT_ITERATIONS = 128        # Number of timing measurements
RESPONSE_BYTES = 16             # 128-bit response
STRIDE_SIZES = [64, 128, 256, 512, 1024, 4096]  # Access stride patterns


@dataclass
class CacheTiming:
    """A single cache timing measurement."""
    stride: int              # Access stride in bytes
    access_time_ns: int      # Time for sequential access
    random_time_ns: int      # Time for random access
    ratio: float = 0.0       # Sequential/random ratio

    def __post_init__(self):
        if self.random_time_ns > 0:
            self.ratio = self.access_time_ns / self.random_time_ns


@dataclass
class CacheProfile:
    """Complete cache timing profile."""
    timings: List[CacheTiming]
    response: bytes = b""          # 16-byte PUF response
    mean_ratio: float = 0.0
    cache_line_size: int = 64      # Detected cache line size

    @property
    def response_hex(self) -> str:
        return self.response.hex()


class CacheTimingPuf:
    """Cache Timing PUF — supplementary entropy from cache behavior.

    Measures how cache access patterns vary due to manufacturing
    differences in the CPU's cache hierarchy.

    Usage:
        puf = CacheTimingPuf()
        profile = puf.measure()
        response = profile.response  # 16-byte response
    """

    def __init__(
        self,
        cache_size: int = DEFAULT_CACHE_SIZE,
        iterations: int = DEFAULT_ITERATIONS,
    ):
        self._cache_size = cache_size
        self._iterations = iterations
        self._last_profile: Optional[CacheProfile] = None

        logger.info(
            "CacheTimingPuf initialized: cache_size=%d, iterations=%d",
            cache_size, iterations,
        )

    def measure(self) -> CacheProfile:
        """Perform cache timing measurements and generate PUF response.

        Returns CacheProfile with 16-byte response.
        """
        timings = []

        for stride in STRIDE_SIZES:
            timing = self._measure_stride(stride)
            timings.append(timing)

        # Calculate aggregate statistics
        ratios = [t.ratio for t in timings if t.ratio > 0]
        mean_ratio = sum(ratios) / len(ratios) if ratios else 0.0

        # Generate response
        response = self._timings_to_response(timings)

        # Detect cache line size from timing pattern
        cache_line = self._detect_cache_line_size(timings)

        profile = CacheProfile(
            timings=timings,
            response=response,
            mean_ratio=mean_ratio,
            cache_line_size=cache_line,
        )

        self._last_profile = profile
        return profile

    def get_response(self) -> bytes:
        """Get 16-byte PUF response."""
        if not self._last_profile:
            self.measure()
        return self._last_profile.response

    def get_stats(self) -> Dict:
        """Get PUF statistics."""
        result = {
            "cache_size": self._cache_size,
            "iterations": self._iterations,
            "has_profile": self._last_profile is not None,
        }
        if self._last_profile:
            result.update({
                "mean_ratio": round(self._last_profile.mean_ratio, 4),
                "cache_line_size": self._last_profile.cache_line_size,
                "response_hex": self._last_profile.response.hex(),
                "num_strides": len(self._last_profile.timings),
            })
        return result

    # ------------------------------------------------------------------
    # Internal Methods
    # ------------------------------------------------------------------

    def _measure_stride(self, stride: int) -> CacheTiming:
        """Measure cache access timing for a given stride."""
        # Create test buffer
        buf = bytearray(self._cache_size)

        # Sequential access timing
        sequential_ns = self._time_sequential_access(buf, stride)

        # "Random" access timing (large stride to cause cache misses)
        random_ns = self._time_random_access(buf, stride)

        return CacheTiming(
            stride=stride,
            access_time_ns=sequential_ns,
            random_time_ns=random_ns,
        )

    def _time_sequential_access(self, buf: bytearray, stride: int) -> int:
        """Time sequential memory access with given stride."""
        total_ns = 0
        positions = list(range(0, len(buf), stride))

        for _ in range(self._iterations):
            start = time.perf_counter_ns()
            for pos in positions:
                if pos < len(buf):
                    _ = buf[pos]
            end = time.perf_counter_ns()
            total_ns += (end - start)

        return total_ns // self._iterations if self._iterations > 0 else 0

    def _time_random_access(self, buf: bytearray, stride: int) -> int:
        """Time pseudo-random memory access pattern."""
        total_ns = 0
        # Use hash-based position sequence for reproducibility
        positions = []
        for i in range(len(buf) // stride):
            h = hashlib.md5(struct.pack("!II", stride, i)).digest()
            pos = struct.unpack("!I", h[:4])[0] % len(buf)
            positions.append(pos)

        for _ in range(self._iterations):
            start = time.perf_counter_ns()
            for pos in positions:
                _ = buf[pos]
            end = time.perf_counter_ns()
            total_ns += (end - start)

        return total_ns // self._iterations if self._iterations > 0 else 0

    def _timings_to_response(self, timings: List[CacheTiming]) -> bytes:
        """Convert timing measurements to a 16-byte PUF response."""
        # Pack timing data into bytes
        timing_data = bytearray()
        for t in timings:
            timing_data.extend(struct.pack(
                "!IIId",
                t.stride,
                t.access_time_ns,
                t.random_time_ns,
                t.ratio,
            ))

        # Hash to 16 bytes (128 bits)
        full_hash = hashlib.sha256(bytes(timing_data)).digest()
        return full_hash[:RESPONSE_BYTES]

    def _detect_cache_line_size(self, timings: List[CacheTiming]) -> int:
        """Detect cache line size from timing pattern.

        Cache line boundary shows a jump in access time ratio.
        """
        if len(timings) < 2:
            return 64  # Default

        # Find the stride where ratio changes most
        max_jump = 0
        line_size = 64

        for i in range(1, len(timings)):
            jump = abs(timings[i].ratio - timings[i - 1].ratio)
            if jump > max_jump:
                max_jump = jump
                line_size = timings[i].stride

        return line_size
