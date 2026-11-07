"""
Decoy Generator — Cover traffic to maintain consistent bandwidth.

When the HTP session is idle, the DecoyGenerator produces cover traffic
that is cryptographically indistinguishable from real packets. This
prevents traffic analysis attacks that detect activity patterns.

Key properties:
1. Decoy packets are random bytes (same as encrypted real data)
2. Size distribution matches the active traffic profile
3. Timing matches profile's idle patterns
4. Hidden flag for receiver identification (HMAC-based)

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import hashlib
import hmac
import logging
import os
import struct
import time
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .profile_library import TrafficProfile, ProfileType, get_profile
from .traffic_shaper import TrafficShaper, ShapedPacket, PADDING_FLAG

logger = logging.getLogger(__name__)


@dataclass
class DecoyConfig:
    """Configuration for decoy traffic generation."""
    # Timing
    idle_threshold_ms: float = 500.0    # After this idle time, start decoys
    max_decoy_rate: float = 0.8         # Max fraction of profile bandwidth for decoys
    min_decoy_rate: float = 0.1         # Min fraction (always some cover)

    # HMAC identification
    hmac_key: bytes = field(default_factory=lambda: os.urandom(32))
    hmac_offset: int = 4                # Offset in packet for HMAC tag

    # Lifecycle
    decoy_ttl_s: float = 3600.0         # Decoy generation window (1 hour)
    ramp_up_s: float = 5.0              # Time to reach full decoy rate
    ramp_down_s: float = 2.0            # Time to stop decoys after real traffic


@dataclass
class DecoyStats:
    """Statistics for decoy traffic generation."""
    decoys_generated: int = 0
    decoy_bytes: int = 0
    real_packets_seen: int = 0
    idle_periods: int = 0
    active: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decoys_generated": self.decoys_generated,
            "decoy_bytes": self.decoy_bytes,
            "real_packets_seen": self.real_packets_seen,
            "idle_periods": self.idle_periods,
            "active": self.active,
        }


class DecoyGenerator:
    """Generates cover traffic indistinguishable from real encrypted data.

    Usage:
        gen = DecoyGenerator(ProfileType.NETFLIX, hmac_key=shared_key)
        gen.set_send_callback(transport.send)
        gen.start()  # Begins background decoy generation

        # When real data arrives:
        gen.notify_real_packet()  # Reduces decoy rate

        # Check if received packet is decoy:
        if gen.is_decoy(received_data):
            continue  # Discard
    """

    def __init__(
        self,
        profile_type: ProfileType,
        config: Optional[DecoyConfig] = None,
        custom_profile: Optional[TrafficProfile] = None,
    ):
        self.config = config or DecoyConfig()
        self._shaper = TrafficShaper(profile_type, custom_profile=custom_profile)
        self.profile = self._shaper.profile

        self._stats = DecoyStats()
        self._send_callback: Optional[Callable[[bytes], None]] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Timing state
        self._last_real_packet_time = 0.0
        self._start_time = 0.0
        self._decoy_rate = self.config.min_decoy_rate

        logger.info("DecoyGenerator initialized: profile=%s", self.profile.name)

    def set_send_callback(self, callback: Callable[[bytes], None]) -> None:
        """Set the callback for sending decoy packets."""
        self._send_callback = callback

    def start(self) -> None:
        """Start background decoy generation."""
        if self._running:
            return

        self._running = True
        self._start_time = time.monotonic()
        self._last_real_packet_time = time.monotonic()
        self._stats.active = True

        self._thread = threading.Thread(
            target=self._decoy_loop,
            name="decoy-generator",
            daemon=True,
        )
        self._thread.start()
        logger.info("DecoyGenerator started")

    def stop(self) -> None:
        """Stop background decoy generation."""
        self._running = False
        self._stats.active = False
        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None
        logger.info("DecoyGenerator stopped")

    def notify_real_packet(self) -> None:
        """Notify the generator that a real packet was sent/received.

        This reduces the decoy rate temporarily.
        """
        with self._lock:
            self._last_real_packet_time = time.monotonic()
            self._stats.real_packets_seen += 1

    def generate_decoy(self) -> ShapedPacket:
        """Generate a single decoy packet matching the profile.

        The packet contains random data with an HMAC tag embedded
        at a fixed offset so the receiver can identify it as a decoy.
        """
        # Generate random payload
        target_size = self.profile.size_distribution.sample()
        payload_size = max(0, target_size - 4)  # Account for shaping header
        random_payload = os.urandom(payload_size)

        # Embed HMAC tag for receiver identification
        # Tag = HMAC-SHA256(key, nonce)[:8] at offset
        nonce = random_payload[:16] if len(random_payload) >= 16 else random_payload
        tag = hmac.new(
            self.config.hmac_key, nonce, hashlib.sha256
        ).digest()[:8]

        # Place tag at fixed offset in payload
        tagged_payload = self._embed_tag(random_payload, tag)

        # Build shaped packet with PADDING flag
        header = struct.pack("!HBB", 0, PADDING_FLAG, 0)
        data = header + tagged_payload

        delay = self.profile.timing.sample()

        self._stats.decoys_generated += 1
        self._stats.decoy_bytes += len(data)

        return ShapedPacket(
            data=data,
            target_size=target_size,
            delay_ms=delay,
            flags=PADDING_FLAG,
            timestamp=time.monotonic(),
        )

    def is_decoy(self, data: bytes) -> bool:
        """Check if a received packet is a decoy.

        Verifies the HMAC tag at the expected offset.
        Returns True if the packet is a decoy (should be discarded).
        """
        if len(data) < 4:
            return False

        # Check shaping header flags
        _, flags, _ = struct.unpack("!HBB", data[:4])
        if flags & PADDING_FLAG:
            return True  # Explicitly marked as padding

        # Also verify HMAC tag for unmarked decoys
        payload = data[4:]
        if len(payload) < 24:  # Need nonce (16) + tag space (8)
            return False

        nonce = payload[:16]
        expected_tag = hmac.new(
            self.config.hmac_key, nonce, hashlib.sha256
        ).digest()[:8]

        embedded_tag = self._extract_tag(payload)
        if embedded_tag and hmac.compare_digest(embedded_tag, expected_tag):
            return True

        return False

    def get_stats(self) -> Dict[str, Any]:
        """Get decoy generation statistics."""
        return self._stats.to_dict()

    # ------------------------------------------------------------------
    # Internal Methods
    # ------------------------------------------------------------------

    def _decoy_loop(self) -> None:
        """Background loop generating decoy traffic."""
        while self._running:
            now = time.monotonic()

            # Check TTL
            if now - self._start_time > self.config.decoy_ttl_s:
                self._running = False
                break

            # Calculate current decoy rate based on idle time
            with self._lock:
                idle_time_ms = (now - self._last_real_packet_time) * 1000

            if idle_time_ms >= self.config.idle_threshold_ms:
                # Ramp up decoy rate
                ramp_factor = min(
                    1.0,
                    (idle_time_ms - self.config.idle_threshold_ms)
                    / (self.config.ramp_up_s * 1000),
                )
                target_rate = (
                    self.config.min_decoy_rate
                    + ramp_factor
                    * (self.config.max_decoy_rate - self.config.min_decoy_rate)
                )
                self._stats.idle_periods += 1
            else:
                # Ramp down
                target_rate = self.config.min_decoy_rate

            self._decoy_rate = target_rate

            # Generate and send decoy
            decoy = self.generate_decoy()

            if self._send_callback:
                try:
                    self._send_callback(decoy.data)
                except Exception as e:
                    logger.debug("Decoy send failed: %s", e)

            # Wait for profile-appropriate delay, scaled by decoy rate
            base_delay = decoy.delay_ms / 1000.0
            scaled_delay = base_delay / max(0.01, self._decoy_rate)
            time.sleep(min(scaled_delay, 5.0))

    def _embed_tag(self, payload: bytes, tag: bytes) -> bytes:
        """Embed an 8-byte HMAC tag at a fixed offset in the payload."""
        offset = min(self.config.hmac_offset, max(0, len(payload) - 8))
        if len(payload) < offset + 8:
            # Payload too small, extend
            payload = payload + os.urandom(offset + 8 - len(payload))

        return payload[:offset] + tag + payload[offset + 8:]

    def _extract_tag(self, payload: bytes) -> Optional[bytes]:
        """Extract the 8-byte HMAC tag from a fixed offset."""
        offset = min(self.config.hmac_offset, max(0, len(payload) - 8))
        if len(payload) < offset + 8:
            return None
        return payload[offset:offset + 8]
