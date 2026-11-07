"""
Traffic Shaper — Molds HTP packets to match target application profiles.

Pads, fragments, and schedules HTP packets so the resulting traffic is
statistically indistinguishable from the target application (Netflix,
Zoom, etc.) when observed by a network adversary.

Key operations:
1. Size shaping: pad/fragment packets to match target size distribution
2. Timing enforcement: schedule transmission to match timing distribution
3. Bandwidth regulation: maintain target bandwidth envelope
4. Protocol wrapping: add appropriate TLS/QUIC framing

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import hashlib
import logging
import os
import struct
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Tuple

from .profile_library import (
    BurstPattern,
    ProfileType,
    TrafficProfile,
    get_profile,
)

logger = logging.getLogger(__name__)

# Shaping constants
FRAGMENT_HEADER_SIZE = 8     # 2B msg_id + 2B frag_index + 2B total_frags + 2B payload_len
PAD_MARKER = b'\x00'         # Padding byte
REAL_DATA_FLAG = 0x01        # Flag: packet contains real data
PADDING_FLAG = 0x02          # Flag: packet is pure padding (decoy)
FRAGMENT_FLAG = 0x04         # Flag: packet is a fragment


@dataclass
class ShapedPacket:
    """A packet after shaping — ready for transmission."""
    data: bytes               # Shaped payload (padded/fragmented)
    target_size: int          # Target size from profile sampling
    delay_ms: float           # Recommended delay before sending
    flags: int = REAL_DATA_FLAG
    fragment_id: int = 0      # Non-zero if fragmented
    fragment_index: int = 0   # Fragment position (0-based)
    total_fragments: int = 1  # Total fragments for this message
    timestamp: float = 0.0    # Scheduled send time

    @property
    def is_fragment(self) -> bool:
        return self.total_fragments > 1

    @property
    def is_padding(self) -> bool:
        return bool(self.flags & PADDING_FLAG)


@dataclass
class ShaperStats:
    """Statistics for the traffic shaper."""
    packets_shaped: int = 0
    bytes_original: int = 0
    bytes_shaped: int = 0
    fragments_created: int = 0
    padding_packets: int = 0
    padding_bytes: int = 0
    bandwidth_samples: Deque = field(default_factory=lambda: deque(maxlen=100))

    @property
    def overhead_ratio(self) -> float:
        if self.bytes_original == 0:
            return 0.0
        return self.bytes_shaped / self.bytes_original

    @property
    def current_bandwidth_kbps(self) -> float:
        if len(self.bandwidth_samples) < 2:
            return 0.0
        oldest_time, oldest_bytes = self.bandwidth_samples[0]
        newest_time, newest_bytes = self.bandwidth_samples[-1]
        duration = newest_time - oldest_time
        if duration <= 0:
            return 0.0
        total_bytes = sum(b for _, b in self.bandwidth_samples)
        return (total_bytes * 8) / (duration * 1000)


class TrafficShaper:
    """Molds HTP traffic to match a target application profile.

    Usage:
        shaper = TrafficShaper(ProfileType.NETFLIX)
        packets = shaper.shape(payload)
        for pkt in packets:
            time.sleep(pkt.delay_ms / 1000)
            transport.send(pkt.data)
    """

    def __init__(
        self,
        profile_type: ProfileType,
        custom_profile: Optional[TrafficProfile] = None,
    ):
        if custom_profile:
            self.profile = custom_profile
        else:
            self.profile = get_profile(profile_type)

        self._stats = ShaperStats()
        self._next_fragment_id = 1
        self._burst_counter = 0     # Tracks position in current burst
        self._last_send_time = 0.0
        self._bandwidth_window: Deque[Tuple[float, int]] = deque(maxlen=200)

        logger.info(
            "TrafficShaper initialized: profile=%s, bandwidth=%d kbps",
            self.profile.name,
            self.profile.target_bandwidth_kbps,
        )

    def shape(self, payload: bytes) -> List[ShapedPacket]:
        """Shape a payload into one or more packets matching the profile.

        The payload is padded or fragmented to match the target size
        distribution. Each resulting packet includes timing information.

        Args:
            payload: Raw HTP payload bytes.

        Returns:
            List of ShapedPacket objects ready for transmission.
        """
        if not payload:
            return []

        self._stats.bytes_original += len(payload)
        now = time.monotonic()

        # Sample target size from profile
        target_size = self.profile.size_distribution.sample()

        # Determine if we need fragmentation or padding
        payload_with_header = self._add_shaping_header(payload, REAL_DATA_FLAG)

        if len(payload_with_header) <= target_size:
            # Pad to target size
            packets = [self._pad_packet(payload_with_header, target_size, now)]
        else:
            # Fragment across multiple profile-sized packets
            packets = self._fragment_packet(payload_with_header, now)

        # Record stats
        for pkt in packets:
            self._stats.packets_shaped += 1
            self._stats.bytes_shaped += len(pkt.data)
            self._bandwidth_window.append((now, len(pkt.data)))
            self._stats.bandwidth_samples.append((now, len(pkt.data)))

        return packets

    def shape_batch(self, payloads: List[bytes]) -> List[ShapedPacket]:
        """Shape multiple payloads, interleaving for natural traffic flow."""
        all_packets = []
        for payload in payloads:
            all_packets.extend(self.shape(payload))
        return all_packets

    def unshape(self, shaped_data: bytes) -> Optional[bytes]:
        """Extract the original payload from a shaped packet.

        Handles both plain and fragmented (single-fragment) packets.
        Returns None if this is a padding-only packet.
        """
        if len(shaped_data) < 4:
            return None

        # Read shaping header: [2B total_len][1B flags][1B reserved]
        total_len, flags, _ = struct.unpack("!HBB", shaped_data[:4])

        if flags & PADDING_FLAG:
            return None  # Pure padding packet

        if flags & FRAGMENT_FLAG:
            # Single-fragment packet — unwrap through fragment header
            return self.unshape_fragments([shaped_data])

        # Extract real payload (after header, before padding)
        payload = shaped_data[4:4 + total_len]
        return payload

    def unshape_fragments(self, fragments: List[bytes]) -> Optional[bytes]:
        """Reassemble fragmented packets into the original payload.

        Args:
            fragments: List of shaped fragment data, in order.

        Returns:
            Reassembled original payload, or None on error.
        """
        if not fragments:
            return None

        reassembled = bytearray()
        for frag_data in fragments:
            if len(frag_data) < 4 + FRAGMENT_HEADER_SIZE:
                continue

            # Skip shaping header
            total_len, flags, _ = struct.unpack("!HBB", frag_data[:4])

            if not (flags & FRAGMENT_FLAG):
                # Not a fragment, just return the unshapped data
                return self.unshape(frag_data)

            # Read fragment header after shaping header
            offset = 4
            msg_id, frag_idx, total_frags, frag_len = struct.unpack(
                "!HHHH", frag_data[offset:offset + FRAGMENT_HEADER_SIZE]
            )
            offset += FRAGMENT_HEADER_SIZE

            reassembled.extend(frag_data[offset:offset + frag_len])

        # The reassembled data still has the original shaping header
        if len(reassembled) < 4:
            return None

        total_len, flags, _ = struct.unpack("!HBB", bytes(reassembled[:4]))
        return bytes(reassembled[4:4 + total_len])

    def generate_padding_packet(self) -> ShapedPacket:
        """Generate a pure padding packet matching the profile.

        Used by DecoyGenerator for cover traffic.
        """
        target_size = self.profile.size_distribution.sample()
        delay = self.profile.timing.sample()

        # Random padding content (indistinguishable from encrypted data)
        padding_content = os.urandom(max(0, target_size - 4))
        header = struct.pack("!HBB", 0, PADDING_FLAG, 0)
        data = header + padding_content

        self._stats.padding_packets += 1
        self._stats.padding_bytes += len(data)

        return ShapedPacket(
            data=data,
            target_size=target_size,
            delay_ms=delay,
            flags=PADDING_FLAG,
            timestamp=time.monotonic(),
        )

    def get_next_delay(self) -> float:
        """Get the next inter-packet delay in milliseconds."""
        return self.profile.timing.sample()

    def wrap_tls_record(self, data: bytes) -> bytes:
        """Wrap data in a TLS Application Data record header.

        TLS record: [0x17][0x03][0x03][2B length][payload]
        """
        if not self.profile.wrap_tls:
            return data
        # TLS 1.2 Application Data: content_type(1B) + version(2B) + length(2B)
        tls_header = struct.pack("!BBBH", 0x17, 0x03, 0x03, len(data))
        return tls_header + data

    def unwrap_tls_record(self, data: bytes) -> bytes:
        """Remove TLS Application Data record header if present."""
        if len(data) >= 5 and data[0] == 0x17 and data[1:3] == b'\x03\x03':
            length = struct.unpack("!H", data[3:5])[0]
            return data[5:5 + length]
        return data

    def get_stats(self) -> Dict[str, Any]:
        """Get shaping statistics."""
        return {
            "profile": self.profile.name,
            "packets_shaped": self._stats.packets_shaped,
            "bytes_original": self._stats.bytes_original,
            "bytes_shaped": self._stats.bytes_shaped,
            "overhead_ratio": round(self._stats.overhead_ratio, 2),
            "fragments_created": self._stats.fragments_created,
            "padding_packets": self._stats.padding_packets,
            "padding_bytes": self._stats.padding_bytes,
            "current_bandwidth_kbps": round(self._stats.current_bandwidth_kbps, 1),
            "target_bandwidth_kbps": self.profile.target_bandwidth_kbps,
        }

    # ------------------------------------------------------------------
    # Internal Methods
    # ------------------------------------------------------------------

    def _add_shaping_header(self, payload: bytes, flags: int) -> bytes:
        """Add 4-byte shaping header: [2B payload_len][1B flags][1B reserved]."""
        header = struct.pack("!HBB", len(payload), flags, 0)
        return header + payload

    def _pad_packet(
        self,
        data: bytes,
        target_size: int,
        now: float,
    ) -> ShapedPacket:
        """Pad data to target_size with random bytes."""
        pad_len = max(0, target_size - len(data))
        if pad_len > 0:
            padded = data + os.urandom(pad_len)
        else:
            padded = data

        delay = self.profile.timing.sample()

        return ShapedPacket(
            data=padded,
            target_size=target_size,
            delay_ms=delay,
            flags=REAL_DATA_FLAG,
            timestamp=now,
        )

    def _fragment_packet(
        self,
        data: bytes,
        now: float,
    ) -> List[ShapedPacket]:
        """Fragment data across multiple profile-sized packets."""
        frag_id = self._next_fragment_id
        self._next_fragment_id = (self._next_fragment_id + 1) % 65536

        # Calculate fragment sizes from profile samples
        fragments = []
        offset = 0
        remaining = len(data)

        while remaining > 0:
            target_size = self.profile.size_distribution.sample()
            # Account for shaping header (4B) + fragment header (8B)
            max_payload = max(1, target_size - 4 - FRAGMENT_HEADER_SIZE)
            chunk_len = min(remaining, max_payload)
            fragments.append(data[offset:offset + chunk_len])
            offset += chunk_len
            remaining -= chunk_len

        total_frags = len(fragments)
        packets = []

        for idx, chunk in enumerate(fragments):
            # Build fragment: [shaping_header][fragment_header][chunk][padding]
            frag_header = struct.pack(
                "!HHHH",
                frag_id, idx, total_frags, len(chunk),
            )
            inner = frag_header + chunk
            # Add shaping header with FRAGMENT flag
            shaped_header = struct.pack(
                "!HBB",
                len(inner),
                REAL_DATA_FLAG | FRAGMENT_FLAG,
                0,
            )
            full_data = shaped_header + inner

            # Pad to a profile-sampled size
            target_size = self.profile.size_distribution.sample()
            pad_len = max(0, target_size - len(full_data))
            if pad_len > 0:
                full_data += os.urandom(pad_len)

            delay = self.profile.timing.sample()

            packets.append(ShapedPacket(
                data=full_data,
                target_size=target_size,
                delay_ms=delay,
                flags=REAL_DATA_FLAG | FRAGMENT_FLAG,
                fragment_id=frag_id,
                fragment_index=idx,
                total_fragments=total_frags,
                timestamp=now,
            ))
            self._stats.fragments_created += 1

        return packets
