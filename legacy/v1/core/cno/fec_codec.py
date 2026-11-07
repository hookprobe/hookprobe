"""
Forward Error Correction Codec — Brainstem Error Recovery

Provides FEC for mesh transport, allowing the organism to recover
from packet loss without retransmission. Critical for real-time
threat intelligence sharing across lossy WAN links.

Uses XOR-based parity (simple, fast, minimal overhead):
    - Every N data packets generates 1 parity packet
    - Can recover from any single packet loss in a group
    - Overhead: 1/N (e.g., N=4 → 25% overhead)

For CNO mesh transport, FEC is applied to:
    - Bloom filter fragments (federated intelligence)
    - Stress state broadcasts (organism coordination)
    - Kill chain alerts (time-critical warnings)

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Default FEC parameters
FEC_GROUP_SIZE = 4             # 4 data packets per parity packet (25% overhead)
FEC_MAX_PACKET_SIZE = 1400     # Max packet payload (below typical MTU)
FEC_RECOVERY_WINDOW_S = 5.0   # Time window to hold packets for recovery


class FECEncoder:
    """Generates parity packets for a group of data packets.

    Simple XOR parity: parity = data[0] ^ data[1] ^ ... ^ data[N-1]
    Can recover any single lost packet in the group.
    """

    def __init__(self, group_size: int = FEC_GROUP_SIZE):
        self.group_size = group_size
        self._current_group: List[bytes] = []
        self._original_lengths: List[int] = []  # Pre-pad lengths per packet
        self._group_id = 0
        self._stats = {
            'packets_encoded': 0,
            'parity_generated': 0,
        }

    def add_packet(self, data: bytes) -> Optional[bytes]:
        """Add a data packet. Returns parity packet when group is full.

        Each packet is padded to FEC_MAX_PACKET_SIZE for uniform XOR.
        Returns None until group_size packets accumulated, then returns
        the parity packet.
        """
        # Track original length BEFORE padding (rstrip would corrupt trailing \x00)
        self._original_lengths.append(len(data))
        # Pad to uniform size
        padded = data.ljust(FEC_MAX_PACKET_SIZE, b'\x00')
        self._current_group.append(padded)
        self._stats['packets_encoded'] += 1

        if len(self._current_group) >= self.group_size:
            parity = self._compute_parity()
            self._current_group.clear()
            self._original_lengths.clear()
            self._group_id += 1
            self._stats['parity_generated'] += 1
            return parity

        return None

    def _compute_parity(self) -> bytes:
        """XOR all packets in the group to produce parity.

        Header: group_id (4 bytes) + group_size (1 byte) + original_lengths (group_size * 2 bytes)
        Body: XOR of all padded packets
        """
        # Compute XOR parity
        parity = bytearray(FEC_MAX_PACKET_SIZE)
        for packet in self._current_group:
            for i in range(FEC_MAX_PACKET_SIZE):
                parity[i] ^= packet[i]

        # Build header with original lengths (tracked before padding — never rstrip)
        lengths = list(self._original_lengths)
        header = struct.pack('<IB', self._group_id, self.group_size)
        for length in lengths:
            header += struct.pack('<H', length)

        return header + bytes(parity)

    def flush(self) -> Optional[bytes]:
        """Force-generate parity for a partial group (end of stream)."""
        if self._current_group:
            # Pad group to full size with empty packets
            while len(self._current_group) < self.group_size:
                self._current_group.append(b'\x00' * FEC_MAX_PACKET_SIZE)
                self._original_lengths.append(0)
            parity = self._compute_parity()
            self._current_group.clear()
            self._original_lengths.clear()
            self._group_id += 1
            self._stats['parity_generated'] += 1
            return parity
        return None

    def get_stats(self) -> Dict[str, Any]:
        return dict(self._stats)


class FECDecoder:
    """Recovers lost packets using parity data.

    Holds received packets in groups. When a packet is missing but
    parity is available, recovers the missing packet via XOR.
    """

    def __init__(self, group_size: int = FEC_GROUP_SIZE):
        self.group_size = group_size
        # group_id → {index: packet_bytes, 'parity': parity_bytes}
        self._groups: Dict[int, Dict] = {}
        self._stats = {
            'packets_received': 0,
            'packets_recovered': 0,
            'groups_complete': 0,
            'groups_unrecoverable': 0,
        }

    def receive_data(self, group_id: int, index: int, data: bytes) -> None:
        """Receive a data packet belonging to a group."""
        if group_id not in self._groups:
            self._groups[group_id] = {}
        padded = data.ljust(FEC_MAX_PACKET_SIZE, b'\x00')
        self._groups[group_id][index] = padded
        self._stats['packets_received'] += 1

        # Cleanup old groups
        self._gc_old_groups()

    def receive_parity(self, parity_data: bytes) -> Optional[Tuple[int, int, bytes]]:
        """Receive a parity packet and attempt recovery.

        Returns (group_id, recovered_index, recovered_data) if recovery
        succeeds, or None if no recovery needed or possible.
        """
        if len(parity_data) < 5:
            return None

        # Parse header
        group_id, group_size = struct.unpack('<IB', parity_data[:5])
        lengths_size = group_size * 2
        if len(parity_data) < 5 + lengths_size + FEC_MAX_PACKET_SIZE:
            return None

        lengths = []
        for i in range(group_size):
            offset = 5 + i * 2
            lengths.append(struct.unpack('<H', parity_data[offset:offset + 2])[0])

        parity_body = parity_data[5 + lengths_size:5 + lengths_size + FEC_MAX_PACKET_SIZE]

        # Store parity + actual group_size from header
        if group_id not in self._groups:
            self._groups[group_id] = {}
        self._groups[group_id]['parity'] = parity_body
        self._groups[group_id]['lengths'] = lengths
        self._groups[group_id]['group_size'] = group_size

        # Try recovery
        return self._try_recover(group_id)

    def _try_recover(self, group_id: int) -> Optional[Tuple[int, int, bytes]]:
        """Try to recover a missing packet in a group."""
        group = self._groups.get(group_id, {})
        parity = group.get('parity')
        lengths = group.get('lengths', [])

        if not parity:
            return None

        # Count received data packets — use group_size from parity header
        received_indices = {k for k in group.keys() if isinstance(k, int)}
        actual_group_size = group.get('group_size', self.group_size)
        expected = set(range(actual_group_size))
        missing = expected - received_indices

        if len(missing) == 0:
            # All packets received, no recovery needed
            self._stats['groups_complete'] += 1
            return None

        if len(missing) > 1:
            # Cannot recover more than 1 packet with simple XOR parity
            self._stats['groups_unrecoverable'] += 1
            return None

        # Exactly 1 missing — recover via XOR
        missing_idx = missing.pop()
        recovered = bytearray(parity)

        for idx in received_indices:
            packet = group[idx]
            for i in range(FEC_MAX_PACKET_SIZE):
                recovered[i] ^= packet[i]

        # Unpad using original length
        original_len = lengths[missing_idx] if missing_idx < len(lengths) else FEC_MAX_PACKET_SIZE
        recovered_data = bytes(recovered[:original_len])

        self._stats['packets_recovered'] += 1
        logger.debug("FEC: recovered packet %d in group %d (%d bytes)",
                     missing_idx, group_id, original_len)

        return group_id, missing_idx, recovered_data

    def _gc_old_groups(self) -> None:
        """Remove groups older than the recovery window."""
        if len(self._groups) > 100:
            # Keep only the 50 most recent groups
            sorted_ids = sorted(self._groups.keys(),
                                key=lambda k: k if isinstance(k, int) else 0)
            for old_id in sorted_ids[:-50]:
                del self._groups[old_id]

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            'active_groups': len(self._groups),
        }


class FECCodec:
    """Combined encoder/decoder for bidirectional FEC."""

    def __init__(self, group_size: int = FEC_GROUP_SIZE):
        self.encoder = FECEncoder(group_size)
        self.decoder = FECDecoder(group_size)

    def get_stats(self) -> Dict[str, Any]:
        return {
            'encoder': self.encoder.get_stats(),
            'decoder': self.decoder.get_stats(),
        }
