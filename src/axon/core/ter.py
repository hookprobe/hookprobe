"""
Temporal Event Record (TER) - Core Data Structure

64-byte sensor snapshot that drives neural weight evolution.
"""

import hashlib
import struct
import time
from dataclasses import dataclass
from typing import Optional
import zlib


@dataclass
class TER:
    """
    Temporal Event Record - 64 bytes total

    Structure:
        H_Entropy    (32 bytes): SHA256 hash of system metrics
        H_Integrity  (20 bytes): RIPEMD160 hash of critical files
        Timestamp    (8 bytes):  Unix timestamp (microseconds)
        Sequence     (2 bytes):  Monotonic sequence number
        Chain_Hash   (2 bytes):  CRC16 of previous TER
    """
    h_entropy: bytes      # 32 bytes
    h_integrity: bytes    # 20 bytes
    timestamp: int        # 8 bytes (microseconds since epoch)
    sequence: int         # 2 bytes (0-65535)
    chain_hash: int       # 2 bytes (CRC16)

    def __post_init__(self):
        assert len(self.h_entropy) == 32, "H_Entropy must be 32 bytes"
        assert len(self.h_integrity) == 20, "H_Integrity must be 20 bytes"
        assert 0 <= self.sequence <= 65535, "Sequence must fit in 2 bytes"
        assert 0 <= self.chain_hash <= 65535, "Chain_Hash must fit in 2 bytes"

    def to_bytes(self) -> bytes:
        """Serialize TER to 64 bytes."""
        return struct.pack(
            '<32s20sQHH',
            self.h_entropy,
            self.h_integrity,
            self.timestamp,
            self.sequence,
            self.chain_hash
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> 'TER':
        """Deserialize TER from 64 bytes."""
        assert len(data) == 64, "TER must be exactly 64 bytes"

        h_entropy, h_integrity, timestamp, sequence, chain_hash = struct.unpack(
            '<32s20sQHH',
            data
        )

        return cls(
            h_entropy=h_entropy,
            h_integrity=h_integrity,
            timestamp=timestamp,
            sequence=sequence,
            chain_hash=chain_hash
        )

    def calculate_threat_score(self) -> float:
        """
        Convert H_Integrity hash to numerical threat score.
        Deterministic: same hash → same score.

        Returns:
            Σ_threat: Normalized threat score [0.0, 1.0]
        """
        # Take first 4 bytes of H_Integrity and interpret as uint32
        sigma_threat_raw = struct.unpack('<I', self.h_integrity[:4])[0]

        # Normalize to [0, 1] range
        sigma_threat = sigma_threat_raw / (2**32 - 1)

        return sigma_threat


class TERGenerator:
    """
    Generate TER from Qsecbit sensor data.
    """

    def __init__(self, qsecbit_interface=None):
        """
        Args:
            qsecbit_interface: Optional Qsecbit instance for sensor data
        """
        self.qsecbit = qsecbit_interface
        self.sequence = 0
        self.prev_ter_hash: Optional[int] = None

    def generate(self, force_integrity_check: bool = False) -> TER:
        """
        Generate TER from current system state.

        Args:
            force_integrity_check: If True, recalculate H_Integrity (expensive)

        Returns:
            TER instance
        """
        # 1. Collect system metrics
        if self.qsecbit:
            cpu = self.qsecbit.get_cpu_usage()
            mem = self.qsecbit.get_memory_footprint()
            net = self.qsecbit.get_network_queue_depth()
            disk = self.qsecbit.get_disk_io_wait()
        else:
            # Fallback: use psutil or /proc
            cpu, mem, net, disk = self._get_system_metrics_fallback()

        timestamp = time.time_ns() // 1000  # microseconds

        # 2. Derive H_Entropy (deterministic hash)
        entropy_data = struct.pack('<4fQ', cpu, mem, net, disk, timestamp)
        h_entropy = hashlib.sha256(entropy_data).digest()

        # 3. Derive H_Integrity
        h_integrity = self._calculate_h_integrity(force=force_integrity_check)

        # 4. Build TER
        ter = TER(
            h_entropy=h_entropy,
            h_integrity=h_integrity,
            timestamp=timestamp,
            sequence=self.sequence,
            chain_hash=self._calculate_chain_hash()
        )

        # 5. Update state for next TER
        self.sequence = (self.sequence + 1) % 65536
        self.prev_ter_hash = self._crc16(ter.to_bytes())

        return ter

    def _get_system_metrics_fallback(self):
        """Fallback system metrics without Qsecbit."""
        import psutil
        cpu = psutil.cpu_percent() / 100.0
        mem = psutil.virtual_memory().percent / 100.0
        net_io = psutil.net_io_counters()
        net = (net_io.bytes_sent + net_io.bytes_recv) / 1e9  # GB
        disk = psutil.disk_io_counters().read_time / 1000.0  # seconds
        return cpu, mem, net, disk

    def _calculate_h_integrity(self, force: bool = False) -> bytes:
        """
        Calculate H_Integrity from critical file hashes.

        Expensive operation - caches result and only recalculates if:
        1. force=True, or
        2. Periodic check (every 100 TERs)
        """
        # Cache integrity hash (expensive to calculate every TER)
        if not force and hasattr(self, '_cached_h_integrity'):
            if self.sequence % 100 != 0:  # Only recalculate every 100 TERs
                return self._cached_h_integrity

        # Calculate hashes of critical files
        try:
            with open('/boot/vmlinuz', 'rb') as f:
                kernel_hash = hashlib.sha256(f.read()).digest()
        except FileNotFoundError:
            kernel_hash = b'\x00' * 32

        try:
            with open('/usr/bin/hookprobe', 'rb') as f:
                binary_hash = hashlib.sha256(f.read()).digest()
        except FileNotFoundError:
            binary_hash = b'\x00' * 32

        try:
            with open('/etc/hookprobe/config.yaml', 'rb') as f:
                config_hash = hashlib.sha256(f.read()).digest()
        except FileNotFoundError:
            config_hash = b'\x00' * 32

        # Combine and hash with RIPEMD160
        integrity_data = kernel_hash + binary_hash + config_hash
        h_integrity = hashlib.new('ripemd160', integrity_data).digest()

        # Cache result
        self._cached_h_integrity = h_integrity

        return h_integrity

    def _calculate_chain_hash(self) -> int:
        """Calculate CRC16 of previous TER (or 0 for first TER)."""
        if self.prev_ter_hash is None:
            return 0
        return self.prev_ter_hash

    @staticmethod
    def _crc16(data: bytes) -> int:
        """
        Calculate CRC16 checksum.
        Uses CRC-16-CCITT polynomial: 0x1021
        """
        crc = 0xFFFF
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ 0x1021
                else:
                    crc = crc << 1
                crc &= 0xFFFF
        return crc


class TERValidator:
    """
    Validate TER sequence integrity.
    """

    @staticmethod
    def validate_sequence(ter_sequence: list[TER]) -> dict:
        """
        Validate TER sequence for tampering, gaps, anomalies.

        Returns:
            dict with validation results
        """
        results = {
            'valid': True,
            'errors': [],
            'warnings': []
        }

        if not ter_sequence:
            results['errors'].append("Empty TER sequence")
            results['valid'] = False
            return results

        # 1. Check chain integrity
        for i in range(1, len(ter_sequence)):
            prev_ter = ter_sequence[i-1]
            curr_ter = ter_sequence[i]

            expected_chain_hash = TERGenerator._crc16(prev_ter.to_bytes())
            if curr_ter.chain_hash != expected_chain_hash:
                results['errors'].append(
                    f"Chain break at index {i}: "
                    f"expected {expected_chain_hash}, got {curr_ter.chain_hash}"
                )
                results['valid'] = False

        # 2. Check sequence monotonicity
        for i in range(1, len(ter_sequence)):
            prev_seq = ter_sequence[i-1].sequence
            curr_seq = ter_sequence[i].sequence

            # Allow for wrap-around (65535 → 0)
            if curr_seq != (prev_seq + 1) % 65536:
                results['warnings'].append(
                    f"Sequence gap at index {i}: {prev_seq} → {curr_seq}"
                )

        # 3. Check timestamp monotonicity
        for i in range(1, len(ter_sequence)):
            prev_ts = ter_sequence[i-1].timestamp
            curr_ts = ter_sequence[i].timestamp

            delta_t = (curr_ts - prev_ts) / 1e6  # seconds

            if delta_t < 0:
                results['errors'].append(
                    f"Timestamp reversal at index {i}: {delta_t:.2f}s"
                )
                results['valid'] = False
            elif delta_t > 3600:  # > 1 hour gap
                results['warnings'].append(
                    f"Large time gap at index {i}: {delta_t:.2f}s"
                )

        # 4. Statistical entropy check (H_Entropy should have high entropy)
        entropy_values = [_calculate_shannon_entropy(ter.h_entropy) for ter in ter_sequence]
        avg_entropy = sum(entropy_values) / len(entropy_values)

        if avg_entropy < 7.0:  # Too low for SHA256 output
            results['warnings'].append(
                f"Low average entropy: {avg_entropy:.2f} bits/byte (expected ~7.9)"
            )

        return results


def _calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte sequence."""
    if not data:
        return 0.0

    # Count byte frequencies
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1

    # Calculate entropy
    entropy = 0.0
    data_len = len(data)
    for count in byte_counts:
        if count > 0:
            prob = count / data_len
            entropy -= prob * (prob.bit_length() - 1)

    return entropy
