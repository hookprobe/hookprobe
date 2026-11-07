#!/usr/bin/env python3
"""
DSM Bloom Filter IOC Sharing Protocol

Privacy-preserving threat intelligence sharing between HookProbe nodes.
Uses Bloom filters to share IOC (Indicator of Compromise) membership
without revealing the exact IPs/domains.

Protocol:
  1. Each node maintains a local Bloom filter of detected malicious IOCs
  2. Periodically, nodes exchange Bloom filters via DSM gossip
  3. On receive, union the remote filter with local (OR operation)
  4. Before blocking an IP, check if it appears in the collective filter
  5. Differential privacy noise is added before sharing

Privacy guarantees:
  - Bloom filters have inherent false positive rate (~1% at optimal)
  - DP noise (ε=1) adds calibrated random bits before sharing
  - Raw IPs/domains never leave the node
  - Filter size is fixed (independent of actual IOC count)

Usage:
    from shared.dsm.bloom_ioc import BloomIOCFilter, IOCSharingProtocol

    # Create local filter
    bloom = BloomIOCFilter(expected_items=10000, fp_rate=0.01)
    bloom.add("192.168.1.100")
    bloom.add("evil-domain.com")

    # Check membership
    if bloom.contains("192.168.1.100"):
        print("IOC found in collective intelligence")

    # Share via DSM (with DP noise)
    protocol = IOCSharingProtocol(bloom, epsilon=1.0)
    export_data = protocol.export_with_privacy()
    # ... send via gossip ...
    protocol.merge_remote(remote_data)
"""

import hashlib
import logging
import math
import os
import struct
import time
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


class BloomIOCFilter:
    """Space-efficient probabilistic IOC membership test.

    Uses multiple hash functions to map IOCs to a fixed-size bit array.
    False positives are possible; false negatives are not.
    """

    def __init__(self, expected_items: int = 10000, fp_rate: float = 0.01):
        """Initialize Bloom filter.

        Args:
            expected_items: Expected number of IOCs to store
            fp_rate: Desired false positive rate (0.01 = 1%)
        """
        # Optimal filter size: m = -n*ln(p) / (ln(2))^2
        self.size = max(64, int(-expected_items * math.log(fp_rate) / (math.log(2) ** 2)))
        # Round up to nearest byte
        self.size = ((self.size + 7) // 8) * 8
        # Optimal hash count: k = (m/n) * ln(2)
        self.num_hashes = max(1, int((self.size / expected_items) * math.log(2)))
        # Bit array stored as bytearray
        self.bits = bytearray(self.size // 8)
        self.item_count = 0
        self.created_at = time.time()

        logger.debug(
            f"BloomIOCFilter: size={self.size} bits ({self.size // 8} bytes), "
            f"hashes={self.num_hashes}, expected_fp={fp_rate:.2%}"
        )

    def _hash_positions(self, item: str) -> List[int]:
        """Generate hash positions for an item using double hashing."""
        # Use SHA-256 for primary hash, MD5 for secondary (both deterministic)
        h1 = int.from_bytes(hashlib.sha256(item.encode()).digest()[:8], 'big')
        h2 = int.from_bytes(hashlib.md5(item.encode()).digest()[:8], 'big')
        return [(h1 + i * h2) % self.size for i in range(self.num_hashes)]

    def add(self, item: str):
        """Add an IOC to the filter."""
        for pos in self._hash_positions(item):
            byte_idx = pos // 8
            bit_idx = pos % 8
            self.bits[byte_idx] |= (1 << bit_idx)
        self.item_count += 1

    def contains(self, item: str) -> bool:
        """Check if an IOC might be in the filter.

        Returns True if the item is PROBABLY in the set (may be false positive).
        Returns False if the item is DEFINITELY NOT in the set.
        """
        for pos in self._hash_positions(item):
            byte_idx = pos // 8
            bit_idx = pos % 8
            if not (self.bits[byte_idx] & (1 << bit_idx)):
                return False
        return True

    def merge(self, other: 'BloomIOCFilter'):
        """Merge another Bloom filter (OR operation)."""
        if len(self.bits) != len(other.bits):
            logger.warning("Cannot merge filters of different sizes")
            return
        for i in range(len(self.bits)):
            self.bits[i] |= other.bits[i]

    def fill_ratio(self) -> float:
        """Fraction of bits set (higher = more items / more FP)."""
        set_bits = sum(bin(b).count('1') for b in self.bits)
        return set_bits / self.size

    def estimated_fp_rate(self) -> float:
        """Estimate current false positive rate."""
        fill = self.fill_ratio()
        if fill >= 1.0:
            return 1.0
        return fill ** self.num_hashes

    def export_bytes(self) -> bytes:
        """Export filter as bytes for network transmission."""
        header = struct.pack(
            '>IIId',
            self.size,
            self.num_hashes,
            self.item_count,
            self.created_at,
        )
        return header + bytes(self.bits)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'BloomIOCFilter':
        """Import filter from network bytes."""
        header_size = struct.calcsize('>IIId')
        size, num_hashes, item_count, created_at = struct.unpack(
            '>IIId', data[:header_size]
        )
        bloom = cls.__new__(cls)
        bloom.size = size
        bloom.num_hashes = num_hashes
        bloom.item_count = item_count
        bloom.created_at = created_at
        bloom.bits = bytearray(data[header_size:])
        return bloom

    def to_dict(self) -> dict:
        """Serialize for JSON/API."""
        return {
            "size_bits": self.size,
            "size_bytes": len(self.bits),
            "num_hashes": self.num_hashes,
            "item_count": self.item_count,
            "fill_ratio": round(self.fill_ratio(), 4),
            "estimated_fp_rate": round(self.estimated_fp_rate(), 6),
            "created_at": self.created_at,
        }


@dataclass
class IOCSharingProtocol:
    """Privacy-preserving IOC sharing via DSM gossip.

    Adds differential privacy noise before sharing Bloom filters
    to prevent inference attacks on the exact IOC set.
    """
    bloom: BloomIOCFilter
    epsilon: float = 1.0        # Privacy budget (lower = more private)
    node_id: str = ""
    last_shared: float = 0.0
    share_interval: int = 3600  # Share every hour

    def __post_init__(self):
        if not self.node_id:
            self.node_id = os.environ.get("HOOKPROBE_NODE_ID", "unknown")

    def export_with_privacy(self) -> bytes:
        """Export Bloom filter with differential privacy noise.

        Randomized response: each bit is flipped with probability
        1/(1+e^ε). For ε=1, flip probability ≈ 27%.
        """
        flip_prob = 1.0 / (1.0 + math.exp(self.epsilon))
        noisy_bits = bytearray(len(self.bloom.bits))

        for i in range(len(self.bloom.bits)):
            byte_val = self.bloom.bits[i]
            noisy_byte = 0
            for bit in range(8):
                original = (byte_val >> bit) & 1
                # Flip with probability flip_prob
                if os.urandom(1)[0] / 255.0 < flip_prob:
                    noisy_byte |= ((1 - original) << bit)
                else:
                    noisy_byte |= (original << bit)
            noisy_bits[i] = noisy_byte

        # Pack with metadata
        header = struct.pack(
            '>IIIdfd',
            self.bloom.size,
            self.bloom.num_hashes,
            self.bloom.item_count,
            self.bloom.created_at,
            self.epsilon,
            time.time(),
        )
        self.last_shared = time.time()
        return header + bytes(noisy_bits)

    def merge_remote(self, data: bytes):
        """Merge a received Bloom filter into local filter."""
        header_size = struct.calcsize('>IIIdfd')
        size, num_hashes, item_count, created_at, epsilon, shared_at = struct.unpack(
            '>IIIdfd', data[:header_size]
        )

        if size != self.bloom.size:
            logger.warning(f"Remote filter size mismatch: {size} vs {self.bloom.size}")
            return False

        remote_bits = bytearray(data[header_size:])
        # OR merge
        for i in range(len(self.bloom.bits)):
            self.bloom.bits[i] |= remote_bits[i]

        logger.info(
            f"Merged remote IOC filter: {item_count} items, ε={epsilon}, "
            f"local fill={self.bloom.fill_ratio():.2%}"
        )
        return True

    def should_share(self) -> bool:
        """Check if it's time to share the filter."""
        return (time.time() - self.last_shared) >= self.share_interval

    def stats(self) -> dict:
        """Get sharing protocol statistics."""
        return {
            "node_id": self.node_id,
            "epsilon": self.epsilon,
            "bloom": self.bloom.to_dict(),
            "last_shared": self.last_shared,
            "share_interval": self.share_interval,
        }


# --- CLI entry point ---
if __name__ == "__main__":
    import json

    # Demo
    bloom = BloomIOCFilter(expected_items=1000, fp_rate=0.01)
    for i in range(100):
        bloom.add(f"192.168.1.{i}")

    print(json.dumps(bloom.to_dict(), indent=2))
    print(f"\nContains 192.168.1.50: {bloom.contains('192.168.1.50')}")
    print(f"Contains 10.0.0.1: {bloom.contains('10.0.0.1')}")

    # Test privacy export
    protocol = IOCSharingProtocol(bloom, epsilon=1.0, node_id="test-node")
    export = protocol.export_with_privacy()
    print(f"\nExport size: {len(export)} bytes")
    print(f"Stats: {json.dumps(protocol.stats(), indent=2)}")
