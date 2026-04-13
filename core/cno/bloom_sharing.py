"""
Bloom Filter IOC Sharing — Privacy-Preserving Threat Intelligence

Nodes share threat intelligence WITHOUT revealing raw IPs or features.
Uses Bloom filters for set membership testing with differential privacy.

How it works:
    1. Each node builds a Bloom filter of its detected malicious IPs
    2. Differential privacy noise (ε=1.0) is added to the filter
    3. Filters are exchanged via the HTP mesh transport
    4. Receiving nodes can test "is IP X known-bad somewhere?" without
       learning which node flagged it or the exact IP list

Properties:
    - False positive rate: ~1% at 10K IPs with 128KB filter
    - Differential privacy: ε=1.0 (strong guarantee)
    - No raw IP leakage between nodes
    - Compact: 128KB per node regardless of IP count

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import hashlib
import logging
import math
import os
import re
import secrets
import struct
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

# ClickHouse config
CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

if not re.match(r'^[A-Za-z0-9_]+$', CH_DB):
    raise ValueError(f"Unsafe CLICKHOUSE_DB value: {CH_DB!r}")

# Bloom filter parameters
BLOOM_SIZE_BITS = 1_048_576    # 128KB = 1M bits
BLOOM_NUM_HASHES = 7           # Optimal for ~1% FPR at 100K items
BLOOM_SEED = 0x48505249        # "HPRI" — HookProbe Intelligence

# Differential privacy
DP_EPSILON = 1.0               # Privacy budget (lower = more private)
DP_SENSITIVITY = 1             # Each IP affects 1 bit per hash function

# Sharing interval
SHARE_INTERVAL_S = 300         # Share filters every 5 minutes
MAX_IPS_PER_FILTER = 100_000   # Cap to prevent filter saturation


class BloomFilter:
    """Space-efficient probabilistic set membership test.

    Uses multiple hash functions (double hashing scheme) to map elements
    to bit positions. False positives possible, false negatives impossible.
    """

    def __init__(self, size_bits: int = BLOOM_SIZE_BITS,
                 num_hashes: int = BLOOM_NUM_HASHES):
        self.size = size_bits
        self.num_hashes = num_hashes
        self._bits = bytearray(size_bits // 8)
        self._count = 0

    def _hash_pair(self, item: str) -> Tuple[int, int]:
        """Generate two independent hashes for double hashing."""
        h = hashlib.sha256(item.encode('utf-8')).digest()
        h1 = struct.unpack('<Q', h[:8])[0]
        h2 = struct.unpack('<Q', h[8:16])[0]
        return h1, h2

    def add(self, item: str) -> None:
        """Add an item to the filter."""
        h1, h2 = self._hash_pair(item)
        for i in range(self.num_hashes):
            pos = (h1 + i * h2) % self.size
            byte_idx = pos // 8
            bit_idx = pos % 8
            self._bits[byte_idx] |= (1 << bit_idx)
        self._count += 1

    def contains(self, item: str) -> bool:
        """Test if an item is (probably) in the filter."""
        h1, h2 = self._hash_pair(item)
        for i in range(self.num_hashes):
            pos = (h1 + i * h2) % self.size
            byte_idx = pos // 8
            bit_idx = pos % 8
            if not (self._bits[byte_idx] & (1 << bit_idx)):
                return False
        return True

    def false_positive_rate(self) -> float:
        """Estimate current false positive rate."""
        if self._count == 0:
            return 0.0
        # FPR ≈ (1 - e^(-kn/m))^k
        k = self.num_hashes
        n = self._count
        m = self.size
        return (1 - math.exp(-k * n / m)) ** k

    def to_bytes(self) -> bytes:
        """Serialize filter to bytes for network transmission."""
        header = struct.pack('<III', self.size, self.num_hashes, self._count)
        return header + bytes(self._bits)

    # Security audit C4: max filter size to prevent OOM from rogue peers
    MAX_BLOOM_SIZE_BITS = 16 * 1024 * 1024 * 8  # 16MB max
    MAX_BLOOM_HASHES = 20

    @classmethod
    def from_bytes(cls, data: bytes) -> 'BloomFilter':
        """Deserialize filter from bytes with size validation.

        Security audit C4: rogue nodes can send size=0xFFFFFFFF causing
        512MB allocation → OOM. Validate size + density before accepting.
        """
        if len(data) < 12:
            raise ValueError("Bloom filter data too short")
        size, num_hashes, count = struct.unpack('<III', data[:12])
        if size == 0 or size > cls.MAX_BLOOM_SIZE_BITS:
            raise ValueError(f"Bloom filter size out of range: {size}")
        if num_hashes == 0 or num_hashes > cls.MAX_BLOOM_HASHES:
            raise ValueError(f"Bloom hash count out of range: {num_hashes}")
        bf = cls(size_bits=size, num_hashes=num_hashes)
        expected_bytes = size // 8
        bf._bits = bytearray(data[12:12 + expected_bytes])
        bf._count = count
        return bf

    def merge(self, other: 'BloomFilter') -> None:
        """Merge another filter into this one (OR operation)."""
        if self.size != other.size:
            raise ValueError("Cannot merge filters of different sizes")
        for i in range(len(self._bits)):
            self._bits[i] |= other._bits[i]
        self._count += other._count

    @property
    def count(self) -> int:
        return self._count

    def bit_density(self) -> float:
        """Fraction of bits set (saturation indicator)."""
        set_bits = sum(bin(b).count('1') for b in self._bits)
        return set_bits / self.size


class DifferentialPrivacy:
    """Adds calibrated noise to Bloom filters for privacy.

    Uses the randomized response mechanism: each bit has a probability
    of being flipped based on the privacy budget ε.

    At ε=1.0:
        P(flip) = 1 / (1 + e^ε) ≈ 0.269
        Strong privacy guarantee while maintaining ~73% accuracy per bit.
    """

    def __init__(self, epsilon: float = DP_EPSILON):
        self.epsilon = epsilon
        self.flip_probability = 1.0 / (1.0 + math.exp(epsilon))
        logger.info("DP initialized: ε=%.2f, flip_prob=%.3f",
                     epsilon, self.flip_probability)

    def add_noise(self, bloom: BloomFilter) -> BloomFilter:
        """Create a noisy copy of the Bloom filter.

        Each bit is independently flipped with probability 1/(1+e^ε).
        The original filter is NOT modified.
        """
        noisy = BloomFilter(bloom.size, bloom.num_hashes)
        noisy._count = bloom._count

        for i in range(len(bloom._bits)):
            byte_val = bloom._bits[i]
            noisy_byte = 0
            for bit in range(8):
                original_bit = (byte_val >> bit) & 1
                if secrets.randbelow(1_000_000) / 1_000_000 < self.flip_probability:
                    noisy_byte |= ((1 - original_bit) << bit)  # Flip
                else:
                    noisy_byte |= (original_bit << bit)  # Keep
            noisy._bits[i] = noisy_byte

        return noisy


class BloomSharingEngine:
    """Manages Bloom filter creation, DP noise, and mesh distribution.

    Builds filters from local HYDRA verdicts and shares them with
    mesh peers. Receives peer filters and merges into a global view.
    """

    def __init__(self):
        self._local_filter = BloomFilter()
        self._global_filter = BloomFilter()  # Merged from all peers
        self._dp = DifferentialPrivacy()
        self._peer_filters: Dict[str, BloomFilter] = {}
        self._last_share = 0.0

        self._stats = {
            'local_ips_added': 0,
            'filters_shared': 0,
            'filters_received': 0,
            'global_lookups': 0,
            'global_hits': 0,
        }

        logger.info("BloomSharingEngine initialized (size=%dKB, hashes=%d, ε=%.1f)",
                     BLOOM_SIZE_BITS // 8192, BLOOM_NUM_HASHES, DP_EPSILON)

    def build_local_filter(self) -> int:
        """Build Bloom filter from recent local malicious verdicts.

        Returns count of IPs added.
        """
        query = (
            f"SELECT DISTINCT src_ip "
            f"FROM {CH_DB}.hydra_verdicts "
            f"WHERE timestamp > now() - INTERVAL 24 HOUR "
            f"AND verdict = 'malicious' "
            f"AND anomaly_score > 0.7 "
            f"LIMIT {MAX_IPS_PER_FILTER}"
        )
        result = _ch_query(query)
        if not result:
            return 0

        self._local_filter = BloomFilter()  # Fresh filter each cycle
        count = 0
        for line in result.strip().split('\n'):
            ip = line.strip()
            if ip and _IPV4_RE.match(ip):
                self._local_filter.add(ip)
                count += 1

        self._stats['local_ips_added'] = count
        logger.debug("Built local Bloom filter: %d IPs, FPR=%.4f, density=%.3f",
                     count, self._local_filter.false_positive_rate(),
                     self._local_filter.bit_density())
        return count

    def get_shareable_filter(self) -> bytes:
        """Get a DP-noised version of the local filter for sharing.

        This is what gets sent to mesh peers — never the raw filter.
        """
        noisy = self._dp.add_noise(self._local_filter)
        self._stats['filters_shared'] += 1
        return noisy.to_bytes()

    MAX_PEER_FILTERS = 100  # Security audit H5: prevent unbounded growth

    def receive_peer_filter(self, peer_id: str, data: bytes) -> bool:
        """Receive and merge a peer's Bloom filter with validation.

        Security audits C4 + H5: validates filter size, density, and
        enforces maximum peer count to prevent OOM from rogue nodes.
        """
        try:
            peer_filter = BloomFilter.from_bytes(data)

            # H5: reject saturated filters (all 1s = mesh-wide DOS)
            density = peer_filter.bit_density()
            if density > 0.90:
                logger.warning("Rejecting saturated filter from %s (density=%.3f)",
                               peer_id, density)
                return False

            # H5: enforce max peer count
            if (len(self._peer_filters) >= self.MAX_PEER_FILTERS
                    and peer_id not in self._peer_filters):
                logger.warning("Peer filter limit (%d) reached, rejecting %s",
                               self.MAX_PEER_FILTERS, peer_id)
                return False

            self._peer_filters[peer_id] = peer_filter

            # Rebuild global filter from all peers (atomic assignment)
            new_global = BloomFilter()
            for pf in self._peer_filters.values():
                new_global.merge(pf)
            self._global_filter = new_global  # Single atomic assignment under GIL

            self._stats['filters_received'] += 1
            logger.info("Received filter from peer %s (%d items), global density=%.3f",
                        peer_id, peer_filter.count, self._global_filter.bit_density())
            return True

        except Exception as e:
            logger.error("Failed to process peer filter from %s: %s", peer_id, e)
            return False

    def is_known_threat(self, ip: str) -> Tuple[bool, str]:
        """Check if an IP is flagged by any node in the mesh.

        Returns (is_threat, source) where source is 'local', 'global', or 'none'.
        """
        self._stats['global_lookups'] += 1

        if self._local_filter.contains(ip):
            self._stats['global_hits'] += 1
            return True, 'local'

        if self._global_filter.contains(ip):
            self._stats['global_hits'] += 1
            return True, 'global'

        return False, 'none'

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            'local_filter_count': self._local_filter.count,
            'local_fpr': round(self._local_filter.false_positive_rate(), 4),
            'local_density': round(self._local_filter.bit_density(), 4),
            'peer_count': len(self._peer_filters),
            'global_filter_count': self._global_filter.count,
            'global_density': round(self._global_filter.bit_density(), 4),
        }


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

_IPV4_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)


def _ch_query(query: str) -> Optional[str]:
    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        data = query.encode('utf-8')
        req = Request(url, data=data)
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        req.add_header('X-ClickHouse-Database', CH_DB)
        with urlopen(req, timeout=10) as resp:
            return resp.read().decode('utf-8')
    except Exception:
        return None
