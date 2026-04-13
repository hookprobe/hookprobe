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
import threading
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


class PeerReputation:
    """Phase 18: Per-peer trust scoring and consistency tracking.

    Tracks historical accuracy, filter consistency, and silence decay
    for each mesh peer. Used to filter untrusted peer intelligence
    and implement BFT voting (2-of-N trusted peers must agree).

    Trust algorithm (matches consciousness.py PeerNode pattern):
        success: trust = min(1.0, trust + α * (1 - trust))    → asymptotic to 1.0
        failure: trust = max(0.0, trust - α * trust)           → asymptotic to 0.0
        silence: trust *= SILENCE_DECAY_FACTOR per interval     → gradual decay
    """

    INITIAL_TRUST = 0.5          # Neutral starting point
    TRUST_ALPHA = 0.1            # Learning rate
    MIN_TRUST_TO_ACCEPT = 0.15   # Below this, reject filters entirely
    SILENCE_DECAY_FACTOR = 0.95  # Per-cycle decay when peer goes silent
    SILENCE_THRESHOLD_S = 600    # 10 min without contact = silence
    CONSISTENCY_THRESHOLD = 0.20 # Max acceptable |expected - observed| density
    MIN_PEERS_FOR_BFT = 2       # Minimum trusted peers for mesh consensus

    def __init__(self):
        # peer_id → reputation dict
        self._peers: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._stats = {
            'trust_updates': 0,
            'filters_rejected_untrusted': 0,
            'filters_rejected_inconsistent': 0,
            'bft_votes_passed': 0,
            'bft_votes_failed': 0,
            'silence_decays': 0,
            'accuracy_checks': 0,
        }

    def _ensure_peer(self, peer_id: str) -> Dict[str, Any]:
        """Get or create a peer reputation record."""
        if peer_id not in self._peers:
            self._peers[peer_id] = {
                'trust_score': self.INITIAL_TRUST,
                'filters_received': 0,
                'last_seen': 0.0,
                'declared_ips_history': [],     # Last 10 declared counts
                'observed_density_history': [],  # Last 10 densities
                'accuracy_hits': 0,              # IPs we also saw locally
                'accuracy_misses': 0,            # IPs we never saw
                'consistency_failures': 0,
            }
        return self._peers[peer_id]

    def update_trust(self, peer_id: str, success: bool) -> float:
        """Update trust score after a filter exchange.

        Returns the new trust score. Thread-safe.
        """
        with self._lock:
            peer = self._ensure_peer(peer_id)
            old = peer['trust_score']
            if success:
                peer['trust_score'] = min(
                    1.0, old + self.TRUST_ALPHA * (1.0 - old))
            else:
                peer['trust_score'] = max(
                    0.0, old - self.TRUST_ALPHA * old)
            self._stats['trust_updates'] += 1
            return peer['trust_score']

    def check_consistency(self, peer_id: str, declared_ips: int,
                          observed_density: float,
                          filter_num_hashes: int = BLOOM_NUM_HASHES,
                          filter_size_bits: int = BLOOM_SIZE_BITS) -> bool:
        """Check if filter density is consistent with declared IP count.

        Uses the PEER's filter parameters (not local constants) for the
        expected density calculation: 1 - e^(-k*n/m).
        """
        with self._lock:
            peer = self._ensure_peer(peer_id)
            peer['declared_ips_history'] = (
                peer['declared_ips_history'][-9:] + [declared_ips])
            peer['observed_density_history'] = (
                peer['observed_density_history'][-9:] + [observed_density])

        if declared_ips <= 0:
            return True  # Can't validate without declared count

        # Use peer's actual filter parameters, not local constants
        expected = 1.0 - math.exp(
            -filter_num_hashes * declared_ips / filter_size_bits)

        delta = abs(observed_density - expected)
        if delta > self.CONSISTENCY_THRESHOLD:
            with self._lock:
                peer = self._ensure_peer(peer_id)
                peer['consistency_failures'] += 1
                self._stats['filters_rejected_inconsistent'] += 1
            logger.warning(
                "Peer %s consistency FAIL: declared=%d → expected=%.3f "
                "vs observed=%.3f (delta=%.3f > %.3f)",
                peer_id[:12], declared_ips, expected,
                observed_density, delta, self.CONSISTENCY_THRESHOLD)
            self.update_trust(peer_id, success=False)
            return False
        return True

    def is_trusted(self, peer_id: str) -> bool:
        """Check if peer is trusted enough to accept filters from."""
        with self._lock:
            peer = self._ensure_peer(peer_id)
            return peer['trust_score'] >= self.MIN_TRUST_TO_ACCEPT

    def record_filter_received(self, peer_id: str) -> None:
        """Record that a filter was successfully received from peer."""
        with self._lock:
            peer = self._ensure_peer(peer_id)
            peer['filters_received'] += 1
            peer['last_seen'] = time.time()

    def record_untrusted_rejection(self) -> None:
        """Record that a filter was rejected from an untrusted peer."""
        with self._lock:
            self._stats['filters_rejected_untrusted'] += 1

    def decay_silent_peers(self) -> int:
        """Reduce trust for peers that haven't sent filters recently.

        Returns count of decayed peers.
        """
        now = time.time()
        decayed = 0
        with self._lock:
            for peer_id, peer in self._peers.items():
                if peer['last_seen'] > 0 and (now - peer['last_seen']) > self.SILENCE_THRESHOLD_S:
                    old_trust = peer['trust_score']
                    peer['trust_score'] = max(
                        0.0, old_trust * self.SILENCE_DECAY_FACTOR)
                    if old_trust != peer['trust_score']:
                        decayed += 1
            if decayed > 0:
                self._stats['silence_decays'] += decayed
        if decayed > 0:
            logger.info("REPUTATION: decayed %d silent peers", decayed)
        return decayed

    def record_accuracy(self, peer_id: str, ip: str,
                        seen_locally: bool) -> None:
        """Record whether a peer-flagged IP was also seen in our traffic.

        This is the post-hoc accuracy check: did the peer's intelligence
        actually match what we observed? Note: Bloom filter FPR (~1%) means
        accuracy_hits includes some false positives — this biases trust
        slightly upward, which is acceptable (erring on the side of trust).
        """
        with self._lock:
            peer = self._ensure_peer(peer_id)
            self._stats['accuracy_checks'] += 1
            if seen_locally:
                peer['accuracy_hits'] += 1
            else:
                peer['accuracy_misses'] += 1
        # Only update trust on hits (confirmed overlap)
        if seen_locally:
            self.update_trust(peer_id, success=True)

    def get_accuracy_rate(self, peer_id: str) -> float:
        """Get the historical accuracy rate for a peer."""
        peer = self._ensure_peer(peer_id)
        total = peer['accuracy_hits'] + peer['accuracy_misses']
        if total == 0:
            return 0.5  # No data → neutral
        return peer['accuracy_hits'] / total

    _UUID_RE = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        re.IGNORECASE)

    def bft_vote(self, ip: str,
                 peer_filters: Dict[str, 'BloomFilter']) -> Tuple[bool, int, int]:
        """BFT voting: require MIN_PEERS_FOR_BFT trusted peers to agree.

        Returns (should_block, votes_for, total_trusted_peers).
        Takes a snapshot of peer_filters to avoid dict-resize during iteration.
        """
        # Snapshot to avoid concurrent modification
        filters_snapshot = list(peer_filters.items())
        votes_for = 0
        trusted_peers = 0
        for peer_id, peer_filter in filters_snapshot:
            if not self.is_trusted(peer_id):
                continue
            trusted_peers += 1
            if peer_filter.contains(ip):
                votes_for += 1

        passed = votes_for >= self.MIN_PEERS_FOR_BFT
        with self._lock:
            if passed:
                self._stats['bft_votes_passed'] += 1
            elif trusted_peers > 0:
                self._stats['bft_votes_failed'] += 1

        return passed, votes_for, trusted_peers

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            peer_summaries = {}
            for peer_id, peer in self._peers.items():
                total = peer['accuracy_hits'] + peer['accuracy_misses']
                peer_summaries[peer_id[:12]] = {
                    'trust': round(peer['trust_score'], 3),
                    'filters': peer['filters_received'],
                    'accuracy': round(
                        peer['accuracy_hits'] / total, 3) if total > 0 else None,
                    'consistency_fails': peer['consistency_failures'],
                }
            return {
                **self._stats,
                'peer_count': len(self._peers),
                'peers': peer_summaries,
            }

    def get_peer_metrics_for_ch(self) -> List[Dict[str, Any]]:
        """Get peer metrics formatted for ClickHouse batch insert.

        Validates peer_id format (UUID) for SQL injection defence-in-depth.
        """
        now = time.time()
        rows = []
        with self._lock:
            for peer_id, peer in self._peers.items():
                # Defence-in-depth: ensure peer_id is valid UUID
                if not self._UUID_RE.match(peer_id):
                    continue
                total = peer['accuracy_hits'] + peer['accuracy_misses']
                rows.append({
                    'peer_id': peer_id,
                    'trust_score': round(peer['trust_score'], 4),
                    'filters_received': peer['filters_received'],
                    'accuracy_rate': round(
                        peer['accuracy_hits'] / total, 4) if total > 0 else 0.5,
                    'consistency_failures': peer['consistency_failures'],
                    'last_seen': peer['last_seen'],
                    'silence_seconds': int(
                        now - peer['last_seen']) if peer['last_seen'] > 0 else -1,
                })
        return rows


class BloomSharingEngine:
    """Manages Bloom filter creation, DP noise, and mesh distribution.

    Builds filters from local HYDRA verdicts and shares them with
    mesh peers. Receives peer filters and merges into a global view.
    Phase 18: Integrates PeerReputation for trust-weighted filter acceptance
    and BFT voting for mesh threat application.
    """

    def __init__(self):
        self._local_filter = BloomFilter()
        self._global_filter = BloomFilter()  # Merged from all peers
        self._dp = DifferentialPrivacy()
        self._peer_filters: Dict[str, BloomFilter] = {}
        self._peer_lock = threading.Lock()  # Protects _peer_filters dict
        self._last_share = 0.0
        # Phase 18: peer reputation system
        self._reputation = PeerReputation()

        self._stats = {
            'local_ips_added': 0,
            'filters_shared': 0,
            'filters_received': 0,
            'filters_rejected': 0,
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

    def receive_peer_filter(self, peer_id: str, data: bytes,
                            declared_ip_count: int = 0) -> bool:
        """Receive and merge a peer's Bloom filter with validation.

        Security audits C4 + H5: validates filter size, density, and
        enforces maximum peer count to prevent OOM from rogue nodes.

        Phase 18: adds reputation checks — rejects untrusted peers,
        validates filter consistency, updates trust on success.
        """
        try:
            # Phase 18: reject filters from untrusted peers
            if not self._reputation.is_trusted(peer_id):
                self._reputation.record_untrusted_rejection()
                self._stats['filters_rejected'] += 1
                logger.warning("Rejecting filter from untrusted peer %s",
                               peer_id[:12])
                return False

            peer_filter = BloomFilter.from_bytes(data)

            # Validate data length matches declared size
            expected_bytes = peer_filter.size // 8
            if len(peer_filter._bits) < expected_bytes:
                logger.warning("Truncated filter from %s: %d < %d bytes",
                               peer_id[:12], len(peer_filter._bits),
                               expected_bytes)
                self._reputation.update_trust(peer_id, success=False)
                self._stats['filters_rejected'] += 1
                return False

            # H5: reject saturated filters (all 1s = mesh-wide DOS)
            density = peer_filter.bit_density()
            if density > 0.90:
                logger.warning("Rejecting saturated filter from %s (density=%.3f)",
                               peer_id, density)
                self._reputation.update_trust(peer_id, success=False)
                self._stats['filters_rejected'] += 1
                return False

            # Phase 18: consistency check using PEER's filter params
            if declared_ip_count > 0:
                if not self._reputation.check_consistency(
                        peer_id, declared_ip_count, density,
                        filter_num_hashes=peer_filter.num_hashes,
                        filter_size_bits=peer_filter.size):
                    self._stats['filters_rejected'] += 1
                    return False

            # H5: enforce max peer count
            with self._peer_lock:
                if (len(self._peer_filters) >= self.MAX_PEER_FILTERS
                        and peer_id not in self._peer_filters):
                    logger.warning("Peer filter limit (%d) reached, rejecting %s",
                                   self.MAX_PEER_FILTERS, peer_id)
                    return False

                self._peer_filters[peer_id] = peer_filter

                # Rebuild global filter from all peers (under lock)
                new_global = BloomFilter()
                for pf in self._peer_filters.values():
                    new_global.merge(pf)
                self._global_filter = new_global

            # Phase 18: record success + update trust
            self._reputation.record_filter_received(peer_id)
            self._reputation.update_trust(peer_id, success=True)

            self._stats['filters_received'] += 1
            logger.info("Received filter from peer %s (%d items, trust=%.3f), "
                        "global density=%.3f",
                        peer_id[:12], peer_filter.count,
                        self._reputation._ensure_peer(peer_id)['trust_score'],
                        self._global_filter.bit_density())
            return True

        except Exception as e:
            logger.error("Failed to process peer filter from %s: %s", peer_id, e)
            self._reputation.update_trust(peer_id, success=False)
            return False

    def is_known_threat(self, ip: str) -> Tuple[bool, str]:
        """Check if an IP is flagged by any node in the mesh.

        Returns (is_threat, source) where source is:
          'local'  — our own filter (always trusted)
          'mesh'   — BFT consensus from 2+ trusted peers
          'none'   — not known

        Phase 18: mesh threats require BFT voting — 2+ trusted peers
        must agree before we trust the global filter result. This prevents
        a single compromised node from injecting fake IOCs.
        """
        self._stats['global_lookups'] += 1

        # Local filter: always trusted (our own detections)
        if self._local_filter.contains(ip):
            self._stats['global_hits'] += 1
            return True, 'local'

        # Phase 18: BFT voting on mesh intelligence
        with self._peer_lock:
            filters_snapshot = dict(self._peer_filters)
        if filters_snapshot:
            passed, votes, total = self._reputation.bft_vote(
                ip, filters_snapshot)
            if passed:
                self._stats['global_hits'] += 1
                return True, f'mesh({votes}/{total})'

        return False, 'none'

    @property
    def reputation(self) -> PeerReputation:
        """Phase 18: expose reputation engine for external accuracy updates."""
        return self._reputation

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            'local_filter_count': self._local_filter.count,
            'local_fpr': round(self._local_filter.false_positive_rate(), 4),
            'local_density': round(self._local_filter.bit_density(), 4),
            'peer_count': len(self._peer_filters),
            'global_filter_count': self._global_filter.count,
            'global_density': round(self._global_filter.bit_density(), 4),
            # Phase 18: reputation stats
            'reputation': self._reputation.get_stats(),
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
