"""
Packet SIEM — Working Memory (Proprioception)

A 60-second in-memory sliding window of ALL packet movement.
This is the organism's proprioceptive awareness — "where are my limbs?"

Design decisions:
    - In-memory deque, NOT ClickHouse (can't handle packet-rate writes)
    - <100µs ingestion per packet snapshot
    - Thread-safe for concurrent reads from Cerebrum
    - Provides get_spatial_state() for instant network posture query

The Packet SIEM does NOT replace ClickHouse logging — it supplements it
with a fast, ephemeral view that the Cerebrum can query without I/O.

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import math
import threading
import time
from collections import Counter, defaultdict, deque
from typing import Any, Dict, List, Optional, Set, Tuple

from .types import PacketSnapshot, SpatialState

logger = logging.getLogger(__name__)

# Configuration
WINDOW_SECONDS = 60.0              # Sliding window duration
MAX_SNAPSHOTS = 200_000            # Hard cap on memory (200K × ~200B = ~40MB)
TOP_N = 10                         # Number of top talkers to track
SPATIAL_CACHE_TTL_S = 1.0          # Cache spatial state for 1 second
GC_INTERVAL_S = 5.0                # Garbage collect expired snapshots every 5s


class PacketSIEM:
    """60-second in-memory network state — the organism's working memory.

    Thread-safe. Multiple threads can ingest concurrently while the
    Cerebrum reads spatial state via get_spatial_state().
    """

    def __init__(self, window_seconds: float = WINDOW_SECONDS,
                 max_snapshots: int = MAX_SNAPSHOTS):
        self._window = window_seconds
        self._max = max_snapshots

        # Core storage — append-only deque with size cap
        self._packets: deque = deque(maxlen=max_snapshots)
        self._lock = threading.Lock()

        # Fast counters (updated on ingest, no need to scan deque)
        self._total_ingested: int = 0
        self._total_bytes: int = 0

        # Per-source counters (rolling, reset on GC)
        self._src_counter: Counter = Counter()
        self._dst_counter: Counter = Counter()
        self._proto_counter: Counter = Counter()
        self._intent_counter: Counter = Counter()
        self._action_counter: Counter = Counter()

        # Unique tracking
        self._unique_flows: Set[str] = set()

        # Cached spatial state
        self._cached_state: Optional[SpatialState] = None
        self._cached_at: float = 0.0

        # Background GC
        self._running = False
        self._gc_thread: Optional[threading.Thread] = None

        logger.info("PacketSIEM initialized (window=%.0fs, max=%d)",
                     window_seconds, max_snapshots)

    # ------------------------------------------------------------------
    # Ingestion (< 100µs per call)
    # ------------------------------------------------------------------

    def ingest(self, snapshot: PacketSnapshot) -> None:
        """Ingest a single packet snapshot into working memory.

        Designed for minimal latency — counter updates only, no I/O.
        """
        with self._lock:
            self._packets.append(snapshot)

        # Fast counter updates (no lock needed — atomic increments in CPython)
        self._total_ingested += 1
        self._total_bytes += snapshot.bytes_len
        self._src_counter[snapshot.src_ip] += 1
        self._dst_counter[snapshot.dst_ip] += 1
        self._proto_counter[snapshot.proto] += 1
        self._intent_counter[snapshot.intent_class] += 1
        self._action_counter[snapshot.action] += 1

        # Flow tracking (5-tuple hash for uniqueness)
        flow_key = (
            f"{snapshot.src_ip}:{snapshot.src_port}-"
            f"{snapshot.dst_ip}:{snapshot.dst_port}-{snapshot.proto}"
        )
        self._unique_flows.add(flow_key)

        # Invalidate cache
        self._cached_state = None

    def ingest_batch(self, snapshots: List[PacketSnapshot]) -> int:
        """Ingest a batch of packet snapshots. Returns count ingested."""
        for snap in snapshots:
            self.ingest(snap)
        return len(snapshots)

    # ------------------------------------------------------------------
    # Spatial State Query (< 1ms)
    # ------------------------------------------------------------------

    def get_spatial_state(self) -> SpatialState:
        """Get the current spatial awareness of the network.

        Returns a cached snapshot if within TTL, otherwise recomputes.
        This is the primary interface for the Cerebrum.
        """
        now = time.time()
        if self._cached_state and (now - self._cached_at) < SPATIAL_CACHE_TTL_S:
            return self._cached_state

        state = self._compute_spatial_state(now)
        self._cached_state = state
        self._cached_at = now
        return state

    def _compute_spatial_state(self, now: float) -> SpatialState:
        """Compute spatial state from the current window."""
        cutoff = now - self._window

        # Snapshot the deque (thread-safe copy of references)
        with self._lock:
            # Filter to window (packets are appended in time order)
            window_packets = [
                p for p in self._packets
                if p.timestamp >= cutoff
            ]

        total = len(window_packets)
        if total == 0:
            return SpatialState(timestamp=now, window_seconds=self._window)

        # Compute metrics from window
        total_bytes = sum(p.bytes_len for p in window_packets)

        # Time span
        if total > 1:
            time_span = window_packets[-1].timestamp - window_packets[0].timestamp
            pps = total / max(time_span, 0.001)
        else:
            pps = 0.0

        # Count unique sources, destinations, flows
        src_ips: Counter = Counter()
        dst_ips: Counter = Counter()
        proto_dist: Counter = Counter()
        intent_dist: Counter = Counter()
        flows: Set[str] = set()
        drops = 0
        alerts = 0

        for p in window_packets:
            src_ips[p.src_ip] += 1
            dst_ips[p.dst_ip] += 1
            proto_dist[p.proto] += 1
            intent_dist[p.intent_class] += 1
            flows.add(f"{p.src_ip}:{p.src_port}-{p.dst_ip}:{p.dst_port}-{p.proto}")
            if p.action == 'drop':
                drops += 1
            elif p.action == 'alert':
                alerts += 1

        threat_ratio = (drops + alerts) / total if total > 0 else 0.0

        # Determine if under attack
        is_attack = (
            threat_ratio > 0.10 or       # >10% threat traffic
            drops > 1000 or              # High volume drops
            pps > 50000                  # Extreme packet rate
        )

        # Find dominant threat
        dominant = ""
        threat_intents = {k: v for k, v in intent_dist.items() if k != 'benign'}
        if threat_intents:
            dominant = max(threat_intents, key=threat_intents.get)

        return SpatialState(
            timestamp=now,
            window_seconds=self._window,
            total_packets=total,
            total_bytes=total_bytes,
            packets_per_second=round(pps, 1),
            unique_src_ips=len(src_ips),
            unique_dst_ips=len(dst_ips),
            unique_flows=len(flows),
            drops=drops,
            alerts=alerts,
            threat_ratio=round(threat_ratio, 4),
            top_sources=dict(src_ips.most_common(TOP_N)),
            top_destinations=dict(dst_ips.most_common(TOP_N)),
            protocol_dist=dict(proto_dist),
            intent_dist=dict(intent_dist),
            is_under_attack=is_attack,
            dominant_threat=dominant,
        )

    # ------------------------------------------------------------------
    # Query Helpers
    # ------------------------------------------------------------------

    def get_ip_activity(self, ip: str, window_seconds: float = 60.0) -> Dict[str, Any]:
        """Get activity summary for a specific IP in the working memory."""
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            packets = [p for p in self._packets
                       if p.timestamp >= cutoff and
                       (p.src_ip == ip or p.dst_ip == ip)]

        if not packets:
            return {'ip': ip, 'packets': 0}

        as_src = [p for p in packets if p.src_ip == ip]
        as_dst = [p for p in packets if p.dst_ip == ip]

        return {
            'ip': ip,
            'packets': len(packets),
            'as_source': len(as_src),
            'as_destination': len(as_dst),
            'bytes_out': sum(p.bytes_len for p in as_src),
            'bytes_in': sum(p.bytes_len for p in as_dst),
            'intents': dict(Counter(p.intent_class for p in packets)),
            'unique_peers': len(set(
                p.dst_ip if p.src_ip == ip else p.src_ip for p in packets
            )),
            'first_seen': min(p.timestamp for p in packets),
            'last_seen': max(p.timestamp for p in packets),
        }

    def get_anomalous_ips(self, threshold_pps: float = 100.0,
                          window_seconds: float = 60.0) -> List[Dict[str, Any]]:
        """Find IPs with anomalous packet rates in working memory."""
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            recent = [p for p in self._packets if p.timestamp >= cutoff]

        if not recent:
            return []

        # Group by source IP
        ip_packets: Dict[str, List[PacketSnapshot]] = defaultdict(list)
        for p in recent:
            ip_packets[p.src_ip].append(p)

        anomalous = []
        for ip, pkts in ip_packets.items():
            if len(pkts) < 5:
                continue
            time_span = max(pkts[-1].timestamp - pkts[0].timestamp, 0.001)
            pps = len(pkts) / time_span
            if pps > threshold_pps:
                anomalous.append({
                    'ip': ip,
                    'packets': len(pkts),
                    'pps': round(pps, 1),
                    'bytes': sum(p.bytes_len for p in pkts),
                    'intents': dict(Counter(p.intent_class for p in pkts)),
                })

        return sorted(anomalous, key=lambda x: x['pps'], reverse=True)

    # ------------------------------------------------------------------
    # Garbage Collection
    # ------------------------------------------------------------------

    def _gc_loop(self) -> None:
        """Periodically remove expired packets from the window."""
        while self._running:
            try:
                self._gc_expired()
            except Exception as e:
                logger.error("SIEM GC error: %s", e)
            time.sleep(GC_INTERVAL_S)

    def _gc_expired(self) -> int:
        """Remove packets older than the window. Returns count removed."""
        cutoff = time.time() - self._window
        removed = 0

        with self._lock:
            while self._packets and self._packets[0].timestamp < cutoff:
                self._packets.popleft()
                removed += 1

        if removed > 0:
            # Rebuild counters from remaining packets
            self._rebuild_counters()
            logger.debug("SIEM GC: removed %d expired snapshots", removed)

        return removed

    def _rebuild_counters(self) -> None:
        """Rebuild fast counters from current window (after GC)."""
        with self._lock:
            packets = list(self._packets)

        self._src_counter = Counter(p.src_ip for p in packets)
        self._dst_counter = Counter(p.dst_ip for p in packets)
        self._proto_counter = Counter(p.proto for p in packets)
        self._intent_counter = Counter(p.intent_class for p in packets)
        self._action_counter = Counter(p.action for p in packets)
        self._unique_flows = set(
            f"{p.src_ip}:{p.src_port}-{p.dst_ip}:{p.dst_port}-{p.proto}"
            for p in packets
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background GC thread."""
        if self._running:
            return
        self._running = True
        self._gc_thread = threading.Thread(target=self._gc_loop, daemon=True,
                                           name="cno-siem-gc")
        self._gc_thread.start()
        logger.info("PacketSIEM started")

    def stop(self) -> None:
        """Stop the GC thread."""
        self._running = False
        if self._gc_thread:
            self._gc_thread.join(timeout=10)
        logger.info("PacketSIEM stopped")

    def get_stats(self) -> Dict[str, Any]:
        """Return SIEM statistics."""
        return {
            'window_seconds': self._window,
            'current_snapshots': len(self._packets),
            'max_snapshots': self._max,
            'total_ingested': self._total_ingested,
            'total_bytes': self._total_bytes,
            'unique_sources': len(self._src_counter),
            'unique_destinations': len(self._dst_counter),
            'unique_flows': len(self._unique_flows),
            'running': self._running,
        }
