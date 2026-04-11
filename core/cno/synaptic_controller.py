"""
Synaptic Controller — The Thalamus

The ONLY component that spans all three biological layers.
Routes events from Cerebellum to the correct Cerebrum processing region,
and feedback from Cerebrum back to Brainstem BPF maps.

Upward routing (Cerebellum → Cerebrum):
    - High risk velocity → Cognitive Defense (frontal lobe)
    - Novel/unknown patterns → Multi-RAG Consensus
    - App deviations → Session Analyzer (Wernicke's area)
    - Temporal drift → Temporal Memory
    - Kill chain advancement → Entity Graph (SIA engine)

Downward routing (Cerebrum → Brainstem):
    - BLOCK action → XDP blocklist map
    - ALLOW action → XDP allowlist map
    - CAMOUFLAGE → camo_config BPF map
    - STRESS_UPDATE → stress_level BPF map
    - RETRAIN → model weight updates

Integration:
    - Reads from: NAPSE EventBus, HYDRA verdicts, AEGIS signals
    - Writes to: BPF maps (via bpf_map_ops), ClickHouse (audit log)
    - Coordinates: StressGauge, PacketSIEM, CognitiveDefense

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import ipaddress
import logging
import os
import re
import socket
import struct
import threading
import time
from collections import deque
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.request import Request, urlopen

from .types import (
    BPFMapWrite,
    BrainLayer,
    EmotionState,
    PacketSnapshot,
    StressSignal,
    StressState,
    SynapticEvent,
    SynapticRoute,
)

logger = logging.getLogger(__name__)

# =============================================================================
# Thalamus Priority Tiers (Phase 2-U C2)
# =============================================================================
# The SynapticController is the thalamus. To formalize the v1.3 "priority =
# biology" principle, every event is classified into one of three tiers:
#
#   TIER_AUTONOMIC (P0) — reflex/wire-speed. XDP writes, stress commits.
#                         Cannot be blocked by ANY other tier.
#   TIER_SOMATIC  (P1) — coordination/working memory. Cerebellum signals.
#                         Cannot be blocked by cognitive tier.
#   TIER_COGNITIVE (P2) — reasoning/content. Multi-RAG consensus, SEO work.
#                         Bounded queue share; P2 flood cannot displace P0/P1.
#
# Priority classification:
#   int priority 0-3  → TIER_AUTONOMIC
#   int priority 4-6  → TIER_SOMATIC
#   int priority 7+   → TIER_COGNITIVE
#
# Backpressure caps (tier-weighted queue admission):
#   P0 always admitted up to MAX_QUEUE_SIZE
#   P1 admitted up to 70% of MAX_QUEUE_SIZE
#   P2 admitted up to 40% of MAX_QUEUE_SIZE
#
# This guarantees that a P2 flood (e.g. SEO embedding burst) can never fill
# the queue to the point of dropping incoming P0 (XDP commit) events.
# =============================================================================

TIER_AUTONOMIC = 'autonomic'
TIER_SOMATIC = 'somatic'
TIER_COGNITIVE = 'cognitive'

TIER_ADMIT_FRACTION: Dict[str, float] = {
    TIER_AUTONOMIC: 1.00,
    TIER_SOMATIC: 0.70,
    TIER_COGNITIVE: 0.40,
}


def classify_tier(priority: int) -> str:
    """Map integer priority to a thalamus tier."""
    if priority <= 3:
        return TIER_AUTONOMIC
    if priority <= 6:
        return TIER_SOMATIC
    return TIER_COGNITIVE

# BPF map operations — import from HYDRA's bpf_map_ops.py
_BPF_AVAILABLE = False
_bpf_ops = None
try:
    import sys as _sys
    _hydra_path = os.environ.get('HYDRA_PATH', '/home/ubuntu/hookprobe/core/hydra')
    if _hydra_path not in _sys.path:
        _sys.path.insert(0, _hydra_path)
    from bpf_map_ops import BPFMapOps as _BPFMapOps
    _bpf_ops = _BPFMapOps()
    _BPF_AVAILABLE = True
    logger.info("BPF map ops loaded from %s", _hydra_path)
except ImportError:
    logger.info("BPF map ops unavailable — BPF writes will be logged only")
except Exception as _e:
    logger.warning("BPF map ops init failed: %s — writes will be logged only", _e)

# IPv4 validation
_IPV4_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)

# ClickHouse config
CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

# Validate CH_DB is a safe identifier
if not re.match(r'^[A-Za-z0-9_]+$', CH_DB):
    raise ValueError(f"Unsafe CLICKHOUSE_DB value: {CH_DB!r}")

# Private/reserved IP ranges — never block these
_RESERVED_NETS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
]


def _is_reserved(ip_str: str) -> bool:
    """Check if IP is private/reserved (never block)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _RESERVED_NETS)
    except ValueError:
        return True  # Invalid IP = treat as reserved (don't block)


class SynapticController:
    """The thalamus — central relay between all three brain layers.

    Thread-safe event queue with priority-based dispatching.
    Routes upward (sensory → cognition) and downward (decision → reflex).
    """

    MAX_QUEUE_SIZE = 10_000
    DISPATCH_INTERVAL_S = 0.1          # 100ms dispatch cycle
    BPF_BATCH_INTERVAL_S = 1.0         # Batch BPF writes every 1s
    AUDIT_FLUSH_INTERVAL_S = 30.0      # Flush audit log every 30s
    MAX_BPF_WRITES_PER_BATCH = 50      # Rate limit BPF operations

    def __init__(self):
        # Event queue (priority-sorted: lower number = higher priority)
        self._queue: deque = deque(maxlen=self.MAX_QUEUE_SIZE)
        self._lock = threading.Lock()

        # Upward route handlers: SynapticRoute → callback(SynapticEvent)
        self._upward_handlers: Dict[SynapticRoute, Callable] = {}
        # Downward BPF write queue
        self._bpf_queue: deque = deque(maxlen=1000)
        self._bpf_lock = threading.Lock()

        # Audit buffer for ClickHouse
        self._audit_buffer: List[Dict[str, Any]] = []
        self._audit_lock = threading.Lock()

        # Stats
        self._stats = {
            'events_received': 0,
            'events_dispatched': 0,
            'events_dropped': 0,
            'bpf_writes': 0,
            'bpf_errors': 0,
            'upward_routes': 0,
            'downward_routes': 0,
        }

        # Phase 2-U C2: per-tier metrics (autonomic/somatic/cognitive)
        self._tier_stats: Dict[str, Dict[str, int]] = {
            TIER_AUTONOMIC: {'received': 0, 'dispatched': 0, 'dropped': 0},
            TIER_SOMATIC:   {'received': 0, 'dispatched': 0, 'dropped': 0},
            TIER_COGNITIVE: {'received': 0, 'dispatched': 0, 'dropped': 0},
        }
        # Rolling queue depth by tier (updated on submit/dispatch for
        # backpressure calculation — separate from the single _queue deque)
        self._tier_queue_depth: Dict[str, int] = {
            TIER_AUTONOMIC: 0,
            TIER_SOMATIC: 0,
            TIER_COGNITIVE: 0,
        }

        self._running = False
        self._threads: List[threading.Thread] = []

        logger.info("SynapticController initialized with tier backpressure")

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_handler(self, route: SynapticRoute,
                         handler: Callable[[SynapticEvent], None]) -> None:
        """Register a handler for a specific route.

        The handler will be called when events are dispatched to this route.
        """
        self._upward_handlers[route] = handler
        logger.info("Handler registered for route: %s", route.value)

    # ------------------------------------------------------------------
    # Event Submission
    # ------------------------------------------------------------------

    def submit(self, event: SynapticEvent) -> bool:
        """Submit an event to the synaptic queue.

        Thread-safe. Returns False if the tier-weighted admission cap rejects
        the event. P0 events are always admitted (up to MAX_QUEUE_SIZE). P1
        is capped at 70% of MAX_QUEUE_SIZE. P2 is capped at 40%.

        This guarantees that a P2 flood can never starve P0 events.
        """
        tier = classify_tier(event.priority)
        admit_cap = int(self.MAX_QUEUE_SIZE * TIER_ADMIT_FRACTION[tier])

        with self._lock:
            total_depth = len(self._queue)
            tier_depth = self._tier_queue_depth[tier]

            # Hard cap: if total queue is full, drop (even P0 can't escape this)
            if total_depth >= self.MAX_QUEUE_SIZE:
                self._stats['events_dropped'] += 1
                self._tier_stats[tier]['dropped'] += 1
                return False

            # Tier-weighted backpressure: P1/P2 rejected when their share
            # of the queue would exceed their admission cap. P0 skips this
            # check (always accepted up to the hard cap above).
            if tier != TIER_AUTONOMIC and tier_depth >= admit_cap:
                self._stats['events_dropped'] += 1
                self._tier_stats[tier]['dropped'] += 1
                return False

            self._queue.append(event)
            self._stats['events_received'] += 1
            self._tier_stats[tier]['received'] += 1
            self._tier_queue_depth[tier] += 1
        return True

    def submit_upward(self, source_layer: BrainLayer, route: SynapticRoute,
                      event_type: str, priority: int = 5,
                      source_ip: str = "", dest_ip: str = "",
                      payload: Optional[Dict[str, Any]] = None) -> bool:
        """Convenience: create and submit an upward-bound event."""
        event = SynapticEvent(
            source_layer=source_layer,
            route=route,
            priority=priority,
            event_type=event_type,
            source_ip=source_ip,
            dest_ip=dest_ip,
            payload=payload or {},
        )
        return self.submit(event)

    def submit_downward(self, route: SynapticRoute, source_ip: str,
                        action: str, ttl_seconds: int = 3600,
                        reason: str = "", priority: int = 3,
                        payload: Optional[Dict[str, Any]] = None) -> bool:
        """Convenience: submit a downward (Cerebrum → Brainstem) event."""
        event = SynapticEvent(
            source_layer=BrainLayer.CEREBRUM,
            route=route,
            priority=priority,
            event_type=f"feedback.{action}",
            source_ip=source_ip,
            payload={
                'action': action,
                'ttl_seconds': ttl_seconds,
                'reason': reason,
                **(payload or {}),
            },
        )
        return self.submit(event)

    # ------------------------------------------------------------------
    # BPF Map Operations (Brainstem feedback)
    # ------------------------------------------------------------------

    def queue_bpf_write(self, write: BPFMapWrite) -> None:
        """Queue a BPF map write for batched execution."""
        with self._bpf_lock:
            self._bpf_queue.append(write)

    def push_to_blocklist(self, ip: str, ttl_seconds: int = 3600,
                          reason: str = "") -> bool:
        """Queue an IP for XDP blocklist insertion.

        Validates the IP and rejects private/reserved addresses.
        """
        if not _IPV4_RE.match(ip):
            logger.warning("Invalid IP for blocklist: %r", ip)
            return False

        if _is_reserved(ip):
            logger.warning("Refusing to block reserved IP: %s", ip)
            return False

        # Pack for LPM_TRIE: prefixlen (u32 LE) + addr (network byte order)
        try:
            key = struct.pack('<I', 32) + socket.inet_aton(ip)
            value = struct.pack('<I', 1)  # 1 = blocked
        except (ValueError, struct.error) as e:
            logger.error("Failed to pack IP %s: %s", ip, e)
            return False

        self.queue_bpf_write(BPFMapWrite(
            map_name='blocklist',
            key=key,
            value=value,
            ttl_seconds=ttl_seconds,
            reason=reason,
        ))
        return True

    def update_stress_level(self, state: StressState) -> None:
        """Push stress state to the BPF stress_level map.

        Map layout: ARRAY[0] = stress_level (u8)
        0=CALM, 1=ALERT, 2=FIGHT, 3=RECOVERY
        """
        state_map = {
            StressState.CALM: 0,
            StressState.ALERT: 1,
            StressState.FIGHT: 2,
            StressState.RECOVERY: 3,
        }
        key = struct.pack('<I', 0)
        value = struct.pack('<B', state_map.get(state, 0))

        self.queue_bpf_write(BPFMapWrite(
            map_name='stress_level',
            key=key,
            value=value,
            reason=f'stress_state={state.value}',
        ))

    def _flush_bpf_writes(self) -> int:
        """Execute pending BPF map writes.

        Uses bpf_map_ops.py for raw syscall access (no bpftool dependency).
        Returns number of successful writes.
        """
        with self._bpf_lock:
            if not self._bpf_queue:
                return 0
            batch = []
            for _ in range(min(len(self._bpf_queue), self.MAX_BPF_WRITES_PER_BATCH)):
                batch.append(self._bpf_queue.popleft())

        success = 0
        for write in batch:
            try:
                ok = self._execute_bpf_write(write)
                if ok:
                    self._stats['bpf_writes'] += 1
                    success += 1
                else:
                    self._stats['bpf_errors'] += 1

                self._audit(
                    event_type='bpf_write',
                    details={
                        'map_name': write.map_name,
                        'operation': write.operation,
                        'reason': write.reason,
                        'ttl_seconds': write.ttl_seconds,
                        'success': ok,
                    },
                )

            except Exception as e:
                logger.error("BPF write failed for map %s: %s", write.map_name, e)
                self._stats['bpf_errors'] += 1

        return success

    def _execute_bpf_write(self, write: BPFMapWrite) -> bool:
        """Execute a single BPF map write via bpf_map_ops or log-only fallback."""
        if _BPF_AVAILABLE and _bpf_ops:
            try:
                if write.map_name in ('blocklist', 'allowlist'):
                    # LPM_TRIE update via bpf_map_ops
                    ok = _bpf_ops.map_update_by_name(
                        write.map_name, write.key, write.value
                    )
                    return ok
                elif write.map_name in ('stress_level', 'camo_config'):
                    # ARRAY map update
                    ok = _bpf_ops.map_update_by_name(
                        write.map_name, write.key, write.value
                    )
                    return ok
                else:
                    logger.debug("Unknown BPF map: %s", write.map_name)
                    return False
            except Exception as e:
                logger.error("BPF ops error for %s: %s", write.map_name, e)
                return False
        else:
            # Fallback: log-only mode (BPF ops unavailable)
            logger.debug(
                "BPF write (log-only): map=%s op=%s reason=%s",
                write.map_name, write.operation, write.reason,
            )
            return True  # Count as success for stats in dev mode

    # ------------------------------------------------------------------
    # Upward Routing (Sensory → Cognition)
    # ------------------------------------------------------------------

    def route_upward(self, event: SynapticEvent) -> bool:
        """Route an event to its registered Cerebrum handler."""
        handler = self._upward_handlers.get(event.route)
        if not handler:
            logger.debug("No handler for route %s, event dropped", event.route.value)
            return False

        start = time.monotonic()
        try:
            handler(event)
            elapsed_us = int((time.monotonic() - start) * 1_000_000)
            event.processed = True
            event.processing_time_us = elapsed_us
            self._stats['upward_routes'] += 1

            self._audit(
                event_type='upward_route',
                details={
                    'route': event.route.value,
                    'source_layer': event.source_layer.value,
                    'event_type': event.event_type,
                    'source_ip': event.source_ip,
                    'processing_us': elapsed_us,
                },
            )
            return True

        except Exception as e:
            logger.error("Handler %s failed: %s", event.route.value, e)
            return False

    # ------------------------------------------------------------------
    # Downward Routing (Cognition → Reflex)
    # ------------------------------------------------------------------

    def route_downward(self, event: SynapticEvent) -> bool:
        """Route a Cerebrum decision to the Brainstem for execution."""
        action = event.payload.get('action', '')
        ip = event.source_ip
        ttl = event.payload.get('ttl_seconds', 3600)
        reason = event.payload.get('reason', event.event_type)

        routed = False

        if event.route == SynapticRoute.XDP_BLOCKLIST:
            routed = self.push_to_blocklist(ip, ttl, reason)
            if routed:
                logger.info("BLOCK %s for %ds: %s", ip, ttl, reason)

        elif event.route == SynapticRoute.XDP_ALLOWLIST:
            if _IPV4_RE.match(ip):
                key = struct.pack('<I', 32) + socket.inet_aton(ip)
                value = struct.pack('<I', 1)
                self.queue_bpf_write(BPFMapWrite(
                    map_name='allowlist', key=key, value=value,
                    reason=reason,
                ))
                routed = True

        elif event.route == SynapticRoute.XDP_FLOW_CTRL:
            stress = event.payload.get('stress_state')
            if stress and isinstance(stress, StressState):
                self.update_stress_level(stress)
                routed = True

        elif event.route == SynapticRoute.XDP_CAMOUFLAGE:
            # Future Phase 2: push to camo_config BPF map
            logger.debug("Camouflage request queued (Phase 2): %s", event.payload)
            routed = True

        elif event.route == SynapticRoute.BASELINE_UPDATE:
            # Cerebellum feedback — update Welford profile
            logger.debug("Baseline update for %s (delegated)", ip)
            routed = True

        elif event.route == SynapticRoute.SCRIBE:
            # Content generation pipeline
            logger.debug("SCRIBE content request: %s", event.event_type)
            routed = True

        if routed:
            self._stats['downward_routes'] += 1
            self._audit(
                event_type='downward_route',
                details={
                    'route': event.route.value,
                    'action': action,
                    'source_ip': ip,
                    'ttl_seconds': ttl,
                    'reason': reason,
                },
            )

        return routed

    # ------------------------------------------------------------------
    # Main Dispatch Loop
    # ------------------------------------------------------------------

    def _dispatch_loop(self) -> None:
        """Main event dispatch loop (runs in dedicated thread)."""
        logger.info("Synaptic dispatch loop started")
        last_bpf_flush = time.monotonic()
        last_audit_flush = time.monotonic()

        while self._running:
            # Drain queue — process up to 100 events per cycle
            events: List[SynapticEvent] = []
            with self._lock:
                for _ in range(min(len(self._queue), 100)):
                    events.append(self._queue.popleft())

            # Sort by priority (lower = higher priority)
            events.sort(key=lambda e: e.priority)

            for event in events:
                tier = classify_tier(event.priority)
                try:
                    # Determine direction based on route
                    if event.route in (
                        SynapticRoute.XDP_BLOCKLIST,
                        SynapticRoute.XDP_ALLOWLIST,
                        SynapticRoute.XDP_CAMOUFLAGE,
                        SynapticRoute.XDP_FLOW_CTRL,
                        SynapticRoute.BASELINE_UPDATE,
                        SynapticRoute.SCRIBE,
                    ):
                        self.route_downward(event)
                    else:
                        self.route_upward(event)

                    self._stats['events_dispatched'] += 1
                    self._tier_stats[tier]['dispatched'] += 1

                except Exception as e:
                    logger.error("Dispatch error for %s: %s", event, e)
                finally:
                    # Decrement tier depth regardless of success so the
                    # backpressure counter stays in sync with the real queue
                    with self._lock:
                        if self._tier_queue_depth[tier] > 0:
                            self._tier_queue_depth[tier] -= 1

            # Periodic BPF flush
            now = time.monotonic()
            if now - last_bpf_flush >= self.BPF_BATCH_INTERVAL_S:
                self._flush_bpf_writes()
                last_bpf_flush = now

            # Periodic audit flush
            if now - last_audit_flush >= self.AUDIT_FLUSH_INTERVAL_S:
                self._flush_audit()
                last_audit_flush = now

            # Sleep if no events (avoid busy-wait)
            if not events:
                time.sleep(self.DISPATCH_INTERVAL_S)

    # ------------------------------------------------------------------
    # Audit Trail (ClickHouse)
    # ------------------------------------------------------------------

    def _audit(self, event_type: str, details: Dict[str, Any]) -> None:
        """Buffer an audit entry for batch insert to ClickHouse."""
        entry = {
            'timestamp': time.time(),
            'event_type': event_type,
            **details,
        }
        with self._audit_lock:
            self._audit_buffer.append(entry)

    def _flush_audit(self) -> None:
        """Batch insert audit entries to cno_synaptic_log."""
        with self._audit_lock:
            if not self._audit_buffer:
                return
            batch = self._audit_buffer[:]
            self._audit_buffer.clear()

        if not batch:
            return

        try:
            import json as _json
            rows = []
            for entry in batch:
                ts = entry.get('timestamp', time.time())
                evt = entry.get('event_type', 'unknown')
                ts_ms = int(ts * 1000)
                rows.append(
                    f"(fromUnixTimestamp64Milli({ts_ms}), '{_ch_escape(evt)}', "
                    f"'{_ch_escape(entry.get('source_layer', ''))}', "
                    f"'{_ch_escape(entry.get('route', ''))}', "
                    f"'{_ch_escape(entry.get('source_ip', ''))}', "
                    f"'{_ch_escape(_json.dumps(entry))}')"
                )

            values = ','.join(rows)
            query = (
                f"INSERT INTO {CH_DB}.cno_synaptic_log "
                f"(timestamp, event_type, source_layer, route, source_ip, details) "
                f"VALUES {values}"
            )
            _ch_post(query)
            logger.debug("Flushed %d audit entries to ClickHouse", len(batch))

        except Exception as e:
            logger.error("Audit flush failed: %s", e)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the synaptic dispatch loop."""
        if self._running:
            return
        self._running = True
        t = threading.Thread(target=self._dispatch_loop, daemon=True,
                             name="cno-synaptic")
        t.start()
        self._threads.append(t)
        logger.info("SynapticController started")

    def stop(self) -> None:
        """Stop the dispatch loop and flush pending writes."""
        self._running = False
        for t in self._threads:
            t.join(timeout=5)
        self._flush_bpf_writes()
        self._flush_audit()
        logger.info("SynapticController stopped")

    def get_stats(self) -> Dict[str, Any]:
        """Return controller statistics including per-tier metrics."""
        return {
            **self._stats,
            'queue_depth': len(self._queue),
            'bpf_queue_depth': len(self._bpf_queue),
            'audit_buffer_depth': len(self._audit_buffer),
            'running': self._running,
            # Phase 2-U C2: tier-level thalamus metrics
            'thalamus': {
                'tiers': {
                    tier: {
                        **stats,
                        'queue_depth': self._tier_queue_depth[tier],
                        'admit_cap': int(self.MAX_QUEUE_SIZE * TIER_ADMIT_FRACTION[tier]),
                    }
                    for tier, stats in self._tier_stats.items()
                },
                'admit_fraction': TIER_ADMIT_FRACTION,
                'max_queue': self.MAX_QUEUE_SIZE,
            },
        }


# ------------------------------------------------------------------
# ClickHouse Helpers
# ------------------------------------------------------------------

def _ch_escape(s: str) -> str:
    """Escape string for ClickHouse SQL (handles injection vectors)."""
    if not s:
        return ''
    return (s.replace('\\', '\\\\').replace("'", "\\'")
             .replace('\n', '\\n').replace('\r', '\\r')
             .replace('\t', '\\t').replace('\0', ''))


def _ch_post(query: str) -> bool:
    """POST a query to ClickHouse HTTP interface."""
    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        data = query.encode('utf-8')
        req = Request(url, data=data)
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        req.add_header('X-ClickHouse-Database', CH_DB)
        with urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception as e:
        logger.debug("ClickHouse POST failed: %s", e)
        return False
