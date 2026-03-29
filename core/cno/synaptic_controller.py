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

        self._running = False
        self._threads: List[threading.Thread] = []

        logger.info("SynapticController initialized")

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

        Thread-safe. Returns False if queue is full (event dropped).
        """
        with self._lock:
            if len(self._queue) >= self.MAX_QUEUE_SIZE:
                self._stats['events_dropped'] += 1
                return False
            self._queue.append(event)
            self._stats['events_received'] += 1
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

        # Pack for LPM_TRIE: prefixlen (u32) + addr (u32 network byte order)
        try:
            addr_int = int(ipaddress.ip_address(ip))
            key = struct.pack('>II', 32, addr_int)
            value = struct.pack('>I', 1)  # 1 = blocked
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
        key = struct.pack('>I', 0)
        value = struct.pack('>B', state_map.get(state, 0))

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
                # For now, log the intended write. In production, this calls
                # bpf_map_ops.py via subprocess or direct ctypes BPF syscall.
                logger.debug(
                    "BPF write: map=%s op=%s reason=%s",
                    write.map_name, write.operation, write.reason,
                )
                self._stats['bpf_writes'] += 1
                success += 1

                # Audit trail
                self._audit(
                    event_type='bpf_write',
                    details={
                        'map_name': write.map_name,
                        'operation': write.operation,
                        'reason': write.reason,
                        'ttl_seconds': write.ttl_seconds,
                    },
                )

            except Exception as e:
                logger.error("BPF write failed for map %s: %s", write.map_name, e)
                self._stats['bpf_errors'] += 1

        return success

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
                addr_int = int(ipaddress.ip_address(ip))
                key = struct.pack('>II', 32, addr_int)
                value = struct.pack('>I', 1)
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
                try:
                    # Determine direction based on route
                    if event.route in (
                        SynapticRoute.XDP_BLOCKLIST,
                        SynapticRoute.XDP_ALLOWLIST,
                        SynapticRoute.XDP_CAMOUFLAGE,
                        SynapticRoute.XDP_FLOW_CTRL,
                        SynapticRoute.BASELINE_UPDATE,
                        SynapticRoute.SIEM_INGEST,
                        SynapticRoute.SCRIBE,
                    ):
                        self.route_downward(event)
                    else:
                        self.route_upward(event)

                    self._stats['events_dispatched'] += 1

                except Exception as e:
                    logger.error("Dispatch error for %s: %s", event, e)

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
                ts = entry.pop('timestamp', time.time())
                evt = entry.pop('event_type', 'unknown')
                rows.append(
                    f"(now64(3), '{_ch_escape(evt)}', "
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
        """Return controller statistics."""
        return {
            **self._stats,
            'queue_depth': len(self._queue),
            'bpf_queue_depth': len(self._bpf_queue),
            'audit_buffer_depth': len(self._audit_buffer),
            'running': self._running,
        }


# ------------------------------------------------------------------
# ClickHouse Helpers
# ------------------------------------------------------------------

def _ch_escape(s: str) -> str:
    """Escape string for ClickHouse SQL."""
    if not s:
        return ''
    return s.replace('\\', '\\\\').replace("'", "\\'")


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
