"""
Mirage Orchestrator — Active Deception Controller

Subscribes to NAPSE EventBus (ALERT, CONNECTION, FLOW_METADATA) and
auto-deploys honeypots when scan patterns are detected. Manages the
escalation state machine per attacker IP.

State Machine:
    DORMANT → DETECTING → ENGAGING → PROFILING → LEARNING
      ↑                                            │
      └────────────── (timeout / reset) ───────────┘

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class MirageState(Enum):
    """Per-attacker escalation state."""
    DORMANT = auto()
    DETECTING = auto()
    ENGAGING = auto()
    PROFILING = auto()
    LEARNING = auto()


@dataclass
class ScanTracker:
    """Tracks scan activity for a single source IP."""
    source_ip: str
    state: MirageState = MirageState.DORMANT
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    dark_port_hits: List[Dict[str, Any]] = field(default_factory=list)
    ports_probed: Set[int] = field(default_factory=set)
    connection_count: int = 0
    alert_count: int = 0
    state_entered_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def dark_port_count(self) -> int:
        return len(self.dark_port_hits)

    @property
    def is_active(self) -> bool:
        """Active if seen in the last 5 minutes."""
        return (datetime.utcnow() - self.last_seen) < timedelta(minutes=5)

    def add_port_hit(self, port: int, proto: str = "tcp") -> None:
        self.ports_probed.add(port)
        self.dark_port_hits.append({
            "port": port,
            "proto": proto,
            "ts": datetime.utcnow().isoformat(),
        })
        self.last_seen = datetime.utcnow()

    def transition(self, new_state: MirageState) -> None:
        old = self.state
        self.state = new_state
        self.state_entered_at = datetime.utcnow()
        logger.info(
            "Mirage %s: %s → %s (ports=%d, alerts=%d)",
            self.source_ip, old.name, new_state.name,
            len(self.ports_probed), self.alert_count,
        )


# Default dark ports — connections to these are suspicious
DARK_PORTS: Set[int] = {
    21, 22, 23, 25, 110, 135, 139, 445, 1433, 1434,
    1521, 2222, 3306, 3389, 4444, 5432, 5900, 5985,
    6379, 8080, 8443, 9100, 9200, 27017,
}

# Scan detection threshold: N dark port hits in WINDOW_SECONDS
SCAN_THRESHOLD = 3
SCAN_WINDOW_SECONDS = 30

# State timeouts
ENGAGING_TIMEOUT_S = 300   # 5 min
PROFILING_TIMEOUT_S = 600  # 10 min
LEARNING_TIMEOUT_S = 3600  # 1 hour


class MirageOrchestrator:
    """
    Central deception controller.

    Subscribes to NAPSE EventBus events and manages per-attacker
    escalation through the state machine. Coordinates with:
    - AdaptiveHoneypot for interaction
    - IntelligenceFeedback for TTP extraction
    - MirageBridge for AEGIS signal emission
    """

    def __init__(
        self,
        dark_ports: Optional[Set[int]] = None,
        scan_threshold: int = SCAN_THRESHOLD,
        scan_window_seconds: int = SCAN_WINDOW_SECONDS,
    ):
        self._dark_ports = dark_ports or DARK_PORTS
        self._scan_threshold = scan_threshold
        self._scan_window = scan_window_seconds
        self._trackers: Dict[str, ScanTracker] = {}
        self._lock = threading.Lock()
        self._callbacks: Dict[str, List[Callable]] = defaultdict(list)
        self._running = False

        # Stats
        self._stats = {
            "events_processed": 0,
            "scans_detected": 0,
            "honeypots_deployed": 0,
            "attackers_profiled": 0,
        }

        logger.info(
            "MirageOrchestrator initialized (dark_ports=%d, threshold=%d/%ds)",
            len(self._dark_ports), scan_threshold, scan_window_seconds,
        )

    # ------------------------------------------------------------------
    # EventBus Integration
    # ------------------------------------------------------------------

    def register_with_event_bus(self, event_bus) -> None:
        """Subscribe to relevant NAPSE EventBus events."""
        from core.napse.synthesis.event_bus import EventType

        event_bus.subscribe(EventType.ALERT, self._on_alert)
        event_bus.subscribe(EventType.CONNECTION, self._on_connection)
        event_bus.subscribe(EventType.FLOW_METADATA, self._on_flow_metadata)
        if hasattr(EventType, "HONEYPOT_TOUCH"):
            event_bus.subscribe(EventType.HONEYPOT_TOUCH, self._on_honeypot_touch)
        logger.info("MirageOrchestrator registered with NAPSE EventBus")

    def _on_alert(self, event_type, alert) -> None:
        """Handle NAPSE alert events."""
        self._stats["events_processed"] += 1
        src_ip = getattr(alert, "src_ip", "") or alert.get("src_ip", "") if isinstance(alert, dict) else getattr(alert, "src_ip", "")
        if not src_ip:
            return

        with self._lock:
            tracker = self._get_or_create(src_ip)
            tracker.alert_count += 1
            tracker.last_seen = datetime.utcnow()

            # Alerts from known scanners escalate immediately
            if tracker.state == MirageState.DETECTING:
                self._transition_to_engaging(tracker)
            elif tracker.state == MirageState.DORMANT:
                self._check_scan_detection(tracker)

    def _on_connection(self, event_type, conn) -> None:
        """Handle connection records — detect dark port touches."""
        self._stats["events_processed"] += 1
        dest_port = getattr(conn, "id_resp_p", 0)
        src_ip = getattr(conn, "id_orig_h", "")
        proto = getattr(conn, "proto", "tcp")

        if not src_ip or dest_port not in self._dark_ports:
            return

        with self._lock:
            tracker = self._get_or_create(src_ip)
            tracker.add_port_hit(dest_port, proto)
            tracker.connection_count += 1
            self._check_scan_detection(tracker)

    def _on_flow_metadata(self, event_type, metadata) -> None:
        """Handle lightweight flow metadata from eBPF."""
        self._stats["events_processed"] += 1
        if not isinstance(metadata, dict):
            return

        dest_port = metadata.get("dest_port", 0)
        src_ip = metadata.get("src_ip", "")
        if not src_ip or dest_port not in self._dark_ports:
            return

        with self._lock:
            tracker = self._get_or_create(src_ip)
            tracker.add_port_hit(dest_port, metadata.get("proto", "tcp"))
            self._check_scan_detection(tracker)

    def _on_honeypot_touch(self, event_type, touch) -> None:
        """Handle honeypot touch events (from HoneypotMesh)."""
        self._stats["events_processed"] += 1
        src_ip = getattr(touch, "source_ip", "") if hasattr(touch, "source_ip") else touch.get("source_ip", "")
        if not src_ip:
            return

        with self._lock:
            tracker = self._get_or_create(src_ip)
            dest_port = getattr(touch, "dest_port", 0) if hasattr(touch, "dest_port") else touch.get("dest_port", 0)
            if dest_port:
                tracker.add_port_hit(dest_port)

            # Honeypot interaction → escalate to ENGAGING
            if tracker.state in (MirageState.DORMANT, MirageState.DETECTING):
                self._transition_to_engaging(tracker)

    # ------------------------------------------------------------------
    # State Machine
    # ------------------------------------------------------------------

    def _check_scan_detection(self, tracker: ScanTracker) -> None:
        """Check if scan threshold is reached within the time window."""
        if tracker.state not in (MirageState.DORMANT, MirageState.DETECTING):
            return

        # Count recent dark port hits within scan window
        cutoff = datetime.utcnow() - timedelta(seconds=self._scan_window)
        recent_hits = [
            h for h in tracker.dark_port_hits
            if datetime.fromisoformat(h["ts"]) > cutoff
        ]

        if len(recent_hits) >= self._scan_threshold:
            if tracker.state == MirageState.DORMANT:
                tracker.transition(MirageState.DETECTING)
                self._stats["scans_detected"] += 1
                self._emit("scan_detected", tracker)

            # Enough evidence — engage
            self._transition_to_engaging(tracker)
        elif tracker.state == MirageState.DORMANT and len(recent_hits) >= 1:
            tracker.transition(MirageState.DETECTING)
            self._emit("scan_detected", tracker)
            self._stats["scans_detected"] += 1

    def _transition_to_engaging(self, tracker: ScanTracker) -> None:
        """Deploy honeypot and begin active engagement."""
        if tracker.state == MirageState.ENGAGING:
            return

        tracker.transition(MirageState.ENGAGING)
        self._stats["honeypots_deployed"] += 1
        self._emit("honeypot_deployed", tracker)

    def transition_to_profiling(self, source_ip: str) -> bool:
        """Move an attacker to PROFILING state (called by AdaptiveHoneypot)."""
        with self._lock:
            tracker = self._trackers.get(source_ip)
            if not tracker or tracker.state != MirageState.ENGAGING:
                return False
            tracker.transition(MirageState.PROFILING)
            self._stats["attackers_profiled"] += 1
            self._emit("attacker_profiled", tracker)
            return True

    def transition_to_learning(self, source_ip: str) -> bool:
        """Move an attacker to LEARNING state (called by IntelligenceFeedback)."""
        with self._lock:
            tracker = self._trackers.get(source_ip)
            if not tracker or tracker.state != MirageState.PROFILING:
                return False
            tracker.transition(MirageState.LEARNING)
            self._emit("attacker_learning", tracker)
            return True

    def reset_tracker(self, source_ip: str) -> bool:
        """Reset an attacker tracker to DORMANT."""
        with self._lock:
            tracker = self._trackers.get(source_ip)
            if not tracker:
                return False
            tracker.transition(MirageState.DORMANT)
            return True

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def cleanup_stale(self, max_age_minutes: int = 60) -> int:
        """Remove stale trackers that haven't been seen recently."""
        cutoff = datetime.utcnow() - timedelta(minutes=max_age_minutes)
        removed = 0
        with self._lock:
            stale_ips = [
                ip for ip, t in self._trackers.items()
                if t.last_seen < cutoff and t.state in (MirageState.DORMANT, MirageState.LEARNING)
            ]
            for ip in stale_ips:
                del self._trackers[ip]
                removed += 1
        if removed:
            logger.info("Mirage cleanup: removed %d stale trackers", removed)
        return removed

    # ------------------------------------------------------------------
    # Callbacks and Queries
    # ------------------------------------------------------------------

    def on(self, event: str, callback: Callable) -> None:
        """Register a callback for mirage events.

        Events: scan_detected, honeypot_deployed, attacker_profiled,
                attacker_learning
        """
        self._callbacks[event].append(callback)

    def _emit(self, event: str, tracker: ScanTracker) -> None:
        """Fire callbacks for an event."""
        for cb in self._callbacks.get(event, []):
            try:
                cb(event, tracker)
            except Exception as e:
                logger.error("Mirage callback error [%s]: %s", event, e)

    def get_tracker(self, source_ip: str) -> Optional[ScanTracker]:
        """Get the tracker for a source IP."""
        with self._lock:
            return self._trackers.get(source_ip)

    def get_active_trackers(self) -> List[ScanTracker]:
        """Get all trackers in an active state (not DORMANT)."""
        with self._lock:
            return [
                t for t in self._trackers.values()
                if t.state != MirageState.DORMANT
            ]

    def get_engaging_ips(self) -> List[str]:
        """Get IPs currently being engaged by honeypots."""
        with self._lock:
            return [
                ip for ip, t in self._trackers.items()
                if t.state in (MirageState.ENGAGING, MirageState.PROFILING)
            ]

    def get_stats(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        with self._lock:
            state_counts = defaultdict(int)
            for t in self._trackers.values():
                state_counts[t.state.name] += 1

        return {
            **self._stats,
            "active_trackers": len(self._trackers),
            "state_distribution": dict(state_counts),
            "dark_ports_monitored": len(self._dark_ports),
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _get_or_create(self, source_ip: str) -> ScanTracker:
        """Get or create a tracker for a source IP (caller must hold lock)."""
        if source_ip not in self._trackers:
            self._trackers[source_ip] = ScanTracker(source_ip=source_ip)
        return self._trackers[source_ip]
