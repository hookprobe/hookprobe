"""
NAPSE Prometheus Metrics

Exposes NAPSE engine statistics as Prometheus-compatible metrics
for monitoring via Grafana/VictoriaMetrics.

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import time
from typing import Any, Dict, Optional

from .event_bus import EventType, NapseEventBus

logger = logging.getLogger(__name__)


class NapseMetrics:
    """
    Collects and exposes NAPSE engine metrics.

    Metrics exposed:
      napse_events_total{type}      - Total events by type
      napse_alerts_total{severity}  - Total alerts by severity
      napse_connections_active      - Currently tracked connections
      napse_engine_uptime_seconds   - Engine uptime
      napse_packets_total           - Total packets processed (from eBPF)
      napse_packets_dropped_total   - Packets dropped (blocked/rate-limited)
      napse_signature_matches_total - Pattern matcher hits
      napse_ml_inferences_total     - ML model inference count
    """

    def __init__(self):
        self._start_time = time.time()
        self._event_counts: Dict[str, int] = {}
        self._alert_severity_counts: Dict[int, int] = {
            1: 0, 2: 0, 3: 0, 4: 0, 5: 0
        }
        self._active_connections = 0
        self._packets_total = 0
        self._packets_dropped = 0
        self._signature_matches = 0
        self._ml_inferences = 0

    def register(self, event_bus: NapseEventBus) -> None:
        """Register with event bus to track all events."""
        event_bus.subscribe_all(self._count_event)
        logger.info("NapseMetrics registered with event bus")

    def _count_event(self, event_type: EventType, event: Any) -> None:
        """Count events by type."""
        key = event_type.name.lower()
        self._event_counts[key] = self._event_counts.get(key, 0) + 1

        if event_type == EventType.ALERT and hasattr(event, 'alert_severity'):
            sev = event.alert_severity
            self._alert_severity_counts[sev] = self._alert_severity_counts.get(sev, 0) + 1

    def update_ebpf_stats(self, packets_total: int, packets_dropped: int) -> None:
        """Update stats from eBPF kernel layer."""
        self._packets_total = packets_total
        self._packets_dropped = packets_dropped

    def update_engine_stats(
        self,
        active_connections: int = 0,
        signature_matches: int = 0,
        ml_inferences: int = 0,
    ) -> None:
        """Update stats from Rust protocol engine."""
        self._active_connections = active_connections
        self._signature_matches = signature_matches
        self._ml_inferences = ml_inferences

    def to_prometheus(self) -> str:
        """Export metrics in Prometheus text format."""
        lines = []
        lines.append("# HELP napse_engine_uptime_seconds NAPSE engine uptime")
        lines.append("# TYPE napse_engine_uptime_seconds gauge")
        lines.append(f"napse_engine_uptime_seconds {time.time() - self._start_time:.1f}")

        lines.append("# HELP napse_events_total Total NAPSE events by type")
        lines.append("# TYPE napse_events_total counter")
        for etype, count in sorted(self._event_counts.items()):
            lines.append(f'napse_events_total{{type="{etype}"}} {count}')

        lines.append("# HELP napse_alerts_total Total alerts by severity")
        lines.append("# TYPE napse_alerts_total counter")
        sev_names = {1: 'critical', 2: 'high', 3: 'medium', 4: 'low', 5: 'info'}
        for sev, count in sorted(self._alert_severity_counts.items()):
            name = sev_names.get(sev, f'sev{sev}')
            lines.append(f'napse_alerts_total{{severity="{name}"}} {count}')

        lines.append("# HELP napse_connections_active Active tracked connections")
        lines.append("# TYPE napse_connections_active gauge")
        lines.append(f"napse_connections_active {self._active_connections}")

        lines.append("# HELP napse_packets_total Total packets processed by eBPF")
        lines.append("# TYPE napse_packets_total counter")
        lines.append(f"napse_packets_total {self._packets_total}")

        lines.append("# HELP napse_packets_dropped_total Packets dropped by eBPF")
        lines.append("# TYPE napse_packets_dropped_total counter")
        lines.append(f"napse_packets_dropped_total {self._packets_dropped}")

        lines.append("# HELP napse_signature_matches_total Signature matcher hits")
        lines.append("# TYPE napse_signature_matches_total counter")
        lines.append(f"napse_signature_matches_total {self._signature_matches}")

        lines.append("# HELP napse_ml_inferences_total ML model inference count")
        lines.append("# TYPE napse_ml_inferences_total counter")
        lines.append(f"napse_ml_inferences_total {self._ml_inferences}")

        return '\n'.join(lines) + '\n'

    def get_stats(self) -> Dict[str, Any]:
        """Get metrics as dictionary."""
        return {
            'uptime_seconds': time.time() - self._start_time,
            'event_counts': dict(self._event_counts),
            'alert_severity_counts': dict(self._alert_severity_counts),
            'active_connections': self._active_connections,
            'packets_total': self._packets_total,
            'packets_dropped': self._packets_dropped,
            'signature_matches': self._signature_matches,
            'ml_inferences': self._ml_inferences,
        }
