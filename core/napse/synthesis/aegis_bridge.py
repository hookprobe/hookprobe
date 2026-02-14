"""
NAPSE AEGIS Bridge

Emits StandardSignal objects to AEGIS for AI-driven threat analysis.
Follows the bridge pattern established by existing bridges in
core/aegis/bridges/ (qsecbit_bridge, dnsxai_bridge, etc.).

Routing key format: napse.{event_type} (e.g., napse.syn_flood,
napse.dns_tunneling, napse.new_device)

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from .event_bus import (
    NapseAlert, NapseNotice, EventType, NapseEventBus,
)

logger = logging.getLogger(__name__)


class NapseAegisBridge:
    """
    Bridge between NAPSE and AEGIS consciousness system.

    Converts NAPSE events into AEGIS StandardSignal format and routes
    them through the orchestrator for agent dispatch.
    """

    def __init__(self, signal_callback: Optional[Callable] = None):
        """
        Args:
            signal_callback: Function to call with StandardSignal dict.
                            Typically aegis_orchestrator.route_signal()
        """
        self._signal_callback = signal_callback
        self._stats = {
            'signals_emitted': 0,
            'alerts_bridged': 0,
            'notices_bridged': 0,
        }

    def set_callback(self, callback: Callable) -> None:
        """Set the AEGIS signal callback."""
        self._signal_callback = callback

    def register(self, event_bus: NapseEventBus) -> None:
        """Register this bridge with the NAPSE event bus."""
        event_bus.subscribe(EventType.ALERT, self._handle_alert)
        event_bus.subscribe(EventType.NOTICE, self._handle_notice)
        logger.info("NapseAegisBridge registered with event bus")

    def _emit_signal(self, signal: Dict[str, Any]) -> None:
        """Emit a signal to AEGIS."""
        if self._signal_callback:
            try:
                self._signal_callback(signal)
                self._stats['signals_emitted'] += 1
            except Exception as e:
                logger.error("Failed to emit AEGIS signal: %s", e)
        else:
            logger.debug("AEGIS callback not set, signal dropped: %s", signal.get('event_type'))

    def _handle_alert(self, _event_type: EventType, alert: NapseAlert) -> None:
        """Convert NAPSE alert to AEGIS StandardSignal."""
        severity_map = {1: 'critical', 2: 'high', 3: 'medium', 4: 'low', 5: 'info'}

        signal = {
            'source': 'napse',
            'event_type': f"napse.{alert.alert_category}",
            'severity': severity_map.get(alert.alert_severity, 'medium'),
            'timestamp': alert.timestamp,
            'data': {
                'signature': alert.alert_signature,
                'signature_id': alert.alert_signature_id,
                'src_ip': alert.src_ip,
                'src_port': alert.src_port,
                'dest_ip': alert.dest_ip,
                'dest_port': alert.dest_port,
                'proto': alert.proto,
                'confidence': alert.confidence,
                'layer': alert.layer,
                'community_id': alert.community_id,
                'evidence': alert.evidence,
            },
        }
        self._emit_signal(signal)
        self._stats['alerts_bridged'] += 1

    def _handle_notice(self, _event_type: EventType, notice: NapseNotice) -> None:
        """Convert NAPSE notice to AEGIS StandardSignal."""
        # Map notice types to AEGIS-friendly event types
        notice_severity_map = {
            'New_Device': 'info',
            'Suspicious_DNS': 'medium',
            'TLS_Cert_Invalid': 'high',
            'Port_Scan_Detected': 'medium',
            'SSH_Bruteforce': 'high',
        }

        signal = {
            'source': 'napse',
            'event_type': f"napse.{notice.note.lower()}",
            'severity': notice_severity_map.get(notice.note, 'info'),
            'timestamp': datetime.fromtimestamp(notice.ts).isoformat(),
            'data': {
                'note': notice.note,
                'msg': notice.msg,
                'sub': notice.sub,
                'src': notice.src,
                'dst': notice.dst,
                'port': notice.p,
                'actions': notice.actions,
            },
        }
        self._emit_signal(signal)
        self._stats['notices_bridged'] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get bridge statistics."""
        return dict(self._stats)
