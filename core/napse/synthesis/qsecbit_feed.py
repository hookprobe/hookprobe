"""
NAPSE QSecBit Direct Feed

Converts NAPSE alerts and events directly into QSecBit ThreatEvent objects,
bypassing the log file intermediary for sub-millisecond detection latency.

Integration modes:
  1. Compatibility mode: NAPSE writes EVE JSON, BaseDetector reads it (Phase 1-4)
  2. Direct mode: NAPSE injects ThreatEvent directly (Phase 5+)

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from .event_bus import (
    NapseAlert, NapseNotice, ConnectionRecord, DNSRecord,
    HTTPRecord, TLSRecord, EventType, NapseEventBus,
)

logger = logging.getLogger(__name__)

# Lazy import to avoid circular dependency at module load
_threat_types = None


def _get_threat_types():
    """Lazy import of QSecBit threat types."""
    global _threat_types
    if _threat_types is None:
        from core.qsecbit.threat_types import (
            ThreatEvent, AttackType, ThreatSeverity, OSILayer,
            MITRE_ATTACK_MAP, DEFAULT_SEVERITY_MAP,
        )
        _threat_types = {
            'ThreatEvent': ThreatEvent,
            'AttackType': AttackType,
            'ThreatSeverity': ThreatSeverity,
            'OSILayer': OSILayer,
            'MITRE_ATTACK_MAP': MITRE_ATTACK_MAP,
            'DEFAULT_SEVERITY_MAP': DEFAULT_SEVERITY_MAP,
        }
    return _threat_types


# NAPSE alert category to QSecBit AttackType mapping
CATEGORY_TO_ATTACK_TYPE = {
    'sql_injection': 'SQL_INJECTION',
    'sqli': 'SQL_INJECTION',
    'xss': 'XSS',
    'cross_site_scripting': 'XSS',
    'dns_tunneling': 'DNS_TUNNELING',
    'http_flood': 'HTTP_FLOOD',
    'syn_flood': 'SYN_FLOOD',
    'udp_flood': 'UDP_FLOOD',
    'port_scan': 'PORT_SCAN',
    'malware_c2': 'MALWARE_C2',
    'command_control': 'MALWARE_C2',
    'command_injection': 'COMMAND_INJECTION',
    'path_traversal': 'PATH_TRAVERSAL',
    'ssl_strip': 'SSL_STRIP',
    'tls_downgrade': 'TLS_DOWNGRADE',
    'arp_spoofing': 'ARP_SPOOFING',
    'vlan_hopping': 'VLAN_HOPPING',
    'rogue_dhcp': 'ROGUE_DHCP',
    'evil_twin': 'EVIL_TWIN',
    'session_hijack': 'SESSION_HIJACK',
    'auth_bypass': 'AUTH_BYPASS',
    'brute_force': 'AUTH_BYPASS',
}

# NAPSE alert severity to QSecBit ThreatSeverity mapping
SEVERITY_MAP = {
    1: 'CRITICAL',
    2: 'HIGH',
    3: 'MEDIUM',
    4: 'LOW',
    5: 'INFO',
}

# NAPSE layer number to QSecBit OSILayer mapping
LAYER_MAP = {
    2: 'L2_DATA_LINK',
    3: 'L3_NETWORK',
    4: 'L4_TRANSPORT',
    5: 'L5_SESSION',
    6: 'L6_PRESENTATION',
    7: 'L7_APPLICATION',
}


class QSecBitDirectFeed:
    """
    Direct event feed to QSecBit, bypassing log files.

    Converts NAPSE events into ThreatEvent objects and injects them
    directly into the QSecBit unified engine detection pipeline.
    """

    def __init__(self, unified_engine=None):
        """
        Args:
            unified_engine: QSecBit UnifiedEngine instance.
                           If None, events are queued until engine is set.
        """
        self.engine = unified_engine
        self._pending: List[Any] = []
        self._stats = {
            'alerts_converted': 0,
            'alerts_injected': 0,
            'conversion_errors': 0,
        }

    def set_engine(self, engine) -> None:
        """Set the QSecBit unified engine and flush pending events."""
        self.engine = engine
        for threat in self._pending:
            self._inject(threat)
        self._pending.clear()

    def register(self, event_bus: NapseEventBus) -> None:
        """Register this feed with the NAPSE event bus."""
        event_bus.subscribe(EventType.ALERT, self._handle_alert)
        logger.info("QSecBitDirectFeed registered with event bus")

    def _handle_alert(self, _event_type: EventType, alert: NapseAlert) -> None:
        """Convert NAPSE alert to QSecBit ThreatEvent."""
        try:
            types = _get_threat_types()
            AttackType = types['AttackType']
            ThreatSeverity = types['ThreatSeverity']
            OSILayer = types['OSILayer']
            ThreatEvent = types['ThreatEvent']

            # Map category to attack type
            attack_name = CATEGORY_TO_ATTACK_TYPE.get(
                alert.alert_category.lower(), 'UNKNOWN'
            )
            attack_type = AttackType[attack_name]

            # Map severity
            severity_name = SEVERITY_MAP.get(alert.alert_severity, 'MEDIUM')
            severity = ThreatSeverity[severity_name]

            # Map layer
            layer_name = LAYER_MAP.get(alert.layer, 'L7_APPLICATION')
            layer = OSILayer[layer_name]

            threat = ThreatEvent(
                id=str(uuid.uuid4()),
                timestamp=datetime.now(),
                attack_type=attack_type,
                layer=layer,
                severity=severity,
                source_ip=alert.src_ip or None,
                dest_ip=alert.dest_ip or None,
                dest_port=alert.dest_port or None,
                description=alert.alert_signature,
                confidence=alert.confidence,
                detector="NAPSE",
                evidence={
                    'napse_sig_id': alert.alert_signature_id,
                    'napse_category': alert.alert_category,
                    'community_id': alert.community_id,
                    **alert.evidence,
                },
            )

            self._stats['alerts_converted'] += 1
            self._inject(threat)

        except Exception as e:
            logger.error("Failed to convert NAPSE alert to ThreatEvent: %s", e)
            self._stats['conversion_errors'] += 1

    def _inject(self, threat) -> None:
        """Inject a ThreatEvent into QSecBit engine."""
        if self.engine is None:
            self._pending.append(threat)
            return

        try:
            if hasattr(self.engine, 'inject_threat'):
                self.engine.inject_threat(threat)
            else:
                # Fallback: add to the appropriate detector
                logger.debug("Engine lacks inject_threat, queuing event")
                self._pending.append(threat)

            self._stats['alerts_injected'] += 1
        except Exception as e:
            logger.error("Failed to inject threat into QSecBit: %s", e)

    def get_stats(self) -> Dict[str, Any]:
        """Get feed statistics."""
        return {
            **self._stats,
            'pending_count': len(self._pending),
            'engine_connected': self.engine is not None,
        }
