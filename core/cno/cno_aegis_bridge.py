"""
CNO-AEGIS Bridge — Bidirectional Type Translation

Bridges the two signal systems in HookProbe:
    CNO: SynapticEvent (dataclass, priority-based, BrainLayer-tagged)
    AEGIS: StandardSignal (dataclass, severity-based, source-tagged)

Without this bridge, the CNO and AEGIS operate as disconnected systems.
With it, AEGIS's 72 routing rules and 9 agents become available to CNO
decisions, and CNO's spatial/stress awareness enriches AEGIS responses.

Directions:
    CNO → AEGIS: SynapticEvent → StandardSignal → AegisOrchestrator
    AEGIS → CNO: StandardSignal → SynapticEvent → SynapticController

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import os
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from .types import BrainLayer, SynapticEvent, SynapticRoute

logger = logging.getLogger(__name__)

# ============================================================================
# Priority ↔ Severity Mapping
# ============================================================================

_PRIORITY_TO_SEVERITY = {
    1: 'CRITICAL', 2: 'CRITICAL',
    3: 'HIGH', 4: 'HIGH',
    5: 'MEDIUM', 6: 'MEDIUM',
    7: 'LOW', 8: 'LOW',
    9: 'INFO', 10: 'INFO',
}

_SEVERITY_TO_PRIORITY = {
    'CRITICAL': 1, 'HIGH': 3, 'MEDIUM': 5, 'LOW': 7, 'INFO': 9,
}

# ============================================================================
# AEGIS event_type → CNO SynapticRoute Mapping
# ============================================================================

_AEGIS_TO_ROUTE = {
    # SIA / Intelligence
    'sia.intent_detected': SynapticRoute.ENTITY_GRAPH,
    'sia.sandbox_triggered': SynapticRoute.COGNITIVE_DEFENSE,
    'sia.kill_chain_advance': SynapticRoute.COGNITIVE_DEFENSE,

    # HYDRA
    'hydra.verdict.malicious': SynapticRoute.COGNITIVE_DEFENSE,
    'hydra.verdict.suspicious': SynapticRoute.TEMPORAL_MEMORY,
    'hydra.campaign_detected': SynapticRoute.MULTI_RAG,

    # DNS
    'dns.block': SynapticRoute.TEMPORAL_MEMORY,
    'dns.dga': SynapticRoute.COGNITIVE_DEFENSE,
    'dns.tunnel': SynapticRoute.COGNITIVE_DEFENSE,

    # Network
    'scan.detected': SynapticRoute.TEMPORAL_MEMORY,
    'scan.port': SynapticRoute.SESSION_ANALYSIS,
    'tls.downgrade': SynapticRoute.COGNITIVE_DEFENSE,
    'device.new': SynapticRoute.TEMPORAL_MEMORY,

    # NAPSE
    'napse.alert': SynapticRoute.COGNITIVE_DEFENSE,
    'napse.zero_day': SynapticRoute.MULTI_RAG,

    # Kernel / Neuro-Kernel
    'kernel.shadow_finding': SynapticRoute.COGNITIVE_DEFENSE,
    'kernel.ebpf_failed': SynapticRoute.COGNITIVE_DEFENSE,

    # Healing
    'healing.process_malicious': SynapticRoute.COGNITIVE_DEFENSE,

    # Threat severity escalation
    'threat.severity.critical': SynapticRoute.COGNITIVE_DEFENSE,
    'threat.severity.high': SynapticRoute.COGNITIVE_DEFENSE,
}

_DEFAULT_ROUTE = SynapticRoute.TEMPORAL_MEMORY

# ============================================================================
# CNO event_type → AEGIS source mapping
# ============================================================================

_CNO_SOURCE_MAP = {
    'hydra.verdict': 'hydra',
    'velocity.spike': 'hydra',
    'session.ssh': 'napse',
    'session.http': 'napse',
    'session.dns': 'napse',
    'session.tls': 'napse',
    'app.deviation': 'napse',
    'topology.new_node': 'dhcp',
    'stress_change': 'qsecbit',
    'feedback.': 'aegis',
}


def _infer_source(event_type: str) -> str:
    """Infer AEGIS source from CNO event_type prefix."""
    for prefix, source in _CNO_SOURCE_MAP.items():
        if event_type.startswith(prefix):
            return source
    return 'cno'


class CNOAegisBridge:
    """Bidirectional type bridge between CNO and AEGIS signal systems.

    Translates SynapticEvent ↔ StandardSignal and optionally routes
    through the AEGIS Orchestrator when available.
    """

    def __init__(self, controller, orchestrator=None):
        """Initialize bridge.

        Args:
            controller: SynapticController instance (for AEGIS→CNO direction)
            orchestrator: Optional AegisOrchestrator instance (for CNO→AEGIS)
        """
        self._controller = controller
        self._orchestrator = orchestrator
        self._stats = {
            'cno_to_aegis': 0,
            'aegis_to_cno': 0,
            'orchestrator_calls': 0,
            'errors': 0,
        }
        logger.info("CNOAegisBridge initialized (orchestrator=%s)",
                     'connected' if orchestrator else 'none')

    # ------------------------------------------------------------------
    # CNO → AEGIS
    # ------------------------------------------------------------------

    def synaptic_to_signal(self, event):
        """Convert a SynapticEvent → StandardSignal for AEGIS routing.

        Imports StandardSignal lazily to avoid circular dependency.
        """
        try:
            from ..aegis.types import StandardSignal
        except ImportError:
            # Fallback: create a dict that looks like StandardSignal
            return {
                'source': _infer_source(event.event_type),
                'event_type': event.event_type,
                'severity': _PRIORITY_TO_SEVERITY.get(event.priority, 'MEDIUM'),
                'data': {
                    'source_ip': event.source_ip,
                    'dest_ip': event.dest_ip,
                    **event.payload,
                },
            }

        severity = _PRIORITY_TO_SEVERITY.get(event.priority, 'MEDIUM')
        source = _infer_source(event.event_type)

        return StandardSignal(
            source=source,
            event_type=event.event_type,
            severity=severity,
            data={
                'source_ip': event.source_ip,
                'dest_ip': event.dest_ip,
                'cno_layer': event.source_layer.value,
                'cno_route': event.route.value,
                **event.payload,
            },
        )

    def route_to_aegis(self, event):
        """Convert event and feed to AEGIS Orchestrator if available.

        Returns list of AgentResponses, or None if orchestrator not wired.
        """
        if not self._orchestrator:
            return None

        self._stats['cno_to_aegis'] += 1
        signal = self.synaptic_to_signal(event)

        try:
            self._stats['orchestrator_calls'] += 1
            responses = self._orchestrator.process_signal(signal)
            return responses
        except Exception as e:
            logger.error("AEGIS orchestrator error: %s", e)
            self._stats['errors'] += 1
            return None

    # ------------------------------------------------------------------
    # AEGIS → CNO
    # ------------------------------------------------------------------

    def signal_to_synaptic(self, signal) -> SynapticEvent:
        """Convert a StandardSignal → SynapticEvent for CNO routing."""
        # Determine route from event_type
        event_type = getattr(signal, 'event_type', '') or ''
        route = _AEGIS_TO_ROUTE.get(event_type, _DEFAULT_ROUTE)

        # Map severity to priority
        severity = getattr(signal, 'severity', 'MEDIUM') or 'MEDIUM'
        priority = _SEVERITY_TO_PRIORITY.get(severity, 5)

        # Extract data
        data = getattr(signal, 'data', {}) or {}
        source_ip = data.get('source_ip', data.get('src_ip', ''))

        return SynapticEvent(
            source_layer=BrainLayer.CEREBRUM,
            route=route,
            priority=priority,
            event_type=event_type,
            source_ip=source_ip,
            payload=dict(data),
        )

    def feed_from_aegis(self, signal) -> bool:
        """Accept an AEGIS signal and inject into CNO via SynapticController."""
        self._stats['aegis_to_cno'] += 1

        try:
            event = self.signal_to_synaptic(signal)
            return self._controller.submit(event)
        except Exception as e:
            logger.error("AEGIS→CNO bridge error: %s", e)
            self._stats['errors'] += 1
            return False

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            'has_orchestrator': self._orchestrator is not None,
        }
