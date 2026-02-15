"""
Mirage Bridge — AEGIS Signal Emitter

Connects the Mirage deception system to AEGIS by converting
Mirage events into StandardSignal objects that route through
the AEGIS orchestrator to SCOUT, GUARDIAN, and MEDIC agents.

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class MirageBridge:
    """
    Bridge between Mirage deception system and AEGIS orchestrator.

    Registers as a callback consumer on MirageOrchestrator and
    IntelligenceFeedback, then emits StandardSignal objects
    with source='mirage' for AEGIS routing.
    """

    def __init__(self, signal_callback: Optional[Callable] = None):
        """
        Args:
            signal_callback: Function that accepts a StandardSignal
                and feeds it to the AEGIS orchestrator's process_signal().
        """
        self._signal_callback = signal_callback
        self._stats = {
            "signals_emitted": 0,
            "errors": 0,
        }
        logger.info("MirageBridge initialized")

    def set_signal_callback(self, callback: Callable) -> None:
        """Set the callback for emitting signals to AEGIS."""
        self._signal_callback = callback

    # ------------------------------------------------------------------
    # Wire to Mirage Components
    # ------------------------------------------------------------------

    def connect(self, orchestrator, honeypot=None, feedback=None) -> None:
        """Wire bridge to Mirage orchestrator, honeypot, and feedback.

        Args:
            orchestrator: MirageOrchestrator instance
            honeypot: AdaptiveHoneypot instance (optional)
            feedback: IntelligenceFeedback instance (optional)
        """
        orchestrator.on("scan_detected", self._on_scan_detected)
        orchestrator.on("honeypot_deployed", self._on_honeypot_deployed)
        orchestrator.on("attacker_profiled", self._on_attacker_profiled)
        orchestrator.on("attacker_learning", self._on_attacker_learning)

        if honeypot:
            honeypot.on("level_escalated", self._on_level_escalated)
            honeypot.on("payload_captured", self._on_payload_captured)

        if feedback:
            feedback.register_consumer("aegis_bridge", self._on_intel_generated)

        logger.info("MirageBridge connected to Mirage components")

    # ------------------------------------------------------------------
    # Event Handlers → StandardSignal Emission
    # ------------------------------------------------------------------

    def _on_scan_detected(self, event: str, tracker) -> None:
        """Scan detected → emit to SCOUT."""
        self._emit_signal(
            event_type="scan.detected",
            severity="MEDIUM",
            data={
                "source_ip": tracker.source_ip,
                "ports_probed": list(tracker.ports_probed),
                "dark_port_hits": tracker.dark_port_count,
                "scan_type": "dark_port_sweep",
                "ports_scanned": len(tracker.ports_probed),
            },
        )

    def _on_honeypot_deployed(self, event: str, tracker) -> None:
        """Honeypot deployed → emit to SCOUT + GUARDIAN."""
        self._emit_signal(
            event_type="mirage.honeypot_deployed",
            severity="MEDIUM",
            data={
                "source_ip": tracker.source_ip,
                "ports_probed": list(tracker.ports_probed),
                "state": tracker.state.name,
            },
        )

    def _on_attacker_profiled(self, event: str, tracker) -> None:
        """Attacker profiled → emit to SCOUT + GUARDIAN."""
        self._emit_signal(
            event_type="mirage.attacker_profiled",
            severity="HIGH",
            data={
                "source_ip": tracker.source_ip,
                "ports_probed": list(tracker.ports_probed),
                "alert_count": tracker.alert_count,
                "connection_count": tracker.connection_count,
                "state": tracker.state.name,
            },
        )

    def _on_attacker_learning(self, event: str, tracker) -> None:
        """Attacker in learning phase → emit to GUARDIAN + MEDIC."""
        self._emit_signal(
            event_type="mirage.attacker_learning",
            severity="HIGH",
            data={
                "source_ip": tracker.source_ip,
                "ports_probed": list(tracker.ports_probed),
                "alert_count": tracker.alert_count,
            },
        )

    def _on_level_escalated(self, event: str, session) -> None:
        """Honeypot interaction level escalated."""
        self._emit_signal(
            event_type="mirage.level_escalated",
            severity="MEDIUM",
            data={
                "source_ip": session.source_ip,
                "level": session.level.name,
                "sophistication": session.sophistication.name,
                "commands_count": len(session.commands_received),
            },
        )

    def _on_payload_captured(self, event: str, session) -> None:
        """Payload captured from attacker → HIGH severity."""
        self._emit_signal(
            event_type="mirage.payload_captured",
            severity="HIGH",
            data={
                "source_ip": session.source_ip,
                "payload_count": len(session.payloads_captured),
                "sophistication": session.sophistication.name,
                "level": session.level.name,
            },
        )

    def _on_intel_generated(self, intel) -> None:
        """Intelligence feedback generated a new ThreatIntel."""
        severity = "MEDIUM"
        if intel.confidence >= 0.85:
            severity = "HIGH"
        if intel.intel_type.value in ("c2_indicator", "payload_hash"):
            severity = "HIGH"

        self._emit_signal(
            event_type=f"mirage.intel_{intel.intel_type.value}",
            severity=severity,
            data={
                "source_ip": intel.source_ip,
                "intel_type": intel.intel_type.value,
                "confidence": intel.confidence,
                "ioc_type": intel.ioc_type,
                "ioc_value": intel.ioc_value,
                "mitre_techniques": intel.mitre_techniques,
            },
        )

    # ------------------------------------------------------------------
    # Signal Emission
    # ------------------------------------------------------------------

    def _emit_signal(
        self,
        event_type: str,
        severity: str = "INFO",
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Create and emit a StandardSignal to AEGIS."""
        if not self._signal_callback:
            logger.debug("MirageBridge: no signal callback, dropping %s", event_type)
            return

        try:
            from core.aegis.types import StandardSignal

            signal = StandardSignal(
                source="mirage",
                event_type=event_type,
                severity=severity,
                data=data or {},
            )
            self._signal_callback(signal)
            self._stats["signals_emitted"] += 1
            logger.debug("MirageBridge emitted: %s (severity=%s)", event_type, severity)
        except Exception as e:
            self._stats["errors"] += 1
            logger.error("MirageBridge signal error: %s", e)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        return dict(self._stats)
