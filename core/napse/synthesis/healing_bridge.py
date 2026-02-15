"""
NAPSE Healing Bridge — AEGIS Integration

Emits StandardSignal events from the HealingEngine to AEGIS agents.
Routes healing events to GUARDIAN (for network-correlated kills)
and FORGE (for hotpatch management).
"""

import logging
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class HealingBridge:
    """Bridge between HealingEngine and AEGIS signal fabric.

    Converts process events into StandardSignal format for
    routing through the AEGIS orchestrator.
    """

    def __init__(
        self,
        emit_signal: Optional[Callable] = None,
    ):
        """
        Args:
            emit_signal: Callback to emit StandardSignal to AEGIS.
                         Signature: (source, event_type, severity, data) -> None
        """
        self._emit_signal = emit_signal
        self._events_emitted = 0

    def on_process_event(self, record) -> None:
        """Handle process execution event from HealingEngine."""
        if record.suspicious_score < 30:
            return  # Only emit for notable events

        severity = "LOW"
        if record.suspicious_score >= 90:
            severity = "CRITICAL"
        elif record.suspicious_score >= 60:
            severity = "HIGH"
        elif record.suspicious_score >= 30:
            severity = "MEDIUM"

        event_type = "healing.process_suspicious"
        if record.verdict.name == "MALICIOUS":
            event_type = "healing.process_malicious"

        self._emit(
            event_type=event_type,
            severity=severity,
            data={
                "pid": record.pid,
                "ppid": record.ppid,
                "uid": record.uid,
                "comm": record.comm,
                "suspicious_score": record.suspicious_score,
                "verdict": record.verdict.name,
                "flags": record.flags,
                "network_alerts": record.network_alerts,
                "file_alerts": record.file_alerts,
                "connection_alerts": record.connection_alerts,
            },
        )

    def on_syscall_event(self, event) -> None:
        """Handle syscall event from HealingEngine."""
        if event.severity < 2:
            return  # Only emit MEDIUM+ severity

        severity_map = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
        severity = severity_map.get(event.severity, "MEDIUM")

        syscall_names = {1: "openat", 2: "connect", 3: "write"}
        syscall_name = syscall_names.get(event.syscall_type, "unknown")

        self._emit(
            event_type=f"healing.syscall_{syscall_name}",
            severity=severity,
            data={
                "pid": event.pid,
                "uid": event.uid,
                "syscall_type": event.syscall_type,
                "syscall_name": syscall_name,
                "severity": event.severity,
                "dst_port": event.dst_port,
                "dst_ip": event.dst_ip,
                "comm": event.comm,
                "path": event.path,
            },
        )

    def on_kill(self, pid: int, comm: str, reason: str) -> None:
        """Emit signal when a process is killed."""
        self._emit(
            event_type="healing.process_killed",
            severity="HIGH",
            data={
                "pid": pid,
                "comm": comm,
                "reason": reason,
                "action": "kill",
            },
        )

    def on_quarantine(self, pid: int, comm: str, reason: str) -> None:
        """Emit signal when a process is quarantined."""
        self._emit(
            event_type="healing.process_quarantined",
            severity="HIGH",
            data={
                "pid": pid,
                "comm": comm,
                "reason": reason,
                "action": "quarantine",
            },
        )

    def on_hotpatch(self, syscall_nr: int, target_comm: str) -> None:
        """Emit signal when a hotpatch is applied."""
        self._emit(
            event_type="healing.hotpatch_applied",
            severity="MEDIUM",
            data={
                "syscall_nr": syscall_nr,
                "target_comm": target_comm or "*",
                "action": "hotpatch",
            },
        )

    def _emit(self, event_type: str, severity: str, data: dict) -> None:
        """Emit a StandardSignal-compatible event."""
        if self._emit_signal:
            try:
                self._emit_signal("healing", event_type, severity, data)
                self._events_emitted += 1
            except Exception as e:
                logger.error("Failed to emit healing signal: %s", e)
        else:
            logger.debug(
                "Healing signal (no emitter): %s %s", event_type, severity,
            )

    def get_stats(self) -> dict:
        return {
            "events_emitted": self._events_emitted,
            "has_emitter": self._emit_signal is not None,
        }
