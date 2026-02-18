"""
eBPF Sensor Manager — Lifecycle management for kernel sensors.

Manages the set of eBPF sensors currently attached to the kernel.
In Phase 1, this tracks programs deployed by the KernelOrchestrator.
In Phase 2, it will also manage event collection sensors for the
streaming RAG pipeline.

Author: Andrei Toma
License: Proprietary
Version: 1.0.0
"""

import logging
import threading
import time
from typing import Any, Dict, List, Optional

from .types import ActiveProgram, ProgramType

logger = logging.getLogger(__name__)


class SensorManager:
    """Manages the lifecycle of deployed eBPF programs.

    Tracks all active programs, enforces limits, handles rollback
    deadlines, and provides status reporting.
    """

    MAX_ACTIVE_PROGRAMS = 32

    def __init__(self):
        self._active: Dict[str, ActiveProgram] = {}
        self._lock = threading.Lock()
        self._history: List[Dict[str, Any]] = []  # Last 100 deploy/remove events

    def deploy(self, program: ActiveProgram) -> bool:
        """Register a newly deployed program.

        Args:
            program: The active program to track.

        Returns:
            True if registered, False if limit reached.
        """
        with self._lock:
            if len(self._active) >= self.MAX_ACTIVE_PROGRAMS:
                logger.warning(
                    "Active program limit reached (%d/%d) — rejecting %s",
                    len(self._active), self.MAX_ACTIVE_PROGRAMS, program.program_id,
                )
                return False

            self._active[program.program_id] = program
            self._record_event("deploy", program.program_id, program.template_name)
            logger.info(
                "Deployed program %s (template=%s, type=%s, attach=%s)",
                program.program_id, program.template_name,
                program.program_type.value, program.attach_point,
            )
            return True

    def remove(self, program_id: str) -> Optional[ActiveProgram]:
        """Remove a deployed program.

        Returns the removed program, or None if not found.
        """
        with self._lock:
            program = self._active.pop(program_id, None)
            if program:
                self._record_event("remove", program_id, program.template_name)
                logger.info("Removed program %s", program_id)
            return program

    def get(self, program_id: str) -> Optional[ActiveProgram]:
        """Get an active program by ID."""
        with self._lock:
            return self._active.get(program_id)

    def get_by_template(self, template_name: str) -> List[ActiveProgram]:
        """Get all active programs from a given template."""
        with self._lock:
            return [
                p for p in self._active.values()
                if p.template_name == template_name
            ]

    def get_by_attach_point(self, attach_point: str) -> List[ActiveProgram]:
        """Get all active programs on a given attach point."""
        with self._lock:
            return [
                p for p in self._active.values()
                if p.attach_point == attach_point
            ]

    def check_rollback_deadlines(self) -> List[str]:
        """Check for programs past their rollback deadline.

        Returns list of program_ids that should be rolled back.
        """
        now = time.time()
        expired = []
        with self._lock:
            for pid, program in self._active.items():
                if program.rollback_deadline > 0 and now > program.rollback_deadline:
                    expired.append(pid)
        return expired

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive status."""
        with self._lock:
            programs = {}
            for pid, p in self._active.items():
                programs[pid] = {
                    "program_type": p.program_type.value,
                    "attach_point": p.attach_point,
                    "template_name": p.template_name,
                    "deployed_at": p.deployed_at,
                    "rollback_deadline": p.rollback_deadline,
                    "signal_source": p.signal_source,
                }

            return {
                "active_count": len(self._active),
                "max_programs": self.MAX_ACTIVE_PROGRAMS,
                "programs": programs,
                "recent_events": self._history[-10:],
            }

    def _record_event(self, event_type: str, program_id: str, template: str) -> None:
        """Record a deployment event (internal, under lock)."""
        self._history.append({
            "event": event_type,
            "program_id": program_id,
            "template": template,
            "timestamp": time.time(),
        })
        # Keep last 100 events
        if len(self._history) > 100:
            self._history = self._history[-100:]

    def __len__(self) -> int:
        with self._lock:
            return len(self._active)
