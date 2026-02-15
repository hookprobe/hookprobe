"""
Virtual Sandbox — Shadow Network Entity Isolation

When SIA confidence exceeds 0.92, redirects suspect entity traffic
to a shadow network via OVS flow rules. Synthesized responses
confirm/deny intent without exposing real network resources.

Integrates with Mirage adaptive honeypots for deep interaction
and telemetry collection during sandbox period.

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Shadow network VLAN for sandboxed entities
SANDBOX_VLAN = 999
SANDBOX_BRIDGE = "FTS"

# Default sandbox duration before auto-release
DEFAULT_SANDBOX_DURATION_S = 600  # 10 minutes
MAX_SANDBOX_DURATION_S = 3600    # 1 hour


@dataclass
class SandboxSession:
    """Tracks a sandboxed entity."""
    entity_id: str
    started_at: float
    duration_s: float = DEFAULT_SANDBOX_DURATION_S
    risk_score: float = 0.0
    intent_phase: str = ""
    evidence_count: int = 0
    flow_rule_ids: List[str] = field(default_factory=list)
    telemetry: Dict[str, Any] = field(default_factory=dict)
    released: bool = False
    release_reason: str = ""

    @property
    def elapsed_s(self) -> float:
        return time.time() - self.started_at

    @property
    def is_expired(self) -> bool:
        return self.elapsed_s >= self.duration_s

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "started_at": self.started_at,
            "elapsed_s": self.elapsed_s,
            "duration_s": self.duration_s,
            "risk_score": self.risk_score,
            "intent_phase": self.intent_phase,
            "evidence_count": self.evidence_count,
            "released": self.released,
            "release_reason": self.release_reason,
        }


class VirtualSandbox:
    """
    Shadow network for suspect entity isolation.

    When SIA triggers sandbox:
    1. Install OVS flow rules to redirect entity traffic to sandbox VLAN
    2. Route traffic through Mirage adaptive honeypots
    3. Collect telemetry on entity behavior
    4. Auto-release after timeout or manual release
    """

    def __init__(
        self,
        bridge: str = SANDBOX_BRIDGE,
        sandbox_vlan: int = SANDBOX_VLAN,
        max_sandboxed: int = 20,
        dry_run: bool = True,
    ):
        self._bridge = bridge
        self._sandbox_vlan = sandbox_vlan
        self._max_sandboxed = max_sandboxed
        self._dry_run = dry_run  # Don't execute OVS commands in testing

        self._sessions: Dict[str, SandboxSession] = {}
        self._callbacks: Dict[str, List[Callable]] = defaultdict(list)

        self._stats = {
            "entities_sandboxed": 0,
            "entities_released": 0,
            "auto_releases": 0,
        }

        logger.info(
            "VirtualSandbox initialized (bridge=%s, vlan=%d, dry_run=%s)",
            bridge, sandbox_vlan, dry_run,
        )

    # ------------------------------------------------------------------
    # Sandbox Operations
    # ------------------------------------------------------------------

    def sandbox_entity(
        self,
        entity_id: str,
        risk_score: float = 0.0,
        intent_phase: str = "",
        evidence_count: int = 0,
        duration_s: float = DEFAULT_SANDBOX_DURATION_S,
    ) -> Dict[str, Any]:
        """Redirect entity traffic to the sandbox shadow network.

        Args:
            entity_id: IP address of the entity to sandbox
            risk_score: Current SIA risk score
            intent_phase: Current intent phase name
            evidence_count: Number of evidence records
            duration_s: Sandbox duration in seconds

        Returns:
            Dict with sandbox status
        """
        if entity_id in self._sessions:
            session = self._sessions[entity_id]
            if not session.released:
                return {
                    "success": True,
                    "message": f"Entity {entity_id} already sandboxed",
                    "session": session.to_dict(),
                }

        if len(self._active_sessions()) >= self._max_sandboxed:
            return {
                "success": False,
                "message": f"Max sandbox capacity ({self._max_sandboxed}) reached",
            }

        duration_s = min(duration_s, MAX_SANDBOX_DURATION_S)

        session = SandboxSession(
            entity_id=entity_id,
            started_at=time.time(),
            duration_s=duration_s,
            risk_score=risk_score,
            intent_phase=intent_phase,
            evidence_count=evidence_count,
        )

        # Install OVS flow rules
        rule_ids = self._install_sandbox_rules(entity_id)
        session.flow_rule_ids = rule_ids

        self._sessions[entity_id] = session
        self._stats["entities_sandboxed"] += 1

        logger.warning(
            "SANDBOX: entity=%s risk=%.3f phase=%s duration=%ds",
            entity_id, risk_score, intent_phase, duration_s,
        )

        self._fire_callback("sandboxed", session)

        return {
            "success": True,
            "message": f"Entity {entity_id} sandboxed (risk={risk_score:.3f})",
            "session": session.to_dict(),
        }

    def release_entity(
        self,
        entity_id: str,
        reason: str = "manual",
    ) -> Dict[str, Any]:
        """Release an entity from the sandbox.

        Args:
            entity_id: Entity to release
            reason: Reason for release (manual, timeout, cleared)

        Returns:
            Dict with release status
        """
        session = self._sessions.get(entity_id)
        if not session or session.released:
            return {
                "success": False,
                "message": f"Entity {entity_id} not in sandbox",
            }

        # Remove OVS flow rules
        self._remove_sandbox_rules(entity_id, session.flow_rule_ids)

        session.released = True
        session.release_reason = reason
        self._stats["entities_released"] += 1

        logger.info(
            "SANDBOX RELEASE: entity=%s reason=%s elapsed=%.0fs",
            entity_id, reason, session.elapsed_s,
        )

        self._fire_callback("released", session)

        return {
            "success": True,
            "message": f"Entity {entity_id} released ({reason})",
            "session": session.to_dict(),
        }

    def check_expired(self) -> List[str]:
        """Check and auto-release expired sandbox sessions."""
        released = []
        for entity_id, session in list(self._sessions.items()):
            if not session.released and session.is_expired:
                self.release_entity(entity_id, reason="timeout")
                self._stats["auto_releases"] += 1
                released.append(entity_id)
        return released

    # ------------------------------------------------------------------
    # Telemetry
    # ------------------------------------------------------------------

    def get_sandbox_telemetry(self, entity_id: str) -> Dict[str, Any]:
        """Get telemetry data for a sandboxed entity."""
        session = self._sessions.get(entity_id)
        if not session:
            return {"error": f"Entity {entity_id} not found in sandbox"}

        return {
            "session": session.to_dict(),
            "telemetry": session.telemetry,
        }

    def record_telemetry(
        self,
        entity_id: str,
        key: str,
        value: Any,
    ) -> None:
        """Record telemetry data for a sandboxed entity."""
        session = self._sessions.get(entity_id)
        if session and not session.released:
            session.telemetry[key] = value

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def is_sandboxed(self, entity_id: str) -> bool:
        """Check if an entity is currently sandboxed."""
        session = self._sessions.get(entity_id)
        return session is not None and not session.released

    def get_session(self, entity_id: str) -> Optional[SandboxSession]:
        """Get sandbox session for an entity."""
        return self._sessions.get(entity_id)

    def get_active_sandboxes(self) -> List[Dict[str, Any]]:
        """Get all active sandbox sessions."""
        return [s.to_dict() for s in self._active_sessions()]

    def on(self, event: str, callback: Callable) -> None:
        """Register callback: sandboxed, released."""
        self._callbacks[event].append(callback)

    # ------------------------------------------------------------------
    # OVS Flow Rules
    # ------------------------------------------------------------------

    def _install_sandbox_rules(self, entity_id: str) -> List[str]:
        """Install OVS flow rules to redirect entity to sandbox VLAN."""
        rules = []

        # Rule 1: Redirect inbound traffic from entity to sandbox VLAN
        rule_id_in = f"sandbox_in_{entity_id.replace('.', '_')}"
        cmd_in = (
            f"ovs-ofctl add-flow {self._bridge} "
            f"priority=1000,ip,nw_src={entity_id},"
            f"actions=mod_vlan_vid:{self._sandbox_vlan},NORMAL"
        )

        # Rule 2: Redirect outbound traffic to entity through sandbox
        rule_id_out = f"sandbox_out_{entity_id.replace('.', '_')}"
        cmd_out = (
            f"ovs-ofctl add-flow {self._bridge} "
            f"priority=1000,ip,nw_dst={entity_id},"
            f"actions=mod_vlan_vid:{self._sandbox_vlan},NORMAL"
        )

        if self._dry_run:
            logger.info("SANDBOX DRY-RUN: %s", cmd_in)
            logger.info("SANDBOX DRY-RUN: %s", cmd_out)
        else:
            try:
                subprocess.run(cmd_in.split(), check=True, timeout=5)
                subprocess.run(cmd_out.split(), check=True, timeout=5)
            except Exception as e:
                logger.error("Failed to install sandbox OVS rules: %s", e)

        rules = [rule_id_in, rule_id_out]
        return rules

    def _remove_sandbox_rules(self, entity_id: str, rule_ids: List[str]) -> None:
        """Remove OVS sandbox flow rules."""
        cmd_in = (
            f"ovs-ofctl del-flows {self._bridge} "
            f"ip,nw_src={entity_id}"
        )
        cmd_out = (
            f"ovs-ofctl del-flows {self._bridge} "
            f"ip,nw_dst={entity_id}"
        )

        if self._dry_run:
            logger.info("SANDBOX DRY-RUN REMOVE: %s", cmd_in)
            logger.info("SANDBOX DRY-RUN REMOVE: %s", cmd_out)
        else:
            try:
                subprocess.run(cmd_in.split(), check=True, timeout=5)
                subprocess.run(cmd_out.split(), check=True, timeout=5)
            except Exception as e:
                logger.error("Failed to remove sandbox OVS rules: %s", e)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _active_sessions(self) -> List[SandboxSession]:
        return [s for s in self._sessions.values() if not s.released]

    def _fire_callback(self, event: str, session: SandboxSession) -> None:
        for cb in self._callbacks.get(event, []):
            try:
                cb(event, session)
            except Exception as e:
                logger.error("Sandbox callback error [%s]: %s", event, e)

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "active_sandboxes": len(self._active_sessions()),
            "total_sessions": len(self._sessions),
        }
