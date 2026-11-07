"""Alexandria Agency import shim (Phase H.C — submodule adoption).

Imports the `alexandria.adapters.agency_gated` decorator when the Agency
package is on PYTHONPATH; falls back to a no-op decorator otherwise. This
lets the submodule run on three deployment shapes:

  1. Full IDS pipeline + ids-alexandria-agency container — gating active.
  2. Submodule used standalone (e.g. unit tests in ~/hookprobe) — no-op,
     business-as-usual.
  3. Sentinel/Guardian tiers without alexandria installed — no-op.

Usage at call sites:

    from core.agency_shim import agency_gated, ActionKind, BlastRadius

    @agency_gated(kind=ActionKind.BLOCK_IP, proposer="cno.synaptic_controller")
    def push_to_blocklist(self, ip, ...):
        ...
"""

from __future__ import annotations

import logging
import os
from typing import Any, Callable

log = logging.getLogger("hookprobe.agency_shim")

_AGENCY_AVAILABLE = False
_AGENCY_DISABLED = os.environ.get("HOOKPROBE_AGENCY_DISABLED", "0") == "1"

# Try to import the real adapter; gracefully fall back to a no-op.
if not _AGENCY_DISABLED:
    try:
        from alexandria.action import ActionKind as _ActionKind
        from alexandria.action import BlastRadius as _BlastRadius
        from alexandria.adapters import AgencyGate as _AgencyGate
        from alexandria.adapters import agency_gated as _agency_gated
        _AGENCY_AVAILABLE = True
    except ImportError:
        _AGENCY_AVAILABLE = False


if _AGENCY_AVAILABLE:
    # Real Agency — re-export.
    ActionKind = _ActionKind        # type: ignore[assignment]
    BlastRadius = _BlastRadius      # type: ignore[assignment]
    AgencyGate = _AgencyGate        # type: ignore[assignment]
    agency_gated = _agency_gated    # type: ignore[assignment]

else:
    # Fallback — Alexandria is not on PYTHONPATH (Sentinel/Guardian tiers,
    # standalone unit tests, or a Fortress without the agency container).
    #
    # Safety posture (fail-closed): an unsupervised organism MUST NOT take
    # HIGH/CRITICAL blast-radius actions with nobody to veto them. So this
    # fallback PASSES LOW/MEDIUM actions through unchanged (business as
    # usual) but DENIES HIGH/CRITICAL actions and returns a neutral value.
    # Escape hatch: set HOOKPROBE_AGENCY_FAILMODE=open to restore the old
    # always-approve behavior (e.g. a deliberately-autonomous edge node).
    #
    # Mirrors the alexandria.action enum values + DEFAULT_BLAST table
    # verbatim so callers move between the two paths without source changes.

    class ActionKind:  # type: ignore[no-redef]
        BLOCK_IP = "block_ip"
        BLOCK_CIDR = "block_cidr"
        UNBLOCK_IP = "unblock_ip"
        RATE_LIMIT = "rate_limit"
        QUARANTINE_NODE = "quarantine_node"
        QUARANTINE_PROCESS = "quarantine_process"
        KILL_PROCESS = "kill_process"
        APPLY_PROFILE = "apply_profile"
        SCALE_CONTAINER = "scale_container"
        RESTART_CONTAINER = "restart_container"
        PROMOTE_MODEL = "promote_model"
        FEDERATED_AGGREGATE = "federated_aggregate"
        RETRAIN_MODEL = "retrain_model"
        BROADCAST_LESSON = "broadcast_lesson"
        # Phase Q — kernel/fast-path mutations
        PUSH_REPUTATION = "push_reputation"
        UPDATE_ALLOWLIST = "update_allowlist"

    class BlastRadius:  # type: ignore[no-redef]
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"

    # Canonical ActionKind -> BlastRadius table (kept in sync with
    # hookprobe-com alexandria/action.py DEFAULT_BLAST).
    _BLAST_BY_KIND = {
        ActionKind.BLOCK_IP: BlastRadius.LOW,
        ActionKind.BLOCK_CIDR: BlastRadius.HIGH,
        ActionKind.UNBLOCK_IP: BlastRadius.LOW,
        ActionKind.RATE_LIMIT: BlastRadius.LOW,
        ActionKind.QUARANTINE_NODE: BlastRadius.HIGH,
        ActionKind.QUARANTINE_PROCESS: BlastRadius.MEDIUM,
        ActionKind.KILL_PROCESS: BlastRadius.CRITICAL,
        ActionKind.APPLY_PROFILE: BlastRadius.MEDIUM,
        ActionKind.SCALE_CONTAINER: BlastRadius.MEDIUM,
        ActionKind.RESTART_CONTAINER: BlastRadius.MEDIUM,
        ActionKind.PROMOTE_MODEL: BlastRadius.HIGH,
        ActionKind.FEDERATED_AGGREGATE: BlastRadius.CRITICAL,
        ActionKind.RETRAIN_MODEL: BlastRadius.MEDIUM,
        ActionKind.BROADCAST_LESSON: BlastRadius.LOW,
        ActionKind.PUSH_REPUTATION: BlastRadius.LOW,
        ActionKind.UPDATE_ALLOWLIST: BlastRadius.MEDIUM,
    }
    _DENY_BLAST = {BlastRadius.HIGH, BlastRadius.CRITICAL}
    _FAILMODE = os.environ.get("HOOKPROBE_AGENCY_FAILMODE", "closed").lower()

    def _unsupervised_denied(kind: Any) -> bool:
        """True if this action must be blocked because no Agency is present
        to approve it. Unknown kinds default to LOW (canon) -> allowed."""
        if _FAILMODE == "open":
            return False
        return _BLAST_BY_KIND.get(kind, BlastRadius.LOW) in _DENY_BLAST

    def agency_gated(*decorator_args, **decorator_kwargs):  # type: ignore[no-redef]
        """Fail-closed shim. LOW/MEDIUM pass through untouched; HIGH/CRITICAL
        are denied (the wrapped function is not called) when no Agency is
        present, unless HOOKPROBE_AGENCY_FAILMODE=open."""
        kind = decorator_kwargs.get("kind")
        proposer = decorator_kwargs.get("proposer", "?")
        if not _unsupervised_denied(kind):
            def deco_passthrough(fn):
                return fn
            return deco_passthrough

        def deco_deny(fn):
            def wrapper(*args, **kwargs):
                log.warning(
                    "agency_shim: DENIED %s by %s — HIGH/CRITICAL blast radius "
                    "with no Agency to approve (set HOOKPROBE_AGENCY_FAILMODE="
                    "open to override)", kind, proposer,
                )
                return None
            return wrapper
        return deco_deny

    class AgencyGate:  # type: ignore[no-redef]
        """Fail-closed context manager. `approved` is True for LOW/MEDIUM
        (or when FAILMODE=open), False for HIGH/CRITICAL when no Agency is
        present."""
        def __init__(self, *args, **kwargs) -> None:
            self.decision = None
            self._kind = kwargs.get("kind")
            if self._kind is None and args:
                self._kind = args[0]

        def __enter__(self) -> "AgencyGate":
            return self

        def __exit__(self, *exc) -> bool:
            return False

        @property
        def approved(self) -> bool:
            return not _unsupervised_denied(self._kind)

        @property
        def reasons(self) -> tuple[str, ...]:
            if self.approved:
                return ()
            return ("agency-absent: HIGH/CRITICAL blast radius fail-closed",)


def is_agency_available() -> bool:
    """Diagnostic helper for healthchecks / dashboards."""
    return _AGENCY_AVAILABLE


__all__ = [
    "ActionKind", "BlastRadius", "AgencyGate", "agency_gated",
    "is_agency_available",
]
