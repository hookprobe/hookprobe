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
    # Fallback — provide string constants + a no-op decorator + a context
    # manager that always approves. Mirrors the alexandria.action enum
    # values verbatim so callers can move between the two paths without
    # source changes.

    class ActionKind:  # type: ignore[no-redef]
        BLOCK_IP = "block_ip"
        BLOCK_CIDR = "block_cidr"
        UNBLOCK_IP = "unblock_ip"
        RATE_LIMIT = "rate_limit"
        QUARANTINE_NODE = "quarantine_node"
        QUARANTINE_PROCESS = "quarantine_process"
        APPLY_PROFILE = "apply_profile"
        SCALE_CONTAINER = "scale_container"
        RESTART_CONTAINER = "restart_container"
        PROMOTE_MODEL = "promote_model"
        FEDERATED_AGGREGATE = "federated_aggregate"
        RETRAIN_MODEL = "retrain_model"
        BROADCAST_LESSON = "broadcast_lesson"

    class BlastRadius:  # type: ignore[no-redef]
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"

    def agency_gated(*decorator_args, **decorator_kwargs):  # type: ignore[no-redef]
        """No-op shim. Returns the wrapped function untouched."""
        def deco(fn):
            return fn
        return deco

    class AgencyGate:  # type: ignore[no-redef]
        """No-op context manager. Always reports `approved=True`."""
        def __init__(self, *args, **kwargs) -> None:
            self.decision = None

        def __enter__(self) -> "AgencyGate":
            return self

        def __exit__(self, *exc) -> bool:
            return False

        @property
        def approved(self) -> bool:
            return True

        @property
        def reasons(self) -> tuple[str, ...]:
            return ()


def is_agency_available() -> bool:
    """Diagnostic helper for healthchecks / dashboards."""
    return _AGENCY_AVAILABLE


__all__ = [
    "ActionKind", "BlastRadius", "AgencyGate", "agency_gated",
    "is_agency_available",
]
