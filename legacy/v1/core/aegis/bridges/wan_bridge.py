"""
WAN / SLA AI Signal Bridge

Watches the SLA AI recommendation file for WAN status changes
and failover events.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .base_bridge import BaseBridge
from ..types import StandardSignal

logger = logging.getLogger(__name__)


class WanBridge(BaseBridge):
    """Bridge for WAN/SLA AI connectivity events."""

    name = "wan"
    poll_interval = 10.0

    def __init__(self, slaai_path: str = "/run/fortress/slaai-recommendation.json"):
        super().__init__()
        self._slaai_path = Path(slaai_path)
        self._last_recommendation: Optional[str] = None
        self._last_interface: Optional[str] = None
        self._last_mtime: float = 0

    def poll(self) -> List[StandardSignal]:
        """Poll SLA AI recommendation file for changes."""
        signals = []

        if not self._slaai_path.exists():
            return signals

        try:
            mtime = self._slaai_path.stat().st_mtime
            if mtime <= self._last_mtime:
                return signals
            self._last_mtime = mtime

            data = json.loads(self._slaai_path.read_text())
            recommendation = data.get("recommendation", "")
            active_interface = data.get("active_interface", "")
            confidence = data.get("confidence", 0.0)

            # Interface change (failover/failback)
            if self._last_interface and active_interface != self._last_interface:
                is_failover = recommendation == "failover"
                signals.append(StandardSignal(
                    source="slaai",
                    event_type="wan.failover" if is_failover else "wan.failback",
                    severity="MEDIUM" if is_failover else "INFO",
                    data={
                        "active_interface": active_interface,
                        "previous_interface": self._last_interface,
                        "recommendation": recommendation,
                        "confidence": confidence,
                        "reason": data.get("reason", ""),
                    },
                ))

            self._last_recommendation = recommendation
            self._last_interface = active_interface

        except Exception as e:
            logger.debug("WAN bridge poll error: %s", e)

        return signals
