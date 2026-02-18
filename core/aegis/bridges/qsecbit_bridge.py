"""
QSecBit Signal Bridge

Watches the QSecBit stats file for score changes and threat events.
Emits signals when security status changes or new threats appear.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .base_bridge import BaseBridge
from ..types import StandardSignal

logger = logging.getLogger(__name__)


class QsecbitBridge(BaseBridge):
    """Bridge for QSecBit security score and threat events.

    QSecBit score convention: higher score = more threat.
      - score > 0.70 → RED (active defense)
      - 0.45 < score < 0.70 → AMBER (monitoring)
      - score < 0.45 → GREEN (protected)
    """

    name = "qsecbit"
    poll_interval = 5.0

    # Default path matches where qsecbit-agent writes stats
    _DEFAULT_STATS_PATH = os.environ.get(
        "QSECBIT_STATS_FILE", "/opt/hookprobe/data/qsecbit_stats.json"
    )

    def __init__(self, stats_path: Optional[str] = None):
        super().__init__()
        self._stats_path = Path(stats_path or self._DEFAULT_STATS_PATH)
        self._last_score: Optional[float] = None
        self._last_status: Optional[str] = None
        self._last_mtime: float = 0
        self._last_threat_count: int = 0

    def poll(self) -> List[StandardSignal]:
        """Poll QSecBit stats for changes."""
        signals = []

        if not self._stats_path.exists():
            return signals

        try:
            mtime = self._stats_path.stat().st_mtime
            if mtime <= self._last_mtime:
                return signals
            self._last_mtime = mtime

            data = json.loads(self._stats_path.read_text())
            score = data.get("score", 0.0)  # 0.0 = safe default (GREEN)
            status = data.get("rag_status", "GREEN")
            threats = data.get("threats_detected", 0)

            # Status change signal
            if self._last_status is not None and status != self._last_status:
                severity = "HIGH" if status == "RED" else "MEDIUM" if status == "AMBER" else "INFO"
                signals.append(StandardSignal(
                    source="qsecbit",
                    event_type=f"status_change.{status.lower()}",
                    severity=severity,
                    data={
                        "score": score,
                        "status": status,
                        "previous_status": self._last_status,
                    },
                ))

            # New threats signal — use rag_status for severity (not raw score)
            # to avoid convention mismatch. Higher score = more threat.
            if threats > self._last_threat_count:
                new_count = threats - self._last_threat_count
                severity = "HIGH" if status == "RED" else "MEDIUM" if status == "AMBER" else "LOW"
                signals.append(StandardSignal(
                    source="qsecbit",
                    event_type="threat.detected",
                    severity=severity,
                    data={
                        "new_threats": new_count,
                        "total_threats": threats,
                        "score": score,
                    },
                ))

            self._last_score = score
            self._last_status = status
            self._last_threat_count = threats

        except Exception as e:
            logger.debug("QSecBit bridge poll error: %s", e)

        return signals
