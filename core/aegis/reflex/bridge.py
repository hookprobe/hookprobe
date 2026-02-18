"""
AEGIS Reflex — Bridge (QSecBit Score → Reflex Engine)

BaseBridge subclass that reads QSecBit score files and feeds them
into the ReflexEngine for graduated interference evaluation.
Emits StandardSignal events for level transitions and recovery.

Polls at 2s (faster than default 5s) for responsive reflex.

Author: Andrei Toma
License: Proprietary - see LICENSE in this directory
Version: 2.0.0
"""

import json
import logging
import os
from typing import Dict, List, Optional

from ..bridges.base_bridge import BaseBridge
from ..types import StandardSignal
from .engine import ReflexEngine

logger = logging.getLogger(__name__)


class ReflexBridge(BaseBridge):
    """Bridge: reads QSecBit scores → feeds to ReflexEngine → emits signals.

    The bridge reads from the QSecBit score JSON file (written by qsecbit-agent)
    and evaluates each IP's score through the ReflexEngine. Level transitions
    and recovery events are emitted as StandardSignals for orchestrator routing.
    """

    name = "reflex"
    poll_interval = 2.0  # Fast tick for responsive reflex

    def __init__(
        self,
        engine: Optional[ReflexEngine] = None,
        qsecbit_score_path: str = "",
    ):
        super().__init__()
        self._engine = engine or ReflexEngine()
        self._score_path = qsecbit_score_path or os.environ.get(
            "QSECBIT_STATS_FILE", "/opt/hookprobe/data/qsecbit_stats.json"
        )
        self._last_mtime: float = 0.0

    @property
    def engine(self) -> ReflexEngine:
        return self._engine

    def poll(self) -> List[StandardSignal]:
        """Poll QSecBit scores and evaluate through reflex engine."""
        signals: List[StandardSignal] = []

        # Read per-IP scores from QSecBit output
        scores = self._read_scores()
        if not scores:
            return signals

        # Evaluate each IP
        for ip, score_data in scores.items():
            qsecbit_score = score_data.get("score", 0.0)
            decision = self._engine.evaluate(ip, qsecbit_score)

            if decision:
                # Level changed — emit signal
                event_type = "reflex.level_changed"
                severity = "info"

                if decision.new_level.value > decision.old_level.value:
                    event_type = "reflex.escalation"
                    severity = "high" if decision.new_level.value >= 2 else "medium"
                elif decision.new_level.value < decision.old_level.value:
                    event_type = "reflex.recovery"
                    severity = "low"

                if decision.new_level.value == 3:
                    event_type = "reflex.disconnect"
                    severity = "critical"

                signal = StandardSignal(
                    source="reflex",
                    event_type=event_type,
                    severity=severity,
                    data={
                        "target_ip": decision.target_ip,
                        "old_level": decision.old_level.name,
                        "new_level": decision.new_level.name,
                        "qsecbit_score": decision.qsecbit_score,
                        "velocity": decision.velocity,
                        "reason": decision.reason,
                    },
                )
                signals.append(signal)

            # Feed energy data for recovery (if available in score data)
            energy_z = score_data.get("energy_z_score")
            if energy_z is not None:
                recovery_decision = self._engine.update_recovery(ip, energy_z)
                if recovery_decision:
                    signal = StandardSignal(
                        source="reflex",
                        event_type="reflex.recovery",
                        severity="info",
                        data={
                            "target_ip": recovery_decision.target_ip,
                            "old_level": recovery_decision.old_level.name,
                            "new_level": "OBSERVE",
                            "reason": recovery_decision.reason,
                        },
                    )
                    signals.append(signal)

        return signals

    def _read_scores(self) -> Dict[str, dict]:
        """Read QSecBit per-IP scores from the score file.

        Expected format:
        {
            "global": {"score": 0.45, "rag_status": "AMBER"},
            "per_ip": {
                "192.168.1.100": {"score": 0.72, "energy_z_score": 1.5},
                "10.0.0.5": {"score": 0.15}
            }
        }

        Falls back to using global score if per_ip is absent.
        """
        if not os.path.exists(self._score_path):
            return {}

        try:
            mtime = os.path.getmtime(self._score_path)
            if mtime <= self._last_mtime:
                return {}  # No new data
            self._last_mtime = mtime

            with open(self._score_path, "r") as f:
                data = json.load(f)

            # Prefer per-IP scores
            per_ip = data.get("per_ip", {})
            if per_ip:
                return per_ip

            # Fallback: use global score for all known targets
            global_score = data.get("global", {}).get("score", 0.0)
            if global_score > 0 and self._engine.get_all_targets():
                return {
                    ip: {"score": global_score}
                    for ip in self._engine.get_all_targets()
                }

            return {}

        except (json.JSONDecodeError, OSError) as e:
            logger.debug("Failed to read QSecBit scores: %s", e)
            return {}
