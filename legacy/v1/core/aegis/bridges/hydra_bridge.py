"""
HYDRA SENTINEL Bridge — Feeds SENTINEL verdicts to AEGIS Signal Fabric.

Watches the SENTINEL score cache file (written by sentinel_engine.py)
for new verdicts and emits StandardSignals for:
  - Malicious IPs (HIGH severity → GUARDIAN, MEDIC)
  - Suspicious IPs (MEDIUM severity → GUARDIAN)
  - Campaign detections (HIGH severity → GUARDIAN, MEDIC, SCOUT)
  - Model drift alerts (MEDIUM severity → ORACLE)

The sentinel_engine.py writes a JSON summary to a cache file after each
scoring cycle. This bridge tails that file for changes.

Cache file format (sentinel_scores.json):
{
    "timestamp": "2026-01-15T10:30:00Z",
    "cycle": 42,
    "scored": 15,
    "verdicts": {"benign": 10, "suspicious": 3, "malicious": 2},
    "malicious_ips": [
        {"ip": "1.2.3.4", "score": 0.85, "verdict": "malicious",
         "confidence": 0.7, "campaign_id": "C-1.2.3.4-5"}
    ],
    "suspicious_ips": [
        {"ip": "5.6.7.8", "score": 0.55, "verdict": "suspicious",
         "confidence": 0.4}
    ],
    "drift_detected": false,
    "model_version": 3
}
"""

import json
import logging
import os
from pathlib import Path
from typing import List, Optional

from .base_bridge import BaseBridge
from ..types import StandardSignal

logger = logging.getLogger(__name__)

# Default path where sentinel_engine.py writes its score summary
SENTINEL_CACHE_PATH = os.environ.get(
    "SENTINEL_CACHE_FILE",
    "/opt/hookprobe/data/sentinel_scores.json",
)


class HydraBridge(BaseBridge):
    """Bridge for HYDRA SENTINEL verdicts → AEGIS signal fabric.

    Polls a JSON cache file written by sentinel_engine.py after each
    scoring cycle. Emits signals for malicious/suspicious verdicts,
    campaign detections, and model drift.

    Signal types emitted:
        hydra.verdict.malicious  → GUARDIAN, MEDIC
        hydra.verdict.suspicious → GUARDIAN
        hydra.campaign_detected  → GUARDIAN, MEDIC, SCOUT
        hydra.drift_detected     → ORACLE
        hydra.model_retrained    → ORACLE
    """

    name = "hydra"
    poll_interval = 10.0  # SENTINEL cycles every 300s; 10s is responsive enough

    def __init__(self, cache_path: Optional[str] = None):
        super().__init__()
        self._cache_path = Path(cache_path or SENTINEL_CACHE_PATH)
        self._last_mtime: float = 0
        self._last_cycle: int = 0
        self._last_model_version: int = 0
        self._seen_malicious: set = set()  # IPs seen as malicious (dedup within session)
        self._last_drift: bool = False

    def poll(self) -> List[StandardSignal]:
        """Poll SENTINEL cache for new verdicts."""
        signals: List[StandardSignal] = []

        if not self._cache_path.exists():
            return signals

        try:
            mtime = self._cache_path.stat().st_mtime
            if mtime <= self._last_mtime:
                return signals
            self._last_mtime = mtime

            data = json.loads(self._cache_path.read_text())
            cycle = data.get("cycle", 0)

            # Skip if same cycle (duplicate read)
            if cycle <= self._last_cycle:
                return signals
            self._last_cycle = cycle

            # Malicious IP verdicts
            for entry in data.get("malicious_ips", []):
                ip = entry.get("ip", "")
                score = float(entry.get("score", 0))
                confidence = float(entry.get("confidence", 0))
                campaign_id = entry.get("campaign_id", "")

                signals.append(StandardSignal(
                    source="hydra",
                    event_type="verdict.malicious",
                    severity="HIGH",
                    data={
                        "ip": ip,
                        "sentinel_score": score,
                        "confidence": confidence,
                        "campaign_id": campaign_id,
                        "cycle": cycle,
                    },
                ))

                # Campaign detection (if IP belongs to a campaign)
                if campaign_id and ip not in self._seen_malicious:
                    signals.append(StandardSignal(
                        source="hydra",
                        event_type="campaign_detected",
                        severity="HIGH",
                        data={
                            "ip": ip,
                            "campaign_id": campaign_id,
                            "sentinel_score": score,
                        },
                    ))

                self._seen_malicious.add(ip)

            # Suspicious IP verdicts
            for entry in data.get("suspicious_ips", []):
                ip = entry.get("ip", "")
                score = float(entry.get("score", 0))
                confidence = float(entry.get("confidence", 0))

                signals.append(StandardSignal(
                    source="hydra",
                    event_type="verdict.suspicious",
                    severity="MEDIUM",
                    data={
                        "ip": ip,
                        "sentinel_score": score,
                        "confidence": confidence,
                        "cycle": cycle,
                    },
                ))

            # Drift detection
            drift = data.get("drift_detected", False)
            if drift and not self._last_drift:
                signals.append(StandardSignal(
                    source="hydra",
                    event_type="drift_detected",
                    severity="MEDIUM",
                    data={
                        "model_version": data.get("model_version", 0),
                        "cycle": cycle,
                    },
                ))
            self._last_drift = drift

            # Model retrained
            model_version = data.get("model_version", 0)
            if model_version > self._last_model_version and self._last_model_version > 0:
                signals.append(StandardSignal(
                    source="hydra",
                    event_type="model_retrained",
                    severity="INFO",
                    data={
                        "old_version": self._last_model_version,
                        "new_version": model_version,
                        "cycle": cycle,
                    },
                ))
            self._last_model_version = model_version

            # Periodic cleanup of seen set (keep bounded)
            if len(self._seen_malicious) > 5000:
                self._seen_malicious.clear()

        except Exception as e:
            logger.debug("HYDRA bridge poll error: %s", e)

        return signals
