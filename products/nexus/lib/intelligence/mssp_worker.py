"""
Nexus MSSP Worker

Background worker that polls the MSSP intelligence queue for
findings needing deep analysis, runs the analysis engine,
and submits results back.

This is the Nexus side of the intelligence loop:
    MSSP → Nexus Worker → Analysis Engine → MSSP
"""

import logging
import threading
import time
from typing import Dict, Optional

from shared.mssp import MSSPClient, Finding

from .analysis_engine import NexusAnalysisEngine

logger = logging.getLogger(__name__)


class NexusMSSPWorker:
    """Background worker polling MSSP for analysis jobs.

    Runs in a daemon thread, pulling findings from the MSSP queue,
    running deep analysis, and submitting results back.
    """

    DEFAULT_POLL_INTERVAL = 5  # seconds

    def __init__(
        self,
        nexus_node_id: str = "",
        poll_interval: int = DEFAULT_POLL_INTERVAL,
        mssp_client: Optional[MSSPClient] = None,
    ):
        self._nexus_node_id = nexus_node_id
        self._poll_interval = poll_interval
        self._client = mssp_client
        self._engine = NexusAnalysisEngine(nexus_node_id)
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Statistics
        self._stats = {
            "jobs_pulled": 0,
            "jobs_completed": 0,
            "jobs_failed": 0,
            "total_analysis_ms": 0,
        }

    def start(self) -> None:
        """Start the worker thread."""
        if self._running:
            return

        if not self._client:
            self._client = MSSPClient()

        # Recommendations arriving via heartbeat trigger analysis
        self._client.on_recommendation(self._handle_recommendation)

        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        logger.info("Nexus MSSP worker started (interval: %ds)", self._poll_interval)

    def stop(self) -> None:
        """Stop the worker thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=10.0)
        logger.info("Nexus MSSP worker stopped")

    def analyze_finding(self, finding: Finding) -> bool:
        """Manually analyze a single finding.

        Returns True if analysis completed and results submitted.
        """
        try:
            result = self._engine.analyze(finding)
            report = self._engine.to_intelligence_report(result)

            # Queue results back to MSSP via next heartbeat
            if self._client:
                for rec in result.recommendations:
                    self._client.queue_finding(Finding(
                        threat_type=finding.threat_type,
                        severity=finding.severity,
                        confidence=result.confidence,
                        ioc_value=finding.ioc_value,
                        ioc_type=finding.ioc_type,
                        description=result.summary,
                        evidence={
                            "nexus_analysis": report,
                            "source_node": self._nexus_node_id,
                        },
                    ))

            self._stats["jobs_completed"] += 1
            self._stats["total_analysis_ms"] += result.analysis_duration_ms
            return True

        except Exception as e:
            self._stats["jobs_failed"] += 1
            logger.error("Analysis failed for %s: %s", finding.finding_id, e)
            return False

    def get_stats(self) -> Dict:
        """Get worker statistics."""
        return {
            **self._stats,
            "running": self._running,
            "engine": self._engine.get_stats(),
        }

    def _handle_recommendation(self, rec) -> None:
        """Handle a recommendation from MSSP — convert to finding and analyze."""
        try:
            self._stats["jobs_pulled"] += 1
            finding = Finding(
                finding_id=rec.finding_id or rec.id,
                threat_type=rec.action,
                severity=rec.priority,
                ioc_value=rec.target,
                description=rec.reasoning,
            )
            self.analyze_finding(finding)
        except Exception as e:
            logger.warning("Recommendation handling error: %s", e)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _poll_loop(self) -> None:
        """Background polling loop."""
        while self._running:
            try:
                self._poll_once()
            except Exception as e:
                logger.warning("Worker poll error: %s", e)

            time.sleep(self._poll_interval)

    def _poll_once(self) -> None:
        """Single poll iteration — heartbeat drives the loop now.

        Recommendations arrive as part of heartbeat response via
        the on_recommendation callback. This method sends a heartbeat
        with telemetry to keep the connection alive.
        """
        if not self._client:
            return

        try:
            # Collect full system telemetry
            try:
                from shared.mssp.telemetry_collector import TelemetryCollector
                telemetry = TelemetryCollector.collect_all()
            except Exception:
                telemetry = {"status": "online"}

            telemetry["version"] = "nexus-worker"

            # Nexus-specific extensions
            telemetry["extensions"] = {
                "nexus": {
                    "stats": self._stats,
                    "engineStats": self._engine.get_stats() if self._engine else {},
                },
            }

            self._client.heartbeat(telemetry)
        except Exception as e:
            logger.debug("Heartbeat error: %s", e)
