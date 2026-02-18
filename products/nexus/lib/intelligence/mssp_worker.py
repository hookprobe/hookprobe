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

from shared.mssp.client import HookProbeMSSPClient, get_mssp_client
from shared.mssp.types import ThreatFinding

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
        mssp_client: Optional[HookProbeMSSPClient] = None,
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
            self._client = get_mssp_client(tier="nexus")

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

    def analyze_finding(self, finding: ThreatFinding) -> bool:
        """Manually analyze a single finding.

        Returns True if analysis completed and results submitted.
        """
        try:
            result = self._engine.analyze(finding)
            report = self._engine.to_intelligence_report(result)

            # Submit results back to MSSP
            if self._client:
                # Submit each recommendation
                for rec in result.recommendations:
                    self._client.submit_finding(ThreatFinding(
                        source_tier="nexus",
                        source_node_id=self._nexus_node_id,
                        threat_type=finding.threat_type,
                        severity=finding.severity,
                        confidence=result.confidence,
                        ioc_value=finding.ioc_value,
                        ioc_type=finding.ioc_type,
                        description=result.summary,
                        raw_evidence={
                            "nexus_analysis": report.to_dict(),
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
        """Single poll iteration."""
        if not self._client:
            return

        # Poll for recommendations (which are actually findings needing analysis)
        # In a full implementation, this would use a dedicated Nexus queue endpoint
        # For now, we poll the standard recommendations endpoint
        try:
            recommendations = self._client.poll_recommendations()
            for rec in recommendations:
                self._stats["jobs_pulled"] += 1
                # Convert recommendation to finding for analysis
                finding = ThreatFinding(
                    finding_id=rec.finding_id,
                    threat_type=rec.action_type,
                    severity="HIGH",
                    ioc_value=rec.target,
                    source_tier="mssp",
                    needs_deep_analysis=True,
                )
                self.analyze_finding(finding)
        except Exception as e:
            logger.debug("Poll iteration error: %s", e)
