"""
AEGIS-Lite — Lightweight AI Security for Guardian (1.5GB)

Cloud-only LLM inference via OpenRouter, 3-layer memory,
all 8 agents active, NAPSE event consumption.

Provides full AEGIS functionality with cloud inference instead
of local LLM to stay within 1.5GB RAM budget.

Architecture:
    NAPSE → AEGIS-Lite Signal Fabric → 8 Agents (cloud LLM) → Defense
    AEGIS-Lite → MSSP (findings) ← MSSP (recommendations)
"""

import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class AegisLite:
    """AEGIS-Lite client for Guardian nodes.

    Wraps the standard AegisClient with Guardian-specific configuration:
    - Cloud-only inference (no local Ollama)
    - 3-layer memory (session + behavioral + threat_intel)
    - Direct NAPSE event consumption
    - MSSP intelligence loop with full telemetry
    """

    VERSION = "1.0.0"

    def __init__(self):
        self._aegis_client = None
        self._mssp_client = None
        self._guardian_agent = None  # Set via set_guardian_agent()

    def initialize(self) -> bool:
        """Initialize AEGIS-Lite with Guardian configuration.

        Returns True if at least one of AEGIS core or MSSP client initialized.
        MSSP works independently of AEGIS (doesn't need local LLM).
        """
        # Force cloud backend — Guardian has 1.5GB RAM, no room for local LLM
        os.environ.setdefault("AEGIS_BACKEND", "cloud")

        # 1. Standard AEGIS with Lite profile paths (optional — may not be available)
        try:
            from core.aegis.client import AegisClient
            from core.aegis.signal_fabric import SignalFabricConfig

            config = SignalFabricConfig(
                qsecbit_stats_path="/opt/hookprobe/guardian/data/qsecbit_stats.json",
                devices_path="/opt/hookprobe/guardian/data/devices.json",
                dnsxai_api_url="http://localhost:8080/api/stats",
                dnsxai_stats_path="/opt/hookprobe/guardian/data/dnsxai_stats.json",
            )
            self._aegis_client = AegisClient(config)
            logger.info("AEGIS-Lite client initialized")
        except Exception as e:
            logger.warning("AEGIS core unavailable (MSSP-only mode): %s", e)

        # 2. MSSP client (single-contract piggyback via heartbeat)
        try:
            from shared.mssp import MSSPClient
            self._mssp_client = MSSPClient()
            self._mssp_client.on_recommendation(self._handle_mssp_recommendation)
            logger.info("MSSP client initialized for Guardian")
        except Exception as e:
            logger.warning("MSSP client init failed: %s", e)

        return self._aegis_client is not None or self._mssp_client is not None

    def start(self) -> None:
        """Start AEGIS-Lite with all services."""
        if self._aegis_client:
            self._aegis_client.start()

        if self._mssp_client:
            self._mssp_client.start(collect_telemetry=self._collect_telemetry)

        logger.info("AEGIS-Lite started")

    def stop(self) -> None:
        """Stop all services."""
        if self._mssp_client:
            self._mssp_client.stop()
        if self._aegis_client:
            self._aegis_client.stop()

        logger.info("AEGIS-Lite stopped")

    def set_guardian_agent(self, agent) -> None:
        """Set reference to GuardianAgent for telemetry collection."""
        self._guardian_agent = agent

    def chat(self, session_id: str, message: str):
        """Chat with AEGIS-Lite (cloud inference)."""
        if self._aegis_client:
            return self._aegis_client.chat(session_id, message)
        return None

    def submit_finding(self, finding) -> bool:
        """Queue a finding for MSSP submission on next heartbeat."""
        if self._mssp_client:
            from shared.mssp import Finding
            if not isinstance(finding, Finding):
                finding = Finding(**finding) if isinstance(finding, dict) else finding
            self._mssp_client.queue_finding(finding)
            return True
        return False

    def _handle_mssp_recommendation(self, rec) -> None:
        """Handle a verified recommendation from MSSP (via heartbeat response)."""
        try:
            from shared.mssp import Feedback
            rec_dict = rec.to_dict() if hasattr(rec, 'to_dict') else rec

            success = False
            if self._aegis_client:
                success = self._aegis_client.execute_action(rec_dict)

            if self._mssp_client:
                self._mssp_client.queue_feedback(Feedback(
                    action_id=rec.id,
                    success=success,
                    effect="executed" if success else "failed",
                ))
        except Exception as e:
            logger.error("Recommendation handling error: %s", e)

    def _collect_telemetry(self) -> dict:
        """Collect full telemetry for heartbeat — generic system + guardian extensions."""
        import json
        from pathlib import Path

        # Generic system/network/security telemetry from /proc
        try:
            from shared.mssp.telemetry_collector import TelemetryCollector
            telemetry = TelemetryCollector.collect_all()
        except Exception:
            telemetry: Dict[str, Any] = {"status": "online"}

        telemetry["status"] = "online"
        telemetry["version"] = self.VERSION

        # Guardian-specific extensions from agent or stats file
        guardian_ext: Dict[str, Any] = {}
        if self._guardian_agent:
            try:
                metrics = self._guardian_agent.collect_metrics()
                telemetry["qsecbit"] = round((1.0 - metrics.qsecbit_score) * 100) if metrics.qsecbit_score is not None else None
                guardian_ext = {
                    "qsecbitScore": metrics.qsecbit_score,
                    "ragStatus": metrics.rag_status,
                    "layerThreats": metrics.layer_threats,
                    "mobileProtection": metrics.mobile_protection,
                    "xdpStats": metrics.xdp_stats,
                    "idsStats": metrics.ids_stats,
                    "components": metrics.components,
                    "recentThreats": metrics.recent_threats[:5] if metrics.recent_threats else [],
                }
            except Exception as e:
                logger.debug("Guardian metrics collection error: %s", e)

        # Fallback: read QSecBit stats from disk (written by guardian-qsecbit service)
        if "qsecbit" not in telemetry:
            try:
                stats_path = Path("/opt/hookprobe/guardian/data/stats.json")
                if stats_path.exists():
                    stats = json.loads(stats_path.read_text())
                    score = stats.get("score")
                    if score is not None:
                        telemetry["qsecbit"] = round((1.0 - score) * 100)
                        guardian_ext.setdefault("qsecbitScore", score)
                        guardian_ext.setdefault("ragStatus", stats.get("rag_status", "UNKNOWN"))
                        guardian_ext.setdefault("components", stats.get("components", {}))
                        guardian_ext.setdefault("xdpStats", stats.get("xdp", {}))
            except Exception:
                pass

        if guardian_ext:
            telemetry.setdefault("extensions", {})["guardian"] = guardian_ext

        if self._aegis_client:
            try:
                telemetry.setdefault("extensions", {})["aegisStatus"] = self._aegis_client.get_full_status()
            except Exception:
                pass

        return telemetry

    def get_status(self) -> Dict[str, Any]:
        """Get AEGIS-Lite status."""
        status: Dict[str, Any] = {
            "version": self.VERSION,
            "profile": "lite",
            "tier": "guardian",
        }

        if self._aegis_client:
            status["aegis"] = self._aegis_client.get_full_status()
        if self._mssp_client:
            status["mssp"] = {
                "running": self._mssp_client.is_running,
                "pending": self._mssp_client.pending_count,
            }

        return status
