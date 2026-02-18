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
    - MSSP intelligence loop
    """

    VERSION = "1.0.0"

    def __init__(self):
        self._aegis_client = None
        self._mssp_client = None
        self._recommendation_handler = None

    def initialize(self) -> bool:
        """Initialize AEGIS-Lite with Guardian configuration."""
        # 1. Standard AEGIS with Lite profile paths
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
            logger.error("AEGIS-Lite init failed: %s", e)
            return False

        # 2. MSSP client
        try:
            from shared.mssp import get_mssp_client
            self._mssp_client = get_mssp_client(tier="guardian")
            logger.info("MSSP client initialized for Guardian")
        except Exception as e:
            logger.warning("MSSP client init failed: %s", e)

        # 3. Recommendation handler
        try:
            from shared.mssp import RecommendationHandler
            self._recommendation_handler = RecommendationHandler(
                mssp_client=self._mssp_client,
            )
            logger.info("Recommendation handler initialized")
        except Exception as e:
            logger.warning("Recommendation handler init failed: %s", e)

        return True

    def start(self) -> None:
        """Start AEGIS-Lite with all services."""
        if self._aegis_client:
            self._aegis_client.start()

        if self._mssp_client:
            self._mssp_client.start_heartbeat(interval=60)

        logger.info("AEGIS-Lite started")

    def stop(self) -> None:
        """Stop all services."""
        if self._mssp_client:
            self._mssp_client.stop_heartbeat()
        if self._aegis_client:
            self._aegis_client.stop()

        logger.info("AEGIS-Lite stopped")

    def chat(self, session_id: str, message: str):
        """Chat with AEGIS-Lite (cloud inference)."""
        if self._aegis_client:
            return self._aegis_client.chat(session_id, message)
        return None

    def submit_finding(self, finding) -> bool:
        """Submit a finding to MSSP."""
        if self._mssp_client:
            result = self._mssp_client.submit_finding(finding)
            return result is not None
        return False

    def handle_recommendation(self, action) -> bool:
        """Handle a recommendation from MSSP/mesh."""
        if self._recommendation_handler:
            return self._recommendation_handler.handle(action)
        return False

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
            status["mssp"] = self._mssp_client.get_stats()

        return status
