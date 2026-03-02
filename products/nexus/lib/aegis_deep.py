"""
AEGIS-Deep — Full AI Security for Nexus (16GB+)

GPU-accelerated AEGIS with large context LLM, extended memory,
federated threat intelligence, and meta-regressive learning.

Nexus-specific additions beyond standard AEGIS:
- NexusMSSPWorker for pulling analysis jobs from MSSP queue
- Enhanced SCOUT with federated threat intel from aggregation server
- Enhanced MEDIC with meta-regressive learning from red/purple teaming
- ClickHouse-backed memory for extended retention

Architecture:
    MSSP Queue → Analysis Engine → AEGIS-Deep (all 8 agents) → Recommendations
    Edge Nodes → Federated Learning → AEGIS-Deep knowledge base
"""

import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class AegisDeep:
    """AEGIS-Deep client for Nexus nodes.

    Wraps the standard AegisClient with Nexus-specific enhancements:
    - MSSP intelligence worker (pulls analysis jobs)
    - Federated threat intelligence integration
    - Meta-regressive learning from purple teaming
    """

    VERSION = "1.0.0"

    def __init__(self, nexus_node_id: str = ""):
        self._nexus_node_id = nexus_node_id or os.environ.get(
            "NEXUS_NODE_ID", "nexus-unknown"
        )
        self._aegis_client = None
        self._mssp_worker = None
        self._analysis_engine = None
        self._pending_provision_id = ""

    def initialize(self) -> bool:
        """Initialize AEGIS-Deep with Nexus enhancements."""
        # 1. Standard AEGIS with Deep profile
        try:
            from core.aegis.client import AegisClient
            from core.aegis.signal_fabric import SignalFabricConfig

            config = SignalFabricConfig(
                qsecbit_stats_path="/opt/hookprobe/nexus/data/qsecbit_stats.json",
                devices_path="/opt/hookprobe/nexus/data/devices.json",
                dnsxai_api_url="http://localhost:8080/api/stats",
            )
            self._aegis_client = AegisClient(config)
            logger.info("AEGIS-Deep client initialized")
        except Exception as e:
            logger.error("AEGIS-Deep init failed: %s", e)
            return False

        # 2. Intelligence analysis engine
        try:
            from .intelligence import NexusAnalysisEngine
            self._analysis_engine = NexusAnalysisEngine(self._nexus_node_id)
            logger.info("Analysis engine initialized")
        except Exception as e:
            logger.warning("Analysis engine init failed: %s", e)

        # 3. Bootstrap provisioning (first-boot: claim code → API key)
        api_key = ""
        try:
            from shared.mssp.bootstrap import MSSPBootstrap
            bootstrap = MSSPBootstrap(product_type="nexus")
            result = bootstrap.start_provision()
            if result["status"] == "already_provisioned":
                api_key = result["api_key"]
                logger.info("Nexus already provisioned")
            elif result["status"] == "pending_claim":
                logger.info(
                    "Claim code: %s — enter in dashboard to claim this Nexus node",
                    result["claim_code"],
                )
                self._pending_provision_id = result.get("provision_id", "")
            elif result["status"] == "error":
                logger.warning("Provisioning failed: %s", result.get("error"))
        except Exception as e:
            logger.warning("Bootstrap init failed: %s", e)

        # 4. MSSP intelligence worker
        try:
            from .intelligence import NexusMSSPWorker
            from shared.mssp import MSSPClient

            mssp_client = MSSPClient(api_key=api_key) if api_key else None
            self._mssp_worker = NexusMSSPWorker(
                nexus_node_id=self._nexus_node_id,
                mssp_client=mssp_client,
            )
            logger.info("MSSP worker initialized")
        except Exception as e:
            logger.warning("MSSP worker init failed: %s", e)

        return True

    def start(self) -> None:
        """Start AEGIS-Deep with all Nexus services."""
        if self._aegis_client:
            self._aegis_client.start()

        # If pending claim, check once before starting worker
        if self._pending_provision_id:
            self._try_complete_provision()

        if self._mssp_worker:
            self._mssp_worker.start()

        logger.info("AEGIS-Deep started on %s", self._nexus_node_id)

    def _try_complete_provision(self) -> None:
        """Check if pending claim was completed, initialize MSSP client if so."""
        try:
            from shared.mssp.bootstrap import MSSPBootstrap
            from shared.mssp import MSSPClient

            bootstrap = MSSPBootstrap(product_type="nexus")
            result = bootstrap.check_claim_status(self._pending_provision_id)

            if result.get("claimed"):
                api_key = result["api_key"]
                logger.info("Nexus claim completed — API key received")
                if self._mssp_worker and not self._mssp_worker._client:
                    self._mssp_worker._client = MSSPClient(api_key=api_key)
                self._pending_provision_id = ""
            else:
                logger.info(
                    "Claim pending — enter claim code in dashboard to activate"
                )
        except Exception as e:
            logger.debug("Provision check error: %s", e)

    def stop(self) -> None:
        """Stop all Nexus services."""
        if self._mssp_worker:
            self._mssp_worker.stop()

        if self._aegis_client:
            self._aegis_client.stop()

        logger.info("AEGIS-Deep stopped")

    def analyze_finding(self, finding) -> Optional[Dict]:
        """Run deep analysis on a finding.

        This is the primary Nexus capability — taking a finding from
        any tier and producing a comprehensive analysis with recommendations.
        """
        if self._analysis_engine:
            result = self._analysis_engine.analyze(finding)
            return {
                "assessment": result.threat_assessment,
                "confidence": result.confidence,
                "mitre": result.mitre_techniques,
                "campaign": result.is_campaign,
                "recommendations": [r.to_dict() for r in result.recommendations],
                "summary": result.summary,
            }
        return None

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive AEGIS-Deep status."""
        status: Dict[str, Any] = {
            "version": self.VERSION,
            "node_id": self._nexus_node_id,
            "profile": "deep",
            "tier": "nexus",
        }

        if self._aegis_client:
            status["aegis"] = self._aegis_client.get_full_status()
        if self._analysis_engine:
            status["analysis_engine"] = self._analysis_engine.get_stats()
        if self._mssp_worker:
            status["mssp_worker"] = self._mssp_worker.get_stats()

        return status
