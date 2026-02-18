"""
Sentinel Agent — Main Daemon

Orchestrates AEGIS-Pico, mesh integration, MSSP reporting,
and defense engine into a unified Sentinel security daemon.

Architecture:
    ┌──────────────────────────────────────────────────┐
    │             SENTINEL AGENT DAEMON                 │
    ├──────────────────────────────────────────────────┤
    │                                                    │
    │  ┌────────────┐  ┌─────────────┐  ┌────────────┐│
    │  │ AEGIS-Pico │  │ Mesh Agent  │  │  Defense   ││
    │  │ (signals)  │  │ (gossip)    │  │  Engine    ││
    │  └─────┬──────┘  └──────┬──────┘  └──────┬─────┘│
    │        │                │                │       │
    │        └────────┬───────┴────────┬───────┘       │
    │                 │                │                │
    │          ┌──────▼──────┐  ┌──────▼──────┐       │
    │          │ MSSP Client │  │ Recommendation│      │
    │          │ (findings)  │  │ Handler       │      │
    │          └─────────────┘  └──────────────┘       │
    │                                                    │
    └──────────────────────────────────────────────────┘
"""

import logging
import os
import signal
import sys
import threading
import time
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class SentinelAgent:
    """Main Sentinel agent daemon.

    Wires together all Sentinel components and manages lifecycle.
    """

    VERSION = "2.0.0"

    def __init__(self):
        self._running = False
        self._aegis = None
        self._mesh = None
        self._defense = None
        self._mssp = None
        self._recommendation_thread = None

    def initialize(self) -> bool:
        """Initialize all Sentinel components."""
        logger.info("Initializing Sentinel Agent v%s", self.VERSION)

        # 1. Defense engine (always available)
        try:
            from .defense import SentinelDefenseEngine
            self._defense = SentinelDefenseEngine()
            logger.info("Defense engine initialized")
        except Exception as e:
            logger.error("Defense engine init failed: %s", e)
            return False

        # 2. AEGIS-Pico
        try:
            from .aegis_pico import AegisPico
            self._aegis = AegisPico()
            self._aegis.set_defense_engine(self._defense)
            logger.info("AEGIS-Pico initialized")
        except Exception as e:
            logger.error("AEGIS-Pico init failed: %s", e)

        # 3. MSSP client
        try:
            from shared.mssp import get_mssp_client
            self._mssp = get_mssp_client(tier="sentinel")
            if self._aegis:
                self._aegis.set_mssp_client(self._mssp)
            logger.info("MSSP client initialized")
        except Exception as e:
            logger.warning("MSSP client init failed (offline mode): %s", e)

        # 4. Mesh integration
        try:
            from .mesh_integration import SentinelMeshAgent, SentinelMeshConfig
            config = SentinelMeshConfig.from_env()
            self._mesh = SentinelMeshAgent(config)

            # Wire mesh threats → AEGIS-Pico
            if self._aegis:
                self._mesh.on_threat(self._on_mesh_threat)

            logger.info("Mesh agent initialized: %s", config.node_id)
        except Exception as e:
            logger.warning("Mesh init failed (standalone mode): %s", e)

        return True

    def start(self) -> None:
        """Start all components and enter main loop."""
        self._running = True

        # Start AEGIS-Pico
        if self._aegis:
            self._aegis.start()

        # Start mesh
        if self._mesh:
            self._mesh.start()

        # Start MSSP heartbeat
        if self._mssp:
            self._mssp.start_heartbeat(interval=120)

        # Start recommendation polling
        if self._mssp:
            self._recommendation_thread = threading.Thread(
                target=self._poll_recommendations_loop, daemon=True,
            )
            self._recommendation_thread.start()

        logger.info("Sentinel Agent started — all components active")

    def stop(self) -> None:
        """Stop all components gracefully."""
        self._running = False

        if self._aegis:
            self._aegis.stop()
        if self._mesh:
            self._mesh.stop()
        if self._mssp:
            self._mssp.stop_heartbeat()
        if self._defense:
            self._defense.stop()

        logger.info("Sentinel Agent stopped")

    def get_status(self) -> Dict:
        """Get comprehensive agent status."""
        status = {
            "version": self.VERSION,
            "running": self._running,
            "components": {},
        }

        if self._aegis:
            status["components"]["aegis_pico"] = self._aegis.get_status()
        if self._mesh:
            status["components"]["mesh"] = self._mesh.get_status()
        if self._defense:
            status["components"]["defense"] = self._defense.get_stats()
        if self._mssp:
            status["components"]["mssp"] = self._mssp.get_stats()

        return status

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _on_mesh_threat(self, intel) -> None:
        """Handle threat intelligence from mesh gossip."""
        if not self._aegis:
            return

        try:
            from core.aegis.types import StandardSignal

            signal = StandardSignal(
                source="mesh_relay",
                event_type="ids_alert",
                severity=self._map_severity(getattr(intel, 'severity', 3)),
                data={
                    "src_ip": getattr(intel, 'ioc_value', ''),
                    "threat_type": getattr(intel, 'threat_type', 'unknown'),
                    "source": "mesh_gossip",
                },
            )
            self._aegis.process_mesh_signal(signal)
        except Exception as e:
            logger.warning("Mesh threat processing error: %s", e)

    def _poll_recommendations_loop(self) -> None:
        """Poll MSSP for recommendations and execute them."""
        poll_interval = 30  # seconds
        while self._running:
            try:
                if self._mssp:
                    recommendations = self._mssp.poll_recommendations()
                    for rec in recommendations:
                        self._handle_recommendation(rec)
            except Exception as e:
                logger.warning("Recommendation poll error: %s", e)

            time.sleep(poll_interval)

    def _handle_recommendation(self, rec) -> None:
        """Handle a single recommendation from MSSP."""
        try:
            # Verify signature
            from shared.mssp.auth import verify_recommendation_signature
            rec_dict = rec.to_dict() if hasattr(rec, 'to_dict') else rec
            if not verify_recommendation_signature(rec_dict):
                logger.warning("Rejected recommendation: invalid signature")
                return

            # Acknowledge receipt
            action_id = getattr(rec, 'action_id', rec_dict.get('action_id', ''))
            if action_id:
                self._mssp.acknowledge_recommendation(action_id)

            # Execute via AEGIS-Pico
            if self._aegis:
                success = self._aegis.execute_recommendation(rec_dict)

                # Submit feedback
                if self._mssp:
                    from shared.mssp.types import ExecutionFeedback
                    feedback = ExecutionFeedback(
                        action_id=action_id,
                        success=success,
                        effect_observed="executed" if success else "failed",
                    )
                    self._mssp.submit_feedback(feedback)

        except Exception as e:
            logger.error("Recommendation handling error: %s", e)

    @staticmethod
    def _map_severity(numeric: int) -> str:
        """Map numeric severity to AEGIS severity string."""
        return {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}.get(numeric, "INFO")


# =============================================================================
# CLI Entry Point
# =============================================================================

def main():
    """Run the Sentinel agent daemon."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    agent = SentinelAgent()

    def shutdown(sig, frame):
        logger.info("Shutdown signal received")
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    if not agent.initialize():
        logger.error("Initialization failed")
        sys.exit(1)

    agent.start()

    logger.info("=" * 60)
    logger.info("HookProbe Sentinel Agent v%s", SentinelAgent.VERSION)
    logger.info("AEGIS-Pico: Active | Defense: Active | Mesh: %s",
                "Active" if agent._mesh else "Standalone")
    logger.info("=" * 60)

    # Main loop
    while agent._running:
        time.sleep(10)


if __name__ == "__main__":
    main()
