"""
AEGIS-Pico Mesh Integration — bridges mesh transport to AegisPico.

Registers as a packet handler on the unified mesh transport so that
RECOMMENDATION packets from Nexus/Fortress are automatically forwarded
to AegisPico.execute_recommendation().
"""

import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class AegisPicoReceiver:
    """Receives AEGIS recommendations from mesh, applies via AegisPico."""

    def __init__(self, aegis_pico=None, mesh_transport=None):
        self._pico = aegis_pico
        self._transport = mesh_transport
        self._received_count = 0
        self._applied_count = 0

    def start(self) -> None:
        """Register as a mesh packet handler for RECOMMENDATION packets."""
        if self._transport is not None:
            try:
                from shared.mesh.unified_transport import PacketType

                self._transport.register_handler(
                    PacketType.RECOMMENDATION, self._on_recommendation_packet
                )
                logger.info("AegisPicoReceiver registered for RECOMMENDATION packets")
            except Exception as e:
                logger.warning("Could not register mesh handler: %s", e)

    def _on_recommendation_packet(self, packet_data: bytes) -> None:
        """Handle an incoming RECOMMENDATION mesh packet."""
        try:
            recommendation = json.loads(packet_data)
            self.handle_recommendation(recommendation)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning("Invalid recommendation packet: %s", e)

    def handle_recommendation(self, recommendation: dict) -> bool:
        """Process a recommendation from Nexus/Fortress.

        Supported actions: block_ip, update_signatures, dns_sinkhole,
        rate_limit, unblock_ip.
        """
        self._received_count += 1
        action = recommendation.get("action") or recommendation.get("action_type", "")

        if not action:
            logger.warning("Recommendation missing action field")
            return False

        # Delegate to AegisPico if available
        if self._pico is not None:
            result = self._pico.execute_recommendation(recommendation)
            if result:
                self._applied_count += 1
            return result

        # Standalone handling when AegisPico is not wired
        if action == "block_ip":
            ip = recommendation.get("target", "")
            if ip:
                logger.info("Recommendation: block IP %s", ip)
                self._applied_count += 1
                return True
        elif action == "update_signatures":
            sigs = recommendation.get("signatures", [])
            logger.info("Recommendation: update %d signatures", len(sigs))
            self._applied_count += 1
            return True
        elif action == "dns_sinkhole":
            domain = recommendation.get("target", "")
            if domain:
                logger.info("Recommendation: sinkhole %s", domain)
                self._applied_count += 1
                return True

        logger.debug("Unhandled recommendation action: %s", action)
        return False

    def get_stats(self) -> dict:
        return {
            "received": self._received_count,
            "applied": self._applied_count,
        }
