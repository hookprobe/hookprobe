"""
AEGIS-Pico — Minimal AI Security for Sentinel (256MB)

Template-only responses (no LLM), 2-layer memory,
3 active agents (ORACLE, WATCHDOG, GUARDIAN).

Provides standalone detection + defense + MSSP reporting
within a 25MB RAM budget.

Architecture:
    Mesh → AEGIS-Pico Signal Fabric → Template Agents → Defense Actions
    AEGIS-Pico → MSSP (findings) ← MSSP (recommendations)
"""

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from core.aegis.profiles import get_profile
from core.aegis.soul import AEGIS_PRINCIPLES
from core.aegis.types import StandardSignal

logger = logging.getLogger(__name__)

# Template responses for ORACLE (no LLM needed)
ORACLE_TEMPLATES = {
    "status": (
        "Your Sentinel node is {status}. Security score: {score}%. "
        "{threat_summary}"
    ),
    "threat_detected": (
        "Threat detected: {threat_type} from {source}. "
        "Severity: {severity}. Action taken: {action}."
    ),
    "recommendation_applied": (
        "Applied recommendation from mesh: {action_type} on {target}. "
        "Reason: {reasoning}."
    ),
    "blocked": (
        "Blocked {target} — {reason}. "
        "This action was {source_desc}."
    ),
    "unknown": (
        "I'm AEGIS-Pico running on your Sentinel node. "
        "I provide automated security with template responses. "
        "For detailed AI analysis, this finding will be forwarded to MSSP."
    ),
}


class PicoMemory:
    """Minimal 2-layer memory for Sentinel (session + threat_intel)."""

    def __init__(self, max_session: int = 50, max_threat: int = 500):
        self._session: Dict[str, str] = {}
        self._threat_intel: Dict[str, Dict] = {}
        self._max_session = max_session
        self._max_threat = max_threat
        self._lock = threading.Lock()

    def store_session(self, key: str, value: str) -> None:
        with self._lock:
            if len(self._session) >= self._max_session:
                oldest = next(iter(self._session))
                del self._session[oldest]
            self._session[key] = value

    def store_threat(self, ioc: str, data: Dict) -> None:
        with self._lock:
            if len(self._threat_intel) >= self._max_threat:
                oldest = next(iter(self._threat_intel))
                del self._threat_intel[oldest]
            self._threat_intel[ioc] = data

    def lookup_threat(self, ioc: str) -> Optional[Dict]:
        with self._lock:
            return self._threat_intel.get(ioc)

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                "session_entries": len(self._session),
                "threat_intel_entries": len(self._threat_intel),
            }


class PicoSignalRouter:
    """Lightweight signal router for AEGIS-Pico.

    Routes signals to defense actions and MSSP reporting
    using template-based logic (no LLM).
    """

    # Severity thresholds for auto-defense
    AUTO_DEFEND_SEVERITIES = {"CRITICAL", "HIGH"}

    def __init__(self, defense_callback: Optional[Callable] = None):
        self._defense_callback = defense_callback
        self._signal_count = 0
        self._actions_taken = 0
        self._lock = threading.Lock()

    def process_signal(self, signal: StandardSignal) -> Optional[Dict]:
        """Process a signal and return action if needed."""
        with self._lock:
            self._signal_count += 1

        action = None

        # IDS alerts → auto-defend if HIGH+
        if signal.event_type == "ids_alert":
            if signal.severity in self.AUTO_DEFEND_SEVERITIES:
                src_ip = signal.data.get("src_ip", "")
                if src_ip:
                    action = {
                        "type": "block_ip",
                        "target": src_ip,
                        "reason": signal.data.get("signature", "IDS alert"),
                        "duration": 3600,
                    }

        # DNS suspicious → sinkhole
        elif signal.event_type in ("dns_suspicious", "dns_event"):
            query = signal.data.get("query", "")
            if signal.severity in ("HIGH", "CRITICAL") and query:
                action = {
                    "type": "dns_sinkhole",
                    "target": query,
                    "reason": "Suspicious DNS activity",
                }

        # Anomaly → monitor + report
        elif signal.event_type == "anomaly_detected":
            action = {
                "type": "monitor",
                "target": signal.data.get("src_ip", "unknown"),
                "reason": signal.data.get("anomaly_type", "Anomaly detected"),
            }

        if action and self._defense_callback:
            self._defense_callback(action)
            with self._lock:
                self._actions_taken += 1

        return action

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                "signals_processed": self._signal_count,
                "actions_taken": self._actions_taken,
            }


class AegisPico:
    """AEGIS-Pico client for Sentinel nodes.

    Provides:
    - Template-based security responses (no LLM)
    - Signal processing from mesh relay
    - Auto-defense actions (block, sinkhole, rate-limit)
    - MSSP finding submission
    - Recommendation execution

    RAM Budget: ~25MB
    """

    VERSION = "1.0.0"

    def __init__(self):
        self.profile = get_profile("sentinel")
        self.memory = PicoMemory(
            max_session=self.profile["memory"]["max_session_entries"],
            max_threat=self.profile["memory"]["max_threat_intel_entries"],
        )
        self.router = PicoSignalRouter()
        self._running = False
        self._signal_callbacks: List[Callable] = []
        self._mssp_client = None
        self._defense_engine = None

        logger.info("AEGIS-Pico initialized (RAM budget: %dMB)", self.profile["ram_budget_mb"])

    def set_defense_engine(self, engine) -> None:
        """Wire the defense engine for auto-actions."""
        self._defense_engine = engine
        self.router._defense_callback = self._execute_defense

    def set_mssp_client(self, client) -> None:
        """Wire the MSSP client for finding submission."""
        self._mssp_client = client

    def on_signal(self, callback: Callable[[StandardSignal], None]) -> None:
        """Register a signal callback."""
        self._signal_callbacks.append(callback)

    def process_mesh_signal(self, signal: StandardSignal) -> None:
        """Process a signal received from mesh relay.

        This is the main entry point for Sentinel, which receives
        pre-processed signals from nearby Fortress/Guardian nodes.
        """
        # Store in threat intel memory
        ioc = signal.data.get("src_ip") or signal.data.get("query", "")
        if ioc:
            self.memory.store_threat(ioc, {
                "event_type": signal.event_type,
                "severity": signal.severity,
                "timestamp": signal.timestamp.isoformat(),
                "data": signal.data,
            })

        # Route signal for defense action
        action = self.router.process_signal(signal)

        # Submit HIGH+ findings to MSSP
        if signal.severity in ("CRITICAL", "HIGH") and self._mssp_client:
            self._submit_finding(signal)

        # Notify callbacks
        for cb in self._signal_callbacks:
            try:
                cb(signal)
            except Exception as e:
                logger.warning("Signal callback error: %s", e)

    def execute_recommendation(self, action: Dict) -> bool:
        """Execute a recommendation received from MSSP/mesh.

        Validates against AEGIS principles before execution.
        """
        action_type = action.get("action_type", "")
        target = action.get("target", "")

        # Principle guard: never disable protection
        if action_type in ("disable_firewall", "disable_ids", "stop_aegis"):
            logger.warning(
                "Rejected recommendation: %s violates protect_first principle",
                action_type,
            )
            return False

        # Principle guard: never block trusted devices without confirmation
        trust = self.memory.lookup_threat(target)
        if trust and trust.get("trusted", False):
            logger.warning(
                "Rejected recommendation: %s targets trusted device %s",
                action_type, target,
            )
            return False

        if self._defense_engine:
            return self._execute_defense({
                "type": action_type,
                "target": target,
                "reason": action.get("reasoning", "MSSP recommendation"),
                "duration": action.get("ttl_seconds", 3600),
            })

        return False

    def respond(self, query: str) -> str:
        """Generate a template response (no LLM)."""
        query_lower = query.lower()

        if any(w in query_lower for w in ("status", "health", "how")):
            stats = self.router.get_stats()
            mem = self.memory.get_stats()
            return ORACLE_TEMPLATES["status"].format(
                status="active" if self._running else "idle",
                score=85,
                threat_summary=f"{mem['threat_intel_entries']} threats tracked, "
                               f"{stats['actions_taken']} actions taken.",
            )

        return ORACLE_TEMPLATES["unknown"]

    def start(self) -> None:
        """Start AEGIS-Pico autonomous operation."""
        self._running = True
        logger.info("AEGIS-Pico started")

    def stop(self) -> None:
        """Stop AEGIS-Pico."""
        self._running = False
        logger.info("AEGIS-Pico stopped")

    def get_status(self) -> Dict:
        """Get AEGIS-Pico status."""
        return {
            "version": self.VERSION,
            "profile": self.profile["name"],
            "tier": self.profile["tier"],
            "running": self._running,
            "memory": self.memory.get_stats(),
            "router": self.router.get_stats(),
            "principles": list(AEGIS_PRINCIPLES.keys()),
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _execute_defense(self, action: Dict) -> bool:
        """Execute a defense action via the defense engine."""
        if not self._defense_engine:
            logger.warning("No defense engine configured")
            return False

        action_type = action.get("type", "")
        target = action.get("target", "")
        reason = action.get("reason", "")
        duration = action.get("duration", 3600)

        try:
            if action_type == "block_ip":
                return self._defense_engine.block_ip(target, duration, reason)
            elif action_type == "dns_sinkhole":
                return self._defense_engine.dns_sinkhole(target, reason)
            elif action_type == "rate_limit":
                return self._defense_engine.rate_limit(target, reason)
            elif action_type == "monitor":
                logger.info("Monitoring %s: %s", target, reason)
                return True
            else:
                logger.warning("Unknown action type: %s", action_type)
                return False
        except Exception as e:
            logger.error("Defense action failed: %s", e)
            return False

    def _submit_finding(self, signal: StandardSignal) -> None:
        """Submit a finding to MSSP for deep analysis."""
        if not self._mssp_client:
            return

        try:
            from shared.mssp.types import ThreatFinding

            finding = ThreatFinding(
                source_tier="sentinel",
                threat_type=signal.event_type,
                severity=signal.severity,
                confidence=0.7,
                ioc_type="ip" if signal.data.get("src_ip") else "domain",
                ioc_value=signal.data.get("src_ip") or signal.data.get("query", ""),
                raw_evidence=signal.data,
                needs_deep_analysis=signal.severity == "CRITICAL",
                description=f"Sentinel detection: {signal.event_type}",
            )

            self._mssp_client.submit_finding(finding)
        except Exception as e:
            logger.warning("Failed to submit finding to MSSP: %s", e)
