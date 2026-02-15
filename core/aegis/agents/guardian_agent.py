"""
GUARDIAN Agent — Network Defense

Handles L3/L4 threats: IP blocking, rate limiting, subnet quarantine.
Monitors QSecBit scores, NAPSE alerts, and XDP telemetry.
"""

import logging
from typing import Any, Dict, List, Optional

from .base import BaseAgent
from ..types import AgentResponse, ChatMessage, ChatResponse, StandardSignal

logger = logging.getLogger(__name__)


class GuardianAgent(BaseAgent):
    """GUARDIAN — Network defense agent."""

    name = "GUARDIAN"
    description = "Network defense: IP blocking, rate limiting, subnet quarantine"
    trigger_patterns = [
        r"(?:syn|udp|icmp)\s*flood",
        r"ddos|dos\s+attack",
        r"port\s*scan",
        r"ip\s*spoof",
        r"qsecbit.*(?:l3|l4|network|transport)",
        r"napse.*alert",
        r"xdp.*(?:block|drop)",
        r"threat\.severity\s*>=?\s*(?:HIGH|CRITICAL)",
        r"block.*ip|rate.*limit|quarantine",
    ]
    allowed_tools = [
        "block_ip", "rate_limit", "quarantine_subnet", "unblock_ip",
        "sandbox_entity", "release_sandbox", "get_entity_intent",
        "profile_attacker_ttps",
    ]
    confidence_threshold = 0.7

    def respond_to_signal(
        self,
        signal: StandardSignal,
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResponse:
        """Handle network-level threats, including SIA intent signals."""
        # SIA intent-aware handling
        if signal.source == "sia":
            return self._handle_sia_signal(signal)

        severity = signal.severity
        source_ip = signal.data.get("source_ip", "unknown")
        attack_type = signal.data.get("attack_type", signal.event_type)

        # Decision logic based on severity
        if severity == "CRITICAL":
            return AgentResponse(
                agent=self.name,
                action="block_ip",
                confidence=0.95,
                reasoning=f"CRITICAL {attack_type} from {source_ip} — immediate block",
                user_message=(
                    f"Blocked IP {source_ip} — detected {attack_type} "
                    f"(CRITICAL severity). Your network is protected."
                ),
                tool_calls=[{
                    "name": "block_ip",
                    "params": {"ip": source_ip, "duration": 3600, "reason": attack_type},
                }],
                sources=["QSecBit", "NAPSE"],
            )
        elif severity == "HIGH":
            return AgentResponse(
                agent=self.name,
                action="rate_limit",
                confidence=0.85,
                reasoning=f"HIGH {attack_type} from {source_ip} — rate limiting first",
                user_message=(
                    f"Rate-limiting traffic from {source_ip} — detected {attack_type}. "
                    f"Monitoring for escalation."
                ),
                tool_calls=[{
                    "name": "rate_limit",
                    "params": {"ip": source_ip, "rate": "100/s", "reason": attack_type},
                }],
                sources=["QSecBit"],
            )
        else:
            return AgentResponse(
                agent=self.name,
                action="",
                confidence=0.6,
                reasoning=f"{severity} {attack_type} from {source_ip} — monitoring",
                user_message=(
                    f"Monitoring suspicious traffic from {source_ip} ({attack_type}). "
                    f"No action needed yet."
                ),
                sources=["QSecBit"],
            )

    def _handle_sia_signal(self, signal: StandardSignal) -> AgentResponse:
        """Handle SIA intent detection signals with phase-aware response."""
        entity_id = signal.data.get("entity_id", "unknown")
        phase = signal.data.get("phase", "")
        risk_score = signal.data.get("risk_score", 0.0)
        confidence = signal.data.get("confidence", 0.0)

        # Phases requiring immediate blocking
        blocking_phases = {
            "LATERAL_MOVEMENT", "EXFILTRATION", "IMPACT",
        }
        # Phases requiring sandbox
        sandbox_phases = {
            "EXECUTION", "PERSISTENCE", "COLLECTION",
        }

        if signal.event_type == "sia.sandbox_triggered":
            return AgentResponse(
                agent=self.name,
                action="sandbox_entity",
                confidence=0.95,
                reasoning=(
                    f"SIA sandbox triggered for {entity_id} "
                    f"(risk={risk_score:.3f}) — isolating to shadow network"
                ),
                user_message=(
                    f"Entity {entity_id} isolated to sandbox — SIA detected "
                    f"high-confidence attack intent (risk={risk_score:.3f})."
                ),
                tool_calls=[{
                    "name": "sandbox_entity",
                    "params": {
                        "entity_id": entity_id,
                        "risk_score": risk_score,
                        "intent_phase": phase,
                    },
                }],
                sources=["SIA", "NAPSE"],
                escalate_to="MEDIC",
            )

        if phase in blocking_phases:
            return AgentResponse(
                agent=self.name,
                action="block_ip",
                confidence=0.90,
                reasoning=(
                    f"SIA intent phase {phase} for {entity_id} "
                    f"(risk={risk_score:.3f}) — blocking"
                ),
                user_message=(
                    f"Blocked {entity_id} — SIA detected {phase} intent "
                    f"(risk={risk_score:.3f}). Active attack progression stopped."
                ),
                tool_calls=[{
                    "name": "block_ip",
                    "params": {
                        "ip": entity_id,
                        "duration": 3600,
                        "reason": f"SIA {phase} intent (risk={risk_score:.3f})",
                    },
                }],
                sources=["SIA", "NAPSE"],
            )

        if phase in sandbox_phases and risk_score >= 0.7:
            return AgentResponse(
                agent=self.name,
                action="sandbox_entity",
                confidence=0.85,
                reasoning=(
                    f"SIA intent phase {phase} for {entity_id} "
                    f"(risk={risk_score:.3f}) — sandboxing for observation"
                ),
                user_message=(
                    f"Sandboxing {entity_id} — SIA detected {phase} intent "
                    f"(risk={risk_score:.3f}). Observing in shadow network."
                ),
                tool_calls=[{
                    "name": "sandbox_entity",
                    "params": {
                        "entity_id": entity_id,
                        "risk_score": risk_score,
                        "intent_phase": phase,
                    },
                }],
                sources=["SIA", "NAPSE"],
            )

        # Lower phases — monitor
        return AgentResponse(
            agent=self.name,
            action="",
            confidence=0.6,
            reasoning=(
                f"SIA intent phase {phase} for {entity_id} "
                f"(risk={risk_score:.3f}) — monitoring"
            ),
            user_message=(
                f"Monitoring {entity_id} — SIA detected {phase} intent "
                f"(risk={risk_score:.3f}). Tracking progression."
            ),
            sources=["SIA"],
        )

    def respond_to_query(
        self,
        message: str,
        history: List[ChatMessage],
        context: Optional[Dict[str, Any]] = None,
    ) -> ChatResponse:
        """Handle user queries about network defense."""
        system_prompt = self.get_system_prompt(context)
        ctx_str = self._build_context_str()

        messages = [
            {"role": "system", "content": system_prompt},
        ]
        for msg in history[-10:]:
            messages.append({"role": msg.role, "content": msg.content})
        messages.append({
            "role": "user",
            "content": f"{message}\n\n---\n[NETWORK DEFENSE DATA]\n{ctx_str}",
        })

        content = self._llm_chat(messages)
        if content:
            return ChatResponse(
                message=content, agent=self.name, confidence=0.85,
                sources=["QSecBit", "NAPSE", "XDP"],
            )

        return ChatResponse(
            message="I'm monitoring the network for L3/L4 threats. "
                    "Ask me about blocked IPs, active threats, or firewall status.",
            agent=self.name, confidence=0.4, sources=["template"],
        )
