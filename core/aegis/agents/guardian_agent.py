"""
GUARDIAN Agent — Network Defense

Handles L3/L4 threats: IP blocking, rate limiting, subnet quarantine.
Monitors QSecBit scores, Suricata alerts, and XDP telemetry.
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
        r"suricata.*alert",
        r"xdp.*(?:block|drop)",
        r"threat\.severity\s*>=?\s*(?:HIGH|CRITICAL)",
        r"block.*ip|rate.*limit|quarantine",
    ]
    allowed_tools = ["block_ip", "rate_limit", "quarantine_subnet", "unblock_ip"]
    confidence_threshold = 0.7

    def respond_to_signal(
        self,
        signal: StandardSignal,
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResponse:
        """Handle network-level threats."""
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
                sources=["QSecBit", "Suricata"],
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
                sources=["QSecBit", "Suricata", "XDP"],
            )

        return ChatResponse(
            message="I'm monitoring the network for L3/L4 threats. "
                    "Ask me about blocked IPs, active threats, or firewall status.",
            agent=self.name, confidence=0.4, sources=["template"],
        )
