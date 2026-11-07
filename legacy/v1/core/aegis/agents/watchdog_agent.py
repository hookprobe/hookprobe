"""
WATCHDOG Agent — DNS Protection

Handles DNS threats: domain blocking, DGA detection, DNS tunneling.
Works alongside dnsXai for intelligent DNS protection.
"""

import logging
from typing import Any, Dict, List, Optional

from .base import BaseAgent
from ..types import AgentResponse, ChatMessage, ChatResponse, StandardSignal

logger = logging.getLogger(__name__)


class WatchdogAgent(BaseAgent):
    """WATCHDOG — DNS protection agent."""

    name = "WATCHDOG"
    description = "DNS protection: domain blocking, DGA detection, tunneling"
    trigger_patterns = [
        r"dns|domain|dga",
        r"dnsxai|blocklist",
        r"tunnel(?:ing)?.*dns",
        r"malware.*domain|phishing.*domain",
        r"dns\.(?:block|query|dga)",
        r"blocked.*domain|domain.*blocked",
    ]
    allowed_tools = [
        "block_domain", "whitelist_domain", "adjust_protection",
        "investigate_domain",
    ]
    confidence_threshold = 0.6

    def respond_to_signal(
        self,
        signal: StandardSignal,
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResponse:
        """Handle DNS-related signals."""
        domain = signal.data.get("domain", "unknown")
        dga_score = signal.data.get("dga_score", 0.0)
        category = signal.data.get("category", "unknown")

        if dga_score >= 0.8:
            return AgentResponse(
                agent=self.name,
                action="block_domain",
                confidence=0.95,
                reasoning=f"DGA score {dga_score:.0%} for {domain} — likely malware C2",
                user_message=(
                    f"Blocked suspicious domain **{domain}** — it matches patterns "
                    f"used by malware to communicate with attackers "
                    f"(DGA score: {dga_score:.0%})."
                ),
                tool_calls=[{
                    "name": "block_domain",
                    "params": {"domain": domain, "reason": "DGA detection"},
                }],
                sources=["dnsXai"],
            )
        elif "tunnel" in signal.event_type:
            return AgentResponse(
                agent=self.name,
                action="block_domain",
                confidence=0.9,
                reasoning=f"DNS tunneling detected via {domain}",
                user_message=(
                    f"Blocked **{domain}** — detected DNS tunneling, which can be "
                    f"used to secretly send data out of your network."
                ),
                tool_calls=[{
                    "name": "block_domain",
                    "params": {"domain": domain, "reason": "DNS tunneling"},
                }],
                sources=["dnsXai"],
            )
        else:
            return AgentResponse(
                agent=self.name,
                action="",
                confidence=0.6,
                reasoning=f"DNS event for {domain} [{category}] — monitoring",
                user_message=f"Monitoring DNS activity for {domain} ({category}).",
                sources=["dnsXai"],
            )

    def respond_to_query(
        self,
        message: str,
        history: List[ChatMessage],
        context: Optional[Dict[str, Any]] = None,
    ) -> ChatResponse:
        """Handle user queries about DNS protection."""
        system_prompt = self.get_system_prompt(context)
        dns_stats = self.fabric.get_dns_stats()

        ctx_str = (
            f"DNS Blocked Today: {dns_stats.get('blocked_today', 0)}\n"
            f"Total Queries: {dns_stats.get('total_queries', 0)}\n"
            f"Protection Level: {dns_stats.get('protection_level', 3)}/5\n"
        )

        messages = [
            {"role": "system", "content": system_prompt},
        ]
        for msg in history[-10:]:
            messages.append({"role": msg.role, "content": msg.content})
        messages.append({
            "role": "user",
            "content": f"{message}\n\n---\n[DNS PROTECTION DATA]\n{ctx_str}",
        })

        content = self._llm_chat(messages)
        if content:
            return ChatResponse(
                message=content, agent=self.name, confidence=0.85,
                sources=["dnsXai"],
            )

        return ChatResponse(
            message=(
                f"dnsXai DNS Protection is active:\n"
                f"- Blocked today: {dns_stats.get('blocked_today', 0)} queries\n"
                f"- Protection level: {dns_stats.get('protection_level', 3)}/5\n\n"
                f"Ask me about specific domains or DNS protection settings."
            ),
            agent=self.name, confidence=0.5, sources=["template"],
        )
