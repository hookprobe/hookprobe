"""
FORGE Agent — Hardening & Configuration

System hardening audits, password management, firmware monitoring,
and security configuration recommendations.
"""

import logging
from typing import Any, Dict, List, Optional

from .base import BaseAgent
from ..types import AgentResponse, ChatMessage, ChatResponse, StandardSignal

logger = logging.getLogger(__name__)


class ForgeAgent(BaseAgent):
    """FORGE — Hardening and configuration agent."""

    name = "FORGE"
    description = "Hardening: audits, password management, config recommendations"
    trigger_patterns = [
        r"harden|hardening|audit",
        r"password|credential.*(?:age|rotate|change)",
        r"firmware|update|patch",
        r"config(?:uration)?.*(?:check|review|improve)",
        r"cis|benchmark|compliance",
        r"scheduled\.audit",
        r"wifi.*password|ssid",
    ]
    allowed_tools = ["generate_password", "rotate_wifi", "recommend_hardening"]
    confidence_threshold = 0.6

    def respond_to_signal(
        self,
        signal: StandardSignal,
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResponse:
        """Handle scheduled audits and config signals."""
        if signal.event_type == "scheduled.audit":
            findings = self._run_basic_audit()
            return AgentResponse(
                agent=self.name,
                action="recommend_hardening",
                confidence=0.8,
                reasoning="Scheduled security audit completed",
                user_message=findings,
                tool_calls=[{
                    "name": "recommend_hardening",
                    "params": {"audit_type": "scheduled"},
                }],
                sources=["Config", "System"],
            )
        else:
            return AgentResponse(
                agent=self.name,
                action="",
                confidence=0.5,
                reasoning=f"Config event: {signal.event_type}",
                user_message=f"Configuration change detected: {signal.event_type}.",
                sources=["Config"],
            )

    def respond_to_query(
        self,
        message: str,
        history: List[ChatMessage],
        context: Optional[Dict[str, Any]] = None,
    ) -> ChatResponse:
        """Handle user queries about hardening and configuration."""
        system_prompt = self.get_system_prompt(context)
        ctx_str = self._build_context_str()

        messages = [
            {"role": "system", "content": system_prompt},
        ]
        for msg in history[-10:]:
            messages.append({"role": msg.role, "content": msg.content})
        messages.append({
            "role": "user",
            "content": f"{message}\n\n---\n[SYSTEM CONFIG DATA]\n{ctx_str}",
        })

        content = self._llm_chat(messages)
        if content:
            return ChatResponse(
                message=content, agent=self.name, confidence=0.85,
                sources=["Config", "System"],
            )

        return ChatResponse(
            message="I can help with security hardening, password management, "
                    "and configuration audits. Ask me about your security posture "
                    "or request a hardening report.",
            agent=self.name, confidence=0.4, sources=["template"],
        )

    def _run_basic_audit(self) -> str:
        """Run a basic security audit and return findings."""
        findings = ["**Security Audit Report**\n"]

        # Check DNS protection level
        dns = self.fabric.get_dns_stats()
        level = dns.get("protection_level", 0)
        if level < 3:
            findings.append(
                f"- **MEDIUM**: DNS protection is at level {level}/5. "
                f"Recommendation: Set to at least level 3 for business networks."
            )

        # Check QSecBit status
        qs = self.fabric.get_qsecbit_status()
        if qs.get("status") != "GREEN":
            findings.append(
                f"- **HIGH**: Security status is {qs.get('status')} "
                f"(score: {qs.get('score', 0):.0%}). Review active threats."
            )

        if len(findings) == 1:
            findings.append("- All checks passed. No issues found.")

        return "\n".join(findings)
