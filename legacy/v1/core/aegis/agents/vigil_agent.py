"""
VIGIL Agent — Authentication Integrity

Handles TLS/SSL monitoring, certificate validation, session integrity,
and authentication attack detection (SSL stripping, TLS downgrade).
"""

import logging
from typing import Any, Dict, List, Optional

from .base import BaseAgent
from ..types import AgentResponse, ChatMessage, ChatResponse, StandardSignal

logger = logging.getLogger(__name__)


class VigilAgent(BaseAgent):
    """VIGIL — Authentication integrity agent."""

    name = "VIGIL"
    description = "Auth integrity: TLS monitoring, cert validation, session security"
    trigger_patterns = [
        r"ssl|tls|certificate|cert",
        r"ssl\s*strip|tls\s*downgrade",
        r"ja3|ja3s|fingerprint.*tls",
        r"session\s*hijack|mitm|man.in.the.middle",
        r"qsecbit.*l5|session\s*layer",
        r"tls\.downgrade|auth.*attack",
    ]
    allowed_tools = ["block_ssl_strip", "enforce_tls", "terminate_session"]
    confidence_threshold = 0.7

    def respond_to_signal(
        self,
        signal: StandardSignal,
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResponse:
        """Handle authentication/TLS signals."""
        event = signal.event_type
        source_ip = signal.data.get("source_ip", "unknown")
        destination = signal.data.get("destination", "")

        if "ssl_strip" in event or "tls_downgrade" in event:
            return AgentResponse(
                agent=self.name,
                action="block_ssl_strip",
                confidence=0.95,
                reasoning=f"SSL strip/TLS downgrade detected from {source_ip}",
                user_message=(
                    f"Blocked an attempt to intercept your encrypted connection"
                    f"{' to ' + destination if destination else ''}. "
                    f"This attack (SSL stripping) tries to remove encryption "
                    f"so an attacker can read your data. Your data is safe."
                ),
                tool_calls=[{
                    "name": "block_ssl_strip",
                    "params": {"source_ip": source_ip, "destination": destination},
                }],
                sources=["QSecBit"],
            )
        elif "cert_mismatch" in event or "cert_expired" in event:
            return AgentResponse(
                agent=self.name,
                action="",
                confidence=0.7,
                reasoning=f"Certificate issue for {destination}: {event}",
                user_message=(
                    f"Certificate issue detected for {destination}: "
                    f"{'expired certificate' if 'expired' in event else 'certificate mismatch'}. "
                    f"This may indicate a misconfiguration or an attack."
                ),
                sources=["QSecBit"],
            )
        else:
            return AgentResponse(
                agent=self.name,
                action="",
                confidence=0.5,
                reasoning=f"Auth event: {event}",
                user_message=f"Authentication event detected: {event}.",
                sources=["QSecBit"],
            )

    def respond_to_query(
        self,
        message: str,
        history: List[ChatMessage],
        context: Optional[Dict[str, Any]] = None,
    ) -> ChatResponse:
        """Handle user queries about authentication and TLS."""
        system_prompt = self.get_system_prompt(context)
        ctx_str = self._build_context_str()

        messages = [
            {"role": "system", "content": system_prompt},
        ]
        for msg in history[-10:]:
            messages.append({"role": msg.role, "content": msg.content})
        messages.append({
            "role": "user",
            "content": f"{message}\n\n---\n[AUTH SECURITY DATA]\n{ctx_str}",
        })

        content = self._llm_chat(messages)
        if content:
            return ChatResponse(
                message=content, agent=self.name, confidence=0.85,
                sources=["QSecBit"],
            )

        return ChatResponse(
            message="I monitor TLS/SSL security and authentication integrity. "
                    "Ask me about certificate status, encrypted connections, "
                    "or authentication security.",
            agent=self.name, confidence=0.4, sources=["template"],
        )
