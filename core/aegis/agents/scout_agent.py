"""
SCOUT Agent — Reconnaissance Detection

Detects port scanning, attacker profiling, honeypot management.
Monitors NAPSE connections and QSecBit L4 for scan behavior.
"""

import logging
from typing import Any, Dict, List, Optional

from .base import BaseAgent
from ..types import AgentResponse, ChatMessage, ChatResponse, StandardSignal

logger = logging.getLogger(__name__)


class ScoutAgent(BaseAgent):
    """SCOUT — Reconnaissance detection agent."""

    name = "SCOUT"
    description = "Recon detection: port scans, attacker profiling, honeypots"
    trigger_patterns = [
        r"scan\.detected|port\s*scan",
        r"recon|reconnaissance",
        r"nmap|masscan|shodan",
        r"honeypot|decoy",
        r"enumerat|probe|sweep",
        r"napse.*conn|connection.*flood",
    ]
    allowed_tools = ["honeypot_redirect", "scan_fingerprint", "profile_attacker"]
    confidence_threshold = 0.6

    def respond_to_signal(
        self,
        signal: StandardSignal,
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResponse:
        """Handle reconnaissance signals."""
        source_ip = signal.data.get("source_ip", "unknown")
        scan_type = signal.data.get("scan_type", "unknown")
        ports_scanned = signal.data.get("ports_scanned", 0)
        tool = signal.data.get("tool_fingerprint", "")

        if ports_scanned > 100 or signal.severity in ("HIGH", "CRITICAL"):
            return AgentResponse(
                agent=self.name,
                action="honeypot_redirect",
                confidence=0.85,
                reasoning=(
                    f"Aggressive scan from {source_ip}: {ports_scanned} ports "
                    f"({scan_type}). Redirecting to honeypot."
                ),
                user_message=(
                    f"Detected network scanning from {source_ip} "
                    f"({ports_scanned} ports scanned). "
                    f"This is like someone testing every door and window. "
                    f"Redirected to decoy service for monitoring."
                ),
                tool_calls=[{
                    "name": "honeypot_redirect",
                    "params": {"source_ip": source_ip},
                }],
                sources=["QSecBit", "NAPSE"],
            )
        else:
            return AgentResponse(
                agent=self.name,
                action="scan_fingerprint",
                confidence=0.6,
                reasoning=f"Scan activity from {source_ip}: {scan_type}",
                user_message=(
                    f"Monitoring scan activity from {source_ip} "
                    f"({scan_type or 'type unknown'}). "
                    f"{'Tool: ' + tool if tool else 'Identifying scanning tool.'}"
                ),
                tool_calls=[{
                    "name": "scan_fingerprint",
                    "params": {"source_ip": source_ip},
                }],
                sources=["QSecBit", "NAPSE"],
            )

    def respond_to_query(
        self,
        message: str,
        history: List[ChatMessage],
        context: Optional[Dict[str, Any]] = None,
    ) -> ChatResponse:
        """Handle user queries about reconnaissance and scanning."""
        system_prompt = self.get_system_prompt(context)
        ctx_str = self._build_context_str()

        messages = [
            {"role": "system", "content": system_prompt},
        ]
        for msg in history[-10:]:
            messages.append({"role": msg.role, "content": msg.content})
        messages.append({
            "role": "user",
            "content": f"{message}\n\n---\n[RECON DETECTION DATA]\n{ctx_str}",
        })

        content = self._llm_chat(messages)
        if content:
            return ChatResponse(
                message=content, agent=self.name, confidence=0.85,
                sources=["QSecBit", "NAPSE"],
            )

        return ChatResponse(
            message="I detect network reconnaissance and scanning activity. "
                    "Ask me about recent scans, attacker profiles, or honeypot status.",
            agent=self.name, confidence=0.4, sources=["template"],
        )
