"""
ORACLE Agent — Status, Q&A, and Advisory

The primary conversational interface and default agent for user queries.
Refactored from core/aegis/oracle.py to use the BaseAgent framework.
"""

import logging
import re
from typing import Any, Dict, List, Optional

from .base import BaseAgent
from ..types import AgentResponse, ChatMessage, ChatResponse, StandardSignal

logger = logging.getLogger(__name__)

# Template responses for when LLM is unavailable
TEMPLATE_RESPONSES = {
    "status": (
        "Here's your current network status:\n\n"
        "- **Security**: {qsecbit_status} (Score: {qsecbit_score:.0%})\n"
        "- **Devices**: {device_count} connected\n"
        "- **DNS Protection**: {dns_blocked_24h} queries blocked today\n"
        "- **Internet**: {wan_status} (Health: {wan_primary_health}%)\n"
        "- **Threats**: {threat_count} detected in last 24h\n\n"
        "*AEGIS is running in offline mode — connect an LLM for detailed analysis.*"
    ),
    "threats": (
        "In the last 24 hours, **{threat_count}** threat(s) were detected.\n\n"
        "{threat_details}\n\n"
        "Your security status is **{qsecbit_status}**."
    ),
    "devices": (
        "There are **{device_count}** device(s) currently connected to your network.\n\n"
        "{device_details}\n\n"
        "*Connect an LLM for detailed device analysis.*"
    ),
    "dns": (
        "dnsXai DNS Protection Statistics:\n\n"
        "- **Blocked today**: {dns_blocked_24h} queries\n"
        "- **Total queries**: {dns_total_queries}\n"
        "- **Protection level**: {dns_protection_level}/5\n\n"
        "dnsXai uses ML to block ads, trackers, and malware domains."
    ),
    "qsecbit": (
        "**QSecBit Security Score**: {qsecbit_score:.0%} ({qsecbit_status})\n\n"
        "QSecBit is HookProbe's AI-powered security metric that monitors your "
        "network across all 7 OSI layers (L2-L7).\n\n"
        "- **GREEN** (>55%): All clear, network is protected\n"
        "- **AMBER** (30-55%): Investigating suspicious activity\n"
        "- **RED** (<30%): Active threat mitigation in progress\n\n"
        "Your current status is **{qsecbit_status}**."
    ),
    "help": (
        "I'm **ORACLE**, your AI security advisor. I can help with:\n\n"
        "- **Network Status** — \"What's my network status?\"\n"
        "- **Threats** — \"Are there any threats?\"\n"
        "- **Devices** — \"How many devices are connected?\"\n"
        "- **DNS Protection** — \"How is DNS protection doing?\"\n"
        "- **Security Score** — \"Explain my security score\"\n\n"
        "Just ask me anything about your network security!"
    ),
    "fallback": (
        "I understand your question, but I'm currently running in offline mode "
        "without an LLM connection.\n\n"
        "I can still show you:\n"
        "- Network status\n"
        "- Device list\n"
        "- Threat summary\n"
        "- DNS statistics\n\n"
        "Try asking \"What is my network status?\" for a quick overview."
    ),
}

# Keyword patterns for template matching
_PATTERNS = [
    (re.compile(r"status|overview|summary|how.*network", re.I), "status"),
    (re.compile(r"threat|attack|danger|risk|alert", re.I), "threats"),
    (re.compile(r"device|connected|client|how many", re.I), "devices"),
    (re.compile(r"dns|block|ad|tracker|dnsxai", re.I), "dns"),
    (re.compile(r"qsecbit|score|rag|green|amber|red|security score", re.I), "qsecbit"),
    (re.compile(r"help|what can you|who are you|hello|hi\b", re.I), "help"),
]


class OracleAgentV2(BaseAgent):
    """ORACLE — Status, Q&A, and Advisory agent."""

    name = "ORACLE"
    description = "Forecasting, advisory, and user Q&A"
    trigger_patterns = [
        r"status|overview|summary",
        r"threat|attack|alert",
        r"device|connected|client",
        r"dns|block|tracker",
        r"qsecbit|score|security",
        r"help|hello|hi\b",
        r"what|how|why|when|explain",
        r"user\.query",
    ]
    allowed_tools = ["trend_analysis", "generate_report", "risk_score"]
    confidence_threshold = 0.5  # Lower threshold — ORACLE handles everything

    def respond_to_signal(
        self,
        signal: StandardSignal,
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResponse:
        """Handle automated signals — ORACLE generates summaries."""
        ctx = self._build_signal_context()

        # For signals, generate a brief summary
        summary = (
            f"Network event: {signal.event_type} from {signal.source} "
            f"[{signal.severity}]"
        )

        return AgentResponse(
            agent=self.name,
            action="",
            confidence=0.7,
            reasoning=f"Signal from {signal.source}: {signal.event_type}",
            user_message=summary,
            sources=[signal.source],
        )

    def respond_to_query(
        self,
        message: str,
        history: List[ChatMessage],
        context: Optional[Dict[str, Any]] = None,
    ) -> ChatResponse:
        """Handle user chat queries."""
        ctx = self._build_signal_context()

        # Try LLM path
        if self.engine.is_ready:
            response = self._llm_respond(message, history, ctx)
            if response:
                return response

        # Template fallback
        return self._template_respond(message, ctx)

    def can_handle_query(self, message: str) -> float:
        """ORACLE is the default — it can handle anything."""
        # Check specific patterns first
        for pattern in self._compiled_patterns:
            if pattern.search(message):
                return 0.8

        # ORACLE is always a fallback
        return 0.3

    def _build_signal_context(self) -> Dict[str, Any]:
        """Gather all signal data for context."""
        summary = self.fabric.get_network_summary()
        dns = self.fabric.get_dns_stats()
        threats = self.fabric.get_recent_threats()

        return {
            "qsecbit_score": summary.qsecbit_score,
            "qsecbit_status": summary.qsecbit_status,
            "device_count": summary.device_count,
            "threat_count": summary.threat_count,
            "dns_blocked_24h": summary.dns_blocked_24h,
            "dns_total_queries": dns.get("total_queries", 0),
            "dns_protection_level": dns.get("protection_level", 3),
            "wan_status": summary.wan_status,
            "wan_primary_health": summary.wan_primary_health,
            "threats": [t.model_dump() for t in threats[:10]],
        }

    def _llm_respond(
        self,
        user_message: str,
        history: List[ChatMessage],
        context: Dict[str, Any],
    ) -> Optional[ChatResponse]:
        """Generate response using the LLM."""
        system_prompt = self.get_system_prompt(context)

        messages = [{"role": "system", "content": system_prompt}]

        # Add conversation history
        for msg in history[-20:]:
            messages.append({"role": msg.role, "content": msg.content})

        # Add context block
        context_block = self._format_context_block(context)
        messages.append({
            "role": "user",
            "content": f"{user_message}\n\n---\n[LIVE NETWORK DATA]\n{context_block}",
        })

        content = self._llm_chat(messages)
        if not content:
            return None

        # Determine sources
        sources = self._detect_sources(user_message)

        return ChatResponse(
            message=content,
            agent=self.name,
            confidence=0.9,
            sources=sources,
        )

    def _format_context_block(self, context: Dict[str, Any]) -> str:
        """Format context data for the LLM."""
        lines = [
            f"QSecBit Score: {context['qsecbit_score']:.0%} ({context['qsecbit_status']})",
            f"Connected Devices: {context['device_count']}",
            f"Threats (24h): {context['threat_count']}",
            f"DNS Blocked (24h): {context['dns_blocked_24h']}",
            f"DNS Total Queries: {context['dns_total_queries']}",
            f"DNS Protection Level: {context['dns_protection_level']}/5",
            f"WAN Status: {context['wan_status']}",
            f"WAN Primary Health: {context['wan_primary_health']}%",
        ]

        threats = context.get("threats", [])
        if threats:
            lines.append(f"\nRecent Threats ({len(threats)}):")
            for t in threats[:5]:
                lines.append(
                    f"  - {t.get('type', 'UNKNOWN')} [{t.get('severity', 'LOW')}] "
                    f"from {t.get('source_ip', 'unknown')} — {t.get('description', '')}"
                )

        devices = self.fabric.get_device_list()
        if devices:
            lines.append(f"\nDevices ({len(devices)}):")
            for d in devices[:10]:
                hostname = d.get("hostname") or "unnamed"
                mac = d.get("mac") or d.get("mac_address") or ""
                vendor = d.get("vendor") or ""
                lines.append(f"  - {hostname} ({mac}) {vendor}")

        # Add memory context
        if self.memory:
            mem_ctx = self.memory.recall_context(max_tokens=200)
            if mem_ctx:
                lines.append(f"\n[MEMORY]\n{mem_ctx}")

        return "\n".join(lines)

    def _detect_sources(self, message: str) -> List[str]:
        """Detect which data sources are relevant to the query."""
        sources = []
        msg_lower = message.lower()
        if "qsecbit" in msg_lower or "security" in msg_lower:
            sources.append("QSecBit")
        if "dns" in msg_lower or "block" in msg_lower:
            sources.append("dnsXai")
        if "device" in msg_lower or "connect" in msg_lower:
            sources.append("DeviceManager")
        if "wan" in msg_lower or "internet" in msg_lower:
            sources.append("SLA AI")
        return sources or ["QSecBit", "dnsXai", "DeviceManager", "SLA AI"]

    def _template_respond(
        self,
        user_message: str,
        context: Dict[str, Any],
    ) -> ChatResponse:
        """Generate response using keyword-matching templates."""
        template_key = "fallback"
        for pattern, key in _PATTERNS:
            if pattern.search(user_message):
                template_key = key
                break

        if template_key == "threats":
            threat_lines = []
            for t in context.get("threats", [])[:5]:
                threat_lines.append(
                    f"- **{t.get('type', 'UNKNOWN')}** [{t.get('severity', 'LOW')}] "
                    f"from {t.get('source_ip', 'unknown')}"
                )
            context["threat_details"] = (
                "\n".join(threat_lines) if threat_lines else "No threats detected."
            )

        if template_key == "devices":
            devices = self.fabric.get_device_list()
            device_lines = []
            for d in devices[:10]:
                hostname = d.get("hostname") or "unnamed"
                mac = d.get("mac") or d.get("mac_address") or ""
                vendor = d.get("vendor") or ""
                device_lines.append(f"- **{hostname}** ({mac}) {vendor}")
            context["device_details"] = (
                "\n".join(device_lines) if device_lines else "No device data available."
            )

        try:
            message = TEMPLATE_RESPONSES[template_key].format(**context)
        except (KeyError, IndexError):
            message = TEMPLATE_RESPONSES["fallback"]

        return ChatResponse(
            message=message,
            agent=self.name,
            confidence=0.5 if template_key != "fallback" else 0.3,
            sources=["template"],
        )
