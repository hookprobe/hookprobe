"""
ORACLE Agent - Status, Q&A, and Advisory

The conversational brain of AEGIS. Gathers data from the SignalFabric,
reasons via the LLM, and responds in plain English.

Falls back to keyword-matching templates when the LLM is unavailable.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional

from .inference import NativeInferenceEngine
from .signal_fabric import SignalFabric
from .types import ChatMessage, ChatResponse

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are ORACLE, the AI security advisor for HookProbe — a network \
security gateway. You help non-technical users understand their network \
security posture in plain English.

Your personality:
- Professional but approachable — explain like a trusted IT person
- Concise — keep answers under 200 words unless detail is requested
- Actionable — always include a recommendation when relevant
- Honest — if you don't know, say so; never fabricate data

You have access to real-time signals:
- QSecBit: AI-powered security score (GREEN/AMBER/RED)
- dnsXai: DNS protection blocking ads, trackers, and malware domains
- SLA AI: WAN/internet connection health monitoring
- Device Manager: Connected device inventory

When presenting data:
- Use the provided context, do not invent numbers
- Format MAC addresses as XX:XX:XX:XX:XX:XX
- Format percentages as whole numbers (e.g., 95%)
- Use bullet points for lists

Current network context will be provided with each question.\
"""

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


class OracleAgent:
    """ORACLE agent — status, Q&A, and advisory."""

    def __init__(self, engine: NativeInferenceEngine, fabric: SignalFabric):
        self.engine = engine
        self.fabric = fabric

    def respond(self, user_message: str, history: List[ChatMessage]) -> ChatResponse:
        """Generate a response to a user message.

        Tries the LLM first; falls back to templates if unavailable.
        """
        # Always gather context
        context = self._build_context()

        # Try LLM path
        if self.engine.is_ready:
            response = self._llm_respond(user_message, history, context)
            if response:
                return response

        # Template fallback
        return self._template_respond(user_message, context)

    def _build_context(self) -> Dict[str, Any]:
        """Gather all signal data for LLM context."""
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
        # Build message list
        messages: List[Dict[str, str]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
        ]

        # Add conversation history (last 20 messages)
        for msg in history[-20:]:
            messages.append({"role": msg.role, "content": msg.content})

        # Build context block
        context_block = self._format_context_block(context)

        # Add current user message with context
        messages.append({
            "role": "user",
            "content": f"{user_message}\n\n---\n[LIVE NETWORK DATA]\n{context_block}",
        })

        response = self.engine.chat(messages)
        if not response:
            return None

        content = response.get("message", {}).get("content", "")
        if not content:
            return None

        # Determine sources used
        sources = []
        if "qsecbit" in user_message.lower() or "security" in user_message.lower():
            sources.append("QSecBit")
        if "dns" in user_message.lower() or "block" in user_message.lower():
            sources.append("dnsXai")
        if "device" in user_message.lower() or "connect" in user_message.lower():
            sources.append("DeviceManager")
        if "wan" in user_message.lower() or "internet" in user_message.lower():
            sources.append("SLA AI")
        if not sources:
            sources = ["QSecBit", "dnsXai", "DeviceManager", "SLA AI"]

        return ChatResponse(
            message=content,
            agent="ORACLE",
            confidence=0.9,
            sources=sources,
        )

    def _format_context_block(self, context: Dict[str, Any]) -> str:
        """Format context data as a readable block for the LLM."""
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

        # Add threat details if any
        threats = context.get("threats", [])
        if threats:
            lines.append(f"\nRecent Threats ({len(threats)}):")
            for t in threats[:5]:
                lines.append(
                    f"  - {t.get('type', 'UNKNOWN')} [{t.get('severity', 'LOW')}] "
                    f"from {t.get('source_ip', 'unknown')} — {t.get('description', '')}"
                )

        # Add device summary
        devices = self.fabric.get_device_list()
        if devices:
            lines.append(f"\nDevices ({len(devices)}):")
            for d in devices[:10]:
                hostname = d.get("hostname") or "unnamed"
                mac = d.get("mac") or d.get("mac_address") or ""
                vendor = d.get("vendor") or ""
                lines.append(f"  - {hostname} ({mac}) {vendor}")

        return "\n".join(lines)

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

        # Build extra context for specific templates
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
            agent="ORACLE",
            confidence=0.5 if template_key != "fallback" else 0.3,
            sources=["template"],
        )
