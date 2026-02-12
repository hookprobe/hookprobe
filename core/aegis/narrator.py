"""
AEGIS Narrator — Response Formatting

Formats agent responses into human-readable messages for different
output channels: chat, notifications, and dashboard cards.

Two narration modes:
  1. TemplateNarrator — Fast, always available (template-based)
  2. LLMNarrator — Rich, context-aware (requires LLM backend)
"""

import logging
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .types import AgentResponse, StandardSignal

if TYPE_CHECKING:
    from .inference import NativeInferenceEngine

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Per-Agent Narrative Templates
# ------------------------------------------------------------------

ACTION_TEMPLATES = {
    # GUARDIAN
    "block_ip": (
        "Blocked IP **{ip}** — {reason}. "
        "Your network is protected from this traffic source."
    ),
    "rate_limit": (
        "Rate-limited traffic from **{ip}** — {reason}. "
        "Monitoring for escalation."
    ),
    "quarantine_subnet": (
        "Quarantined subnet **{subnet}** — {reason}. "
        "Devices in this range are isolated."
    ),
    "unblock_ip": "Unblocked IP **{ip}**. Traffic from this source is now allowed.",

    # WATCHDOG
    "block_domain": (
        "Blocked domain **{domain}** — {reason}. "
        "DNS queries to this domain are now filtered."
    ),
    "whitelist_domain": (
        "Whitelisted **{domain}**. This domain will no longer be blocked."
    ),
    "adjust_protection": "DNS protection level changed to **{level}/5**.",

    # SHIELD
    "classify_device": (
        "Classified device **{mac}** as {device_type}. "
        "Assigned to {bubble} bubble."
    ),
    "assign_policy": "Security policy updated for **{mac}**: {policy}.",
    "move_bubble": "Moved device **{mac}** to **{bubble_id}** bubble.",

    # VIGIL
    "block_ssl_strip": (
        "Blocked SSL stripping attack from **{source_ip}**. "
        "Your encrypted connections are protected."
    ),
    "enforce_tls": "Enforced TLS {min_version}+ for connections to **{destination}**.",
    "terminate_session": "Terminated compromised session — {reason}.",

    # SCOUT
    "honeypot_redirect": (
        "Redirected attacker **{source_ip}** to honeypot. "
        "Monitoring their behavior for intelligence."
    ),
    "scan_fingerprint": "Identified scanning tool from **{source_ip}**: {tool}.",
    "profile_attacker": "Built attacker profile for **{source_ip}**.",

    # FORGE
    "generate_password": "Generated new secure password for {purpose}.",
    "rotate_wifi": "WiFi password rotation initiated for {band} band.",
    "recommend_hardening": "Security hardening report generated.",

    # MEDIC
    "full_quarantine": (
        "**QUARANTINE ACTIVE**: Isolated {source_ip} from all network access — {reason}."
    ),
    "forensic_capture": "Forensic packet capture started for **{source_ip}** ({duration}s).",
    "incident_timeline": "Incident timeline generated for the last {hours} hours.",
}

THREAT_TEMPLATES = {
    "CRITICAL": (
        "**CRITICAL THREAT DETECTED**\n\n"
        "{description}\n\n"
        "Action taken: {action_taken}\n"
        "Your network is protected."
    ),
    "HIGH": (
        "**High-severity event detected**\n\n"
        "{description}\n\n"
        "Action: {action_taken}"
    ),
    "MEDIUM": "Suspicious activity detected: {description}. Monitoring.",
    "LOW": "Minor event: {description}.",
    "INFO": "{description}",
}

STATUS_TEMPLATE = (
    "**Network Status**\n\n"
    "- Security: {status} ({score:.0%})\n"
    "- Devices: {device_count} connected\n"
    "- DNS blocked: {dns_blocked} today\n"
    "- Internet: {wan_status}\n"
    "- Active agents: {agent_count}"
)


class TemplateNarrator:
    """Fast template-based narration (no LLM required)."""

    def narrate_action(
        self,
        agent: str,
        action: str,
        result: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Narrate an action taken by an agent."""
        template = ACTION_TEMPLATES.get(action)
        if not template:
            return f"**{agent}** executed {action}: {result}"

        try:
            safe_params = _SafeDict(params or {})
            safe_params.setdefault("reason", "security policy")
            safe_params.setdefault("device_type", "unknown")
            safe_params.setdefault("bubble", "default")
            safe_params.setdefault("tool", "unknown")
            safe_params.setdefault("min_version", "1.2")
            safe_params.setdefault("purpose", "general")
            safe_params.setdefault("band", "both")
            safe_params.setdefault("duration", "60")
            safe_params.setdefault("hours", "24")
            return template.format_map(safe_params)
        except Exception:
            return f"**{agent}** executed {action}: {result}"

    def narrate_status(self, summary: Dict[str, Any]) -> str:
        """Narrate the current network status."""
        try:
            return STATUS_TEMPLATE.format_map(_SafeDict(summary))
        except Exception:
            return "Network status is being monitored."

    def narrate_threat(
        self,
        threat: Dict[str, Any],
        action_taken: str = "monitoring",
    ) -> str:
        """Narrate a threat event."""
        severity = threat.get("severity", "INFO")
        template = THREAT_TEMPLATES.get(severity, THREAT_TEMPLATES["INFO"])

        try:
            return template.format(
                description=threat.get("description", "Threat detected"),
                action_taken=action_taken,
            )
        except Exception:
            return f"[{severity}] Threat detected. Action: {action_taken}"

    def narrate_signal(self, signal: StandardSignal) -> str:
        """Narrate a raw signal for logging/notification."""
        return (
            f"[{signal.severity}] {signal.source}: {signal.event_type} "
            f"at {signal.timestamp.strftime('%H:%M:%S')}"
        )


class LLMNarrator:
    """LLM-powered narration for complex multi-agent scenarios."""

    def __init__(self, engine: "NativeInferenceEngine"):
        self._engine = engine
        self._template = TemplateNarrator()

    def narrate_complex(
        self,
        agent_responses: List[AgentResponse],
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Narrate a multi-agent response using the LLM.

        Falls back to template narration if LLM unavailable.
        """
        if not self._engine.is_ready or len(agent_responses) <= 1:
            return self._template_fallback(agent_responses)

        # Build LLM prompt
        response_text = "\n".join(
            f"- {r.agent}: {r.action or 'advisory'} — {r.reasoning}"
            for r in agent_responses
        )

        messages = [
            {
                "role": "system",
                "content": (
                    "You are AEGIS, an AI security assistant. "
                    "Summarize the following agent responses into a single, "
                    "clear message for a non-technical user. "
                    "Be concise (under 100 words). Use bullet points."
                ),
            },
            {
                "role": "user",
                "content": f"Multiple agents responded:\n{response_text}",
            },
        ]

        result = self._engine.chat(messages, max_tokens=200)
        if result:
            content = result.get("message", {}).get("content", "")
            if content:
                return content

        return self._template_fallback(agent_responses)

    def _template_fallback(self, responses: List[AgentResponse]) -> str:
        """Fallback narration when LLM is unavailable."""
        if not responses:
            return "No actions taken."
        if len(responses) == 1:
            r = responses[0]
            return r.user_message or f"{r.agent}: {r.action or 'monitoring'}"

        lines = ["**Multiple agents responded:**\n"]
        for r in responses:
            lines.append(f"- **{r.agent}**: {r.user_message or r.reasoning}")
        return "\n".join(lines)


# ------------------------------------------------------------------
# Output Formatters
# ------------------------------------------------------------------

def format_chat(message: str, agent: str = "ORACLE") -> Dict[str, Any]:
    """Format a message for the chat UI."""
    return {
        "message": message,
        "agent": agent,
        "type": "chat",
    }


def format_notification(
    message: str,
    severity: str = "INFO",
    agent: str = "AEGIS",
) -> Dict[str, Any]:
    """Format a message as a notification."""
    return {
        "message": message,
        "severity": severity,
        "agent": agent,
        "type": "notification",
    }


def format_dashboard_card(
    title: str,
    content: str,
    agent: str = "ORACLE",
    severity: str = "INFO",
) -> Dict[str, Any]:
    """Format a message as a dashboard card."""
    return {
        "title": title,
        "content": content,
        "agent": agent,
        "severity": severity,
        "type": "dashboard_card",
    }


class _SafeDict(dict):
    """Dict that returns the key name for missing keys."""
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"
