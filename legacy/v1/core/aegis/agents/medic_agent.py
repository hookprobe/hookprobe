"""
MEDIC Agent — Incident Response

Coordinates across all agents during incidents. Handles full quarantine,
forensic capture, and incident timeline reconstruction.
"""

import logging
from typing import Any, Dict, List, Optional

from .base import BaseAgent
from ..types import AgentResponse, ChatMessage, ChatResponse, StandardSignal

logger = logging.getLogger(__name__)


class MedicAgent(BaseAgent):
    """MEDIC — Incident response agent."""

    name = "MEDIC"
    description = "Incident response: quarantine, forensics, incident timeline"
    trigger_patterns = [
        r"incident|emergency|breach",
        r"quarantine|isolat",
        r"forensic|evidence|capture",
        r"timeline|investigation",
        r"(?:multi|cross).*agent.*(?:trigger|alert|escalat)",
        r"qsecbit.*red|critical.*threat",
        r"coordinated.*attack",
        # HYDRA SENTINEL escalation patterns
        r"hydra.*campaign",
        r"hydra.*verdict.*malicious",
        r"sentinel.*campaign|sentinel.*coordinated",
    ]
    allowed_tools = [
        "full_quarantine", "forensic_capture", "incident_timeline",
        "sentinel_campaign_info",
    ]
    confidence_threshold = 0.8  # Higher threshold — MEDIC actions are disruptive

    def respond_to_signal(
        self,
        signal: StandardSignal,
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResponse:
        """Handle escalated incidents, cross-agent correlations, and HYDRA campaigns."""
        # HYDRA SENTINEL campaign escalation
        if signal.source == "hydra":
            return self._handle_hydra_escalation(signal, context)

        source_ip = signal.data.get("source_ip", "unknown")
        related_agents = signal.data.get("related_agents", [])
        attack_chain = signal.data.get("attack_chain", [])

        if signal.severity == "CRITICAL" or len(related_agents) >= 2:
            timeline = self._build_timeline(signal, context)
            return AgentResponse(
                agent=self.name,
                action="full_quarantine",
                confidence=0.9,
                reasoning=(
                    f"Multi-vector incident: {', '.join(related_agents) if related_agents else signal.event_type}. "
                    f"Source: {source_ip}. Initiating quarantine."
                ),
                user_message=(
                    f"**Incident Response Activated**\n\n"
                    f"A coordinated attack was detected involving "
                    f"{', '.join(related_agents) if related_agents else 'multiple signals'}.\n\n"
                    f"{timeline}\n\n"
                    f"Action taken: Quarantined source ({source_ip}). "
                    f"Your network is protected."
                ),
                tool_calls=[{
                    "name": "full_quarantine",
                    "params": {"source_ip": source_ip, "reason": "coordinated attack"},
                }],
                sources=["QSecBit", "NAPSE", "dnsXai"],
            )
        else:
            return AgentResponse(
                agent=self.name,
                action="incident_timeline",
                confidence=0.7,
                reasoning=f"Incident signal: {signal.event_type} from {source_ip}",
                user_message=(
                    f"Investigating incident: {signal.event_type}. "
                    f"Building timeline and assessing impact."
                ),
                tool_calls=[{
                    "name": "incident_timeline",
                    "params": {"source_ip": source_ip},
                }],
                sources=["QSecBit"],
            )

    def respond_to_query(
        self,
        message: str,
        history: List[ChatMessage],
        context: Optional[Dict[str, Any]] = None,
    ) -> ChatResponse:
        """Handle user queries about incidents and forensics."""
        system_prompt = self.get_system_prompt(context)
        ctx_str = self._build_context_str()

        # Include recent decisions in context
        if self.memory:
            decisions = self.memory.get_recent_decisions(limit=10)
            if decisions:
                dec_lines = ["Recent Agent Decisions:"]
                for d in decisions[:5]:
                    dec_lines.append(
                        f"  {d.timestamp} | {d.agent} | {d.action} | "
                        f"confidence={d.confidence:.0%}"
                    )
                ctx_str += "\n\n" + "\n".join(dec_lines)

        messages = [
            {"role": "system", "content": system_prompt},
        ]
        for msg in history[-10:]:
            messages.append({"role": msg.role, "content": msg.content})
        messages.append({
            "role": "user",
            "content": f"{message}\n\n---\n[INCIDENT DATA]\n{ctx_str}",
        })

        content = self._llm_chat(messages)
        if content:
            return ChatResponse(
                message=content, agent=self.name, confidence=0.85,
                sources=["QSecBit", "AuditTrail"],
            )

        return ChatResponse(
            message="I'm the incident response coordinator. "
                    "Ask me about active incidents, quarantined devices, "
                    "or recent security events.",
            agent=self.name, confidence=0.4, sources=["template"],
        )

    def _handle_hydra_escalation(
        self,
        signal: StandardSignal,
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResponse:
        """Handle HYDRA SENTINEL escalation — campaigns and malicious verdicts."""
        ip = signal.data.get("ip", "unknown")
        campaign_id = signal.data.get("campaign_id", "")
        score = signal.data.get("sentinel_score", 0.0)

        if signal.event_type == "campaign_detected":
            timeline = self._build_timeline(signal, context)
            return AgentResponse(
                agent=self.name,
                action="forensic_capture",
                confidence=0.9,
                reasoning=(
                    f"SENTINEL campaign {campaign_id} escalated to MEDIC. "
                    f"IP {ip} (score={score:.2f}). Initiating forensic capture."
                ),
                user_message=(
                    f"**Campaign Response Activated**\n\n"
                    f"HYDRA SENTINEL detected coordinated campaign `{campaign_id}` "
                    f"involving IP {ip} (threat score: {score:.0%}).\n\n"
                    f"{timeline}\n\n"
                    f"Action: Forensic capture started. Building incident timeline."
                ),
                tool_calls=[
                    {
                        "name": "forensic_capture",
                        "params": {"source_ip": ip, "duration": 120},
                    },
                    {
                        "name": "sentinel_campaign_info",
                        "params": {"campaign_id": campaign_id},
                    },
                ],
                sources=["SENTINEL", "HYDRA"],
            )

        if signal.event_type == "verdict.malicious":
            return AgentResponse(
                agent=self.name,
                action="incident_timeline",
                confidence=0.85,
                reasoning=(
                    f"SENTINEL malicious verdict for {ip} "
                    f"(score={score:.2f}) escalated to MEDIC"
                ),
                user_message=(
                    f"Investigating malicious IP {ip} — HYDRA SENTINEL "
                    f"threat score: {score:.0%}. Building incident timeline."
                ),
                tool_calls=[{
                    "name": "incident_timeline",
                    "params": {"source_ip": ip},
                }],
                sources=["SENTINEL", "HYDRA"],
            )

        # Other HYDRA signals (drift, retrain) — log and monitor
        return AgentResponse(
            agent=self.name,
            action="",
            confidence=0.5,
            reasoning=f"HYDRA event {signal.event_type} noted by MEDIC",
            user_message=f"HYDRA SENTINEL event: {signal.event_type}. Logged for tracking.",
            sources=["SENTINEL"],
        )

    def _build_timeline(
        self,
        signal: StandardSignal,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Build an incident timeline from available data."""
        lines = ["**Incident Timeline:**"]
        lines.append(
            f"- {signal.timestamp.strftime('%H:%M:%S')} — "
            f"{signal.event_type} detected [{signal.severity}] "
            f"(source: {signal.source})"
        )

        # Add related events from context
        if context and "related_signals" in context:
            for s in context["related_signals"][:5]:
                ts = s.get("timestamp", "")
                lines.append(
                    f"- {ts} — {s.get('event_type', 'unknown')} "
                    f"[{s.get('severity', 'LOW')}] "
                    f"(source: {s.get('source', 'unknown')})"
                )

        return "\n".join(lines)
