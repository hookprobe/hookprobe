"""
SHIELD Agent — Endpoint Protection

Handles device classification, policy assignment, and ecosystem bubble management.
Works with ML fingerprinting, mDNS, and DHCP data.
"""

import logging
from typing import Any, Dict, List, Optional

from .base import BaseAgent
from ..types import AgentResponse, ChatMessage, ChatResponse, StandardSignal

logger = logging.getLogger(__name__)


class ShieldAgent(BaseAgent):
    """SHIELD — Endpoint protection agent."""

    name = "SHIELD"
    description = "Endpoint protection: device classification, policy, bubbles"
    trigger_patterns = [
        r"device\.new|new.*device|dhcp.*(?:ack|discover)",
        r"mdns|bonjour|avahi",
        r"fingerprint|classify",
        r"bubble|ecosystem",
        r"endpoint|policy.*assign",
        r"iot|smart.*(?:home|device)",
    ]
    allowed_tools = ["classify_device", "assign_policy", "move_bubble"]
    confidence_threshold = 0.6

    def respond_to_signal(
        self,
        signal: StandardSignal,
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResponse:
        """Handle device-related signals."""
        mac = signal.data.get("mac", "unknown")
        hostname = signal.data.get("hostname", "")
        vendor = signal.data.get("vendor", "")
        device_type = signal.data.get("device_type", "unknown")

        if signal.event_type in ("device.new", "new_device"):
            return AgentResponse(
                agent=self.name,
                action="classify_device",
                confidence=0.8,
                reasoning=f"New device {mac} ({vendor}) — classifying and assigning policy",
                user_message=(
                    f"New device detected: **{hostname or vendor or mac}**\n"
                    f"- MAC: {mac}\n"
                    f"- Vendor: {vendor or 'unknown'}\n"
                    f"- Assigned to Guest bubble for now.\n\n"
                    f"I'll analyze its behavior to find its best group."
                ),
                tool_calls=[{
                    "name": "classify_device",
                    "params": {"mac": mac, "hostname": hostname, "vendor": vendor},
                }],
                sources=["DeviceManager", "DHCP"],
            )
        elif "affinity" in signal.event_type:
            related_mac = signal.data.get("related_mac", "")
            affinity = signal.data.get("affinity_score", 0.0)
            return AgentResponse(
                agent=self.name,
                action="move_bubble" if affinity > 0.75 else "",
                confidence=affinity,
                reasoning=f"Affinity {affinity:.0%} between {mac} and {related_mac}",
                user_message=(
                    f"Detected relationship between devices "
                    f"(affinity: {affinity:.0%}). "
                    f"{'Suggesting bubble merge.' if affinity > 0.75 else 'Monitoring.'}"
                ),
                sources=["EcosystemBubble"],
            )
        else:
            return AgentResponse(
                agent=self.name,
                action="",
                confidence=0.5,
                reasoning=f"Device event: {signal.event_type} for {mac}",
                user_message=f"Device activity detected for {hostname or mac}.",
                sources=["DeviceManager"],
            )

    def respond_to_query(
        self,
        message: str,
        history: List[ChatMessage],
        context: Optional[Dict[str, Any]] = None,
    ) -> ChatResponse:
        """Handle user queries about devices and endpoints."""
        system_prompt = self.get_system_prompt(context)
        devices = self.fabric.get_device_list()

        device_lines = []
        for d in devices[:15]:
            hostname = d.get("hostname") or "unnamed"
            mac = d.get("mac") or ""
            vendor = d.get("vendor") or ""
            dtype = d.get("device_type") or ""
            bubble = d.get("bubble") or ""
            device_lines.append(f"  {hostname} | {mac} | {vendor} | {dtype} | {bubble}")

        ctx_str = (
            f"Connected Devices: {len(devices)}\n"
            f"Device List:\n" + "\n".join(device_lines)
        )

        messages = [
            {"role": "system", "content": system_prompt},
        ]
        for msg in history[-10:]:
            messages.append({"role": msg.role, "content": msg.content})
        messages.append({
            "role": "user",
            "content": f"{message}\n\n---\n[DEVICE DATA]\n{ctx_str}",
        })

        content = self._llm_chat(messages)
        if content:
            return ChatResponse(
                message=content, agent=self.name, confidence=0.85,
                sources=["DeviceManager", "EcosystemBubble"],
            )

        return ChatResponse(
            message=f"There are **{len(devices)}** devices connected. "
                    f"Ask me about specific devices or bubble assignments.",
            agent=self.name, confidence=0.4, sources=["template"],
        )
