"""
AIOCHI Narrative Engine
Transforms network events into human-readable stories.

This engine takes security alerts, device events, and performance metrics
and translates them into plain English narratives that non-technical users
can understand.

Philosophy:
- Template-first (fast, works offline)
- LLM-fallback (for complex/novel situations)
- Persona-aware (parent, gamer, remote worker, privacy-conscious)
"""

import json
import logging
import random
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable

logger = logging.getLogger(__name__)


class Severity(Enum):
    """Event severity levels."""
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class EventCategory(Enum):
    """Event categories for narrative generation."""
    SECURITY = "security"
    DEVICE = "device"
    PERFORMANCE = "performance"
    PRIVACY = "privacy"
    NETWORK = "network"
    UPDATE = "update"


class Persona(Enum):
    """User personas that affect narrative tone."""
    PARENT = "parent"          # Reassuring, family-focused
    GAMER = "gamer"            # Performance-focused, technical
    REMOTE_WORKER = "worker"   # Productivity-focused
    PRIVACY_CONSCIOUS = "privacy"  # Security-focused
    DEFAULT = "default"        # Balanced


@dataclass
class NetworkEvent:
    """Represents a network event to be narrated."""
    event_type: str              # e.g., "new_device", "blocked_threat", "device_offline"
    timestamp: datetime = field(default_factory=datetime.now)
    severity: Severity = Severity.INFO
    category: EventCategory = EventCategory.DEVICE
    device_mac: str = ""
    device_label: str = ""       # Human-friendly name
    source_ip: str = ""
    destination_ip: str = ""
    threat_type: str = ""        # For security events
    blocked: bool = False
    technical_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "category": self.category.value,
            "device_mac": self.device_mac,
            "device_label": self.device_label,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "threat_type": self.threat_type,
            "blocked": self.blocked,
            "technical_details": self.technical_details,
        }


@dataclass
class Narrative:
    """A human-readable narrative for an event."""
    id: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    severity: Severity = Severity.INFO
    category: EventCategory = EventCategory.DEVICE
    device_mac: str = ""
    device_label: str = ""
    headline: str = ""           # Short summary (for notifications)
    narrative: str = ""          # Full human-readable story
    action_required: bool = False
    action_taken: str = ""
    persona: Persona = Persona.DEFAULT
    technical_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "category": self.category.value,
            "device_mac": self.device_mac,
            "device_label": self.device_label,
            "headline": self.headline,
            "narrative": self.narrative,
            "action_required": self.action_required,
            "action_taken": self.action_taken,
            "persona": self.persona.value,
            "technical_details": self.technical_details,
        }


# Narrative templates organized by event type and persona
# Format: {event_type: {persona: [template_variations]}}
NARRATIVE_TEMPLATES: Dict[str, Dict[str, List[str]]] = {
    # Device Events
    "new_device": {
        "parent": [
            "A new device '{device_label}' just joined your network. I'll keep an eye on it!",
            "Welcome! '{device_label}' is now connected. It's learning about your network.",
            "New arrival: '{device_label}' is online. Everything looks normal so far.",
        ],
        "gamer": [
            "New device detected: '{device_label}'. Checking if it impacts your bandwidth...",
            "'{device_label}' joined the network. No interference with your gaming traffic.",
        ],
        "worker": [
            "'{device_label}' connected to your network. Your work connection is still prioritized.",
            "New device: '{device_label}'. Your work apps remain unaffected.",
        ],
        "privacy": [
            "New device '{device_label}' joined. Monitoring for unusual activity.",
            "'{device_label}' is now on your network. I'm watching its traffic patterns.",
        ],
        "default": [
            "New device connected: '{device_label}'.",
            "'{device_label}' just joined your network.",
        ],
    },

    "device_offline": {
        "parent": [
            "'{device_label}' went offline. This might be normal if it's sleeping or turned off.",
            "Heads up: '{device_label}' disconnected. Don't worry if someone just left home!",
        ],
        "gamer": [
            "'{device_label}' disconnected. More bandwidth available for gaming!",
        ],
        "worker": [
            "'{device_label}' went offline. This doesn't affect your work connection.",
        ],
        "privacy": [
            "'{device_label}' disconnected at {time}. Logging this activity.",
        ],
        "default": [
            "'{device_label}' is now offline.",
        ],
    },

    "device_reconnected": {
        "parent": [
            "'{device_label}' is back online. Welcome back!",
            "'{device_label}' reconnected. All systems normal.",
        ],
        "default": [
            "'{device_label}' reconnected to the network.",
        ],
    },

    # Security Events
    "blocked_threat": {
        "parent": [
            "I blocked a suspicious connection to '{device_label}'. Your device is safe!",
            "Good news: I stopped '{device_label}' from connecting to a known bad server. All safe!",
            "'{device_label}' tried to reach a suspicious server. I blocked it - nothing to worry about.",
        ],
        "gamer": [
            "Threat blocked on '{device_label}'. No impact to your gaming session.",
            "Suspicious connection blocked. Your ping remains unaffected.",
        ],
        "worker": [
            "Security alert: Blocked malicious connection from '{device_label}'. Your work is protected.",
            "Threat neutralized on '{device_label}'. Work applications remain secure.",
        ],
        "privacy": [
            "BLOCKED: '{device_label}' attempted connection to {threat_source}. {threat_type} threat neutralized.",
            "Threat blocked: {threat_type} from {threat_source}. '{device_label}' is now safe.",
        ],
        "default": [
            "Blocked suspicious connection from '{device_label}'.",
        ],
    },

    "threat_detected": {
        "parent": [
            "I'm investigating unusual activity on '{device_label}'. I'll let you know what I find.",
            "Noticed something odd on '{device_label}'. Checking it out now...",
        ],
        "privacy": [
            "ALERT: Suspicious activity detected on '{device_label}'. Type: {threat_type}. Investigating.",
        ],
        "default": [
            "Investigating unusual activity on '{device_label}'.",
        ],
    },

    "attack_repelled": {
        "parent": [
            "Someone tried to attack your network but I stopped them. All your devices are safe!",
            "Attack repelled! Your family's devices are protected.",
        ],
        "privacy": [
            "Attack repelled: {threat_type} from {threat_source}. Your network perimeter held.",
        ],
        "default": [
            "External attack blocked. Network secure.",
        ],
    },

    "malware_blocked": {
        "parent": [
            "'{device_label}' almost downloaded something harmful, but I blocked it. Stay safe!",
            "Malware blocked on '{device_label}'. The kids' devices are protected!",
        ],
        "privacy": [
            "Malware blocked: '{device_label}' attempted to download {threat_type}. Connection terminated.",
        ],
        "default": [
            "Malware download blocked on '{device_label}'.",
        ],
    },

    # Privacy Events
    "tracker_blocked": {
        "parent": [
            "Blocked {count} tracking attempts today. Your family's privacy is protected.",
            "I've stopped {count} trackers from following your family online.",
        ],
        "privacy": [
            "{count} trackers blocked in the last hour. Categories: {categories}.",
            "Privacy report: {count} tracking attempts neutralized. Top offender: {top_domain}.",
        ],
        "default": [
            "{count} trackers blocked.",
        ],
    },

    "ad_blocked": {
        "parent": [
            "I've blocked {count} ads today. Cleaner internet for everyone!",
        ],
        "default": [
            "{count} ads blocked today.",
        ],
    },

    # Performance Events
    "speed_degradation": {
        "parent": [
            "Your internet is a bit slower right now. It might be temporary.",
            "I noticed a slowdown. Checking if something is using too much bandwidth...",
        ],
        "gamer": [
            "WARNING: Latency spike detected! Ping increased by {ping_increase}ms.",
            "Network congestion affecting your gaming. Switching to priority mode...",
        ],
        "worker": [
            "Heads up: Internet speed dropped. Video calls might be affected.",
            "Network slowdown detected. Prioritizing your work applications.",
        ],
        "default": [
            "Internet speed reduced. Currently at {speed}Mbps.",
        ],
    },

    "speed_restored": {
        "parent": [
            "Great news! Your internet is back to normal speed.",
        ],
        "gamer": [
            "Connection restored! Ping back to normal.",
        ],
        "default": [
            "Internet speed restored to {speed}Mbps.",
        ],
    },

    "interference_detected": {
        "parent": [
            "Something nearby might be causing WiFi interference. The {device} could be the culprit.",
            "WiFi interference detected. Try moving the {device} away from your router.",
        ],
        "gamer": [
            "WiFi interference detected from {device}. Consider switching to 5GHz band.",
        ],
        "default": [
            "WiFi interference detected. Source: {device}.",
        ],
    },

    # Update Events
    "firmware_update": {
        "parent": [
            "'{device_label}' updated its software successfully. It's now more secure!",
            "Update complete! '{device_label}' is running the latest firmware.",
        ],
        "default": [
            "'{device_label}' firmware updated.",
        ],
    },

    "update_available": {
        "parent": [
            "An update is available for '{device_label}'. I'll install it tonight.",
        ],
        "default": [
            "Update available for '{device_label}'.",
        ],
    },

    # Network Events
    "wan_failover": {
        "parent": [
            "Your main internet went down, but I switched to backup. You're still connected!",
            "Internet hiccup! Don't worry - I switched to your backup connection.",
        ],
        "worker": [
            "Primary WAN failed. Switched to backup. Your work session is uninterrupted.",
        ],
        "default": [
            "Switched to backup internet connection.",
        ],
    },

    "wan_restored": {
        "parent": [
            "Your main internet is back! I've switched back to save your backup data.",
        ],
        "default": [
            "Primary internet connection restored.",
        ],
    },

    "guest_joined": {
        "parent": [
            "A guest '{device_label}' joined your Guest WiFi. They're safely isolated from your main network.",
        ],
        "privacy": [
            "Guest device connected: '{device_label}'. Isolated on guest VLAN. No access to internal resources.",
        ],
        "default": [
            "Guest '{device_label}' connected to Guest WiFi.",
        ],
    },
}

# Headline templates (short versions for notifications)
HEADLINE_TEMPLATES: Dict[str, str] = {
    "new_device": "New device: {device_label}",
    "device_offline": "{device_label} went offline",
    "device_reconnected": "{device_label} is back",
    "blocked_threat": "Threat blocked on {device_label}",
    "threat_detected": "Investigating {device_label}",
    "attack_repelled": "Attack blocked!",
    "malware_blocked": "Malware blocked",
    "tracker_blocked": "{count} trackers blocked",
    "ad_blocked": "{count} ads blocked",
    "speed_degradation": "Internet slower than usual",
    "speed_restored": "Speed restored",
    "interference_detected": "WiFi interference",
    "firmware_update": "{device_label} updated",
    "update_available": "Update available",
    "wan_failover": "Switched to backup internet",
    "wan_restored": "Main internet restored",
    "guest_joined": "Guest connected",
}


class NarrativeEngine:
    """
    Translates network events into human-readable narratives.

    This engine:
    1. Receives events from ClickHouse, Suricata, Zeek, QSecBit, etc.
    2. Looks up device identity (human labels)
    3. Selects appropriate template based on event type and persona
    4. Fills in template with event details
    5. Optionally calls LLM for complex/novel situations
    """

    def __init__(
        self,
        persona: Persona = Persona.DEFAULT,
        identity_engine=None,
        llm_callback: Optional[Callable[[str, Dict], str]] = None,
        use_llm_fallback: bool = True,
    ):
        """
        Initialize the Narrative Engine.

        Args:
            persona: User persona (affects tone and content)
            identity_engine: IdentityEngine instance for device lookups
            llm_callback: Optional callback for LLM-based narration
            use_llm_fallback: Whether to use LLM for unknown events
        """
        self.persona = persona
        self.identity_engine = identity_engine
        self.llm_callback = llm_callback
        self.use_llm_fallback = use_llm_fallback

        # Track recent narratives for deduplication
        self._recent_hashes: List[str] = []
        self._max_recent = 100

    def translate(self, event: NetworkEvent) -> Narrative:
        """
        Translate a network event into a human-readable narrative.

        Args:
            event: NetworkEvent to translate

        Returns:
            Narrative with human-readable content
        """
        # Get device label if we have an identity engine
        device_label = event.device_label
        if not device_label and event.device_mac and self.identity_engine:
            identity = self.identity_engine.get_identity(event.device_mac)
            if identity:
                device_label = identity.human_label

        # Create narrative object
        narrative = Narrative(
            id=self._generate_id(),
            timestamp=event.timestamp,
            severity=event.severity,
            category=event.category,
            device_mac=event.device_mac,
            device_label=device_label or event.device_mac or "Unknown device",
            persona=self.persona,
            technical_details=event.technical_details,
        )

        # Get template-based narrative
        narrative_text = self._get_template_narrative(event, narrative.device_label)
        headline = self._get_headline(event, narrative.device_label)

        # If no template found and LLM available, use LLM
        if not narrative_text and self.use_llm_fallback and self.llm_callback:
            narrative_text = self._get_llm_narrative(event, narrative.device_label)
            headline = self._extract_headline(narrative_text)

        # Fallback to generic message
        if not narrative_text:
            narrative_text = f"Event: {event.event_type} on {narrative.device_label}"
            headline = f"{event.event_type.replace('_', ' ').title()}"

        narrative.narrative = narrative_text
        narrative.headline = headline

        # Determine if action is required
        if event.severity in (Severity.HIGH, Severity.CRITICAL) and not event.blocked:
            narrative.action_required = True

        # Note any automated action taken
        if event.blocked:
            narrative.action_taken = "Automatically blocked"

        return narrative

    def _get_template_narrative(self, event: NetworkEvent, device_label: str) -> Optional[str]:
        """Get narrative from templates."""
        event_templates = NARRATIVE_TEMPLATES.get(event.event_type, {})

        # Try persona-specific template first
        templates = event_templates.get(self.persona.value, [])

        # Fall back to default
        if not templates:
            templates = event_templates.get("default", [])

        if not templates:
            return None

        # Select random template for variety
        template = random.choice(templates)

        # Fill in template variables
        return self._fill_template(template, event, device_label)

    def _get_headline(self, event: NetworkEvent, device_label: str) -> str:
        """Get headline from templates."""
        template = HEADLINE_TEMPLATES.get(event.event_type, event.event_type.replace("_", " ").title())
        return self._fill_template(template, event, device_label)

    def _fill_template(self, template: str, event: NetworkEvent, device_label: str) -> str:
        """Fill template with event data."""
        # Build replacement dict
        replacements = {
            "device_label": device_label,
            "device_mac": event.device_mac,
            "time": event.timestamp.strftime("%I:%M %p"),
            "date": event.timestamp.strftime("%B %d"),
            "threat_type": event.threat_type or "suspicious activity",
            "threat_source": event.source_ip or "external server",
            "source_ip": event.source_ip or "unknown",
            "destination_ip": event.destination_ip or "unknown",
        }

        # Add technical details
        for key, value in event.technical_details.items():
            replacements[key] = str(value)

        # Replace all placeholders
        result = template
        for key, value in replacements.items():
            result = result.replace(f"{{{key}}}", value)

        return result

    def _get_llm_narrative(self, event: NetworkEvent, device_label: str) -> Optional[str]:
        """Get narrative from LLM (for complex/novel events)."""
        if not self.llm_callback:
            return None

        prompt = self._build_llm_prompt(event, device_label)
        context = {
            "event": event.to_dict(),
            "persona": self.persona.value,
            "device_label": device_label,
        }

        try:
            return self.llm_callback(prompt, context)
        except Exception as e:
            logger.warning(f"LLM narrative failed: {e}")
            return None

    def _build_llm_prompt(self, event: NetworkEvent, device_label: str) -> str:
        """Build prompt for LLM narrative generation."""
        persona_descriptions = {
            Persona.PARENT: "a reassuring home network assistant speaking to a parent",
            Persona.GAMER: "a performance-focused assistant helping a gamer",
            Persona.REMOTE_WORKER: "a productivity-focused assistant for a remote worker",
            Persona.PRIVACY_CONSCIOUS: "a security-focused assistant for a privacy-conscious user",
            Persona.DEFAULT: "a friendly network assistant",
        }

        return f"""You are {persona_descriptions[self.persona]}.

Translate this technical network event into a simple, human-readable sentence:

Event Type: {event.event_type}
Device: {device_label}
Severity: {event.severity.name}
Category: {event.category.value}
Details: {json.dumps(event.technical_details)}

Guidelines:
- Use simple language a non-technical person can understand
- Be reassuring when appropriate
- Mention the device by its human name
- If it's a security event, explain if the user is safe
- Keep it to 1-2 sentences

Response:"""

    def _extract_headline(self, narrative: str) -> str:
        """Extract a headline from a narrative."""
        # Take first sentence, truncate if too long
        first_sentence = narrative.split(".")[0]
        if len(first_sentence) > 50:
            return first_sentence[:47] + "..."
        return first_sentence

    def _generate_id(self) -> str:
        """Generate unique narrative ID."""
        import uuid
        return str(uuid.uuid4())

    def set_persona(self, persona: Persona) -> None:
        """Change the current persona."""
        self.persona = persona
        logger.info(f"Persona changed to: {persona.value}")

    def get_recent_narratives(self, limit: int = 20) -> List[Narrative]:
        """Get recent narratives (requires ClickHouse in production)."""
        # In production, this would query ClickHouse
        return []


# Pre-built LLM prompt templates for n8n workflows
N8N_PROMPT_TEMPLATES = {
    "threat_narrative": """
You are the AI Eye, a friendly home network security assistant.

A security event occurred:
- Device: {{$json.device_label}}
- Event: {{$json.event_type}}
- Severity: {{$json.severity}}
- Details: {{$json.technical_details}}

Write a 1-2 sentence explanation for a non-technical homeowner.
Be reassuring if the threat was blocked.
""",

    "device_narrative": """
You are the AI Eye, a friendly home network assistant.

A device event occurred:
- Device: {{$json.device_label}}
- Event: {{$json.event_type}}
- Time: {{$json.timestamp}}

Write a 1-2 sentence update for a homeowner.
Keep it casual and informative.
""",

    "performance_narrative": """
You are the AI Eye, a performance-aware network assistant.

A network performance event:
- Affected Device: {{$json.device_label}}
- Issue: {{$json.event_type}}
- Metrics: {{$json.metrics}}

Write a 1-2 sentence explanation and suggest if user action is needed.
""",
}


if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.DEBUG)

    engine = NarrativeEngine(persona=Persona.PARENT)

    # Create a sample event
    event = NetworkEvent(
        event_type="blocked_threat",
        severity=Severity.HIGH,
        category=EventCategory.SECURITY,
        device_mac="00:1E:C2:12:34:56",
        device_label="Dad's iPhone",
        source_ip="185.128.40.22",
        threat_type="Malware C2",
        blocked=True,
    )

    # Translate to narrative
    narrative = engine.translate(event)

    print(f"Headline: {narrative.headline}")
    print(f"Narrative: {narrative.narrative}")
    print(f"Action Required: {narrative.action_required}")
    print(f"Action Taken: {narrative.action_taken}")
