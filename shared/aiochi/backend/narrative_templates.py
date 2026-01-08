#!/usr/bin/env python3
"""
AIOCHI Narrative Templates - Human-readable event descriptions

This module provides template-based narrative generation for network events.
It works without requiring LLM (Ollama) or workflow engine (n8n).

Usage:
    from narrative_templates import NarrativeEngine

    engine = NarrativeEngine()
    narrative = engine.generate(
        event_type="new_device",
        device_name="iPhone",
        network_name="Home WiFi"
    )
    # Returns: "A new device 'iPhone' just joined Home WiFi."

The engine can optionally use Ollama for complex events if available.
"""

import random
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum

logger = logging.getLogger(__name__)


class EventSeverity(Enum):
    """Event severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventCategory(Enum):
    """Event categories."""
    DEVICE = "device"
    SECURITY = "security"
    PERFORMANCE = "performance"
    NETWORK = "network"
    BUBBLE = "bubble"


# =============================================================================
# NARRATIVE TEMPLATES
# =============================================================================
# Each event type has multiple templates for variety.
# Variables are enclosed in {braces} and replaced at runtime.
# =============================================================================

NARRATIVE_TEMPLATES: Dict[str, Dict[str, Any]] = {
    # -------------------------------------------------------------------------
    # DEVICE EVENTS
    # -------------------------------------------------------------------------
    "new_device": {
        "severity": EventSeverity.INFO,
        "category": EventCategory.DEVICE,
        "templates": [
            "A new device '{device_name}' just joined {network_name}.",
            "Welcome! '{device_name}' is now connected to your network.",
            "New arrival: '{device_name}' on {network_name}.",
            "'{device_name}' has connected for the first time.",
        ],
        "action_required": False,
    },

    "device_online": {
        "severity": EventSeverity.INFO,
        "category": EventCategory.DEVICE,
        "templates": [
            "'{device_name}' is back online.",
            "'{device_name}' reconnected to the network.",
            "Good news: '{device_name}' is connected again.",
        ],
        "action_required": False,
    },

    "device_offline": {
        "severity": EventSeverity.INFO,
        "category": EventCategory.DEVICE,
        "templates": [
            "'{device_name}' went offline. This might be normal if it's sleeping.",
            "Heads up: '{device_name}' disconnected at {time}.",
            "'{device_name}' is no longer connected.",
        ],
        "action_required": False,
    },

    "device_renamed": {
        "severity": EventSeverity.INFO,
        "category": EventCategory.DEVICE,
        "templates": [
            "Device renamed from '{old_name}' to '{new_name}'.",
            "'{old_name}' is now known as '{new_name}'.",
        ],
        "action_required": False,
    },

    "device_identified": {
        "severity": EventSeverity.INFO,
        "category": EventCategory.DEVICE,
        "templates": [
            "Identified '{device_name}' as a {device_type} from {manufacturer}.",
            "'{device_name}' recognized: {device_type} ({manufacturer}).",
            "Device fingerprint complete: '{device_name}' is a {manufacturer} {device_type}.",
        ],
        "action_required": False,
    },

    # -------------------------------------------------------------------------
    # SECURITY EVENTS
    # -------------------------------------------------------------------------
    "blocked_threat": {
        "severity": EventSeverity.HIGH,
        "category": EventCategory.SECURITY,
        "templates": [
            "I blocked a suspicious connection from {threat_source}. {device_name} is safe.",
            "Threat neutralized! {device_name} tried to connect to a known bad server.",
            "Your {device_name} was protected from a potential attack from {threat_source}.",
            "Security alert: Blocked malicious traffic to {threat_source}. Your network is protected.",
        ],
        "action_required": False,
    },

    "blocked_tracker": {
        "severity": EventSeverity.LOW,
        "category": EventCategory.SECURITY,
        "templates": [
            "Blocked {count} tracking attempts from '{device_name}'. Your privacy is protected.",
            "Privacy protection: Stopped {domain} from tracking '{device_name}'.",
            "Tracker blocked: {domain} can't follow '{device_name}'.",
        ],
        "action_required": False,
    },

    "blocked_ad": {
        "severity": EventSeverity.INFO,
        "category": EventCategory.SECURITY,
        "templates": [
            "Blocked {count} ads for '{device_name}'. Enjoying ad-free browsing!",
            "Ad blocked: {domain} won't interrupt '{device_name}'.",
        ],
        "action_required": False,
    },

    "suspicious_activity": {
        "severity": EventSeverity.MEDIUM,
        "category": EventCategory.SECURITY,
        "templates": [
            "Unusual activity detected from '{device_name}': {description}. Monitoring closely.",
            "Something's different: '{device_name}' is {description}. I'm keeping an eye on it.",
            "Alert: '{device_name}' is showing unusual behavior. {description}.",
        ],
        "action_required": True,
    },

    "port_scan_detected": {
        "severity": EventSeverity.MEDIUM,
        "category": EventCategory.SECURITY,
        "templates": [
            "Someone is probing the network from {source_ip}. Already blocked.",
            "Port scan detected from {source_ip}. Your network is protected.",
            "Reconnaissance attempt from {source_ip} blocked. They can't see your devices.",
        ],
        "action_required": False,
    },

    "malware_blocked": {
        "severity": EventSeverity.CRITICAL,
        "category": EventCategory.SECURITY,
        "templates": [
            "CRITICAL: Blocked malware communication from '{device_name}' to {c2_server}. Device quarantined.",
            "Malware detected! '{device_name}' tried to contact {c2_server}. I've isolated it for safety.",
            "Emergency block: '{device_name}' was compromised. Malware traffic to {c2_server} stopped.",
        ],
        "action_required": True,
    },

    "brute_force_blocked": {
        "severity": EventSeverity.HIGH,
        "category": EventCategory.SECURITY,
        "templates": [
            "Blocked brute force attack from {source_ip}. {attempt_count} login attempts stopped.",
            "Someone tried to guess passwords from {source_ip}. Blocked after {attempt_count} attempts.",
        ],
        "action_required": False,
    },

    # -------------------------------------------------------------------------
    # BUBBLE (ECOSYSTEM) EVENTS
    # -------------------------------------------------------------------------
    "bubble_created": {
        "severity": EventSeverity.INFO,
        "category": EventCategory.BUBBLE,
        "templates": [
            "Created new device group: '{bubble_name}' with {device_count} devices.",
            "New ecosystem detected: '{bubble_name}' groups {device_count} related devices.",
            "'{bubble_name}' bubble formed with: {device_list}.",
        ],
        "action_required": False,
    },

    "device_added_to_bubble": {
        "severity": EventSeverity.INFO,
        "category": EventCategory.BUBBLE,
        "templates": [
            "'{device_name}' joined the '{bubble_name}' group.",
            "Added '{device_name}' to '{bubble_name}' - they seem to belong together.",
            "'{device_name}' is now part of {bubble_name}'s devices.",
        ],
        "action_required": False,
    },

    "bubble_detected_same_user": {
        "severity": EventSeverity.INFO,
        "category": EventCategory.BUBBLE,
        "templates": [
            "'{device_name}' appears to belong to the same person as '{related_device}'.",
            "Detected: '{device_name}' and '{related_device}' share the same owner.",
            "Same user detected: '{device_name}' and '{related_device}' have similar patterns.",
        ],
        "action_required": False,
    },

    "presence_detected": {
        "severity": EventSeverity.INFO,
        "category": EventCategory.BUBBLE,
        "templates": [
            "{person_name} is home. {device_count} devices connected.",
            "{person_name}'s devices just came online.",
            "Welcome home, {person_name}!",
        ],
        "action_required": False,
    },

    "presence_left": {
        "severity": EventSeverity.INFO,
        "category": EventCategory.BUBBLE,
        "templates": [
            "{person_name} appears to have left. {device_count} devices went offline.",
            "{person_name}'s devices disconnected.",
            "Goodbye, {person_name}!",
        ],
        "action_required": False,
    },

    # -------------------------------------------------------------------------
    # PERFORMANCE EVENTS
    # -------------------------------------------------------------------------
    "slow_connection": {
        "severity": EventSeverity.LOW,
        "category": EventCategory.PERFORMANCE,
        "templates": [
            "'{device_name}' is experiencing slow speeds ({speed_mbps} Mbps). {reason}",
            "Performance notice: '{device_name}' connection dropped to {speed_mbps} Mbps.",
        ],
        "action_required": False,
    },

    "high_latency": {
        "severity": EventSeverity.LOW,
        "category": EventCategory.PERFORMANCE,
        "templates": [
            "High latency detected for '{device_name}': {latency_ms}ms. {suggestion}",
            "'{device_name}' has {latency_ms}ms ping. Gaming/video calls might lag.",
        ],
        "action_required": False,
    },

    "wifi_interference": {
        "severity": EventSeverity.MEDIUM,
        "category": EventCategory.PERFORMANCE,
        "templates": [
            "WiFi interference detected on channel {channel}. Consider switching channels.",
            "Your {band} WiFi is congested. {suggestion}",
            "Neighbor's WiFi on channel {channel} is causing interference.",
        ],
        "action_required": True,
    },

    "bandwidth_hog": {
        "severity": EventSeverity.LOW,
        "category": EventCategory.PERFORMANCE,
        "templates": [
            "'{device_name}' is using {usage_percent}% of bandwidth ({usage_mbps} Mbps).",
            "High bandwidth: '{device_name}' is downloading heavily.",
        ],
        "action_required": False,
    },

    # -------------------------------------------------------------------------
    # NETWORK EVENTS
    # -------------------------------------------------------------------------
    "policy_changed": {
        "severity": EventSeverity.INFO,
        "category": EventCategory.NETWORK,
        "templates": [
            "'{device_name}' policy changed from {old_policy} to {new_policy}.",
            "Updated access for '{device_name}': now has {new_policy} access.",
        ],
        "action_required": False,
    },

    "device_quarantined": {
        "severity": EventSeverity.HIGH,
        "category": EventCategory.NETWORK,
        "templates": [
            "'{device_name}' has been quarantined. Reason: {reason}.",
            "Security action: '{device_name}' isolated from network. {reason}",
        ],
        "action_required": True,
    },

    "device_trusted": {
        "severity": EventSeverity.INFO,
        "category": EventCategory.NETWORK,
        "templates": [
            "'{device_name}' is now trusted with full network access.",
            "Trust granted: '{device_name}' can access all network resources.",
        ],
        "action_required": False,
    },

    "wan_failover": {
        "severity": EventSeverity.MEDIUM,
        "category": EventCategory.NETWORK,
        "templates": [
            "Primary internet connection failed. Switched to backup ({backup_name}).",
            "Internet failover: Now using {backup_name}. Primary connection will be retried.",
        ],
        "action_required": False,
    },

    "wan_restored": {
        "severity": EventSeverity.INFO,
        "category": EventCategory.NETWORK,
        "templates": [
            "Primary internet connection restored. Back to normal.",
            "Good news: Primary internet is back online.",
        ],
        "action_required": False,
    },

    # -------------------------------------------------------------------------
    # SYSTEM EVENTS
    # -------------------------------------------------------------------------
    "system_healthy": {
        "severity": EventSeverity.INFO,
        "category": EventCategory.NETWORK,
        "templates": [
            "All systems healthy. {device_count} devices online, no threats detected.",
            "Everything looks good! Your network is running smoothly.",
        ],
        "action_required": False,
    },

    "update_available": {
        "severity": EventSeverity.INFO,
        "category": EventCategory.NETWORK,
        "templates": [
            "Software update available: {version}. {description}",
            "New version {version} ready to install.",
        ],
        "action_required": True,
    },
}


class NarrativeEngine:
    """
    Template-based narrative generation engine.

    Generates human-readable event descriptions using templates.
    Optionally falls back to Ollama LLM for complex events.
    """

    def __init__(self, ollama_url: Optional[str] = None):
        """
        Initialize the narrative engine.

        Args:
            ollama_url: Optional Ollama API URL for LLM fallback
        """
        self.ollama_url = ollama_url
        self.templates = NARRATIVE_TEMPLATES

    def generate(
        self,
        event_type: str,
        use_llm: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate a narrative for an event.

        Args:
            event_type: Type of event (e.g., "new_device", "blocked_threat")
            use_llm: Whether to use LLM for generation (requires Ollama)
            **kwargs: Variables for template substitution

        Returns:
            Dict with narrative, severity, category, and metadata
        """
        # Add default time if not provided
        if 'time' not in kwargs:
            kwargs['time'] = datetime.now().strftime("%I:%M %p")

        template_config = self.templates.get(event_type)

        if not template_config:
            # Unknown event type - generate generic narrative
            return self._generate_generic(event_type, **kwargs)

        # Select random template for variety
        template = random.choice(template_config["templates"])

        # Substitute variables
        try:
            narrative = template.format(**kwargs)
        except KeyError as e:
            logger.warning(f"Missing template variable {e} for {event_type}")
            # Try to generate with available variables
            narrative = self._safe_format(template, kwargs)

        return {
            "event_type": event_type,
            "narrative": narrative,
            "severity": template_config["severity"].value,
            "category": template_config["category"].value,
            "action_required": template_config.get("action_required", False),
            "timestamp": datetime.now().isoformat(),
            "variables": kwargs,
        }

    def _safe_format(self, template: str, variables: Dict[str, Any]) -> str:
        """Safely format template, replacing missing variables with placeholders."""
        import re

        def replace_var(match):
            var_name = match.group(1)
            return str(variables.get(var_name, f"[{var_name}]"))

        return re.sub(r'\{(\w+)\}', replace_var, template)

    def _generate_generic(self, event_type: str, **kwargs) -> Dict[str, Any]:
        """Generate a generic narrative for unknown event types."""
        device = kwargs.get('device_name', 'A device')
        narrative = f"Event '{event_type}' occurred for {device}."

        return {
            "event_type": event_type,
            "narrative": narrative,
            "severity": EventSeverity.INFO.value,
            "category": EventCategory.DEVICE.value,
            "action_required": False,
            "timestamp": datetime.now().isoformat(),
            "variables": kwargs,
        }

    def get_event_types(self) -> List[str]:
        """Get list of supported event types."""
        return list(self.templates.keys())

    def get_template_info(self, event_type: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific event type."""
        config = self.templates.get(event_type)
        if not config:
            return None

        return {
            "event_type": event_type,
            "severity": config["severity"].value,
            "category": config["category"].value,
            "action_required": config.get("action_required", False),
            "template_count": len(config["templates"]),
            "example_template": config["templates"][0],
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

_engine: Optional[NarrativeEngine] = None


def get_narrative_engine() -> NarrativeEngine:
    """Get the global narrative engine instance."""
    global _engine
    if _engine is None:
        _engine = NarrativeEngine()
    return _engine


def generate_narrative(event_type: str, **kwargs) -> str:
    """
    Quick function to generate a narrative string.

    Args:
        event_type: Type of event
        **kwargs: Variables for template

    Returns:
        Human-readable narrative string
    """
    engine = get_narrative_engine()
    result = engine.generate(event_type, **kwargs)
    return result["narrative"]


# =============================================================================
# CLI INTERFACE
# =============================================================================

if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="AIOCHI Narrative Templates")
    parser.add_argument("command", choices=["list", "generate", "info"],
                        help="Command to run")
    parser.add_argument("--event", "-e", help="Event type")
    parser.add_argument("--vars", "-v", help="Variables as JSON")

    args = parser.parse_args()
    engine = NarrativeEngine()

    if args.command == "list":
        print("Supported event types:")
        for event_type in engine.get_event_types():
            info = engine.get_template_info(event_type)
            print(f"  {event_type}: {info['severity']} ({info['category']})")

    elif args.command == "generate":
        if not args.event:
            print("Error: --event required")
            exit(1)

        variables = {}
        if args.vars:
            variables = json.loads(args.vars)

        # Add some defaults for testing
        defaults = {
            "device_name": "iPhone",
            "network_name": "Home WiFi",
            "manufacturer": "Apple",
            "device_type": "smartphone",
            "threat_source": "malware.example.com",
            "bubble_name": "Family",
        }
        for k, v in defaults.items():
            if k not in variables:
                variables[k] = v

        result = engine.generate(args.event, **variables)
        print(json.dumps(result, indent=2))

    elif args.command == "info":
        if not args.event:
            print("Error: --event required")
            exit(1)

        info = engine.get_template_info(args.event)
        if info:
            print(json.dumps(info, indent=2))
        else:
            print(f"Unknown event type: {args.event}")
