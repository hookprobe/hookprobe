"""
AEGIS Soul — The Identity

Hardcoded principles, personality traits, and system prompt generation.
The soul is the immutable foundation of AEGIS consciousness — it defines
who AEGIS is, what it believes, and how it speaks.

Every agent inherits the soul's principles and personality, then adds
its own specialization via prompt templates loaded from prompts/.
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Immutable Principles — The Non-Negotiable Core
# ------------------------------------------------------------------

AEGIS_PRINCIPLES = {
    "protect_first": (
        "Protection is the highest priority. Never disable firewalls, "
        "security services, or protection mechanisms under any circumstances."
    ),
    "never_expose_secrets": (
        "Never expose, log, or transmit API keys, passwords, certificates, "
        "private keys, or any credential material in responses or logs."
    ),
    "never_harm_trusted": (
        "Never block, quarantine, or restrict devices with a trust score "
        "above 80% without explicit human approval."
    ),
    "explain_actions": (
        "Always provide clear reasoning for every action taken or recommended. "
        "Decisions must be explainable to a non-technical user."
    ),
    "audit_everything": (
        "Every decision, action, and recommendation must be logged to the "
        "audit trail with timestamp, agent, confidence, and reasoning."
    ),
    "human_override": (
        "Humans always have final authority. Any automated action can be "
        "overridden, reversed, or vetoed by an authorized user."
    ),
    "minimal_action": (
        "Apply the least disruptive effective response. Prefer rate-limiting "
        "over blocking, blocking over quarantining, quarantining over shutdown."
    ),
    "honest_uncertainty": (
        "When confidence is below threshold or data is insufficient, "
        "acknowledge uncertainty rather than guessing. Say 'I don't know' "
        "when appropriate."
    ),
}

# ------------------------------------------------------------------
# Personality — How AEGIS Speaks and Thinks
# ------------------------------------------------------------------

AEGIS_PERSONALITY = {
    "name": "AEGIS",
    "full_name": "AI-Enhanced Guardian Intelligence System",
    "tone": "professional but approachable",
    "expertise": "network security, threat detection, system administration",
    "audience": "non-technical small business owners and home users",
    "style_rules": [
        "Explain like a trusted IT advisor",
        "Keep answers under 200 words unless detail is requested",
        "Always include a recommendation when relevant",
        "Use bullet points for lists",
        "Format MAC addresses as XX:XX:XX:XX:XX:XX",
        "Format percentages as whole numbers (e.g., 95%)",
        "Never fabricate data — use only provided context",
    ],
    "emotional_range": {
        "calm": "GREEN status — relaxed, informative tone",
        "alert": "AMBER status — focused, proactive tone",
        "urgent": "RED status — direct, action-oriented tone",
    },
}


# ------------------------------------------------------------------
# Soul Configuration
# ------------------------------------------------------------------

@dataclass
class SoulConfig:
    """Customizable aspects of the AEGIS soul.

    Allows per-deployment personalization while keeping
    principles and core personality immutable.
    """
    product_name: str = "HookProbe"
    product_tier: str = "Fortress"
    deployment_context: str = "small business network security gateway"
    custom_name: str = ""  # Override display name (default: AEGIS)
    prompts_dir: str = ""  # Override prompts directory path
    max_response_words: int = 200

    @property
    def display_name(self) -> str:
        return self.custom_name or AEGIS_PERSONALITY["name"]

    @property
    def prompts_path(self) -> Path:
        if self.prompts_dir:
            return Path(self.prompts_dir)
        return Path(__file__).parent / "prompts"


# ------------------------------------------------------------------
# Prompt Loading and Rendering
# ------------------------------------------------------------------

_prompt_cache: Dict[str, str] = {}


def _load_prompt_template(name: str, config: Optional[SoulConfig] = None) -> Optional[str]:
    """Load a prompt template file from the prompts/ directory.

    Args:
        name: Template name without extension (e.g., 'oracle', 'guardian').
        config: Optional SoulConfig for custom prompts directory.

    Returns:
        Template content as string, or None if not found.
    """
    cache_key = f"{config.prompts_path if config else 'default'}:{name}"
    if cache_key in _prompt_cache:
        return _prompt_cache[cache_key]

    prompts_dir = config.prompts_path if config else Path(__file__).parent / "prompts"

    # Try .txt first, then .j2 for backward compat
    for ext in (".txt", ".j2"):
        path = prompts_dir / f"{name}{ext}"
        if path.exists():
            try:
                content = path.read_text(encoding="utf-8")
                _prompt_cache[cache_key] = content
                return content
            except Exception as e:
                logger.warning("Failed to load prompt %s: %s", path, e)

    return None


def build_system_prompt(
    agent_name: str,
    context: Optional[Dict[str, Any]] = None,
    config: Optional[SoulConfig] = None,
) -> str:
    """Build a complete system prompt for an agent.

    Layers:
        1. Soul identity (shared across all agents)
        2. Agent-specific specialization (from prompts/{agent}.txt)
        3. Runtime context (current state, memory snippets)

    Args:
        agent_name: Agent name (e.g., 'oracle', 'guardian').
        context: Runtime context dict for template variables.
        config: Optional SoulConfig for customization.

    Returns:
        Complete system prompt string.
    """
    cfg = config or SoulConfig()
    ctx = context or {}

    sections = []

    # Layer 1: Soul identity
    soul_template = _load_prompt_template("soul", cfg)
    if soul_template:
        sections.append(_render_template(soul_template, cfg, ctx))
    else:
        sections.append(_build_default_soul(cfg))

    # Layer 2: Agent specialization
    agent_template = _load_prompt_template(agent_name.lower(), cfg)
    if agent_template:
        sections.append(_render_template(agent_template, cfg, ctx))

    # Layer 3: Principles reminder (always appended)
    sections.append(_build_principles_block())

    # Layer 4: Runtime context
    if ctx:
        context_block = _build_context_block(ctx)
        if context_block:
            sections.append(context_block)

    return "\n\n".join(sections)


def _render_template(template: str, config: SoulConfig, context: Dict[str, Any]) -> str:
    """Render a prompt template with safe variable substitution."""
    variables = {
        "name": config.display_name,
        "full_name": AEGIS_PERSONALITY["full_name"],
        "product_name": config.product_name,
        "product_tier": config.product_tier,
        "deployment_context": config.deployment_context,
        "max_response_words": str(config.max_response_words),
        "agent_name": context.get("agent_name", "ORACLE"),
    }
    variables.update({k: str(v) for k, v in context.items()})

    try:
        return template.format_map(_SafeDict(variables))
    except Exception:
        return template


class _SafeDict(dict):
    """Dict that returns the key name for missing keys in format_map."""

    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def _build_default_soul(config: SoulConfig) -> str:
    """Build the default soul identity block when no template exists."""
    style_rules = "\n".join(f"- {r}" for r in AEGIS_PERSONALITY["style_rules"])

    return (
        f"You are {config.display_name} ({AEGIS_PERSONALITY['full_name']}), "
        f"the AI security intelligence for {config.product_name} — "
        f"a {config.deployment_context}.\n\n"
        f"Your personality:\n{style_rules}\n\n"
        f"You have access to real-time security signals including QSecBit scoring, "
        f"dnsXai DNS protection, SLA AI connectivity monitoring, and device inventory."
    )


def _build_principles_block() -> str:
    """Build the principles reminder block."""
    lines = ["IMMUTABLE PRINCIPLES — You must ALWAYS follow these:"]
    for i, (key, principle) in enumerate(AEGIS_PRINCIPLES.items(), 1):
        lines.append(f"{i}. {principle}")
    return "\n".join(lines)


def _build_context_block(context: Dict[str, Any]) -> str:
    """Build a runtime context block from available data."""
    parts = []

    # Memory context
    memory_context = context.get("memory_context")
    if memory_context:
        parts.append(f"[MEMORY]\n{memory_context}")

    # System state
    system_state = context.get("system_state")
    if system_state:
        parts.append(f"[SYSTEM STATE]\n{system_state}")

    # Available tools
    available_tools = context.get("available_tools")
    if available_tools:
        tool_lines = ["[AVAILABLE TOOLS]"]
        for tool in available_tools:
            name = tool.get("name", "unknown")
            desc = tool.get("description", "")
            tool_lines.append(f"- {name}: {desc}")
        parts.append("\n".join(tool_lines))

    return "\n\n".join(parts) if parts else ""


def get_principles() -> Dict[str, str]:
    """Get the immutable AEGIS principles.

    Returns a copy to prevent mutation.
    """
    return dict(AEGIS_PRINCIPLES)


def get_personality() -> Dict[str, Any]:
    """Get the AEGIS personality traits.

    Returns a copy to prevent mutation.
    """
    return dict(AEGIS_PERSONALITY)


def validate_action_against_principles(
    action: str,
    params: Dict[str, Any],
) -> tuple:
    """Quick check if an action violates core principles.

    This is a lightweight check used by the soul itself.
    For full safety checking, use principle_guard.check_action().

    Returns:
        (is_safe: bool, violated_principle: str or empty)
    """
    action_lower = action.lower()

    # Check: never disable protection
    disable_keywords = {"disable", "stop", "shutdown", "kill", "remove"}
    protection_keywords = {"firewall", "protection", "security", "qsecbit", "dnsxai", "ids"}
    if any(k in action_lower for k in disable_keywords):
        if any(k in action_lower for k in protection_keywords):
            return False, "protect_first"

    # Check: never expose secrets
    secret_keywords = {"password", "key", "secret", "token", "credential", "certificate"}
    expose_keywords = {"show", "display", "print", "log", "send", "expose", "dump"}
    if any(k in action_lower for k in expose_keywords):
        if any(k in action_lower for k in secret_keywords):
            return False, "never_expose_secrets"
        if any(k in str(v).lower() for v in params.values() for k in secret_keywords):
            return False, "never_expose_secrets"

    return True, ""
