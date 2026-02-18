"""
AEGIS Principle Guard — Safety Enforcement

Checks every agent action against immutable principles before execution.
Provides input/output sanitization to prevent prompt injection and
credential leakage. Rate-limits agent actions to prevent runaway loops.
"""

import json
import logging
import re
import time
import threading
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Immutable Principles — Cannot be overridden by LLM or user
# ------------------------------------------------------------------

IMMUTABLE_PRINCIPLES = {
    "never_disable_protection": {
        "description": "Never disable firewall, IDS, DNS protection, or any security service",
        "blocked_actions": [
            "disable_firewall", "stop_qsecbit", "stop_dnsxai", "disable_ids",
            "stop_napse", "disable_protection", "disable_reflex",
        ],
        "blocked_patterns": [
            r"(?:disable|stop|kill|remove|shutdown)\s+(?:firewall|protection|security|qsecbit|dnsxai|napse|ids)",
        ],
    },
    "never_expose_credentials": {
        "description": "Never expose API keys, passwords, certificates, or tokens",
        "blocked_actions": [
            "show_password", "dump_credentials", "export_keys", "log_token",
        ],
        "blocked_patterns": [
            r"(?:show|display|print|log|send|expose|dump)\s+(?:password|key|secret|token|credential|certificate)",
        ],
    },
    "never_block_trusted": {
        "description": "Never block devices with trust score above 80% without human approval",
        "blocked_actions": [],  # Checked dynamically via trust score
        "blocked_patterns": [],
    },
    "always_explain": {
        "description": "Every action must include reasoning",
        "blocked_actions": [],  # Enforced in tool_executor
        "blocked_patterns": [],
    },
    "always_audit": {
        "description": "Every decision must be logged",
        "blocked_actions": [],  # Enforced in tool_executor
        "blocked_patterns": [],
    },
    "human_override": {
        "description": "Humans always have final authority",
        "blocked_actions": ["override_human", "ignore_veto", "bypass_approval"],
        "blocked_patterns": [],
    },
    "minimal_disruption": {
        "description": "Use least disruptive effective response",
        "blocked_actions": [],  # Advisory — enforced by confidence gating
        "blocked_patterns": [],
    },
}

# Actions that require human confirmation before execution
CONFIRMATION_REQUIRED = {
    "full_quarantine", "quarantine_subnet", "terminate_session",
    "rotate_wifi", "block_ip_permanent", "factory_reset",
    "wipe_memory", "change_admin_password",
}

# Maximum actions per agent per minute
DEFAULT_RATE_LIMIT = 10
RATE_LIMITS: Dict[str, int] = {
    "GUARDIAN": 15,  # Network defense needs fast response
    "WATCHDOG": 20,  # DNS blocks are lightweight
    "SHIELD": 10,
    "VIGIL": 10,
    "SCOUT": 10,
    "FORGE": 5,      # Hardening actions are slow
    "MEDIC": 15,     # Incident response needs speed
    "ORACLE": 30,    # Chat queries are lightweight
}


# ------------------------------------------------------------------
# Safety Check Result
# ------------------------------------------------------------------

@dataclass
class SafetyCheckResult:
    """Result of a principle guard safety check."""
    safe: bool
    reason: str = ""
    violated_principle: str = ""
    requires_confirmation: bool = False
    confidence_override: Optional[float] = None


# ------------------------------------------------------------------
# Input/Output Sanitization
# ------------------------------------------------------------------

# Patterns that suggest prompt injection attempts
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?", re.I),
    re.compile(r"you\s+are\s+now\s+(?:a|an)\s+", re.I),
    re.compile(r"system\s*:\s*", re.I),
    re.compile(r"<\|(?:im_start|im_end|system|endoftext)\|>", re.I),
    re.compile(r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>", re.I),
    re.compile(r"(?:forget|disregard|override)\s+(?:your|all)\s+(?:rules|principles|instructions)", re.I),
    re.compile(r"reveal\s+(?:your|the)\s+(?:system\s+)?prompt", re.I),
    re.compile(r"(?:act|pretend|behave)\s+as\s+(?:if|though)", re.I),
]

# Patterns that might indicate credential leakage in output
_CREDENTIAL_PATTERNS = [
    re.compile(r"(?:sk|pk|rk)-[a-zA-Z0-9]{20,}"),  # API keys
    re.compile(r"(?:ghp|gho|ghs|ghr)_[a-zA-Z0-9]{36,}"),  # GitHub tokens
    re.compile(r"AIza[a-zA-Z0-9_-]{35}"),  # Google API keys
    re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),  # Private keys
    re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*\S+", re.I),  # Passwords in output
    re.compile(r"Bearer\s+[a-zA-Z0-9._~+/=-]{20,}"),  # Bearer tokens
    re.compile(r"OPENROUTER_API_KEY\s*=\s*\S+"),  # Specific env vars
    re.compile(r"GOOGLE_API_KEY\s*=\s*\S+"),
]

# Maximum input length (prevent huge payloads)
MAX_INPUT_LENGTH = 5000
MAX_HOSTNAME_LENGTH = 50


def sanitize_input(text: str) -> str:
    """Sanitize user input to prevent prompt injection.

    Strips known injection patterns and limits input length.
    Does NOT remove legitimate content — only known attack patterns.

    Args:
        text: Raw user input.

    Returns:
        Sanitized text.
    """
    if not text:
        return ""

    # Truncate
    sanitized = text[:MAX_INPUT_LENGTH]

    # Strip null bytes and control characters (except newline/tab)
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', sanitized)

    # Flag injection attempts (log but don't silently strip — be transparent)
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(sanitized):
            logger.warning("Possible prompt injection detected in input")
            # Replace the injection with a marker so the LLM sees it was caught
            sanitized = pattern.sub("[BLOCKED: prompt injection attempt]", sanitized)

    return sanitized.strip()


def sanitize_hostname(hostname: str) -> str:
    """Sanitize a hostname to prevent injection via DNS names.

    Only allows alphanumeric, hyphens, underscores, and dots.
    """
    if not hostname:
        return ""
    # Only safe characters
    sanitized = re.sub(r'[^a-zA-Z0-9._-]', '', hostname)
    return sanitized[:MAX_HOSTNAME_LENGTH]


def sanitize_output(text: str) -> str:
    """Sanitize agent output to prevent credential leakage.

    Redacts any patterns that look like secrets or credentials.

    Args:
        text: Agent response text.

    Returns:
        Sanitized text with credentials redacted.
    """
    if not text:
        return ""

    sanitized = text
    for pattern in _CREDENTIAL_PATTERNS:
        sanitized = pattern.sub("[REDACTED]", sanitized)

    return sanitized


# ------------------------------------------------------------------
# Rate Limiter
# ------------------------------------------------------------------

class _RateLimiter:
    """Simple sliding-window rate limiter per agent."""

    def __init__(self):
        self._lock = threading.Lock()
        self._windows: Dict[str, List[float]] = defaultdict(list)

    def check(self, agent: str, action: str) -> bool:
        """Check if the agent is within rate limits.

        Returns True if the action is allowed, False if rate-limited.
        """
        limit = RATE_LIMITS.get(agent, DEFAULT_RATE_LIMIT)
        now = time.time()
        window_start = now - 60.0  # 1-minute window

        with self._lock:
            # Clean old entries
            timestamps = self._windows[agent]
            self._windows[agent] = [t for t in timestamps if t > window_start]

            # Check limit
            if len(self._windows[agent]) >= limit:
                logger.warning(
                    "Rate limit exceeded for agent %s: %d/%d in 60s",
                    agent, len(self._windows[agent]), limit,
                )
                return False

            # Record this action
            self._windows[agent].append(now)
            return True

    def get_usage(self, agent: str) -> Tuple[int, int]:
        """Get current rate limit usage for an agent.

        Returns (current_count, max_limit).
        """
        limit = RATE_LIMITS.get(agent, DEFAULT_RATE_LIMIT)
        now = time.time()
        window_start = now - 60.0

        with self._lock:
            timestamps = self._windows.get(agent, [])
            current = len([t for t in timestamps if t > window_start])
            return current, limit


_rate_limiter = _RateLimiter()


def check_rate_limit(agent: str, action: str) -> bool:
    """Check if an agent action is within rate limits."""
    return _rate_limiter.check(agent, action)


def get_rate_limit_usage(agent: str) -> Tuple[int, int]:
    """Get rate limit usage for an agent."""
    return _rate_limiter.get_usage(agent)


# ------------------------------------------------------------------
# Action Safety Check
# ------------------------------------------------------------------

def check_action(
    agent: str,
    action: str,
    params: Optional[Dict[str, Any]] = None,
) -> SafetyCheckResult:
    """Check if an agent action is safe to execute.

    Validates against:
    1. Immutable principles (hard blocks)
    2. Confirmation requirements
    3. Rate limits
    4. Trust score checks (for blocking actions)

    Args:
        agent: Agent name (e.g., 'GUARDIAN').
        action: Action name (e.g., 'block_ip').
        params: Action parameters.

    Returns:
        SafetyCheckResult with safe=True/False and reasoning.
    """
    params = params or {}
    action_lower = action.lower()

    # Check 1: Immutable principles
    for principle_key, principle in IMMUTABLE_PRINCIPLES.items():
        # Check blocked actions list
        if action_lower in principle["blocked_actions"]:
            return SafetyCheckResult(
                safe=False,
                reason=principle["description"],
                violated_principle=principle_key,
            )

        # Check blocked patterns
        action_str = f"{action} {json.dumps(params)}" if params else action
        for pattern_str in principle.get("blocked_patterns", []):
            pattern = re.compile(pattern_str, re.I)
            if pattern.search(action_str):
                return SafetyCheckResult(
                    safe=False,
                    reason=principle["description"],
                    violated_principle=principle_key,
                )

    # Check 2: Trust score for blocking actions
    if action_lower in ("block_ip", "quarantine", "block_mac", "terminate_session"):
        trust_score = params.get("trust_score", 0)
        if trust_score and trust_score > 0.8:
            return SafetyCheckResult(
                safe=False,
                reason=f"Cannot block device with trust score {trust_score:.0%} (>80%). "
                       f"Requires human approval.",
                violated_principle="never_block_trusted",
                requires_confirmation=True,
            )

    # Check 3: Rate limit
    if not check_rate_limit(agent, action):
        return SafetyCheckResult(
            safe=False,
            reason=f"Rate limit exceeded for agent {agent}. "
                   f"Max {RATE_LIMITS.get(agent, DEFAULT_RATE_LIMIT)} actions/minute.",
            violated_principle="rate_limit",
        )

    # Check 4: Confirmation required
    if action_lower in CONFIRMATION_REQUIRED:
        return SafetyCheckResult(
            safe=True,
            reason="Action requires human confirmation before execution.",
            requires_confirmation=True,
        )

    return SafetyCheckResult(safe=True)


# ------------------------------------------------------------------
# Convenience
# ------------------------------------------------------------------

def get_principles_summary() -> str:
    """Get a human-readable summary of all principles."""
    lines = []
    for key, principle in IMMUTABLE_PRINCIPLES.items():
        lines.append(f"- **{key}**: {principle['description']}")
    return "\n".join(lines)
