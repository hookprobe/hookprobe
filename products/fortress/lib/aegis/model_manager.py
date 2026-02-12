"""
AEGIS Model Manager

OpenRouter model registry and API key management.
Handles model selection, API key discovery, and availability checks.
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"

# Model registry: key -> OpenRouter model ID + metadata
# Ordered by cost/quality trade-off for small-business security use
MODEL_REGISTRY: Dict[str, Dict[str, Any]] = {
    "gemini-flash": {
        "model_id": "google/gemini-2.0-flash-001",
        "description": "Gemini 2.0 Flash - fast, cost-effective, good reasoning",
        "max_tokens": 8192,
        "tier": "fast",
    },
    "gpt-4o-mini": {
        "model_id": "openai/gpt-4o-mini",
        "description": "GPT-4o Mini - compact, reliable, low cost",
        "max_tokens": 4096,
        "tier": "fast",
    },
    "claude-haiku": {
        "model_id": "anthropic/claude-3.5-haiku",
        "description": "Claude 3.5 Haiku - fast, concise, security-aware",
        "max_tokens": 4096,
        "tier": "fast",
    },
    "gemini-pro": {
        "model_id": "google/gemini-2.5-pro-preview",
        "description": "Gemini 2.5 Pro - advanced reasoning, higher cost",
        "max_tokens": 8192,
        "tier": "quality",
    },
}

DEFAULT_MODEL_KEY = "gemini-flash"


def get_api_key() -> str:
    """Discover OpenRouter API key from multiple sources.

    Priority:
      1. OPENROUTER_API_KEY environment variable
      2. /etc/hookprobe/fortress.conf key=value
      3. /etc/hookprobe/secrets/openrouter_api_key file
    """
    # 1. Environment variable
    key = os.environ.get("OPENROUTER_API_KEY", "")
    if key:
        return key

    # 2. Fortress config file
    try:
        conf_path = Path("/etc/hookprobe/fortress.conf")
        if conf_path.exists():
            for line in conf_path.read_text().split("\n"):
                line = line.strip()
                if line.startswith("OPENROUTER_API_KEY="):
                    return line.split("=", 1)[1].strip().strip("\"'")
    except Exception:
        pass

    # 3. Dedicated secrets file
    try:
        key_path = Path("/etc/hookprobe/secrets/openrouter_api_key")
        if key_path.exists():
            return key_path.read_text().strip()
    except Exception:
        pass

    return ""


def get_api_url() -> str:
    """Get the OpenRouter API URL."""
    return os.environ.get("AEGIS_API_URL", OPENROUTER_API_URL)


def get_model_id(model_key: Optional[str] = None) -> str:
    """Resolve a model key to an OpenRouter model ID.

    Args:
        model_key: Registry key (e.g., "gemini-flash") or direct model ID.
                   If None or "auto", uses the default.

    Returns:
        OpenRouter model ID string.
    """
    if not model_key or model_key == "auto":
        model_key = DEFAULT_MODEL_KEY

    # Check registry first
    if model_key in MODEL_REGISTRY:
        return MODEL_REGISTRY[model_key]["model_id"]

    # Treat as a direct OpenRouter model ID (e.g., "google/gemini-2.0-flash-001")
    if "/" in model_key:
        return model_key

    # Fallback to default
    logger.warning("Unknown model key '%s', using default '%s'", model_key, DEFAULT_MODEL_KEY)
    return MODEL_REGISTRY[DEFAULT_MODEL_KEY]["model_id"]


def get_model_info(model_key: Optional[str] = None) -> Dict[str, Any]:
    """Get full model info from the registry.

    Returns registry entry if found, or a synthetic entry for direct model IDs.
    """
    if not model_key or model_key == "auto":
        model_key = DEFAULT_MODEL_KEY

    if model_key in MODEL_REGISTRY:
        return {"model_key": model_key, **MODEL_REGISTRY[model_key]}

    # Direct model ID — build synthetic entry
    model_id = model_key if "/" in model_key else get_model_id(model_key)
    return {
        "model_key": model_key,
        "model_id": model_id,
        "description": f"Custom model: {model_id}",
        "max_tokens": 4096,
        "tier": "custom",
    }


def list_available() -> List[Dict[str, Any]]:
    """List all models in the registry."""
    return [
        {"model_key": key, **info}
        for key, info in MODEL_REGISTRY.items()
    ]


def is_api_configured() -> bool:
    """Check if an OpenRouter API key is configured."""
    key = get_api_key()
    return len(key) > 10
