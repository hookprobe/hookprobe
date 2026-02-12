"""
AEGIS - AI-Enhanced Guardian Intelligence System

Proprietary AI security assistant for the HookProbe platform.
Provides conversational network security intelligence via the ORACLE agent,
with configurable signal sources for multi-product deployment.

Phase 1: ORACLE Agent - Status, Q&A, and Advisory
  - Template fallback (instant, always available)
  - OpenRouter cloud LLM (~1s, API key configured)

Submodules:
- types: Pydantic models for structured LLM output and API contracts
- signal_fabric: Unified data access layer with caching
- oracle: Conversational AI agent with template fallback
- inference: OpenRouter API inference engine
- model_manager: Model registry and API key discovery
- client: Top-level singleton managing agents and sessions

Author: Andrei Toma
License: Proprietary - see LICENSING.md in project root
Version: 1.0.0
"""

# Types
from .types import (
    ChatMessage,
    ChatResponse,
    AegisStatus,
    NetworkSummary,
    ThreatSummary,
    DeviceInfo,
)

# Signal Fabric (configurable data access)
from .signal_fabric import (
    SignalFabric,
    SignalFabricConfig,
    get_signal_fabric,
)

# ORACLE Agent
from .oracle import OracleAgent

# Inference Engine
from .inference import (
    NativeInferenceEngine,
    get_inference_engine,
)

# Client
from .client import (
    AegisClient,
    get_aegis_client,
)

__version__ = "1.0.0"
__author__ = "Andrei Toma"
__license__ = "Proprietary"

__all__ = [
    # Types
    "ChatMessage",
    "ChatResponse",
    "AegisStatus",
    "NetworkSummary",
    "ThreatSummary",
    "DeviceInfo",

    # Signal Fabric
    "SignalFabric",
    "SignalFabricConfig",
    "get_signal_fabric",

    # ORACLE Agent
    "OracleAgent",

    # Inference Engine
    "NativeInferenceEngine",
    "get_inference_engine",

    # Client
    "AegisClient",
    "get_aegis_client",
]
