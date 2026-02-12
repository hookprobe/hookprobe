"""
AEGIS - AI-Enhanced Guardian Intelligence System

Proprietary AI security assistant for the HookProbe platform.
Autonomous, multi-agent security consciousness with:

  - 8 specialized agents (ORACLE, GUARDIAN, WATCHDOG, SHIELD, VIGIL, SCOUT, FORGE, MEDIC)
  - Multi-layer persistent memory (session, behavioral, institutional, threat intel)
  - Hybrid LLM inference (local Ollama + OpenRouter cloud)
  - Real-time signal bridges (QSecBit, dnsXai, DHCP, WAN)
  - Confidence-gated autonomous actions
  - Principle-guarded safety enforcement
  - Inner psyche for self-reflection and learning

Submodules:
- types: Pydantic models + dataclasses for signals, agents, tools
- soul: Identity, principles, and per-agent prompt generation
- memory: Multi-layer persistent SQLite memory
- principle_guard: Safety enforcement and sanitization
- agents: 8 specialized agent classes with registry
- tool_executor: Safe action execution with permission matrix
- orchestrator: Central event router and coordinator
- inference: Hybrid Ollama + OpenRouter inference engine
- signal_fabric: Unified data access layer with caching
- bridges: Real-time signal bridges (file watchers + HTTP polling)
- narrator: Template + LLM response formatting
- autonomous: Scheduled tasks and real-time watcher
- self_model: System self-knowledge and health
- inner_psyche: Reflection, learning, and confidence calibration
- oracle: Legacy ORACLE agent (Phase 1 compatibility)
- client: Top-level singleton managing full stack

Author: Andrei Toma
License: Proprietary - see LICENSING.md in project root
Version: 2.0.0
"""

# Types
from .types import (
    ChatMessage,
    ChatResponse,
    AegisStatus,
    NetworkSummary,
    ThreatSummary,
    DeviceInfo,
    SignalSeverity,
    StandardSignal,
    AgentInvocation,
    AgentResponse,
    ToolDefinition,
    ToolResult,
)

# Signal Fabric (configurable data access)
from .signal_fabric import (
    SignalFabric,
    SignalFabricConfig,
    get_signal_fabric,
)

# ORACLE Agent (legacy, always available)
from .oracle import OracleAgent

# Inference Engine
from .inference import (
    NativeInferenceEngine,
    OllamaBackend,
    get_inference_engine,
)

# Client
from .client import (
    AegisClient,
    get_aegis_client,
)

__version__ = "2.0.0"
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
    "SignalSeverity",
    "StandardSignal",
    "AgentInvocation",
    "AgentResponse",
    "ToolDefinition",
    "ToolResult",

    # Signal Fabric
    "SignalFabric",
    "SignalFabricConfig",
    "get_signal_fabric",

    # ORACLE Agent (legacy)
    "OracleAgent",

    # Inference Engine
    "NativeInferenceEngine",
    "OllamaBackend",
    "get_inference_engine",

    # Client
    "AegisClient",
    "get_aegis_client",
]

# Lazy imports for heavier components (import on demand via client)
# These are importable but not loaded at package import time:
#
#   from core.aegis.soul import SoulConfig, build_system_prompt
#   from core.aegis.memory import MemoryManager, get_memory_manager
#   from core.aegis.principle_guard import check_action, sanitize_input
#   from core.aegis.agents import AgentRegistry, BaseAgent
#   from core.aegis.tool_executor import ToolExecutor
#   from core.aegis.orchestrator import AegisOrchestrator
#   from core.aegis.bridges import BridgeManager
#   from core.aegis.narrator import TemplateNarrator, LLMNarrator
#   from core.aegis.autonomous import AutonomousScheduler, AutonomousWatcher
#   from core.aegis.self_model import SystemModel, get_system_model
#   from core.aegis.inner_psyche import InnerPsyche
