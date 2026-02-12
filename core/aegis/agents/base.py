"""
AEGIS Base Agent — Abstract base class for all specialized agents.

Every agent inherits from BaseAgent and implements:
- trigger_patterns: Regex patterns for signal routing
- allowed_tools: Tools this agent is permitted to use
- respond(): Core logic for handling signals/queries
"""

import logging
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from ..types import AgentResponse, ChatMessage, ChatResponse, StandardSignal

if TYPE_CHECKING:
    from ..inference import NativeInferenceEngine
    from ..memory import MemoryManager
    from ..signal_fabric import SignalFabric
    from ..soul import SoulConfig

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Abstract base class for AEGIS agents.

    Each agent has:
    - A name and description
    - Trigger patterns (regex) for automatic routing
    - A list of allowed tools
    - A confidence threshold for autonomous action
    - Access to the inference engine, signal fabric, and memory
    """

    name: str = "BASE"
    description: str = "Base agent"
    trigger_patterns: List[str] = []
    allowed_tools: List[str] = []
    confidence_threshold: float = 0.6

    def __init__(
        self,
        engine: "NativeInferenceEngine",
        fabric: "SignalFabric",
        memory: Optional["MemoryManager"] = None,
        soul_config: Optional["SoulConfig"] = None,
    ):
        self.engine = engine
        self.fabric = fabric
        self.memory = memory
        self.soul_config = soul_config
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.trigger_patterns
        ]

    @abstractmethod
    def respond_to_signal(
        self,
        signal: StandardSignal,
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResponse:
        """Handle an automated signal from a bridge.

        Args:
            signal: Normalized signal from a bridge.
            context: Additional context (memory, related signals).

        Returns:
            AgentResponse with action and reasoning.
        """
        ...

    @abstractmethod
    def respond_to_query(
        self,
        message: str,
        history: List[ChatMessage],
        context: Optional[Dict[str, Any]] = None,
    ) -> ChatResponse:
        """Handle a user chat query.

        Args:
            message: User's question or request.
            history: Conversation history.
            context: Additional context.

        Returns:
            ChatResponse with human-readable message.
        """
        ...

    def can_handle(self, signal: StandardSignal) -> float:
        """Score how well this agent can handle a given signal.

        Returns a confidence score 0.0-1.0. The orchestrator uses
        this to route signals to the best agent.

        Default implementation checks trigger_patterns against
        signal source and event_type.
        """
        text = f"{signal.source} {signal.event_type} {signal.severity}"
        data_str = " ".join(str(v) for v in signal.data.values())
        full_text = f"{text} {data_str}"

        max_score = 0.0
        for pattern in self._compiled_patterns:
            if pattern.search(full_text):
                max_score = max(max_score, 0.8)

        return max_score

    def can_handle_query(self, message: str) -> float:
        """Score how well this agent can handle a user query.

        Returns 0.0-1.0 confidence.
        """
        for pattern in self._compiled_patterns:
            if pattern.search(message):
                return 0.7
        return 0.0

    def get_system_prompt(self, context: Optional[Dict[str, Any]] = None) -> str:
        """Build the system prompt for this agent."""
        from ..soul import build_system_prompt
        ctx = context or {}
        ctx["agent_name"] = self.name
        return build_system_prompt(self.name, ctx, self.soul_config)

    def _llm_chat(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 512,
    ) -> Optional[str]:
        """Send messages to the LLM and return content.

        Returns None if LLM is unavailable.
        """
        if not self.engine.is_ready:
            return None

        result = self.engine.chat(messages, max_tokens=max_tokens)
        if not result:
            return None

        return result.get("message", {}).get("content", "")

    def _build_context_str(self) -> str:
        """Build a context string from signal fabric and memory."""
        parts = []

        # Signal fabric context
        try:
            summary = self.fabric.get_network_summary()
            parts.append(
                f"Network: {summary.qsecbit_status} ({summary.qsecbit_score:.0%}), "
                f"{summary.device_count} devices, {summary.threat_count} threats, "
                f"{summary.dns_blocked_24h} DNS blocked"
            )
        except Exception:
            pass

        # Memory context
        if self.memory:
            try:
                mem_ctx = self.memory.recall_context(max_tokens=300)
                if mem_ctx:
                    parts.append(mem_ctx)
            except Exception:
                pass

        return "\n\n".join(parts)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name}>"
