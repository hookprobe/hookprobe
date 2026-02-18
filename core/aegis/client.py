"""
AEGIS Client

Top-level client that wires together all AEGIS components:
  - Inference Engine (hybrid LLM)
  - Soul Config (identity)
  - Memory Manager (persistent memory)
  - Agent Registry (8 specialized agents)
  - Tool Executor (safe action execution)
  - Orchestrator (event routing)
  - Bridge Manager (real-time signals)
  - Autonomous Scheduler (periodic tasks)
  - Autonomous Watcher (real-time response)
  - Inner Psyche (reflection & learning)
  - Self Model (system knowledge)
  - Narrator (response formatting)

Provides session management for chat conversations.
"""

import logging
import threading
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from .inference import NativeInferenceEngine, get_inference_engine
from .signal_fabric import SignalFabric, SignalFabricConfig, get_signal_fabric
from .types import AegisStatus, ChatMessage, ChatResponse

logger = logging.getLogger(__name__)

MAX_SESSION_MESSAGES = 40
MAX_SESSIONS = 100


class AegisClient:
    """Top-level AEGIS client managing the full consciousness stack.

    Backward-compatible: chat(), get_status(), clear_session() still work.
    New: start(), stop(), get_full_status() for autonomous operation.
    """

    def __init__(self, config: Optional[SignalFabricConfig] = None):
        self.fabric = get_signal_fabric(config)
        self.engine = get_inference_engine()
        self._sessions: Dict[str, List[ChatMessage]] = {}
        self._sessions_lock = threading.Lock()

        # Phase 1: Soul + Memory
        self.soul_config = None
        self.memory = None
        self.principle_guard = None

        # Phase 2: Agents + Orchestrator
        self.registry = None
        self.tool_executor = None
        self.orchestrator = None

        # Phase 3: Bridges + Narrator
        self.bridges = None
        self.narrator = None

        # Phase 4: Autonomous
        self.scheduler = None
        self.watcher = None
        self.self_model = None
        self.psyche = None

        # Legacy oracle (always available)
        self.oracle = None

        # Initialize components
        self._init_components()

    def _init_components(self):
        """Initialize all AEGIS components with graceful fallbacks."""
        # Phase 1: Soul + Memory + Safety
        try:
            from .soul import SoulConfig
            self.soul_config = SoulConfig()
        except Exception as e:
            logger.debug("Soul config init: %s", e)

        try:
            from .memory import MemoryManager
            self.memory = MemoryManager()
        except Exception as e:
            logger.debug("Memory init: %s", e)

        # Phase 2: Agent Registry + Tools + Orchestrator
        try:
            from .agents import AgentRegistry
            from .tool_executor import ToolExecutor

            self.registry = AgentRegistry(
                engine=self.engine,
                fabric=self.fabric,
                memory=self.memory,
                soul_config=self.soul_config,
            )
            self.tool_executor = ToolExecutor(memory=self.memory)

            from .orchestrator import AegisOrchestrator
            self.orchestrator = AegisOrchestrator(
                registry=self.registry,
                tool_executor=self.tool_executor,
                memory=self.memory,
            )
        except Exception as e:
            logger.debug("Orchestrator init: %s", e)

        # Phase 3: Bridges + Narrator
        try:
            from .bridges import BridgeManager
            self.bridges = BridgeManager()
        except Exception as e:
            logger.debug("Bridges init: %s", e)

        try:
            from .narrator import TemplateNarrator
            self.narrator = TemplateNarrator()
        except Exception as e:
            logger.debug("Narrator init: %s", e)

        # Phase 4: Autonomous + Self-Model + Psyche
        try:
            from .autonomous import AutonomousScheduler, AutonomousWatcher
            self.scheduler = AutonomousScheduler()
            self.watcher = AutonomousWatcher()
            if self.orchestrator:
                self.watcher.set_orchestrator(self.orchestrator)
            if self.memory:
                self.watcher.set_memory(self.memory)
        except Exception as e:
            logger.debug("Autonomous init: %s", e)

        try:
            from .self_model import SystemModel
            self.self_model = SystemModel()
        except Exception as e:
            logger.debug("Self-model init: %s", e)

        try:
            from .inner_psyche import InnerPsyche
            self.psyche = InnerPsyche()
            if self.memory:
                self.psyche.set_memory(self.memory)
        except Exception as e:
            logger.debug("Psyche init: %s", e)

        # Legacy oracle (backward compat)
        try:
            from .oracle import OracleAgent
            self.oracle = OracleAgent(self.engine, self.fabric)
        except Exception as e:
            logger.debug("Legacy oracle init: %s", e)

    # ------------------------------------------------------------------
    # Chat Interface
    # ------------------------------------------------------------------

    def chat(self, session_id: str, message: str) -> ChatResponse:
        """Send a user message and get a response.

        Uses the orchestrator (multi-agent routing) if available,
        otherwise falls back to the legacy OracleAgent.
        """
        if not session_id:
            session_id = str(uuid.uuid4())

        # Snapshot history under lock
        with self._sessions_lock:
            history = list(self._sessions.get(session_id, []))

        user_msg = ChatMessage(role="user", content=message, timestamp=datetime.now())
        history.append(user_msg)

        # LLM call outside lock (can be slow)
        if self.orchestrator:
            response = self.orchestrator.process_user_query(
                message, session_id, history,
            )
        elif self.oracle:
            response = self.oracle.respond(message, history)
        else:
            response = ChatResponse(
                message="AEGIS is starting up. Please try again in a moment.",
                agent="SYSTEM",
                confidence=0.0,
                sources=[],
            )

        assistant_msg = ChatMessage(
            role="assistant", content=response.message, timestamp=datetime.now(),
        )
        history.append(assistant_msg)

        if len(history) > MAX_SESSION_MESSAGES:
            history = history[-MAX_SESSION_MESSAGES:]

        # Write back under lock
        with self._sessions_lock:
            self._sessions[session_id] = history
            if len(self._sessions) > MAX_SESSIONS:
                oldest_key = next(iter(self._sessions))
                del self._sessions[oldest_key]

        return response

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start autonomous operation: bridges, scheduler, watcher.

        Call this after initialization to begin real-time monitoring.
        """
        # Discover system model
        if self.self_model:
            try:
                model = self.self_model.discover()
                if self.memory:
                    self.memory.store(
                        "institutional", "system_model",
                        str(model), source="self_model",
                    )
                logger.info(
                    "System model: %s tier, %d capabilities active",
                    model.get("tier", "unknown"),
                    sum(1 for v in model.get("capabilities", {}).values() if v),
                )
            except Exception as e:
                logger.error("System discovery error: %s", e)

        # Start signal bridges
        if self.bridges:
            if self.watcher:
                self.bridges.set_callback(self.watcher.on_signal)
            self.bridges.start_all()
            logger.info("Signal bridges started: %s", self.bridges.list_bridges())

        # Start autonomous scheduler
        if self.scheduler:
            if self.orchestrator:
                self.scheduler.set_callback(self._scheduler_callback)
            self.scheduler.start()
            logger.info("Autonomous scheduler started")

    def stop(self) -> None:
        """Stop all autonomous components."""
        if self.bridges:
            self.bridges.stop_all()
        if self.scheduler:
            self.scheduler.stop()
        if self.memory:
            self.memory.close()
        logger.info("AEGIS stopped")

    def _scheduler_callback(
        self, agent: str, action: str, params: Dict[str, Any],
    ) -> None:
        """Handle a scheduled task via the orchestrator."""
        if action == "memory_decay" and self.memory:
            self.memory.decay_all()
            return

        if action == "review_decisions" and self.psyche:
            report = self.psyche.reflect()
            logger.info(
                "Reflection: %d decisions, %d patterns, %d suggestions",
                report.decisions_reviewed,
                len(report.patterns_found),
                len(report.suggestions),
            )
            return

        # Route other scheduled tasks through orchestrator
        if self.orchestrator:
            from .types import StandardSignal
            signal = StandardSignal(
                source="scheduler",
                event_type=f"scheduled.{action}",
                severity="INFO",
                data=params,
            )
            self.orchestrator.process_signal(signal)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self) -> AegisStatus:
        """Get AEGIS system health status (backward compatible)."""
        health = self.engine.health_check()
        return AegisStatus(**health)

    def get_full_status(self) -> Dict[str, Any]:
        """Get comprehensive status of all AEGIS components."""
        status: Dict[str, Any] = {
            "engine": self.engine.health_check(),
            "agents": self.registry.list_agents() if self.registry else [],
            "sessions": len(self._sessions),
        }

        if self.orchestrator:
            status["orchestrator"] = self.orchestrator.get_stats()
        if self.bridges:
            status["bridges"] = self.bridges.get_status()
        if self.memory:
            status["memory"] = self.memory.get_stats()
        if self.self_model:
            status["system_model"] = self.self_model.get_model()
        if self.scheduler:
            status["scheduled_tasks"] = self.scheduler.get_tasks()
        if self.watcher:
            status["watcher"] = self.watcher.get_stats()
        if self.psyche:
            status["psyche"] = self.psyche.get_stats()

        return status

    # ------------------------------------------------------------------
    # Session Management
    # ------------------------------------------------------------------

    def clear_session(self, session_id: str) -> bool:
        """Clear a conversation session."""
        with self._sessions_lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
        return False

    def get_session_history(self, session_id: str) -> List[ChatMessage]:
        """Get conversation history for a session."""
        with self._sessions_lock:
            return list(self._sessions.get(session_id, []))

    # ------------------------------------------------------------------
    # Learning Interface
    # ------------------------------------------------------------------

    def provide_feedback(
        self,
        decision_id: str,
        feedback: str,
        correct_action: str = "",
    ) -> None:
        """Provide user feedback on a decision.

        Args:
            decision_id: The decision to provide feedback on.
            feedback: "false_alarm", "wrong_action", "missed_threat", "good".
            correct_action: What the correct action should have been.
        """
        if self.psyche:
            self.psyche.learn_from_correction(decision_id, feedback, correct_action)


# Singleton
_client: Optional[AegisClient] = None


def get_aegis_client(config: Optional[SignalFabricConfig] = None) -> AegisClient:
    """Get or create the global AegisClient instance.

    Args:
        config: Optional SignalFabricConfig. Only used when creating
                the instance for the first time.
    """
    global _client
    if _client is None:
        _client = AegisClient(config)
    return _client
