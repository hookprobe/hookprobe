"""
AEGIS Client

Singleton client managing the LLM connection, SignalFabric,
and ORACLE agent. Provides session management for chat conversations.
"""

import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from .inference import NativeInferenceEngine, get_inference_engine
from .oracle import OracleAgent
from .signal_fabric import SignalFabric, SignalFabricConfig, get_signal_fabric
from .types import AegisStatus, ChatMessage, ChatResponse

logger = logging.getLogger(__name__)

MAX_SESSION_MESSAGES = 40  # Keep last 40 messages per session
MAX_SESSIONS = 100  # Limit total sessions in memory


class AegisClient:
    """Top-level AEGIS client managing agents and sessions."""

    def __init__(self, config: Optional[SignalFabricConfig] = None):
        self.fabric = get_signal_fabric(config)
        self.engine = get_inference_engine()
        self.oracle = OracleAgent(self.engine, self.fabric)
        self._sessions: Dict[str, List[ChatMessage]] = {}

    def chat(self, session_id: str, message: str) -> ChatResponse:
        """Send a user message and get a response.

        Creates a new session if session_id doesn't exist.
        """
        if not session_id:
            session_id = str(uuid.uuid4())

        # Get or create session history
        history = self._sessions.get(session_id, [])

        # Add user message
        user_msg = ChatMessage(role="user", content=message, timestamp=datetime.now())
        history.append(user_msg)

        # Get response from ORACLE
        response = self.oracle.respond(message, history)

        # Add assistant response to history
        assistant_msg = ChatMessage(
            role="assistant", content=response.message, timestamp=datetime.now()
        )
        history.append(assistant_msg)

        # Trim history
        if len(history) > MAX_SESSION_MESSAGES:
            history = history[-MAX_SESSION_MESSAGES:]

        self._sessions[session_id] = history

        # Evict oldest sessions if over limit
        if len(self._sessions) > MAX_SESSIONS:
            oldest_key = next(iter(self._sessions))
            del self._sessions[oldest_key]

        return response

    def get_status(self) -> AegisStatus:
        """Get AEGIS system health status."""
        health = self.engine.health_check()
        return AegisStatus(**health)

    def clear_session(self, session_id: str) -> bool:
        """Clear a conversation session."""
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False

    def get_session_history(self, session_id: str) -> List[ChatMessage]:
        """Get conversation history for a session."""
        return self._sessions.get(session_id, [])


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
