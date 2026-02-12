"""
AEGIS Agent Registry

Auto-discovers and manages all specialized agents.
Provides routing: given a signal or query, find the best agent to handle it.
"""

import logging
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

from .base import BaseAgent
from .oracle_agent import OracleAgentV2
from .guardian_agent import GuardianAgent
from .watchdog_agent import WatchdogAgent
from .shield_agent import ShieldAgent
from .vigil_agent import VigilAgent
from .scout_agent import ScoutAgent
from .forge_agent import ForgeAgent
from .medic_agent import MedicAgent

if TYPE_CHECKING:
    from ..inference import NativeInferenceEngine
    from ..memory import MemoryManager
    from ..signal_fabric import SignalFabric
    from ..soul import SoulConfig
    from ..types import StandardSignal

logger = logging.getLogger(__name__)

# All agent classes in priority order
AGENT_CLASSES = [
    GuardianAgent,
    WatchdogAgent,
    ShieldAgent,
    VigilAgent,
    ScoutAgent,
    ForgeAgent,
    MedicAgent,
    OracleAgentV2,  # ORACLE is always last (catch-all)
]


class AgentRegistry:
    """Registry of all AEGIS agents.

    Manages agent lifecycle and provides signal/query routing.
    """

    def __init__(
        self,
        engine: "NativeInferenceEngine",
        fabric: "SignalFabric",
        memory: Optional["MemoryManager"] = None,
        soul_config: Optional["SoulConfig"] = None,
    ):
        self._agents: Dict[str, BaseAgent] = {}
        self._engine = engine
        self._fabric = fabric
        self._memory = memory
        self._soul_config = soul_config

        # Auto-register all built-in agents
        for agent_cls in AGENT_CLASSES:
            self.register(agent_cls(engine, fabric, memory, soul_config))

    def register(self, agent: BaseAgent) -> None:
        """Register an agent instance."""
        self._agents[agent.name] = agent
        logger.debug("Registered agent: %s", agent.name)

    def get(self, name: str) -> Optional[BaseAgent]:
        """Get an agent by name."""
        return self._agents.get(name.upper())

    def list_agents(self) -> List[str]:
        """List all registered agent names."""
        return list(self._agents.keys())

    def find_best_agent(self, signal: "StandardSignal") -> Tuple[str, float]:
        """Find the best agent to handle a signal.

        Returns (agent_name, confidence). ORACLE is the fallback
        if no specialized agent claims the signal.
        """
        best_name = "ORACLE"
        best_score = 0.3  # ORACLE's minimum

        for name, agent in self._agents.items():
            score = agent.can_handle(signal)
            if score > best_score:
                best_score = score
                best_name = name

        return best_name, best_score

    def find_best_agent_for_query(self, message: str) -> Tuple[str, float]:
        """Find the best agent to handle a user query.

        Returns (agent_name, confidence).
        """
        best_name = "ORACLE"
        best_score = 0.3

        for name, agent in self._agents.items():
            score = agent.can_handle_query(message)
            if score > best_score:
                best_score = score
                best_name = name

        return best_name, best_score

    def find_all_agents(
        self,
        signal: "StandardSignal",
        min_confidence: float = 0.5,
    ) -> List[Tuple[str, float]]:
        """Find all agents that can handle a signal above threshold.

        Returns list of (agent_name, confidence) sorted by confidence desc.
        """
        candidates = []
        for name, agent in self._agents.items():
            score = agent.can_handle(signal)
            if score >= min_confidence:
                candidates.append((name, score))

        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates


__all__ = [
    "AgentRegistry",
    "BaseAgent",
    "OracleAgentV2",
    "GuardianAgent",
    "WatchdogAgent",
    "ShieldAgent",
    "VigilAgent",
    "ScoutAgent",
    "ForgeAgent",
    "MedicAgent",
    "AGENT_CLASSES",
]
