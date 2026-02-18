"""
AEGIS Orchestrator — Event Router + Coordinator

Routes signals to the best agent, coordinates multi-agent responses,
and handles the chat pipeline. This is the central brain that connects
agents, tools, memory, and the signal fabric.
"""

import logging
import time
import threading
from collections import deque
from typing import Any, Deque, Dict, List, Optional

from .agents import AgentRegistry
from .memory import MemoryManager
from .principle_guard import sanitize_input, sanitize_output
from .tool_executor import ToolExecutor
from .types import (
    AgentInvocation,
    AgentResponse,
    ChatMessage,
    ChatResponse,
    StandardSignal,
)

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Signal Routing Rules (rule-based, no LLM needed)
# ------------------------------------------------------------------

ROUTING_RULES = {
    # Severity-based escalation
    "threat.severity.critical": ["GUARDIAN", "MEDIC"],
    "threat.severity.high": ["GUARDIAN"],

    # Source-based routing
    "qsecbit.l3": ["GUARDIAN"],
    "qsecbit.l4": ["GUARDIAN", "SCOUT"],
    "qsecbit.l5": ["VIGIL"],

    # Event type routing
    "dns.block": ["WATCHDOG"],
    "dns.dga": ["WATCHDOG"],
    "dns.tunnel": ["WATCHDOG"],
    "device.new": ["SHIELD"],
    "device.affinity": ["SHIELD"],
    "tls.downgrade": ["VIGIL"],
    "tls.ssl_strip": ["VIGIL"],
    "scan.detected": ["SCOUT"],
    "scan.port": ["SCOUT"],

    # NAPSE IDS/IPS/NSM routing
    "napse.ids_alert": ["GUARDIAN"],
    "napse.anomaly": ["WATCHDOG"],
    "napse.dns": ["WATCHDOG"],
    "napse.tls": ["VIGIL"],
    "napse.http": ["SCOUT"],
    "napse.file": ["GUARDIAN", "MEDIC"],
    "napse.flow": ["SCOUT"],
    "mirage.honeypot_deployed": ["SCOUT"],
    "mirage.attacker_profiled": ["SCOUT", "GUARDIAN"],
    "mirage.attacker_learning": ["GUARDIAN", "MEDIC"],
    "mirage.payload_captured": ["GUARDIAN", "MEDIC"],
    "mirage.level_escalated": ["SCOUT"],
    "mirage.intel": ["GUARDIAN"],
    "sia.intent_detected": ["GUARDIAN", "MEDIC", "SCOUT"],
    "sia.sandbox_triggered": ["MEDIC"],
    "healing.process_suspicious": ["GUARDIAN", "FORGE"],
    "healing.process_malicious": ["GUARDIAN", "MEDIC"],
    "healing.process_killed": ["MEDIC"],
    "healing.process_quarantined": ["MEDIC"],
    "healing.syscall_connect": ["GUARDIAN"],
    "healing.syscall_openat": ["FORGE"],
    "healing.hotpatch_applied": ["FORGE"],
    "scheduled.audit": ["FORGE"],
    "scheduled.health_check": ["ORACLE"],
    "scheduled.generate_report": ["ORACLE"],
    "scheduled.recommend_hardening": ["FORGE"],
    "config.change": ["FORGE"],

    # Neuro-Kernel routing
    "napse.zero_day": ["GUARDIAN"],
    "kernel.ebpf_deployed": ["MEDIC", "ORACLE"],
    "kernel.ebpf_failed": ["FORGE", "MEDIC"],
    "kernel.rollback": ["MEDIC"],
    "kernel.anomaly": ["GUARDIAN", "MEDIC"],
    "kernel.verdict": ["GUARDIAN"],
    "kernel.nexus_offload": ["ORACLE"],
    "kernel.llm_blocked": ["MEDIC"],
    "kernel.shadow_finding": ["FORGE", "GUARDIAN"],

    # Reflex graduated response routing
    "reflex.level_changed": ["GUARDIAN", "MEDIC"],
    "reflex.escalation": ["GUARDIAN", "MEDIC"],
    "reflex.recovery": ["MEDIC"],
    "reflex.jitter_applied": ["GUARDIAN"],
    "reflex.disconnect": ["GUARDIAN", "MEDIC"],

    # Multi-agent escalation (MEDIC coordinates)
    "incident.multi_agent": ["MEDIC"],
    "incident.critical": ["MEDIC"],

    # Default (user queries)
    "user.query": ["ORACLE"],
}


class AegisOrchestrator:
    """Central coordinator for the AEGIS consciousness.

    Responsibilities:
    - Route signals to the best agent(s)
    - Execute the full pipeline: route -> invoke -> tools -> narrate
    - Handle user chat queries
    - Correlate cross-agent events for escalation
    - Manage the event history for pattern detection
    """

    def __init__(
        self,
        registry: AgentRegistry,
        tool_executor: ToolExecutor,
        memory: Optional[MemoryManager] = None,
    ):
        self.registry = registry
        self.tool_executor = tool_executor
        self.memory = memory

        # Recent signals for correlation
        self._recent_signals: Deque[StandardSignal] = deque(maxlen=100)
        self._recent_agent_triggers: Deque[AgentInvocation] = deque(maxlen=50)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Signal Processing Pipeline
    # ------------------------------------------------------------------

    def process_signal(self, signal: StandardSignal) -> List[AgentResponse]:
        """Process a signal through the full pipeline.

        1. Route signal to agent(s)
        2. Invoke each agent
        3. Execute any tool calls
        4. Check for cross-agent escalation
        5. Store in memory

        Returns list of agent responses.
        """
        with self._lock:
            self._recent_signals.append(signal)

        # Step 1: Route
        agents = self.route_signal(signal)
        if not agents:
            agents = [("ORACLE", 0.3)]

        responses = []

        for agent_name, confidence in agents:
            # Step 2: Invoke agent
            agent = self.registry.get(agent_name)
            if not agent:
                continue

            invocation = AgentInvocation(
                agent_name=agent_name,
                signal=signal,
            )
            with self._lock:
                self._recent_agent_triggers.append(invocation)

            try:
                context = self._build_signal_context(signal)
                response = agent.respond_to_signal(signal, context)
                responses.append(response)

                # Step 3: Execute tool calls
                for tool_call in response.tool_calls:
                    tool_name = tool_call.get("name", "")
                    params = tool_call.get("params", {})
                    if tool_name:
                        tool_result = self.tool_executor.execute(
                            agent_name, tool_name, params,
                        )
                        logger.info(
                            "Tool %s by %s: success=%s",
                            tool_name, agent_name, tool_result.success,
                        )

                # Step 4: Store agent response in memory
                if self.memory and response.action:
                    self.memory.store(
                        "session",
                        f"action_{int(time.time())}",
                        f"{agent_name}: {response.action} — {response.reasoning}",
                    )

            except Exception as e:
                logger.error("Agent %s error: %s", agent_name, e)

        # Step 5: Check for cross-agent escalation
        escalation = self._check_escalation(responses)
        if escalation:
            responses.append(escalation)

        return responses

    def route_signal(self, signal: StandardSignal) -> List[tuple]:
        """Route a signal to the best agent(s) using rules + registry.

        Returns list of (agent_name, confidence) tuples.
        """
        agents = []

        # Rule-based routing first
        for rule_key, rule_agents in ROUTING_RULES.items():
            if self._matches_rule(signal, rule_key):
                for agent_name in rule_agents:
                    agents.append((agent_name, 0.8))

        # If no rule matched, use registry-based routing
        if not agents:
            candidates = self.registry.find_all_agents(signal, min_confidence=0.5)
            agents = candidates[:3]  # Max 3 agents per signal

        # Deduplicate
        seen = set()
        unique_agents = []
        for name, conf in agents:
            if name not in seen:
                seen.add(name)
                unique_agents.append((name, conf))

        return unique_agents

    # ------------------------------------------------------------------
    # Chat Pipeline
    # ------------------------------------------------------------------

    def process_user_query(
        self,
        message: str,
        session_id: str,
        history: Optional[List[ChatMessage]] = None,
    ) -> ChatResponse:
        """Process a user chat message through the agent pipeline.

        1. Sanitize input
        2. Find best agent for the query
        3. Invoke agent with context
        4. Sanitize output
        5. Store in memory

        Returns ChatResponse.
        """
        # Sanitize input
        clean_message = sanitize_input(message)
        if not clean_message:
            return ChatResponse(
                message="I couldn't understand your message. Please try again.",
                agent="ORACLE",
                confidence=0.0,
                sources=[],
            )

        history = history or []

        # Find best agent
        agent_name, confidence = self.registry.find_best_agent_for_query(clean_message)
        agent = self.registry.get(agent_name)
        if not agent:
            agent = self.registry.get("ORACLE")
            agent_name = "ORACLE"

        # Build context with memory
        context = {}
        if self.memory:
            context["memory_context"] = self.memory.recall_context(max_tokens=300)

        # Invoke agent
        try:
            response = agent.respond_to_query(clean_message, history, context)
        except Exception as e:
            logger.exception("Agent %s query error", agent_name)
            response = ChatResponse(
                message="An error occurred while processing your request.",
                agent=agent_name,
                confidence=0.0,
                sources=[],
            )

        # Sanitize output
        response.message = sanitize_output(response.message)

        return response

    # ------------------------------------------------------------------
    # Cross-Agent Correlation
    # ------------------------------------------------------------------

    def _check_escalation(
        self,
        responses: List[AgentResponse],
    ) -> Optional[AgentResponse]:
        """Check if multiple agent responses indicate coordinated attack.

        Triggers MEDIC if 2+ different agents are triggered within 60s.
        """
        if len(responses) < 2:
            return None

        # Check if responses request escalation
        for r in responses:
            if r.escalate_to:
                escalate_agent = self.registry.get(r.escalate_to)
                if escalate_agent:
                    # Create a synthetic signal for the escalation
                    signal = StandardSignal(
                        source="orchestrator",
                        event_type="incident.multi_agent",
                        severity="HIGH",
                        data={
                            "related_agents": [r.agent for r in responses],
                            "trigger_count": len(responses),
                        },
                    )
                    return escalate_agent.respond_to_signal(signal)

        # Auto-escalate to MEDIC if 2+ different agents triggered
        unique_agents = set(r.agent for r in responses if r.action)
        if len(unique_agents) >= 2 and "MEDIC" not in unique_agents:
            medic = self.registry.get("MEDIC")
            if medic:
                signal = StandardSignal(
                    source="orchestrator",
                    event_type="incident.multi_agent",
                    severity="HIGH",
                    data={
                        "related_agents": list(unique_agents),
                        "trigger_count": len(unique_agents),
                    },
                )
                logger.info(
                    "Escalating to MEDIC: %d agents triggered (%s)",
                    len(unique_agents), ", ".join(unique_agents),
                )
                return medic.respond_to_signal(signal)

        return None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _matches_rule(self, signal: StandardSignal, rule_key: str) -> bool:
        """Check if a signal matches a routing rule key."""
        parts = rule_key.split(".")

        if parts[0] == "threat" and parts[1] == "severity":
            return signal.severity.upper() == parts[2].upper()

        # Match source.event_type patterns
        source_match = signal.source.lower() == parts[0]
        if len(parts) >= 2:
            event_match = parts[1] in signal.event_type.lower()
            return source_match and event_match

        return source_match

    def _build_signal_context(self, signal: StandardSignal) -> Dict[str, Any]:
        """Build context for an agent processing a signal."""
        context: Dict[str, Any] = {}

        # Add related recent signals
        related = []
        for s in self._recent_signals:
            if s is not signal and s.source == signal.source:
                related.append({
                    "source": s.source,
                    "event_type": s.event_type,
                    "severity": s.severity,
                    "timestamp": s.timestamp.isoformat(),
                })
        if related:
            context["related_signals"] = related[-5:]

        # Add memory context
        if self.memory:
            context["memory_context"] = self.memory.recall_context(max_tokens=200)

        return context

    def get_stats(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        return {
            "agents": self.registry.list_agents(),
            "recent_signals": len(self._recent_signals),
            "recent_triggers": len(self._recent_agent_triggers),
            "pending_confirmations": len(self.tool_executor.get_pending()),
        }
