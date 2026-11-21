"""
AEGIS Tool Executor — Safe Action Execution

Validates every tool call against the principle guard and permission matrix
before execution. Logs all actions to the audit trail.

Pipeline: principle_guard -> permission_matrix -> rate_limit -> execute -> audit
"""

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from .principle_guard import check_action, sanitize_output
from .types import ToolDefinition, ToolResult

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Tool Registry — All available tools and their definitions
# ------------------------------------------------------------------

TOOL_REGISTRY: Dict[str, ToolDefinition] = {
    # GUARDIAN tools
    "block_ip": ToolDefinition(
        name="block_ip",
        description="Block traffic from a source IP address",
        parameters={
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to block"},
                "duration": {"type": "integer", "description": "Block duration in seconds (0=permanent)", "default": 3600},
                "reason": {"type": "string", "description": "Reason for blocking"},
            },
            "required": ["ip"],
        },
        agents=["GUARDIAN", "MEDIC"],
    ),
    "rate_limit": ToolDefinition(
        name="rate_limit",
        description="Apply rate limiting to traffic from a source",
        parameters={
            "type": "object",
            "properties": {
                "ip": {"type": "string"},
                "rate": {"type": "string", "description": "Rate limit (e.g., 100/s)"},
                "reason": {"type": "string"},
            },
            "required": ["ip"],
        },
        agents=["GUARDIAN"],
    ),
    "quarantine_subnet": ToolDefinition(
        name="quarantine_subnet",
        description="Isolate an entire subnet via OpenFlow rules",
        parameters={
            "type": "object",
            "properties": {
                "subnet": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["subnet"],
        },
        agents=["GUARDIAN", "MEDIC"],
        requires_confirmation=True,
    ),
    "unblock_ip": ToolDefinition(
        name="unblock_ip",
        description="Remove an IP block",
        parameters={
            "type": "object",
            "properties": {
                "ip": {"type": "string"},
            },
            "required": ["ip"],
        },
        agents=["GUARDIAN", "MEDIC"],
    ),

    # WATCHDOG tools
    "block_domain": ToolDefinition(
        name="block_domain",
        description="Add a domain to the DNS blocklist",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["domain"],
        },
        agents=["WATCHDOG"],
    ),
    "whitelist_domain": ToolDefinition(
        name="whitelist_domain",
        description="Add a domain to the DNS whitelist",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain or *.domain.com wildcard"},
            },
            "required": ["domain"],
        },
        agents=["WATCHDOG"],
    ),
    "adjust_protection": ToolDefinition(
        name="adjust_protection",
        description="Change dnsXai protection level (0-5)",
        parameters={
            "type": "object",
            "properties": {
                "level": {"type": "integer", "minimum": 0, "maximum": 5},
            },
            "required": ["level"],
        },
        agents=["WATCHDOG"],
    ),
    "investigate_domain": ToolDefinition(
        name="investigate_domain",
        description="Get detailed classification for a domain",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
            },
            "required": ["domain"],
        },
        agents=["WATCHDOG", "ORACLE"],
    ),

    # SHIELD tools
    "classify_device": ToolDefinition(
        name="classify_device",
        description="Identify and classify a device type",
        parameters={
            "type": "object",
            "properties": {
                "mac": {"type": "string"},
                "hostname": {"type": "string"},
                "vendor": {"type": "string"},
            },
            "required": ["mac"],
        },
        agents=["SHIELD"],
    ),
    "assign_policy": ToolDefinition(
        name="assign_policy",
        description="Set security policy for a device or bubble",
        parameters={
            "type": "object",
            "properties": {
                "mac": {"type": "string"},
                "policy": {"type": "string"},
            },
            "required": ["mac", "policy"],
        },
        agents=["SHIELD"],
    ),
    "move_bubble": ToolDefinition(
        name="move_bubble",
        description="Move a device to a different ecosystem bubble",
        parameters={
            "type": "object",
            "properties": {
                "mac": {"type": "string"},
                "bubble_id": {"type": "string"},
            },
            "required": ["mac", "bubble_id"],
        },
        agents=["SHIELD"],
    ),

    # VIGIL tools
    "block_ssl_strip": ToolDefinition(
        name="block_ssl_strip",
        description="Block a detected SSL stripping attempt",
        parameters={
            "type": "object",
            "properties": {
                "source_ip": {"type": "string"},
                "destination": {"type": "string"},
            },
            "required": ["source_ip"],
        },
        agents=["VIGIL"],
    ),
    "enforce_tls": ToolDefinition(
        name="enforce_tls",
        description="Force TLS for a destination",
        parameters={
            "type": "object",
            "properties": {
                "destination": {"type": "string"},
                "min_version": {"type": "string", "default": "1.2"},
            },
            "required": ["destination"],
        },
        agents=["VIGIL"],
    ),
    "terminate_session": ToolDefinition(
        name="terminate_session",
        description="Kill a compromised session",
        parameters={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["session_id"],
        },
        agents=["VIGIL", "MEDIC"],
        requires_confirmation=True,
    ),

    # SCOUT tools
    "honeypot_redirect": ToolDefinition(
        name="honeypot_redirect",
        description="Redirect attacker traffic to a honeypot",
        parameters={
            "type": "object",
            "properties": {
                "source_ip": {"type": "string"},
            },
            "required": ["source_ip"],
        },
        agents=["SCOUT"],
    ),
    "scan_fingerprint": ToolDefinition(
        name="scan_fingerprint",
        description="Identify the scanning tool used by an attacker",
        parameters={
            "type": "object",
            "properties": {
                "source_ip": {"type": "string"},
            },
            "required": ["source_ip"],
        },
        agents=["SCOUT"],
    ),
    "profile_attacker": ToolDefinition(
        name="profile_attacker",
        description="Build an attacker profile from observed behavior",
        parameters={
            "type": "object",
            "properties": {
                "source_ip": {"type": "string"},
            },
            "required": ["source_ip"],
        },
        agents=["SCOUT"],
    ),
    "deploy_honeypot": ToolDefinition(
        name="deploy_honeypot",
        description="Deploy an adaptive honeypot targeting a specific attacker IP",
        parameters={
            "type": "object",
            "properties": {
                "source_ip": {"type": "string", "description": "Attacker IP to engage"},
                "ports": {"type": "array", "items": {"type": "integer"}, "description": "Ports to deploy honeypots on"},
            },
            "required": ["source_ip"],
        },
        agents=["SCOUT"],
    ),
    "engage_attacker": ToolDefinition(
        name="engage_attacker",
        description="Actively engage an attacker through adaptive honeypot interaction",
        parameters={
            "type": "object",
            "properties": {
                "source_ip": {"type": "string"},
                "interaction_level": {"type": "integer", "minimum": 1, "maximum": 3, "description": "1=banner, 2=auth, 3=shell"},
            },
            "required": ["source_ip"],
        },
        agents=["SCOUT"],
    ),
    "profile_attacker_ttps": ToolDefinition(
        name="profile_attacker_ttps",
        description="Get detailed TTP profile from Mirage deception intelligence",
        parameters={
            "type": "object",
            "properties": {
                "source_ip": {"type": "string"},
            },
            "required": ["source_ip"],
        },
        agents=["SCOUT", "GUARDIAN"],
    ),

    # SIA tools
    "sandbox_entity": ToolDefinition(
        name="sandbox_entity",
        description="Redirect suspect entity traffic to the virtual sandbox shadow network",
        parameters={
            "type": "object",
            "properties": {
                "entity_id": {"type": "string", "description": "IP address of entity to sandbox"},
                "risk_score": {"type": "number", "description": "SIA risk score (0.0-1.0)"},
                "intent_phase": {"type": "string", "description": "Current attack phase"},
                "duration": {"type": "integer", "description": "Sandbox duration in seconds", "default": 600},
            },
            "required": ["entity_id"],
        },
        agents=["GUARDIAN", "MEDIC"],
        requires_confirmation=True,
    ),
    "release_sandbox": ToolDefinition(
        name="release_sandbox",
        description="Release an entity from the virtual sandbox",
        parameters={
            "type": "object",
            "properties": {
                "entity_id": {"type": "string", "description": "IP address of entity to release"},
                "reason": {"type": "string", "description": "Reason for release"},
            },
            "required": ["entity_id"],
        },
        agents=["GUARDIAN", "MEDIC"],
    ),
    "get_entity_intent": ToolDefinition(
        name="get_entity_intent",
        description="Get the current SIA intent analysis for a network entity",
        parameters={
            "type": "object",
            "properties": {
                "entity_id": {"type": "string", "description": "IP address to query"},
            },
            "required": ["entity_id"],
        },
        agents=["GUARDIAN", "MEDIC", "ORACLE"],
    ),

    # Healing tools (eBPF process enforcement)
    "kill_process": ToolDefinition(
        name="kill_process",
        description="Kill a malicious process identified by the eBPF healing engine",
        parameters={
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "Process ID to kill"},
                "reason": {"type": "string", "description": "Reason for killing"},
            },
            "required": ["pid"],
        },
        agents=["GUARDIAN", "MEDIC"],
        requires_confirmation=True,
    ),
    "quarantine_process": ToolDefinition(
        name="quarantine_process",
        description="Isolate a suspicious process via cgroup resource limits",
        parameters={
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "Process ID to quarantine"},
                "reason": {"type": "string", "description": "Reason for quarantine"},
            },
            "required": ["pid"],
        },
        agents=["GUARDIAN", "MEDIC"],
        requires_confirmation=True,
    ),
    "apply_hotpatch": ToolDefinition(
        name="apply_hotpatch",
        description="Apply an eBPF hotpatch to block a vulnerable syscall pattern",
        parameters={
            "type": "object",
            "properties": {
                "syscall_nr": {"type": "integer", "description": "Syscall number"},
                "target_comm": {"type": "string", "description": "Target process name (empty for all)"},
                "patch_type": {"type": "integer", "description": "1=block, 2=block_arg, 3=log_only"},
            },
            "required": ["syscall_nr"],
        },
        agents=["FORGE"],
        requires_confirmation=True,
    ),

    # FORGE tools
    "generate_password": ToolDefinition(
        name="generate_password",
        description="Generate a cryptographically secure password",
        parameters={
            "type": "object",
            "properties": {
                "length": {"type": "integer", "default": 16},
                "purpose": {"type": "string"},
            },
        },
        agents=["FORGE"],
    ),
    "rotate_wifi": ToolDefinition(
        name="rotate_wifi",
        description="Initiate WiFi password rotation",
        parameters={
            "type": "object",
            "properties": {
                "band": {"type": "string", "description": "2.4ghz, 5ghz, or both"},
            },
        },
        agents=["FORGE"],
        requires_confirmation=True,
    ),
    "recommend_hardening": ToolDefinition(
        name="recommend_hardening",
        description="Generate a hardening report with actionable items",
        parameters={
            "type": "object",
            "properties": {
                "audit_type": {"type": "string", "default": "full"},
            },
        },
        agents=["FORGE"],
    ),

    # REFLEX tools (Surgical Interference)
    "reflex_set_level": ToolDefinition(
        name="reflex_set_level",
        description="Set reflex interference level for a target IP (0=observe, 1=jitter, 2=shadow, 3=disconnect)",
        parameters={
            "type": "object",
            "properties": {
                "source_ip": {"type": "string", "description": "Target IP address"},
                "level": {"type": "integer", "description": "0=observe, 1=jitter, 2=shadow, 3=disconnect"},
                "reason": {"type": "string", "description": "Reason for level change"},
            },
            "required": ["source_ip", "level"],
        },
        agents=["GUARDIAN", "MEDIC"],
        requires_confirmation=True,
    ),
    "reflex_remove_target": ToolDefinition(
        name="reflex_remove_target",
        description="Remove all reflex interference from a target IP",
        parameters={
            "type": "object",
            "properties": {
                "source_ip": {"type": "string", "description": "Target IP address"},
            },
            "required": ["source_ip"],
        },
        agents=["GUARDIAN", "MEDIC"],
    ),
    "reflex_status": ToolDefinition(
        name="reflex_status",
        description="Get current reflex interference status for all active targets",
        parameters={
            "type": "object",
            "properties": {},
        },
        agents=["GUARDIAN", "MEDIC", "ORACLE"],
    ),
    "reflex_force_recovery": ToolDefinition(
        name="reflex_force_recovery",
        description="Force Bayesian recovery check for a target IP",
        parameters={
            "type": "object",
            "properties": {
                "source_ip": {"type": "string", "description": "Target IP address"},
            },
            "required": ["source_ip"],
        },
        agents=["MEDIC"],
    ),

    # NEURO-KERNEL tools
    "deploy_ebpf": ToolDefinition(
        name="deploy_ebpf",
        description="Deploy a verified eBPF program to the kernel",
        parameters={
            "type": "object",
            "properties": {
                "template_name": {"type": "string", "description": "Template name from registry"},
                "interface": {"type": "string", "description": "Network interface to attach to"},
            },
            "required": ["template_name"],
        },
        agents=["GUARDIAN", "MEDIC"],
        requires_confirmation=True,
    ),
    "rollback_ebpf": ToolDefinition(
        name="rollback_ebpf",
        description="Rollback a deployed eBPF program to previous version",
        parameters={
            "type": "object",
            "properties": {
                "program_id": {"type": "string", "description": "Program ID to rollback"},
            },
            "required": ["program_id"],
        },
        agents=["GUARDIAN", "MEDIC"],
    ),
    "list_kernel_programs": ToolDefinition(
        name="list_kernel_programs",
        description="List all active eBPF programs managed by Neuro-Kernel",
        parameters={
            "type": "object",
            "properties": {},
        },
        agents=["GUARDIAN", "MEDIC", "ORACLE"],
    ),
    "query_kernel_context": ToolDefinition(
        name="query_kernel_context",
        description="Search streaming RAG for recent kernel events matching a query",
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Natural language query about kernel events"},
                "time_window_s": {"type": "number", "description": "How far back to search in seconds"},
            },
            "required": ["query"],
        },
        agents=["GUARDIAN", "MEDIC", "ORACLE", "SCOUT"],
    ),
    "get_kernel_metrics": ToolDefinition(
        name="get_kernel_metrics",
        description="Get Neuro-Kernel health metrics: active programs, RAG stats, inference stats",
        parameters={
            "type": "object",
            "properties": {},
        },
        agents=["GUARDIAN", "MEDIC", "ORACLE"],
    ),
    "get_inference_verdict": ToolDefinition(
        name="get_inference_verdict",
        description="Route a threat context through the hybrid inference engine for a verdict",
        parameters={
            "type": "object",
            "properties": {
                "event_type": {"type": "string", "description": "Threat event type"},
                "source_ip": {"type": "string", "description": "Source IP under analysis"},
                "qsecbit_score": {"type": "number", "description": "Current QSecBit score (0-1)"},
                "qsecbit_confidence": {"type": "number", "description": "QSecBit confidence (0-1)"},
            },
            "required": ["event_type", "source_ip"],
        },
        agents=["GUARDIAN", "MEDIC"],
    ),

    # HYDRA SENTINEL tools
    "sentinel_query_verdict": ToolDefinition(
        name="sentinel_query_verdict",
        description="Query HYDRA SENTINEL verdict and threat score for a specific IP",
        parameters={
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to query"},
            },
            "required": ["ip"],
        },
        agents=["GUARDIAN", "MEDIC", "ORACLE"],
    ),
    "sentinel_campaign_info": ToolDefinition(
        name="sentinel_campaign_info",
        description="Get details about a SENTINEL campaign (member IPs, co-occurrence graph, reputation)",
        parameters={
            "type": "object",
            "properties": {
                "campaign_id": {"type": "string", "description": "Campaign ID (e.g., C-1.2.3.4-5)"},
            },
            "required": ["campaign_id"],
        },
        agents=["GUARDIAN", "MEDIC", "SCOUT", "ORACLE"],
    ),
    "sentinel_retrain": ToolDefinition(
        name="sentinel_retrain",
        description="Force SENTINEL model retrain cycle (triggers Page-Hinkley drift reset)",
        parameters={
            "type": "object",
            "properties": {
                "reason": {"type": "string", "description": "Reason for forced retrain"},
            },
            "required": ["reason"],
        },
        agents=["ORACLE", "FORGE"],
        requires_confirmation=True,
    ),

    # MEDIC tools
    "full_quarantine": ToolDefinition(
        name="full_quarantine",
        description="Isolate a device from all network access",
        parameters={
            "type": "object",
            "properties": {
                "source_ip": {"type": "string"},
                "mac": {"type": "string"},
                "reason": {"type": "string"},
            },
        },
        agents=["MEDIC"],
        requires_confirmation=True,
    ),
    "forensic_capture": ToolDefinition(
        name="forensic_capture",
        description="Trigger packet capture for evidence",
        parameters={
            "type": "object",
            "properties": {
                "source_ip": {"type": "string"},
                "duration": {"type": "integer", "default": 60},
            },
        },
        agents=["MEDIC"],
    ),
    "incident_timeline": ToolDefinition(
        name="incident_timeline",
        description="Build a timeline of events for an incident",
        parameters={
            "type": "object",
            "properties": {
                "source_ip": {"type": "string"},
                "hours": {"type": "integer", "default": 24},
            },
        },
        agents=["MEDIC", "ORACLE"],
    ),

    # ORACLE tools
    "trend_analysis": ToolDefinition(
        name="trend_analysis",
        description="Analyze security trends over time",
        parameters={
            "type": "object",
            "properties": {
                "period": {"type": "string", "default": "7d"},
            },
        },
        agents=["ORACLE"],
    ),
    "generate_report": ToolDefinition(
        name="generate_report",
        description="Generate a security report",
        parameters={
            "type": "object",
            "properties": {
                "report_type": {"type": "string", "default": "summary"},
            },
        },
        agents=["ORACLE"],
    ),
    "risk_score": ToolDefinition(
        name="risk_score",
        description="Calculate risk score for a device or network",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
            },
        },
        agents=["ORACLE"],
    ),
}

# Permission matrix: agent -> allowed tools (derived from TOOL_REGISTRY)
PERMISSION_MATRIX: Dict[str, List[str]] = {}
for _tool_name, _tool_def in TOOL_REGISTRY.items():
    for _agent in _tool_def.agents:
        if _agent not in PERMISSION_MATRIX:
            PERMISSION_MATRIX[_agent] = []
        PERMISSION_MATRIX[_agent].append(_tool_name)


# ------------------------------------------------------------------
# Tool Executor
# ------------------------------------------------------------------

# Tool implementation functions (stubs — replaced by real implementations)
_tool_implementations: Dict[str, Callable] = {}


def register_tool_implementation(name: str, func: Callable) -> None:
    """Register a tool implementation function.

    Called by product-level code to wire real implementations
    (e.g., XDP blocking, dnsXai API calls).
    """
    _tool_implementations[name] = func


class ToolExecutor:
    """Executes agent tool calls with safety checks.

    Pipeline: principle_guard -> permission_matrix -> execute -> audit
    """

    def __init__(self, memory=None):
        self._memory = memory
        self._pending_confirmations: Dict[str, Dict] = {}
        self._confirmations_lock = threading.Lock()

    def execute(
        self,
        agent_name: str,
        tool_name: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> ToolResult:
        """Execute a tool call with full safety pipeline.

        Args:
            agent_name: Name of the requesting agent.
            tool_name: Name of the tool to execute.
            params: Tool parameters.

        Returns:
            ToolResult with success/failure and reasoning.
        """
        params = params or {}

        # Check 1: Tool exists
        tool_def = TOOL_REGISTRY.get(tool_name)
        if not tool_def:
            return ToolResult(
                success=False,
                result=f"Unknown tool: {tool_name}",
                reasoning="Tool not found in registry",
            )

        # Check 2: Agent has permission
        allowed = PERMISSION_MATRIX.get(agent_name, [])
        if tool_name not in allowed:
            return ToolResult(
                success=False,
                result=f"Agent {agent_name} not permitted to use {tool_name}",
                reasoning="Permission denied by matrix",
            )

        # Check 3: Principle guard
        safety = check_action(agent_name, tool_name, params)
        if not safety.safe:
            self._log_decision(
                agent_name, tool_name, params, 0.0,
                f"BLOCKED: {safety.reason}", "blocked", False,
            )
            return ToolResult(
                success=False,
                result=f"Action blocked: {safety.reason}",
                reasoning=f"Violated principle: {safety.violated_principle}",
            )

        # Check 4: Requires confirmation
        if safety.requires_confirmation or tool_def.requires_confirmation:
            confirm_id = self._store_pending(agent_name, tool_name, params)
            self._log_decision(
                agent_name, tool_name, params, 0.0,
                "Awaiting human confirmation", "pending", False,
            )
            return ToolResult(
                success=True,
                result=f"Action requires confirmation (ID: {confirm_id})",
                reasoning="Queued for human approval",
                decision_id=confirm_id,
            )

        # Execute
        try:
            result = self._execute_tool(tool_name, params)
        except NotImplementedError as e:
            decision_id = self._log_decision(
                agent_name, tool_name, params, 0.0,
                str(e), "NOT_IMPLEMENTED", False,
            )
            return ToolResult(
                success=False,
                result=str(e),
                reasoning="Tool not yet implemented",
                decision_id=decision_id,
            )

        # Sanitize output
        result_text = sanitize_output(result)

        # Audit log
        decision_id = self._log_decision(
            agent_name, tool_name, params, 0.8,
            f"Executed {tool_name}", result_text, True,
        )

        return ToolResult(
            success=True,
            result=result_text,
            reasoning=f"Executed by {agent_name}",
            logged=True,
            decision_id=decision_id,
        )

    def approve_pending(self, confirm_id: str) -> ToolResult:
        """Approve a pending tool call."""
        with self._confirmations_lock:
            pending = self._pending_confirmations.pop(confirm_id, None)
        if not pending:
            return ToolResult(
                success=False,
                result=f"No pending action with ID {confirm_id}",
            )

        result = self._execute_tool(pending["tool_name"], pending["params"])
        self._log_decision(
            pending["agent_name"], pending["tool_name"], pending["params"],
            0.9, "Approved and executed", result, True,
        )

        return ToolResult(success=True, result=result, reasoning="Human approved")

    def reject_pending(self, confirm_id: str) -> bool:
        """Reject a pending tool call."""
        with self._confirmations_lock:
            pending = self._pending_confirmations.pop(confirm_id, None)
        if pending:
            self._log_decision(
                pending["agent_name"], pending["tool_name"], pending["params"],
                0.0, "Rejected by human", "rejected", False,
            )
            return True
        return False

    def get_pending(self) -> Dict[str, Dict]:
        """Get all pending confirmation requests."""
        with self._confirmations_lock:
            return dict(self._pending_confirmations)

    def get_tool_definitions_for_agent(self, agent_name: str) -> List[Dict[str, Any]]:
        """Get tool definitions in OpenAI function-calling format."""
        allowed = PERMISSION_MATRIX.get(agent_name, [])
        tools = []
        for name in allowed:
            tool_def = TOOL_REGISTRY.get(name)
            if tool_def:
                tools.append({
                    "type": "function",
                    "function": {
                        "name": tool_def.name,
                        "description": tool_def.description,
                        "parameters": tool_def.parameters,
                    },
                })
        return tools

    def _execute_tool(self, tool_name: str, params: Dict[str, Any]) -> str:
        """Execute a tool using registered implementation or stub."""
        impl = _tool_implementations.get(tool_name)
        if impl:
            try:
                return str(impl(**params))
            except Exception as e:
                logger.error("Tool execution error [%s]: %s", tool_name, e)
                return f"Error: {e}"

        # No implementation found — fail explicitly instead of silently succeeding
        logger.warning("Tool '%s' has no implementation — returning error", tool_name)
        raise NotImplementedError(f"Tool '{tool_name}' is not yet implemented")

    def _store_pending(
        self,
        agent_name: str,
        tool_name: str,
        params: Dict[str, Any],
    ) -> str:
        """Store a pending confirmation request."""
        import uuid
        confirm_id = str(uuid.uuid4())[:8]
        with self._confirmations_lock:
            self._pending_confirmations[confirm_id] = {
                "agent_name": agent_name,
                "tool_name": tool_name,
                "params": params,
                "timestamp": time.time(),
            }
        return confirm_id

    def _log_decision(
        self,
        agent: str,
        action: str,
        params: Dict[str, Any],
        confidence: float,
        reasoning: str,
        result: str,
        approved: bool,
    ) -> str:
        """Log a decision to the audit trail via memory."""
        if self._memory:
            return self._memory.log_decision(
                agent=agent,
                action=action,
                params=params,
                confidence=confidence,
                reasoning=reasoning,
                result=result,
                approved=approved,
            )
        return ""
