"""
Neuro-Kernel Orchestrator — Closed-Loop Kernel Response

Receives signals from the AEGIS orchestrator, matches against the
template registry, verifies via the compiler pipeline, sandbox-tests,
and deploys to the Reflex engine via hot-swap.

Phase 1: Template-based response only (no LLM code generation).
Phase 3: Will add LLM-driven eBPF generation for novel threats.

Pipeline:
    StandardSignal → template_match → compile → verify → sandbox → deploy → audit

Integration points:
    - Reads from: AEGIS orchestrator (StandardSignal)
    - Writes to: ReflexEngine (hot_swap_program) or SensorManager (track)
    - Guarded by: PrincipleGuard (never_disable_kernel_safety)
    - Audited by: MemoryManager (decisions table)
    - Coordinated with: QSecBit XDPManager (prevent conflicts)

Author: Andrei Toma
License: Proprietary
Version: 1.0.0
"""

import hashlib
import logging
import threading
import time
from typing import Any, Dict, List, Optional

from ..types import StandardSignal
from .ebpf_compiler import EBPFCompiler
from .ebpf_sandbox import EBPFSandbox
from .ebpf_template_registry import TemplateRegistry
from .sensor_manager import SensorManager
from .streaming_rag import StreamingRAGPipeline
from .types import (
    ActiveProgram,
    CompilationResult,
    KernelAction,
    KernelActionType,
    ProgramType,
    TemplateMatch,
)

logger = logging.getLogger(__name__)


class KernelOrchestrator:
    """Closed-loop: signal → template match → verify → deploy.

    Security invariants:
    1. All eBPF passes static analysis + kernel verifier
    2. Sandbox testing before production deployment
    3. Automatic rollback on timeout (300s default)
    4. Duplicate detection (same template + attach_point = skip)
    5. Maximum concurrent programs enforced by SensorManager
    """

    SANDBOX_DURATION_S = 5          # Phase 1: compile-test only
    ROLLBACK_TIMEOUT_S = 300        # Auto-rollback if no improvement
    MAX_DEPLOYS_PER_MINUTE = 5      # Rate limit

    def __init__(
        self,
        interface: str = "eth0",
        compiler: Optional[EBPFCompiler] = None,
        sandbox: Optional[EBPFSandbox] = None,
        sensors: Optional[SensorManager] = None,
        templates: Optional[TemplateRegistry] = None,
        rag_pipeline: Optional[StreamingRAGPipeline] = None,
    ):
        self._interface = interface
        self._compiler = compiler or EBPFCompiler()
        self._sandbox = sandbox or EBPFSandbox(self._compiler)
        self._sensors = sensors or SensorManager()
        self._templates = templates or TemplateRegistry()
        self._rag_pipeline = rag_pipeline

        self._lock = threading.Lock()
        self._deploy_timestamps: List[float] = []
        self._decision_log: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def handle_signal(self, signal: StandardSignal) -> Optional[KernelAction]:
        """Process a signal that may require kernel-level response.

        Decision tree (Phase 1):
        1. Is this a known pattern? → Use template eBPF
        2. No match? → Return None (let other AEGIS agents handle)

        Args:
            signal: Normalized signal from any bridge.

        Returns:
            KernelAction if a program was deployed, None otherwise.
        """
        # Step 1: Check template registry
        match = self._templates.match(signal)
        if not match:
            return None

        logger.info(
            "Template match: %s (confidence=%.2f) for signal %s/%s",
            match.template_name, match.confidence,
            signal.source, signal.event_type,
        )

        # Step 2: Rate limit check
        if not self._check_rate_limit():
            logger.warning("Deploy rate limit exceeded — skipping %s", match.template_name)
            return None

        # Step 3: Duplicate check
        if self._is_duplicate(match):
            logger.debug("Template %s already deployed — skipping", match.template_name)
            return None

        # Step 4: Deploy the template
        return self._deploy_template(match, signal)

    def rollback(self, program_id: str) -> Optional[KernelAction]:
        """Rollback a deployed program.

        Removes the program from the sensor manager and logs the action.

        Args:
            program_id: ID of the program to rollback.

        Returns:
            KernelAction describing the rollback, or None if not found.
        """
        program = self._sensors.remove(program_id)
        if not program:
            logger.warning("Rollback failed: program %s not found", program_id)
            return None

        action = KernelAction(
            action_type=KernelActionType.ROLLBACK,
            program_id=program_id,
            program_type=program.program_type,
            attach_point=program.attach_point,
            template_name=program.template_name,
        )
        self._log_action(action, "Rollback: removed program")
        logger.info("Rolled back program %s (template=%s)", program_id, program.template_name)
        return action

    def check_rollbacks(self) -> List[KernelAction]:
        """Check for programs past their rollback deadline.

        Called periodically (e.g., from a bridge tick loop).
        Returns list of rollback actions taken.
        """
        expired = self._sensors.check_rollback_deadlines()
        actions = []
        for program_id in expired:
            action = self.rollback(program_id)
            if action:
                actions.append(action)
        return actions

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive orchestrator status."""
        status = {
            "sensors": self._sensors.get_status(),
            "templates": self._templates.list_templates(),
            "template_count": len(self._templates),
            "recent_actions": self._decision_log[-10:],
            "interface": self._interface,
        }
        if self._rag_pipeline:
            status["streaming_rag"] = self._rag_pipeline.stats()
        return status

    @property
    def sensor_manager(self) -> SensorManager:
        """Access the sensor manager (for external queries)."""
        return self._sensors

    @property
    def template_registry(self) -> TemplateRegistry:
        """Access the template registry (for external registration)."""
        return self._templates

    @property
    def rag_pipeline(self) -> Optional[StreamingRAGPipeline]:
        """Access the streaming RAG pipeline (if configured)."""
        return self._rag_pipeline

    @rag_pipeline.setter
    def rag_pipeline(self, pipeline: Optional[StreamingRAGPipeline]) -> None:
        """Set or replace the streaming RAG pipeline."""
        self._rag_pipeline = pipeline

    def build_llm_context(self, signal: StandardSignal) -> str:
        """Build LLM context enriched with streaming RAG events.

        Combines the signal data with recent kernel events from the
        vector store. Used by Phase 3 (LLM code generation) to give
        the model situational awareness.

        Args:
            signal: The current signal being processed.

        Returns:
            Formatted context string for LLM prompt injection.
        """
        parts = []

        # Signal context
        parts.append(
            f"Current Signal: {signal.source}/{signal.event_type} "
            f"[{signal.severity}]"
        )
        if signal.data:
            ip = signal.data.get("source_ip", "")
            if ip:
                parts.append(f"Source IP: {ip}")

        # Streaming RAG context (if available)
        if self._rag_pipeline:
            query = f"{signal.event_type} {signal.data.get('source_ip', '')}".strip()
            rag_context = self._rag_pipeline.query(query, k=10)
            if rag_context and rag_context != "No recent kernel events found.":
                parts.append("")
                parts.append(rag_context)

        # Active programs context
        active = self._sensors.get_status()
        if active.get("active_programs"):
            parts.append(f"\nActive eBPF programs: {active['active_count']}")

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Internal: Template deployment
    # ------------------------------------------------------------------

    def _deploy_template(
        self,
        match: TemplateMatch,
        signal: StandardSignal,
    ) -> Optional[KernelAction]:
        """Deploy a matched template.

        Pipeline: compile → verify → sandbox → register
        """
        # Compile and verify
        compilation = self._compiler.compile_and_verify(
            match.c_source, match.program_type,
        )
        if not compilation.success:
            logger.warning(
                "Template %s failed compilation: %s",
                match.template_name, compilation.error,
            )
            self._log_action_dict(
                "deploy_failed", match.template_name,
                f"Compilation failed: {compilation.error}",
            )
            return None

        # Sandbox test
        sandbox_result = self._sandbox.test(
            compilation, duration_s=self.SANDBOX_DURATION_S,
        )
        if not sandbox_result.passed:
            logger.warning(
                "Template %s failed sandbox: %s",
                match.template_name, sandbox_result.reason,
            )
            self._log_action_dict(
                "sandbox_failed", match.template_name,
                f"Sandbox failed: {sandbox_result.reason}",
            )
            return None

        # Generate program ID
        program_id = self._generate_program_id(match.template_name, signal)

        # Create active program record
        now = time.time()
        active = ActiveProgram(
            program_id=program_id,
            program_type=match.program_type,
            attach_point=self._interface,
            template_name=match.template_name,
            deployed_at=now,
            rollback_deadline=now + self.ROLLBACK_TIMEOUT_S,
            c_source=match.c_source,
            signal_source=f"{signal.source}/{signal.event_type}",
        )

        # Register with sensor manager
        if not self._sensors.deploy(active):
            logger.warning("Sensor manager rejected deployment (limit reached)")
            return None

        # Build action record
        action = KernelAction(
            action_type=KernelActionType.DEPLOY_TEMPLATE,
            program_id=program_id,
            program_type=match.program_type,
            attach_point=self._interface,
            template_name=match.template_name,
            target_ip=signal.data.get("source_ip", ""),
            compilation=compilation,
            sandbox=sandbox_result,
            rollback_timeout_s=self.ROLLBACK_TIMEOUT_S,
            metadata={
                "signal_source": signal.source,
                "signal_event": signal.event_type,
                "signal_severity": signal.severity,
                "match_confidence": match.confidence,
            },
        )

        self._log_action(action, "Deployed template")
        logger.info(
            "Deployed template %s as %s on %s (rollback in %ds)",
            match.template_name, program_id, self._interface,
            self.ROLLBACK_TIMEOUT_S,
        )
        return action

    # ------------------------------------------------------------------
    # Internal: Helpers
    # ------------------------------------------------------------------

    def _check_rate_limit(self) -> bool:
        """Check if deploy rate limit allows another deployment."""
        now = time.time()
        with self._lock:
            # Clean old timestamps
            self._deploy_timestamps = [
                t for t in self._deploy_timestamps if now - t < 60.0
            ]
            if len(self._deploy_timestamps) >= self.MAX_DEPLOYS_PER_MINUTE:
                return False
            self._deploy_timestamps.append(now)
            return True

    def _is_duplicate(self, match: TemplateMatch) -> bool:
        """Check if this template is already deployed on this interface."""
        existing = self._sensors.get_by_template(match.template_name)
        for program in existing:
            if program.attach_point == self._interface:
                return True
        return False

    def _generate_program_id(self, template_name: str, signal: StandardSignal) -> str:
        """Generate a unique program ID."""
        data = f"{template_name}:{self._interface}:{time.time()}"
        return f"nk-{hashlib.sha256(data.encode()).hexdigest()[:12]}"

    def _log_action(self, action: KernelAction, description: str) -> None:
        """Log a kernel action to the decision log."""
        entry = action.to_dict()
        entry["description"] = description
        with self._lock:
            self._decision_log.append(entry)
            if len(self._decision_log) > 100:
                self._decision_log = self._decision_log[-100:]

    def _log_action_dict(self, event: str, template: str, detail: str) -> None:
        """Log a simple event to the decision log."""
        with self._lock:
            self._decision_log.append({
                "event": event,
                "template": template,
                "detail": detail,
                "timestamp": time.time(),
            })
            if len(self._decision_log) > 100:
                self._decision_log = self._decision_log[-100:]
