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


class LLMCodeGenerator:
    """Phase 20: Generate eBPF programs from natural-language threat descriptions.

    Uses the LLM to translate attack descriptions into compilable XDP C code.
    The generated code goes through the same safety pipeline as templates:
    static analysis → kernel verifier → sandbox → deploy.

    Safety invariants:
    1. Prompt constrains the LLM to safe eBPF patterns only
    2. Static analysis catches banned patterns in generated code
    3. Kernel verifier catches memory safety issues
    4. Rate limit: max 2 generated deploys per hour (conservative)
    5. Rollback: 300s auto-rollback if no improvement
    """

    MAX_GENERATED_PER_HOUR = 2
    GENERATION_TIMEOUT_S = 30

    # System prompt for eBPF code generation
    SYSTEM_PROMPT = (
        "You are an eBPF/XDP security engineer. Generate a SINGLE XDP program "
        "in C that mitigates the described network attack.\n\n"
        "CONSTRAINTS (MUST follow all):\n"
        "- Use BCC-style macros: BPF_HASH, BPF_ARRAY, BPF_PERCPU_ARRAY\n"
        "- Include ONLY: <uapi/linux/bpf.h>, <linux/if_ether.h>, <linux/ip.h>, "
        "<linux/tcp.h>, <linux/udp.h>\n"
        "- Entry function signature: int xdp_filter(struct xdp_md *ctx)\n"
        "- Return XDP_PASS for allowed traffic, XDP_DROP for blocked traffic\n"
        "- ALWAYS bounds-check data pointers: if ((void *)(hdr + 1) > data_end) return XDP_PASS;\n"
        "- Use rate limiting per source IP (BPF_HASH with u32 key = ip->saddr)\n"
        "- NEVER use: bpf_probe_write_user, bpf_override_return, system(), exec(), "
        "asm volatile, popen(), fork(), dlopen()\n"
        "- Maximum 100 lines of C code\n"
        "- Default to XDP_PASS for any packet you don't understand\n\n"
        "Output ONLY the C code in a ```c code block. No explanations."
    )

    # Example template included in prompt for few-shot learning
    EXAMPLE_TEMPLATE = (
        "EXAMPLE — SYN flood rate limiter:\n"
        "```c\n"
        "#include <uapi/linux/bpf.h>\n"
        "#include <linux/if_ether.h>\n"
        "#include <linux/ip.h>\n"
        "#include <linux/tcp.h>\n"
        "BPF_HASH(pkt_count, u32, u64, 65536);\n"
        "BPF_HASH(pkt_window, u32, u64, 65536);\n"
        "#define RATE_LIMIT 100\n"
        "#define WINDOW_NS 1000000000ULL\n"
        "int xdp_filter(struct xdp_md *ctx) {\n"
        "    void *data = (void *)(long)ctx->data;\n"
        "    void *data_end = (void *)(long)ctx->data_end;\n"
        "    struct ethhdr *eth = data;\n"
        "    if ((void *)(eth + 1) > data_end) return XDP_PASS;\n"
        "    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;\n"
        "    struct iphdr *ip = (void *)(eth + 1);\n"
        "    if ((void *)(ip + 1) > data_end) return XDP_PASS;\n"
        "    // ... rate limit by ip->saddr ...\n"
        "    return XDP_PASS;\n"
        "}\n"
        "```\n"
    )

    def __init__(
        self,
        compiler: EBPFCompiler,
        llm_fn: Optional[callable] = None,
    ):
        self._compiler = compiler
        self._llm_fn = llm_fn
        self._generation_timestamps: List[float] = []
        self._lock = threading.Lock()
        self._stats = {
            'attempts': 0,
            'successes': 0,
            'compile_failures': 0,
            'llm_failures': 0,
            'rate_limited': 0,
        }

    def can_generate(self) -> bool:
        """Check if generation rate limit allows another attempt."""
        now = time.time()
        with self._lock:
            self._generation_timestamps = [
                t for t in self._generation_timestamps if now - t < 3600.0
            ]
            return len(self._generation_timestamps) < self.MAX_GENERATED_PER_HOUR

    def generate(self, threat_description: str,
                 rag_context: str = "") -> Optional[str]:
        """Generate eBPF C code from a threat description.

        Args:
            threat_description: Natural-language description of the attack.
            rag_context: Optional RAG context from recent kernel events.

        Returns:
            Extracted C source code, or None on failure.
        """
        if not self._llm_fn:
            logger.debug("LLM function not configured — cannot generate")
            return None

        if not self.can_generate():
            self._stats['rate_limited'] += 1
            logger.warning("LLM code generation rate limit exceeded (max %d/hr)",
                           self.MAX_GENERATED_PER_HOUR)
            return None

        self._stats['attempts'] += 1

        # Build the user prompt
        user_prompt = f"THREAT DESCRIPTION:\n{threat_description}\n"
        if rag_context:
            user_prompt += f"\nRECENT CONTEXT:\n{rag_context}\n"
        user_prompt += f"\n{self.EXAMPLE_TEMPLATE}\n"
        user_prompt += "Generate a single XDP program to mitigate this threat."

        try:
            llm_output = self._llm_fn(self.SYSTEM_PROMPT, user_prompt)
            if not llm_output:
                self._stats['llm_failures'] += 1
                return None

            # Extract code from LLM output
            code = self._compiler.extract_code(llm_output)
            if not code:
                self._stats['llm_failures'] += 1
                logger.warning("LLM output contained no extractable C code")
                return None

            # Record successful generation
            with self._lock:
                self._generation_timestamps.append(time.time())

            self._stats['successes'] += 1
            logger.info("LLM generated %d chars of eBPF code", len(code))
            return code

        except Exception as e:
            self._stats['llm_failures'] += 1
            logger.error("LLM code generation failed: %s", e)
            return None

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            'pending_capacity': (
                self.MAX_GENERATED_PER_HOUR
                - len([t for t in self._generation_timestamps
                       if time.time() - t < 3600.0])
            ),
        }


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
        llm_fn: Optional[callable] = None,
    ):
        self._interface = interface
        self._compiler = compiler or EBPFCompiler()
        self._sandbox = sandbox or EBPFSandbox(self._compiler)
        self._sensors = sensors or SensorManager()
        self._templates = templates or TemplateRegistry()
        self._rag_pipeline = rag_pipeline

        # Phase 20: LLM code generator for novel threats
        self._code_generator = LLMCodeGenerator(
            compiler=self._compiler, llm_fn=llm_fn)

        # Phase 26: Prefrontal Cortex executive veto on generated programs
        self._prefrontal = None
        try:
            from core.cno.prefrontal_cortex import PrefrontalCortex
            self._prefrontal = PrefrontalCortex()
            logger.info("Prefrontal cortex enabled (Phase 26 veto active)")
        except ImportError:
            try:
                # Fallback path for IDS container layout
                import sys as _sys, os as _os
                _sys.path.insert(0, _os.environ.get('HOOKPROBE_BASE',
                                                     '/home/ubuntu/hookprobe'))
                from core.cno.prefrontal_cortex import PrefrontalCortex
                self._prefrontal = PrefrontalCortex()
                logger.info("Prefrontal cortex enabled (Phase 26)")
            except ImportError:
                logger.info("Prefrontal cortex unavailable — Phase 20 unprotected")

        self._lock = threading.Lock()
        self._deploy_timestamps: List[float] = []
        self._decision_log: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def handle_signal(self, signal: StandardSignal) -> Optional[KernelAction]:
        """Process a signal that may require kernel-level response.

        Decision tree:
        1. Is this a known pattern? → Use template eBPF (Phase 1)
        2. No template match? → Try LLM code generation (Phase 20)
        3. No LLM available? → Return None (let other AEGIS agents handle)

        Args:
            signal: Normalized signal from any bridge.

        Returns:
            KernelAction if a program was deployed, None otherwise.
        """
        # Step 1: Check template registry (Phase 1 — fast path)
        match = self._templates.match(signal)
        if match:
            logger.info(
                "Template match: %s (confidence=%.2f) for signal %s/%s",
                match.template_name, match.confidence,
                signal.source, signal.event_type,
            )

            # Rate limit check
            if not self._check_rate_limit():
                logger.warning("Deploy rate limit exceeded — skipping %s",
                               match.template_name)
                return None

            # Duplicate check
            if self._is_duplicate(match):
                logger.debug("Template %s already deployed — skipping",
                             match.template_name)
                return None

            return self._deploy_template(match, signal)

        # Step 2: Phase 20 — No template match, try LLM code generation
        return self.handle_novel_threat(signal)

    def handle_novel_threat(
        self, signal: StandardSignal,
        threat_description: str = "",
    ) -> Optional[KernelAction]:
        """Phase 20: Generate and deploy eBPF for a novel (non-template) threat.

        Pipeline: LLM generate → extract → compile → verify → sandbox → deploy

        Safety layers:
        1. Rate limit: max 2 generated programs per hour
        2. Static analysis: banned patterns, helper whitelist
        3. Kernel verifier: memory safety, bounds checks
        4. Sandbox: compilation verification
        5. Auto-rollback: 300s timeout if no improvement

        Args:
            signal: The signal that triggered this (for context + logging).
            threat_description: Optional override; defaults to signal data.

        Returns:
            KernelAction with DEPLOY_GENERATED type, or None on failure.
        """
        if not self._code_generator._llm_fn:
            return None

        if not self._check_rate_limit():
            logger.warning("Deploy rate limit exceeded — skipping novel threat")
            return None

        # Build threat description from signal if not provided
        if not threat_description:
            threat_description = (
                f"Attack type: {signal.event_type}\n"
                f"Source: {signal.source}\n"
                f"Severity: {signal.severity}\n"
            )
            if signal.data:
                ip = signal.data.get('source_ip', '')
                if ip:
                    threat_description += f"Source IP: {ip}\n"
                summary = signal.data.get('summary', '')
                if summary:
                    threat_description += f"Summary: {summary}\n"

        # Build RAG context
        rag_context = self.build_llm_context(signal)

        # Generate code via LLM
        logger.info("PHASE 20: Generating eBPF for novel threat: %s/%s",
                     signal.source, signal.event_type)
        c_source = self._code_generator.generate(threat_description, rag_context)
        if not c_source:
            self._log_action_dict(
                "generate_failed", "llm_generated",
                f"LLM code generation failed for {signal.event_type}")
            return None

        # Compile and verify (same pipeline as templates)
        compilation = self._compiler.compile_and_verify(
            c_source, ProgramType.XDP)
        if not compilation.success:
            self._code_generator._stats['compile_failures'] += 1
            self._log_action_dict(
                "generate_compile_failed", "llm_generated",
                f"Generated code failed compilation: {compilation.error}")
            logger.warning("PHASE 20: Generated code failed compilation: %s",
                           compilation.error)
            return None

        # Sandbox test
        sandbox_result = self._sandbox.test(
            compilation, duration_s=self.SANDBOX_DURATION_S)
        if not sandbox_result.passed:
            self._log_action_dict(
                "generate_sandbox_failed", "llm_generated",
                f"Generated code failed sandbox: {sandbox_result.reason}")
            return None

        # Phase 26: Prefrontal Cortex executive veto
        # AFTER sandbox, BEFORE deploy. Catches verifier-passing but
        # adversarial code (magic-packet backdoors, RFC-1918 drops, etc).
        if self._prefrontal:
            try:
                approved, reason = self._prefrontal.evaluate(c_source, signal)
                if not approved:
                    self._log_action_dict(
                        "generate_prefrontal_veto", "llm_generated",
                        f"Prefrontal cortex vetoed: {reason}")
                    logger.warning(
                        "PHASE 26 VETO: generated XDP rejected — %s", reason)
                    return None
            except Exception as e:
                logger.error("Prefrontal cortex error (failing closed): %s", e)
                return None

        # Deploy
        program_id = self._generate_program_id("llm_generated", signal)
        now = time.time()
        active = ActiveProgram(
            program_id=program_id,
            program_type=ProgramType.XDP,
            attach_point=self._interface,
            template_name="llm_generated",
            deployed_at=now,
            rollback_deadline=now + self.ROLLBACK_TIMEOUT_S,
            c_source=c_source,
            signal_source=f"{signal.source}/{signal.event_type}",
        )

        if not self._sensors.deploy(active):
            logger.warning("Sensor manager rejected generated program deployment")
            return None

        action = KernelAction(
            action_type=KernelActionType.DEPLOY_GENERATED,
            program_id=program_id,
            program_type=ProgramType.XDP,
            attach_point=self._interface,
            template_name="llm_generated",
            target_ip=signal.data.get("source_ip", "") if signal.data else "",
            compilation=compilation,
            sandbox=sandbox_result,
            rollback_timeout_s=self.ROLLBACK_TIMEOUT_S,
            metadata={
                "signal_source": signal.source,
                "signal_event": signal.event_type,
                "signal_severity": signal.severity,
                "threat_description": threat_description[:500],
                "generated_code_length": len(c_source),
                "phase": "20_self_evolving",
            },
        )

        self._log_action(action, "Phase 20: Deployed LLM-generated program")
        logger.info(
            "PHASE 20: Deployed LLM-generated XDP program %s on %s "
            "(rollback in %ds, %d chars)",
            program_id, self._interface,
            self.ROLLBACK_TIMEOUT_S, len(c_source),
        )
        return action

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
            # Phase 20: LLM code generation stats
            "code_generator": self._code_generator.get_stats(),
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
