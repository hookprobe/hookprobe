"""
eBPF Sandbox — Isolated testing environment for eBPF programs.

Before deploying to production, programs are tested in an isolated
environment. In Phase 1 (template-based), the sandbox validates
that template compilation succeeds and static analysis passes.

Full network-namespace sandbox (Phase 3) will test against synthetic
traffic to verify correct drop/pass behavior.

Author: Andrei Toma
License: Proprietary
Version: 1.0.0
"""

import logging
import time
from typing import Optional

from .ebpf_compiler import EBPFCompiler
from .types import (
    CompilationResult,
    ProgramType,
    SandboxResult,
    SandboxTestResult,
    VerifyStatus,
)

logger = logging.getLogger(__name__)


class EBPFSandbox:
    """Isolated test environment for eBPF programs.

    Phase 1: Validates compilation and static analysis only.
    Phase 3: Will add network namespace isolation with synthetic traffic.
    """

    DEFAULT_DURATION_S = 5  # Phase 1 — just compile-test, no traffic

    def __init__(self, compiler: Optional[EBPFCompiler] = None):
        self._compiler = compiler or EBPFCompiler()

    def test(
        self,
        compilation: CompilationResult,
        duration_s: int = DEFAULT_DURATION_S,
    ) -> SandboxTestResult:
        """Test an eBPF program in the sandbox.

        Phase 1 implementation:
          - Verifies compilation succeeded
          - Verifies static analysis passed
          - Returns PASSED if both checks pass

        Args:
            compilation: Result from EBPFCompiler.compile_and_verify().
            duration_s: Test duration (unused in Phase 1).

        Returns:
            SandboxTestResult with pass/fail status.
        """
        start = time.time()

        # Check compilation result
        if not compilation.success:
            return SandboxTestResult(
                passed=False,
                result=SandboxResult.FAILED_BEHAVIOR,
                reason=f"Compilation failed: {compilation.error}",
                duration_s=time.time() - start,
            )

        # Check verification status
        if compilation.verify_status == VerifyStatus.FAILED_STATIC:
            return SandboxTestResult(
                passed=False,
                result=SandboxResult.FAILED_BEHAVIOR,
                reason=f"Static analysis failed: {compilation.error}",
                duration_s=time.time() - start,
            )

        if compilation.verify_status == VerifyStatus.FAILED_VERIFIER:
            return SandboxTestResult(
                passed=False,
                result=SandboxResult.FAILED_BEHAVIOR,
                reason=f"BPF verifier rejected: {compilation.error}",
                duration_s=time.time() - start,
            )

        # Check for serious warnings
        serious_warnings = [
            w for w in compilation.warnings
            if "unknown" not in w.lower()  # Skip "unknown helpers" (BCC macros)
        ]

        elapsed = time.time() - start

        if compilation.verify_status == VerifyStatus.SKIPPED:
            # BCC unavailable — trust static analysis
            return SandboxTestResult(
                passed=True,
                result=SandboxResult.PASSED,
                reason="Static analysis passed (BPF verifier skipped — BCC unavailable)",
                duration_s=elapsed,
                side_effects=[f"Warning: {w}" for w in compilation.warnings],
            )

        return SandboxTestResult(
            passed=True,
            result=SandboxResult.PASSED,
            reason="Compilation and verification passed",
            duration_s=elapsed,
            side_effects=[f"Warning: {w}" for w in serious_warnings],
        )

    def test_source(
        self,
        c_source: str,
        program_type: ProgramType = ProgramType.XDP,
        duration_s: int = DEFAULT_DURATION_S,
    ) -> SandboxTestResult:
        """Convenience: compile + verify + sandbox test in one call."""
        compilation = self._compiler.compile_and_verify(c_source, program_type)
        return self.test(compilation, duration_s)
