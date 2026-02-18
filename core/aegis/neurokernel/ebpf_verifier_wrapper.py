"""
eBPF Verifier Wrapper — Python interface to the kernel BPF verifier.

Wraps the BCC compilation pipeline to provide structured verification
results. When BCC is unavailable, returns SKIPPED status.

Author: Andrei Toma
License: Proprietary
Version: 1.0.0
"""

import logging
from typing import Optional, Tuple

from .types import CompilationResult, ProgramType, VerifyStatus

# Optional BCC
try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False

logger = logging.getLogger(__name__)


class EBPFVerifier:
    """Wraps the kernel BPF verifier via BCC.

    The BPF verifier is the kernel's safety gate — it rejects programs
    with unbounded loops, out-of-bounds access, or unsafe operations.
    This wrapper provides a clean Python interface with structured results.
    """

    def verify(self, c_source: str, program_type: ProgramType) -> CompilationResult:
        """Compile and verify an eBPF C program.

        Args:
            c_source: eBPF C source code.
            program_type: Target attachment type (XDP, TC, kprobe).

        Returns:
            CompilationResult with verification status.
        """
        if not BCC_AVAILABLE:
            logger.debug("BCC unavailable — skipping kernel verification")
            return CompilationResult(
                success=True,
                program_type=program_type,
                c_source=c_source,
                verify_status=VerifyStatus.SKIPPED,
            )

        try:
            bpf = BPF(text=c_source)
            return CompilationResult(
                success=True,
                program_type=program_type,
                c_source=c_source,
                verify_status=VerifyStatus.PASSED,
            )
        except Exception as e:
            error_msg = str(e)
            logger.warning("BPF verifier rejected program: %s", error_msg[:200])
            return CompilationResult(
                success=False,
                program_type=program_type,
                c_source=c_source,
                error=error_msg,
                verify_status=VerifyStatus.FAILED_VERIFIER,
            )

    @staticmethod
    def is_available() -> bool:
        """Check if the BPF verifier (BCC) is available."""
        return BCC_AVAILABLE
