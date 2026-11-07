"""
eBPF Compiler — Static analysis + BPF verification pipeline.

Security-critical component. All eBPF C code (whether from templates
or LLM-generated) MUST pass through this pipeline before deployment.

Verification layers:
  1. Static analysis: banned patterns, allowed helpers, size limits
  2. BPF verifier: kernel rejects unsafe programs (via EBPFVerifier)

Author: Andrei Toma
License: Proprietary
Version: 1.0.0
"""

import logging
import re
from typing import List, Optional

from .ebpf_verifier_wrapper import EBPFVerifier
from .types import CompilationResult, ProgramType, VerifyStatus

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Static Analysis Rules
# ------------------------------------------------------------------

# BANNED constructs — reject immediately if found
BANNED_PATTERNS: List[re.Pattern] = [
    re.compile(r'bpf_probe_write_user'),        # Write to userspace memory
    re.compile(r'bpf_override_return'),          # Override syscall return
    re.compile(r'\bsystem\s*\('),               # Shell command execution
    re.compile(r'\bexec[lv]?[pe]?\s*\('),       # Process execution
    re.compile(r'__attribute__\s*\(\s*\(\s*(?!packed|aligned)'),  # GCC attributes (except packed/aligned)
    re.compile(r'\basm\s+volatile\b'),           # Inline assembly
    re.compile(r'#include\s*<(?!uapi|linux)'),   # Only kernel headers allowed
    re.compile(r'\bpopen\s*\('),                 # Shell via popen
    re.compile(r'\bfork\s*\('),                  # Process forking
    re.compile(r'\bdlopen\s*\('),               # Dynamic loading
]

# ALLOWED BPF helpers (whitelist approach)
ALLOWED_HELPERS = {
    'bpf_map_lookup_elem', 'bpf_map_update_elem', 'bpf_map_delete_elem',
    'bpf_ktime_get_ns', 'bpf_get_prandom_u32',
    'bpf_xdp_adjust_head', 'bpf_xdp_adjust_tail',
    'bpf_get_current_pid_tgid', 'bpf_get_current_comm',
    'bpf_perf_event_output', 'bpf_ringbuf_output',
    'bpf_skb_store_bytes', 'bpf_l3_csum_replace', 'bpf_l4_csum_replace',
    'bpf_redirect', 'bpf_clone_redirect',
    'bpf_sk_redirect_hash',
    'bpf_trace_printk',
    'bpf_send_signal',
    # BCC macros that expand to helpers (not actual bpf_ functions)
    # These are fine — BCC handles them
}

# Maximum program complexity
MAX_CODE_LENGTH = 8192          # Characters of C source
MAX_INCLUDES = 10               # Maximum #include directives


class EBPFCompiler:
    """Compiles and verifies eBPF C programs.

    Pipeline: static_analysis → kernel_verifier
    """

    def __init__(self, verifier: Optional[EBPFVerifier] = None):
        self._verifier = verifier or EBPFVerifier()

    def compile_and_verify(
        self,
        c_source: str,
        program_type: ProgramType = ProgramType.XDP,
    ) -> CompilationResult:
        """Full compilation pipeline: static analysis + kernel verification.

        Args:
            c_source: eBPF C source code.
            program_type: Target attachment type.

        Returns:
            CompilationResult with success/failure details.
        """
        # Layer 1: Static analysis
        static_result = self.static_analysis(c_source)
        if not static_result.success:
            return static_result

        # Layer 2: Kernel BPF verifier
        verify_result = self._verifier.verify(c_source, program_type)

        # Carry forward warnings from static analysis
        verify_result.warnings.extend(static_result.warnings)

        return verify_result

    def static_analysis(self, c_source: str) -> CompilationResult:
        """Run static analysis on eBPF C source.

        Checks:
          1. Code length limit
          2. Banned pattern detection
          3. Include count limit
          4. BPF helper whitelist (warning, not blocking — BCC macros
             expand to valid helpers that wouldn't be in our list)

        Returns:
            CompilationResult with PASSED or FAILED_STATIC status.
        """
        warnings: List[str] = []

        # Check 1: Code length
        if len(c_source) > MAX_CODE_LENGTH:
            return CompilationResult(
                success=False,
                c_source=c_source,
                error=f"Code exceeds maximum length ({len(c_source)} > {MAX_CODE_LENGTH})",
                verify_status=VerifyStatus.FAILED_STATIC,
            )

        # Check 2: Banned patterns
        for pattern in BANNED_PATTERNS:
            match = pattern.search(c_source)
            if match:
                return CompilationResult(
                    success=False,
                    c_source=c_source,
                    error=f"Banned pattern detected: {match.group()!r}",
                    verify_status=VerifyStatus.FAILED_STATIC,
                )

        # Check 3: Include count
        includes = re.findall(r'#include\s*[<"]', c_source)
        if len(includes) > MAX_INCLUDES:
            return CompilationResult(
                success=False,
                c_source=c_source,
                error=f"Too many includes ({len(includes)} > {MAX_INCLUDES})",
                verify_status=VerifyStatus.FAILED_STATIC,
            )

        # Check 4: BPF helper usage (warning only)
        # Find all bpf_ function calls
        bpf_calls = set(re.findall(r'\b(bpf_\w+)\s*\(', c_source))
        unknown_helpers = bpf_calls - ALLOWED_HELPERS
        if unknown_helpers:
            warnings.append(
                f"Unknown BPF helpers (may be BCC macros): {', '.join(sorted(unknown_helpers))}"
            )

        return CompilationResult(
            success=True,
            c_source=c_source,
            verify_status=VerifyStatus.PASSED,
            warnings=warnings,
        )

    def extract_code(self, llm_output: str) -> Optional[str]:
        """Extract C code from LLM output (Phase 3 — code generation).

        Handles common LLM output formats:
          - ```c ... ``` code blocks
          - ```ebpf ... ``` code blocks
          - Raw C code with #include

        Returns:
            Extracted C source, or None if no code found.
        """
        # Try fenced code blocks first
        patterns = [
            re.compile(r'```(?:c|ebpf|bpf)\s*\n(.*?)```', re.DOTALL),
            re.compile(r'```\s*\n(.*?)```', re.DOTALL),
        ]

        for pattern in patterns:
            match = pattern.search(llm_output)
            if match:
                code = match.group(1).strip()
                if '#include' in code or 'BPF_' in code:
                    return code

        # Try raw code (starts with #include)
        lines = llm_output.split('\n')
        code_lines = []
        in_code = False
        for line in lines:
            if line.strip().startswith('#include') or line.strip().startswith('BPF_'):
                in_code = True
            if in_code:
                code_lines.append(line)

        if code_lines:
            return '\n'.join(code_lines).strip()

        return None
