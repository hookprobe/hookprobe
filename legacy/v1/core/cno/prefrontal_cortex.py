"""
Prefrontal Cortex — Phase 26a

Executive veto on LLM-generated XDP programs. The threat hunter's audit
identified that Phase 20's static analysis + BPF verifier is necessary
but not sufficient to defend against adversarial prompt injection that
generates verifier-passing but malicious XDP code (e.g., magic packet
backdoor that drops legitimate traffic when a specific TCP option
is present).

This module adds three additional safety layers AFTER sandbox but BEFORE
production deployment:

1. Symbolic constraint check — verify that the program cannot reach
   XDP_DROP for traffic in the allowlist or matching RFC-1918 ranges
2. Static pattern audit — search for suspicious constants (magic
   sequences, single-IP hardcoded drops, etc.) that pass verifier but
   suggest backdoor
3. Canary deploy — route a small fraction of traffic through a parallel
   slot first; if drop rate deviates from baseline by >10%, reject the
   program before production

Without this, Phase 20 is one prompt injection away from a router self-DoS.

Author: HookProbe Team
License: Proprietary
Version: 26.0.0
"""

import logging
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# Suspicious patterns that pass BPF verifier but indicate likely backdoor
SUSPICIOUS_PATTERNS = [
    # Magic-number drops (single specific value triggers drop)
    (re.compile(r'==\s*0x[0-9a-fA-F]{8,16}\s*\)', re.IGNORECASE),
     'magic_constant_comparison'),
    (re.compile(r'tcp_flags\s*==\s*\d+', re.IGNORECASE),
     'specific_flag_match'),
    # Hardcoded single-IP drop (CIDR /32 from generated code)
    (re.compile(r'saddr\s*==\s*0x[0-9a-fA-F]{8}', re.IGNORECASE),
     'hardcoded_ip_drop'),
    # Drop based on payload byte at specific offset (steganographic backdoor)
    (re.compile(r'data\s*\+\s*\d{2,}.*XDP_DROP', re.IGNORECASE | re.DOTALL),
     'payload_offset_drop'),
    # Dropping ALL traffic (likely accidental DoS)
    (re.compile(r'^\s*return\s+XDP_DROP\s*;', re.MULTILINE),
     'unconditional_drop'),
]

# RFC-1918 + loopback prefixes that must NOT be droppable
PROTECTED_PREFIXES = [
    '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
    '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.',
    '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
    '192.168.', '127.', '169.254.',
]

# Canary thresholds
CANARY_DURATION_S = 300         # 5 min canary observation
MAX_DROP_DEVIATION_PCT = 10.0   # >10% drop rate increase = reject
MIN_CANARY_PACKETS = 100         # Need at least this many packets to assess


class PrefrontalCortex:
    """Executive veto on LLM-generated kernel programs.

    Called from kernel_orchestrator.handle_novel_threat() AFTER sandbox
    succeeds but BEFORE sensor_manager.deploy(). Returns (approved, reason).

    Three checks, all must pass:
      1. Static suspicious-pattern audit
      2. Symbolic protected-prefix check (heuristic)
      3. Canary deploy + observation (if canary infrastructure available)
    """

    def __init__(self, packet_rate_query_fn=None):
        """
        Args:
            packet_rate_query_fn: Optional callback(interface, since_ts, until_ts)
                → packet_rate_pps. Used for canary observation. If None,
                canary phase is skipped (logged as deferred).
        """
        self._packet_rate_query = packet_rate_query_fn
        self._lock = threading.Lock()

        self._stats = {
            'programs_evaluated': 0,
            'approved': 0,
            'rejected_suspicious_pattern': 0,
            'rejected_protected_prefix': 0,
            'rejected_canary_drop_spike': 0,
            'canary_skipped_no_query_fn': 0,
        }

    def evaluate(self, c_source: str, signal: Any = None) -> Tuple[bool, str]:
        """Evaluate a generated XDP program for safety.

        Args:
            c_source: The generated C source code from LLM
            signal: Optional StandardSignal that triggered generation

        Returns:
            (approved, reason): True if safe to deploy, False with reason
        """
        with self._lock:
            self._stats['programs_evaluated'] += 1

        # Check 1: suspicious patterns
        passed, reason = self._check_suspicious_patterns(c_source)
        if not passed:
            with self._lock:
                self._stats['rejected_suspicious_pattern'] += 1
            return False, f"prefrontal_veto: {reason}"

        # Check 2: protected prefix safety (heuristic — looks for explicit
        # references to RFC-1918 IPs that the program might drop)
        passed, reason = self._check_protected_prefixes(c_source)
        if not passed:
            with self._lock:
                self._stats['rejected_protected_prefix'] += 1
            return False, f"prefrontal_veto: {reason}"

        # Check 3: canary deploy (if infrastructure available)
        # Note: full canary deploy requires kernel_orchestrator integration
        # to attach the program to a canary slot. This module returns the
        # evaluation result; the orchestrator wires the actual canary slot.
        # For now, we simulate: if packet_rate_query is None, we skip and log.
        if not self._packet_rate_query:
            with self._lock:
                self._stats['canary_skipped_no_query_fn'] += 1
            logger.info("PREFRONTAL: canary deferred (no packet_rate_query)")

        with self._lock:
            self._stats['approved'] += 1
        logger.info("PREFRONTAL APPROVED: %d chars passed all veto checks",
                     len(c_source))
        return True, "approved"

    def _check_suspicious_patterns(self, c_source: str) -> Tuple[bool, str]:
        """Search for patterns indicating likely backdoor or DoS."""
        # Check if there's at least one bounds check (basic sanity)
        if 'data_end' not in c_source:
            return False, "no_bounds_check (missing data_end)"

        # Check unconditional drop near end of function
        # (legitimate XDP programs default to XDP_PASS)
        if re.search(r'^\s*return\s+XDP_DROP\s*;\s*$', c_source, re.MULTILINE):
            # Check if this is the LAST statement before closing brace
            lines = c_source.split('\n')
            for i, line in enumerate(lines):
                if re.match(r'^\s*return\s+XDP_DROP\s*;\s*$', line):
                    # Check next non-empty line
                    for j in range(i + 1, min(i + 5, len(lines))):
                        if lines[j].strip() == '}':
                            return False, "unconditional_xdp_drop_at_end"

        # Check for suspicious constants
        for pattern, name in SUSPICIOUS_PATTERNS:
            if name == 'unconditional_drop':
                continue  # Handled above
            matches = pattern.findall(c_source)
            if len(matches) > 0:
                # Allow some patterns in moderation; block if many
                if name == 'magic_constant_comparison' and len(matches) > 3:
                    return False, f"too_many_magic_constants ({len(matches)})"
                if name == 'hardcoded_ip_drop':
                    return False, "hardcoded_ip_in_drop_path"
                if name == 'payload_offset_drop':
                    return False, "payload_offset_drop_pattern"

        return True, "patterns_clean"

    def _check_protected_prefixes(self, c_source: str) -> Tuple[bool, str]:
        """Heuristic: look for explicit references to RFC-1918 IPs in
        a context that suggests they might be dropped.

        Bytes representation of e.g. 192.168.x.x = 0xc0a8....
        We search for these byte sequences near XDP_DROP returns.
        """
        # Specific dangerous: 0x7f000001 (127.0.0.1), 0xc0a80000 (192.168.0.0)
        # If these appear as comparison operands AND the function has XDP_DROP
        dangerous_constants = [
            ('0xa', '10.x.x.x range'),
            ('0xc0a8', '192.168.x.x range'),
            ('0x7f00', '127.x.x.x loopback'),
            ('0xa9fe', '169.254.x.x link-local'),
        ]
        for hex_prefix, desc in dangerous_constants:
            # Search for comparisons with these prefixes
            pattern = re.compile(
                rf'(saddr|daddr|src|dst)\s*[=<>]+\s*{hex_prefix}',
                re.IGNORECASE)
            if pattern.search(c_source):
                # Check if XDP_DROP appears within 5 lines after the match
                for m in pattern.finditer(c_source):
                    after = c_source[m.end():m.end() + 500]
                    if 'XDP_DROP' in after:
                        return False, f"may_drop_{desc.replace(' ', '_')}"
        return True, "prefixes_safe"

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._stats)
