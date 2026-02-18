"""
Neuro-Kernel Type Definitions

Data types for the closed-loop kernel orchestration system.
All types are plain dataclasses — no Pydantic needed for internal use.

Author: Andrei Toma
License: Proprietary
Version: 1.0.0
"""

import time
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional


# ------------------------------------------------------------------
# Enums
# ------------------------------------------------------------------

class KernelActionType(str, Enum):
    """Type of kernel-level action."""
    DEPLOY_TEMPLATE = "deploy_template"      # Pre-built eBPF template
    DEPLOY_GENERATED = "deploy_generated"    # LLM-generated eBPF (Phase 3)
    ROLLBACK = "rollback"                    # Revert to previous program
    REMOVE = "remove"                        # Remove an active program


class ProgramType(str, Enum):
    """eBPF program attach type."""
    XDP = "xdp"
    TC = "tc"
    KPROBE = "kprobe"
    TRACEPOINT = "tracepoint"
    UPROBE = "uprobe"


class VerifyStatus(str, Enum):
    """Result of eBPF verification."""
    PASSED = "passed"
    FAILED_STATIC = "failed_static"       # Static analysis caught issue
    FAILED_VERIFIER = "failed_verifier"   # Kernel BPF verifier rejected
    FAILED_SANDBOX = "failed_sandbox"     # Behavioral sandbox test failed
    SKIPPED = "skipped"                   # Verification skipped (BCC unavailable)


class SandboxResult(str, Enum):
    """Sandbox test outcome."""
    PASSED = "passed"
    FAILED_BEHAVIOR = "failed_behavior"   # Unexpected drop/pass pattern
    FAILED_SIDE_EFFECT = "failed_side_effect"  # Unexpected map writes, etc.
    FAILED_TIMEOUT = "failed_timeout"     # Program hung or exceeded time
    SKIPPED = "skipped"                   # Sandbox unavailable


class SensorType(str, Enum):
    """Type of eBPF sensor."""
    NETWORK = "network"       # Packet-level (XDP/TC)
    SYSCALL = "syscall"       # Kprobe/tracepoint on syscalls
    FILE = "file"             # File access monitoring
    PROCESS = "process"       # Process lifecycle (exec, exit)
    DNS = "dns"               # DNS query/response capture


# ------------------------------------------------------------------
# Data Types
# ------------------------------------------------------------------

@dataclass
class CompilationResult:
    """Result of compiling an eBPF program."""
    success: bool
    program_type: ProgramType = ProgramType.XDP
    bytecode: Optional[bytes] = None       # Compiled BPF object (if success)
    c_source: str = ""                     # Original C source
    error: str = ""                        # Error message (if failed)
    verify_status: VerifyStatus = VerifyStatus.SKIPPED
    instruction_count: int = 0
    warnings: List[str] = field(default_factory=list)

    @property
    def verified(self) -> bool:
        return self.verify_status == VerifyStatus.PASSED


@dataclass
class SandboxTestResult:
    """Result of sandbox testing an eBPF program."""
    passed: bool
    result: SandboxResult = SandboxResult.SKIPPED
    reason: str = ""
    duration_s: float = 0.0
    packets_tested: int = 0
    packets_dropped: int = 0
    packets_passed: int = 0
    side_effects: List[str] = field(default_factory=list)


@dataclass
class KernelAction:
    """A kernel-level action taken by the orchestrator."""
    action_type: KernelActionType
    program_id: str                          # Unique ID for this program
    program_type: ProgramType = ProgramType.XDP
    attach_point: str = ""                   # Interface or function name
    template_name: str = ""                  # Template used (if template-based)
    target_ip: str = ""                      # Target IP (if applicable)
    compilation: Optional[CompilationResult] = None
    sandbox: Optional[SandboxTestResult] = None
    timestamp: float = field(default_factory=time.time)
    rollback_timeout_s: int = 300            # Auto-rollback if no improvement
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_type": self.action_type.value,
            "program_id": self.program_id,
            "program_type": self.program_type.value,
            "attach_point": self.attach_point,
            "template_name": self.template_name,
            "target_ip": self.target_ip,
            "timestamp": self.timestamp,
            "rollback_timeout_s": self.rollback_timeout_s,
        }


@dataclass
class ActiveProgram:
    """Tracks a currently deployed eBPF program."""
    program_id: str
    program_type: ProgramType
    attach_point: str
    template_name: str = ""
    deployed_at: float = field(default_factory=time.time)
    rollback_deadline: float = 0.0           # 0 = no auto-rollback
    previous_program_id: str = ""            # For rollback chain
    c_source: str = ""                       # For audit
    signal_source: str = ""                  # What triggered this deployment
    drop_count: int = 0
    pass_count: int = 0


@dataclass
class SensorEvent:
    """A single event from an eBPF sensor."""
    sensor_type: SensorType
    timestamp: float = field(default_factory=time.time)
    source_ip: str = ""
    dest_ip: str = ""
    protocol: int = 0                        # IP protocol number
    port: int = 0
    pid: int = 0
    comm: str = ""                           # Process name
    payload_len: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TemplateMatch:
    """Result of matching a signal against the template registry."""
    matched: bool
    template_name: str = ""
    program_type: ProgramType = ProgramType.XDP
    c_source: str = ""
    confidence: float = 0.0
    description: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
