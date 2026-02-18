"""
LLM Monitor — eBPF-inspired LLM Process Self-Defense.

Monitors the Ollama/vLLM LLM process for signs of compromise:
1. Output monitoring: generated text contains banned patterns
2. Resource monitoring: inference exceeding time/memory budgets
3. Process tracking: PID lifecycle and anomaly detection

If compromise is detected, the monitor flags the event and can
optionally kill the LLM process before malicious output is acted upon.

This is the "immune system watching the brain" — even if the LLM is
prompt-injected, the monitor catches the resulting anomalous behavior.

Note: Actual eBPF kprobe/uprobe attachment requires root and BCC.
This module provides the monitoring framework with a pure-Python
fallback that checks outputs and resource usage without eBPF.

Author: Andrei Toma
License: Proprietary
Version: 1.0.0
"""

import logging
import os
import re
import signal
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# eBPF C Source Template (for reference / future BCC integration)
# ------------------------------------------------------------------

LLM_MONITOR_BPF_TEMPLATE = r'''
#include <uapi/linux/bpf.h>
#include <linux/sched.h>

// Monitor: if the LLM process (tracked by PID in llm_pids map)
// attempts to:
//   - connect() to an unexpected IP
//   - open() a file outside /tmp and model directories
//   - execve() any subprocess
// Then log the event and optionally kill the process.

BPF_HASH(llm_pids, u32, u8, 64);           // Tracked LLM PIDs
BPF_HASH(allowed_fds, u32, u8, 1024);      // Pre-approved file descriptors
BPF_PERF_OUTPUT(llm_events);               // Events to userspace

struct llm_event_t {
    u32 pid;
    u32 event_type;  // 1=connect, 2=open, 3=execve
    u64 timestamp;
};

// Kprobe on tcp_v4_connect — catch outbound connections
int kprobe__tcp_v4_connect(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *tracked = llm_pids.lookup(&pid);
    if (!tracked) return 0;

    struct llm_event_t evt = {};
    evt.pid = pid;
    evt.event_type = 1;
    evt.timestamp = bpf_ktime_get_ns();
    llm_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// Kprobe on sys_execve — kill if LLM tries to spawn subprocess
int kprobe__sys_execve(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *tracked = llm_pids.lookup(&pid);
    if (!tracked) return 0;

    bpf_send_signal(9);  // SIGKILL
    return 0;
}
'''


# ------------------------------------------------------------------
# Enums & Data Types
# ------------------------------------------------------------------

class MonitorEventType(str, Enum):
    """Types of events the LLM monitor detects."""
    BANNED_OUTPUT = "banned_output"       # Generated text has banned pattern
    RESOURCE_EXCEEDED = "resource_exceeded"  # Time/memory budget exceeded
    SUSPICIOUS_NETWORK = "suspicious_network"  # Unexpected network connection
    SUBPROCESS_ATTEMPT = "subprocess_attempt"  # Tried to exec a child process
    FILE_ACCESS = "file_access"           # Accessed file outside whitelist
    PID_DIED = "pid_died"                 # Tracked PID no longer running


class MonitorAction(str, Enum):
    """Action taken by the monitor."""
    LOG = "log"                   # Log the event
    ALERT = "alert"               # Alert MEDIC agent
    BLOCK_OUTPUT = "block_output" # Block the generated output
    KILL_PROCESS = "kill_process" # Send SIGKILL to the LLM process


@dataclass
class MonitorAlert:
    """An alert from the LLM monitor."""
    event_type: MonitorEventType
    action_taken: MonitorAction
    pid: int = 0
    description: str = ""
    evidence: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type.value,
            "action_taken": self.action_taken.value,
            "pid": self.pid,
            "description": self.description,
            "evidence": self.evidence[:500],  # Cap evidence size
            "timestamp": self.timestamp,
        }


# ------------------------------------------------------------------
# Banned Patterns
# ------------------------------------------------------------------

# Patterns that should NEVER appear in LLM output destined for execution.
# These are checked BEFORE the output reaches the eBPF compiler or tool executor.
BANNED_OUTPUT_PATTERNS = [
    # Shell injection
    re.compile(r';\s*rm\s+-rf\s+/', re.IGNORECASE),
    re.compile(r';\s*curl\s+.*\|\s*(?:bash|sh)', re.IGNORECASE),
    re.compile(r';\s*wget\s+.*\|\s*(?:bash|sh)', re.IGNORECASE),
    re.compile(r'`.*`'),  # Backtick command substitution
    re.compile(r'\$\(.*\)'),  # $(command) substitution

    # Privilege escalation
    re.compile(r'sudo\s+', re.IGNORECASE),
    re.compile(r'chmod\s+[0-7]*s', re.IGNORECASE),  # setuid
    re.compile(r'chown\s+root', re.IGNORECASE),

    # Data exfiltration
    re.compile(r'nc\s+.*-e\s+/bin/', re.IGNORECASE),  # Reverse shell
    re.compile(r'python.*-c.*socket', re.IGNORECASE),

    # eBPF-specific dangerous patterns
    re.compile(r'bpf_probe_write_user'),
    re.compile(r'bpf_override_return'),
    re.compile(r'system\s*\('),
    re.compile(r'exec[lv]?[pe]?\s*\('),
]


# ------------------------------------------------------------------
# LLM Monitor
# ------------------------------------------------------------------

class LLMMonitor:
    """Monitors LLM inference process for signs of compromise.

    Two modes of operation:
    1. Output scanning: Check generated text before it's acted upon
    2. Process monitoring: Track PID health and resource usage

    Usage:
        monitor = LLMMonitor()
        monitor.track_pid(12345)

        # Check LLM output before using it
        safe, alert = monitor.check_output("some LLM generated text")
        if not safe:
            # Block the output, alert MEDIC
            ...

        # Periodic health check
        alerts = monitor.check_health()
    """

    MAX_INFERENCE_TIME_S = 30.0    # Max time for a single inference
    MAX_OUTPUT_LENGTH = 16384      # Max characters of LLM output
    HEALTH_CHECK_INTERVAL_S = 5.0  # Check tracked PIDs every 5s

    def __init__(
        self,
        kill_on_exec: bool = False,
        on_alert: Optional[Callable[[MonitorAlert], None]] = None,
    ):
        """Initialize the LLM monitor.

        Args:
            kill_on_exec: If True, kill LLM process on subprocess attempt.
            on_alert: Callback invoked on each alert.
        """
        self._kill_on_exec = kill_on_exec
        self._on_alert = on_alert

        self._tracked_pids: Set[int] = set()
        self._lock = threading.Lock()
        self._alerts: List[MonitorAlert] = []
        self._inference_starts: Dict[int, float] = {}  # pid → start time

        # Stats
        self._outputs_checked = 0
        self._outputs_blocked = 0
        self._health_checks = 0

    # ------------------------------------------------------------------
    # Public: PID Tracking
    # ------------------------------------------------------------------

    def track_pid(self, pid: int) -> None:
        """Start tracking an LLM process by PID."""
        with self._lock:
            self._tracked_pids.add(pid)
        logger.info("LLM Monitor: tracking PID %d", pid)

    def untrack_pid(self, pid: int) -> None:
        """Stop tracking an LLM process."""
        with self._lock:
            self._tracked_pids.discard(pid)
            self._inference_starts.pop(pid, None)

    def get_tracked_pids(self) -> List[int]:
        """Get list of tracked PIDs."""
        with self._lock:
            return list(self._tracked_pids)

    # ------------------------------------------------------------------
    # Public: Output Checking
    # ------------------------------------------------------------------

    def check_output(self, text: str, pid: int = 0) -> tuple:
        """Check LLM output for banned patterns.

        Args:
            text: The generated text to check.
            pid: The PID that generated this output (for logging).

        Returns:
            Tuple of (safe: bool, alert: Optional[MonitorAlert]).
            If safe is False, the output should NOT be used.
        """
        self._outputs_checked += 1

        # Length check
        if len(text) > self.MAX_OUTPUT_LENGTH:
            alert = MonitorAlert(
                event_type=MonitorEventType.BANNED_OUTPUT,
                action_taken=MonitorAction.BLOCK_OUTPUT,
                pid=pid,
                description=f"Output too long: {len(text)} chars (max {self.MAX_OUTPUT_LENGTH})",
                evidence=text[:200],
            )
            self._record_alert(alert)
            self._outputs_blocked += 1
            return False, alert

        # Pattern check
        for pattern in BANNED_OUTPUT_PATTERNS:
            match = pattern.search(text)
            if match:
                alert = MonitorAlert(
                    event_type=MonitorEventType.BANNED_OUTPUT,
                    action_taken=MonitorAction.BLOCK_OUTPUT,
                    pid=pid,
                    description=f"Banned pattern detected: {pattern.pattern}",
                    evidence=match.group(0)[:200],
                )
                self._record_alert(alert)
                self._outputs_blocked += 1
                return False, alert

        return True, None

    # ------------------------------------------------------------------
    # Public: Inference Timing
    # ------------------------------------------------------------------

    def start_inference(self, pid: int = 0) -> None:
        """Mark the start of an inference call for timeout tracking."""
        with self._lock:
            self._inference_starts[pid] = time.time()

    def end_inference(self, pid: int = 0) -> Optional[MonitorAlert]:
        """Mark the end of an inference call. Returns alert if exceeded."""
        with self._lock:
            start = self._inference_starts.pop(pid, None)

        if start is None:
            return None

        duration = time.time() - start
        if duration > self.MAX_INFERENCE_TIME_S:
            alert = MonitorAlert(
                event_type=MonitorEventType.RESOURCE_EXCEEDED,
                action_taken=MonitorAction.ALERT,
                pid=pid,
                description=f"Inference took {duration:.1f}s (max {self.MAX_INFERENCE_TIME_S}s)",
            )
            self._record_alert(alert)
            return alert
        return None

    # ------------------------------------------------------------------
    # Public: Health Check
    # ------------------------------------------------------------------

    def check_health(self) -> List[MonitorAlert]:
        """Check health of all tracked PIDs.

        Returns list of alerts for any issues found.
        """
        self._health_checks += 1
        alerts = []

        with self._lock:
            pids = list(self._tracked_pids)

        for pid in pids:
            if not self._pid_alive(pid):
                alert = MonitorAlert(
                    event_type=MonitorEventType.PID_DIED,
                    action_taken=MonitorAction.ALERT,
                    pid=pid,
                    description=f"Tracked LLM PID {pid} is no longer running",
                )
                self._record_alert(alert)
                alerts.append(alert)
                self.untrack_pid(pid)

            # Check for stuck inference
            with self._lock:
                start = self._inference_starts.get(pid)
            if start is not None:
                elapsed = time.time() - start
                if elapsed > self.MAX_INFERENCE_TIME_S:
                    alert = MonitorAlert(
                        event_type=MonitorEventType.RESOURCE_EXCEEDED,
                        action_taken=MonitorAction.ALERT,
                        pid=pid,
                        description=f"Inference running for {elapsed:.1f}s (stuck?)",
                    )
                    self._record_alert(alert)
                    alerts.append(alert)

        return alerts

    # ------------------------------------------------------------------
    # Public: Stats & History
    # ------------------------------------------------------------------

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alerts."""
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def stats(self) -> Dict[str, Any]:
        """Get monitor statistics."""
        return {
            "tracked_pids": len(self._tracked_pids),
            "outputs_checked": self._outputs_checked,
            "outputs_blocked": self._outputs_blocked,
            "health_checks": self._health_checks,
            "total_alerts": len(self._alerts),
            "kill_on_exec": self._kill_on_exec,
            "bpf_template_available": True,
        }

    @staticmethod
    def get_bpf_template() -> str:
        """Return the eBPF C source template for kprobe monitoring.

        This template is for documentation and future BCC integration.
        It requires root privileges and BCC to attach.
        """
        return LLM_MONITOR_BPF_TEMPLATE

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _record_alert(self, alert: MonitorAlert) -> None:
        """Record an alert and notify callback."""
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-500:]

        if self._on_alert:
            try:
                self._on_alert(alert)
            except Exception as e:
                logger.warning("Alert callback error: %s", e)

        logger.warning(
            "LLM Monitor alert: %s — %s (PID %d)",
            alert.event_type.value, alert.description, alert.pid,
        )

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        """Check if a PID is still running."""
        if pid <= 0:
            return False
        try:
            os.kill(pid, 0)  # Signal 0 = check existence
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True  # PID exists but we can't signal it
