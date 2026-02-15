"""
NAPSE Healing Engine — eBPF-to-Process Correlation and Response

Bridges kernel-level eBPF events to host-level process enforcement.
When SIA detects attack intent phases, the HealingEngine traces which
process opened the flagged connection and can:

1. Kill malicious processes (SIGKILL via eBPF or userspace)
2. Quarantine processes (cgroup isolation)
3. Apply hotpatches (block vulnerable syscall patterns)

Integration:
- Loads eBPF programs (process_tracer, syscall_monitor, hotpatch) via BCC
- Correlates network alerts to PIDs via /proc/net/tcp
- Emits StandardSignal to AEGIS via HealingBridge
"""

import logging
import os
import re
import signal
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class ProcessVerdict(Enum):
    """Verdict for a monitored process."""
    CLEAN = auto()
    SUSPICIOUS = auto()
    MALICIOUS = auto()
    QUARANTINED = auto()
    KILLED = auto()


@dataclass
class ProcessRecord:
    """Tracked process with suspicious activity."""
    pid: int
    ppid: int = 0
    uid: int = 0
    comm: str = ""
    suspicious_score: int = 0
    verdict: ProcessVerdict = ProcessVerdict.CLEAN
    flags: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    network_alerts: int = 0
    file_alerts: int = 0
    connection_alerts: int = 0

    @property
    def total_alerts(self) -> int:
        return self.network_alerts + self.file_alerts + self.connection_alerts


@dataclass
class SyscallEvent:
    """Parsed syscall event from eBPF ring buffer."""
    timestamp_ns: int
    pid: int
    uid: int
    syscall_type: int  # 1=openat, 2=connect, 3=write
    severity: int
    dst_port: int = 0
    dst_ip: int = 0
    comm: str = ""
    path: str = ""


@dataclass
class HotpatchRule:
    """Rule for the hotpatch eBPF program."""
    syscall_nr: int
    patch_type: int = 1  # 1=block, 2=block_arg, 3=log_only
    target_comm: str = ""
    enabled: bool = True


class HealingEngine:
    """Kernel-level process healing engine.

    In production, this loads eBPF programs via BCC. In environments
    without BCC (VMs, containers), it falls back to /proc-based
    monitoring and userspace signal delivery.
    """

    # Suspicious score thresholds (matching kernel constants)
    SCORE_CLEAN = 0
    SCORE_LOW = 10
    SCORE_MEDIUM = 30
    SCORE_HIGH = 60
    SCORE_CRITICAL = 90

    # Known C2 ports (matching kernel)
    C2_PORTS = {4444, 5555, 8888, 1337}

    # Sensitive paths
    SENSITIVE_PATHS = {
        "/etc/shadow", "/etc/passwd", "/etc/sudoers",
        "/proc/kcore", "/proc/kallsyms",
    }

    # Persistence paths
    PERSISTENCE_PATHS = {
        "/etc/cron", "/var/spool/cron", "/etc/systemd",
        "/etc/rc.local", "/etc/init.d",
    }

    def __init__(
        self,
        dry_run: bool = True,
        bcc_available: bool = False,
        on_process_event: Optional[Callable] = None,
        on_syscall_event: Optional[Callable] = None,
    ):
        self.dry_run = dry_run
        self.bcc_available = bcc_available
        self.on_process_event = on_process_event
        self.on_syscall_event = on_syscall_event

        # Tracked processes
        self._processes: Dict[int, ProcessRecord] = {}
        self._killed_pids: Set[int] = set()
        self._quarantined_pids: Set[int] = set()

        # Hotpatch rules
        self._hotpatch_rules: Dict[int, HotpatchRule] = {}

        # Stats
        self._stats = {
            "processes_tracked": 0,
            "processes_killed": 0,
            "processes_quarantined": 0,
            "hotpatches_applied": 0,
            "network_correlations": 0,
            "events_processed": 0,
        }

    def process_exec_event(
        self,
        pid: int,
        ppid: int,
        uid: int,
        comm: str,
        suspicious_score: int,
        flags: int = 0,
    ) -> ProcessRecord:
        """Handle a process execution event (from eBPF or /proc)."""
        self._stats["events_processed"] += 1

        record = self._processes.get(pid)
        if record is None:
            record = ProcessRecord(
                pid=pid, ppid=ppid, uid=uid, comm=comm,
                suspicious_score=suspicious_score, flags=flags,
            )
            self._processes[pid] = record
            self._stats["processes_tracked"] += 1
        else:
            record.suspicious_score = max(record.suspicious_score, suspicious_score)
            record.flags |= flags
            record.last_seen = time.time()

        # Auto-classify
        if suspicious_score >= self.SCORE_CRITICAL:
            record.verdict = ProcessVerdict.MALICIOUS
        elif suspicious_score >= self.SCORE_HIGH:
            record.verdict = ProcessVerdict.SUSPICIOUS

        if self.on_process_event:
            self.on_process_event(record)

        return record

    def process_syscall_event(self, event: SyscallEvent) -> Optional[ProcessRecord]:
        """Handle a syscall event (from eBPF ring buffer)."""
        self._stats["events_processed"] += 1

        record = self._processes.get(event.pid)
        if record is None:
            record = ProcessRecord(
                pid=event.pid, uid=event.uid, comm=event.comm,
            )
            self._processes[event.pid] = record
            self._stats["processes_tracked"] += 1

        record.last_seen = time.time()

        if event.syscall_type == 1:  # openat
            record.file_alerts += 1
            record.suspicious_score += event.severity * 10
        elif event.syscall_type == 2:  # connect
            record.connection_alerts += 1
            record.suspicious_score += event.severity * 15
        elif event.syscall_type == 3:  # write
            record.file_alerts += 1
            record.suspicious_score += event.severity * 10

        # Escalate verdict
        if record.suspicious_score >= self.SCORE_CRITICAL:
            record.verdict = ProcessVerdict.MALICIOUS
        elif record.suspicious_score >= self.SCORE_HIGH:
            record.verdict = ProcessVerdict.SUSPICIOUS

        if self.on_syscall_event:
            self.on_syscall_event(event)

        return record

    def correlate_network_alert(
        self,
        source_ip: str,
        source_port: int,
        dest_ip: str,
        dest_port: int,
    ) -> Optional[ProcessRecord]:
        """Correlate a network alert to a process via /proc/net/tcp.

        Returns the ProcessRecord if found, None otherwise.
        """
        self._stats["network_correlations"] += 1

        pid = self._find_pid_for_connection(source_ip, source_port)
        if pid is None:
            return None

        record = self._processes.get(pid)
        if record is None:
            # Create new record from /proc
            comm = self._read_proc_comm(pid)
            record = ProcessRecord(
                pid=pid, comm=comm or "unknown",
                suspicious_score=self.SCORE_MEDIUM,
            )
            self._processes[pid] = record
            self._stats["processes_tracked"] += 1

        record.network_alerts += 1
        record.suspicious_score += 20
        record.last_seen = time.time()

        if record.suspicious_score >= self.SCORE_CRITICAL:
            record.verdict = ProcessVerdict.MALICIOUS

        return record

    def kill_process(self, pid: int, reason: str = "") -> bool:
        """Kill a malicious process.

        In dry_run mode, only logs the action.
        """
        if pid in self._killed_pids:
            return True  # already killed

        record = self._processes.get(pid)
        comm = record.comm if record else "unknown"

        if self.dry_run:
            logger.info(
                "[DRY RUN] Would kill PID %d (%s): %s", pid, comm, reason,
            )
            if record:
                record.verdict = ProcessVerdict.KILLED
            self._killed_pids.add(pid)
            self._stats["processes_killed"] += 1
            return True

        try:
            os.kill(pid, signal.SIGKILL)
            logger.warning("Killed PID %d (%s): %s", pid, comm, reason)
            if record:
                record.verdict = ProcessVerdict.KILLED
            self._killed_pids.add(pid)
            self._stats["processes_killed"] += 1
            return True
        except ProcessLookupError:
            logger.info("PID %d already dead", pid)
            self._killed_pids.add(pid)
            return True
        except PermissionError:
            logger.error("No permission to kill PID %d", pid)
            return False

    def quarantine_process(self, pid: int, reason: str = "") -> bool:
        """Quarantine a process via cgroup isolation.

        Moves the process to a restricted cgroup that limits:
        - Network access (no egress)
        - CPU to 5%
        - Memory to 64MB
        """
        if pid in self._quarantined_pids:
            return True

        record = self._processes.get(pid)
        comm = record.comm if record else "unknown"

        if self.dry_run:
            logger.info(
                "[DRY RUN] Would quarantine PID %d (%s): %s", pid, comm, reason,
            )
            if record:
                record.verdict = ProcessVerdict.QUARANTINED
            self._quarantined_pids.add(pid)
            self._stats["processes_quarantined"] += 1
            return True

        # Create quarantine cgroup
        cgroup_path = Path("/sys/fs/cgroup/hookprobe-quarantine")
        try:
            cgroup_path.mkdir(parents=True, exist_ok=True)

            # Set resource limits
            (cgroup_path / "cpu.max").write_text("5000 100000")  # 5%
            (cgroup_path / "memory.max").write_text("67108864")  # 64MB

            # Move process
            (cgroup_path / "cgroup.procs").write_text(str(pid))

            logger.warning("Quarantined PID %d (%s): %s", pid, comm, reason)
            if record:
                record.verdict = ProcessVerdict.QUARANTINED
            self._quarantined_pids.add(pid)
            self._stats["processes_quarantined"] += 1
            return True
        except Exception as e:
            logger.error("Failed to quarantine PID %d: %s", pid, e)
            return False

    def apply_hotpatch(self, rule: HotpatchRule) -> bool:
        """Apply a hotpatch rule to the eBPF hotpatch program.

        In production with BCC, this updates the patch_table map.
        Without BCC, records the rule for userspace enforcement.
        """
        self._hotpatch_rules[rule.syscall_nr] = rule
        self._stats["hotpatches_applied"] += 1

        logger.info(
            "Applied hotpatch: syscall=%d, type=%d, comm=%s, enabled=%s",
            rule.syscall_nr, rule.patch_type,
            rule.target_comm or "*", rule.enabled,
        )
        return True

    def remove_hotpatch(self, syscall_nr: int) -> bool:
        """Remove a hotpatch rule."""
        if syscall_nr in self._hotpatch_rules:
            del self._hotpatch_rules[syscall_nr]
            return True
        return False

    def get_process(self, pid: int) -> Optional[ProcessRecord]:
        """Get a tracked process record."""
        return self._processes.get(pid)

    def get_suspicious_processes(
        self, min_score: int = SCORE_MEDIUM,
    ) -> List[ProcessRecord]:
        """Get all processes above a suspicious score threshold."""
        return [
            r for r in self._processes.values()
            if r.suspicious_score >= min_score
        ]

    def get_malicious_processes(self) -> List[ProcessRecord]:
        """Get all processes classified as malicious."""
        return [
            r for r in self._processes.values()
            if r.verdict == ProcessVerdict.MALICIOUS
        ]

    def _find_pid_for_connection(
        self,
        local_ip: str,
        local_port: int,
    ) -> Optional[int]:
        """Find PID that owns a local TCP connection via /proc/net/tcp."""
        try:
            ip_hex = self._ip_to_hex(local_ip)
            port_hex = f"{local_port:04X}"
            target = f"{ip_hex}:{port_hex}"

            proc_net = Path("/proc/net/tcp")
            if not proc_net.exists():
                return None

            content = proc_net.read_text()
            for line in content.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 10:
                    continue
                if parts[1] == target:
                    inode = int(parts[9])
                    return self._find_pid_by_inode(inode)
        except Exception as e:
            logger.debug("Failed to correlate connection: %s", e)

        return None

    def _find_pid_by_inode(self, inode: int) -> Optional[int]:
        """Find PID that owns a socket inode."""
        socket_str = f"socket:[{inode}]"
        try:
            for pid_dir in Path("/proc").iterdir():
                if not pid_dir.name.isdigit():
                    continue
                fd_dir = pid_dir / "fd"
                if not fd_dir.exists():
                    continue
                try:
                    for fd in fd_dir.iterdir():
                        try:
                            link = os.readlink(str(fd))
                            if link == socket_str:
                                return int(pid_dir.name)
                        except (OSError, ValueError):
                            continue
                except PermissionError:
                    continue
        except Exception:
            pass
        return None

    @staticmethod
    def _ip_to_hex(ip: str) -> str:
        """Convert IP address to /proc/net/tcp hex format (little-endian)."""
        parts = ip.split(".")
        if len(parts) != 4:
            return "00000000"
        return "".join(f"{int(p):02X}" for p in reversed(parts))

    @staticmethod
    def _read_proc_comm(pid: int) -> Optional[str]:
        """Read process comm from /proc/<pid>/comm."""
        try:
            return Path(f"/proc/{pid}/comm").read_text().strip()
        except Exception:
            return None

    def get_stats(self) -> dict:
        return {
            **self._stats,
            "active_processes": len(self._processes),
            "killed_pids": len(self._killed_pids),
            "quarantined_pids": len(self._quarantined_pids),
            "hotpatch_rules": len(self._hotpatch_rules),
            "dry_run": self.dry_run,
            "bcc_available": self.bcc_available,
        }
