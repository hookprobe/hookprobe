"""
AEGIS Autonomous Operation

Self-operating mode with scheduled tasks and confidence-gated actions.

Components:
  - AutonomousScheduler: Cron-like periodic tasks
  - AutonomousWatcher: Real-time event response with confidence gating
  - SystemIntrospector: Self-discovery of installed HookProbe components
"""

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from .types import StandardSignal

logger = logging.getLogger(__name__)

# Confidence thresholds for autonomous actions
CONFIDENCE_AUTO_ACT = 0.8   # Auto-execute without human
CONFIDENCE_NOTIFY = 0.6     # Notify human, suggest action
CONFIDENCE_LOG_ONLY = 0.0   # Just log, no action


# ------------------------------------------------------------------
# Scheduled Tasks
# ------------------------------------------------------------------

@dataclass
class ScheduledTask:
    """A periodic task for autonomous execution."""
    name: str
    interval_seconds: int
    agent: str
    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    last_run: Optional[float] = None
    enabled: bool = True


class AutonomousScheduler:
    """Cron-like scheduler for periodic AEGIS tasks.

    Default schedule:
    - Hourly: Health check, bridge status
    - Daily: Network summary, decision review
    - Weekly: Security audit (FORGE)
    """

    def __init__(self):
        self._tasks: Dict[str, ScheduledTask] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callback: Optional[Callable[[str, str, Dict], None]] = None

        # Register default tasks
        self._register_defaults()

    def _register_defaults(self):
        """Register built-in scheduled tasks."""
        self.schedule(ScheduledTask(
            name="hourly_health_check",
            interval_seconds=3600,
            agent="ORACLE",
            action="health_check",
        ))
        self.schedule(ScheduledTask(
            name="daily_network_summary",
            interval_seconds=86400,
            agent="ORACLE",
            action="generate_report",
            params={"report_type": "daily_summary"},
        ))
        self.schedule(ScheduledTask(
            name="daily_decision_review",
            interval_seconds=86400,
            agent="MEDIC",
            action="review_decisions",
        ))
        self.schedule(ScheduledTask(
            name="weekly_security_audit",
            interval_seconds=604800,
            agent="FORGE",
            action="recommend_hardening",
            params={"audit_type": "weekly"},
        ))
        self.schedule(ScheduledTask(
            name="daily_memory_decay",
            interval_seconds=86400,
            agent="system",
            action="memory_decay",
        ))

    def schedule(self, task: ScheduledTask) -> None:
        """Add or update a scheduled task."""
        self._tasks[task.name] = task

    def unschedule(self, name: str) -> bool:
        """Remove a scheduled task."""
        return self._tasks.pop(name, None) is not None

    def set_callback(self, callback: Callable[[str, str, Dict], None]) -> None:
        """Set callback for task execution: callback(agent, action, params)."""
        self._callback = callback

    def start(self) -> None:
        """Start the scheduler in a daemon thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop,
            name="aegis-scheduler",
            daemon=True,
        )
        self._thread.start()
        logger.info("Autonomous scheduler started with %d tasks", len(self._tasks))

    def stop(self) -> None:
        """Stop the scheduler."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _run_loop(self) -> None:
        """Main scheduler loop — check tasks every 60s."""
        while self._running:
            now = time.time()
            for task in self._tasks.values():
                if not task.enabled:
                    continue
                if task.last_run is None or (now - task.last_run) >= task.interval_seconds:
                    self._execute_task(task)
                    task.last_run = now

            time.sleep(60)

    def _execute_task(self, task: ScheduledTask) -> None:
        """Execute a scheduled task via callback."""
        logger.info("Scheduled task: %s (%s.%s)", task.name, task.agent, task.action)
        if self._callback:
            try:
                self._callback(task.agent, task.action, task.params)
            except Exception as e:
                logger.error("Scheduled task %s error: %s", task.name, e)

    def get_tasks(self) -> List[Dict[str, Any]]:
        """Get all scheduled tasks and their status."""
        return [
            {
                "name": t.name,
                "agent": t.agent,
                "action": t.action,
                "interval": t.interval_seconds,
                "last_run": t.last_run,
                "enabled": t.enabled,
            }
            for t in self._tasks.values()
        ]


# ------------------------------------------------------------------
# Real-Time Watcher
# ------------------------------------------------------------------

class AutonomousWatcher:
    """Real-time event watcher with confidence-gated actions.

    Receives signals from bridges and invokes agents via the orchestrator.
    Actions are gated by confidence:
      - >= 0.8: Auto-execute (no human needed)
      - 0.6-0.8: Notify human, suggest action
      - < 0.6: Log only
    """

    def __init__(self):
        self._orchestrator = None
        self._memory = None
        self._running = False
        self._signal_count = 0
        self._auto_actions = 0
        self._notifications = 0

    def set_orchestrator(self, orchestrator) -> None:
        """Wire to the orchestrator for signal processing."""
        self._orchestrator = orchestrator

    def set_memory(self, memory) -> None:
        """Wire to memory for logging."""
        self._memory = memory

    def on_signal(self, signal: StandardSignal) -> None:
        """Process a signal with confidence gating.

        This is the callback registered with BridgeManager.
        """
        if not self._orchestrator:
            return

        self._signal_count += 1

        try:
            responses = self._orchestrator.process_signal(signal)

            for response in responses:
                if response.confidence >= CONFIDENCE_AUTO_ACT and response.action:
                    # Auto-execute
                    self._auto_actions += 1
                    logger.info(
                        "AUTO: %s.%s (confidence=%.0f%%)",
                        response.agent, response.action, response.confidence * 100,
                    )
                elif response.confidence >= CONFIDENCE_NOTIFY and response.action:
                    # Notify human
                    self._notifications += 1
                    logger.info(
                        "NOTIFY: %s suggests %s (confidence=%.0f%%)",
                        response.agent, response.action, response.confidence * 100,
                    )
                    if self._memory:
                        self._memory.store(
                            "session",
                            f"suggestion_{int(time.time())}",
                            f"{response.agent} suggests: {response.action} — "
                            f"{response.reasoning} (confidence: {response.confidence:.0%})",
                        )
                # else: log only (already logged by orchestrator)

        except Exception as e:
            logger.error("Autonomous watcher error: %s", e)

    def get_stats(self) -> Dict[str, Any]:
        """Get watcher statistics."""
        return {
            "signals_processed": self._signal_count,
            "auto_actions": self._auto_actions,
            "notifications": self._notifications,
        }


# ------------------------------------------------------------------
# System Introspector
# ------------------------------------------------------------------

class SystemIntrospector:
    """Discovers what HookProbe components are installed.

    Builds a system model that AEGIS uses for context-aware decisions.
    """

    def learn_system(self) -> Dict[str, Any]:
        """Discover all installed HookProbe components and capabilities."""
        system = {
            "product_tier": self._detect_tier(),
            "components": self._detect_components(),
            "network": self._detect_network(),
            "containers": self._detect_containers(),
            "hostname": os.uname().nodename,
            "discovered_at": datetime.utcnow().isoformat(),
        }
        return system

    def _detect_tier(self) -> str:
        """Detect which product tier is installed."""
        if os.path.exists("/etc/hookprobe/fortress.conf"):
            return "fortress"
        if os.path.exists("/opt/hookprobe/guardian"):
            return "guardian"
        if os.path.exists("/opt/hookprobe/sentinel"):
            return "sentinel"
        return "unknown"

    def _detect_components(self) -> Dict[str, bool]:
        """Detect which components are available."""
        return {
            "qsecbit": os.path.exists("/opt/hookprobe/fortress/data/qsecbit_stats.json") or
                       os.path.exists("/opt/hookprobe/guardian/data/qsecbit_stats.json"),
            "dnsxai": self._check_service("fts-dnsxai") or
                      os.path.exists("/opt/hookprobe/dnsxai"),
            "slaai": os.path.exists("/run/fortress/slaai-recommendation.json"),
            "aiochi": os.path.exists("/opt/hookprobe/aiochi"),
            "suricata": self._check_service("fts-suricata") or
                        self._check_service("aiochi-suricata"),
            "zeek": self._check_service("fts-zeek") or
                    self._check_service("aiochi-zeek"),
            "ollama": self._check_service("aiochi-ollama") or
                      self._check_port(11434),
            "clickhouse": self._check_service("fts-clickhouse") or
                          self._check_service("aiochi-clickhouse"),
            "ovs_bridge": os.path.exists("/usr/bin/ovs-vsctl"),
            "wifi": os.path.exists("/etc/hookprobe/wifi-interfaces.conf"),
        }

    def _detect_network(self) -> Dict[str, Any]:
        """Detect basic network configuration."""
        network = {}
        conf_path = "/etc/hookprobe/fortress.conf"
        if os.path.exists(conf_path):
            try:
                with open(conf_path) as f:
                    for line in f:
                        line = line.strip()
                        if "=" in line and not line.startswith("#"):
                            key, _, val = line.partition("=")
                            key = key.strip()
                            val = val.strip().strip('"').strip("'")
                            if key in ("LAN_SUBNET", "WAN_INTERFACE", "WIFI_SSID",
                                       "WEB_PORT", "HOSTAPD_OVS_MODE"):
                                network[key.lower()] = val
            except Exception:
                pass
        return network

    def _detect_containers(self) -> List[str]:
        """Detect running containers."""
        try:
            import subprocess
            result = subprocess.run(
                ["podman", "ps", "--format", "{{.Names}}"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                return [n.strip() for n in result.stdout.strip().split("\n") if n.strip()]
        except Exception:
            pass
        return []

    @staticmethod
    def _check_service(name: str) -> bool:
        """Check if a container/service is running."""
        try:
            import subprocess
            result = subprocess.run(
                ["podman", "inspect", name, "--format", "{{.State.Running}}"],
                capture_output=True, text=True, timeout=3,
            )
            return result.stdout.strip() == "true"
        except Exception:
            return False

    @staticmethod
    def _check_port(port: int) -> bool:
        """Check if a TCP port is open on localhost."""
        import socket
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                return s.connect_ex(("127.0.0.1", port)) == 0
        except Exception:
            return False
