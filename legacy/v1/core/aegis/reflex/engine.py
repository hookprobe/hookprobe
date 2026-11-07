"""
AEGIS Reflex — Engine (Central Evaluator + Executor)

The ReflexEngine evaluates QSecBit scores per-IP, determines the
appropriate interference level, and manages eBPF program map entries.
Score velocity (dQ/dt) acts as a multiplier for fast escalation/de-escalation.

This is the digital immune system: it inflames proportionally to threat
severity and self-heals via the Bayesian recovery loop.

Author: Andrei Toma
License: Proprietary - see LICENSE in this directory
Version: 2.0.0
"""

import atexit
import logging
import os
import socket
import struct
import subprocess
import threading
import time
from collections import deque
from typing import Any, Dict, List, Optional

from .ebpf_programs import (
    BCC_AVAILABLE,
    JITTER_TC_PROGRAM,
    SOCKMAP_REDIRECT_PROGRAM,
    SURGICAL_DISCONNECT_PROGRAM,
    get_fallback_block_commands,
    get_fallback_block_remove_commands,
    get_fallback_jitter_commands,
    get_fallback_jitter_remove_commands,
    get_fallback_shadow_commands,
    get_fallback_shadow_remove_commands,
)
from .recovery import BayesianRecoveryEngine
from .types import (
    LEVEL_THRESHOLDS,
    ReflexDecision,
    ReflexLevel,
    ReflexTarget,
    ScoreVelocity,
)

if BCC_AVAILABLE:
    from bcc import BPF

logger = logging.getLogger(__name__)


# Default Mirage honeypot port (from shared/mirage/)
DEFAULT_MIRAGE_PORT = 9999


class ReflexEngine:
    """Central evaluator and executor for graduated interference.

    Responsibilities:
    - Map QSecBit scores to reflex levels (with velocity adjustment)
    - Manage per-IP eBPF map entries (jitter, sockmap, kill)
    - Delegate recovery monitoring to BayesianRecoveryEngine
    - Log all decisions for audit trail
    - Fall back to iptables/tc when BCC unavailable
    """

    # Score velocity thresholds for level adjustment
    VELOCITY_ESCALATE = 0.10       # dQ/dt > 0.1/s → bump up one level
    VELOCITY_DEESCALATE = -0.05    # dQ/dt < -0.05/s → drop down one level

    # Jitter range (ms) within JITTER level
    JITTER_MIN_MS = 10
    JITTER_MAX_MS = 500

    def __init__(
        self,
        interface: str = "eth0",
        mirage_port: int = DEFAULT_MIRAGE_PORT,
    ):
        self._interface = interface
        self._mirage_port = mirage_port

        # Per-IP state (guarded by _targets_lock)
        self._targets: Dict[str, ReflexTarget] = {}
        self._velocity_trackers: Dict[str, ScoreVelocity] = {}
        self._targets_lock = threading.Lock()

        # Decision audit log
        self._decision_log: deque = deque(maxlen=10000)

        # Bayesian recovery engine
        self._recovery = BayesianRecoveryEngine()

        # Lazy-loaded BPF programs (loaded on first use)
        self._bpf_jitter: Optional[Any] = None
        self._bpf_sockmap: Optional[Any] = None
        self._bpf_surgical: Optional[Any] = None
        self._bpf_loaded = False

        # Track whether eBPF is usable
        self._use_ebpf = BCC_AVAILABLE

        # Executor mode: "active" (default) applies rules, "log-only" just logs
        self._executor_mode = os.environ.get("REFLEX_EXECUTOR", "active")

        # Cleanup on exit
        atexit.register(self.cleanup)

        logger.info(
            "ReflexEngine initialized (interface=%s, mirage_port=%d, ebpf=%s, mode=%s)",
            interface, mirage_port, self._use_ebpf, self._executor_mode,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, ip: str, qsecbit_score: float) -> Optional[ReflexDecision]:
        """Evaluate a QSecBit score for an IP and apply appropriate reflex level.

        Args:
            ip: Source IP address
            qsecbit_score: Current QSecBit score (0.0–1.0, higher = more threat)

        Returns:
            ReflexDecision if level changed, None if no change.
        """
        with self._targets_lock:
            return self._evaluate_locked(ip, qsecbit_score)

    def _evaluate_locked(self, ip: str, qsecbit_score: float) -> Optional[ReflexDecision]:
        """Evaluate under lock (internal)."""
        # Compute velocity
        velocity = self._compute_velocity(ip, qsecbit_score)

        # Determine target level
        new_level = self.score_to_level(qsecbit_score, velocity)

        # Get current level (default OBSERVE)
        current_target = self._targets.get(ip)
        old_level = current_target.level if current_target else ReflexLevel.OBSERVE

        if new_level == old_level and current_target:
            # Same level — update score/velocity but no transition
            current_target.qsecbit_score = qsecbit_score
            current_target.score_velocity = velocity
            # Update jitter amount if in JITTER level (score may have changed)
            if new_level == ReflexLevel.JITTER:
                new_jitter = self.compute_jitter(qsecbit_score)
                if current_target.jitter_ms != new_jitter:
                    current_target.jitter_ms = new_jitter
                    self._apply_jitter(ip, new_jitter)
            return None

        # Level transition — create or update target
        reason = self._build_reason(old_level, new_level, qsecbit_score, velocity)
        decision = ReflexDecision(
            target_ip=ip,
            old_level=old_level,
            new_level=new_level,
            reason=reason,
            qsecbit_score=qsecbit_score,
            velocity=velocity,
        )
        self._decision_log.append(decision)

        # Apply the new level
        self._apply_level(ip, new_level, qsecbit_score, velocity)

        logger.info(
            "Reflex transition: %s %s→%s (Q=%.3f, dQ/dt=%.4f) — %s",
            ip, old_level.name, new_level.name, qsecbit_score, velocity, reason,
        )

        return decision

    def score_to_level(self, score: float, velocity: float = 0.0) -> ReflexLevel:
        """Map a QSecBit score + velocity to a reflex level.

        Base level from score thresholds, then velocity modifies by +/-1.
        """
        # Base level from score thresholds
        base_level = ReflexLevel.OBSERVE
        for level, (lower, upper) in LEVEL_THRESHOLDS.items():
            if lower <= score < upper:
                base_level = level
                break
        # Score == 1.0 edge case
        if score >= 1.0:
            base_level = ReflexLevel.DISCONNECT

        # Velocity adjustment: +/-1 level
        adjusted = base_level.value
        if velocity > self.VELOCITY_ESCALATE:
            adjusted = min(adjusted + 1, ReflexLevel.DISCONNECT.value)
        elif velocity < self.VELOCITY_DEESCALATE:
            adjusted = max(adjusted - 1, ReflexLevel.OBSERVE.value)

        return ReflexLevel(adjusted)

    def compute_jitter(self, score: float) -> int:
        """Compute jitter delay in ms for a given QSecBit score.

        Non-linear (quadratic) curve: 10ms at Q=0.30, 500ms at Q=0.60.
        """
        lower, upper = LEVEL_THRESHOLDS[ReflexLevel.JITTER]
        range_width = upper - lower
        if range_width <= 0:
            return self.JITTER_MIN_MS

        normalized = max(0.0, min(1.0, (score - lower) / range_width))
        # Quadratic curve for aggressive ramp-up
        base = int(self.JITTER_MIN_MS + (self.JITTER_MAX_MS - self.JITTER_MIN_MS) * (normalized ** 2))
        return max(self.JITTER_MIN_MS, min(self.JITTER_MAX_MS, base))

    def tick(self, scores: Optional[Dict[str, float]] = None) -> List[ReflexDecision]:
        """Periodic tick — re-evaluate all targets and run recovery checks.

        Args:
            scores: Optional dict of ip → qsecbit_score for batch evaluation

        Returns:
            List of ReflexDecisions from this tick.
        """
        decisions = []

        if scores:
            for ip, score in scores.items():
                decision = self.evaluate(ip, score)
                if decision:
                    decisions.append(decision)

        # Snapshot targets under lock for recovery iteration
        with self._targets_lock:
            snapshot = list(self._targets.items())
        for ip, target in snapshot:
            if target.level.value >= ReflexLevel.JITTER.value:
                if self._recovery.has_target(ip):
                    pass

        return decisions

    def update_recovery(self, ip: str, energy_z_score: float) -> Optional[ReflexDecision]:
        """Feed energy data into the Bayesian recovery engine.

        Args:
            ip: Target IP
            energy_z_score: Z-score from energy_monitor (0 = normal, >2 = anomalous)

        Returns:
            ReflexDecision if recovery triggered, None otherwise.
        """
        result = self._recovery.update(ip, energy_z_score)
        if result == "recover":
            with self._targets_lock:
                target = self._targets.get(ip)
                if target:
                    old_level = target.level
                    decision = ReflexDecision(
                        target_ip=ip,
                        old_level=old_level,
                        new_level=ReflexLevel.OBSERVE,
                        reason=f"Bayesian recovery: P(threat) < {self._recovery.RECOVERY_THRESHOLD}",
                        qsecbit_score=target.qsecbit_score,
                        velocity=target.score_velocity,
                    )
                    self._decision_log.append(decision)
                    self._apply_level(ip, ReflexLevel.OBSERVE, target.qsecbit_score, 0.0)
                    logger.info("Recovery: %s %s→OBSERVE (Bayesian self-heal)", ip, old_level.name)
                    return decision
        return None

    def remove_target(self, ip: str) -> bool:
        """Remove all reflex interference from an IP."""
        with self._targets_lock:
            return self._remove_target_locked(ip)

    def _remove_target_locked(self, ip: str) -> bool:
        """Remove target under lock (internal)."""
        target = self._targets.get(ip)
        if not target:
            return False

        self._clear_all_ebpf(ip, target)
        self._recovery.remove_target(ip)
        self._velocity_trackers.pop(ip, None)
        del self._targets[ip]
        logger.info("Reflex removed: %s", ip)
        return True

    def force_level(self, ip: str, level: ReflexLevel, reason: str = "") -> ReflexDecision:
        """Manually force a reflex level (tool_executor interface)."""
        with self._targets_lock:
            return self._force_level_locked(ip, level, reason)

    def _force_level_locked(self, ip: str, level: ReflexLevel, reason: str = "") -> ReflexDecision:
        """Force level under lock (internal)."""
        current = self._targets.get(ip)
        old_level = current.level if current else ReflexLevel.OBSERVE
        score = current.qsecbit_score if current else 0.0
        velocity = current.score_velocity if current else 0.0

        decision = ReflexDecision(
            target_ip=ip,
            old_level=old_level,
            new_level=level,
            reason=reason or f"Manual override to {level.name}",
            qsecbit_score=score,
            velocity=velocity,
        )
        self._decision_log.append(decision)
        self._apply_level(ip, level, score, velocity)
        return decision

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive status for reporting."""
        with self._targets_lock:
            return {
                "active_targets": {
                    ip: target.to_dict() for ip, target in self._targets.items()
                },
                "total_targets": len(self._targets),
                "ebpf_available": self._use_ebpf,
                "ebpf_loaded": self._bpf_loaded,
                "recent_decisions": [d.to_dict() for d in list(self._decision_log)[-20:]],
                "recovery_states": self._recovery.get_all_states(),
                "level_counts": {
                    level.name: sum(
                        1 for t in self._targets.values() if t.level == level
                    )
                    for level in ReflexLevel
                },
            }

    def get_target(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get state for a specific target IP."""
        with self._targets_lock:
            target = self._targets.get(ip)
            if not target:
                return None
            result = target.to_dict()
        recovery = self._recovery.get_state(ip)
        if recovery:
            result["recovery"] = recovery
        return result

    def get_all_targets(self) -> Dict[str, ReflexTarget]:
        """Get a snapshot of all targets (thread-safe)."""
        with self._targets_lock:
            return dict(self._targets)

    def hot_swap_program(
        self,
        program_id: str,
        program_type: str,
        attach_point: str,
        c_source: str,
        rollback_timeout_s: int = 300,
    ) -> bool:
        """Hot-swap an eBPF program generated by the Neuro-Kernel.

        In Phase 1, this logs the deployment and tracks the program.
        Full BPF_F_REPLACE atomic swap requires kernel 5.13+ and will
        be implemented when BCC provides the attach API.

        Args:
            program_id: Unique ID for this program.
            program_type: "xdp", "tc", "kprobe".
            attach_point: Interface or function name.
            c_source: C source code (for audit trail).
            rollback_timeout_s: Auto-rollback timeout.

        Returns:
            True if registered successfully.
        """
        if self._executor_mode == "log-only":
            logger.info(
                "Reflex log-only: would hot-swap %s (%s on %s)",
                program_id, program_type, attach_point,
            )
            return True

        # Phase 1: Log and track. Full BPF attach in Phase 3.
        logger.info(
            "Hot-swap registered: %s (%s on %s, rollback in %ds)",
            program_id, program_type, attach_point, rollback_timeout_s,
        )
        return True

    # ------------------------------------------------------------------
    # Internal: Level application
    # ------------------------------------------------------------------

    def _apply_level(
        self, ip: str, level: ReflexLevel, score: float, velocity: float
    ) -> None:
        """Apply a reflex level to a target IP.

        Handles transitions: clears old level's eBPF, applies new level's eBPF.
        """
        old_target = self._targets.get(ip)
        if old_target:
            self._clear_all_ebpf(ip, old_target)

        # Create/update target state
        target = ReflexTarget(
            source_ip=ip,
            level=level,
            qsecbit_score=score,
            score_velocity=velocity,
        )

        if level == ReflexLevel.OBSERVE:
            # Clean slate — no eBPF, remove from recovery
            self._targets.pop(ip, None)
            self._recovery.remove_target(ip)
            return

        if level == ReflexLevel.JITTER:
            target.jitter_ms = self.compute_jitter(score)
            self._apply_jitter(ip, target.jitter_ms)

        elif level == ReflexLevel.SHADOW:
            target.shadow_port = self._mirage_port
            self._apply_shadow(ip, self._mirage_port)

        elif level == ReflexLevel.DISCONNECT:
            self._apply_disconnect(ip, target.pid)

        self._targets[ip] = target

        # Register for recovery monitoring (JITTER+ levels)
        if not self._recovery.has_target(ip):
            self._recovery.register_target(ip, initial_prior=min(0.9, score))

    def _clear_all_ebpf(self, ip: str, target: ReflexTarget) -> None:
        """Remove all eBPF entries for a target."""
        if target.level == ReflexLevel.JITTER:
            self._remove_jitter(ip)
        elif target.level == ReflexLevel.SHADOW:
            self._remove_shadow(ip, target.shadow_port)
        elif target.level == ReflexLevel.DISCONNECT:
            self._remove_disconnect(ip)

    # ------------------------------------------------------------------
    # eBPF map operations (with iptables/tc fallback)
    # ------------------------------------------------------------------

    def _apply_jitter(self, ip: str, jitter_ms: int) -> None:
        """Add/update jitter map entry for an IP."""
        if self._use_ebpf:
            self._ensure_bpf_jitter()
            if self._bpf_jitter:
                try:
                    ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
                    jitter_ns = jitter_ms * 1_000_000  # ms → ns
                    jitter_map = self._bpf_jitter["jitter_targets"]
                    jitter_map[jitter_map.Key(ip_int)] = jitter_map.Leaf(jitter_ns)
                    return
                except Exception as e:
                    logger.warning("eBPF jitter failed for %s: %s (falling back)", ip, e)

        # Fallback: tc netem
        self._run_fallback_commands(
            get_fallback_jitter_commands(ip, jitter_ms, self._interface)
        )

    def _remove_jitter(self, ip: str) -> None:
        """Remove jitter map entry for an IP."""
        if self._use_ebpf and self._bpf_jitter:
            try:
                ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
                jitter_map = self._bpf_jitter["jitter_targets"]
                del jitter_map[jitter_map.Key(ip_int)]
                return
            except Exception:
                pass

        self._run_fallback_commands(
            get_fallback_jitter_remove_commands(ip, self._interface)
        )

    def _apply_shadow(self, ip: str, mirage_port: int) -> None:
        """Add sockmap redirect entry for an IP."""
        if self._use_ebpf:
            self._ensure_bpf_sockmap()
            if self._bpf_sockmap:
                try:
                    # Sockmap redirect requires socket fd — complex setup
                    # For now, use the BPF map; full sockmap wiring requires
                    # the Mirage honeypot to register its socket fd
                    ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
                    logger.info("Sockmap shadow registered for %s → port %d", ip, mirage_port)
                    # NOTE: sockmap wiring is incomplete (needs Mirage socket fd).
                    # Fall through to iptables REDIRECT until fully wired.
                except Exception as e:
                    logger.warning("eBPF sockmap failed for %s: %s (falling back)", ip, e)

        # Fallback: iptables REDIRECT
        self._run_fallback_commands(get_fallback_shadow_commands(ip, mirage_port))

    def _remove_shadow(self, ip: str, mirage_port: int) -> None:
        """Remove sockmap redirect for an IP."""
        if self._use_ebpf and self._bpf_sockmap:
            try:
                ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
                return
            except Exception:
                pass

        self._run_fallback_commands(
            get_fallback_shadow_remove_commands(ip, mirage_port)
        )

    def _apply_disconnect(self, ip: str, pid: Optional[int] = None) -> None:
        """Add surgical disconnect (XDP drop + optional PID kill)."""
        if self._use_ebpf:
            self._ensure_bpf_surgical()
            if self._bpf_surgical:
                try:
                    ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
                    kill_map = self._bpf_surgical["kill_targets"]
                    target_pid = pid or 0
                    kill_map[kill_map.Key(ip_int)] = kill_map.Leaf(target_pid)
                    return
                except Exception as e:
                    logger.warning("eBPF surgical failed for %s: %s (falling back)", ip, e)

        # Fallback: iptables DROP + conntrack flush
        self._run_fallback_commands(get_fallback_block_commands(ip))

    def _remove_disconnect(self, ip: str) -> None:
        """Remove surgical disconnect for an IP."""
        if self._use_ebpf and self._bpf_surgical:
            try:
                ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
                kill_map = self._bpf_surgical["kill_targets"]
                del kill_map[kill_map.Key(ip_int)]
                return
            except Exception:
                pass

        self._run_fallback_commands(get_fallback_block_remove_commands(ip))

    # ------------------------------------------------------------------
    # BPF program lifecycle
    # ------------------------------------------------------------------

    def _ensure_bpf_jitter(self) -> None:
        """Lazy-load the TC jitter BPF program."""
        if self._bpf_jitter is not None or not self._use_ebpf:
            return
        try:
            self._bpf_jitter = BPF(text=JITTER_TC_PROGRAM)
            self._bpf_loaded = True
            logger.info("BPF jitter TC program loaded")
        except Exception as e:
            logger.warning("Failed to load BPF jitter program: %s", e)
            self._bpf_jitter = None

    def _ensure_bpf_sockmap(self) -> None:
        """Lazy-load the sockmap redirect BPF program."""
        if self._bpf_sockmap is not None or not self._use_ebpf:
            return
        try:
            self._bpf_sockmap = BPF(text=SOCKMAP_REDIRECT_PROGRAM)
            self._bpf_loaded = True
            logger.info("BPF sockmap redirect program loaded")
        except Exception as e:
            logger.warning("Failed to load BPF sockmap program: %s", e)
            self._bpf_sockmap = None

    def _ensure_bpf_surgical(self) -> None:
        """Lazy-load the surgical disconnect BPF program."""
        if self._bpf_surgical is not None or not self._use_ebpf:
            return
        try:
            self._bpf_surgical = BPF(text=SURGICAL_DISCONNECT_PROGRAM)
            self._bpf_loaded = True
            logger.info("BPF surgical disconnect program loaded")
        except Exception as e:
            logger.warning("Failed to load BPF surgical program: %s", e)
            self._bpf_surgical = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_velocity(self, ip: str, score: float) -> float:
        """Compute score velocity (dQ/dt) for an IP."""
        if ip not in self._velocity_trackers:
            self._velocity_trackers[ip] = ScoreVelocity()
        return self._velocity_trackers[ip].update(score)

    def _build_reason(
        self, old: ReflexLevel, new: ReflexLevel, score: float, velocity: float
    ) -> str:
        """Build a human-readable reason for a level transition."""
        direction = "escalation" if new.value > old.value else "de-escalation"
        vel_note = ""
        if velocity > self.VELOCITY_ESCALATE:
            vel_note = f" (fast rise dQ/dt={velocity:.4f})"
        elif velocity < self.VELOCITY_DEESCALATE:
            vel_note = f" (rapid decay dQ/dt={velocity:.4f})"
        return f"Score {direction}: Q={score:.3f}{vel_note}"

    def _run_fallback_commands(self, commands: List[List[str]]) -> None:
        """Execute fallback commands (iptables/tc) in list form.

        Uses subprocess list-form (no shell=True) to prevent command injection.
        Input IPs are validated by _validate_ip() in ebpf_programs.py.
        In log-only mode, commands are logged but not executed.
        """
        for cmd in commands:
            if self._executor_mode == "log-only":
                logger.info("Reflex log-only: would run %s", cmd)
                continue
            try:
                subprocess.run(
                    cmd, capture_output=True, timeout=5,
                    check=False,
                )
            except Exception as e:
                logger.warning("Fallback command failed: %s — %s", cmd, e)

    def cleanup(self) -> None:
        """Remove all eBPF programs and target entries."""
        for ip in list(self._targets.keys()):
            self.remove_target(ip)
        self._bpf_jitter = None
        self._bpf_sockmap = None
        self._bpf_surgical = None
        self._bpf_loaded = False
        logger.info("ReflexEngine cleaned up")

    def __del__(self):
        """Cleanup on garbage collection."""
        try:
            self.cleanup()
        except Exception:
            pass
