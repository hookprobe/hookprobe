"""
AEGIS Reflex — Type Definitions

Data model for the Surgical Interference system. Defines reflex levels,
per-target state, score velocity tracking, and decision records.

Author: Andrei Toma
License: Proprietary - see LICENSE in this directory
Version: 2.0.0
"""

import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class ReflexLevel(Enum):
    """Graduated interference levels mapped to QSecBit score ranges.

    Each level represents increasing friction applied to suspicious traffic.
    The attacker experiences 'Degraded Reality' rather than a hard block.
    """
    OBSERVE = 0       # Q: 0.00–0.30 — XDP pass-through, baseline monitoring
    JITTER = 1        # Q: 0.30–0.60 — TC stochastic delay (10–500ms)
    SHADOW = 2        # Q: 0.60–0.85 — sockmap redirect to Mirage honeypot
    DISCONNECT = 3    # Q: 0.85–1.00 — bpf_send_signal(SIGKILL) + TCP_RST


# QSecBit score thresholds for each level (lower_bound, upper_bound)
LEVEL_THRESHOLDS = {
    ReflexLevel.OBSERVE:    (0.00, 0.30),
    ReflexLevel.JITTER:     (0.30, 0.60),
    ReflexLevel.SHADOW:     (0.60, 0.85),
    ReflexLevel.DISCONNECT: (0.85, 1.00),
}


@dataclass
class ReflexTarget:
    """Per-IP reflex state. Tracks what interference is currently applied."""

    source_ip: str
    level: ReflexLevel
    applied_at: float = field(default_factory=time.monotonic)
    qsecbit_score: float = 0.0
    score_velocity: float = 0.0       # dQ/dt (score units per second)

    # Level-specific state
    pid: Optional[int] = None         # Target PID for DISCONNECT level
    jitter_ms: int = 0                # Current jitter applied (JITTER level)
    shadow_port: int = 0              # Mirage redirect port (SHADOW level)

    # Bayesian recovery state
    recovery_prior: float = 0.5       # P(threat), updated by BayesianRecoveryEngine
    consecutive_normal: int = 0       # Consecutive normal energy readings

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for status reporting and memory logging."""
        return {
            "source_ip": self.source_ip,
            "level": self.level.name,
            "level_value": self.level.value,
            "applied_at": self.applied_at,
            "qsecbit_score": self.qsecbit_score,
            "score_velocity": self.score_velocity,
            "pid": self.pid,
            "jitter_ms": self.jitter_ms,
            "shadow_port": self.shadow_port,
            "recovery_prior": round(self.recovery_prior, 4),
            "consecutive_normal": self.consecutive_normal,
        }


@dataclass
class ScoreVelocity:
    """Tracks rate of change (dQ/dt) for a single IP's QSecBit score.

    Uses a sliding window of (timestamp, score) pairs to compute the
    first derivative. Positive velocity = worsening, negative = improving.
    """
    current: float = 0.0                # dQ/dt in score-units per second
    samples: deque = field(default_factory=lambda: deque(maxlen=50))
    window_seconds: float = 10.0        # Sliding window size

    def update(self, score: float) -> float:
        """Add a new score sample and recompute velocity."""
        now = time.monotonic()
        self.samples.append((now, score))

        # Need at least 2 samples to compute derivative
        if len(self.samples) < 2:
            self.current = 0.0
            return self.current

        # Trim samples outside window
        cutoff = now - self.window_seconds
        while self.samples and self.samples[0][0] < cutoff:
            self.samples.popleft()

        if len(self.samples) < 2:
            self.current = 0.0
            return self.current

        # Linear regression slope over the window
        t0, s0 = self.samples[0]
        t1, s1 = self.samples[-1]
        dt = t1 - t0
        if dt > 0:
            self.current = (s1 - s0) / dt
        else:
            self.current = 0.0

        return self.current


@dataclass
class ReflexDecision:
    """Record of a level transition decision. Logged for audit trail."""

    target_ip: str
    old_level: ReflexLevel
    new_level: ReflexLevel
    reason: str
    qsecbit_score: float
    velocity: float
    timestamp: float = field(default_factory=time.monotonic)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_ip": self.target_ip,
            "old_level": self.old_level.name,
            "new_level": self.new_level.name,
            "reason": self.reason,
            "qsecbit_score": round(self.qsecbit_score, 4),
            "velocity": round(self.velocity, 6),
            "timestamp": self.timestamp,
        }
