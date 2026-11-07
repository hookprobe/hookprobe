"""
AEGIS Reflex — Bayesian Recovery Engine

Self-healing loop: after throttling a target, monitors energy signature
to determine if the process has normalized. Uses Bayesian posterior
updates — if P(threat|energy) drops below threshold for consecutive
readings, the reflex level is removed and the score decays to GREEN.

The immune system inflames, then cools down.

Author: Andrei Toma
License: Proprietary - see LICENSE in this directory
Version: 2.0.0
"""

import logging
import math
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class RecoveryState:
    """Per-IP recovery tracking state."""
    source_ip: str
    prior: float = 0.5               # P(threat) — Bayesian prior
    consecutive_normal: int = 0       # Consecutive low-threat readings
    last_update: float = field(default_factory=time.monotonic)
    history: deque = field(default_factory=lambda: deque(maxlen=100))


class BayesianRecoveryEngine:
    """Bayesian self-healing for the Reflex system.

    After a target is jittered/shadowed/disconnected, this engine monitors
    the energy signature (per-PID power consumption from RAPL). A truly
    recovered process has normal energy — the Bayesian posterior converges
    toward P(normal).

    Recovery condition:
        P(threat|energy) < RECOVERY_THRESHOLD for CONSECUTIVE_NORMAL readings

    Energy likelihood model:
        L(normal|z)  = exp(-z^2 / 2)         — Gaussian, peaks at z=0
        L(threat|z)  = 1 - exp(-z^2 / 2)     — inverse, peaks at high z
    where z is the energy Z-score from energy_monitor.py
    """

    RECOVERY_THRESHOLD = 0.2     # P(threat) must drop below this
    CONSECUTIVE_NORMAL = 6       # 6 consecutive normal readings (~30s at 5s)
    DECAY_RATE = 0.85            # Prior decays toward 0.5 per observation
    MIN_PRIOR = 0.01             # Floor to prevent numerical zero
    MAX_PRIOR = 0.99             # Ceiling to prevent numerical one

    def __init__(self):
        self._targets: Dict[str, RecoveryState] = {}

    def register_target(self, ip: str, initial_prior: float = 0.5) -> None:
        """Register a new IP for recovery monitoring."""
        self._targets[ip] = RecoveryState(
            source_ip=ip,
            prior=max(self.MIN_PRIOR, min(self.MAX_PRIOR, initial_prior)),
        )
        logger.debug("Recovery registered: %s (prior=%.3f)", ip, initial_prior)

    def remove_target(self, ip: str) -> None:
        """Stop monitoring an IP."""
        self._targets.pop(ip, None)

    def has_target(self, ip: str) -> bool:
        return ip in self._targets

    def update(self, ip: str, energy_z_score: float) -> Optional[str]:
        """Perform Bayesian posterior update for a target IP.

        Args:
            ip: Target IP address
            energy_z_score: Z-score from energy_monitor (0 = normal, >2 = anomalous)

        Returns:
            "recover" if recovery condition met, None otherwise.
        """
        state = self._targets.get(ip)
        if not state:
            return None

        # Compute likelihoods
        l_threat = self._energy_likelihood_threat(energy_z_score)
        l_normal = self._energy_likelihood_normal(energy_z_score)

        # Bayesian update: P(threat|E) = P(threat) * L(threat|E) / evidence
        prior = state.prior
        evidence = prior * l_threat + (1 - prior) * l_normal

        if evidence > 0:
            posterior = (prior * l_threat) / evidence
        else:
            posterior = prior

        # Clamp to prevent numerical extremes
        posterior = max(self.MIN_PRIOR, min(self.MAX_PRIOR, posterior))
        state.prior = posterior
        state.last_update = time.monotonic()
        state.history.append({
            "timestamp": state.last_update,
            "z_score": round(energy_z_score, 4),
            "posterior": round(posterior, 4),
        })

        logger.debug(
            "Recovery update %s: z=%.2f L_t=%.3f L_n=%.3f prior=%.3f→posterior=%.3f",
            ip, energy_z_score, l_threat, l_normal, prior, posterior,
        )

        # Check recovery condition
        if posterior < self.RECOVERY_THRESHOLD:
            state.consecutive_normal += 1
            if state.consecutive_normal >= self.CONSECUTIVE_NORMAL:
                logger.info(
                    "Recovery triggered for %s: P(threat)=%.3f < %.3f for %d consecutive readings",
                    ip, posterior, self.RECOVERY_THRESHOLD, state.consecutive_normal,
                )
                return "recover"
        else:
            # Single anomalous reading resets the counter
            state.consecutive_normal = 0

        return None

    def get_state(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get recovery state for an IP."""
        state = self._targets.get(ip)
        if not state:
            return None
        return {
            "source_ip": state.source_ip,
            "prior": round(state.prior, 4),
            "consecutive_normal": state.consecutive_normal,
            "last_update": state.last_update,
            "readings": len(state.history),
        }

    def get_all_states(self) -> Dict[str, Dict[str, Any]]:
        """Get recovery state for all tracked IPs."""
        return {ip: self.get_state(ip) for ip in self._targets}

    @staticmethod
    def _energy_likelihood_normal(z_score: float) -> float:
        """Likelihood of observing this energy Z-score given normal behavior.

        Gaussian-like: peaks at z=0, decays for high z.
        L(normal|z) = exp(-z^2 / 2)
        """
        return math.exp(-(z_score ** 2) / 2.0)

    @staticmethod
    def _energy_likelihood_threat(z_score: float) -> float:
        """Likelihood of observing this energy Z-score given threat behavior.

        Inverse of normal: low at z=0, high at large z.
        L(threat|z) = 1 - exp(-z^2 / 2)
        """
        return 1.0 - math.exp(-(z_score ** 2) / 2.0)
