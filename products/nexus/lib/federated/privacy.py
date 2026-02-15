"""
Differential Privacy for Federated Learning

Provides Gaussian mechanism noise injection, gradient clipping,
and Renyi Differential Privacy (RDP) budget tracking to ensure
no single node's data can be extracted from shared model updates.
"""

import logging
import math
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PrivacyBudget:
    """Tracks cumulative privacy expenditure using Renyi DP accounting."""

    epsilon_target: float = 8.0
    delta: float = 1e-5
    _rdp_alphas: List[float] = field(default_factory=lambda: [
        1.5, 1.75, 2.0, 2.5, 3.0, 4.0, 5.0, 6.0, 8.0, 16.0, 32.0, 64.0,
    ])
    _rdp_epsilons: List[float] = field(default_factory=lambda: [0.0] * 12)
    rounds_spent: int = 0

    @property
    def remaining_epsilon(self) -> float:
        """Compute remaining epsilon from RDP accountant."""
        if not any(e > 0 for e in self._rdp_epsilons):
            return self.epsilon_target
        best_eps = float("inf")
        for alpha, rdp_eps in zip(self._rdp_alphas, self._rdp_epsilons):
            eps = rdp_eps + math.log(1.0 / self.delta) / (alpha - 1.0)
            best_eps = min(best_eps, eps)
        return max(0.0, self.epsilon_target - best_eps)

    @property
    def exhausted(self) -> bool:
        return self.remaining_epsilon <= 0.0

    def account_round(self, sigma: float, sensitivity: float, sample_rate: float):
        """Account for one round of Gaussian mechanism noise."""
        if sigma <= 0 or sensitivity <= 0:
            return
        ratio = sensitivity / sigma
        for i, alpha in enumerate(self._rdp_alphas):
            if sample_rate >= 1.0:
                rdp = alpha * (ratio ** 2) / 2.0
            else:
                exponent = (alpha - 1) * (ratio ** 2) / 2.0
                if alpha <= 1:
                    rdp = 0.0
                elif exponent > 500:
                    # Overflow guard: use simplified upper bound
                    rdp = exponent
                else:
                    try:
                        rdp = (
                            math.log(1 - sample_rate + sample_rate * math.exp(exponent))
                            / (alpha - 1)
                        )
                    except OverflowError:
                        rdp = exponent
            self._rdp_epsilons[i] += max(0.0, rdp)
        self.rounds_spent += 1

    def to_dict(self) -> dict:
        return {
            "epsilon_target": self.epsilon_target,
            "delta": self.delta,
            "remaining_epsilon": self.remaining_epsilon,
            "rounds_spent": self.rounds_spent,
            "exhausted": self.exhausted,
        }


class DifferentialPrivacy:
    """Gaussian mechanism for differential privacy in federated learning.

    Applies calibrated Gaussian noise to gradient updates and enforces
    per-sample gradient clipping to bound sensitivity.
    """

    def __init__(
        self,
        noise_multiplier: float = 1.0,
        max_grad_norm: float = 1.0,
        epsilon_target: float = 8.0,
        delta: float = 1e-5,
    ):
        self.noise_multiplier = noise_multiplier
        self.max_grad_norm = max_grad_norm
        self.budget = PrivacyBudget(epsilon_target=epsilon_target, delta=delta)
        self._rng = None

    def _get_rng(self):
        if self._rng is None:
            import random
            self._rng = random.Random()
        return self._rng

    def clip_gradients(self, gradients: List[float]) -> List[float]:
        """Clip gradient vector to max_grad_norm (L2 norm)."""
        norm = math.sqrt(sum(g * g for g in gradients)) if gradients else 0.0
        if norm <= self.max_grad_norm or norm == 0.0:
            return list(gradients)
        scale = self.max_grad_norm / norm
        return [g * scale for g in gradients]

    def add_noise(self, gradients: List[float], sample_rate: float = 1.0) -> List[float]:
        """Add calibrated Gaussian noise to clipped gradients.

        Args:
            gradients: Pre-clipped gradient vector.
            sample_rate: Fraction of dataset used (for tighter RDP accounting).

        Returns:
            Noised gradient vector.
        """
        if self.budget.exhausted:
            logger.warning("Privacy budget exhausted — returning zeros")
            return [0.0] * len(gradients)

        sigma = self.noise_multiplier * self.max_grad_norm
        rng = self._get_rng()

        noised = []
        for g in gradients:
            noise = rng.gauss(0.0, sigma)
            noised.append(g + noise)

        self.budget.account_round(
            sigma=sigma,
            sensitivity=self.max_grad_norm,
            sample_rate=sample_rate,
        )

        return noised

    def privatize_update(
        self,
        weight_delta: List[float],
        sample_rate: float = 1.0,
    ) -> Optional[List[float]]:
        """Full pipeline: clip + noise a weight update.

        Returns None if privacy budget is exhausted.
        """
        if self.budget.exhausted:
            logger.warning("Privacy budget exhausted — cannot privatize")
            return None

        clipped = self.clip_gradients(weight_delta)
        noised = self.add_noise(clipped, sample_rate=sample_rate)
        return noised

    def get_stats(self) -> dict:
        return {
            "noise_multiplier": self.noise_multiplier,
            "max_grad_norm": self.max_grad_norm,
            **self.budget.to_dict(),
        }
