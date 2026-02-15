"""
Bayesian Scorer — Real-Time Belief Evolution for QSECBIT

Evolves QSECBIT score using Bayesian inference as SIA evidence arrives:

    P(Attack|E) = P(E|Attack) · P(Attack) / P(E)

Key behaviors:
- Prior from current QSECBIT score
- Likelihood from IntentDecoder confidence and phase
- Exponential decay for old evidence
- Threshold 0.92 triggers Virtual Sandbox

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .intent_decoder import IntentPhase

logger = logging.getLogger(__name__)

# Sandbox trigger threshold
SANDBOX_THRESHOLD = 0.92

# Evidence decay half-life in seconds (evidence loses half its weight)
EVIDENCE_DECAY_HALFLIFE = 300.0  # 5 minutes


@dataclass
class EvidenceRecord:
    """A single piece of Bayesian evidence."""
    timestamp: float
    likelihood_ratio: float  # P(E|Attack) / P(E|Benign)
    phase: IntentPhase = IntentPhase.BENIGN
    confidence: float = 0.0
    source: str = ""  # "sia", "mirage", "alert", etc.

    @property
    def age_seconds(self) -> float:
        return time.time() - self.timestamp

    @property
    def decayed_weight(self) -> float:
        """Weight after exponential decay."""
        decay = math.exp(-0.693 * self.age_seconds / EVIDENCE_DECAY_HALFLIFE)
        return decay


@dataclass
class EntityBelief:
    """Bayesian belief state for a single entity."""
    entity_id: str
    prior: float = 0.1               # P(Attack) prior
    posterior: float = 0.1            # P(Attack|Evidence)
    evidence: List[EvidenceRecord] = field(default_factory=list)
    last_updated: float = 0.0
    sandbox_triggered: bool = False
    peak_posterior: float = 0.0

    @property
    def risk_score(self) -> float:
        """Current risk score [0, 1]."""
        return self.posterior

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "prior": self.prior,
            "posterior": self.posterior,
            "risk_score": self.risk_score,
            "evidence_count": len(self.evidence),
            "sandbox_triggered": self.sandbox_triggered,
            "peak_posterior": self.peak_posterior,
        }


# Likelihood ratios for different phases
# P(evidence | attack) / P(evidence | benign)
PHASE_LIKELIHOOD_RATIOS: Dict[IntentPhase, float] = {
    IntentPhase.BENIGN: 0.1,
    IntentPhase.RECONNAISSANCE: 3.0,
    IntentPhase.INITIAL_ACCESS: 8.0,
    IntentPhase.EXECUTION: 15.0,
    IntentPhase.PERSISTENCE: 12.0,
    IntentPhase.LATERAL_MOVEMENT: 20.0,
    IntentPhase.COLLECTION: 10.0,
    IntentPhase.EXFILTRATION: 25.0,
    IntentPhase.IMPACT: 30.0,
}


class BayesianScorer:
    """
    Evolves per-entity risk scores using Bayesian inference.

    The scorer maintains a belief state for each entity and updates it
    as new evidence arrives from the IntentDecoder, Mirage, and alerts.
    When posterior probability exceeds the sandbox threshold (0.92),
    it triggers the Virtual Sandbox.
    """

    def __init__(
        self,
        default_prior: float = 0.1,
        sandbox_threshold: float = SANDBOX_THRESHOLD,
        max_evidence_per_entity: int = 100,
    ):
        self._default_prior = default_prior
        self._sandbox_threshold = sandbox_threshold
        self._max_evidence = max_evidence_per_entity

        self._beliefs: Dict[str, EntityBelief] = {}
        self._sandbox_callbacks: List[Callable] = []

        self._stats = {
            "updates": 0,
            "sandbox_triggers": 0,
            "entities_tracked": 0,
        }

        logger.info(
            "BayesianScorer initialized (prior=%.2f, threshold=%.2f)",
            default_prior, sandbox_threshold,
        )

    # ------------------------------------------------------------------
    # Belief Updates
    # ------------------------------------------------------------------

    def update_belief(
        self,
        entity_id: str,
        phase: IntentPhase,
        confidence: float,
        source: str = "sia",
        qsecbit_score: Optional[float] = None,
    ) -> float:
        """Update belief for an entity given new SIA evidence.

        Uses Bayes' rule:
            P(A|E) = P(E|A) * P(A) / [P(E|A)*P(A) + P(E|~A)*P(~A)]

        Args:
            entity_id: Entity identifier
            phase: Current IntentDecoder phase
            confidence: IntentDecoder confidence [0, 1]
            source: Evidence source identifier
            qsecbit_score: Current QSECBIT score (used to set prior)

        Returns:
            Updated posterior probability [0, 1]
        """
        self._stats["updates"] += 1

        belief = self._get_or_create_belief(entity_id)

        # Optionally update prior from QSECBIT
        if qsecbit_score is not None:
            belief.prior = max(0.01, min(0.99, qsecbit_score))

        # Compute likelihood ratio
        base_lr = PHASE_LIKELIHOOD_RATIOS.get(phase, 1.0)
        # Scale by confidence
        lr = 1.0 + (base_lr - 1.0) * confidence

        # Record evidence
        evidence = EvidenceRecord(
            timestamp=time.time(),
            likelihood_ratio=lr,
            phase=phase,
            confidence=confidence,
            source=source,
        )
        belief.evidence.append(evidence)

        # Cap evidence list
        if len(belief.evidence) > self._max_evidence:
            belief.evidence = belief.evidence[-self._max_evidence:]

        # Compute posterior from all evidence with decay
        belief.posterior = self._compute_posterior(belief)
        belief.last_updated = time.time()
        belief.peak_posterior = max(belief.peak_posterior, belief.posterior)

        # Check sandbox threshold
        if belief.posterior >= self._sandbox_threshold and not belief.sandbox_triggered:
            belief.sandbox_triggered = True
            self._stats["sandbox_triggers"] += 1
            logger.warning(
                "SIA SANDBOX TRIGGER: entity=%s posterior=%.4f phase=%s",
                entity_id, belief.posterior, phase.name,
            )
            self._fire_sandbox(entity_id, belief)

        return belief.posterior

    def _compute_posterior(self, belief: EntityBelief) -> float:
        """Compute posterior from all decayed evidence using Bayes' rule.

        Sequential Bayesian update:
            P_new = P_old * LR / (P_old * LR + (1-P_old))
        where LR is the decayed likelihood ratio.
        """
        posterior = belief.prior

        for ev in belief.evidence:
            weight = ev.decayed_weight
            if weight < 0.01:
                continue  # Skip negligible evidence

            # Weighted likelihood ratio
            lr = 1.0 + (ev.likelihood_ratio - 1.0) * weight

            # Bayesian update
            numerator = posterior * lr
            denominator = posterior * lr + (1.0 - posterior)
            if denominator > 1e-30:
                posterior = numerator / denominator

            # Clamp to avoid extremes
            posterior = max(0.001, min(0.999, posterior))

        return posterior

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_risk_score(self, entity_id: str) -> float:
        """Get current risk score for an entity."""
        belief = self._beliefs.get(entity_id)
        if belief is None:
            return self._default_prior
        return belief.posterior

    def should_sandbox(self, entity_id: str) -> bool:
        """Check if an entity should be sandboxed."""
        return self.get_risk_score(entity_id) >= self._sandbox_threshold

    def get_belief(self, entity_id: str) -> Optional[EntityBelief]:
        """Get full belief state for an entity."""
        return self._beliefs.get(entity_id)

    def get_high_risk_entities(self, threshold: float = 0.7) -> List[EntityBelief]:
        """Get all entities above a risk threshold."""
        return [
            b for b in self._beliefs.values()
            if b.posterior >= threshold
        ]

    def reset_entity(self, entity_id: str) -> None:
        """Reset belief state for an entity (e.g., after sandbox release)."""
        belief = self._beliefs.get(entity_id)
        if belief:
            belief.posterior = self._default_prior
            belief.evidence = []
            belief.sandbox_triggered = False

    # ------------------------------------------------------------------
    # Sandbox Callbacks
    # ------------------------------------------------------------------

    def on_sandbox_trigger(self, callback: Callable) -> None:
        """Register callback for sandbox trigger events."""
        self._sandbox_callbacks.append(callback)

    def _fire_sandbox(self, entity_id: str, belief: EntityBelief) -> None:
        """Fire sandbox trigger callbacks."""
        for cb in self._sandbox_callbacks:
            try:
                cb(entity_id, belief)
            except Exception as e:
                logger.error("Sandbox callback error: %s", e)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "entities_tracked": len(self._beliefs),
            "sandbox_threshold": self._sandbox_threshold,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _get_or_create_belief(self, entity_id: str) -> EntityBelief:
        if entity_id not in self._beliefs:
            self._beliefs[entity_id] = EntityBelief(
                entity_id=entity_id,
                prior=self._default_prior,
                posterior=self._default_prior,
                last_updated=time.time(),
            )
            self._stats["entities_tracked"] += 1
        return self._beliefs[entity_id]
