"""
Intent Decoder — Hidden Markov Model for Attack Phase Detection

Maps entity embeddings to 8 MITRE ATT&CK-aligned hidden states using
a Hidden Markov Model with Viterbi decoding:

    V_t,j = max_i(V_{t-1,i} · a_ij) · b_j(O_t)

Hidden States (MITRE Kill Chain):
    RECONNAISSANCE  → INITIAL_ACCESS → EXECUTION → PERSISTENCE
    → LATERAL_MOVEMENT → COLLECTION → EXFILTRATION → IMPACT

Transition matrix A is initialized from attack_chain_predictor's
18 patterns. Emission probabilities B are computed from graph
embeddings via learned observation models.

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import math
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class IntentPhase(IntEnum):
    """MITRE ATT&CK kill chain phases as HMM hidden states."""
    BENIGN = 0
    RECONNAISSANCE = 1
    INITIAL_ACCESS = 2
    EXECUTION = 3
    PERSISTENCE = 4
    LATERAL_MOVEMENT = 5
    COLLECTION = 6
    EXFILTRATION = 7
    IMPACT = 8

    @property
    def is_attack(self) -> bool:
        return self != IntentPhase.BENIGN

    @property
    def mitre_tactic(self) -> str:
        mapping = {
            0: "none",
            1: "TA0043",  # Reconnaissance
            2: "TA0001",  # Initial Access
            3: "TA0002",  # Execution
            4: "TA0003",  # Persistence
            5: "TA0008",  # Lateral Movement
            6: "TA0009",  # Collection
            7: "TA0010",  # Exfiltration
            8: "TA0040",  # Impact
        }
        return mapping.get(self.value, "unknown")


@dataclass
class IntentSequence:
    """Result of Viterbi decoding — most likely intent sequence."""
    entity_id: str
    phases: List[IntentPhase] = field(default_factory=list)
    confidences: List[float] = field(default_factory=list)
    current_phase: IntentPhase = IntentPhase.BENIGN
    current_confidence: float = 0.0

    @property
    def is_attacking(self) -> bool:
        return self.current_phase.is_attack and self.current_confidence > 0.5

    @property
    def attack_progress(self) -> float:
        """How far through the kill chain (0.0 = recon, 1.0 = impact)."""
        if not self.current_phase.is_attack:
            return 0.0
        return self.current_phase.value / IntentPhase.IMPACT.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "current_phase": self.current_phase.name,
            "current_confidence": self.current_confidence,
            "attack_progress": self.attack_progress,
            "is_attacking": self.is_attacking,
            "phase_history": [p.name for p in self.phases[-10:]],
            "confidence_history": self.confidences[-10:],
        }


# Number of hidden states
NUM_STATES = len(IntentPhase)

# Transition matrix A[i][j] = P(state_j | state_i)
# Initialized from attack chain predictor patterns
# Rows must sum to 1.0
DEFAULT_TRANSITION_MATRIX: List[List[float]] = [
    # BENIGN → mostly stays benign, small chance of recon
    [0.90, 0.08, 0.01, 0.005, 0.001, 0.001, 0.001, 0.001, 0.001],
    # RECON → initial access or stays recon
    [0.10, 0.50, 0.25, 0.05, 0.03, 0.03, 0.02, 0.01, 0.01],
    # INITIAL_ACCESS → execution or persistence
    [0.05, 0.05, 0.30, 0.30, 0.15, 0.05, 0.05, 0.03, 0.02],
    # EXECUTION → persistence or lateral
    [0.03, 0.02, 0.05, 0.30, 0.25, 0.20, 0.08, 0.05, 0.02],
    # PERSISTENCE → lateral or collection
    [0.02, 0.01, 0.02, 0.05, 0.30, 0.30, 0.15, 0.10, 0.05],
    # LATERAL_MOVEMENT → collection or more lateral
    [0.02, 0.01, 0.02, 0.05, 0.05, 0.30, 0.30, 0.15, 0.10],
    # COLLECTION → exfiltration
    [0.02, 0.01, 0.01, 0.02, 0.02, 0.02, 0.30, 0.40, 0.20],
    # EXFILTRATION → impact or done
    [0.10, 0.01, 0.01, 0.01, 0.01, 0.01, 0.05, 0.40, 0.40],
    # IMPACT → stays or returns to benign
    [0.20, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01, 0.04, 0.70],
]

# Initial state probabilities
DEFAULT_INITIAL_PROBS: List[float] = [
    0.85,   # BENIGN
    0.08,   # RECON
    0.02,   # INITIAL_ACCESS
    0.01,   # EXECUTION
    0.01,   # PERSISTENCE
    0.01,   # LATERAL_MOVEMENT
    0.01,   # COLLECTION
    0.005,  # EXFILTRATION
    0.005,  # IMPACT
]

# Emission feature thresholds — maps entity features to likely states
# Each state has a characteristic "signature" of feature values
# [port_entropy_threshold, connection_rate_threshold, alert_threshold, ...]
STATE_EMISSION_PROFILES: Dict[int, Dict[str, Tuple[float, float]]] = {
    # state_id: {feature_name: (mean, std)}
    0: {"port_entropy": (1.0, 0.5), "conn_rate": (0.01, 0.01), "alerts": (0.0, 0.1)},
    1: {"port_entropy": (4.0, 1.0), "conn_rate": (0.5, 0.3), "alerts": (0.0, 0.2)},
    2: {"port_entropy": (2.0, 1.0), "conn_rate": (0.1, 0.1), "alerts": (1.0, 0.5)},
    3: {"port_entropy": (1.5, 0.8), "conn_rate": (0.2, 0.2), "alerts": (2.0, 1.0)},
    4: {"port_entropy": (1.0, 0.5), "conn_rate": (0.05, 0.05), "alerts": (0.5, 0.5)},
    5: {"port_entropy": (3.0, 1.0), "conn_rate": (0.3, 0.2), "alerts": (1.5, 1.0)},
    6: {"port_entropy": (1.5, 0.8), "conn_rate": (0.1, 0.1), "alerts": (0.5, 0.5)},
    7: {"port_entropy": (1.0, 0.5), "conn_rate": (0.2, 0.2), "alerts": (1.0, 0.8)},
    8: {"port_entropy": (2.0, 1.5), "conn_rate": (1.0, 0.5), "alerts": (3.0, 1.0)},
}


def _log_gaussian(x: float, mean: float, std: float) -> float:
    """Log probability of x under Gaussian(mean, std)."""
    if std < 1e-12:
        std = 1e-12
    return -0.5 * math.log(2 * math.pi * std * std) - 0.5 * ((x - mean) / std) ** 2


class IntentDecoder:
    """
    HMM-based intent decoder with Viterbi decoding.

    Maintains per-entity Viterbi state and decodes the most likely
    sequence of attack phases from a stream of observations.
    """

    def __init__(
        self,
        transition_matrix: Optional[List[List[float]]] = None,
        initial_probs: Optional[List[float]] = None,
    ):
        self._A = transition_matrix or DEFAULT_TRANSITION_MATRIX
        self._pi = initial_probs or DEFAULT_INITIAL_PROBS
        self._num_states = NUM_STATES

        # Per-entity Viterbi state: entity_id -> (log_probs, sequence)
        self._entity_states: Dict[str, Dict[str, Any]] = {}

        self._stats = {
            "observations": 0,
            "decodes": 0,
            "attacks_detected": 0,
        }

        logger.info("IntentDecoder initialized (%d states)", self._num_states)

    # ------------------------------------------------------------------
    # Observation and Decoding
    # ------------------------------------------------------------------

    def observe(
        self,
        entity_id: str,
        features: Optional[List[float]] = None,
        embedding: Optional[List[float]] = None,
        deviation: float = 0.0,
    ) -> IntentSequence:
        """Process a new observation for an entity and return decoded intent.

        Args:
            entity_id: Entity identifier
            features: Raw feature vector from EntityNode.get_feature_vector()
            embedding: Entity embedding from GraphEmbedder
            deviation: Deviation from Golden Harmonic [0, 1]

        Returns:
            IntentSequence with current phase and confidence
        """
        self._stats["observations"] += 1

        # Compute emission probabilities for each state
        emissions = self._compute_emissions(features, deviation)

        # Viterbi step
        state = self._entity_states.get(entity_id)
        if state is None:
            # Initialize
            log_probs = []
            for s in range(self._num_states):
                lp = math.log(max(self._pi[s], 1e-30)) + emissions[s]
                log_probs.append(lp)
            self._entity_states[entity_id] = {
                "log_probs": log_probs,
                "phases": [self._best_state(log_probs)],
            }
        else:
            # Viterbi forward step
            prev_log_probs = state["log_probs"]
            new_log_probs = []
            for j in range(self._num_states):
                best_lp = float("-inf")
                for i in range(self._num_states):
                    lp = prev_log_probs[i] + math.log(max(self._A[i][j], 1e-30))
                    if lp > best_lp:
                        best_lp = lp
                new_log_probs.append(best_lp + emissions[j])
            state["log_probs"] = new_log_probs
            state["phases"].append(self._best_state(new_log_probs))

            # Cap history
            if len(state["phases"]) > 100:
                state["phases"] = state["phases"][-50:]

        return self.decode_intent(entity_id)

    def decode_intent(self, entity_id: str) -> IntentSequence:
        """Get the current decoded intent sequence for an entity."""
        self._stats["decodes"] += 1
        state = self._entity_states.get(entity_id)
        if state is None:
            return IntentSequence(entity_id=entity_id)

        phases = [IntentPhase(p) for p in state["phases"]]
        current = phases[-1] if phases else IntentPhase.BENIGN

        # Confidence from log probability margin
        log_probs = state["log_probs"]
        confidence = self._compute_confidence(log_probs, current.value)

        # Track if we detected an attack
        if current.is_attack and confidence > 0.5:
            self._stats["attacks_detected"] += 1

        seq = IntentSequence(
            entity_id=entity_id,
            phases=phases,
            confidences=[confidence],
            current_phase=current,
            current_confidence=confidence,
        )
        return seq

    def get_current_phase(self, entity_id: str) -> IntentPhase:
        """Get just the current phase for an entity."""
        state = self._entity_states.get(entity_id)
        if state is None or not state.get("phases"):
            return IntentPhase.BENIGN
        return IntentPhase(state["phases"][-1])

    def predict_next_phase(self, entity_id: str) -> Tuple[IntentPhase, float]:
        """Predict the most likely next phase."""
        current = self.get_current_phase(entity_id)
        row = self._A[current.value]
        best_state = max(range(self._num_states), key=lambda s: row[s])
        return IntentPhase(best_state), row[best_state]

    def reset_entity(self, entity_id: str) -> None:
        """Reset decoder state for an entity."""
        self._entity_states.pop(entity_id, None)

    # ------------------------------------------------------------------
    # Emission Probability Computation
    # ------------------------------------------------------------------

    def _compute_emissions(
        self,
        features: Optional[List[float]],
        deviation: float,
    ) -> List[float]:
        """Compute log emission probability for each state given observation."""
        emissions = []

        for s in range(self._num_states):
            profile = STATE_EMISSION_PROFILES.get(s, {})
            log_p = 0.0

            if features and len(features) >= 16:
                port_entropy = features[9]   # index from get_feature_vector()
                conn_rate = features[14]
                alerts = features[7]

                if "port_entropy" in profile:
                    mean, std = profile["port_entropy"]
                    log_p += _log_gaussian(port_entropy, mean, std)
                if "conn_rate" in profile:
                    mean, std = profile["conn_rate"]
                    log_p += _log_gaussian(conn_rate, mean, std)
                if "alerts" in profile:
                    mean, std = profile["alerts"]
                    log_p += _log_gaussian(alerts, mean, std)

            # Deviation bonus for attack states
            if s > 0 and deviation > 0:
                log_p += math.log(max(deviation, 1e-30)) * 2.0
            elif s == 0 and deviation < 0.3:
                log_p += math.log(max(1.0 - deviation, 1e-30))

            emissions.append(log_p)

        return emissions

    def _best_state(self, log_probs: List[float]) -> int:
        """Get the state with highest log probability."""
        return max(range(self._num_states), key=lambda s: log_probs[s])

    def _compute_confidence(self, log_probs: List[float], best_state: int) -> float:
        """Compute confidence as softmax probability of best state."""
        max_lp = max(log_probs)
        # Numerical stability
        exp_probs = [math.exp(min(lp - max_lp, 50)) for lp in log_probs]
        total = sum(exp_probs)
        if total < 1e-30:
            return 0.0
        return exp_probs[best_state] / total

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "tracked_entities": len(self._entity_states),
        }
