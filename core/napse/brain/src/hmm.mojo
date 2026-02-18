# =============================================================================
# Hidden Markov Model for Intent State Tracking
# =============================================================================
#
# Tracks the temporal evolution of threat intent per network flow.
# Maps to the Cyber Kill Chain stages:
#   0: idle
#   1: reconnaissance
#   2: weaponization
#   3: delivery
#   4: exploitation
#   5: installation
#   6: command_control
#   7: action_on_objectives
#
# The HMM models the progression of an attack as a sequence of hidden states.
# Observation emissions are the intent classifications from the Bayesian engine.
# Transition probabilities capture the expected attack progression patterns.

from math import log, exp


alias NUM_STATES: Int = 8
alias NUM_OBSERVATIONS: Int = 8  # Same as NUM_CLASSES from intent_engine


@value
struct HMMState:
    """Metadata for a single HMM hidden state."""
    var name: String
    var index: Int
    var is_terminal: Bool

    fn __init__(out self, name: String, index: Int, terminal: Bool = False):
        self.name = name
        self.index = index
        self.is_terminal = terminal


fn get_kill_chain_states() -> List[HMMState]:
    """Return the Cyber Kill Chain states."""
    var states = List[HMMState]()
    states.append(HMMState("idle", 0))
    states.append(HMMState("reconnaissance", 1))
    states.append(HMMState("weaponization", 2))
    states.append(HMMState("delivery", 3))
    states.append(HMMState("exploitation", 4))
    states.append(HMMState("installation", 5))
    states.append(HMMState("command_control", 6))
    states.append(HMMState("action_on_objectives", 7, True))
    return states


struct FlowHMM:
    """Per-flow Hidden Markov Model tracker.

    Each tracked network flow (identified by community_id or 5-tuple)
    has its own HMM instance that evolves as new packets are observed.

    The Viterbi algorithm finds the most likely state sequence given
    observations, allowing Napse to predict the NEXT stage of an attack
    before it happens.
    """
    var current_state: Int
    var state_probabilities: InlinedFixedVector[Float32, NUM_STATES]
    var observation_count: UInt64
    var last_update_ns: UInt64

    # Transition matrix: A[i][j] = P(state_j | state_i)
    # Initialized with kill-chain-aware priors
    var transition_log_probs: InlinedFixedVector[Float32, 64]  # NUM_STATES * NUM_STATES

    # Emission matrix: B[i][j] = P(observation_j | state_i)
    var emission_log_probs: InlinedFixedVector[Float32, 64]  # NUM_STATES * NUM_OBSERVATIONS

    fn __init__(out self):
        self.current_state = 0  # Start in idle
        self.observation_count = 0
        self.last_update_ns = 0

        # Initialize state probabilities (start in idle with certainty)
        self.state_probabilities = InlinedFixedVector[Float32, NUM_STATES]()
        self.state_probabilities.append(1.0)  # idle
        for i in range(1, NUM_STATES):
            self.state_probabilities.append(0.0)

        # Initialize transition matrix with kill-chain priors
        # Key insight: attacks tend to progress forward through the kill chain
        self.transition_log_probs = InlinedFixedVector[Float32, 64]()
        for i in range(NUM_STATES):
            for j in range(NUM_STATES):
                var prob: Float32
                if i == j:
                    prob = 0.7  # High self-transition (most packets don't change state)
                elif j == i + 1:
                    prob = 0.2  # Forward progression
                elif j == 0:
                    prob = 0.05  # Return to idle (attack stopped)
                else:
                    prob = 0.05 / Float32(NUM_STATES - 3)  # Small prob for skip/back
                self.transition_log_probs.append(log(max(prob, 1e-10)))

        # Initialize emission matrix
        # Maps: which intent class is most likely in each kill chain stage
        self.emission_log_probs = InlinedFixedVector[Float32, 64]()
        for i in range(NUM_STATES):
            for j in range(NUM_OBSERVATIONS):
                var prob: Float32
                # Map kill chain stages to intent classes
                if i == 0 and j == 0:
                    prob = 0.9  # idle -> benign
                elif i == 1 and j == 1:
                    prob = 0.7  # reconnaissance -> scan
                elif i == 2 and j == 6:
                    prob = 0.6  # weaponization -> malware
                elif i == 3 and j == 6:
                    prob = 0.5  # delivery -> malware
                elif i == 4 and j == 2:
                    prob = 0.5  # exploitation -> bruteforce
                elif i == 5 and j == 6:
                    prob = 0.6  # installation -> malware
                elif i == 6 and j == 3:
                    prob = 0.8  # command_control -> c2_beacon
                elif i == 7 and j == 4:
                    prob = 0.7  # action_on_objectives -> exfiltration
                else:
                    prob = 0.1 / Float32(NUM_OBSERVATIONS - 1)
                self.emission_log_probs.append(log(max(prob, 1e-10)))

    fn observe(mut self, intent_class: Int, timestamp_ns: UInt64):
        """Update HMM state given a new intent classification observation.

        Uses forward algorithm to update state probabilities:
          P(s_t | o_1:t) ∝ P(o_t | s_t) * Σ_s_{t-1} P(s_t | s_{t-1}) * P(s_{t-1} | o_1:{t-1})
        """
        if intent_class < 0 or intent_class >= NUM_OBSERVATIONS:
            return

        var new_probs = InlinedFixedVector[Float32, NUM_STATES]()

        for j in range(NUM_STATES):
            # Sum over all previous states
            var log_sum: Float32 = -1e10
            for i in range(NUM_STATES):
                var log_trans = self.transition_log_probs[i * NUM_STATES + j]
                var log_prev = log(max(self.state_probabilities[i], 1e-10))
                var log_term = log_trans + log_prev
                # Log-sum-exp for numerical stability
                if log_term > log_sum:
                    log_sum = log_term

            # Multiply by emission probability
            var log_emit = self.emission_log_probs[j * NUM_OBSERVATIONS + intent_class]
            new_probs.append(exp(log_sum + log_emit))

        # Normalize
        var total: Float32 = 0.0
        for j in range(NUM_STATES):
            total += new_probs[j]

        if total > 0:
            for j in range(NUM_STATES):
                self.state_probabilities[j] = new_probs[j] / total

        # Update most likely state
        var max_prob: Float32 = 0.0
        for j in range(NUM_STATES):
            if self.state_probabilities[j] > max_prob:
                max_prob = self.state_probabilities[j]
                self.current_state = j

        self.observation_count += 1
        self.last_update_ns = timestamp_ns

    fn get_state_name(self) -> String:
        """Return human-readable name of the current most likely state."""
        var states = get_kill_chain_states()
        if self.current_state < len(states):
            return states[self.current_state].name
        return "unknown"

    fn predict_next_state(self) -> Tuple[Int, Float32]:
        """Predict the most likely next state and its probability.

        This is the key predictive capability: Napse can warn
        "This flow is likely to enter command_control stage next"
        BEFORE it actually happens.
        """
        var best_next: Int = 0
        var best_prob: Float32 = 0.0

        for j in range(NUM_STATES):
            var prob: Float32 = 0.0
            for i in range(NUM_STATES):
                var trans_prob = exp(self.transition_log_probs[i * NUM_STATES + j])
                prob += self.state_probabilities[i] * trans_prob
            if prob > best_prob:
                best_prob = prob
                best_next = j

        return (best_next, best_prob)

    fn is_progressing(self) -> Bool:
        """Check if the flow shows kill chain progression (state > idle)."""
        return self.current_state > 0

    fn threat_score(self) -> Float32:
        """Calculate a 0.0-1.0 threat score based on HMM state progression.

        Higher states in the kill chain = higher threat score.
        Weighted by probability of being in that state.
        """
        var score: Float32 = 0.0
        for i in range(NUM_STATES):
            # Weight each state by its position in the kill chain
            var stage_weight = Float32(i) / Float32(NUM_STATES - 1)
            score += self.state_probabilities[i] * stage_weight
        return score


fn max(a: Float32, b: Float32) -> Float32:
    if a > b:
        return a
    return b
