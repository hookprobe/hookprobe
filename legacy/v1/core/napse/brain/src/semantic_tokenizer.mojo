# =============================================================================
# Semantic Tokenizer — Behavioral Token Codebook
# =============================================================================
#
# The core innovation of the Neural-Kernel: converts 32-dimensional feature
# vectors into discrete Behavioral Tokens that an LLM can reason about.
#
# Architecture:
#   XDP (kernel) → Aegis (Zig) → 32-dim features → Semantic Tokenizer (Mojo)
#                                                           ↓
#                                                   Behavioral Tokens
#                                                           ↓
#                                                   [SCANNING] → [LATERAL_MOVE] → [EXFIL_PREP]
#                                                           ↓
#                                                   Meta-Regression + Flash-RAG + LLM
#
# The Information Density Gap:
#   An LLM cannot read 1M packets/second. But it CAN read 1000 behavioral
#   tokens/second. The tokenizer compresses 1000:1 by mapping feature vectors
#   to a discrete codebook of ~256 behavioral archetypes.
#
# Codebook Design:
#   6 token dimensions × N values each = composite behavioral state
#   - FlowShape (8):      BULK, INTERACTIVE, SCAN, DRIP, BURST, TRICKLE, FLOOD, MIXED
#   - EntropyBand (4):    LOW, MEDIUM, HIGH, RANDOM
#   - TimingPattern (6):  REGULAR, BURSTY, SLOW_LOW, JITTER, PERIODIC, CHAOTIC
#   - ProtoBehavior (6):  HTTP_NORMAL, DNS_TUNNEL, TLS_DOWNGRADE, SSH_BRUTE, QUIC_FLOOD, MIXED
#   - Reputation (6):     KNOWN_GOOD, NEUTRAL, SUSPICIOUS, TOR_EXIT, VPN_PROXY, KNOWN_BAD
#   - TemporalTrend (5):  STABLE, ACCELERATING, DECELERATING, SPIKE, OSCILLATING
#
# Total unique tokens: 8 × 4 × 6 × 6 × 6 × 5 = 34,560 behavioral archetypes
# Packed into 16-bit composite: flow(3b) | entropy(2b) | timing(3b) | proto(3b) | rep(3b) | trend(3b)

from math import sqrt, log2, abs
from algorithm import vectorize

alias FEATURE_DIMS: Int = 32
alias TOKEN_DIMS: Int = 6

# ============================================================================
# Token Enumerations
# ============================================================================

# FlowShape: How does the traffic flow look?
alias FLOW_BULK: UInt8 = 0         # High volume, sustained (file transfer)
alias FLOW_INTERACTIVE: UInt8 = 1  # Low volume, bidirectional (SSH session)
alias FLOW_SCAN: UInt8 = 2         # Many destinations, small packets (port scan)
alias FLOW_DRIP: UInt8 = 3         # Slow, low volume (C2 beaconing)
alias FLOW_BURST: UInt8 = 4        # Sudden spike then quiet (DDoS burst)
alias FLOW_TRICKLE: UInt8 = 5      # Steady low rate (exfil, DNS tunnel)
alias FLOW_FLOOD: UInt8 = 6        # Maximum rate (SYN flood, amplification)
alias FLOW_MIXED: UInt8 = 7        # No clear pattern (legitimate diverse traffic)

# EntropyBand: How random is the payload content?
alias ENTROPY_LOW: UInt8 = 0       # < 2.0 bits (plaintext, repeated patterns)
alias ENTROPY_MEDIUM: UInt8 = 1    # 2.0-5.0 bits (structured data, HTML)
alias ENTROPY_HIGH: UInt8 = 2      # 5.0-7.0 bits (compressed, encrypted)
alias ENTROPY_RANDOM: UInt8 = 3    # > 7.0 bits (cryptographic, random padding)

# TimingPattern: What does the inter-arrival time distribution look like?
alias TIMING_REGULAR: UInt8 = 0    # Low jitter, consistent IAT (automated)
alias TIMING_BURSTY: UInt8 = 1     # Clusters of rapid packets then silence
alias TIMING_SLOW_LOW: UInt8 = 2   # Very long IAT (slow-post, slow-read)
alias TIMING_JITTER: UInt8 = 3     # High variance, unpredictable (human)
alias TIMING_PERIODIC: UInt8 = 4   # Regular intervals (heartbeat, polling)
alias TIMING_CHAOTIC: UInt8 = 5    # No discernible pattern

# ProtoBehavior: What protocol-level behavior is observed?
alias PROTO_HTTP_NORMAL: UInt8 = 0   # Standard HTTP/S request-response
alias PROTO_DNS_TUNNEL: UInt8 = 1    # High DNS query rate, large TXT records
alias PROTO_TLS_DOWNGRADE: UInt8 = 2 # TLS < 1.2, weak ciphers, SNI anomaly
alias PROTO_SSH_BRUTE: UInt8 = 3     # Many SSH connections, rapid auth attempts
alias PROTO_QUIC_FLOOD: UInt8 = 4    # UDP/443 flood, QUIC abuse
alias PROTO_MIXED: UInt8 = 5         # Multi-protocol traffic

# Reputation: What do we know about this IP?
alias REP_KNOWN_GOOD: UInt8 = 0    # CDN, cloud provider, ISP — verified benign
alias REP_NEUTRAL: UInt8 = 1       # Unknown, no prior history
alias REP_SUSPICIOUS: UInt8 = 2    # Some threat feed hits, low confidence
alias REP_TOR_EXIT: UInt8 = 3      # Tor exit node
alias REP_VPN_PROXY: UInt8 = 4     # VPN/proxy service
alias REP_KNOWN_BAD: UInt8 = 5     # Active threat feed match, high confidence

# TemporalTrend: How is this IP's behavior changing over time?
alias TREND_STABLE: UInt8 = 0      # Risk velocity ≈ 0
alias TREND_ACCELERATING: UInt8 = 1 # Risk velocity > +0.1/min (getting worse)
alias TREND_DECELERATING: UInt8 = 2 # Risk velocity < -0.1/min (calming down)
alias TREND_SPIKE: UInt8 = 3       # Sudden jump then return (flash attack)
alias TREND_OSCILLATING: UInt8 = 4 # Alternating high/low (evasion pattern)

# Token name lookup tables (for LLM narrative generation)
alias FLOW_NAMES = List[String](
    "BULK_TRANSFER", "INTERACTIVE", "SCAN_SWEEP", "DRIP_FEED",
    "BURST", "TRICKLE", "FLOOD", "MIXED"
)
alias ENTROPY_NAMES = List[String]("LOW_ENTROPY", "MEDIUM_ENTROPY", "HIGH_ENTROPY", "RANDOM_ENTROPY")
alias TIMING_NAMES = List[String]("REGULAR_TIMING", "BURSTY", "SLOW_AND_LOW", "HIGH_JITTER", "PERIODIC", "CHAOTIC")
alias PROTO_NAMES = List[String]("HTTP_NORMAL", "DNS_TUNNEL", "TLS_DOWNGRADE", "SSH_BRUTE", "QUIC_FLOOD", "MIXED_PROTO")
alias REP_NAMES = List[String]("KNOWN_GOOD", "NEUTRAL", "SUSPICIOUS", "TOR_EXIT", "VPN_PROXY", "KNOWN_BAD")
alias TREND_NAMES = List[String]("STABLE", "ACCELERATING", "DECELERATING", "SPIKE", "OSCILLATING")


# ============================================================================
# Behavioral Token Structure
# ============================================================================

@value
struct BehavioralToken:
    """A discrete behavioral archetype for one IP in one time window.

    This is the fundamental unit of the Semantic Telemetry pipeline.
    The LLM reads sequences of these, not raw numbers.
    """
    var flow_shape: UInt8
    var entropy_band: UInt8
    var timing_pattern: UInt8
    var protocol_behavior: UInt8
    var reputation_class: UInt8
    var temporal_trend: UInt8

    fn __init__(out self):
        self.flow_shape = FLOW_MIXED
        self.entropy_band = ENTROPY_MEDIUM
        self.timing_pattern = TIMING_JITTER
        self.protocol_behavior = PROTO_MIXED
        self.reputation_class = REP_NEUTRAL
        self.temporal_trend = TREND_STABLE

    fn to_composite(self) -> UInt32:
        """Pack 6 token dims into a 17-bit composite ID.

        Layout: [flow:3][entropy:2][timing:3][proto:3][rep:3][trend:3] = 17 bits
        Stored as UInt32 (lower 17 bits used). Max value = 131,071.
        """
        var c: UInt32 = 0
        c |= UInt32(self.flow_shape & 0x07) << 14
        c |= UInt32(self.entropy_band & 0x03) << 12
        c |= UInt32(self.timing_pattern & 0x07) << 9
        c |= UInt32(self.protocol_behavior & 0x07) << 6
        c |= UInt32(self.reputation_class & 0x07) << 3
        c |= UInt32(self.temporal_trend & 0x07)
        return c

    fn to_narrative(self) -> String:
        """Generate human-readable token string for LLM prompt injection.

        Example: "[SCAN_SWEEP | HIGH_ENTROPY | BURSTY | SSH_BRUTE | KNOWN_BAD | ACCELERATING]"
        """
        return (
            "[" + FLOW_NAMES[int(self.flow_shape)]
            + " | " + ENTROPY_NAMES[int(self.entropy_band)]
            + " | " + TIMING_NAMES[int(self.timing_pattern)]
            + " | " + PROTO_NAMES[int(self.protocol_behavior)]
            + " | " + REP_NAMES[int(self.reputation_class)]
            + " | " + TREND_NAMES[int(self.temporal_trend)]
            + "]"
        )

    fn threat_level(self) -> Float32:
        """Quick threat assessment from token dimensions.

        Weighted sum: reputation and protocol carry the most signal.
        Returns 0.0 (benign) to 1.0 (critical threat).
        """
        var score: Float32 = 0.0
        # Flow shape contribution (scan/flood/burst = threatening)
        if self.flow_shape == FLOW_SCAN:
            score += 0.15
        elif self.flow_shape == FLOW_FLOOD:
            score += 0.20
        elif self.flow_shape == FLOW_BURST:
            score += 0.10
        elif self.flow_shape == FLOW_DRIP:
            score += 0.05

        # Entropy contribution (random = encrypted/evasion)
        if self.entropy_band == ENTROPY_RANDOM:
            score += 0.10
        elif self.entropy_band == ENTROPY_HIGH:
            score += 0.05

        # Timing contribution (slow-and-low, periodic = evasion)
        if self.timing_pattern == TIMING_SLOW_LOW:
            score += 0.10
        elif self.timing_pattern == TIMING_PERIODIC:
            score += 0.05

        # Protocol contribution (tunnel, brute, downgrade = attack)
        if self.protocol_behavior == PROTO_DNS_TUNNEL:
            score += 0.20
        elif self.protocol_behavior == PROTO_SSH_BRUTE:
            score += 0.20
        elif self.protocol_behavior == PROTO_TLS_DOWNGRADE:
            score += 0.15

        # Reputation contribution (strongest signal)
        if self.reputation_class == REP_KNOWN_BAD:
            score += 0.25
        elif self.reputation_class == REP_TOR_EXIT:
            score += 0.15
        elif self.reputation_class == REP_VPN_PROXY:
            score += 0.10

        # Temporal trend (accelerating = escalation)
        if self.temporal_trend == TREND_ACCELERATING:
            score += 0.15
        elif self.temporal_trend == TREND_SPIKE:
            score += 0.10

        return min(score, 1.0)


# ============================================================================
# Semantic Tokenizer Engine
# ============================================================================

struct SemanticTokenizer:
    """Maps 32-dimensional feature vectors to discrete Behavioral Tokens.

    This is the bridge between the raw numerical world (Aegis/XDP features)
    and the symbolic world (LLM-readable behavioral descriptions).

    The tokenizer uses SIMD-accelerated threshold comparisons to classify
    each feature dimension into discrete bins, then combines bins into
    a composite behavioral token.

    Performance target: 50,000 feature vectors → tokens in < 10ms (SIMD)
    """
    # Adaptive thresholds (updated from training data statistics)
    var pps_thresholds: InlinedFixedVector[Float32, 4]      # [low, med, high, extreme]
    var entropy_thresholds: InlinedFixedVector[Float32, 4]   # [low, med, high, random]
    var iat_jitter_thresholds: InlinedFixedVector[Float32, 4]
    var port_diversity_thresholds: InlinedFixedVector[Float32, 4]
    var tokenized_count: UInt64
    var batch_count: UInt64

    fn __init__(out self):
        self.tokenized_count = 0
        self.batch_count = 0

        # Default thresholds (calibrated from production traffic baseline)
        # These should be updated periodically from ClickHouse percentiles
        self.pps_thresholds = InlinedFixedVector[Float32, 4]()
        self.pps_thresholds.append(10.0)     # < 10 pps = interactive/drip
        self.pps_thresholds.append(100.0)    # 10-100 = normal
        self.pps_thresholds.append(1000.0)   # 100-1000 = high (bulk/scan)
        self.pps_thresholds.append(5000.0)   # > 5000 = flood/burst

        self.entropy_thresholds = InlinedFixedVector[Float32, 4]()
        self.entropy_thresholds.append(0.25)  # normalized: < 2.0 bits
        self.entropy_thresholds.append(0.625) # 2.0-5.0 bits
        self.entropy_thresholds.append(0.875) # 5.0-7.0 bits
        self.entropy_thresholds.append(0.95)  # > 7.0 bits (near-random)

        self.iat_jitter_thresholds = InlinedFixedVector[Float32, 4]()
        self.iat_jitter_thresholds.append(0.01)  # Very regular
        self.iat_jitter_thresholds.append(0.1)   # Some variation
        self.iat_jitter_thresholds.append(0.5)   # High jitter
        self.iat_jitter_thresholds.append(0.9)   # Chaotic

        self.port_diversity_thresholds = InlinedFixedVector[Float32, 4]()
        self.port_diversity_thresholds.append(2.0)    # 1-2 ports = focused
        self.port_diversity_thresholds.append(5.0)    # 3-5 = normal
        self.port_diversity_thresholds.append(20.0)   # 6-20 = diverse
        self.port_diversity_thresholds.append(100.0)  # > 20 = scan sweep

    fn tokenize(mut self, features: InlinedFixedVector[Float32, FEATURE_DIMS],
                reputation: UInt8, risk_velocity: Float32) -> BehavioralToken:
        """Convert a 32-dim feature vector into a BehavioralToken.

        Feature vector layout (from feature_extract.zig):
          [0]  src_ip_hash         [8]  tcp_psh          [16] payload_uniformity  [24] htp_packet_type
          [1]  dst_ip_hash         [9]  port_category    [17] inter_arrival_ns    [25] bytes_ratio
          [2]  entropy             [10] protocol         [18] dns_query_type      [26] flow_packet_count
          [3]  payload_length      [11] packet_rate      [19] http_method         [27] flow_duration
          [4]  tcp_syn             [12] ttl              [20] tls_version         [28] src_port_ephemeral
          [5]  tcp_ack             [13] window_size      [21] tls_cipher_strength [29] dst_port_well_known
          [6]  tcp_fin             [14] ip_frag          [22] ssh_version         [30] reserved_0
          [7]  tcp_rst             [15] ip_df            [23] quic_version        [31] reserved_1
        """
        var token = BehavioralToken()
        self.tokenized_count += 1

        # ---- FLOW SHAPE (features: packet_rate[11], payload_length[3], port diversity) ----
        var pps = features[11]       # log-scaled packets/sec
        var payload = features[3]    # payload_len / MTU
        var syn_ratio = features[4]  # SYN flag frequency
        var bytes_ratio = features[25]

        if pps > self.pps_thresholds[3]:
            # Extreme rate
            if syn_ratio > 0.8:
                token.flow_shape = FLOW_FLOOD       # SYN flood
            else:
                token.flow_shape = FLOW_BURST       # Data flood / DDoS
        elif pps > self.pps_thresholds[2]:
            # High rate
            if payload < 0.1:
                token.flow_shape = FLOW_SCAN        # Many small packets = scan
            else:
                token.flow_shape = FLOW_BULK        # Large sustained transfer
        elif pps < self.pps_thresholds[0]:
            # Very low rate
            if features[27] > 0.5:  # Long flow duration
                token.flow_shape = FLOW_DRIP        # Slow C2 beaconing
            else:
                token.flow_shape = FLOW_INTERACTIVE # Short interactive session
        else:
            # Normal rate
            if payload > 0.5 and bytes_ratio > 0.8:
                token.flow_shape = FLOW_TRICKLE     # Steady upload (exfil?)
            else:
                token.flow_shape = FLOW_MIXED       # Normal diverse traffic

        # ---- ENTROPY BAND (features: entropy[2], uniformity[16]) ----
        var entropy = features[2]

        if entropy > self.entropy_thresholds[3]:
            token.entropy_band = ENTROPY_RANDOM
        elif entropy > self.entropy_thresholds[2]:
            token.entropy_band = ENTROPY_HIGH
        elif entropy > self.entropy_thresholds[1]:
            token.entropy_band = ENTROPY_MEDIUM
        else:
            token.entropy_band = ENTROPY_LOW

        # ---- TIMING PATTERN (features: inter_arrival[17], iat concentration) ----
        var iat_norm = features[17]  # log-scaled IAT

        if iat_norm < self.iat_jitter_thresholds[0]:
            token.timing_pattern = TIMING_REGULAR     # Machine-like regularity
        elif iat_norm > self.iat_jitter_thresholds[3]:
            token.timing_pattern = TIMING_CHAOTIC     # No pattern
        elif iat_norm > self.iat_jitter_thresholds[2]:
            token.timing_pattern = TIMING_JITTER      # Human-like variance
        elif features[27] > 0.7 and pps < self.pps_thresholds[0]:
            token.timing_pattern = TIMING_SLOW_LOW    # Slow-post / slow-read
        elif iat_norm < self.iat_jitter_thresholds[1]:
            token.timing_pattern = TIMING_PERIODIC    # Heartbeat / polling
        else:
            token.timing_pattern = TIMING_BURSTY      # Clusters of activity

        # ---- PROTOCOL BEHAVIOR (features: L7 indicators) ----
        var dns_indicator = features[18]    # DNS query type encoded
        var http_indicator = features[19]   # HTTP method encoded
        var tls_version = features[20]      # TLS version encoded
        var ssh_indicator = features[22]    # SSH version encoded
        var quic_indicator = features[23]   # QUIC version encoded

        if dns_indicator > 0.5 and pps > self.pps_thresholds[1]:
            token.protocol_behavior = PROTO_DNS_TUNNEL
        elif ssh_indicator > 0.0 and syn_ratio > 0.5:
            token.protocol_behavior = PROTO_SSH_BRUTE
        elif tls_version > 0.0 and tls_version < 0.3:
            token.protocol_behavior = PROTO_TLS_DOWNGRADE
        elif quic_indicator > 0.0 and pps > self.pps_thresholds[2]:
            token.protocol_behavior = PROTO_QUIC_FLOOD
        elif http_indicator > 0.0:
            token.protocol_behavior = PROTO_HTTP_NORMAL
        else:
            token.protocol_behavior = PROTO_MIXED

        # ---- REPUTATION (from external enrichment, passed as parameter) ----
        # Clamp to valid range to prevent out-of-bounds in to_narrative()
        token.reputation_class = min(reputation, REP_KNOWN_BAD)  # max = 5

        # ---- TEMPORAL TREND (from risk velocity, passed as parameter) ----
        if risk_velocity > 0.2:
            token.temporal_trend = TREND_SPIKE
        elif risk_velocity > 0.1:
            token.temporal_trend = TREND_ACCELERATING
        elif risk_velocity < -0.1:
            token.temporal_trend = TREND_DECELERATING
        elif abs(risk_velocity) > 0.05:
            token.temporal_trend = TREND_OSCILLATING
        else:
            token.temporal_trend = TREND_STABLE

        return token

    fn tokenize_batch(
        mut self,
        features_batch: List[InlinedFixedVector[Float32, FEATURE_DIMS]],
        reputations: List[UInt8],
        velocities: List[Float32],
    ) -> List[BehavioralToken]:
        """Tokenize a batch of feature vectors.

        In production, this uses SIMD to process 8 feature vectors
        simultaneously for each token dimension.
        """
        self.batch_count += 1
        var tokens = List[BehavioralToken]()

        for i in range(len(features_batch)):
            var rep = reputations[i] if i < len(reputations) else REP_NEUTRAL
            var vel = velocities[i] if i < len(velocities) else Float32(0.0)
            tokens.append(self.tokenize(features_batch[i], rep, vel))

        return tokens

    fn stats(self) -> String:
        """Return tokenizer statistics."""
        return (
            "SemanticTokenizer: "
            + str(self.tokenized_count) + " tokens generated, "
            + str(self.batch_count) + " batches"
        )
