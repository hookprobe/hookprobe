-- HookProbe IDS ClickHouse Schema v3.2 — Neural-Kernel Extension
-- Adds: VectorSimilarity indexes, behavioral tokens, risk velocity, Flash-RAG support
--
-- Migration from v3.1 to v3.2:
--   1. Run this file against hookprobe_ids database
--   2. Rebuild predictor_engine container to pick up risk_velocity phase
--   3. Vector indexes are experimental — requires: SET allow_experimental_vector_similarity_index = 1

-- ============================================================================
-- P0: VECTOR SIMILARITY INDEXES (Flash-RAG Backend)
-- ============================================================================
-- Enables millisecond cosine-distance queries against historical feature vectors.
-- Without this, RAG lookback is a full-scan O(n) query. With it, it's O(log n).

-- Enable experimental vector similarity (required per-session or in users.xml)
-- SET allow_experimental_vector_similarity_index = 1;

-- Vector index on IP feature vectors (24-dim behavioral fingerprints)
-- Used by Flash-RAG: "Find 5 most similar historical attack patterns"
ALTER TABLE hookprobe_ids.hydra_ip_features
    ADD INDEX IF NOT EXISTS idx_feature_vec feature_vector
    TYPE vector_similarity('hnsw', 'cosineDistance') GRANULARITY 2;

-- NOTE: Vector index on attack pattern centroids REMOVED.
-- The HNSW index rejects empty arrays, but most patterns (temporal, intent,
-- campaign) don't have feature centroids. The empty DEFAULT [] caused every
-- INSERT to fail with: "arrays in column 'feature_centroid' must not be empty"
-- If vector search is needed on patterns, populate feature_centroid first.
-- ALTER TABLE hookprobe_ids.sentinel_attack_patterns
--     ADD INDEX IF NOT EXISTS idx_pattern_centroid feature_centroid
--     TYPE vector_similarity('hnsw', 'cosineDistance') GRANULARITY 2;

-- ============================================================================
-- P0: PER-IP RISK VELOCITY TIME SERIES
-- ============================================================================
-- Stores per-IP risk scores over time for ΔRisk/Δt computation.
-- The meta-regression engine reads from this to calculate β₁ (risk slope).
-- QSecBit is global — this table is per-entity temporal.

CREATE TABLE IF NOT EXISTS hookprobe_ids.ip_risk_scores (
    timestamp DateTime64(3) CODEC(Delta, ZSTD(1)),
    src_ip IPv4 CODEC(ZSTD(1)),
    -- Core risk metrics
    anomaly_score Float32 CODEC(Gorilla, ZSTD(1)),
    sentinel_score Float32 CODEC(Gorilla, ZSTD(1)),
    composite_risk Float32 CODEC(Gorilla, ZSTD(1)),
    -- Risk velocity (ΔRisk/Δt, computed by predictor)
    risk_velocity Float32 DEFAULT 0 CODEC(Gorilla, ZSTD(1)),
    -- OLS regression coefficients (last N windows)
    beta_0 Float32 DEFAULT 0 CODEC(Gorilla, ZSTD(1)),  -- intercept
    beta_1 Float32 DEFAULT 0 CODEC(Gorilla, ZSTD(1)),  -- L4 slope
    -- Behavioral token sequence (discrete codebook IDs)
    token_sequence Array(UInt16) DEFAULT [] CODEC(ZSTD(1)),
    -- Kill chain state (from HMM)
    kill_chain_state LowCardinality(String) DEFAULT 'idle' CODEC(ZSTD(1)),
    kill_chain_confidence Float32 DEFAULT 0 CODEC(Gorilla, ZSTD(1)),
    -- RAG trigger flag
    rag_triggered UInt8 DEFAULT 0 CODEC(ZSTD(1)),
    INDEX idx_src_ip src_ip TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_risk_velocity risk_velocity TYPE minmax GRANULARITY 4
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_ip)
TTL toDateTime(timestamp) + INTERVAL 30 DAY;

-- ============================================================================
-- P0: BEHAVIORAL TOKEN TABLE (Semantic Telemetry)
-- ============================================================================
-- Each row is a tokenized behavioral snapshot of an IP in a time window.
-- Tokens are discrete codebook entries, not raw features.
-- The LLM reads token sequences, not numbers.

CREATE TABLE IF NOT EXISTS hookprobe_ids.behavioral_tokens (
    timestamp DateTime64(3) CODEC(Delta, ZSTD(1)),
    src_ip IPv4 CODEC(ZSTD(1)),
    -- Discrete behavioral tokens (codebook IDs)
    flow_shape UInt8 DEFAULT 0 CODEC(ZSTD(1)),          -- 0-7: BULK, INTERACTIVE, SCAN, DRIP, BURST, TRICKLE, FLOOD, MIXED
    entropy_band UInt8 DEFAULT 0 CODEC(ZSTD(1)),         -- 0-3: LOW, MEDIUM, HIGH, RANDOM
    timing_pattern UInt8 DEFAULT 0 CODEC(ZSTD(1)),       -- 0-5: REGULAR, BURSTY, SLOW_LOW, JITTER, PERIODIC, CHAOTIC
    protocol_behavior UInt8 DEFAULT 0 CODEC(ZSTD(1)),    -- 0-5: HTTP_NORMAL, DNS_TUNNEL, TLS_DOWNGRADE, SSH_BRUTE, QUIC_FLOOD, MIXED
    reputation_class UInt8 DEFAULT 0 CODEC(ZSTD(1)),     -- 0-5: KNOWN_GOOD, NEUTRAL, SUSPICIOUS, TOR_EXIT, VPN_PROXY, KNOWN_BAD
    temporal_trend UInt8 DEFAULT 0 CODEC(ZSTD(1)),       -- 0-4: STABLE, ACCELERATING, DECELERATING, SPIKE, OSCILLATING
    -- Composite token (packed: flow<<14 | entropy<<12 | timing<<9 | proto<<6 | rep<<3 | trend)
    -- 17-bit layout stored as UInt32. Enables exact-match queries.
    composite_token UInt32 DEFAULT 0 CODEC(ZSTD(1)),
    -- Token embedding vector (for vector similarity search)
    token_embedding Array(Float32) DEFAULT [] CODEC(ZSTD(1)),
    -- Source feature vector that produced this token
    source_features Array(Float32) DEFAULT [] CODEC(ZSTD(1)),
    -- Human-readable token string (for LLM prompt context)
    token_narrative String DEFAULT '' CODEC(ZSTD(1)),
    INDEX idx_src_ip src_ip TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_composite composite_token TYPE set(0) GRANULARITY 4
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_ip)
TTL toDateTime(timestamp) + INTERVAL 30 DAY;

-- ============================================================================
-- P1: FLASH-RAG CONTEXT TABLE (LLM Prompt Cache)
-- ============================================================================
-- Stores pre-computed RAG contexts for LLM consumption.
-- When risk_velocity > threshold, the predictor queries ClickHouse for
-- similar historical patterns and caches the result here.
-- The LLM reads this table for "you are a Tier 3 SOC analyst" prompts.

CREATE TABLE IF NOT EXISTS hookprobe_ids.rag_contexts (
    timestamp DateTime64(3) CODEC(Delta, ZSTD(1)),
    src_ip IPv4 CODEC(ZSTD(1)),
    -- Trigger info
    trigger_type LowCardinality(String) CODEC(ZSTD(1)),  -- 'risk_velocity', 'kill_chain_advance', 'campaign_detected'
    risk_velocity Float32 DEFAULT 0 CODEC(Gorilla, ZSTD(1)),
    -- RAG results (top-5 similar historical patterns)
    similar_ips Array(String) DEFAULT [] CODEC(ZSTD(1)),
    similar_scores Array(Float32) DEFAULT [] CODEC(ZSTD(1)),
    similar_verdicts Array(String) DEFAULT [] CODEC(ZSTD(1)),
    similar_timestamps Array(DateTime64(3)) DEFAULT [],
    -- LLM prompt context (pre-formatted for injection)
    prompt_context String DEFAULT '' CODEC(ZSTD(3)),
    -- LLM response (if generated)
    llm_response String DEFAULT '' CODEC(ZSTD(3)),
    llm_action LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),  -- 'block_subnet', 'alert_only', 'investigate', 'ignore'
    -- Feedback loop: was LLM recommendation acted on?
    operator_action LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    INDEX idx_src_ip src_ip TYPE bloom_filter() GRANULARITY 4
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_ip)
TTL toDateTime(timestamp) + INTERVAL 90 DAY;

-- ============================================================================
-- MATERIALIZED VIEW: Real-time Risk Velocity Aggregation
-- ============================================================================
-- Auto-computes risk velocity from hydra_verdicts on INSERT.
-- No polling needed — ClickHouse computes it as data arrives.

CREATE MATERIALIZED VIEW IF NOT EXISTS hookprobe_ids.mv_risk_velocity
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(window)
ORDER BY (src_ip, window)
AS SELECT
    toStartOfFiveMinute(timestamp) AS window,
    src_ip,
    argMaxState(anomaly_score, timestamp) AS latest_score,
    argMinState(anomaly_score, timestamp) AS earliest_score,
    maxState(anomaly_score) AS max_score,
    minState(anomaly_score) AS min_score,
    countState() AS verdict_count
FROM hookprobe_ids.hydra_verdicts
GROUP BY src_ip, window;
