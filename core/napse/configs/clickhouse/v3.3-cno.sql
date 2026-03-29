-- ============================================================================
-- ClickHouse Schema v3.3 — Cognitive Network Organism (CNO)
--
-- Phase 1 tables for the biological defense architecture.
-- Run on: hookprobe_ids database
--
-- Usage:
--   clickhouse-client --database hookprobe_ids < v3.3-cno.sql
--
-- Author: HookProbe Team
-- Version: 3.3
-- ============================================================================

-- ------------------------------------------------------------------
-- CNO Synaptic Log — Event routing audit trail
-- ------------------------------------------------------------------
-- Tracks every event routed through the Synaptic Controller (thalamus).
-- Used for debugging routing decisions and measuring processing latency.

CREATE TABLE IF NOT EXISTS hookprobe_ids.cno_synaptic_log
(
    timestamp       DateTime64(3)   DEFAULT now64(3),
    event_type      LowCardinality(String),        -- 'upward_route', 'downward_route', 'bpf_write'
    source_layer    LowCardinality(String),        -- 'brainstem', 'cerebellum', 'cerebrum'
    route           LowCardinality(String),        -- 'cognitive_defense', 'xdp_blocklist', etc.
    source_ip       String          DEFAULT '',
    details         String          DEFAULT '{}',  -- JSON payload

    INDEX idx_event_type event_type TYPE set(0) GRANULARITY 4,
    INDEX idx_source_ip  source_ip  TYPE bloom_filter() GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, event_type)
TTL toDateTime(timestamp) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;


-- ------------------------------------------------------------------
-- CNO Stress History — Organism stress state transitions
-- ------------------------------------------------------------------
-- Records every stress state transition with the signals that caused it.
-- Used for post-incident analysis and tuning thresholds.

CREATE TABLE IF NOT EXISTS hookprobe_ids.cno_stress_history
(
    timestamp       DateTime64(3)   DEFAULT now64(3),
    old_state       LowCardinality(String),        -- 'calm', 'alert', 'fight', 'recovery'
    new_state       LowCardinality(String),
    composite_score Float32         DEFAULT 0,
    signals         String          DEFAULT '{}',  -- JSON: {xdp_drop_rate, incidents, velocity, cpu, anomaly}

    INDEX idx_new_state new_state TYPE set(0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp)
TTL toDateTime(timestamp) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;


-- ------------------------------------------------------------------
-- CNO Emotion Log — Network emotional state (Phase 2 placeholder)
-- ------------------------------------------------------------------
-- Tracks the emotion engine's state transitions and camouflage actions.

CREATE TABLE IF NOT EXISTS hookprobe_ids.cno_emotion_log
(
    timestamp       DateTime64(3)   DEFAULT now64(3),
    old_emotion     LowCardinality(String),        -- 'serene', 'vigilant', 'anxious', 'fearful', 'angry'
    new_emotion     LowCardinality(String),
    valence         Float32         DEFAULT 0,      -- -1.0 (negative) to 1.0 (positive)
    arousal         Float32         DEFAULT 0,      -- 0.0 (calm) to 1.0 (activated)
    trigger_event   String          DEFAULT '',     -- What caused the transition
    camouflage_actions String       DEFAULT '[]',   -- JSON array of actions taken

    INDEX idx_emotion new_emotion TYPE set(0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp)
TTL toDateTime(timestamp) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;


-- ------------------------------------------------------------------
-- CNO Consensus Log — Multi-RAG consensus verdicts (Phase 2 placeholder)
-- ------------------------------------------------------------------
-- Records Multi-RAG consensus decisions with per-silo scores.

CREATE TABLE IF NOT EXISTS hookprobe_ids.cno_consensus_log
(
    timestamp           DateTime64(3)   DEFAULT now64(3),
    src_ip              String,

    -- Per-silo scores (0.0 - 1.0)
    silo_global_score   Float32         DEFAULT 0,      -- Global Threat Intel
    silo_local_score    Float32         DEFAULT 0,      -- Local Baseline History
    silo_psych_score    Float32         DEFAULT 0,      -- Attacker Psychology

    -- Weighted consensus
    consensus_score     Float32         DEFAULT 0,      -- Weighted average
    consensus_verdict   LowCardinality(String),         -- 'benign', 'suspicious', 'malicious'
    consensus_action    LowCardinality(String),         -- 'monitor', 'investigate', 'block', 'throttle'
    confidence          Float32         DEFAULT 0,

    -- Context
    behavioral_token    String          DEFAULT '',     -- Human-readable token narrative
    kill_chain_stage    LowCardinality(String) DEFAULT 'idle',
    rag_context         String          DEFAULT '{}',   -- Condensed RAG context used

    INDEX idx_src_ip    src_ip  TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_verdict   consensus_verdict TYPE set(0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_ip)
TTL toDateTime(timestamp) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;


-- ------------------------------------------------------------------
-- Materialized View: CNO Stress Aggregation (5-min windows)
-- ------------------------------------------------------------------
-- Provides fast dashboard queries for stress history visualization.

CREATE MATERIALIZED VIEW IF NOT EXISTS hookprobe_ids.mv_cno_stress_5m
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (window)
TTL toDateTime(window) + INTERVAL 30 DAY
AS SELECT
    toStartOfFiveMinutes(timestamp) AS window,
    argMaxState(new_state, timestamp) AS latest_state,
    avgState(composite_score) AS avg_score,
    countState() AS transitions
FROM hookprobe_ids.cno_stress_history
GROUP BY window;
