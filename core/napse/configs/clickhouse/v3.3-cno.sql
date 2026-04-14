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


-- ------------------------------------------------------------------
-- CNO Peer Reputation — Phase 18 Mesh Trust Scoring
-- ------------------------------------------------------------------
-- Tracks per-peer trust scores, accuracy rates, and consistency.
-- Inserted every sync cycle (5 min) for trend analysis.
-- Used by the Mesh Reputation System for BFT voting decisions.

CREATE TABLE IF NOT EXISTS hookprobe_ids.cno_peer_reputation
(
    timestamp               DateTime64(3)   DEFAULT now64(3),
    peer_id                 String,                            -- UUID of mesh peer
    trust_score             Float32         DEFAULT 0.5,       -- 0.0-1.0 (0.5 = neutral)
    filters_received        UInt32          DEFAULT 0,         -- Total filters from this peer
    accuracy_rate           Float32         DEFAULT 0.5,       -- hits / (hits + misses)
    consistency_failures    UInt32          DEFAULT 0,         -- Times density didn't match declared count
    silence_seconds         Int32           DEFAULT -1,        -- Seconds since last contact (-1 = never)

    INDEX idx_peer_id peer_id TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_trust   trust_score TYPE minmax GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, peer_id)
TTL toDateTime(timestamp) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;


-- ------------------------------------------------------------------
-- Materialized View: Peer Trust Trends (hourly)
-- ------------------------------------------------------------------
-- Pre-aggregates peer trust for dashboard trend graphs.

CREATE MATERIALIZED VIEW IF NOT EXISTS hookprobe_ids.mv_peer_trust_hourly
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(window)
ORDER BY (window, peer_id)
TTL toDateTime(window) + INTERVAL 30 DAY
AS SELECT
    toStartOfHour(timestamp) AS window,
    peer_id,
    avgState(trust_score) AS avg_trust,
    avgState(accuracy_rate) AS avg_accuracy,
    maxState(filters_received) AS total_filters,
    maxState(consistency_failures) AS total_consistency_fails
FROM hookprobe_ids.cno_peer_reputation
GROUP BY window, peer_id;


-- ------------------------------------------------------------------
-- CNO Zero-Day Candidates — Phase 19 Novelty Detection
-- ------------------------------------------------------------------
-- Records patterns that don't match any known attack signature.
-- Includes LLM-generated hypotheses for XAI audit trail.

CREATE TABLE IF NOT EXISTS hookprobe_ids.cno_zero_day_candidates
(
    timestamp           DateTime64(3)   DEFAULT now64(3),
    source_ip           String,
    event_type          LowCardinality(String),     -- 'network', 'syscall', 'file', 'dns'
    novelty_score       Float32         DEFAULT 0,  -- 0.0-1.0 (higher = more novel)
    max_similarity      Float32         DEFAULT 0,  -- Nearest neighbor similarity
    summary             String          DEFAULT '',  -- Natural language event summary
    hypothesis          String          DEFAULT '',  -- LLM-generated hypothesis

    INDEX idx_src_ip    source_ip TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_novelty   novelty_score TYPE minmax GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, source_ip)
TTL toDateTime(timestamp) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;


-- ------------------------------------------------------------------
-- CNO Workspace State — Phase 24 Global Workspace Audit
-- ------------------------------------------------------------------
-- Every 30s snapshot of the organism's "conscious" state: focus_ip,
-- emotion, stress, novel_flag, working_hypothesis, active MITRE tactics.

CREATE TABLE IF NOT EXISTS hookprobe_ids.cno_workspace_state
(
    timestamp             DateTime64(3) DEFAULT now64(3),
    focus_ip              String,
    focus_score           Float32,
    current_emotion       LowCardinality(String),
    current_stress        LowCardinality(String),
    emotion_valence       Float32,
    emotion_arousal       Float32,
    novel_pattern_flag    UInt8,
    working_hypothesis    String,
    recent_tactics        Array(String),

    INDEX idx_focus_ip focus_ip TYPE bloom_filter() GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY timestamp
TTL toDateTime(timestamp) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;


-- ------------------------------------------------------------------
-- CNO Weight History — Phase 23 Predictive Coder Drift Audit
-- ------------------------------------------------------------------
-- Every 5 min the predictive coder persists current silo weights.
-- Drift magnitude = sum(|current - initial|) across all silos.
-- Enables dashboards showing how weights evolve per-deployment.

CREATE TABLE IF NOT EXISTS hookprobe_ids.cno_weight_history
(
    timestamp            DateTime64(3) DEFAULT now64(3),
    weight_global        Float32,
    weight_local         Float32,
    weight_psychology    Float32,
    drift_magnitude      Float32 DEFAULT 0,
    updates_applied      UInt32 DEFAULT 0,

    INDEX idx_drift drift_magnitude TYPE minmax GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY timestamp
TTL toDateTime(timestamp) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;


-- ------------------------------------------------------------------
-- CNO Episodic Memory — Phase 22 Narrative Episodes (Hippocampus)
-- ------------------------------------------------------------------
-- One row per Multi-RAG verdict. Opened at verdict time, closed 10min
-- later when outcome is determined (block_success / block_ineffective /
-- false_positive / true_negative). Phase 23 predictive coder consumes
-- closed episodes to drift silo weights. Phase 25 sleep replays high-
-- prediction-error episodes for learning.

CREATE TABLE IF NOT EXISTS hookprobe_ids.cno_episodic_memory
(
    episode_id                   String,
    onset_ts                     DateTime64(3) DEFAULT now64(3),
    resolution_ts                Nullable(DateTime64(3)),
    src_ip                       String,
    event_type                   LowCardinality(String) DEFAULT '',
    initial_verdict              LowCardinality(String),
    initial_confidence           Float32 DEFAULT 0,
    initial_consensus_score      Float32 DEFAULT 0.5,
    initial_silo_scores_json     String DEFAULT '{}',
    initial_action               LowCardinality(String),
    meta_route                   LowCardinality(String) DEFAULT 'STANDARD',
    ttp_sequence                 Array(String),
    consensus_trace              String DEFAULT '',
    final_outcome                LowCardinality(String) DEFAULT 'pending',
    prediction_error             Float32 DEFAULT 0,
    actual_outcome_score         Float32 DEFAULT 0,
    packet_rate_delta_pct        Float32 DEFAULT 0,
    replay_count                 UInt16 DEFAULT 0,
    lessons_learned              String DEFAULT '',

    INDEX idx_episode_id episode_id TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_src_ip     src_ip TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_outcome    final_outcome TYPE set(8) GRANULARITY 4,
    INDEX idx_pred_err   prediction_error TYPE minmax GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(onset_ts)
ORDER BY (onset_ts, src_ip)
TTL toDateTime(onset_ts) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;


-- ------------------------------------------------------------------
-- CNO Generated Programs — Phase 20 Self-Evolving XDP
-- ------------------------------------------------------------------
-- Records LLM-generated eBPF programs deployed by the Kernel Orchestrator.
-- Includes the generated C source, compilation status, and deployment outcome.

CREATE TABLE IF NOT EXISTS hookprobe_ids.cno_generated_programs
(
    timestamp           DateTime64(3)   DEFAULT now64(3),
    program_id          String,
    signal_source       String          DEFAULT '',     -- What triggered generation
    signal_event        String          DEFAULT '',
    threat_description  String          DEFAULT '',     -- Input to LLM
    code_length         UInt32          DEFAULT 0,      -- Generated C source length
    compilation_status  LowCardinality(String) DEFAULT 'unknown',
    sandbox_status      LowCardinality(String) DEFAULT 'unknown',
    deployed            Bool            DEFAULT false,
    rollback_at         Nullable(DateTime64(3)),
    source_ip           String          DEFAULT '',

    INDEX idx_program_id program_id TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_deployed   deployed TYPE set(2) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, program_id)
TTL toDateTime(timestamp) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
