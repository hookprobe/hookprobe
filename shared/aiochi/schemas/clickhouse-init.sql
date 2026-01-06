-- AIOCHI ClickHouse Schema
-- Cognitive Network Layer Database
--
-- This schema defines all tables for the AIOCHI data pipeline:
-- 1. Raw event ingestion (Suricata, Zeek)
-- 2. Device identities (enriched fingerprints)
-- 3. Human narratives (translated events)
-- 4. Presence tracking (bubbles, states)
-- 5. Performance metrics (health scores)

-- Create database if not exists
CREATE DATABASE IF NOT EXISTS aiochi;

USE aiochi;

-- ============================================================================
-- DEVICE IDENTITIES
-- Enriched device information with human-friendly labels
-- ============================================================================

CREATE TABLE IF NOT EXISTS device_identities (
    mac String,
    first_seen DateTime DEFAULT now(),
    last_seen DateTime DEFAULT now(),
    human_label String,           -- "Dad's iPhone"
    device_type String,           -- "iPhone 15 Pro"
    vendor String,                -- "Apple"
    ecosystem String,             -- "apple", "google", "amazon", etc.
    bubble_id String,             -- "family_dad"
    trust_level UInt8,            -- 0-4 (L0-L4)
    confidence Float32,           -- 0.0-1.0
    fingerprint_hash String,      -- Unique fingerprint identifier
    hostname String,
    ip_address String,
    dhcp_options Array(UInt8),    -- DHCP Option 55 values
    mdns_services Array(String),  -- Discovered mDNS services

    INDEX idx_mac mac TYPE bloom_filter GRANULARITY 1,
    INDEX idx_bubble bubble_id TYPE bloom_filter GRANULARITY 1,
    INDEX idx_ecosystem ecosystem TYPE bloom_filter GRANULARITY 1
) ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (mac)
TTL last_seen + INTERVAL 90 DAY;

-- ============================================================================
-- NARRATIVES
-- Human-readable stories generated from events
-- ============================================================================

CREATE TABLE IF NOT EXISTS narratives (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    severity Enum8('info' = 1, 'low' = 2, 'medium' = 3, 'high' = 4, 'critical' = 5),
    category String,              -- "security", "device", "performance", "privacy"
    device_mac String,
    device_label String,          -- "Dad's iPhone" (denormalized for speed)
    headline String,              -- Short summary for notifications
    narrative String,             -- Full human-readable story
    technical_details String,     -- JSON blob for curious users
    action_required Bool DEFAULT false,
    action_taken String,
    persona String DEFAULT 'parent',
    dismissed Bool DEFAULT false,

    INDEX idx_severity severity TYPE minmax GRANULARITY 1,
    INDEX idx_category category TYPE bloom_filter GRANULARITY 1,
    INDEX idx_device device_mac TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, severity)
TTL timestamp + INTERVAL 30 DAY;

-- ============================================================================
-- PRESENCE SNAPSHOTS
-- For bubble visualization (who's home)
-- ============================================================================

CREATE TABLE IF NOT EXISTS presence_snapshots (
    timestamp DateTime DEFAULT now(),
    bubble_id String,
    bubble_label String,          -- "Dad", "Mom", "Kids"
    devices Array(String),        -- List of device labels
    device_macs Array(String),    -- List of MACs
    ap_name String,               -- "Living Room AP"
    signal_strength Int16,
    is_home Bool DEFAULT true,
    state String,                 -- "home", "away", "arriving", "leaving"

    INDEX idx_bubble bubble_id TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, bubble_id)
TTL timestamp + INTERVAL 7 DAY;

-- ============================================================================
-- PERFORMANCE METRICS
-- For health score calculation
-- ============================================================================

CREATE TABLE IF NOT EXISTS performance_metrics (
    timestamp DateTime DEFAULT now(),
    device_mac String DEFAULT '',  -- Empty for network-wide
    latency_ms Float32,
    jitter_ms Float32,
    packet_loss_pct Float32,
    signal_dbm Int16,
    bandwidth_mbps Float32,
    interference_score Float32,
    congestion_score Float32,
    health_score UInt8,           -- 0-100

    INDEX idx_device device_mac TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, device_mac)
TTL timestamp + INTERVAL 7 DAY;

-- ============================================================================
-- AMBIENT STATE HISTORY
-- Track dashboard state changes
-- ============================================================================

CREATE TABLE IF NOT EXISTS ambient_state_history (
    timestamp DateTime DEFAULT now(),
    state Enum8('calm' = 1, 'curious' = 2, 'alert' = 3),
    primary_event_id String,
    primary_event_headline String,
    active_event_count UInt16
) ENGINE = MergeTree()
ORDER BY (timestamp)
TTL timestamp + INTERVAL 30 DAY;

-- ============================================================================
-- TIME PATTERNS
-- Learned behavioral patterns (for anomaly detection)
-- ============================================================================

CREATE TABLE IF NOT EXISTS time_patterns (
    device_mac String,
    day_of_week UInt8,            -- 0-6 (Monday-Sunday)
    hour_of_day UInt8,            -- 0-23
    typical_state Enum8('online' = 1, 'offline' = 2, 'active' = 3, 'idle' = 4),
    confidence Float32,
    sample_count UInt32 DEFAULT 1,
    last_updated DateTime DEFAULT now(),

    INDEX idx_device device_mac TYPE bloom_filter GRANULARITY 1
) ENGINE = ReplacingMergeTree(last_updated)
ORDER BY (device_mac, day_of_week, hour_of_day);

-- ============================================================================
-- QUICK ACTION HISTORY
-- Track executed quick actions
-- ============================================================================

CREATE TABLE IF NOT EXISTS quick_action_history (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    action_id String,
    action_name String,
    target String,                -- MAC, bubble_id, etc.
    status Enum8('pending' = 1, 'running' = 2, 'success' = 3, 'failed' = 4, 'reverted' = 5),
    result_message String,
    reverts_at Nullable(DateTime),
    reverted Bool DEFAULT false,
    user_id String DEFAULT 'system',

    INDEX idx_action action_id TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, action_id)
TTL timestamp + INTERVAL 90 DAY;

-- ============================================================================
-- RAW EVENTS - SURICATA ALERTS
-- Ingested from Suricata EVE JSON logs
-- ============================================================================

CREATE TABLE IF NOT EXISTS suricata_alerts (
    timestamp DateTime,
    flow_id UInt64,
    event_type String,
    src_ip String,
    src_port UInt16,
    dest_ip String,
    dest_port UInt16,
    proto String,
    app_proto String,
    alert_action String,
    alert_gid UInt32,
    alert_signature_id UInt32,
    alert_rev UInt32,
    alert_signature String,
    alert_category String,
    alert_severity UInt8,
    alert_metadata String,        -- JSON
    http_hostname String,
    http_url String,
    tls_sni String,
    dns_query String,
    raw_json String,              -- Full JSON for debugging

    INDEX idx_src_ip src_ip TYPE bloom_filter GRANULARITY 1,
    INDEX idx_dest_ip dest_ip TYPE bloom_filter GRANULARITY 1,
    INDEX idx_signature alert_signature_id TYPE minmax GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, alert_severity, flow_id)
TTL timestamp + INTERVAL 30 DAY;

-- ============================================================================
-- RAW EVENTS - ZEEK CONNECTIONS
-- Ingested from Zeek conn.log
-- ============================================================================

CREATE TABLE IF NOT EXISTS zeek_connections (
    ts DateTime,
    uid String,
    id_orig_h String,             -- Source IP
    id_orig_p UInt16,             -- Source port
    id_resp_h String,             -- Destination IP
    id_resp_p UInt16,             -- Destination port
    proto String,
    service String,
    duration Float64,
    orig_bytes UInt64,
    resp_bytes UInt64,
    conn_state String,
    local_orig Bool,
    local_resp Bool,
    missed_bytes UInt64,
    history String,
    orig_pkts UInt64,
    orig_ip_bytes UInt64,
    resp_pkts UInt64,
    resp_ip_bytes UInt64,
    community_id String,

    INDEX idx_orig_ip id_orig_h TYPE bloom_filter GRANULARITY 1,
    INDEX idx_resp_ip id_resp_h TYPE bloom_filter GRANULARITY 1,
    INDEX idx_service service TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (ts, uid)
TTL ts + INTERVAL 7 DAY;

-- ============================================================================
-- RAW EVENTS - ZEEK DNS
-- Ingested from Zeek dns.log
-- ============================================================================

CREATE TABLE IF NOT EXISTS zeek_dns (
    ts DateTime,
    uid String,
    id_orig_h String,
    id_orig_p UInt16,
    id_resp_h String,
    id_resp_p UInt16,
    proto String,
    trans_id UInt16,
    rtt Float64,
    query String,
    qclass UInt16,
    qclass_name String,
    qtype UInt16,
    qtype_name String,
    rcode UInt16,
    rcode_name String,
    AA Bool,
    TC Bool,
    RD Bool,
    RA Bool,
    Z UInt8,
    answers Array(String),
    TTLs Array(Float64),
    rejected Bool,

    INDEX idx_query query TYPE bloom_filter GRANULARITY 1,
    INDEX idx_orig_ip id_orig_h TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (ts, uid)
TTL ts + INTERVAL 7 DAY;

-- ============================================================================
-- MATERIALIZED VIEWS
-- Pre-aggregated data for dashboard queries
-- ============================================================================

-- Hourly narrative counts by category
CREATE MATERIALIZED VIEW IF NOT EXISTS narratives_hourly_mv
ENGINE = SummingMergeTree()
ORDER BY (hour, category, severity)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    category,
    severity,
    count() AS count
FROM narratives
GROUP BY hour, category, severity;

-- Daily device activity
CREATE MATERIALIZED VIEW IF NOT EXISTS device_activity_daily_mv
ENGINE = SummingMergeTree()
ORDER BY (day, device_mac)
AS SELECT
    toDate(timestamp) AS day,
    device_mac,
    count() AS event_count,
    max(timestamp) AS last_seen
FROM narratives
WHERE device_mac != ''
GROUP BY day, device_mac;

-- Threat summary by hour
CREATE MATERIALIZED VIEW IF NOT EXISTS threats_hourly_mv
ENGINE = SummingMergeTree()
ORDER BY (hour, alert_category)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    alert_category,
    count() AS count,
    max(alert_severity) AS max_severity
FROM suricata_alerts
GROUP BY hour, alert_category;

-- ============================================================================
-- DICTIONARY FOR DEVICE LABELS
-- Fast lookup for device human labels
-- ============================================================================

CREATE DICTIONARY IF NOT EXISTS device_labels (
    mac String,
    human_label String,
    device_type String,
    ecosystem String
)
PRIMARY KEY mac
SOURCE(CLICKHOUSE(
    HOST 'localhost'
    PORT 9000
    USER 'aiochi'
    PASSWORD ''
    DB 'aiochi'
    TABLE 'device_identities'
))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 300);

-- Function to get device label (with fallback)
CREATE FUNCTION IF NOT EXISTS getDeviceLabel AS (mac) ->
    ifNull(
        dictGetOrNull('device_labels', 'human_label', mac),
        mac
    );

-- ============================================================================
-- AGENTIC AI - DEVICE TRUST SCORES
-- Memory for AI Agent decision making
-- ============================================================================

CREATE TABLE IF NOT EXISTS device_trust (
    mac_address String,
    trust_score UInt8 DEFAULT 50,  -- 0-100 (higher = more trusted)
    ecosystem String,              -- "apple", "google", "amazon", "iot", "unknown"
    bubble_id String,              -- Family bubble association
    last_action String,            -- Last AI action taken
    action_count UInt32 DEFAULT 0, -- Total actions on this device
    block_count UInt32 DEFAULT 0,
    migrate_count UInt32 DEFAULT 0,
    throttle_count UInt32 DEFAULT 0,
    trust_count UInt32 DEFAULT 0,  -- Times marked trusted
    last_seen DateTime DEFAULT now(),
    first_seen DateTime DEFAULT now(),
    is_known Bool DEFAULT false,   -- User explicitly identified
    is_blocked Bool DEFAULT false, -- Currently blocked
    blocked_reason String,
    notes String,                  -- Human-added notes

    INDEX idx_mac mac_address TYPE bloom_filter GRANULARITY 1,
    INDEX idx_ecosystem ecosystem TYPE bloom_filter GRANULARITY 1,
    INDEX idx_trust trust_score TYPE minmax GRANULARITY 1
) ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (mac_address)
TTL last_seen + INTERVAL 365 DAY;

-- ============================================================================
-- AGENTIC AI - AGENT ACTIONS LOG
-- Audit trail of all AI decisions
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_actions (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    event_id String,               -- Triggering security event
    mac_address String,
    device_label String,
    action Enum8('BLOCK' = 1, 'MIGRATE' = 2, 'THROTTLE' = 3, 'MONITOR' = 4, 'TRUST' = 5),
    target String,                 -- VLAN name for migrate, rate for throttle
    reason String,                 -- AI's reasoning
    narrative String,              -- Human-friendly explanation
    trust_score_before UInt8,
    trust_score_after UInt8,
    deterministic Bool DEFAULT false,  -- Was this a short-circuit decision?
    model_used String,             -- "llama3.2:3b" or "deterministic"
    inference_time_ms UInt32,
    human_feedback Enum8('pending' = 0, 'approved' = 1, 'rejected' = 2, 'undo' = 3) DEFAULT 'pending',
    feedback_timestamp Nullable(DateTime),
    feedback_notes String,

    INDEX idx_mac mac_address TYPE bloom_filter GRANULARITY 1,
    INDEX idx_action action TYPE minmax GRANULARITY 1,
    INDEX idx_feedback human_feedback TYPE minmax GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, action, mac_address)
TTL timestamp + INTERVAL 180 DAY;

-- ============================================================================
-- AGENTIC AI - THREAT BLOCKLIST
-- Known bad actors for deterministic blocking
-- ============================================================================

CREATE TABLE IF NOT EXISTS threat_blocklist (
    indicator_type Enum8('mac' = 1, 'ip' = 2, 'domain' = 3, 'ja3' = 4, 'user_agent' = 5),
    indicator_value String,
    threat_category String,        -- "malware", "c2", "phishing", "scanner"
    severity Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    source String,                 -- "suricata", "zeek", "user", "mesh", "external"
    added_at DateTime DEFAULT now(),
    expires_at Nullable(DateTime),
    auto_block Bool DEFAULT true,  -- Deterministic block on match
    confidence Float32 DEFAULT 1.0,
    notes String,

    INDEX idx_indicator indicator_value TYPE bloom_filter GRANULARITY 1
) ENGINE = ReplacingMergeTree(added_at)
ORDER BY (indicator_type, indicator_value);

-- ============================================================================
-- AGENTIC AI - ACTION RATE LIMITER
-- Prevent flapping (memory for recent actions)
-- ============================================================================

CREATE TABLE IF NOT EXISTS action_rate_limit (
    mac_address String,
    action Enum8('BLOCK' = 1, 'MIGRATE' = 2, 'THROTTLE' = 3, 'MONITOR' = 4, 'TRUST' = 5),
    last_action_at DateTime DEFAULT now(),
    action_count_5min UInt8 DEFAULT 1,
    cooldown_until Nullable(DateTime),

    INDEX idx_mac mac_address TYPE bloom_filter GRANULARITY 1
) ENGINE = ReplacingMergeTree(last_action_at)
ORDER BY (mac_address, action);

-- ============================================================================
-- SAMPLE QUERIES FOR DASHBOARD
-- ============================================================================

-- Recent narratives for feed
-- SELECT * FROM narratives
-- WHERE NOT dismissed
-- ORDER BY timestamp DESC
-- LIMIT 20;

-- Current health score
-- SELECT
--     health_score,
--     latency_ms,
--     packet_loss_pct
-- FROM performance_metrics
-- WHERE device_mac = ''
-- ORDER BY timestamp DESC
-- LIMIT 1;

-- Bubble presence summary
-- SELECT
--     bubble_id,
--     bubble_label,
--     state,
--     length(devices) AS device_count
-- FROM presence_snapshots
-- WHERE timestamp > now() - INTERVAL 5 MINUTE
-- ORDER BY timestamp DESC
-- LIMIT 1 BY bubble_id;

-- Top blocked threats today
-- SELECT
--     alert_signature,
--     alert_category,
--     count() AS count
-- FROM suricata_alerts
-- WHERE timestamp > today()
--   AND alert_action = 'blocked'
-- GROUP BY alert_signature, alert_category
-- ORDER BY count DESC
-- LIMIT 10;


-- ============================================================================
-- PURPLE TEAM SCHEMA (Gap #4 Fix)
-- Database for Nexus Red/Purple Team simulation results
-- ============================================================================

CREATE DATABASE IF NOT EXISTS purple_team;

USE purple_team;

-- Simulation Results
-- Core table for storing purple team simulation outcomes
CREATE TABLE IF NOT EXISTS simulations (
    simulation_id String,
    timestamp DateTime DEFAULT now(),
    nexus_node_id String DEFAULT '',

    -- Defense metrics
    defense_score UInt8,              -- 0-100
    overall_risk Enum8('LOW' = 1, 'MEDIUM' = 2, 'HIGH' = 3, 'CRITICAL' = 4),

    -- Attack metrics
    attacks_total UInt8,
    attacks_successful UInt8,
    attacks_detected UInt8,
    attacks_blocked UInt8,

    -- Bubble metrics
    bubbles_tested UInt8,
    bubbles_penetrated UInt8,
    devices_compromised UInt16,

    -- Detection metrics
    true_positives UInt8,
    false_positives UInt8,
    true_negatives UInt8,
    false_negatives UInt8,

    -- CVSS scores
    cvss_max Float32,
    cvss_avg Float32,

    -- Action taken
    action Enum8('log_only' = 1, 'alert_and_optimize' = 2, 'review_required' = 3, 'immediate_alert' = 4),
    priority Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),

    -- Recommendations (stored as JSON)
    recommendations String,           -- JSON array of recommendation strings

    -- Duration
    duration_seconds Float32,

    INDEX idx_sim simulation_id TYPE bloom_filter GRANULARITY 1,
    INDEX idx_risk overall_risk TYPE minmax GRANULARITY 1,
    INDEX idx_score defense_score TYPE minmax GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, simulation_id)
TTL timestamp + INTERVAL 90 DAY;


-- Attack Results
-- Detailed results for each attack vector in a simulation
CREATE TABLE IF NOT EXISTS attack_results (
    id UUID DEFAULT generateUUIDv4(),
    simulation_id String,
    timestamp DateTime DEFAULT now(),

    -- Attack details
    attack_type String,               -- 'ter_replay', 'mac_impersonation', etc.
    attack_name String,               -- Human-readable name
    mitre_technique String,           -- MITRE ATT&CK ID (e.g., T1134)

    -- Results
    success Bool,
    partial_success Bool,
    detected Bool,
    blocked Bool,

    -- Scoring
    confidence Float32,               -- 0.0-1.0
    exploitability Float32,           -- CVSS exploitability
    impact Float32,                   -- CVSS impact
    cvss_score Float32,               -- Combined CVSS

    -- Timing
    execution_time_ms Float32,

    -- Target
    target_bubble_id String,
    target_mac String,

    -- Evidence (JSON)
    evidence String,                  -- JSON array
    details String,                   -- JSON object

    INDEX idx_sim simulation_id TYPE bloom_filter GRANULARITY 1,
    INDEX idx_attack attack_type TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, simulation_id, attack_type)
TTL timestamp + INTERVAL 90 DAY;


-- Optimization History
-- Track optimizations applied from purple team recommendations
CREATE TABLE IF NOT EXISTS optimizations (
    id UUID DEFAULT generateUUIDv4(),
    optimization_id String,
    simulation_id String,
    timestamp DateTime DEFAULT now(),

    -- What was optimized
    parameter String,
    action String,                    -- 'increase', 'decrease', 'enable', 'disable'
    old_value String,
    new_value String,
    reason String,

    -- Result
    applied Bool,
    error String DEFAULT '',

    -- Impact tracking
    defense_score_before UInt8,
    defense_score_after UInt8,

    INDEX idx_sim simulation_id TYPE bloom_filter GRANULARITY 1,
    INDEX idx_param parameter TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, simulation_id)
TTL timestamp + INTERVAL 180 DAY;


-- Defense Outcomes
-- Real-world defense outcomes for comparison with simulations
CREATE TABLE IF NOT EXISTS defense_outcomes (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),

    -- Event details
    attack_type String,
    detected Bool,
    blocked Bool,
    detection_method String,
    response_action String,

    -- Target
    target_mac String,
    target_bubble_id String,

    -- Source (for correlation)
    source_ip String DEFAULT '',

    -- Metrics
    detection_time_ms Float32,
    response_time_ms Float32,

    INDEX idx_attack attack_type TYPE bloom_filter GRANULARITY 1,
    INDEX idx_mac target_mac TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, attack_type)
TTL timestamp + INTERVAL 90 DAY;


-- Meta-Regression Observations
-- Store observations for meta-regressive learning
CREATE TABLE IF NOT EXISTS meta_regression_observations (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    simulation_id String,

    -- Bubble being analyzed
    bubble_id String,
    bubble_type String,

    -- Feature values
    temporal_sync Float32,            -- 0.0-1.0
    d2d_affinity Float32,             -- 0.0-1.0
    nse_resonance Float32,            -- 0.0-1.0

    -- Target variable
    accuracy Float32,                 -- 0.0-1.0 (bubble assignment accuracy)

    -- Model output (after regression)
    predicted_accuracy Float32,
    residual Float32,

    INDEX idx_sim simulation_id TYPE bloom_filter GRANULARITY 1,
    INDEX idx_bubble bubble_id TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, simulation_id)
TTL timestamp + INTERVAL 90 DAY;


-- Regression Coefficients
-- Store learned regression coefficients over time
CREATE TABLE IF NOT EXISTS regression_coefficients (
    timestamp DateTime DEFAULT now(),
    model_version UInt32,

    -- Coefficients from E = β₀ + β₁(Ts) + β₂(D2D) + β₃(NSE) + ε
    beta_0 Float32,                   -- Intercept
    beta_temporal_sync Float32,       -- β₁
    beta_d2d_affinity Float32,        -- β₂
    beta_nse_resonance Float32,       -- β₃

    -- Model quality
    r_squared Float32,
    observations_count UInt32,

    -- Source
    nexus_node_id String DEFAULT ''
) ENGINE = MergeTree()
ORDER BY (timestamp, model_version)
TTL timestamp + INTERVAL 365 DAY;


-- ============================================================================
-- PURPLE TEAM VIEWS
-- ============================================================================

-- Defense score trend over last 30 days
-- CREATE VIEW defense_score_trend AS
-- SELECT
--     toDate(timestamp) AS date,
--     avg(defense_score) AS avg_score,
--     min(defense_score) AS min_score,
--     max(defense_score) AS max_score,
--     count() AS simulations
-- FROM purple_team.simulations
-- WHERE timestamp > now() - INTERVAL 30 DAY
-- GROUP BY date
-- ORDER BY date;

-- Attack success rate by type
-- CREATE VIEW attack_success_rates AS
-- SELECT
--     attack_type,
--     count() AS total,
--     sum(success) AS successful,
--     round(sum(success) / count() * 100, 1) AS success_rate_pct,
--     avg(cvss_score) AS avg_cvss
-- FROM purple_team.attack_results
-- WHERE timestamp > now() - INTERVAL 30 DAY
-- GROUP BY attack_type
-- ORDER BY success_rate_pct DESC;

-- Latest coefficients
-- SELECT * FROM purple_team.regression_coefficients
-- ORDER BY timestamp DESC
-- LIMIT 1;
