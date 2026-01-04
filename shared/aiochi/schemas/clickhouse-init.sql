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
