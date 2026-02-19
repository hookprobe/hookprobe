-- HookProbe IDS ClickHouse Schema v3.1
-- Aegis (Zig/eBPF) + Napse (Mojo) Architecture
--
-- Tables:
--   - aegis_observations: Raw feature vectors from kernel eBPF probes
--   - napse_intents: AI intent classifications from Napse Mojo engine
--   - napse_flows: Flow summaries with Bayesian state tracking
--   - xdp_stats: XDP/eBPF kernel-level packet statistics
--   - qsecbit_scores: QSECBIT security scoring
--   - incidents: Security incidents
--   - iocs: Indicators of Compromise
--
-- Migration from v3.0 to v3.1 (for existing databases):
--   ALTER TABLE hookprobe_ids.napse_intents ADD COLUMN IF NOT EXISTS vrf LowCardinality(String) DEFAULT 'unknown';
--   ALTER TABLE hookprobe_ids.napse_flows ADD COLUMN IF NOT EXISTS vrf LowCardinality(String) DEFAULT 'unknown';
--   ALTER TABLE hookprobe_ids.xdp_stats ADD COLUMN IF NOT EXISTS interface String DEFAULT 'dummy-mirror';
--   ALTER TABLE hookprobe_ids.xdp_stats ADD COLUMN IF NOT EXISTS total_packets UInt64 DEFAULT 0;
--   ALTER TABLE hookprobe_ids.xdp_stats ADD COLUMN IF NOT EXISTS total_bytes UInt64 DEFAULT 0;
--   ALTER TABLE hookprobe_ids.xdp_stats ADD COLUMN IF NOT EXISTS tcp_packets UInt64 DEFAULT 0;
--   ALTER TABLE hookprobe_ids.xdp_stats ADD COLUMN IF NOT EXISTS udp_packets UInt64 DEFAULT 0;
--   ALTER TABLE hookprobe_ids.xdp_stats ADD COLUMN IF NOT EXISTS icmp_packets UInt64 DEFAULT 0;
--   ALTER TABLE hookprobe_ids.xdp_stats ADD COLUMN IF NOT EXISTS other_packets UInt64 DEFAULT 0;
--   ALTER TABLE hookprobe_ids.xdp_stats ADD COLUMN IF NOT EXISTS tcp_bytes UInt64 DEFAULT 0;
--   ALTER TABLE hookprobe_ids.xdp_stats ADD COLUMN IF NOT EXISTS udp_bytes UInt64 DEFAULT 0;
--   ALTER TABLE hookprobe_ids.xdp_stats ADD COLUMN IF NOT EXISTS icmp_bytes UInt64 DEFAULT 0;
--   ALTER TABLE hookprobe_ids.xdp_stats ADD COLUMN IF NOT EXISTS other_bytes UInt64 DEFAULT 0;
--   ALTER TABLE hookprobe_ids.xdp_stats ADD COLUMN IF NOT EXISTS http_packets UInt64 DEFAULT 0;
--   ALTER TABLE hookprobe_ids.xdp_stats ADD COLUMN IF NOT EXISTS https_packets UInt64 DEFAULT 0;
--   ALTER TABLE hookprobe_ids.xdp_stats ADD COLUMN IF NOT EXISTS dns_packets UInt64 DEFAULT 0;
--   ALTER TABLE hookprobe_ids.xdp_stats ADD COLUMN IF NOT EXISTS ssh_packets UInt64 DEFAULT 0;
--   ALTER TABLE hookprobe_ids.xdp_stats ADD COLUMN IF NOT EXISTS vpn_packets UInt64 DEFAULT 0;
--   ALTER TABLE hookprobe_ids.xdp_stats ADD COLUMN IF NOT EXISTS htp_packets UInt64 DEFAULT 0;

-- Create database
CREATE DATABASE IF NOT EXISTS hookprobe_ids;

-- ============================================================================
-- AEGIS TABLES (Zig/eBPF Kernel Observations)
-- ============================================================================

-- Raw feature vectors captured by Aegis kernel probes.
-- High-volume table: short TTL, optimized for time-series append.
-- Each row is a single packet/event observation with computed entropy
-- and a feature vector for downstream Napse classification.
CREATE TABLE IF NOT EXISTS hookprobe_ids.aegis_observations (
    timestamp DateTime64(3) CODEC(Delta, ZSTD(1)),
    tenant_id UInt32 DEFAULT 0 CODEC(Delta, ZSTD(1)),
    sequence UInt64 CODEC(Delta, ZSTD(1)),
    src_ip IPv4 CODEC(ZSTD(1)),
    dst_ip IPv4 CODEC(ZSTD(1)),
    src_port UInt16 CODEC(Delta, ZSTD(1)),
    dst_port UInt16 CODEC(Delta, ZSTD(1)),
    proto UInt8 CODEC(Delta, ZSTD(1)),
    entropy Float32 CODEC(Gorilla, ZSTD(1)),
    payload_len UInt16 CODEC(Delta, ZSTD(1)),
    tcp_flags UInt8 CODEC(ZSTD(1)),
    feature_vector Array(Float32) CODEC(ZSTD(1)),
    community_id String CODEC(ZSTD(1)),
    INDEX idx_src_ip src_ip TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_dst_ip dst_ip TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_community_id community_id TYPE bloom_filter() GRANULARITY 4
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_ip, dst_ip)
TTL toDateTime(timestamp) + INTERVAL 7 DAY;

-- ============================================================================
-- NAPSE TABLES (Mojo AI Classification Engine)
-- ============================================================================

-- AI intent classifications produced by the Napse Mojo engine.
-- Each row represents a classified network event with Bayesian
-- posterior probabilities and HMM state tracking.
CREATE TABLE IF NOT EXISTS hookprobe_ids.napse_intents (
    timestamp DateTime64(3) CODEC(Delta, ZSTD(1)),
    tenant_id UInt32 DEFAULT 0 CODEC(Delta, ZSTD(1)),
    src_ip IPv4 CODEC(ZSTD(1)),
    dst_ip IPv4 CODEC(ZSTD(1)),
    src_port UInt16 CODEC(Delta, ZSTD(1)),
    dst_port UInt16 CODEC(Delta, ZSTD(1)),
    proto UInt8 CODEC(Delta, ZSTD(1)),
    intent_class LowCardinality(String) CODEC(ZSTD(1)),
    confidence Float32 CODEC(Gorilla, ZSTD(1)),
    severity UInt8 CODEC(Delta, ZSTD(1)),
    hmm_state LowCardinality(String) CODEC(ZSTD(1)),
    prior_probability Float32 CODEC(Gorilla, ZSTD(1)),
    posterior_probability Float32 CODEC(Gorilla, ZSTD(1)),
    entropy Float32 CODEC(Gorilla, ZSTD(1)),
    community_id String CODEC(ZSTD(1)),
    features_summary String CODEC(ZSTD(1)),
    vrf LowCardinality(String) DEFAULT 'unknown' CODEC(ZSTD(1)),
    INDEX idx_src_ip src_ip TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_dst_ip dst_ip TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_intent_class intent_class TYPE set(0) GRANULARITY 4,
    INDEX idx_community_id community_id TYPE bloom_filter() GRANULARITY 4
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_ip, dst_ip)
TTL toDateTime(timestamp) + INTERVAL 90 DAY;

-- Flow summaries with aggregated statistics and final Napse classification.
-- One row per completed flow (identified by community_id).
CREATE TABLE IF NOT EXISTS hookprobe_ids.napse_flows (
    timestamp DateTime64(3) CODEC(Delta, ZSTD(1)),
    tenant_id UInt32 DEFAULT 0 CODEC(Delta, ZSTD(1)),
    community_id String CODEC(ZSTD(1)),
    src_ip IPv4 CODEC(ZSTD(1)),
    dst_ip IPv4 CODEC(ZSTD(1)),
    src_port UInt16 CODEC(Delta, ZSTD(1)),
    dst_port UInt16 CODEC(Delta, ZSTD(1)),
    proto UInt8 CODEC(Delta, ZSTD(1)),
    service LowCardinality(String) CODEC(ZSTD(1)),
    duration Float64 CODEC(Gorilla, ZSTD(1)),
    bytes_orig UInt64 CODEC(Delta, ZSTD(1)),
    bytes_resp UInt64 CODEC(Delta, ZSTD(1)),
    pkts_orig UInt64 CODEC(Delta, ZSTD(1)),
    pkts_resp UInt64 CODEC(Delta, ZSTD(1)),
    max_entropy Float32 CODEC(Gorilla, ZSTD(1)),
    avg_entropy Float32 CODEC(Gorilla, ZSTD(1)),
    intent_class LowCardinality(String) CODEC(ZSTD(1)),
    confidence Float32 CODEC(Gorilla, ZSTD(1)),
    hmm_final_state LowCardinality(String) CODEC(ZSTD(1)),
    vrf LowCardinality(String) DEFAULT 'unknown' CODEC(ZSTD(1)),
    INDEX idx_src_ip src_ip TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_dst_ip dst_ip TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_community_id community_id TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_intent_class intent_class TYPE set(0) GRANULARITY 4
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_ip, dst_ip)
TTL toDateTime(timestamp) + INTERVAL 30 DAY;

-- ============================================================================
-- AGGREGATION VIEWS
-- ============================================================================

-- Hourly intent summary (replaces mv_alerts_hourly)
-- Groups napse_intents by hour, intent_class, severity for dashboard trending.
CREATE MATERIALIZED VIEW IF NOT EXISTS hookprobe_ids.mv_intents_hourly
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, intent_class, severity)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    intent_class,
    severity,
    count() AS intent_count,
    avg(confidence) AS avg_confidence,
    uniqExact(src_ip) AS unique_sources,
    uniqExact(dst_ip) AS unique_destinations
FROM hookprobe_ids.napse_intents
GROUP BY hour, intent_class, severity;

-- Top talkers by day (from flow summaries)
-- Groups napse_flows by day and source IP for bandwidth analysis.
CREATE MATERIALIZED VIEW IF NOT EXISTS hookprobe_ids.mv_top_talkers_daily
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (day, src_ip)
AS SELECT
    toStartOfDay(timestamp) AS day,
    src_ip,
    sum(bytes_orig) AS bytes_sent,
    sum(bytes_resp) AS bytes_received,
    sum(pkts_orig) AS pkts_sent,
    sum(pkts_resp) AS pkts_received,
    uniqExact(dst_ip) AS unique_destinations
FROM hookprobe_ids.napse_flows
GROUP BY day, src_ip;

-- ============================================================================
-- xSOC DASHBOARD TABLES (unchanged)
-- ============================================================================

-- XDP/eBPF kernel-level packet statistics
CREATE TABLE IF NOT EXISTS hookprobe_ids.xdp_stats (
    timestamp DateTime64(3),
    interface String DEFAULT 'dummy-mirror',
    total_packets UInt64 DEFAULT 0,
    total_bytes UInt64 DEFAULT 0,
    tcp_packets UInt64 DEFAULT 0,
    udp_packets UInt64 DEFAULT 0,
    icmp_packets UInt64 DEFAULT 0,
    other_packets UInt64 DEFAULT 0,
    tcp_bytes UInt64 DEFAULT 0,
    udp_bytes UInt64 DEFAULT 0,
    icmp_bytes UInt64 DEFAULT 0,
    other_bytes UInt64 DEFAULT 0,
    http_packets UInt64 DEFAULT 0,
    https_packets UInt64 DEFAULT 0,
    dns_packets UInt64 DEFAULT 0,
    ssh_packets UInt64 DEFAULT 0,
    vpn_packets UInt64 DEFAULT 0,
    htp_packets UInt64 DEFAULT 0,
    high_rate_ip_count UInt32 DEFAULT 0,
    delta_packets UInt64 DEFAULT 0,
    delta_bytes UInt64 DEFAULT 0,
    packets_passed UInt64 DEFAULT 0,
    packets_dropped UInt64 DEFAULT 0,
    rate_drops UInt64 DEFAULT 0,
    vrf String DEFAULT 'unknown'
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY timestamp
TTL toDateTime(timestamp) + INTERVAL 30 DAY;

-- QSECBIT Security Scores (dashboard-level aggregate)
CREATE TABLE IF NOT EXISTS hookprobe_ids.qsecbit_scores (
    timestamp DateTime64(3),
    score UInt8 DEFAULT 0,
    status Enum8('critical' = 1, 'warning' = 2, 'protected' = 3) DEFAULT 'warning',
    threat_score UInt8 DEFAULT 0,
    network_score UInt8 DEFAULT 0,
    detection_score UInt8 DEFAULT 0,
    response_score UInt8 DEFAULT 0,
    critical_alerts UInt32 DEFAULT 0,
    high_alerts UInt32 DEFAULT 0,
    medium_alerts UInt32 DEFAULT 0,
    low_alerts UInt32 DEFAULT 0,
    high_rate_ips UInt32 DEFAULT 0,
    blocked_threats UInt32 DEFAULT 0,
    active_incidents UInt32 DEFAULT 0,
    trend Enum8('improving' = 1, 'stable' = 2, 'degrading' = 3) DEFAULT 'stable',
    score_delta Int16 DEFAULT 0,
    vrf String DEFAULT 'unknown',
    site_id String DEFAULT ''
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY timestamp
TTL toDateTime(timestamp) + INTERVAL 7 DAY;

-- Security Incidents
CREATE TABLE IF NOT EXISTS hookprobe_ids.incidents (
    id UUID DEFAULT generateUUIDv4(),
    created_at DateTime64(3) DEFAULT now64(3),
    updated_at DateTime64(3) DEFAULT now64(3),
    title String,
    description String DEFAULT '',
    severity Enum8('critical' = 1, 'high' = 2, 'medium' = 3, 'low' = 4) DEFAULT 'medium',
    status Enum8('new' = 1, 'investigating' = 2, 'contained' = 3, 'resolved' = 4) DEFAULT 'new',
    category String DEFAULT '',
    affected_devices UInt32 DEFAULT 0,
    cia_impact Array(Enum8('confidentiality' = 1, 'integrity' = 2, 'availability' = 3)),
    threat_score UInt8 DEFAULT 0,
    sources Array(String),
    src_ips Array(String),
    dest_ips Array(String),
    vrf String DEFAULT 'unknown'
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (created_at, severity)
TTL toDateTime(created_at) + INTERVAL 90 DAY;

-- Indicators of Compromise (IoCs)
CREATE TABLE IF NOT EXISTS hookprobe_ids.iocs (
    id UUID DEFAULT generateUUIDv4(),
    created_at DateTime64(3) DEFAULT now64(3),
    last_seen DateTime64(3) DEFAULT now64(3),
    type Enum8('ip' = 1, 'domain' = 2, 'hash' = 3, 'url' = 4, 'email' = 5, 'file' = 6) DEFAULT 'ip',
    value String,
    confidence UInt8 DEFAULT 50,
    risk_score UInt8 DEFAULT 50,
    threat_type String DEFAULT '',
    status Enum8('active' = 1, 'blocked' = 2, 'investigating' = 3, 'resolved' = 4) DEFAULT 'active',
    sources Array(String),
    detection_count UInt32 DEFAULT 1,
    vrf String DEFAULT 'unknown'
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (created_at, risk_score)
TTL toDateTime(created_at) + INTERVAL 90 DAY;

-- ============================================================================
-- HYDRA TABLES (Active Defense Layer)
-- ============================================================================

-- XDP block/alert events from RINGBUF consumer.
-- Each row represents a packet that was dropped or flagged by the XDP program.
CREATE TABLE IF NOT EXISTS hookprobe_ids.hydra_events (
    timestamp DateTime64(3) CODEC(Delta, ZSTD(1)),
    src_ip IPv4 CODEC(ZSTD(1)),
    dst_ip IPv4 CODEC(ZSTD(1)),
    src_port UInt16 CODEC(Delta, ZSTD(1)),
    dst_port UInt16 CODEC(Delta, ZSTD(1)),
    proto UInt8 CODEC(Delta, ZSTD(1)),
    action LowCardinality(String) CODEC(ZSTD(1)),  -- 'drop', 'alert', 'rate_limit'
    reason LowCardinality(String) CODEC(ZSTD(1)),  -- 'blocklist', 'rate_exceeded', 'syn_flood', 'rpf_fail'
    feed_source LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),  -- 'spamhaus_drop', 'firehol_l1', etc.
    tcp_flags UInt8 DEFAULT 0 CODEC(ZSTD(1)),
    INDEX idx_src_ip src_ip TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_dst_ip dst_ip TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_action action TYPE set(0) GRANULARITY 4,
    INDEX idx_reason reason TYPE set(0) GRANULARITY 4
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_ip)
TTL toDateTime(timestamp) + INTERVAL 90 DAY;

-- Threat feed sync status log.
-- Tracks each feed download: success/failure, entry counts, timing.
CREATE TABLE IF NOT EXISTS hookprobe_ids.hydra_feed_sync (
    timestamp DateTime64(3) CODEC(Delta, ZSTD(1)),
    feed_name LowCardinality(String) CODEC(ZSTD(1)),
    feed_url String CODEC(ZSTD(1)),
    entries_count UInt32 DEFAULT 0 CODEC(Delta, ZSTD(1)),
    new_entries UInt32 DEFAULT 0 CODEC(Delta, ZSTD(1)),
    removed_entries UInt32 DEFAULT 0 CODEC(Delta, ZSTD(1)),
    status LowCardinality(String) CODEC(ZSTD(1)),  -- 'success', 'error', 'timeout', 'unchanged'
    sync_duration_ms UInt32 DEFAULT 0 CODEC(Delta, ZSTD(1)),
    error_message String DEFAULT '' CODEC(ZSTD(1))
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, feed_name)
TTL toDateTime(timestamp) + INTERVAL 365 DAY;

-- nftables/XDP block log.
-- Each row is an IP that was actively blocked at the network level.
CREATE TABLE IF NOT EXISTS hookprobe_ids.hydra_blocks (
    timestamp DateTime64(3) CODEC(Delta, ZSTD(1)),
    src_ip IPv4 CODEC(ZSTD(1)),
    duration_seconds UInt32 DEFAULT 300 CODEC(Delta, ZSTD(1)),
    reason LowCardinality(String) CODEC(ZSTD(1)),  -- 'threat_feed', 'rate_limit', 'brute_force', 'manual'
    source LowCardinality(String) CODEC(ZSTD(1)),  -- 'xdp', 'nftables', 'operator'
    auto_expired UInt8 DEFAULT 0 CODEC(ZSTD(1)),
    event_count UInt32 DEFAULT 0 CODEC(Delta, ZSTD(1)),
    INDEX idx_src_ip src_ip TYPE bloom_filter() GRANULARITY 4
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_ip)
TTL toDateTime(timestamp) + INTERVAL 365 DAY;

-- Per-IP feature vectors for ML anomaly detection (Phase 3).
-- One row per IP per 5-minute window with extracted behavioral features.
CREATE TABLE IF NOT EXISTS hookprobe_ids.hydra_ip_features (
    timestamp DateTime64(3) CODEC(Delta, ZSTD(1)),
    src_ip IPv4 CODEC(ZSTD(1)),
    -- Network features
    pps Float32 CODEC(Gorilla, ZSTD(1)),
    bps Float32 CODEC(Gorilla, ZSTD(1)),
    unique_dst_ports UInt16 CODEC(Delta, ZSTD(1)),
    unique_dst_ips UInt16 CODEC(Delta, ZSTD(1)),
    syn_ratio Float32 CODEC(Gorilla, ZSTD(1)),
    avg_pkt_size Float32 CODEC(Gorilla, ZSTD(1)),
    -- Temporal features
    iat_mean Float32 CODEC(Gorilla, ZSTD(1)),
    iat_entropy Float32 CODEC(Gorilla, ZSTD(1)),
    burst_count UInt16 CODEC(Delta, ZSTD(1)),
    -- Behavioral features
    port_diversity Float32 CODEC(Gorilla, ZSTD(1)),
    protocol_mix Float32 CODEC(Gorilla, ZSTD(1)),
    -- Full feature vector for ML input (24 features)
    feature_vector Array(Float32) CODEC(ZSTD(1)),
    INDEX idx_src_ip src_ip TYPE bloom_filter() GRANULARITY 4
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_ip)
TTL toDateTime(timestamp) + INTERVAL 30 DAY;

-- ML verdict log (Phase 3).
-- Stores anomaly detection results and ensemble decisions.
CREATE TABLE IF NOT EXISTS hookprobe_ids.hydra_verdicts (
    timestamp DateTime64(3) CODEC(Delta, ZSTD(1)),
    src_ip IPv4 CODEC(ZSTD(1)),
    anomaly_score Float32 CODEC(Gorilla, ZSTD(1)),
    model_scores Array(Float32) CODEC(ZSTD(1)),  -- [isolation_forest, cnn, hmm]
    verdict LowCardinality(String) CODEC(ZSTD(1)),  -- 'benign', 'suspicious', 'malicious'
    action_taken LowCardinality(String) CODEC(ZSTD(1)),  -- 'none', 'alert', 'throttle', 'block'
    operator_decision LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),  -- 'confirm', 'false_positive', ''
    operator_decided_at Nullable(DateTime64(3)),
    INDEX idx_src_ip src_ip TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_verdict verdict TYPE set(0) GRANULARITY 4
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_ip)
TTL toDateTime(timestamp) + INTERVAL 90 DAY;

-- Hourly HYDRA event summary for dashboard trending.
CREATE MATERIALIZED VIEW IF NOT EXISTS hookprobe_ids.mv_hydra_events_hourly
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, action, reason)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    action,
    reason,
    count() AS event_count,
    uniqExact(src_ip) AS unique_sources
FROM hookprobe_ids.hydra_events
GROUP BY hour, action, reason;

-- RDAP enrichment cache (Phase 6: IP identity awareness).
-- Stores RDAP/RIPE query results for IP ownership classification.
-- ReplacingMergeTree deduplicates by ip on background merge (latest queried_at wins).
CREATE TABLE IF NOT EXISTS hookprobe_ids.rdap_cache (
    ip IPv4,
    queried_at DateTime DEFAULT now(),
    rdap_name String CODEC(ZSTD(1)),
    rdap_handle String CODEC(ZSTD(1)),
    rdap_type LowCardinality(String) CODEC(ZSTD(1)),  -- 'datacenter', 'isp', 'cdn', 'vpn', 'tor', 'edu', 'gov', 'unknown'
    country LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    asn UInt32 DEFAULT 0 CODEC(Delta, ZSTD(1)),
    asn_name String DEFAULT '' CODEC(ZSTD(1)),
    abuse_contact String DEFAULT '' CODEC(ZSTD(1)),
    cidr_prefix UInt8 DEFAULT 0 CODEC(ZSTD(1)),
    weighted_score UInt16 DEFAULT 0 CODEC(ZSTD(1)),
    raw_json String DEFAULT '' CODEC(ZSTD(3))
) ENGINE = ReplacingMergeTree(queried_at)
ORDER BY ip
TTL queried_at + INTERVAL 30 DAY;
