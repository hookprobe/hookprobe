-- HookProbe IDS ClickHouse Schema v3.0
-- Multi-Tenant Event Analytics Database
-- Aegis (Zig/eBPF) + Napse (Mojo) Architecture
--
-- All tables use tenant_id in partition keys for tenant isolation.
-- TTL policies enforce data retention per table type.

-- Create database
CREATE DATABASE IF NOT EXISTS hookprobe_ids;

-- ============================================================================
-- TENANT MANAGEMENT
-- ============================================================================

CREATE TABLE IF NOT EXISTS hookprobe_ids.tenants (
    tenant_id      UInt32,
    tenant_name    String,
    ip_ranges      Array(String),
    rate_limit_pps UInt32 DEFAULT 10000,
    created_at     DateTime DEFAULT now(),
    active         UInt8 DEFAULT 1
) ENGINE = MergeTree()
ORDER BY tenant_id;

-- Default tenant (0)
INSERT INTO hookprobe_ids.tenants (tenant_id, tenant_name, ip_ranges)
VALUES (0, 'default', ['0.0.0.0/0'])
ON DUPLICATE KEY UPDATE tenant_name = tenant_name;

-- ============================================================================
-- AEGIS TABLES (Zig/eBPF Kernel Observations) - Multi-Tenant
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
PARTITION BY (toYYYYMM(timestamp), tenant_id)
ORDER BY (tenant_id, timestamp, src_ip, dst_ip)
TTL timestamp + INTERVAL 7 DAY;

-- ============================================================================
-- NAPSE TABLES (Mojo AI Classification Engine) - Multi-Tenant
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
PARTITION BY (toYYYYMM(timestamp), tenant_id)
ORDER BY (tenant_id, timestamp, src_ip, dst_ip)
TTL timestamp + INTERVAL 90 DAY;

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
PARTITION BY (toYYYYMM(timestamp), tenant_id)
ORDER BY (tenant_id, timestamp, src_ip, dst_ip)
TTL timestamp + INTERVAL 30 DAY;

-- ============================================================================
-- QSECBIT TABLES (Multi-Tenant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS hookprobe_ids.qsecbit_scores (
    timestamp DateTime64(3) CODEC(Delta, ZSTD(1)),
    tenant_id UInt32 CODEC(Delta, ZSTD(1)),
    src_ip IPv4 CODEC(ZSTD(1)),
    score Float32 CODEC(Gorilla),
    alert_count UInt32 CODEC(Delta, ZSTD(1)),
    rate_triggers UInt32 CODEC(Delta, ZSTD(1)),
    categories Array(LowCardinality(String)) CODEC(ZSTD(1)),
    status Enum8('active' = 1, 'blocked' = 2, 'decaying' = 3) CODEC(ZSTD(1))
) ENGINE = MergeTree()
PARTITION BY (toYYYYMM(timestamp), tenant_id)
ORDER BY (tenant_id, timestamp, src_ip)
TTL timestamp + INTERVAL 7 DAY;

CREATE TABLE IF NOT EXISTS hookprobe_ids.blocking_actions (
    timestamp DateTime64(3) CODEC(Delta, ZSTD(1)),
    tenant_id UInt32 CODEC(Delta, ZSTD(1)),
    src_ip IPv4 CODEC(ZSTD(1)),
    dst_ip IPv4 CODEC(ZSTD(1)),
    proto LowCardinality(String) CODEC(ZSTD(1)),
    src_port UInt16 CODEC(Delta, ZSTD(1)),
    dst_port UInt16 CODEC(Delta, ZSTD(1)),
    block_reason LowCardinality(String) CODEC(ZSTD(1)),
    block_source LowCardinality(String) CODEC(ZSTD(1)),
    duration_seconds UInt32 CODEC(Delta, ZSTD(1)),
    qsecbit_score Float32 CODEC(Gorilla),
    related_intents Array(String) CODEC(ZSTD(1))
) ENGINE = MergeTree()
PARTITION BY (toYYYYMM(timestamp), tenant_id)
ORDER BY (tenant_id, timestamp, src_ip)
TTL timestamp + INTERVAL 180 DAY;

-- ============================================================================
-- XDP STATISTICS (Multi-Tenant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS hookprobe_ids.xdp_stats (
    timestamp DateTime CODEC(Delta, ZSTD(1)),
    tenant_id UInt32 DEFAULT 0 CODEC(Delta, ZSTD(1)),
    packets_passed UInt64 CODEC(Delta, ZSTD(1)),
    packets_dropped UInt64 CODEC(Delta, ZSTD(1)),
    rate_drops UInt64 CODEC(Delta, ZSTD(1)),
    ips_drops UInt64 CODEC(Delta, ZSTD(1)),
    ddos_drops UInt64 CODEC(Delta, ZSTD(1)),
    redirected UInt64 CODEC(Delta, ZSTD(1))
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, tenant_id)
TTL timestamp + INTERVAL 30 DAY;

-- ============================================================================
-- VPN/FORTRESS TABLES (Multi-Tenant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS hookprobe_ids.fortress_events (
    timestamp DateTime64(3) CODEC(Delta, ZSTD(1)),
    tenant_id UInt32 CODEC(Delta, ZSTD(1)),
    fortress_id String CODEC(ZSTD(1)),
    event_type LowCardinality(String) CODEC(ZSTD(1)),
    src_ip IPv4 CODEC(ZSTD(1)),
    dst_ip IPv4 CODEC(ZSTD(1)),
    details Map(String, String) CODEC(ZSTD(1))
) ENGINE = MergeTree()
PARTITION BY (toYYYYMM(timestamp), tenant_id)
ORDER BY (tenant_id, timestamp, fortress_id)
TTL timestamp + INTERVAL 90 DAY;

-- ============================================================================
-- AGGREGATION VIEWS (Multi-Tenant Aware)
-- ============================================================================

-- Hourly intent summary (replaces mv_alerts_hourly)
-- Groups napse_intents by hour, tenant, intent_class, severity for dashboard trending.
CREATE MATERIALIZED VIEW IF NOT EXISTS hookprobe_ids.mv_intents_hourly
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, hour, intent_class, severity)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    tenant_id,
    intent_class,
    severity,
    count() AS intent_count,
    avg(confidence) AS avg_confidence,
    uniqExact(src_ip) AS unique_sources,
    uniqExact(dst_ip) AS unique_destinations
FROM hookprobe_ids.napse_intents
GROUP BY tenant_id, hour, intent_class, severity;

-- Top talkers by day (from flow summaries)
-- Groups napse_flows by day, tenant, and source IP for bandwidth analysis.
CREATE MATERIALIZED VIEW IF NOT EXISTS hookprobe_ids.mv_top_talkers_daily
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, day, src_ip)
AS SELECT
    toStartOfDay(timestamp) AS day,
    tenant_id,
    src_ip,
    sum(bytes_orig) AS bytes_sent,
    sum(bytes_resp) AS bytes_received,
    sum(pkts_orig) AS pkts_sent,
    sum(pkts_resp) AS pkts_received,
    uniqExact(dst_ip) AS unique_destinations
FROM hookprobe_ids.napse_flows
GROUP BY tenant_id, day, src_ip;

-- Real-time threat dashboard (multi-tenant)
-- Groups napse_intents by minute and tenant for live threat level display.
CREATE MATERIALIZED VIEW IF NOT EXISTS hookprobe_ids.mv_threat_dashboard
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(minute)
ORDER BY (tenant_id, minute, threat_level)
AS SELECT
    toStartOfMinute(timestamp) AS minute,
    tenant_id,
    multiIf(
        severity <= 1, 'critical',
        severity <= 2, 'high',
        severity <= 3, 'medium',
        'low'
    ) AS threat_level,
    count() AS event_count
FROM hookprobe_ids.napse_intents
GROUP BY tenant_id, minute, threat_level;
