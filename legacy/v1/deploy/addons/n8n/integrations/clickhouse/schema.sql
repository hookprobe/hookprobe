-- ClickHouse Schema for HookProbe Automation
-- Version: 1.0

-- Main security events table
CREATE TABLE IF NOT EXISTS security_events (
    timestamp DateTime64(3) DEFAULT now64(),
    source_ip IPv4,
    destination_ip IPv4,
    source_port UInt16,
    destination_port UInt16,
    protocol LowCardinality(String),
    event_type LowCardinality(String),
    severity LowCardinality(String),
    qsecbit_score Float32,
    confidence Float32,
    threat_type LowCardinality(String),
    indicators Array(String),
    raw_data String,
    tenant_id LowCardinality(String) DEFAULT 'default',
    processed Bool DEFAULT false,
    INDEX idx_source_ip source_ip TYPE minmax GRANULARITY 1,
    INDEX idx_qsecbit_score qsecbit_score TYPE minmax GRANULARITY 1,
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 1
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, tenant_id, source_ip)
TTL timestamp + INTERVAL 90 DAY  -- GDPR compliance: 90 days retention
SETTINGS index_granularity = 8192;

-- Threat correlation table
CREATE TABLE IF NOT EXISTS threat_correlation (
    timestamp DateTime64(3) DEFAULT now64(),
    event_id UUID,
    source_ip IPv4,
    threat_type LowCardinality(String),
    correlation_source LowCardinality(String),  -- 'nmap', 'metasploit', 'yara', 'osint'
    ioc_value String,
    ioc_type LowCardinality(String),  -- 'ip', 'domain', 'hash', 'signature'
    confidence Float32,
    metadata String,  -- JSON string
    tenant_id LowCardinality(String) DEFAULT 'default'
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, tenant_id, source_ip)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Automated responses table
CREATE TABLE IF NOT EXISTS automated_responses (
    timestamp DateTime64(3) DEFAULT now64(),
    event_id UUID,
    response_action LowCardinality(String),  -- 'ISOLATE_DEVICE', 'BLOCK_IP', 'RATE_LIMIT'
    target_ip IPv4,
    severity LowCardinality(String),
    success Bool,
    response_duration_ms UInt32,
    commands Array(String),
    error_message String,
    tenant_id LowCardinality(String) DEFAULT 'default'
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, tenant_id, target_ip)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- QSECBIT score timeline
CREATE TABLE IF NOT EXISTS qsecbit_scores (
    timestamp DateTime64(3) DEFAULT now64(),
    tenant_id LowCardinality(String) DEFAULT 'default',
    source_ip IPv4,
    score Float32,
    confidence Float32,
    threat_type LowCardinality(String),
    indicators_count UInt16
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, tenant_id, source_ip)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Materialized view for real-time threat statistics
CREATE MATERIALIZED VIEW IF NOT EXISTS threat_stats_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, tenant_id, threat_type)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    tenant_id,
    threat_type,
    COUNT(*) AS event_count,
    AVG(qsecbit_score) AS avg_score,
    MAX(qsecbit_score) AS max_score,
    uniqExact(source_ip) AS unique_sources
FROM security_events
GROUP BY hour, tenant_id, threat_type;

-- Materialized view for response effectiveness
CREATE MATERIALIZED VIEW IF NOT EXISTS response_effectiveness_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, tenant_id, response_action)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    tenant_id,
    response_action,
    COUNT(*) AS total_actions,
    AVG(response_duration_ms) AS avg_duration_ms,
    SUM(CASE WHEN success = true THEN 1 ELSE 0 END) AS success_count,
    COUNT(*) AS total_count
FROM automated_responses
GROUP BY hour, tenant_id, response_action;

-- Create database if not exists
CREATE DATABASE IF NOT EXISTS hookprobe;
