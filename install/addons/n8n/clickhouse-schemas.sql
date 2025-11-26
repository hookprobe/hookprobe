-- ============================================================
-- HookProbe N8N Automation - ClickHouse Schemas
-- Version: 2.0 - QSECBIT Integration Edition
-- ============================================================

-- Create database if not exists
CREATE DATABASE IF NOT EXISTS security;

-- ============================================================
-- QSECBIT MONITORING
-- ============================================================

CREATE TABLE IF NOT EXISTS security.qsecbit_monitoring
(
    timestamp DateTime64(3) DEFAULT now64(),
    score Float64,
    rag_status Enum8('GREEN' = 1, 'AMBER' = 2, 'RED' = 3),
    drift Float64,
    attack_probability Float64,
    classifier_decay Float64,
    quantum_drift Float64,
    energy_anomaly Nullable(Float64),
    source_ip String,
    source_pod Enum8('POD-001' = 1, 'POD-002' = 2, 'POD-003' = 3, 'POD-004' = 4, 'POD-005' = 5, 'POD-006' = 6, 'POD-007' = 7, 'POD-008' = 8, 'POD-009' = 9),
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3,
    INDEX idx_score score TYPE minmax GRANULARITY 3,
    INDEX idx_rag rag_status TYPE set(3) GRANULARITY 3
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, rag_status, score)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ============================================================
-- THREAT INTELLIGENCE
-- ============================================================

CREATE TABLE IF NOT EXISTS security.threat_intelligence
(
    timestamp DateTime64(3) DEFAULT now64(),
    qsecbit_score Float64,
    source_ip String,
    dest_ip Nullable(String),
    attack_type Enum8('unknown' = 0, 'ddos' = 1, 'sql_injection' = 2, 'xss' = 3, 'port_scan' = 4, 'brute_force' = 5, 'malware' = 6, 'c2_communication' = 7, 'data_exfil' = 8),
    severity Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    nmap_result String,  -- JSON
    metasploit_result String,  -- JSON
    yara_result String,  -- JSON
    correlation_data String,  -- JSON
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3,
    INDEX idx_severity severity TYPE set(4) GRANULARITY 3,
    INDEX idx_source_ip source_ip TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, severity, source_ip)
TTL timestamp + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- ============================================================
-- THREAT ANALYSIS
-- ============================================================

CREATE TABLE IF NOT EXISTS security.threat_analysis
(
    timestamp DateTime64(3) DEFAULT now64(),
    correlation_required Bool,
    source_ip String,
    attack_type String,
    severity Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    qsecbit_score Float64,
    deep_analysis_result String,  -- JSON
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3,
    INDEX idx_source_ip source_ip TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, severity)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ============================================================
-- NMAP SCANS
-- ============================================================

CREATE TABLE IF NOT EXISTS security.nmap_scans
(
    timestamp DateTime64(3) DEFAULT now64(),
    target String,
    scan_type Enum8('active' = 1, 'passive' = 2),
    open_ports Array(UInt16),
    os_detection String,
    services String,  -- JSON array
    scan_duration_ms UInt32,
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3,
    INDEX idx_target target TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, target)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ============================================================
-- METASPLOIT SCANS
-- ============================================================

CREATE TABLE IF NOT EXISTS security.metasploit_scans
(
    timestamp DateTime64(3) DEFAULT now64(),
    target String,
    ports_scanned Array(UInt16),
    vulnerabilities String,  -- JSON array
    exploits_available UInt16,
    cve_references Array(String),
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3,
    INDEX idx_target target TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, target)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ============================================================
-- YARA SCANS
-- ============================================================

CREATE TABLE IF NOT EXISTS security.yara_scans
(
    timestamp DateTime64(3) DEFAULT now64(),
    file_hash String,
    files_scanned UInt32,
    matches String,  -- JSON array
    threat_detected Bool,
    malware_family Nullable(String),
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3,
    INDEX idx_file_hash file_hash TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, threat_detected)
TTL timestamp + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

-- ============================================================
-- AUTOMATED RESPONSES
-- ============================================================

CREATE TABLE IF NOT EXISTS security.automated_responses
(
    timestamp DateTime64(3) DEFAULT now64(),
    threat_data String,  -- JSON
    actions String,  -- JSON
    response_type Enum8('acl_update' = 1, 'node_isolation' = 2, 'cloudflare_update' = 3, 'combined' = 4),
    success Bool,
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, response_type)
TTL timestamp + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- ============================================================
-- ACL CHANGES
-- ============================================================

CREATE TABLE IF NOT EXISTS security.acl_changes
(
    timestamp DateTime64(3) DEFAULT now64(),
    action Enum8('block_ip' = 1, 'unblock_ip' = 2, 'block_port' = 3, 'allow_ip' = 4),
    ip_address String,
    port Nullable(UInt16),
    duration UInt32,
    applied Bool,
    rule_id Nullable(String),
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3,
    INDEX idx_ip_address ip_address TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, action, ip_address)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ============================================================
-- EDGE ISOLATIONS
-- ============================================================

CREATE TABLE IF NOT EXISTS security.edge_isolations
(
    timestamp DateTime64(3) DEFAULT now64(),
    node_id String,
    isolated Bool,
    vxlan_updated Bool,
    psk_rotated Bool DEFAULT false,
    reason String,
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3,
    INDEX idx_node_id node_id TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, node_id)
TTL timestamp + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- ============================================================
-- CLOUDFLARE UPDATES
-- ============================================================

CREATE TABLE IF NOT EXISTS security.cloudflare_updates
(
    timestamp DateTime64(3) DEFAULT now64(),
    ips_blocked UInt32,
    ip_blocklist Array(String),
    rule_updated Bool,
    rule_id Nullable(String),
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ============================================================
-- ATTACK SURFACE MAPPING
-- ============================================================

CREATE TABLE IF NOT EXISTS security.attack_surface
(
    timestamp DateTime64(3) DEFAULT now64(),
    device_id String,
    ip_address String,
    mac_address Nullable(String),
    hostname Nullable(String),
    open_ports Array(UInt16),
    services String,  -- JSON array
    os Nullable(String),
    last_seen DateTime64(3),
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3,
    INDEX idx_ip_address ip_address TYPE bloom_filter GRANULARITY 4,
    INDEX idx_device_id device_id TYPE bloom_filter GRANULARITY 4
)
ENGINE = ReplacingMergeTree(last_seen)
PARTITION BY toYYYYMM(timestamp)
ORDER BY (device_id, ip_address)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS security.attack_surface_changes
(
    timestamp DateTime64(3) DEFAULT now64(),
    new_devices String,  -- JSON array
    changed_ports String,  -- JSON array
    changed_services String,  -- JSON array
    qsecbit_risk_score Float64,
    alert_generated Bool DEFAULT false,
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3,
    INDEX idx_risk_score qsecbit_risk_score TYPE minmax GRANULARITY 3
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, qsecbit_risk_score)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ============================================================
-- NETWORK DISCOVERY
-- ============================================================

CREATE TABLE IF NOT EXISTS security.network_discovery
(
    timestamp DateTime64(3) DEFAULT now64(),
    scan_type Enum8('quick' = 1, 'full' = 2),
    devices_found UInt32,
    devices String,  -- JSON array
    scan_duration_ms UInt32,
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, scan_type)
TTL timestamp + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- ============================================================
-- CREDENTIAL ATTACK DEFENSE
-- ============================================================

CREATE TABLE IF NOT EXISTS security.credential_attacks
(
    timestamp DateTime64(3) DEFAULT now64(),
    source_ip String,
    target_service Enum8('ssh' = 1, 'http' = 2, 'https' = 3, 'ftp' = 4, 'smtp' = 5, 'other' = 99),
    attack_type Enum8('brute_force' = 1, 'credential_stuffing' = 2, 'dictionary_attack' = 3),
    attempts_count UInt32,
    banned Bool,
    ban_duration UInt32,
    qsecbit_resilience_score Float64,
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3,
    INDEX idx_source_ip source_ip TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, source_ip, target_service)
TTL timestamp + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

-- ============================================================
-- CONTAINER RUNTIME SECURITY
-- ============================================================

CREATE TABLE IF NOT EXISTS security.container_runtime_events
(
    timestamp DateTime64(3) DEFAULT now64(),
    container_id String,
    container_name String,
    event_type Enum8('privileged_escalation' = 1, 'unexpected_port' = 2, 'suspicious_syscall' = 3, 'file_modification' = 4, 'network_anomaly' = 5),
    severity Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    action_taken Enum8('logged' = 1, 'killed' = 2, 'rolled_back' = 3, 'isolated' = 4),
    details String,  -- JSON
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3,
    INDEX idx_container_id container_id TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, severity, container_id)
TTL timestamp + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- ============================================================
-- MATERIALIZED VIEWS FOR ANALYTICS
-- ============================================================

-- Hourly threat summary
CREATE MATERIALIZED VIEW IF NOT EXISTS security.threat_summary_hourly
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, severity, attack_type)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    severity,
    attack_type,
    count() AS threat_count,
    avg(qsecbit_score) AS avg_score,
    max(qsecbit_score) AS max_score
FROM security.threat_intelligence
GROUP BY hour, severity, attack_type;

-- Daily QSECBIT status summary
CREATE MATERIALIZED VIEW IF NOT EXISTS security.qsecbit_daily_summary
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (day, rag_status)
AS SELECT
    toDate(timestamp) AS day,
    rag_status,
    count() AS status_count,
    avg(score) AS avg_score,
    max(score) AS max_score,
    min(score) AS min_score
FROM security.qsecbit_monitoring
GROUP BY day, rag_status;

-- ============================================================
-- EXAMPLE QUERIES
-- ============================================================

-- Get recent high-severity threats
-- SELECT timestamp, source_ip, attack_type, qsecbit_score
-- FROM security.threat_intelligence
-- WHERE severity = 'high' AND timestamp >= now() - INTERVAL 24 HOUR
-- ORDER BY timestamp DESC
-- LIMIT 100;

-- Get attack surface changes in last 7 days
-- SELECT timestamp, new_devices, changed_ports, qsecbit_risk_score
-- FROM security.attack_surface_changes
-- WHERE timestamp >= now() - INTERVAL 7 DAY
-- ORDER BY qsecbit_risk_score DESC;

-- Get automated response statistics
-- SELECT
--     toStartOfDay(timestamp) AS day,
--     response_type,
--     count() AS response_count,
--     sum(case when success then 1 else 0 end) AS successful_responses
-- FROM security.automated_responses
-- WHERE timestamp >= now() - INTERVAL 30 DAY
-- GROUP BY day, response_type
-- ORDER BY day DESC, response_count DESC;
