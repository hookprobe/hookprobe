-- ============================================================================
-- AIOCHI L1 SOC Schema Extensions
-- Physical Layer Security Operations Center
--
-- Based on Trio+ validated approach:
-- - Gemini 3 Flash: Technical validation
-- - Nemotron: Security audit (defense-in-depth)
-- - Devstral: Algorithm verification
--
-- This schema enables treating L1 (Physical Layer) as a Security Sensor
-- for detecting IMSI catchers, jammers, and rogue cell towers.
-- ============================================================================

USE aiochi;

-- ============================================================================
-- CELLULAR METRICS
-- 5G/LTE signal telemetry from MBIM/QMI modems
-- ============================================================================

CREATE TABLE IF NOT EXISTS cellular_metrics (
    timestamp DateTime DEFAULT now(),
    device_id String,                     -- HookProbe device identifier
    modem_interface String,               -- "wwan0", "cdc-wdm0"

    -- Connection Type
    network_type Enum8('unknown' = 0, '2g' = 1, '3g' = 2, 'lte' = 3, '5g_nsa' = 4, '5g_sa' = 5),
    registration_state Enum8('unknown' = 0, 'idle' = 1, 'searching' = 2, 'registered' = 3, 'denied' = 4),

    -- Signal Strength Metrics (Critical for L1 Trust Score)
    rssi_dbm Int16,                       -- Received Signal Strength Indicator (-120 to -30)
    rsrp_dbm Int16,                       -- Reference Signal Received Power (-140 to -44)
    rsrq_db Int16,                        -- Reference Signal Received Quality (-20 to -3)
    sinr_db Int16,                        -- Signal-to-Interference-plus-Noise Ratio (-23 to 40)
    snr_db Float32,                       -- Signal-to-Noise Ratio (key jamming indicator)

    -- Band Information (for autonomous switching)
    current_band String,                  -- "n78", "b7", "b13", etc.
    earfcn UInt32,                        -- E-UTRA Absolute Radio Frequency Channel Number
    frequency_mhz Float32,                -- Actual frequency in MHz
    bandwidth_mhz UInt8,                  -- Channel bandwidth (5, 10, 15, 20, etc.)

    -- Tower Identification (Critical for rogue tower detection)
    cell_id UInt32,                       -- Cell ID from network
    physical_cell_id UInt16,              -- Physical Cell ID (PCI)
    tracking_area_code UInt32,            -- TAC for location verification
    mcc String,                           -- Mobile Country Code
    mnc String,                           -- Mobile Network Code
    plmn String,                          -- Combined MCC+MNC

    -- Quality Metrics
    cqi UInt8,                            -- Channel Quality Indicator (0-15)
    timing_advance UInt16,                -- Distance indicator (0-1282, ~78m per unit)

    -- L1 Trust Score (calculated)
    l1_trust_score Float32,               -- 0.0-100.0
    l1_trust_state Enum8('trusted' = 1, 'suspicious' = 2, 'hostile' = 3, 'unknown' = 4),

    INDEX idx_device device_id TYPE bloom_filter GRANULARITY 1,
    INDEX idx_cell cell_id TYPE bloom_filter GRANULARITY 1,
    INDEX idx_trust l1_trust_state TYPE minmax GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, device_id)
TTL timestamp + INTERVAL 30 DAY;


-- ============================================================================
-- TOWER REGISTRY
-- Known tower database (whitelist) + OpenCellID integration
-- ============================================================================

CREATE TABLE IF NOT EXISTS tower_registry (
    cell_id UInt32,
    physical_cell_id UInt16,
    mcc String,
    mnc String,
    tracking_area_code UInt32,

    -- Location Data
    latitude Float64,
    longitude Float64,
    location_accuracy_m UInt32,           -- Estimated accuracy in meters

    -- Tower Metadata
    carrier_name String,
    tower_type Enum8('macro' = 1, 'small_cell' = 2, 'femto' = 3, 'unknown' = 4),
    expected_bands Array(String),         -- ["b7", "b13", "n78"]
    expected_neighbors Array(UInt32),     -- Expected neighbor cell IDs

    -- Trust Status
    source Enum8('whitelist' = 1, 'opencellid' = 2, 'carrier' = 3, 'user_reported' = 4, 'auto_learned' = 5),
    reputation_score Float32,             -- 0.0-1.0
    first_seen DateTime DEFAULT now(),
    last_seen DateTime DEFAULT now(),
    observation_count UInt32 DEFAULT 1,

    -- Blacklist Status (with time decay per Nemotron recommendation)
    is_blacklisted Bool DEFAULT false,
    blacklist_reason String,
    blacklist_timestamp Nullable(DateTime),
    blacklist_indicators UInt8 DEFAULT 0, -- Requires >= 3 per security audit

    INDEX idx_cell cell_id TYPE bloom_filter GRANULARITY 1,
    INDEX idx_location (latitude, longitude) TYPE minmax GRANULARITY 1
) ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (mcc, mnc, cell_id, physical_cell_id);


-- ============================================================================
-- L1 ANOMALY EVENTS
-- Security events detected at Physical Layer
-- ============================================================================

CREATE TABLE IF NOT EXISTS l1_anomaly_events (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    device_id String,

    -- Anomaly Classification (MITRE ATT&CK aligned)
    anomaly_type Enum8(
        'unknown_tower' = 1,
        'rogue_tower' = 2,
        'imsi_catcher' = 3,
        'jamming' = 4,
        'downgrade_attack' = 5,
        'timing_anomaly' = 6,
        'handover_storm' = 7,
        'signal_spoofing' = 8,
        'gps_tower_mismatch' = 9,
        'encryption_downgrade' = 10,
        'battery_drain_attack' = 11
    ),
    severity Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    confidence Float32,                   -- 0.0-1.0

    -- Detection Evidence (multiple indicators per Nemotron)
    evidence String,                      -- JSON blob with detection details
    indicators_count UInt8,               -- Number of corroborating indicators

    -- Tower Info
    cell_id UInt32,
    physical_cell_id UInt16,
    reported_location_lat Float64,
    reported_location_lon Float64,
    gps_location_lat Float64,
    gps_location_lon Float64,
    location_mismatch_m Float32,          -- Distance between reported and GPS

    -- Signal Metrics at Time of Detection
    rsrp_dbm Int16,
    sinr_db Int16,
    snr_db Float32,

    -- Response
    action_taken String,                  -- "blacklist", "survival_mode", "alert_only"
    playbook_triggered String,
    auto_resolved Bool DEFAULT false,
    resolution_notes String,

    INDEX idx_device device_id TYPE bloom_filter GRANULARITY 1,
    INDEX idx_type anomaly_type TYPE minmax GRANULARITY 1,
    INDEX idx_severity severity TYPE minmax GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, severity, anomaly_type)
TTL timestamp + INTERVAL 90 DAY;


-- ============================================================================
-- HANDOVER TRACKING
-- Track cell handovers for ping-pong and IMSI catcher detection
-- ============================================================================

CREATE TABLE IF NOT EXISTS handover_events (
    timestamp DateTime DEFAULT now(),
    device_id String,

    -- Source Tower
    from_cell_id UInt32,
    from_pci UInt16,
    from_rsrp_dbm Int16,
    from_sinr_db Int16,

    -- Target Tower
    to_cell_id UInt32,
    to_pci UInt16,
    to_rsrp_dbm Int16,
    to_sinr_db Int16,

    -- Handover Metadata
    handover_type Enum8('normal' = 1, 'fast' = 2, 'blind' = 3, 'forced' = 4),
    handover_cause Enum8(
        'signal_quality' = 1,
        'load_balancing' = 2,
        'mobility' = 3,
        'coverage' = 4,
        'emergency' = 5,
        'suspicious' = 6
    ),
    duration_ms UInt32,                   -- How long the handover took

    -- Anomaly Detection
    is_suspicious Bool DEFAULT false,
    distance_km Float32,                  -- Distance between towers (for ping-pong detection)

    INDEX idx_device device_id TYPE bloom_filter GRANULARITY 1,
    INDEX idx_from_cell from_cell_id TYPE bloom_filter GRANULARITY 1,
    INDEX idx_to_cell to_cell_id TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, device_id)
TTL timestamp + INTERVAL 14 DAY;


-- ============================================================================
-- L1 TRUST SCORE HISTORY
-- Historical trust scores for trend analysis
-- ============================================================================

CREATE TABLE IF NOT EXISTS l1_trust_score_history (
    timestamp DateTime DEFAULT now(),
    device_id String,

    -- Overall Trust Score
    trust_score Float32,                  -- 0.0-100.0
    trust_state Enum8('trusted' = 1, 'suspicious' = 2, 'hostile' = 3, 'unknown' = 4),

    -- Component Scores (per Devstral-validated algorithm)
    signal_stability_score Float32,       -- W=0.15 (adjusted)
    snr_score Float32,                    -- W=0.20 (adjusted)
    tower_identity_score Float32,         -- W=0.35 (increased for security)
    temporal_consistency_score Float32,   -- W=0.15
    handover_score Float32,               -- W=0.10
    unexpected_pairs_score Float32,       -- W=0.05 (new per Devstral)

    -- Hard Threshold Overrides (per security audit)
    forced_zero Bool DEFAULT false,       -- True if unknown tower forced score to 0
    capped_score Nullable(Float32),       -- If SNR or handover triggered cap
    cap_reason String,

    -- Context
    current_cell_id UInt32,
    current_pci UInt16,
    rsrp_variance Float32,                -- For stability calculation
    handover_count_hour UInt16,

    INDEX idx_device device_id TYPE bloom_filter GRANULARITY 1,
    INDEX idx_state trust_state TYPE minmax GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, device_id)
TTL timestamp + INTERVAL 30 DAY;


-- ============================================================================
-- SURVIVAL MODE LOG
-- Track survival mode activations and responses
-- ============================================================================

CREATE TABLE IF NOT EXISTS survival_mode_log (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    device_id String,

    -- Trigger
    trigger_reason String,                -- "l1_trust_below_20", "jamming_detected", etc.
    l1_trust_score_at_trigger Float32,
    anomaly_event_id Nullable(UUID),

    -- Actions Taken (per Gemini validation)
    vpn_enabled Bool DEFAULT false,
    vpn_pre_established Bool DEFAULT false,  -- Per Nemotron: pre-establish before survival
    protocol_lockdown Bool DEFAULT false,     -- Disabled 2G/3G
    band_locked String,                       -- Locked to specific band
    cell_blacklisted Bool DEFAULT false,
    airplane_pulse_mode Bool DEFAULT false,   -- Per Gemini: pulse to conserve battery

    -- Duration
    exit_timestamp Nullable(DateTime),
    duration_seconds UInt32 DEFAULT 0,
    exit_reason String,

    -- Outcome
    attack_confirmed Bool DEFAULT false,
    false_positive Bool DEFAULT false,

    INDEX idx_device device_id TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, device_id)
TTL timestamp + INTERVAL 180 DAY;


-- ============================================================================
-- AUTONOMOUS ACTIONS LOG
-- Track all autonomous modem reconfigurations (per Nemotron audit)
-- ============================================================================

CREATE TABLE IF NOT EXISTS autonomous_actions_log (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    device_id String,

    -- Action
    action_type Enum8(
        'band_switch' = 1,
        'rat_change' = 2,          -- Radio Access Technology change
        'cell_blacklist' = 3,
        'modem_reset' = 4,
        'survival_mode_enter' = 5,
        'survival_mode_exit' = 6,
        'vpn_trigger' = 7,
        'apn_cycle' = 8
    ),
    action_details String,         -- JSON with specifics

    -- Pre-action State
    pre_action_state String,       -- JSON snapshot
    pre_action_trust_score Float32,

    -- Post-action State
    post_action_state String,      -- JSON snapshot
    post_action_trust_score Float32,

    -- Rate Limiting (per Nemotron: prevent battery exhaustion)
    actions_last_5min UInt8,       -- Count for rate limiting
    action_blocked Bool DEFAULT false,
    block_reason String,

    -- Validation
    triggered_by Enum8('automatic' = 1, 'manual' = 2, 'playbook' = 3),
    corroborating_evidence_count UInt8,  -- Must be >= 3 per security audit

    INDEX idx_device device_id TYPE bloom_filter GRANULARITY 1,
    INDEX idx_action action_type TYPE minmax GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, device_id)
TTL timestamp + INTERVAL 90 DAY;


-- ============================================================================
-- MATERIALIZED VIEWS FOR L1 SOC DASHBOARD
-- ============================================================================

-- Hourly L1 Trust Score Average
CREATE MATERIALIZED VIEW IF NOT EXISTS l1_trust_hourly_mv
ENGINE = SummingMergeTree()
ORDER BY (hour, device_id, trust_state)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    device_id,
    trust_state,
    avg(trust_score) AS avg_trust_score,
    min(trust_score) AS min_trust_score,
    max(trust_score) AS max_trust_score,
    count() AS sample_count
FROM l1_trust_score_history
GROUP BY hour, device_id, trust_state;

-- Daily Anomaly Summary
CREATE MATERIALIZED VIEW IF NOT EXISTS l1_anomaly_daily_mv
ENGINE = SummingMergeTree()
ORDER BY (day, anomaly_type, severity)
AS SELECT
    toDate(timestamp) AS day,
    anomaly_type,
    severity,
    count() AS count,
    avg(confidence) AS avg_confidence
FROM l1_anomaly_events
GROUP BY day, anomaly_type, severity;

-- Handover Frequency (for ping-pong detection)
CREATE MATERIALIZED VIEW IF NOT EXISTS handover_frequency_mv
ENGINE = SummingMergeTree()
ORDER BY (hour, device_id)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    device_id,
    count() AS handover_count,
    countIf(is_suspicious) AS suspicious_count,
    avg(distance_km) AS avg_distance_km
FROM handover_events
GROUP BY hour, device_id;

-- Tower Activity (for rogue tower detection)
CREATE MATERIALIZED VIEW IF NOT EXISTS tower_activity_mv
ENGINE = SummingMergeTree()
ORDER BY (hour, cell_id, physical_cell_id)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    cell_id,
    physical_cell_id,
    count() AS connection_count,
    uniq(device_id) AS unique_devices,
    avg(rsrp_dbm) AS avg_rsrp,
    avg(sinr_db) AS avg_sinr
FROM cellular_metrics
WHERE cell_id != 0
GROUP BY hour, cell_id, physical_cell_id;
