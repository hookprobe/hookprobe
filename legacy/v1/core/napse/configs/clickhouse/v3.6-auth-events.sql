-- ============================================================================
-- ClickHouse Schema v3.6 — Keycloak authentication telemetry (Phase 5)
--
-- Why: the `hookprobe` realm never persisted events, so credential attacks on
-- auth.hookprobe.com were invisible to HYDRA/SENTINEL. The host shipper
-- (hookprobe-com containers/keycloak/telemetry/kc_auth_shipper.py) polls the
-- Keycloak admin events API, redacts, attributes tenants server-side and
-- writes here; detections ALSO emit hookprobe_ids.hydra_events rows
-- (action='alert', feed_source='keycloak', reason in auth_fail /
-- password_spray / credential_stuffing / auth_distributed / auth_lockout) so
-- SENTINEL scores the source IP with no new consumer.
--
-- Privacy: no raw usernames/emails (username_hash = HMAC-SHA256, host key),
-- no passwords/tokens/codes/session ids; details is an allowlisted JSON blob.
--
-- Run on: hookprobe_ids database (additive, IF NOT EXISTS — safe to re-run)
--   clickhouse-client --database hookprobe_ids --multiquery < v3.6-auth-events.sql
-- ============================================================================

CREATE TABLE IF NOT EXISTS hookprobe_ids.auth_events
(
    ts            DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
    event_key     String CODEC(ZSTD(1)),                 -- Keycloak event id (or digest) — dedup key
    kind          LowCardinality(String),                -- 'user' | 'admin'
    event_type    LowCardinality(String),                -- LOGIN_ERROR, ADMIN_UPDATE, ...
    realm         LowCardinality(String),
    client_id     LowCardinality(String) DEFAULT '',
    user_id       String DEFAULT '' CODEC(ZSTD(1)),      -- Keycloak subject (UUID) assigned by the server
    username_hash String DEFAULT '' CODEC(ZSTD(1)),      -- HMAC-SHA256(lower(username))[:32]
    ip            String DEFAULT '' CODEC(ZSTD(1)),      -- client IP as Keycloak saw it (v4 or v6)
    ip_v4         IPv4 MATERIALIZED toIPv4OrDefault(ip),
    error         LowCardinality(String) DEFAULT '',     -- invalid_user_credentials, user_not_found, ...
    is_failure    UInt8 DEFAULT 0,
    site_ids      Array(String) DEFAULT [],              -- tenants via userId -> user_site_access (server-side)
    resource_type LowCardinality(String) DEFAULT '',     -- admin events only
    details       String DEFAULT '{}' CODEC(ZSTD(3)),    -- allowlisted, redacted JSON
    ingested_at   DateTime DEFAULT now(),
    INDEX idx_ip ip TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_user user_id TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_uhash username_hash TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_type event_type TYPE set(0) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, event_key)
TTL toDateTime(ts) + INTERVAL 180 DAY;

CREATE TABLE IF NOT EXISTS hookprobe_ids.auth_detections
(
    ts             DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
    detection_key  String CODEC(ZSTD(1)),                -- reason|account-or-ip (suppression key)
    reason         LowCardinality(String),               -- auth_fail | password_spray | credential_stuffing | auth_distributed | auth_lockout
    severity       LowCardinality(String),
    src_ips        Array(String),
    account_key    String DEFAULT '',                    -- 'u:<userId>' or 'h:<username_hash>'
    site_ids       Array(String) DEFAULT [],
    window_s       UInt32,
    event_count    UInt32,
    distinct_users UInt32,
    distinct_ips   UInt32,
    first_seen     DateTime64(3, 'UTC'),
    last_seen      DateTime64(3, 'UTC'),
    ingested_at    DateTime DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, reason)
TTL toDateTime(ts) + INTERVAL 365 DAY;
