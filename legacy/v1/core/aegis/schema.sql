-- AEGIS Memory Schema
-- SQLite tables for persistent multi-layer memory.
--
-- Tables:
--   aegis_sessions       — Daily event summaries (session layer)
--   aegis_device_profiles — Per-device learned patterns (behavioral layer)
--   aegis_network_knowledge — Network knowledge base (institutional layer)
--   aegis_threat_intel   — Attack patterns and IOCs (threat_intel layer)
--   aegis_decisions      — Agent action audit trail

CREATE TABLE IF NOT EXISTS aegis_sessions (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL DEFAULT (datetime('now')),
    summary     TEXT NOT NULL,
    events_json TEXT NOT NULL DEFAULT '[]',
    ttl_days    INTEGER DEFAULT 30
);

CREATE TABLE IF NOT EXISTS aegis_device_profiles (
    mac         TEXT PRIMARY KEY,
    profile_json TEXT NOT NULL DEFAULT '{}',
    confidence  REAL NOT NULL DEFAULT 0.0,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS aegis_network_knowledge (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT 'system',
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS aegis_threat_intel (
    threat_hash TEXT PRIMARY KEY,
    type        TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'LOW',
    context_json TEXT NOT NULL DEFAULT '{}',
    first_seen  TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen   TEXT NOT NULL DEFAULT (datetime('now')),
    count       INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS aegis_decisions (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL DEFAULT (datetime('now')),
    agent       TEXT NOT NULL,
    action      TEXT NOT NULL,
    params_json TEXT NOT NULL DEFAULT '{}',
    confidence  REAL NOT NULL DEFAULT 0.0,
    reasoning   TEXT NOT NULL DEFAULT '',
    result      TEXT NOT NULL DEFAULT '',
    approved    INTEGER NOT NULL DEFAULT 0
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_sessions_timestamp ON aegis_sessions(timestamp);
CREATE INDEX IF NOT EXISTS idx_device_profiles_updated ON aegis_device_profiles(updated_at);
CREATE INDEX IF NOT EXISTS idx_threat_intel_severity ON aegis_threat_intel(severity);
CREATE INDEX IF NOT EXISTS idx_threat_intel_last_seen ON aegis_threat_intel(last_seen);
CREATE INDEX IF NOT EXISTS idx_decisions_timestamp ON aegis_decisions(timestamp);
CREATE INDEX IF NOT EXISTS idx_decisions_agent ON aegis_decisions(agent);
