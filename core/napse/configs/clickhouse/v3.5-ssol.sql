-- ============================================================================
-- ClickHouse Schema v3.5 — Self-Supervised Outcome Loop (SSOL)
--
-- Ch 27/28 Sprint 1 — the keystone table. The CNO/Senzorium stack acts
-- (block/allow) but never recorded whether it was right. This ledger turns
-- the network's own reaction into weak, confidence-scored labels: thousands
-- a day vs. the ~10 operator decisions the trainers previously relied on.
--
-- Consumers (later sprints): SENTINEL calibrator (both-class anchor — kills
-- the all-TP isotonic collapse), the learned stacker (Sprint 2), the online
-- learner (Sprint 3), and the autonomy governor's measured-precision budget
-- (Sprint 4). For Sprint 1 the table is write-only — no enforcement risk.
--
-- Run on: hookprobe_ids database
--   clickhouse-client --database hookprobe_ids < v3.5-ssol.sql
--
-- Author: HookProbe Team
-- Version: 3.5
-- ============================================================================

-- ------------------------------------------------------------------
-- CNO Outcome Ledger — self-supervised ground truth
-- ------------------------------------------------------------------
-- One row per reconciled decision. weak_label/label_conf are derived from
-- observable evidence (threat-feed/IoC membership, historical malicious
-- verdicts, operator false-positive overrides, scan fan-out, RDAP class,
-- pre/post packet-rate delta) — NOT from a human verdict. Operator labels
-- remain the high-weight anchor; these enter training at conf-scaled weight.

CREATE TABLE IF NOT EXISTS hookprobe_ids.cno_outcome_ledger
(
    ts              DateTime        DEFAULT now(),
    src_ip          String,
    action          LowCardinality(String) DEFAULT 'block',      -- block | allow | quarantine
    decider         LowCardinality(String) DEFAULT 'cno_reflex', -- cno_reflex|anomaly_ml|sentinel|predictive|stacker
    pre_score       Float32         DEFAULT 0,                    -- detector score at decision time
    weak_label      LowCardinality(String) DEFAULT 'ambiguous',  -- malicious | benign | ambiguous
    label_conf      Float32         DEFAULT 0,                    -- 0..1 confidence in the weak label
    evidence        String          DEFAULT '',                  -- which signals fired (audit / debug)
    reconciled_at   DateTime        DEFAULT now(),
    fed_to_training UInt8           DEFAULT 0,                    -- consumer claim flag (idempotent drain)

    INDEX idx_src_ip     src_ip     TYPE bloom_filter() GRANULARITY 4,
    INDEX idx_weak_label weak_label TYPE set(0) GRANULARITY 4,
    INDEX idx_decider    decider    TYPE set(0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, src_ip)
TTL ts + INTERVAL 90 DAY;
