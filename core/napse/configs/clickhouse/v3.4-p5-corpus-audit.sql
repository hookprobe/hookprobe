-- Ch 26 Phase 5 — corpus audit table.
--
-- Tracks every change to the ai-waf training corpus (fine_tune/data/*.jsonl).
-- An adversary who gains ml_corpus write access could otherwise poison the
-- model silently — a training-time attack that survives across model
-- rotations and defeats the Phase 4 runtime-only resilience.
--
-- Write pattern: the ai-waf/fine_tune/corpus_audit.py helper is called
-- BEFORE any append/modify/delete of corpus files. It computes the
-- pre-change sha256, performs the operation, then inserts this row with
-- the post-change sha256 and the operator identity (Keycloak subject if
-- running under the dashboard, "cli:<OS_USER>" if operator-run).
--
-- Detection pattern: nightly query for rows where operator is unexpected
-- or action='manual_edit' — alerts via Discord report if found.

CREATE TABLE IF NOT EXISTS hookprobe_ids.ml_corpus_audit
(
    ts                DateTime64(3, 'UTC')     DEFAULT now64(3),
    operator          LowCardinality(String),   -- keycloak sub, or cli:<user>
    action            LowCardinality(String),   -- append|remove|modify|sign|rotate
    corpus_path       String,                   -- e.g. fine_tune/data/corpus.jsonl
    rows_before       UInt32,
    rows_after        UInt32,
    sha256_before     FixedString(64),
    sha256_after      FixedString(64),
    git_commit        FixedString(40)           DEFAULT '',
    reason            String                    DEFAULT '',
    -- fp-triage details: if this change is a reaction to an observed FP,
    -- link it here so downstream re-training pipelines can distinguish
    -- "intentional retraining on new attack" from "oops, undo this."
    triage_ticket     String                    DEFAULT ''
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, operator, corpus_path)
-- TTL needs a DateTime (not DateTime64) expression in CH 24.x.
TTL toDateTime(ts) + INTERVAL 365 DAY;

-- Convenience view: recent operator activity for the Alexandria librarian
-- to cite when auditing model provenance.
CREATE VIEW IF NOT EXISTS hookprobe_ids.ml_corpus_audit_recent AS
SELECT
    ts,
    operator,
    action,
    corpus_path,
    rows_after - rows_before AS delta_rows,
    substr(sha256_before, 1, 16) AS sha256_before_short,
    substr(sha256_after, 1, 16) AS sha256_after_short,
    substr(git_commit, 1, 8) AS git_short,
    reason,
    triage_ticket
FROM hookprobe_ids.ml_corpus_audit
WHERE ts > now() - INTERVAL 90 DAY
ORDER BY ts DESC;
