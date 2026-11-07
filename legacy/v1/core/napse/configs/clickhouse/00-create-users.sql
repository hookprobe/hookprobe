-- HookProbe IDS: Create application users (runs before init.sql)
-- This runs as the 'default' user which has access_management=1
--
-- SECURITY: Passwords are injected via environment variables at deploy time.
-- The install script generates random passwords and substitutes them here.
-- Do NOT commit plaintext passwords to this file.

CREATE USER IF NOT EXISTS ids
    IDENTIFIED WITH sha256_password BY '${CLICKHOUSE_IDS_PASSWORD}'
    HOST LOCAL
    DEFAULT DATABASE hookprobe_ids
    SETTINGS max_execution_time = 60, allow_experimental_vector_similarity_index = 1;

CREATE USER IF NOT EXISTS readonly
    IDENTIFIED WITH sha256_password BY '${CLICKHOUSE_READONLY_PASSWORD}'
    HOST LOCAL
    SETTINGS readonly = 1, max_execution_time = 60;

-- Grant IDS user access (no GRANT OPTION - CWE-250 least privilege)
GRANT ALL ON hookprobe_ids.* TO ids;
GRANT SELECT ON hookprobe_ids.* TO readonly;
GRANT SELECT ON system.* TO ids;
GRANT SELECT ON system.* TO readonly;
