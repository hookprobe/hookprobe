-- AIOCHI ClickHouse Initialization
-- This file is executed by ClickHouse on first startup
--
-- NOTE: The main schema is mounted directly in podman-compose.aiochi.yml
-- This file exists for compatibility and can contain additional initialization
--
-- See: shared/aiochi/schemas/clickhouse-init.sql for full schema

-- Verify database exists (schema file creates it)
SELECT 'AIOCHI ClickHouse initialized' AS status;
