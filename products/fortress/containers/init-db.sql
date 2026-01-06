-- HookProbe Fortress Database Initialization
-- This file is mounted into postgres and runs on first startup
--
-- Version: 5.5.0
-- Schema Version: 1
-- License: AGPL-3.0

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ============================================================
-- SCHEMA VERSION TABLE (Migrations tracking)
-- ============================================================
CREATE TABLE IF NOT EXISTS schema_version (
    id SERIAL PRIMARY KEY,
    version INTEGER NOT NULL,
    description TEXT NOT NULL,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    applied_by VARCHAR(100) DEFAULT current_user,
    checksum VARCHAR(64)
);

-- Initialize schema version
INSERT INTO schema_version (version, description) VALUES
    (1, 'Initial schema - devices, vlans, policies, threats, dns, audit')
ON CONFLICT DO NOTHING;

-- ============================================================
-- DEVICES TABLE (Connected clients)
-- ============================================================
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mac_address VARCHAR(17) UNIQUE NOT NULL,
    ip_address INET,
    hostname VARCHAR(255),
    device_type VARCHAR(50),
    manufacturer VARCHAR(255),
    vlan_id INTEGER DEFAULT 100,  -- Default to LAN VLAN (physical)
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_blocked BOOLEAN DEFAULT FALSE,
    is_known BOOLEAN DEFAULT FALSE,
    notes TEXT,
    -- Network policy (alternative to VLAN)
    network_policy VARCHAR(50) DEFAULT 'default',
    internet_access BOOLEAN DEFAULT TRUE,
    lan_access BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_vlan ON devices(vlan_id);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
CREATE INDEX IF NOT EXISTS idx_devices_policy ON devices(network_policy);

-- ============================================================
-- VLANS TABLE (Optional - VLAN segmentation)
-- ============================================================
CREATE TABLE IF NOT EXISTS vlans (
    id SERIAL PRIMARY KEY,
    vlan_id INTEGER UNIQUE NOT NULL,
    name VARCHAR(50) NOT NULL,
    description TEXT,
    subnet CIDR NOT NULL,
    gateway INET,
    dhcp_enabled BOOLEAN DEFAULT TRUE,
    dhcp_range_start INET,
    dhcp_range_end INET,
    dns_policy VARCHAR(20) DEFAULT 'standard',
    bandwidth_limit_mbps INTEGER,
    is_isolated BOOLEAN DEFAULT FALSE,
    is_logical BOOLEAN DEFAULT FALSE,  -- True for segment VLANs (OpenFlow tags within physical VLAN)
    trust_floor INTEGER DEFAULT 0,     -- Minimum trust level required (0-4)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Default VLANs for VLAN mode network segmentation
-- FLAT BRIDGE ARCHITECTURE
-- All devices share the same L2 segment on FTS bridge (10.200.0.0/xx)
-- Segmentation is via OpenFlow NAC rules, not physical VLANs
-- "VLAN IDs" are logical segment identifiers for device classification
-- Trust levels: 0=UNTRUSTED, 1=MINIMAL, 2=STANDARD, 3=HIGH, 4=ENTERPRISE
INSERT INTO vlans (vlan_id, name, description, subnet, gateway, is_isolated, is_logical, trust_floor)
VALUES
    -- Default LAN segment (all devices start here)
    (0, 'LAN', 'Default LAN segment (flat bridge)', '10.200.0.0/23', '10.200.0.1', false, true, 0),
    -- Logical segments (device classification via OpenFlow NAC rules)
    (10, 'SecMON', 'Security monitoring devices (NVR, SIEM)', '10.200.0.0/23', '10.200.0.1', false, true, 3),
    (20, 'POS', 'Point of Sale terminals (isolated)', '10.200.0.0/23', '10.200.0.1', true, true, 3),
    (30, 'Staff', 'Staff devices (laptops, phones)', '10.200.0.0/23', '10.200.0.1', false, true, 2),
    (40, 'Guest', 'Guest WiFi network (isolated)', '10.200.0.0/23', '10.200.0.1', true, true, 1),
    (50, 'Cameras', 'IP cameras and CCTV (isolated)', '10.200.0.0/23', '10.200.0.1', true, true, 2),
    (60, 'IIoT', 'Industrial IoT / Smart devices (isolated)', '10.200.0.0/23', '10.200.0.1', true, true, 2),
    (99, 'Quarantine', 'Unknown/suspicious devices (isolated)', '10.200.0.0/23', '10.200.0.1', true, true, 0)
ON CONFLICT (vlan_id) DO NOTHING;

-- ============================================================
-- NETWORK POLICIES TABLE (Alternative to VLANs)
-- ============================================================
CREATE TABLE IF NOT EXISTS network_policies (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    -- Access controls
    internet_access BOOLEAN DEFAULT TRUE,
    lan_access BOOLEAN DEFAULT TRUE,
    -- Destination restrictions (JSON array of CIDRs or IPs)
    allowed_destinations JSONB DEFAULT '[]'::jsonb,
    blocked_destinations JSONB DEFAULT '[]'::jsonb,
    -- Port restrictions
    allowed_ports JSONB DEFAULT '[]'::jsonb,  -- e.g. [80, 443, 22]
    blocked_ports JSONB DEFAULT '[]'::jsonb,
    -- Rate limiting
    bandwidth_limit_kbps INTEGER,
    -- DNS policy
    dns_policy VARCHAR(20) DEFAULT 'standard',
    -- Logging level
    log_level VARCHAR(10) DEFAULT 'normal',  -- none, normal, verbose
    -- Active status
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Default network policies
INSERT INTO network_policies (name, description, internet_access, lan_access)
VALUES
    ('full_access', 'Full internet and LAN access (staff)', TRUE, TRUE),
    ('lan_only', 'LAN access only - no internet (sensors, IoT)', FALSE, TRUE),
    ('internet_only', 'Internet access only - no LAN (guests)', TRUE, FALSE),
    ('isolated', 'Completely isolated - no network access', FALSE, FALSE),
    ('default', 'Default policy for unknown devices', TRUE, TRUE)
ON CONFLICT (name) DO NOTHING;

-- ============================================================
-- OUI CLASSIFICATIONS TABLE (Device type by manufacturer)
-- ============================================================
CREATE TABLE IF NOT EXISTS oui_classifications (
    id SERIAL PRIMARY KEY,
    oui VARCHAR(8) UNIQUE NOT NULL,  -- XX:XX:XX format
    manufacturer VARCHAR(255) NOT NULL,
    device_category VARCHAR(50) NOT NULL,  -- iot, pos, workstation, mobile, printer, camera
    default_policy VARCHAR(50) DEFAULT 'default',
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Common OUI classifications
INSERT INTO oui_classifications (oui, manufacturer, device_category, default_policy) VALUES
    -- IoT devices
    ('B8:27:EB', 'Raspberry Pi Foundation', 'iot', 'lan_only'),
    ('DC:A6:32', 'Raspberry Pi Trading', 'iot', 'lan_only'),
    ('24:0A:C4', 'Espressif (ESP8266/ESP32)', 'iot', 'lan_only'),
    ('3C:71:BF', 'Espressif', 'iot', 'lan_only'),
    ('5C:CF:7F', 'Espressif', 'iot', 'lan_only'),
    ('00:17:88', 'Philips Hue', 'iot', 'lan_only'),
    ('34:94:54', 'Shelly', 'iot', 'lan_only'),
    -- Cameras
    ('00:0C:B5', 'Hikvision', 'camera', 'lan_only'),
    ('18:68:CB', 'Hikvision', 'camera', 'lan_only'),
    ('3C:EF:8C', 'Dahua', 'camera', 'lan_only'),
    ('B4:6B:FC', 'Reolink', 'camera', 'lan_only'),
    -- POS terminals
    ('00:50:10', 'Verifone', 'pos', 'internet_only'),
    ('00:07:81', 'Ingenico', 'pos', 'internet_only'),
    ('58:E6:BA', 'Square', 'pos', 'internet_only'),
    -- Printers
    ('00:1E:0B', 'HP Printer', 'printer', 'lan_only'),
    ('00:26:AB', 'Epson', 'printer', 'lan_only'),
    ('00:1B:A9', 'Brother', 'printer', 'lan_only'),
    -- Voice assistants (isolated by default)
    ('18:D6:C7', 'Google Nest', 'voice_assistant', 'internet_only'),
    ('0C:47:C9', 'Amazon Echo', 'voice_assistant', 'internet_only')
ON CONFLICT (oui) DO NOTHING;

-- ============================================================
-- THREATS TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS threats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    threat_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    source_ip INET,
    source_mac VARCHAR(17),
    destination_ip INET,
    destination_port INTEGER,
    protocol VARCHAR(10),
    description TEXT,
    mitre_attack_id VARCHAR(20),
    is_blocked BOOLEAN DEFAULT FALSE,
    blocked_at TIMESTAMP WITH TIME ZONE,
    evidence JSONB DEFAULT '{}'::jsonb,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threats_type ON threats(threat_type);
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_detected ON threats(detected_at);
CREATE INDEX IF NOT EXISTS idx_threats_source ON threats(source_ip);

-- ============================================================
-- QSECBIT HISTORY
-- ============================================================
CREATE TABLE IF NOT EXISTS qsecbit_history (
    id SERIAL PRIMARY KEY,
    score DECIMAL(5,4) NOT NULL,
    rag_status VARCHAR(10) NOT NULL,
    components JSONB NOT NULL,
    layer_stats JSONB,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_qsecbit_recorded ON qsecbit_history(recorded_at);

-- ============================================================
-- DNS QUERIES LOG
-- ============================================================
CREATE TABLE IF NOT EXISTS dns_queries (
    id BIGSERIAL PRIMARY KEY,
    client_ip INET NOT NULL,
    client_mac VARCHAR(17),
    domain VARCHAR(255) NOT NULL,
    query_type VARCHAR(10),
    response_code VARCHAR(20),
    is_blocked BOOLEAN DEFAULT FALSE,
    block_reason VARCHAR(50),
    category VARCHAR(50),
    queried_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_queries USING gin(domain gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_dns_client ON dns_queries(client_ip);
CREATE INDEX IF NOT EXISTS idx_dns_blocked ON dns_queries(is_blocked) WHERE is_blocked = TRUE;
CREATE INDEX IF NOT EXISTS idx_dns_queried ON dns_queries(queried_at);

-- ============================================================
-- AUDIT LOG
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    details JSONB,
    ip_address INET,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);

-- ============================================================
-- FILTER RULES TABLE (nftables rule storage)
-- ============================================================
CREATE TABLE IF NOT EXISTS filter_rules (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    rule_type VARCHAR(20) NOT NULL,  -- 'mac', 'ip', 'port', 'combined'
    priority INTEGER DEFAULT 100,
    -- Match criteria
    source_mac VARCHAR(17),
    source_ip CIDR,
    dest_ip CIDR,
    dest_port INTEGER,
    protocol VARCHAR(10),
    -- Action
    action VARCHAR(20) NOT NULL,  -- 'accept', 'drop', 'reject', 'mark', 'log'
    -- Metadata
    device_id UUID REFERENCES devices(id),
    policy_id INTEGER REFERENCES network_policies(id),
    is_active BOOLEAN DEFAULT TRUE,
    hits BIGINT DEFAULT 0,
    last_hit TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_filter_rules_mac ON filter_rules(source_mac);
CREATE INDEX IF NOT EXISTS idx_filter_rules_active ON filter_rules(is_active);

-- ============================================================
-- VIEWS
-- ============================================================
CREATE OR REPLACE VIEW v_device_summary AS
SELECT
    vlan_id,
    network_policy,
    COUNT(*) as device_count,
    COUNT(*) FILTER (WHERE last_seen > NOW() - INTERVAL '5 minutes') as active_count,
    COUNT(*) FILTER (WHERE is_blocked) as blocked_count
FROM devices
GROUP BY vlan_id, network_policy;

CREATE OR REPLACE VIEW v_threat_summary AS
SELECT
    DATE_TRUNC('hour', detected_at) as hour,
    threat_type,
    severity,
    COUNT(*) as count
FROM threats
WHERE detected_at > NOW() - INTERVAL '24 hours'
GROUP BY DATE_TRUNC('hour', detected_at), threat_type, severity
ORDER BY hour DESC;

CREATE OR REPLACE VIEW v_device_policies AS
SELECT
    d.id,
    d.mac_address,
    d.ip_address,
    d.hostname,
    d.device_type,
    d.manufacturer,
    d.network_policy,
    p.internet_access,
    p.lan_access,
    p.bandwidth_limit_kbps,
    p.dns_policy
FROM devices d
LEFT JOIN network_policies p ON d.network_policy = p.name;

-- ============================================================
-- BACKUP HISTORY TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS backup_history (
    id SERIAL PRIMARY KEY,
    backup_type VARCHAR(20) NOT NULL,  -- 'full', 'db', 'config', 'app'
    backup_file VARCHAR(255) NOT NULL,
    file_size BIGINT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(50) DEFAULT 'system',
    notes TEXT
);

-- ============================================================
-- SYSTEM EVENTS TABLE (for tracking upgrades, restarts, etc)
-- ============================================================
CREATE TABLE IF NOT EXISTS system_events (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,  -- 'upgrade', 'restart', 'backup', 'restore', 'config_change'
    severity VARCHAR(20) DEFAULT 'info',  -- 'info', 'warning', 'error', 'critical'
    description TEXT NOT NULL,
    details JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_system_events_type ON system_events(event_type);
CREATE INDEX IF NOT EXISTS idx_system_events_created ON system_events(created_at);

-- ============================================================
-- MIGRATION HELPER FUNCTION
-- ============================================================
CREATE OR REPLACE FUNCTION apply_migration(
    p_version INTEGER,
    p_description TEXT,
    p_sql TEXT
) RETURNS BOOLEAN AS $$
DECLARE
    current_version INTEGER;
BEGIN
    -- Get current schema version
    SELECT COALESCE(MAX(version), 0) INTO current_version FROM schema_version;

    -- Check if migration already applied
    IF p_version <= current_version THEN
        RAISE NOTICE 'Migration % already applied, skipping', p_version;
        RETURN FALSE;
    END IF;

    -- Check if this is the next sequential migration
    IF p_version != current_version + 1 THEN
        RAISE EXCEPTION 'Migration % cannot be applied. Current version is %, expected %',
            p_version, current_version, current_version + 1;
    END IF;

    -- Execute migration SQL
    EXECUTE p_sql;

    -- Record migration
    INSERT INTO schema_version (version, description, checksum)
    VALUES (p_version, p_description, md5(p_sql));

    -- Log event
    INSERT INTO system_events (event_type, description, details)
    VALUES ('upgrade', 'Database migration applied', jsonb_build_object('version', p_version, 'description', p_description));

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- ============================================================
-- CLEANUP FUNCTIONS (for data retention/GDPR)
-- ============================================================
CREATE OR REPLACE FUNCTION cleanup_old_dns_queries(retention_days INTEGER DEFAULT 7) RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM dns_queries
    WHERE queried_at < NOW() - (retention_days || ' days')::INTERVAL;

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION cleanup_old_threats(retention_days INTEGER DEFAULT 30) RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM threats
    WHERE detected_at < NOW() - (retention_days || ' days')::INTERVAL;

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION cleanup_old_qsecbit_history(retention_days INTEGER DEFAULT 7) RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM qsecbit_history
    WHERE recorded_at < NOW() - (retention_days || ' days')::INTERVAL;

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION cleanup_old_audit_logs(retention_days INTEGER DEFAULT 90) RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM audit_log
    WHERE created_at < NOW() - (retention_days || ' days')::INTERVAL;

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Master cleanup function
CREATE OR REPLACE FUNCTION run_data_retention() RETURNS TABLE(table_name TEXT, deleted_count INTEGER) AS $$
BEGIN
    RETURN QUERY SELECT 'dns_queries'::TEXT, cleanup_old_dns_queries(7);
    RETURN QUERY SELECT 'threats'::TEXT, cleanup_old_threats(30);
    RETURN QUERY SELECT 'qsecbit_history'::TEXT, cleanup_old_qsecbit_history(7);
    RETURN QUERY SELECT 'audit_log'::TEXT, cleanup_old_audit_logs(90);
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO fortress;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO fortress;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO fortress;
