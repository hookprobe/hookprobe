-- HookProbe Fortress Database Migration 002
-- Device Identity Integration & Lifecycle Management
--
-- G.N.C. Phase 2: Enhanced device tracking with MAC randomization support
--
-- This migration adds:
-- 1. Device status enum (ONLINE, STALE, OFFLINE, EXPIRED)
-- 2. Identity-based tracking (decoupled from MAC address)
-- 3. DHCP lease tracking with automatic expiry
-- 4. Device identifier correlation (Option 55, 61, mDNS)
--
-- Version: 5.6.0
-- License: AGPL-3.0

-- ============================================================
-- TRANSACTION WRAPPER: Ensures atomic migration
-- ============================================================
-- Check if migration already applied before starting transaction
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM schema_version WHERE version = 2) THEN
        RAISE NOTICE 'Migration 002 already applied, skipping';
        RETURN;
    END IF;
END$$;

BEGIN;

-- ============================================================
-- STEP 1: Add device status and identity columns to devices table
-- ============================================================

-- Add status column with enum values
DO $$
BEGIN
    -- Create enum type if not exists
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'device_status') THEN
        CREATE TYPE device_status AS ENUM ('ONLINE', 'STALE', 'OFFLINE', 'EXPIRED');
    END IF;
END$$;

-- Add new columns to devices table
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS status device_status DEFAULT 'OFFLINE',
    ADD COLUMN IF NOT EXISTS identity_id UUID,
    ADD COLUMN IF NOT EXISTS dhcp_lease_start TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS dhcp_lease_expiry TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS dhcp_option55 TEXT,
    ADD COLUMN IF NOT EXISTS dhcp_option61 TEXT,
    ADD COLUMN IF NOT EXISTS dhcp_vendor_class TEXT,
    ADD COLUMN IF NOT EXISTS mdns_name TEXT,
    ADD COLUMN IF NOT EXISTS stale_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS offline_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS connection_count INTEGER DEFAULT 1,
    ADD COLUMN IF NOT EXISTS signal_strength INTEGER;

-- Create indexes for new columns
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_devices_identity ON devices(identity_id);
CREATE INDEX IF NOT EXISTS idx_devices_lease_expiry ON devices(dhcp_lease_expiry);
CREATE INDEX IF NOT EXISTS idx_devices_option55 ON devices(dhcp_option55);
CREATE INDEX IF NOT EXISTS idx_devices_option61 ON devices(dhcp_option61);

-- ============================================================
-- STEP 2: Create device_identities table (persistent identity)
-- ============================================================

CREATE TABLE IF NOT EXISTS device_identities (
    identity_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Display name (user-visible, won't increment)
    canonical_name VARCHAR(255) NOT NULL,

    -- Primary correlation identifiers (most stable)
    dhcp_option61 TEXT,           -- Client ID - very stable
    mdns_device_id TEXT,          -- mDNS service name

    -- Secondary correlation identifiers
    dhcp_option55 TEXT,           -- OS fingerprint (shared by device type)
    hostname_pattern VARCHAR(255), -- Normalized hostname
    oui_prefix VARCHAR(8),        -- Vendor OUI (XX:XX:XX)

    -- Device classification
    device_type VARCHAR(50),      -- iPhone, MacBook, Android, IoT, etc.
    manufacturer VARCHAR(255),
    fingerbank_id INTEGER,
    os_family VARCHAR(50),        -- iOS, Android, Windows, Linux

    -- Current MAC (most recent)
    current_mac VARCHAR(17),      -- Most recently seen MAC address

    -- Policy assignment
    bubble_id UUID,
    network_policy VARCHAR(50) DEFAULT 'default',
    vlan_id INTEGER DEFAULT 0,
    trust_level INTEGER DEFAULT 2,  -- 0=untrusted, 4=enterprise

    -- Statistics
    total_macs_seen INTEGER DEFAULT 0,
    total_connections INTEGER DEFAULT 0,

    -- Timestamps
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Unique constraints for primary identifiers
CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_canonical_name
    ON device_identities(canonical_name);
CREATE INDEX IF NOT EXISTS idx_identity_option61
    ON device_identities(dhcp_option61);
CREATE INDEX IF NOT EXISTS idx_identity_mdns
    ON device_identities(mdns_device_id);
CREATE INDEX IF NOT EXISTS idx_identity_option55
    ON device_identities(dhcp_option55);
CREATE INDEX IF NOT EXISTS idx_identity_hostname
    ON device_identities(hostname_pattern);
CREATE INDEX IF NOT EXISTS idx_identity_current_mac
    ON device_identities(current_mac);

-- ============================================================
-- STEP 3: Create device_identifiers table (all observed signals)
-- ============================================================

CREATE TABLE IF NOT EXISTS device_identifiers (
    identifier_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id UUID NOT NULL REFERENCES device_identities(identity_id) ON DELETE CASCADE,

    -- Identifier type and value
    identifier_type VARCHAR(50) NOT NULL,  -- MAC_ADDRESS, DHCP_OPTION_55, DHCP_OPTION_61, MDNS_NAME, OUI, HOSTNAME
    identifier_value TEXT NOT NULL,

    -- Confidence and priority
    confidence_score DECIMAL(3,2) DEFAULT 0.50,  -- 0.00 to 1.00
    is_primary BOOLEAN DEFAULT FALSE,

    -- Timestamps
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    times_seen INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_identifiers_identity ON device_identifiers(identity_id);
CREATE INDEX IF NOT EXISTS idx_identifiers_type_value ON device_identifiers(identifier_type, identifier_value);
CREATE UNIQUE INDEX IF NOT EXISTS idx_identifiers_unique
    ON device_identifiers(identity_id, identifier_type, identifier_value);

-- ============================================================
-- STEP 4: Create dhcp_lease_history table
-- ============================================================

CREATE TABLE IF NOT EXISTS dhcp_lease_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id UUID REFERENCES device_identities(identity_id) ON DELETE SET NULL,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,

    -- Lease information
    mac_address VARCHAR(17) NOT NULL,
    ip_address INET NOT NULL,
    hostname VARCHAR(255),

    -- DHCP options
    dhcp_option55 TEXT,
    dhcp_option61 TEXT,
    dhcp_vendor_class TEXT,

    -- Timestamps
    lease_start TIMESTAMP WITH TIME ZONE NOT NULL,
    lease_duration INTEGER,  -- seconds
    lease_expiry TIMESTAMP WITH TIME ZONE,
    lease_released TIMESTAMP WITH TIME ZONE,

    -- Interface
    interface VARCHAR(50) DEFAULT 'FTS'
);

CREATE INDEX IF NOT EXISTS idx_lease_history_identity ON dhcp_lease_history(identity_id);
CREATE INDEX IF NOT EXISTS idx_lease_history_mac ON dhcp_lease_history(mac_address);
CREATE INDEX IF NOT EXISTS idx_lease_history_ip ON dhcp_lease_history(ip_address);
CREATE INDEX IF NOT EXISTS idx_lease_history_expiry ON dhcp_lease_history(lease_expiry);

-- ============================================================
-- STEP 5: Create device correlation functions
-- ============================================================

-- Function to find identity by various signals
CREATE OR REPLACE FUNCTION find_device_identity(
    p_mac VARCHAR(17),
    p_dhcp_option55 TEXT DEFAULT NULL,
    p_dhcp_option61 TEXT DEFAULT NULL,
    p_mdns_name TEXT DEFAULT NULL,
    p_hostname TEXT DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    v_identity_id UUID;
    v_score DECIMAL;
BEGIN
    -- Priority 1: DHCP Option 61 (Client ID) - highest confidence
    IF p_dhcp_option61 IS NOT NULL THEN
        SELECT identity_id INTO v_identity_id
        FROM device_identities
        WHERE dhcp_option61 = p_dhcp_option61
        LIMIT 1;

        IF v_identity_id IS NOT NULL THEN
            RETURN v_identity_id;
        END IF;
    END IF;

    -- Priority 2: Existing MAC mapping
    SELECT identity_id INTO v_identity_id
    FROM device_identifiers
    WHERE identifier_type = 'MAC_ADDRESS' AND identifier_value = p_mac
    LIMIT 1;

    IF v_identity_id IS NOT NULL THEN
        RETURN v_identity_id;
    END IF;

    -- Priority 3: mDNS device name
    IF p_mdns_name IS NOT NULL THEN
        SELECT identity_id INTO v_identity_id
        FROM device_identities
        WHERE mdns_device_id = p_mdns_name
        LIMIT 1;

        IF v_identity_id IS NOT NULL THEN
            RETURN v_identity_id;
        END IF;
    END IF;

    -- Priority 4: Hostname + Option 55 combination
    IF p_hostname IS NOT NULL AND p_dhcp_option55 IS NOT NULL THEN
        SELECT identity_id INTO v_identity_id
        FROM device_identities
        WHERE hostname_pattern = LOWER(REGEXP_REPLACE(p_hostname, '[0-9]+$', ''))
          AND dhcp_option55 = p_dhcp_option55
        ORDER BY last_seen DESC
        LIMIT 1;

        IF v_identity_id IS NOT NULL THEN
            RETURN v_identity_id;
        END IF;
    END IF;

    -- No match found
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Function to update device status based on lease expiry
CREATE OR REPLACE FUNCTION update_device_status() RETURNS INTEGER AS $$
DECLARE
    updated_count INTEGER := 0;
    stale_threshold INTERVAL := '30 minutes';
BEGIN
    -- Mark ONLINE devices as STALE if not seen recently
    UPDATE devices
    SET status = 'STALE', stale_at = NOW()
    WHERE status = 'ONLINE'
      AND last_seen < NOW() - stale_threshold
      AND (dhcp_lease_expiry IS NULL OR dhcp_lease_expiry > NOW());

    GET DIAGNOSTICS updated_count = ROW_COUNT;

    -- Mark devices as OFFLINE if lease expired
    UPDATE devices
    SET status = 'OFFLINE', offline_at = NOW(), ip_address = NULL
    WHERE status IN ('ONLINE', 'STALE')
      AND dhcp_lease_expiry IS NOT NULL
      AND dhcp_lease_expiry < NOW();

    -- Mark devices as EXPIRED after 30 days offline
    UPDATE devices
    SET status = 'EXPIRED'
    WHERE status = 'OFFLINE'
      AND offline_at < NOW() - INTERVAL '30 days';

    RETURN updated_count;
END;
$$ LANGUAGE plpgsql;

-- Function to register device (upsert with identity correlation)
CREATE OR REPLACE FUNCTION register_device(
    p_mac VARCHAR(17),
    p_ip INET,
    p_hostname VARCHAR(255) DEFAULT NULL,
    p_dhcp_option55 TEXT DEFAULT NULL,
    p_dhcp_option61 TEXT DEFAULT NULL,
    p_dhcp_vendor_class TEXT DEFAULT NULL,
    p_mdns_name TEXT DEFAULT NULL,
    p_lease_duration INTEGER DEFAULT 3600,
    p_manufacturer VARCHAR(255) DEFAULT NULL
) RETURNS TABLE(device_id UUID, identity_id UUID, is_new BOOLEAN, canonical_name VARCHAR) AS $$
DECLARE
    v_identity_id UUID;
    v_device_id UUID;
    v_is_new BOOLEAN := FALSE;
    v_canonical_name VARCHAR(255);
    v_hostname_pattern VARCHAR(255);
    v_oui VARCHAR(8);
BEGIN
    -- Normalize hostname pattern (remove trailing numbers)
    v_hostname_pattern := LOWER(REGEXP_REPLACE(COALESCE(p_hostname, ''), '[0-9]+$', ''));
    v_oui := UPPER(SUBSTRING(p_mac FROM 1 FOR 8));

    -- Try to find existing identity
    v_identity_id := find_device_identity(p_mac, p_dhcp_option55, p_dhcp_option61, p_mdns_name, p_hostname);

    IF v_identity_id IS NULL THEN
        -- Create new identity
        v_is_new := TRUE;
        v_canonical_name := COALESCE(p_mdns_name, p_hostname, p_manufacturer || ' Device', 'Unknown Device');

        -- Ensure unique canonical name (no incrementing!)
        -- If name exists, append truncated MAC
        IF EXISTS (SELECT 1 FROM device_identities WHERE canonical_name = v_canonical_name) THEN
            v_canonical_name := v_canonical_name || ' (' || SUBSTRING(p_mac FROM 10) || ')';
        END IF;

        INSERT INTO device_identities (
            canonical_name, dhcp_option55, dhcp_option61, mdns_device_id,
            hostname_pattern, oui_prefix, manufacturer
        ) VALUES (
            v_canonical_name, p_dhcp_option55, p_dhcp_option61, p_mdns_name,
            v_hostname_pattern, v_oui, p_manufacturer
        ) RETURNING device_identities.identity_id, device_identities.canonical_name
        INTO v_identity_id, v_canonical_name;

    ELSE
        -- Update existing identity
        UPDATE device_identities
        SET last_seen = NOW(),
            current_mac = p_mac,
            dhcp_option55 = COALESCE(p_dhcp_option55, dhcp_option55),
            dhcp_option61 = COALESCE(p_dhcp_option61, dhcp_option61),
            mdns_device_id = COALESCE(p_mdns_name, mdns_device_id),
            total_connections = total_connections + 1,
            updated_at = NOW()
        WHERE device_identities.identity_id = v_identity_id
        RETURNING device_identities.canonical_name INTO v_canonical_name;
    END IF;

    -- Register MAC identifier
    INSERT INTO device_identifiers (identity_id, identifier_type, identifier_value, confidence_score)
    VALUES (v_identity_id, 'MAC_ADDRESS', p_mac, 0.90)
    ON CONFLICT (identity_id, identifier_type, identifier_value)
    DO UPDATE SET last_seen = NOW(), times_seen = device_identifiers.times_seen + 1;

    -- Register other identifiers if available
    IF p_dhcp_option55 IS NOT NULL THEN
        INSERT INTO device_identifiers (identity_id, identifier_type, identifier_value, confidence_score)
        VALUES (v_identity_id, 'DHCP_OPTION_55', p_dhcp_option55, 0.70)
        ON CONFLICT (identity_id, identifier_type, identifier_value)
        DO UPDATE SET last_seen = NOW(), times_seen = device_identifiers.times_seen + 1;
    END IF;

    IF p_dhcp_option61 IS NOT NULL THEN
        INSERT INTO device_identifiers (identity_id, identifier_type, identifier_value, confidence_score, is_primary)
        VALUES (v_identity_id, 'DHCP_OPTION_61', p_dhcp_option61, 1.00, TRUE)
        ON CONFLICT (identity_id, identifier_type, identifier_value)
        DO UPDATE SET last_seen = NOW(), times_seen = device_identifiers.times_seen + 1;
    END IF;

    -- Upsert device record
    INSERT INTO devices (
        mac_address, ip_address, hostname, identity_id, status,
        dhcp_option55, dhcp_option61, dhcp_vendor_class, mdns_name,
        dhcp_lease_start, dhcp_lease_expiry, manufacturer, last_seen
    ) VALUES (
        p_mac, p_ip, p_hostname, v_identity_id, 'ONLINE',
        p_dhcp_option55, p_dhcp_option61, p_dhcp_vendor_class, p_mdns_name,
        NOW(), NOW() + (p_lease_duration || ' seconds')::INTERVAL, p_manufacturer, NOW()
    )
    ON CONFLICT (mac_address) DO UPDATE SET
        ip_address = EXCLUDED.ip_address,
        hostname = COALESCE(EXCLUDED.hostname, devices.hostname),
        identity_id = v_identity_id,
        status = 'ONLINE',
        dhcp_option55 = COALESCE(EXCLUDED.dhcp_option55, devices.dhcp_option55),
        dhcp_option61 = COALESCE(EXCLUDED.dhcp_option61, devices.dhcp_option61),
        dhcp_vendor_class = COALESCE(EXCLUDED.dhcp_vendor_class, devices.dhcp_vendor_class),
        mdns_name = COALESCE(EXCLUDED.mdns_name, devices.mdns_name),
        dhcp_lease_start = NOW(),
        dhcp_lease_expiry = NOW() + (p_lease_duration || ' seconds')::INTERVAL,
        last_seen = NOW(),
        connection_count = devices.connection_count + 1,
        stale_at = NULL,
        offline_at = NULL
    RETURNING devices.id INTO v_device_id;

    -- Record lease history
    INSERT INTO dhcp_lease_history (
        identity_id, device_id, mac_address, ip_address, hostname,
        dhcp_option55, dhcp_option61, dhcp_vendor_class,
        lease_start, lease_duration, lease_expiry
    ) VALUES (
        v_identity_id, v_device_id, p_mac, p_ip, p_hostname,
        p_dhcp_option55, p_dhcp_option61, p_dhcp_vendor_class,
        NOW(), p_lease_duration, NOW() + (p_lease_duration || ' seconds')::INTERVAL
    );

    RETURN QUERY SELECT v_device_id, v_identity_id, v_is_new, v_canonical_name;
END;
$$ LANGUAGE plpgsql;

-- ============================================================
-- STEP 6: Create view for device listing with identity info
-- ============================================================

CREATE OR REPLACE VIEW v_devices_with_identity AS
SELECT
    d.id,
    d.mac_address,
    d.ip_address,
    d.hostname,
    d.status::TEXT as status,
    d.vlan_id,
    d.network_policy,
    d.is_blocked,
    d.first_seen,
    d.last_seen,
    d.stale_at,
    d.offline_at,
    d.dhcp_lease_expiry,
    d.dhcp_option55,
    d.dhcp_option61,
    d.dhcp_vendor_class,
    d.mdns_name,
    d.signal_strength,
    d.connection_count,
    d.manufacturer,
    d.device_type,
    -- Identity fields
    i.identity_id,
    i.canonical_name,
    i.canonical_name as display_name,
    i.mdns_device_id,
    i.device_type as identity_device_type,
    i.os_family,
    i.trust_level,
    i.total_macs_seen,
    i.current_mac as identity_current_mac,
    -- MAC randomization detection (locally administered bit check)
    CASE
        WHEN SUBSTRING(d.mac_address FROM 2 FOR 1) IN ('2', '6', 'A', 'E', 'a', 'e') THEN TRUE
        ELSE FALSE
    END as is_mac_randomized,
    -- Calculated fields
    CASE
        WHEN d.status = 'ONLINE' THEN 'Online'
        WHEN d.status = 'STALE' THEN 'Stale'
        WHEN d.status = 'OFFLINE' THEN 'Offline'
        WHEN d.status = 'EXPIRED' THEN 'Expired'
        ELSE 'Unknown'
    END as status_display,
    CASE
        WHEN d.dhcp_lease_expiry IS NOT NULL THEN
            EXTRACT(EPOCH FROM (d.dhcp_lease_expiry - NOW()))::INTEGER
        ELSE NULL
    END as lease_remaining_seconds
FROM devices d
LEFT JOIN device_identities i ON d.identity_id = i.identity_id;

-- ============================================================
-- STEP 7: Record migration
-- ============================================================

INSERT INTO schema_version (version, description)
VALUES (2, 'Device identity integration with MAC randomization support')
ON CONFLICT DO NOTHING;

INSERT INTO system_events (event_type, description, details)
VALUES ('upgrade', 'Migration 002 applied - Device identity integration',
        '{"version": 2, "features": ["device_status_enum", "identity_tracking", "lease_history", "correlation_functions"]}');

-- ============================================================
-- COMMIT TRANSACTION: All changes applied atomically
-- ============================================================
COMMIT;
