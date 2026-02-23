-- Migration 003: Fix register_device function ambiguous column references
--
-- Problem: RETURNS TABLE column names (device_id, identity_id, canonical_name)
-- conflicted with identically-named columns in device_identities, device_identifiers,
-- and devices tables, causing "column reference is ambiguous" errors.
--
-- Fix: Rename RETURNS TABLE columns to use r_ prefix (r_device_id, r_identity_id, etc.)
-- and qualify all table column references in SET/WHERE clauses.
--
-- Date: 2026-02-23

-- Must DROP first because return type signature changed
DROP FUNCTION IF EXISTS register_device(character varying, inet, character varying, text, text, text, text, integer, character varying);

CREATE OR REPLACE FUNCTION public.register_device(
    p_mac character varying, p_ip inet,
    p_hostname character varying DEFAULT NULL,
    p_dhcp_option55 text DEFAULT NULL,
    p_dhcp_option61 text DEFAULT NULL,
    p_dhcp_vendor_class text DEFAULT NULL,
    p_mdns_name text DEFAULT NULL,
    p_lease_duration integer DEFAULT 3600,
    p_manufacturer character varying DEFAULT NULL
)
RETURNS TABLE(r_device_id uuid, r_identity_id uuid, r_is_new boolean, r_canonical_name character varying)
LANGUAGE plpgsql AS $func$
DECLARE
    v_identity_id UUID;
    v_device_id UUID;
    v_is_new BOOLEAN := FALSE;
    v_canonical_name VARCHAR(255);
    v_hostname_pattern VARCHAR(255);
    v_oui VARCHAR(8);
BEGIN
    v_hostname_pattern := LOWER(REGEXP_REPLACE(COALESCE(p_hostname, ''), '[0-9]+$', ''));
    v_oui := UPPER(SUBSTRING(p_mac FROM 1 FOR 8));

    v_identity_id := find_device_identity(p_mac, p_dhcp_option55, p_dhcp_option61, p_mdns_name, p_hostname);

    IF v_identity_id IS NULL THEN
        v_is_new := TRUE;
        v_canonical_name := COALESCE(p_mdns_name, p_hostname, p_manufacturer || ' Device', 'Unknown Device');

        IF EXISTS (SELECT 1 FROM device_identities di WHERE di.canonical_name = v_canonical_name) THEN
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
        UPDATE device_identities
        SET last_seen = NOW(),
            current_mac = p_mac,
            dhcp_option55 = COALESCE(p_dhcp_option55, device_identities.dhcp_option55),
            dhcp_option61 = COALESCE(p_dhcp_option61, device_identities.dhcp_option61),
            mdns_device_id = COALESCE(p_mdns_name, device_identities.mdns_device_id),
            total_connections = device_identities.total_connections + 1,
            updated_at = NOW()
        WHERE device_identities.identity_id = v_identity_id
        RETURNING device_identities.canonical_name INTO v_canonical_name;
    END IF;

    INSERT INTO device_identifiers (identity_id, identifier_type, identifier_value, confidence_score)
    VALUES (v_identity_id, 'MAC_ADDRESS', p_mac, 0.90)
    ON CONFLICT (identity_id, identifier_type, identifier_value)
    DO UPDATE SET last_seen = NOW(), times_seen = device_identifiers.times_seen + 1;

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
$func$;
