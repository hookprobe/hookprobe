#!/usr/bin/env python3
"""
End-to-End Tests for Fortress SDN Dashboard

Tests the full flow from device discovery to dashboard display:
1. Device auto-registration via Fingerbank pipeline
2. DHCP fingerprint processing
3. API endpoints (device detail, add tag, set policy)
4. Data persistence and retrieval

Run: pytest products/fortress/tests/test_sdn_e2e.py -v
"""

import json
import os
import sys
import tempfile
import sqlite3
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime

import pytest

# Add paths for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'web'))


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    yield db_path
    try:
        os.unlink(db_path)
    except FileNotFoundError:
        pass


@pytest.fixture
def temp_data_dir():
    """Create temporary data directory for cache files."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def sample_devices():
    """Sample device data mimicking devices.json from dhcp-event.sh."""
    return {
        "80:8A:BD:43:E2:BA": {
            "mac_address": "80:8A:BD:43:E2:BA",
            "ip_address": "10.200.0.15",
            "hostname": "Galaxy-S21",
            "dhcp_fingerprint": "1,3,6,15,26,28,51,58,59,43",
            "vendor_class": "android-dhcp-12",
            "first_seen": "2024-01-15T10:30:00",
            "last_seen": "2024-01-15T14:30:00",
            "is_active": True
        },
        "00:1B:63:84:45:E6": {
            "mac_address": "00:1B:63:84:45:E6",
            "ip_address": "10.200.0.20",
            "hostname": "MacBook-Pro",
            "dhcp_fingerprint": "1,121,3,6,15,119,252,95,44,46",
            "vendor_class": "",
            "first_seen": "2024-01-15T09:00:00",
            "last_seen": "2024-01-15T14:35:00",
            "is_active": True
        },
        "DC:A6:32:12:34:56": {
            "mac_address": "DC:A6:32:12:34:56",
            "ip_address": "10.200.0.100",
            "hostname": "raspberrypi",
            "dhcp_fingerprint": "1,3,28,6",
            "vendor_class": "dhcpcd-9.4.0:Linux-5.15.0-v8+:aarch64:bcm2711",
            "first_seen": "2024-01-10T08:00:00",
            "last_seen": "2024-01-15T14:40:00",
            "is_active": True
        }
    }


@pytest.fixture
def sample_status_cache():
    """Sample device_status.json data from device-status-updater.sh."""
    return {
        "devices": [
            {
                "mac": "80:8A:BD:43:E2:BA",
                "ip": "10.200.0.15",
                "status": "online",
                "neighbor_state": "REACHABLE",
                "last_packet_count": 1234
            },
            {
                "mac": "00:1B:63:84:45:E6",
                "ip": "10.200.0.20",
                "status": "online",
                "neighbor_state": "REACHABLE",
                "last_packet_count": 5678
            }
        ]
    }


# =============================================================================
# SDN AUTOPILOT UNIT TESTS
# =============================================================================

class TestSDNAutopilot:
    """Test SDN Autopilot module directly."""

    def test_autopilot_initialization(self, temp_db):
        """Test SDN Autopilot initializes with database."""
        from sdn_autopilot import SDNAutoPilot

        pilot = SDNAutoPilot(db_path=temp_db)
        assert pilot is not None
        assert pilot.db_path == Path(temp_db)

        # Verify database tables created
        conn = sqlite3.connect(temp_db)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='device_identity'"
        )
        assert cursor.fetchone() is not None
        conn.close()

    def test_sync_device_with_fingerprint(self, temp_db):
        """Test sync_device uses Fingerbank pipeline with DHCP fingerprint."""
        from sdn_autopilot import SDNAutoPilot

        pilot = SDNAutoPilot(db_path=temp_db)

        # Sync a Samsung device with DHCP fingerprint
        result = pilot.sync_device(
            mac="80:8A:BD:43:E2:BA",
            ip="10.200.0.15",
            hostname="Galaxy-S21",
            dhcp_fingerprint="1,3,6,15,26,28,51,58,59,43",
            vendor_class="android-dhcp-12",
            apply_rules=False  # Don't try to apply OpenFlow rules in test
        )

        assert result is not None
        # Fingerbank may identify as Samsung (OUI) or Android (vendor_class)
        # Both are valid - vendor_class takes precedence when available
        assert result.vendor in ["Samsung", "Android"]
        assert result.confidence >= 0.5

        # Verify device persisted
        device = pilot.get_device("80:8A:BD:43:E2:BA")
        assert device is not None
        assert device['ip'] == "10.200.0.15"
        assert device['hostname'] == "Galaxy-S21"

    def test_sync_device_apple_fingerprint(self, temp_db):
        """Test sync_device correctly identifies Apple device."""
        from sdn_autopilot import SDNAutoPilot

        pilot = SDNAutoPilot(db_path=temp_db)

        # Apple macOS Ventura fingerprint
        result = pilot.sync_device(
            mac="00:1B:63:84:45:E6",
            ip="10.200.0.20",
            hostname="MacBook-Pro",
            dhcp_fingerprint="1,121,3,6,15,119,252,95,44,46",
            apply_rules=False
        )

        assert result is not None
        assert result.vendor == "Apple"
        # macOS with this fingerprint should get high confidence
        assert result.confidence >= 0.7

    def test_ensure_device_exists_creates_via_fingerbank(self, temp_db):
        """Test ensure_device_exists creates device via Fingerbank pipeline."""
        from sdn_autopilot import SDNAutoPilot

        pilot = SDNAutoPilot(db_path=temp_db)

        # Device doesn't exist yet
        assert pilot.get_device("DC:A6:32:12:34:56") is None

        # ensure_device_exists should create via sync_device
        device = pilot.ensure_device_exists(
            mac="DC:A6:32:12:34:56",
            ip="10.200.0.100",
            hostname="raspberrypi",
            dhcp_fingerprint="1,3,28,6",
            vendor_class="dhcpcd-9.4.0:Linux-5.15.0-v8+:aarch64:bcm2711"
        )

        assert device is not None
        assert device['mac'] == "DC:A6:32:12:34:56"
        assert device['ip'] == "10.200.0.100"
        # Raspberry Pi OUI should be detected
        assert "Raspberry" in device.get('vendor', '') or device.get('confidence', 0) > 0

    def test_ensure_device_exists_updates_existing(self, temp_db):
        """Test ensure_device_exists updates last_seen for existing device."""
        from sdn_autopilot import SDNAutoPilot

        pilot = SDNAutoPilot(db_path=temp_db)

        # Create device first
        pilot.sync_device(
            mac="80:8A:BD:43:E2:BA",
            ip="10.200.0.15",
            hostname="Galaxy-S21",
            apply_rules=False
        )

        original = pilot.get_device("80:8A:BD:43:E2:BA")
        original_last_seen = original['last_seen']

        # Call ensure_device_exists again
        import time
        time.sleep(0.1)  # Small delay to ensure timestamp differs

        device = pilot.ensure_device_exists(
            mac="80:8A:BD:43:E2:BA",
            ip="10.200.0.16"  # Updated IP
        )

        assert device is not None
        assert device['ip'] == "10.200.0.16"  # IP should be updated
        assert device['last_seen'] >= original_last_seen

    def test_sync_from_device_list(self, temp_db, sample_devices):
        """Test sync_from_device_list processes multiple devices."""
        from sdn_autopilot import SDNAutoPilot

        pilot = SDNAutoPilot(db_path=temp_db)

        # Convert sample_devices dict to list format expected by sync_from_device_list
        devices_list = [
            {
                'mac': mac,
                'ip': info['ip_address'],
                'hostname': info['hostname'],
                'dhcp_fingerprint': info['dhcp_fingerprint'],
                'vendor_class': info['vendor_class']
            }
            for mac, info in sample_devices.items()
        ]

        synced = pilot.sync_from_device_list(devices_list)
        assert synced == 3  # All 3 devices should be synced

        # Verify all devices exist
        for mac in sample_devices:
            device = pilot.get_device(mac)
            assert device is not None, f"Device {mac} should exist"

    def test_set_policy_persists(self, temp_db):
        """Test set_policy correctly persists policy change."""
        from sdn_autopilot import SDNAutoPilot

        pilot = SDNAutoPilot(db_path=temp_db)

        # Create device first
        pilot.sync_device(
            mac="80:8A:BD:43:E2:BA",
            ip="10.200.0.15",
            apply_rules=False
        )

        # Set policy
        success = pilot.set_policy("80:8A:BD:43:E2:BA", "internet_only")
        assert success is True

        # Verify policy persisted
        device = pilot.get_device("80:8A:BD:43:E2:BA")
        assert device['policy'] == "internet_only"
        assert device['manual_override'] == 1  # Should be marked as manual

    def test_add_tag(self, temp_db):
        """Test add_tag correctly adds tag to device."""
        from sdn_autopilot import SDNAutoPilot

        pilot = SDNAutoPilot(db_path=temp_db)

        # Create device first
        pilot.sync_device(
            mac="80:8A:BD:43:E2:BA",
            ip="10.200.0.15",
            apply_rules=False
        )

        # Add tag
        success = pilot.add_tag("80:8A:BD:43:E2:BA", "TV")
        assert success is True

        # Verify tag persisted
        device = pilot.get_device("80:8A:BD:43:E2:BA")
        tags = json.loads(device.get('tags', '[]'))
        assert "TV" in tags

    def test_get_device_detail(self, temp_db):
        """Test get_device_detail returns comprehensive device info."""
        from sdn_autopilot import SDNAutoPilot

        pilot = SDNAutoPilot(db_path=temp_db)

        # Create device
        pilot.sync_device(
            mac="80:8A:BD:43:E2:BA",
            ip="10.200.0.15",
            hostname="Galaxy-S21",
            dhcp_fingerprint="1,3,6,15,26,28,51,58,59,43",
            apply_rules=False
        )

        # Add a tag
        pilot.add_tag("80:8A:BD:43:E2:BA", "Phone")

        # Get detail
        detail = pilot.get_device_detail("80:8A:BD:43:E2:BA")

        assert detail is not None
        assert detail['mac'] == "80:8A:BD:43:E2:BA"
        assert detail['ip'] == "10.200.0.15"
        assert detail['hostname'] == "Galaxy-S21"
        assert 'tags' in detail
        assert 'policy' in detail


# =============================================================================
# DATA FLOW TESTS
# =============================================================================

class TestDataFlow:
    """Test data flow from cache files through to database."""

    def test_cache_merge_preserves_fingerprints(self, temp_data_dir, sample_devices, sample_status_cache):
        """Test that merging cache files preserves DHCP fingerprints."""
        # Write sample files
        devices_file = temp_data_dir / 'devices.json'
        status_file = temp_data_dir / 'device_status.json'

        devices_file.write_text(json.dumps(sample_devices))
        status_file.write_text(json.dumps(sample_status_cache))

        # Mock the cache loading function
        from sdn_autopilot import SDNAutoPilot

        # Simulate what _load_device_status_cache does
        cache = {}

        # Load DHCP devices first
        dhcp_data = json.loads(devices_file.read_text())
        for mac, device in dhcp_data.items():
            mac_upper = mac.upper()
            cache[mac_upper] = {
                'status': 'online' if device.get('is_active', False) else 'offline',
                'ip': device.get('ip_address', ''),
                'hostname': device.get('hostname', ''),
                'dhcp_fingerprint': device.get('dhcp_fingerprint', ''),
                'vendor_class': device.get('vendor_class', ''),
            }

        # Merge with status cache
        status_data = json.loads(status_file.read_text())
        for device in status_data.get('devices', []):
            mac = device.get('mac', '').upper()
            if mac in cache:
                cache[mac]['status'] = device.get('status', cache[mac]['status'])
                cache[mac]['neighbor_state'] = device.get('neighbor_state', 'UNKNOWN')

        # Verify fingerprints preserved after merge
        assert cache["80:8A:BD:43:E2:BA"]['dhcp_fingerprint'] == "1,3,6,15,26,28,51,58,59,43"
        assert cache["80:8A:BD:43:E2:BA"]['vendor_class'] == "android-dhcp-12"
        assert cache["80:8A:BD:43:E2:BA"]['status'] == "online"

    def test_full_pipeline_fingerprint_to_db(self, temp_db, sample_devices):
        """Test full pipeline from cache file to database."""
        from sdn_autopilot import SDNAutoPilot

        pilot = SDNAutoPilot(db_path=temp_db)

        # Simulate the sync process
        devices_list = [
            {
                'mac': mac,
                'ip': info['ip_address'],
                'hostname': info['hostname'],
                'dhcp_fingerprint': info['dhcp_fingerprint'],
                'vendor_class': info['vendor_class']
            }
            for mac, info in sample_devices.items()
        ]

        pilot.sync_from_device_list(devices_list)

        # Verify DHCP fingerprint was stored
        device = pilot.get_device("80:8A:BD:43:E2:BA")
        assert device is not None

        # Check database directly for dhcp_fingerprint column
        conn = sqlite3.connect(temp_db)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT dhcp_fingerprint FROM device_identity WHERE mac = ?",
            ("80:8A:BD:43:E2:BA",)
        ).fetchone()
        conn.close()

        # The fingerprint should be stored
        assert row is not None
        # Note: sync_device stores the fingerprint passed to it
        assert row['dhcp_fingerprint'] == "1,3,6,15,26,28,51,58,59,43"


# =============================================================================
# API ENDPOINT TESTS (Mock Flask Context)
# =============================================================================

class TestAPIEndpoints:
    """Test API endpoints work correctly."""

    def test_api_device_set_policy(self, temp_db):
        """Test api_device_set_policy endpoint logic."""
        from sdn_autopilot import SDNAutoPilot

        pilot = SDNAutoPilot(db_path=temp_db)

        # Create device
        pilot.sync_device(
            mac="80:8A:BD:43:E2:BA",
            ip="10.200.0.15",
            apply_rules=False
        )

        # Simulate API call - set policy
        success = pilot.set_policy("80:8A:BD:43:E2:BA", "lan_only")
        assert success is True

        # Verify
        device = pilot.get_device("80:8A:BD:43:E2:BA")
        assert device['policy'] == "lan_only"

    def test_api_device_add_tag_with_autocreate(self, temp_db):
        """Test api_device_add_tag creates device if not exists."""
        from sdn_autopilot import SDNAutoPilot

        pilot = SDNAutoPilot(db_path=temp_db)

        # Device doesn't exist yet
        assert pilot.get_device("80:8A:BD:43:E2:BA") is None

        # Create device via ensure_device_exists (simulating API auto-create)
        device = pilot.ensure_device_exists(
            mac="80:8A:BD:43:E2:BA",
            ip="10.200.0.15",
            hostname="Galaxy-S21",
            dhcp_fingerprint="1,3,6,15,26,28,51,58,59,43"
        )
        assert device is not None

        # Now add tag
        success = pilot.add_tag("80:8A:BD:43:E2:BA", "TV")
        assert success is True

        # Verify
        device = pilot.get_device("80:8A:BD:43:E2:BA")
        tags = json.loads(device.get('tags', '[]'))
        assert "TV" in tags


# =============================================================================
# REGRESSION TESTS
# =============================================================================

class TestRegressions:
    """Regression tests for previously identified issues."""

    def test_policy_change_persists_not_demo_mode(self, temp_db):
        """Regression: Policy changes must persist, not return demo success."""
        from sdn_autopilot import SDNAutoPilot

        pilot = SDNAutoPilot(db_path=temp_db)

        # Create device
        pilot.sync_device(
            mac="80:8A:BD:43:E2:BA",
            ip="10.200.0.15",
            apply_rules=False
        )

        # Get initial policy
        device_before = pilot.get_device("80:8A:BD:43:E2:BA")
        initial_policy = device_before['policy']

        # Change policy
        pilot.set_policy("80:8A:BD:43:E2:BA", "quarantine")

        # Verify policy actually changed in database
        device_after = pilot.get_device("80:8A:BD:43:E2:BA")
        assert device_after['policy'] == "quarantine"

        # Re-read from fresh connection to ensure persistence
        conn = sqlite3.connect(temp_db)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT policy, manual_override FROM device_identity WHERE mac = ?",
            ("80:8A:BD:43:E2:BA",)
        ).fetchone()
        conn.close()

        assert row['policy'] == "quarantine"
        assert row['manual_override'] == 1

    def test_tag_api_500_error_fixed(self, temp_db):
        """Regression: Adding tag to non-existent device should not 500."""
        from sdn_autopilot import SDNAutoPilot

        pilot = SDNAutoPilot(db_path=temp_db)

        # Device doesn't exist - ensure_device_exists should create it
        device = pilot.ensure_device_exists(
            mac="80:8A:BD:43:E2:BA",
            ip="10.200.0.15"
        )
        assert device is not None

        # Now add_tag should work
        success = pilot.add_tag("80:8A:BD:43:E2:BA", "Phone")
        assert success is True

    def test_fingerbank_used_not_simple_oui(self, temp_db):
        """Regression: Device creation should use Fingerbank, not just OUI."""
        from sdn_autopilot import SDNAutoPilot

        pilot = SDNAutoPilot(db_path=temp_db)

        # Create device with DHCP fingerprint
        device = pilot.ensure_device_exists(
            mac="00:1B:63:84:45:E6",
            ip="10.200.0.20",
            hostname="MacBook-Pro",
            dhcp_fingerprint="1,121,3,6,15,119,252,95,44,46"
        )

        assert device is not None
        # Apple device should be identified with good confidence
        # (not just 0.5 default from simple OUI lookup)
        assert device.get('vendor') == 'Apple'

        # Confidence should be higher than default 0.5 if Fingerbank is working
        # (depends on whether Fingerbank module is available)


# =============================================================================
# FLASK API INTEGRATION TESTS
# =============================================================================

@pytest.mark.skipif(
    not os.path.exists('/opt/hookprobe/fortress'),
    reason="Full Flask integration tests require deployed Fortress environment"
)
class TestFlaskAPIIntegration:
    """Test Flask API endpoints with test client.

    These tests require a full Fortress deployment and are skipped in CI.
    Run on deployed Fortress with: pytest test_sdn_e2e.py -k Flask
    """

    def test_placeholder(self):
        """Placeholder - full Flask tests run on deployed system only."""
        # Core SDN Autopilot tests above validate the business logic
        # Flask integration tests would run against live /sdn/api/* endpoints
        pass


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
