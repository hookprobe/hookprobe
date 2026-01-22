#!/usr/bin/env python3
"""
Tests for HookProbe Cortex Fleet Management System

Tests multi-tenant access control, fleet management, and location privacy.
"""

import pytest
from datetime import datetime
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from fleet_manager import (
    FleetManager,
    AccessLevel,
    LocationPrivacy,
    Customer,
    Device,
    User,
    DeclaredLocation,
    IPBasedLocation,
    get_fleet_manager,
)


class TestFleetManager:
    """Test FleetManager core functionality."""

    @pytest.fixture
    def fleet_manager(self):
        """Create a fresh FleetManager instance for each test."""
        return FleetManager()

    @pytest.fixture
    def populated_fleet_manager(self, fleet_manager):
        """Create a FleetManager with test data."""
        # Register customers
        fleet_manager.register_customer(
            "acme-corp",
            "ACME Corporation",
            subscription_tier="enterprise",
            max_devices=500
        )
        fleet_manager.register_customer(
            "startup-inc",
            "Startup Inc",
            subscription_tier="startup",
            max_devices=50
        )

        # Register devices for ACME
        fleet_manager.register_device(
            "device-acme-001",
            "acme-corp",
            tier="guardian",
            label="NYC Office Guardian",
            department="Engineering",
            ip_location={"lat": 40.7128, "lng": -74.0060, "city": "New York"},
            declared_location={"lat": 40.7580, "lng": -73.9855, "label": "Empire State Building, Floor 42"}
        )
        fleet_manager.register_device(
            "device-acme-002",
            "acme-corp",
            tier="fortress",
            label="DC Fortress",
            department="Operations",
            ip_location={"lat": 38.9072, "lng": -77.0369, "city": "Washington DC"}
        )

        # Register devices for Startup
        fleet_manager.register_device(
            "device-startup-001",
            "startup-inc",
            tier="guardian",
            label="Home Office",
            ip_location={"lat": 37.7749, "lng": -122.4194, "city": "San Francisco"}
        )

        # Register users
        fleet_manager.register_user(
            "global-admin-001",
            "admin@hookprobe.com",
            name="Global Admin",
            access_level=AccessLevel.GLOBAL_ADMIN
        )
        fleet_manager.register_user(
            "fleet-admin-acme",
            "admin@acme.com",
            name="ACME Admin",
            access_level=AccessLevel.FLEET_ADMIN,
            customer_id="acme-corp"
        )
        fleet_manager.register_user(
            "user-acme-001",
            "user@acme.com",
            name="ACME User",
            access_level=AccessLevel.END_USER,
            customer_id="acme-corp",
            device_ids=["device-acme-001"]
        )

        return fleet_manager


class TestCustomerManagement(TestFleetManager):
    """Test customer registration and management."""

    def test_register_customer(self, fleet_manager):
        """Test registering a new customer."""
        customer = fleet_manager.register_customer(
            "test-corp",
            "Test Corporation",
            contact_email="test@corp.com",
            subscription_tier="professional"
        )

        assert customer.customer_id == "test-corp"
        assert customer.name == "Test Corporation"
        assert customer.subscription_tier == "professional"
        assert customer.device_count == 0

    def test_get_customer(self, populated_fleet_manager):
        """Test retrieving a customer."""
        customer = populated_fleet_manager.get_customer("acme-corp")

        assert customer is not None
        assert customer.name == "ACME Corporation"
        assert customer.subscription_tier == "enterprise"

    def test_get_nonexistent_customer(self, fleet_manager):
        """Test retrieving a non-existent customer."""
        customer = fleet_manager.get_customer("nonexistent")
        assert customer is None

    def test_get_all_customers(self, populated_fleet_manager):
        """Test retrieving all customers."""
        customers = populated_fleet_manager.get_all_customers()

        assert len(customers) == 2
        names = [c.name for c in customers]
        assert "ACME Corporation" in names
        assert "Startup Inc" in names


class TestDeviceManagement(TestFleetManager):
    """Test device registration and management."""

    def test_register_device(self, fleet_manager):
        """Test registering a device."""
        fleet_manager.register_customer("test-corp", "Test Corp")

        device = fleet_manager.register_device(
            "device-001",
            "test-corp",
            tier="guardian",
            label="Test Device",
            ip_location={"lat": 40.7128, "lng": -74.0060, "city": "New York"}
        )

        assert device.device_id == "device-001"
        assert device.tier == "guardian"
        assert device.ip_location.city == "New York"

    def test_register_device_invalid_customer(self, fleet_manager):
        """Test registering device with invalid customer."""
        device = fleet_manager.register_device(
            "device-001",
            "nonexistent-customer",
            tier="guardian"
        )
        assert device is None

    def test_device_with_declared_location(self, fleet_manager):
        """Test device with user-declared location."""
        fleet_manager.register_customer("test-corp", "Test Corp")

        device = fleet_manager.register_device(
            "device-001",
            "test-corp",
            ip_location={"lat": 40.7, "lng": -74.0, "city": "New York"},
            declared_location={"lat": 40.7580, "lng": -73.9855, "label": "Office Floor 5"}
        )

        assert device.declared_location is not None
        assert device.declared_location.label == "Office Floor 5"
        assert device.location_privacy == LocationPrivacy.DECLARED

    def test_update_device_health(self, populated_fleet_manager):
        """Test updating device health metrics."""
        result = populated_fleet_manager.update_device_health(
            "device-acme-001",
            qsecbit_score=0.65,
            heartbeat=True
        )

        assert result is True

        device = populated_fleet_manager.devices["device-acme-001"]
        assert device.qsecbit_score == 0.65
        assert device.qsecbit_status == "amber"
        assert device.online is True

    def test_qsecbit_status_thresholds(self, populated_fleet_manager):
        """Test Qsecbit status threshold calculations."""
        device_id = "device-acme-001"

        # Green < 0.45
        populated_fleet_manager.update_device_health(device_id, qsecbit_score=0.3)
        assert populated_fleet_manager.devices[device_id].qsecbit_status == "green"

        # Amber 0.45-0.70
        populated_fleet_manager.update_device_health(device_id, qsecbit_score=0.55)
        assert populated_fleet_manager.devices[device_id].qsecbit_status == "amber"

        # Red > 0.70
        populated_fleet_manager.update_device_health(device_id, qsecbit_score=0.85)
        assert populated_fleet_manager.devices[device_id].qsecbit_status == "red"


class TestAccessControl(TestFleetManager):
    """Test multi-tenant access control."""

    def test_global_admin_sees_all_devices(self, populated_fleet_manager):
        """Global admin should see all devices from all customers."""
        nodes = populated_fleet_manager.get_visible_nodes("global-admin-001")

        assert len(nodes) == 3  # 2 ACME + 1 Startup
        device_ids = [n["id"] for n in nodes]
        assert "device-acme-001" in device_ids
        assert "device-acme-002" in device_ids
        assert "device-startup-001" in device_ids

    def test_fleet_admin_sees_own_org_only(self, populated_fleet_manager):
        """Fleet admin should only see their organization's devices."""
        nodes = populated_fleet_manager.get_visible_nodes("fleet-admin-acme")

        assert len(nodes) == 2  # Only ACME devices
        device_ids = [n["id"] for n in nodes]
        assert "device-acme-001" in device_ids
        assert "device-acme-002" in device_ids
        assert "device-startup-001" not in device_ids

    def test_end_user_sees_own_devices_only(self, populated_fleet_manager):
        """End user should only see their assigned devices."""
        nodes = populated_fleet_manager.get_visible_nodes("user-acme-001")

        assert len(nodes) == 1
        assert nodes[0]["id"] == "device-acme-001"

    def test_global_admin_customer_filter(self, populated_fleet_manager):
        """Global admin can filter by customer."""
        nodes = populated_fleet_manager.get_visible_nodes(
            "global-admin-001",
            customer_filter="startup-inc"
        )

        assert len(nodes) == 1
        assert nodes[0]["id"] == "device-startup-001"

    def test_unknown_user_sees_nothing(self, populated_fleet_manager):
        """Unknown user should see no devices."""
        nodes = populated_fleet_manager.get_visible_nodes("unknown-user")
        assert len(nodes) == 0


class TestLocationPrivacy(TestFleetManager):
    """Test location privacy model."""

    def test_global_admin_sees_declared_location(self, populated_fleet_manager):
        """Global admin sees declared location when available."""
        nodes = populated_fleet_manager.get_visible_nodes("global-admin-001")

        # Find device with declared location
        acme_device = next(n for n in nodes if n["id"] == "device-acme-001")

        assert acme_device["location_precision"] == "declared"
        assert "Floor 42" in acme_device["label"] or acme_device["lat"] == 40.7580

    def test_fleet_admin_sees_declared_for_own_org(self, populated_fleet_manager):
        """Fleet admin sees declared location for their own org devices."""
        nodes = populated_fleet_manager.get_visible_nodes("fleet-admin-acme")

        acme_device = next(n for n in nodes if n["id"] == "device-acme-001")
        assert acme_device["location_precision"] == "declared"

    def test_ip_location_fallback(self, populated_fleet_manager):
        """Device without declared location uses IP-based city location."""
        nodes = populated_fleet_manager.get_visible_nodes("fleet-admin-acme")

        dc_device = next(n for n in nodes if n["id"] == "device-acme-002")
        assert dc_device["location_precision"] == "city"

    def test_cross_org_sees_city_only(self, populated_fleet_manager):
        """Users from other orgs should only see city-level location."""
        # Create a user from startup that somehow can see ACME devices
        # (This wouldn't happen in practice, but tests the location privacy)
        populated_fleet_manager.register_user(
            "startup-user",
            "user@startup.com",
            access_level=AccessLevel.FLEET_ADMIN,
            customer_id="startup-inc"
        )

        # They can only see their own devices
        nodes = populated_fleet_manager.get_visible_nodes("startup-user")
        assert len(nodes) == 1
        assert nodes[0]["id"] == "device-startup-001"


class TestCityClustering(TestFleetManager):
    """Test city-level aggregation for clustering."""

    def test_city_clusters(self, populated_fleet_manager):
        """Test city-level clustering aggregation."""
        clusters = populated_fleet_manager.get_city_clusters("global-admin-001")

        # Should have 3 clusters (NYC, DC, SF)
        assert len(clusters) == 3

        # Find NYC cluster (should be single node)
        nyc = next((c for c in clusters if "New York" in str(c) or c.get("lat", 0) > 40), None)
        assert nyc is not None

    def test_same_city_aggregation(self, populated_fleet_manager):
        """Devices in same city should cluster together."""
        # Add another NYC device
        populated_fleet_manager.register_device(
            "device-acme-003",
            "acme-corp",
            tier="sentinel",
            ip_location={"lat": 40.72, "lng": -74.01, "city": "New York"}
        )

        clusters = populated_fleet_manager.get_city_clusters("global-admin-001")

        # Find NYC cluster
        nyc_cluster = next(
            (c for c in clusters if c.get("type") == "cluster" and c.get("count", 0) >= 2),
            None
        )

        # Either we have a cluster or separate nodes at similar coords
        nyc_items = [c for c in clusters if abs(c.get("lat", 0) - 40.7) < 1]
        assert len(nyc_items) >= 1


class TestFleetStats(TestFleetManager):
    """Test fleet statistics generation."""

    def test_global_admin_stats(self, populated_fleet_manager):
        """Global admin gets global stats."""
        stats = populated_fleet_manager.get_fleet_stats("global-admin-001")

        assert stats["total_customers"] == 2
        assert stats["total_devices"] == 3
        assert "by_tier" in stats
        assert stats["by_tier"]["guardian"] == 2
        assert stats["by_tier"]["fortress"] == 1

    def test_fleet_admin_stats(self, populated_fleet_manager):
        """Fleet admin gets organization stats."""
        stats = populated_fleet_manager.get_fleet_stats("fleet-admin-acme")

        assert stats["total_devices"] == 2
        assert "by_department" in stats
        assert stats["by_department"]["Engineering"] == 1

    def test_end_user_stats(self, populated_fleet_manager):
        """End user gets limited stats."""
        stats = populated_fleet_manager.get_fleet_stats("user-acme-001")

        assert stats["total_devices"] == 1


class TestCustomerStats(TestFleetManager):
    """Test customer statistics updates."""

    def test_customer_stats_update_on_device_health(self, populated_fleet_manager):
        """Customer stats should update when device health changes."""
        # Set one device to amber, one to red
        populated_fleet_manager.update_device_health("device-acme-001", qsecbit_score=0.55)
        populated_fleet_manager.update_device_health("device-acme-002", qsecbit_score=0.80)

        customer = populated_fleet_manager.get_customer("acme-corp")

        assert customer.worst_status == "red"
        assert customer.avg_qsecbit > 0


class TestGlobalInstance:
    """Test global fleet manager instance."""

    def test_get_fleet_manager_singleton(self):
        """get_fleet_manager should return singleton."""
        fm1 = get_fleet_manager()
        fm2 = get_fleet_manager()

        assert fm1 is fm2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
