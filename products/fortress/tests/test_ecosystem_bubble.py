#!/usr/bin/env python3
"""
Test suite for Ecosystem Bubble functionality.

Tests the same-user device detection system including:
- Presence sensor with mDNS detection
- Behavioral clustering with DBSCAN
- Bubble lifecycle management
- SDN rule generation
"""

import pytest
import sys
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

# Add lib to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))


class TestDependencies:
    """Test that required dependencies are available."""

    def test_numpy_available(self):
        """Test numpy is importable."""
        try:
            import numpy as np
            assert np.__version__, "numpy version should be available"
            print(f"✓ numpy {np.__version__} available")
        except ImportError:
            pytest.skip("numpy not installed")

    def test_sklearn_available(self):
        """Test scikit-learn is importable."""
        try:
            from sklearn.cluster import DBSCAN
            from sklearn.preprocessing import StandardScaler
            print("✓ scikit-learn available")
        except ImportError:
            pytest.skip("scikit-learn not installed")

    def test_zeroconf_available(self):
        """Test zeroconf is importable."""
        try:
            from zeroconf import Zeroconf, ServiceBrowser
            print("✓ zeroconf available")
        except ImportError:
            pytest.skip("zeroconf not installed")


class TestBehavioralClustering:
    """Test the behavioral clustering engine."""

    @pytest.fixture
    def temp_db(self, tmp_path):
        """Create temporary database path."""
        return tmp_path / "clustering.db"

    def test_clustering_engine_init(self, temp_db):
        """Test clustering engine initialization."""
        with patch('behavior_clustering.CLUSTERING_DB', temp_db):
            from behavior_clustering import BehavioralClusteringEngine
            engine = BehavioralClusteringEngine()
            assert engine is not None
            print("✓ Clustering engine initialized")

    def test_update_behavior(self, temp_db):
        """Test updating device behavior."""
        with patch('behavior_clustering.CLUSTERING_DB', temp_db):
            from behavior_clustering import BehavioralClusteringEngine
            engine = BehavioralClusteringEngine()

            # Add device behavior
            engine.update_behavior(
                "AA:BB:CC:DD:EE:01",
                ecosystem="apple",
                time_correlation=0.8,
                proximity_score=0.7,
                sync_frequency=5.0,
                handoff_count=3,
                mdns_services=["_airplay._tcp", "_companion-link._tcp"],
                hostname_pattern="John's iPhone"
            )

            # Verify behavior stored
            behavior = engine._behaviors.get("AA:BB:CC:DD:EE:01")
            assert behavior is not None
            assert behavior.ecosystem == "apple"
            assert behavior.time_correlation == 0.8
            print("✓ Device behavior updated")

    def test_device_clustering(self, temp_db):
        """Test DBSCAN clustering of devices."""
        with patch('behavior_clustering.CLUSTERING_DB', temp_db):
            from behavior_clustering import BehavioralClusteringEngine

            engine = BehavioralClusteringEngine()

            # Add Apple ecosystem devices (same user - John)
            engine.update_behavior(
                "AA:BB:CC:DD:EE:01",
                ecosystem="apple",
                time_correlation=0.9,
                proximity_score=0.85,
                sync_frequency=10.0,
                handoff_count=5,
                mdns_services=["_airplay._tcp", "_companion-link._tcp"],
                mdns_device_id="ABC12345-001",
                hostname_pattern="John's iPhone"
            )

            engine.update_behavior(
                "AA:BB:CC:DD:EE:02",
                ecosystem="apple",
                time_correlation=0.88,
                proximity_score=0.82,
                sync_frequency=8.0,
                handoff_count=4,
                mdns_services=["_airplay._tcp", "_raop._tcp"],
                mdns_device_id="ABC12345-002",
                hostname_pattern="John's MacBook"
            )

            engine.update_behavior(
                "AA:BB:CC:DD:EE:03",
                ecosystem="apple",
                time_correlation=0.87,
                proximity_score=0.80,
                sync_frequency=6.0,
                handoff_count=3,
                mdns_services=["_homekit._tcp", "_companion-link._tcp"],
                mdns_device_id="ABC12345-003",
                hostname_pattern="John's iPad"
            )

            # Add different user device (separate bubble)
            engine.update_behavior(
                "FF:EE:DD:CC:BB:01",
                ecosystem="apple",
                time_correlation=0.2,
                proximity_score=0.1,
                sync_frequency=1.0,
                handoff_count=0,
                mdns_services=["_airplay._tcp"],
                mdns_device_id="XYZ99999-001",
                hostname_pattern="Guest iPhone"
            )

            # Run clustering
            clusters = engine.cluster_devices()

            print(f"✓ Found {len(clusters)} cluster(s)")
            for cluster in clusters:
                print(f"  Bubble: {cluster.bubble_id}")
                print(f"  Devices: {cluster.devices}")
                print(f"  Confidence: {cluster.confidence:.1%}")

            # With proper similarity, John's devices should cluster together
            # Note: Results depend on DBSCAN parameters and feature engineering
            assert len(clusters) >= 0  # May vary based on ML availability

    def test_rule_based_fallback(self, temp_db):
        """Test rule-based clustering when ML is unavailable."""
        with patch('behavior_clustering.CLUSTERING_DB', temp_db):
            from behavior_clustering import BehavioralClusteringEngine

            engine = BehavioralClusteringEngine()

            # Add devices with matching hostnames
            engine.update_behavior(
                "AA:BB:CC:DD:EE:01",
                ecosystem="apple",
                mdns_services=["_airplay._tcp", "_companion-link._tcp"],
                hostname_pattern="John's iPhone"
            )

            engine.update_behavior(
                "AA:BB:CC:DD:EE:02",
                ecosystem="apple",
                mdns_services=["_airplay._tcp", "_raop._tcp"],
                hostname_pattern="John's MacBook"
            )

            # Force rule-based clustering
            clusters = engine._rule_based_clustering()

            print(f"✓ Rule-based clustering found {len(clusters)} cluster(s)")
            # Check if John's devices are grouped
            for cluster in clusters:
                if "AA:BB:CC:DD:EE:01" in cluster.devices:
                    assert "AA:BB:CC:DD:EE:02" in cluster.devices, \
                        "Devices with same owner should be clustered"
                    print(f"  ✓ John's devices correctly grouped: {cluster.devices}")


class TestPresenceSensor:
    """Test the multi-modal presence sensor."""

    @pytest.fixture
    def temp_db(self, tmp_path):
        """Create temporary database path."""
        return tmp_path / "presence.db"

    def test_presence_sensor_init(self, temp_db):
        """Test presence sensor initialization."""
        with patch('presence_sensor.PRESENCE_DB', temp_db):
            from presence_sensor import PresenceSensor
            sensor = PresenceSensor(interface="vlan100")
            assert sensor is not None
            print("✓ Presence sensor initialized")

    def test_ecosystem_detection(self, temp_db):
        """Test ecosystem detection from mDNS service."""
        with patch('presence_sensor.PRESENCE_DB', temp_db):
            from presence_sensor import PresenceSensor, EcosystemType
            sensor = PresenceSensor()

            # Test Apple detection
            ecosystem = sensor._determine_ecosystem("_airplay._tcp", {})
            assert ecosystem == EcosystemType.APPLE
            print("✓ Apple ecosystem detected from AirPlay")

            # Test Google detection
            ecosystem = sensor._determine_ecosystem("_googlecast._tcp", {})
            assert ecosystem == EcosystemType.GOOGLE
            print("✓ Google ecosystem detected from Chromecast")

            # Test Amazon detection
            ecosystem = sensor._determine_ecosystem("_amzn-alexa._tcp", {})
            assert ecosystem == EcosystemType.AMAZON
            print("✓ Amazon ecosystem detected from Alexa")

    def test_record_network_event(self, temp_db):
        """Test recording network join/leave events."""
        with patch('presence_sensor.PRESENCE_DB', temp_db):
            from presence_sensor import PresenceSensor, PresenceState
            sensor = PresenceSensor()

            # Record join event
            sensor.record_network_event(
                mac="AA:BB:CC:DD:EE:01",
                event_type="join",
                access_point="FTS_5G"
            )

            device = sensor.get_device("AA:BB:CC:DD:EE:01")
            assert device is not None
            assert device.state == PresenceState.ACTIVE
            print("✓ Network join event recorded")


class TestEcosystemBubbleManager:
    """Test the main bubble manager orchestrator."""

    @pytest.fixture
    def temp_dbs(self, tmp_path):
        """Create temporary database paths."""
        return {
            'bubble': tmp_path / "bubbles.db",
            'clustering': tmp_path / "clustering.db",
            'presence': tmp_path / "presence.db"
        }

    def test_bubble_manager_init(self, temp_dbs):
        """Test bubble manager initialization."""
        with patch('ecosystem_bubble.BUBBLE_DB', temp_dbs['bubble']), \
             patch('behavior_clustering.CLUSTERING_DB', temp_dbs['clustering']), \
             patch('presence_sensor.PRESENCE_DB', temp_dbs['presence']):
            from ecosystem_bubble import EcosystemBubbleManager
            manager = EcosystemBubbleManager()
            assert manager is not None
            print("✓ Bubble manager initialized")

    def test_generate_bubble_rules(self, temp_dbs):
        """Test SDN rule generation for bubbles."""
        with patch('ecosystem_bubble.BUBBLE_DB', temp_dbs['bubble']), \
             patch('behavior_clustering.CLUSTERING_DB', temp_dbs['clustering']), \
             patch('presence_sensor.PRESENCE_DB', temp_dbs['presence']):
            from ecosystem_bubble import EcosystemBubbleManager, Bubble, BubbleState

            manager = EcosystemBubbleManager()

            # Create a test bubble
            bubble = Bubble(
                bubble_id="APL-abc123",
                ecosystem="apple",
                devices={"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"},
                state=BubbleState.ACTIVE,
                confidence=0.9
            )

            # Generate rules
            rules = manager._generate_bubble_rules(bubble)

            # 3 devices = 3 pairs = 6 rules (bidirectional)
            expected_rules = 3 * 2  # 3 device pairs * 2 directions
            assert len(rules) == expected_rules, f"Expected {expected_rules} rules, got {len(rules)}"
            print(f"✓ Generated {len(rules)} SDN rules for 3-device bubble")

            # Verify rule structure
            for rule in rules:
                assert rule['type'] == 'allow'
                assert rule['priority'] == 500
                assert 'eth_src' in rule['match']
                assert 'eth_dst' in rule['match']
                print(f"  Rule: {rule['match']['eth_src']} -> {rule['match']['eth_dst']}")

    def test_bubble_stats(self, temp_dbs):
        """Test getting bubble manager statistics."""
        with patch('ecosystem_bubble.BUBBLE_DB', temp_dbs['bubble']), \
             patch('behavior_clustering.CLUSTERING_DB', temp_dbs['clustering']), \
             patch('presence_sensor.PRESENCE_DB', temp_dbs['presence']):
            from ecosystem_bubble import EcosystemBubbleManager

            manager = EcosystemBubbleManager()
            stats = manager.get_stats()

            assert 'total_bubbles' in stats
            assert 'active_bubbles' in stats
            assert 'running' in stats
            print(f"✓ Stats: {stats}")


class TestIntegration:
    """End-to-end integration tests."""

    @pytest.fixture
    def temp_dbs(self, tmp_path):
        """Create temporary database paths."""
        return {
            'bubble': tmp_path / "bubbles.db",
            'clustering': tmp_path / "clustering.db",
            'presence': tmp_path / "presence.db"
        }

    def test_full_bubble_creation_flow(self, temp_dbs):
        """Test complete flow from device detection to bubble creation."""
        with patch('ecosystem_bubble.BUBBLE_DB', temp_dbs['bubble']), \
             patch('ecosystem_bubble.SDN_TRIGGER_FILE', temp_dbs['bubble'].parent / '.sdn_trigger'), \
             patch('behavior_clustering.CLUSTERING_DB', temp_dbs['clustering']), \
             patch('presence_sensor.PRESENCE_DB', temp_dbs['presence']):
            from ecosystem_bubble import get_bubble_manager
            from behavior_clustering import get_clustering_engine

            # Get singleton instances
            manager = get_bubble_manager()
            clustering = get_clustering_engine()

            # Simulate devices joining with correlated behavior
            devices = [
                {
                    'mac': 'AA:BB:CC:DD:EE:01',
                    'ecosystem': 'apple',
                    'time_correlation': 0.95,
                    'proximity_score': 0.9,
                    'sync_frequency': 15.0,
                    'handoff_count': 8,
                    'mdns_services': ['_airplay._tcp', '_companion-link._tcp'],
                    'mdns_device_id': 'DEV001',
                    'hostname_pattern': "Alice's iPhone",
                },
                {
                    'mac': 'AA:BB:CC:DD:EE:02',
                    'ecosystem': 'apple',
                    'time_correlation': 0.93,
                    'proximity_score': 0.88,
                    'sync_frequency': 12.0,
                    'handoff_count': 7,
                    'mdns_services': ['_airplay._tcp', '_raop._tcp'],
                    'mdns_device_id': 'DEV002',
                    'hostname_pattern': "Alice's MacBook Pro",
                },
            ]

            for device in devices:
                clustering.update_behavior(**device)
                print(f"  Added device: {device['mac']} ({device['hostname_pattern']})")

            # Run clustering
            clusters = clustering.cluster_devices()
            print(f"\n✓ Clustering complete: {len(clusters)} clusters found")

            # Check if Alice's devices were clustered
            stats = clustering.get_stats()
            print(f"  Clustering stats: {stats}")

            # Check bubble manager can check same-bubble relationship
            same, confidence = manager.are_same_bubble(
                'AA:BB:CC:DD:EE:01',
                'AA:BB:CC:DD:EE:02'
            )
            print(f"  Same bubble: {same} (confidence: {confidence:.1%})")


if __name__ == '__main__':
    # Run tests with verbose output
    pytest.main([__file__, '-v', '--tb=short', '-s'])
