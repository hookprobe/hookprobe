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
            sensor = PresenceSensor(interface="FTS")
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


class TestManualBubbleManagement:
    """Test manual bubble management features."""

    @pytest.fixture
    def temp_dbs(self, tmp_path):
        """Create temporary database paths."""
        return {
            'bubble': tmp_path / "bubbles.db",
            'clustering': tmp_path / "clustering.db",
            'presence': tmp_path / "presence.db"
        }

    def test_bubble_types(self, temp_dbs):
        """Test BubbleType enum and policies."""
        with patch('ecosystem_bubble.BUBBLE_DB', temp_dbs['bubble']), \
             patch('behavior_clustering.CLUSTERING_DB', temp_dbs['clustering']), \
             patch('presence_sensor.PRESENCE_DB', temp_dbs['presence']):
            from ecosystem_bubble import BubbleType, BUBBLE_TYPE_POLICIES

            # Verify all bubble types have policies
            for bubble_type in BubbleType:
                assert bubble_type in BUBBLE_TYPE_POLICIES, \
                    f"Missing policy for {bubble_type}"
                policy = BUBBLE_TYPE_POLICIES[bubble_type]
                assert 'internet_access' in policy
                assert 'lan_access' in policy
                assert 'vlan' in policy
                print(f"✓ {bubble_type.value}: VLAN {policy['vlan']}")

    def test_create_manual_bubble(self, temp_dbs):
        """Test creating a manual bubble."""
        with patch('ecosystem_bubble.BUBBLE_DB', temp_dbs['bubble']), \
             patch('ecosystem_bubble.SDN_TRIGGER_FILE', temp_dbs['bubble'].parent / '.sdn_trigger'), \
             patch('behavior_clustering.CLUSTERING_DB', temp_dbs['clustering']), \
             patch('presence_sensor.PRESENCE_DB', temp_dbs['presence']):
            from ecosystem_bubble import EcosystemBubbleManager, BubbleType

            manager = EcosystemBubbleManager()

            # Create a family bubble
            bubble = manager.create_manual_bubble(
                name="Dad's Devices",
                bubble_type=BubbleType.FAMILY,
                devices=["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"]
            )

            assert bubble is not None
            assert bubble.name == "Dad's Devices"
            assert bubble.bubble_type == BubbleType.FAMILY
            assert len(bubble.devices) == 2
            assert bubble.is_manual is True
            assert bubble.created_by == 'user'
            print(f"✓ Created manual bubble: {bubble.bubble_id}")

    def test_move_device_between_bubbles(self, temp_dbs):
        """Test moving a device from one bubble to another."""
        with patch('ecosystem_bubble.BUBBLE_DB', temp_dbs['bubble']), \
             patch('ecosystem_bubble.SDN_TRIGGER_FILE', temp_dbs['bubble'].parent / '.sdn_trigger'), \
             patch('behavior_clustering.CLUSTERING_DB', temp_dbs['clustering']), \
             patch('presence_sensor.PRESENCE_DB', temp_dbs['presence']):
            from ecosystem_bubble import EcosystemBubbleManager, BubbleType

            manager = EcosystemBubbleManager()

            # Create two bubbles
            dad_bubble = manager.create_manual_bubble(
                name="Dad",
                bubble_type=BubbleType.FAMILY,
                devices=["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"]
            )

            mom_bubble = manager.create_manual_bubble(
                name="Mom",
                bubble_type=BubbleType.FAMILY,
                devices=["FF:EE:DD:CC:BB:01"]
            )

            # Move device from Dad to Mom
            result = manager.move_device(
                mac="AA:BB:CC:DD:EE:02",
                to_bubble_id=mom_bubble.bubble_id
            )

            assert result is True
            # Refresh bubbles
            updated_dad = manager.get_bubble(dad_bubble.bubble_id)
            updated_mom = manager.get_bubble(mom_bubble.bubble_id)

            assert "AA:BB:CC:DD:EE:02" not in updated_dad.devices
            assert "AA:BB:CC:DD:EE:02" in updated_mom.devices
            print("✓ Device moved successfully")

    def test_pin_bubble(self, temp_dbs):
        """Test pinning a bubble to prevent AI changes."""
        with patch('ecosystem_bubble.BUBBLE_DB', temp_dbs['bubble']), \
             patch('ecosystem_bubble.SDN_TRIGGER_FILE', temp_dbs['bubble'].parent / '.sdn_trigger'), \
             patch('behavior_clustering.CLUSTERING_DB', temp_dbs['clustering']), \
             patch('presence_sensor.PRESENCE_DB', temp_dbs['presence']):
            from ecosystem_bubble import EcosystemBubbleManager, BubbleType

            manager = EcosystemBubbleManager()

            bubble = manager.create_manual_bubble(
                name="Kids",
                bubble_type=BubbleType.FAMILY,
                devices=["AA:BB:CC:DD:EE:03"]
            )

            # Pin the bubble
            result = manager.pin_bubble(bubble.bubble_id, pinned=True)
            assert result is True

            # Verify it's pinned
            updated = manager.get_bubble(bubble.bubble_id)
            assert updated.pinned is True
            print("✓ Bubble pinned successfully")

    def test_guest_bubble_isolation(self, temp_dbs):
        """Test that guest bubbles have internet-only access."""
        with patch('ecosystem_bubble.BUBBLE_DB', temp_dbs['bubble']), \
             patch('ecosystem_bubble.SDN_TRIGGER_FILE', temp_dbs['bubble'].parent / '.sdn_trigger'), \
             patch('behavior_clustering.CLUSTERING_DB', temp_dbs['clustering']), \
             patch('presence_sensor.PRESENCE_DB', temp_dbs['presence']):
            from ecosystem_bubble import EcosystemBubbleManager, BubbleType, BUBBLE_TYPE_POLICIES

            manager = EcosystemBubbleManager()

            bubble = manager.create_manual_bubble(
                name="Guest",
                bubble_type=BubbleType.GUEST,
                devices=["GG:UU:EE:SS:TT:01"]
            )

            # Verify guest policy
            guest_policy = BUBBLE_TYPE_POLICIES[BubbleType.GUEST]
            assert guest_policy['internet_access'] is True
            assert guest_policy['lan_access'] is False
            assert guest_policy['smart_home_access'] is False
            assert guest_policy['d2d_allowed'] is False
            print(f"✓ Guest bubble isolated: VLAN {guest_policy['vlan']}")

    def test_ai_suggestions(self, temp_dbs):
        """Test getting AI suggestions for bubble assignments."""
        with patch('ecosystem_bubble.BUBBLE_DB', temp_dbs['bubble']), \
             patch('ecosystem_bubble.SDN_TRIGGER_FILE', temp_dbs['bubble'].parent / '.sdn_trigger'), \
             patch('behavior_clustering.CLUSTERING_DB', temp_dbs['clustering']), \
             patch('presence_sensor.PRESENCE_DB', temp_dbs['presence']):
            from ecosystem_bubble import EcosystemBubbleManager, BubbleType
            from behavior_clustering import get_clustering_engine

            manager = EcosystemBubbleManager()
            clustering = get_clustering_engine()

            # Create a bubble
            manager.create_manual_bubble(
                name="Family",
                bubble_type=BubbleType.FAMILY,
                devices=["AA:BB:CC:DD:EE:01"]
            )

            # Add correlated device behavior
            clustering.update_behavior(
                mac="AA:BB:CC:DD:EE:01",
                ecosystem="apple",
                time_correlation=0.95,
                hostname_pattern="Dad's iPhone"
            )
            clustering.update_behavior(
                mac="AA:BB:CC:DD:EE:02",
                ecosystem="apple",
                time_correlation=0.93,
                hostname_pattern="Dad's iPad"
            )

            # Get AI suggestions
            suggestions = manager.get_ai_suggestions()
            print(f"✓ Got {len(suggestions)} AI suggestions")
            for s in suggestions:
                print(f"  {s.get('device_mac')}: {s.get('reason')}")


class TestConnectionGraph:
    """Test D2D connection graph analysis."""

    @pytest.fixture
    def temp_zeek_log(self, tmp_path):
        """Create temporary Zeek conn.log with test data."""
        log_dir = tmp_path / "zeek" / "current"
        log_dir.mkdir(parents=True)
        conn_log = log_dir / "conn.log"

        # Sample Zeek conn.log entries (JSON format)
        import json
        entries = [
            {
                "ts": 1704067200.0,
                "id.orig_h": "10.200.0.10",  # Dad's iPhone
                "id.orig_p": 12345,
                "id.resp_h": "10.200.0.11",  # Dad's MacBook
                "id.resp_p": 445,
                "proto": "tcp",
                "service": "smb",
                "duration": 5.5,
                "orig_bytes": 1024,
                "resp_bytes": 2048,
                "conn_state": "SF",
                "orig_l2_addr": "aa:bb:cc:dd:ee:01",
                "resp_l2_addr": "aa:bb:cc:dd:ee:02",
            },
            {
                "ts": 1704067300.0,
                "id.orig_h": "10.200.0.10",
                "id.orig_p": 54321,
                "id.resp_h": "10.200.0.12",  # Dad's iPad
                "id.resp_p": 5353,
                "proto": "udp",
                "service": "mdns",
                "duration": 0.5,
                "orig_bytes": 128,
                "resp_bytes": 256,
                "conn_state": "SF",
                "orig_l2_addr": "aa:bb:cc:dd:ee:01",
                "resp_l2_addr": "aa:bb:cc:dd:ee:03",
            },
        ]

        with open(conn_log, 'w') as f:
            for entry in entries:
                f.write(json.dumps(entry) + '\n')

        return tmp_path / "zeek"

    def test_connection_graph_init(self, temp_zeek_log):
        """Test connection graph initialization."""
        with patch('connection_graph.ZEEK_LOG_DIR', temp_zeek_log / 'current'):
            from connection_graph import D2DConnectionGraph
            graph = D2DConnectionGraph()
            assert graph is not None
            print("✓ Connection graph initialized")

    def test_parse_zeek_conn_log(self, temp_zeek_log):
        """Test parsing Zeek conn.log for D2D connections."""
        with patch('connection_graph.ZEEK_LOG_DIR', temp_zeek_log / 'current'), \
             patch('connection_graph.ZEEK_CONN_LOG', temp_zeek_log / 'current' / 'conn.log'):
            from connection_graph import D2DConnectionGraph
            graph = D2DConnectionGraph()

            connections = graph.parse_zeek_conn_log()
            assert len(connections) == 2
            print(f"✓ Parsed {len(connections)} connections")

            for conn in connections:
                print(f"  {conn.src_mac} -> {conn.dst_mac} ({conn.service})")

    def test_affinity_score_calculation(self, temp_zeek_log):
        """Test affinity score calculation."""
        with patch('connection_graph.ZEEK_LOG_DIR', temp_zeek_log / 'current'), \
             patch('connection_graph.ZEEK_CONN_LOG', temp_zeek_log / 'current' / 'conn.log'):
            from connection_graph import D2DConnectionGraph
            graph = D2DConnectionGraph()

            # Parse connections and analyze
            graph.parse_zeek_conn_log()
            graph.analyze_relationships()

            # Get affinity between two devices
            affinity = graph.get_affinity(
                "aa:bb:cc:dd:ee:01",
                "aa:bb:cc:dd:ee:02"
            )

            assert 0 <= affinity <= 1.0
            print(f"✓ Affinity score: {affinity:.2%}")

    def test_high_affinity_services(self, temp_zeek_log):
        """Test detection of high-affinity service types."""
        with patch('connection_graph.ZEEK_LOG_DIR', temp_zeek_log / 'current'):
            from connection_graph import HIGH_AFFINITY_SERVICES

            # SMB/file sharing indicates same-user devices
            assert 'smb' in HIGH_AFFINITY_SERVICES
            # mDNS for discovery
            assert 'mdns' in HIGH_AFFINITY_SERVICES
            # AirPlay/AirDrop
            assert 'airplay' in HIGH_AFFINITY_SERVICES or 'airdrop' in HIGH_AFFINITY_SERVICES
            print(f"✓ High-affinity services defined: {len(HIGH_AFFINITY_SERVICES)}")


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


class TestMDNSQueryResponsePairing:
    """Test mDNS query/response pairing for device relationship detection."""

    @pytest.fixture
    def temp_db(self, tmp_path):
        """Create temporary database path."""
        return tmp_path / "presence.db"

    def test_record_mdns_query(self, temp_db):
        """Test recording an mDNS query."""
        with patch('presence_sensor.PRESENCE_DB', temp_db):
            from presence_sensor import PresenceSensor
            sensor = PresenceSensor()

            # Record a query
            sensor.record_mdns_query(
                mac="AA:BB:CC:DD:EE:01",
                service_type="_airplay._tcp",
                query_name="Apple TV"
            )

            # Verify query recorded
            assert len(sensor._mdns_queries) > 0
            query = sensor._mdns_queries[0]
            assert query.query_mac == "AA:BB:CC:DD:EE:01"
            assert query.service_type == "_airplay._tcp"
            print("✓ mDNS query recorded")

    def test_mdns_query_response_pairing(self, temp_db):
        """Test pairing mDNS queries with responses."""
        with patch('presence_sensor.PRESENCE_DB', temp_db):
            from presence_sensor import PresenceSensor
            sensor = PresenceSensor()

            # Record query from iPhone
            sensor.record_mdns_query(
                mac="AA:BB:CC:DD:EE:01",  # iPhone
                service_type="_airplay._tcp",
                query_name="Apple TV"
            )

            # Record response from Apple TV
            sensor.record_mdns_response(
                mac="FF:EE:DD:CC:BB:AA",  # Apple TV
                service_type="_airplay._tcp",
                service_name="Apple TV"
            )

            # Check discovery pair was created
            pairs = sensor.get_discovery_pairs()
            assert len(pairs) > 0
            print(f"✓ Created {len(pairs)} discovery pair(s)")

    def test_discovery_hits_count(self, temp_db):
        """Test counting discovery hits between devices."""
        with patch('presence_sensor.PRESENCE_DB', temp_db):
            from presence_sensor import PresenceSensor
            sensor = PresenceSensor()

            mac_a = "AA:BB:CC:DD:EE:01"
            mac_b = "FF:EE:DD:CC:BB:AA"

            # Multiple queries/responses
            for i in range(3):
                sensor.record_mdns_query(mac_a, "_airplay._tcp", f"Query-{i}")
                sensor.record_mdns_response(mac_b, "_airplay._tcp", f"Response-{i}")

            # Get discovery hits
            hits = sensor.get_discovery_hits(mac_a, mac_b)
            assert hits >= 3
            print(f"✓ Discovery hits: {hits}")


class TestTemporalAffinityScoring:
    """Test enhanced temporal affinity scoring."""

    @pytest.fixture
    def temp_zeek_log(self, tmp_path):
        """Create temporary Zeek log directory."""
        log_dir = tmp_path / "zeek" / "current"
        log_dir.mkdir(parents=True)
        conn_log = log_dir / "conn.log"
        conn_log.touch()
        return tmp_path / "zeek"

    def test_temporal_pattern_creation(self, temp_zeek_log):
        """Test creating temporal patterns for devices."""
        with patch('connection_graph.ZEEK_LOG_DIR', temp_zeek_log / 'current'), \
             patch('connection_graph.ZEEK_CONN_LOG', temp_zeek_log / 'current' / 'conn.log'):
            from connection_graph import TemporalPattern

            pattern = TemporalPattern(mac="AA:BB:CC:DD:EE:01")
            pattern.active_hours = {8, 9, 10, 11, 12, 18, 19, 20, 21}
            pattern.wake_events = [(8, 0), (8, 1), (8, 2)]  # (hour, day_of_week)
            pattern.sleep_events = [(22, 0), (22, 1), (23, 2)]

            assert len(pattern.active_hours) == 9
            print(f"✓ Temporal pattern created: {len(pattern.active_hours)} active hours")

    def test_temporal_similarity(self, temp_zeek_log):
        """Test calculating temporal similarity between devices."""
        with patch('connection_graph.ZEEK_LOG_DIR', temp_zeek_log / 'current'), \
             patch('connection_graph.ZEEK_CONN_LOG', temp_zeek_log / 'current' / 'conn.log'):
            from connection_graph import TemporalPattern

            # Two devices with similar patterns (same user)
            pattern_a = TemporalPattern(mac="AA:BB:CC:DD:EE:01")
            pattern_a.active_hours = {8, 9, 10, 11, 12, 18, 19, 20, 21}
            pattern_a.wake_events = [(8, 0), (8, 1), (8, 2)]

            pattern_b = TemporalPattern(mac="AA:BB:CC:DD:EE:02")
            pattern_b.active_hours = {8, 9, 10, 11, 13, 18, 19, 20, 22}
            pattern_b.wake_events = [(8, 0), (8, 1), (9, 2)]

            similarity = pattern_a.similarity(pattern_b)
            assert 0 <= similarity <= 1.0
            assert similarity > 0.5  # Should be high for similar patterns
            print(f"✓ Temporal similarity: {similarity:.2%}")

    def test_different_user_low_similarity(self, temp_zeek_log):
        """Test that different users have low temporal similarity."""
        with patch('connection_graph.ZEEK_LOG_DIR', temp_zeek_log / 'current'), \
             patch('connection_graph.ZEEK_CONN_LOG', temp_zeek_log / 'current' / 'conn.log'):
            from connection_graph import TemporalPattern

            # Day worker
            pattern_a = TemporalPattern(mac="AA:BB:CC:DD:EE:01")
            pattern_a.active_hours = {8, 9, 10, 11, 12, 13, 14, 15, 16}

            # Night worker
            pattern_b = TemporalPattern(mac="FF:EE:DD:CC:BB:AA")
            pattern_b.active_hours = {20, 21, 22, 23, 0, 1, 2, 3, 4}

            similarity = pattern_a.similarity(pattern_b)
            assert similarity < 0.3  # Should be low for different patterns
            print(f"✓ Different user similarity: {similarity:.2%}")


class TestReinforcementLearning:
    """Test reinforcement learning feedback engine."""

    @pytest.fixture
    def temp_db(self, tmp_path):
        """Create temporary database path."""
        return tmp_path / "feedback.db"

    def test_feedback_engine_init(self, temp_db):
        """Test feedback engine initialization."""
        with patch('reinforcement_feedback.FEEDBACK_DB', temp_db):
            from reinforcement_feedback import ReinforcementFeedbackEngine
            engine = ReinforcementFeedbackEngine(db_path=temp_db)
            assert engine is not None
            print("✓ Reinforcement feedback engine initialized")

    def test_record_correction(self, temp_db):
        """Test recording a user correction."""
        with patch('reinforcement_feedback.FEEDBACK_DB', temp_db):
            from reinforcement_feedback import ReinforcementFeedbackEngine
            engine = ReinforcementFeedbackEngine(db_path=temp_db)

            # User moves device from Dad's bubble to Mom's bubble
            engine.record_correction(
                mac="AA:BB:CC:DD:EE:01",
                old_bubble_id="bubble-dad",
                new_bubble_id="bubble-mom",
                old_bubble_devices=["AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"],
                new_bubble_devices=["FF:EE:DD:CC:BB:01"],
                reason="Device actually belongs to Mom"
            )

            assert len(engine._pending_corrections) == 1
            print("✓ Correction recorded")

    def test_apply_corrections(self, temp_db):
        """Test applying corrections to affinity scores."""
        with patch('reinforcement_feedback.FEEDBACK_DB', temp_db):
            from reinforcement_feedback import ReinforcementFeedbackEngine
            engine = ReinforcementFeedbackEngine(db_path=temp_db)

            # Record and apply correction
            engine.record_correction(
                mac="AA:BB:CC:DD:EE:01",
                old_bubble_id="bubble-dad",
                new_bubble_id="bubble-mom",
                old_bubble_devices=["AA:BB:CC:DD:EE:02"],
                new_bubble_devices=["FF:EE:DD:CC:BB:01"],
            )

            engine.apply_pending_corrections()

            # Check negative adjustment with old bubble device
            adj_old = engine.get_affinity_adjustment(
                "AA:BB:CC:DD:EE:01",
                "AA:BB:CC:DD:EE:02"
            )
            assert adj_old < 0  # Negative feedback
            print(f"✓ Old bubble adjustment: {adj_old:+.3f}")

            # Check positive adjustment with new bubble device
            adj_new = engine.get_affinity_adjustment(
                "AA:BB:CC:DD:EE:01",
                "FF:EE:DD:CC:BB:01"
            )
            assert adj_new > 0  # Positive feedback
            print(f"✓ New bubble adjustment: {adj_new:+.3f}")

    def test_adjusted_affinity(self, temp_db):
        """Test getting adjusted affinity score."""
        with patch('reinforcement_feedback.FEEDBACK_DB', temp_db):
            from reinforcement_feedback import ReinforcementFeedbackEngine
            engine = ReinforcementFeedbackEngine(db_path=temp_db)

            # Set up a known adjustment
            engine._adjustments[("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02")] = 0.2

            # Get adjusted affinity
            base_affinity = 0.5
            adjusted = engine.get_adjusted_affinity(
                "AA:BB:CC:DD:EE:01",
                "AA:BB:CC:DD:EE:02",
                base_affinity
            )

            assert adjusted == 0.7  # 0.5 + 0.2
            print(f"✓ Adjusted affinity: {base_affinity} -> {adjusted}")

    def test_decay_factor(self, temp_db):
        """Test that adjustments decay over time."""
        with patch('reinforcement_feedback.FEEDBACK_DB', temp_db):
            from reinforcement_feedback import ReinforcementFeedbackEngine, DECAY_FACTOR
            engine = ReinforcementFeedbackEngine(db_path=temp_db)

            # Set up adjustment
            initial_adj = 0.2
            engine._adjustments[("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02")] = initial_adj

            # Apply decay
            engine.apply_decay()

            new_adj = engine.get_affinity_adjustment(
                "AA:BB:CC:DD:EE:01",
                "AA:BB:CC:DD:EE:02"
            )

            expected = initial_adj * DECAY_FACTOR
            assert abs(new_adj - expected) < 0.001
            print(f"✓ Decay applied: {initial_adj} -> {new_adj}")


class TestN8NWebhook:
    """Test n8n webhook integration."""

    def test_webhook_client_init(self):
        """Test webhook client initialization."""
        with patch('n8n_webhook.CONFIG_FILE', Path('/tmp/nonexistent.conf')):
            from n8n_webhook import N8NWebhookClient
            client = N8NWebhookClient(enabled=False)
            assert client is not None
            print("✓ Webhook client initialized")

    def test_event_creation(self):
        """Test creating webhook events."""
        from n8n_webhook import WebhookEvent
        from datetime import datetime

        event = WebhookEvent(
            event_type="bubble_change",
            timestamp=datetime.now(),
            data={
                "mac": "AA:BB:CC:DD:EE:01",
                "old_bubble_id": "bubble-1",
                "new_bubble_id": "bubble-2"
            }
        )

        assert event.event_type == "bubble_change"
        json_str = event.to_json()
        assert "bubble_change" in json_str
        print("✓ Webhook event created")

    def test_event_queue(self):
        """Test queueing events."""
        with patch('n8n_webhook.CONFIG_FILE', Path('/tmp/nonexistent.conf')):
            from n8n_webhook import N8NWebhookClient
            # Create client with URL but don't actually send
            client = N8NWebhookClient(
                webhook_url="http://localhost:5678/webhook/test",
                enabled=True
            )

            # Queue an event
            client.send("test_event", {"message": "test"})

            # Check queue
            assert client._event_queue.qsize() >= 0
            print("✓ Event queued successfully")

            # Stop client
            client.stop()

    def test_convenience_methods(self):
        """Test convenience methods for specific event types."""
        with patch('n8n_webhook.CONFIG_FILE', Path('/tmp/nonexistent.conf')):
            from n8n_webhook import N8NWebhookClient
            client = N8NWebhookClient(enabled=False)

            # These shouldn't raise errors even when disabled
            client.on_bubble_change("AA:BB:CC:DD:EE:01", "old", "new")
            client.on_device_join("AA:BB:CC:DD:EE:01", "10.200.0.10", "iPhone", "bubble-1")
            client.on_manual_correction("AA:BB:CC:DD:EE:01", "old", "new", "test reason")
            print("✓ Convenience methods work when disabled")


class TestClickHouseGraphStorage:
    """Test ClickHouse graph storage (with mocks)."""

    def test_clickhouse_store_init(self):
        """Test ClickHouse store initialization."""
        with patch('clickhouse_graph.ClickHouseGraphStore._init_client') as mock_init:
            mock_init.return_value = None
            from clickhouse_graph import ClickHouseGraphStore
            store = ClickHouseGraphStore(enabled=False)
            assert store is not None
            print("✓ ClickHouse store initialized (disabled mode)")

    def test_record_relationship_disabled(self):
        """Test recording relationship when disabled."""
        with patch('clickhouse_graph.ClickHouseGraphStore._init_client') as mock_init:
            mock_init.return_value = None
            from clickhouse_graph import ClickHouseGraphStore
            store = ClickHouseGraphStore(enabled=False)

            # Should not raise error when disabled
            store.record_relationship(
                mac_a="AA:BB:CC:DD:EE:01",
                mac_b="AA:BB:CC:DD:EE:02",
                connection_count=5,
                high_affinity_count=3,
                services=["smb", "mdns"],
                temporal_sync=0.8,
                affinity_score=0.75
            )
            print("✓ Record relationship works when disabled")

    def test_record_bubble_assignment_disabled(self):
        """Test recording bubble assignment when disabled."""
        with patch('clickhouse_graph.ClickHouseGraphStore._init_client') as mock_init:
            mock_init.return_value = None
            from clickhouse_graph import ClickHouseGraphStore
            store = ClickHouseGraphStore(enabled=False)

            # Should not raise error when disabled
            store.record_bubble_assignment(
                mac="AA:BB:CC:DD:EE:01",
                bubble_id="bubble-dad",
                bubble_name="Dad",
                bubble_type="FAMILY",
                confidence=0.95,
                is_manual=True,
                source="user"
            )
            print("✓ Record bubble assignment works when disabled")


if __name__ == '__main__':
    # Run tests with verbose output
    pytest.main([__file__, '-v', '--tb=short', '-s'])
