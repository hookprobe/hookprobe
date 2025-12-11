#!/usr/bin/env python3
"""
Tests for HookProbe Globe Visualization Backend

Phase 1C: Production Integration Tests

Run with: pytest shared/cortex/tests/
"""

import pytest
import json
from datetime import datetime

# Add parent to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from demo_data import (
    DemoDataGenerator,
    HOOKPROBE_NODES,
    THREAT_SOURCES,
    ATTACK_TYPES,
    MITIGATION_METHODS,
)
from geo_resolver import GeoResolver
from node_registry import NodeRegistry, NodeTwin, NodeTier, QsecbitStatus


class TestDemoDataGenerator:
    """Tests for demo data generation."""

    def test_generator_initialization(self):
        """Test generator initializes correctly."""
        gen = DemoDataGenerator()
        assert gen.event_counter == 0
        assert len(gen.nodes) == len(HOOKPROBE_NODES)

    def test_generate_event_returns_dict(self):
        """Test that generate_event returns a dictionary."""
        gen = DemoDataGenerator()
        event = gen.generate_event()
        assert isinstance(event, dict)
        assert "type" in event
        assert "timestamp" in event

    def test_generate_event_increments_counter(self):
        """Test that event counter increments."""
        gen = DemoDataGenerator()
        gen.generate_event()
        gen.generate_event()
        gen.generate_event()
        assert gen.event_counter == 3

    def test_attack_event_structure(self):
        """Test attack event has correct structure."""
        gen = DemoDataGenerator()
        event = gen._generate_attack()

        assert event["type"] == "attack_detected"
        assert "source" in event
        assert "target" in event
        assert "severity" in event
        assert "attack_type" in event
        assert "description" in event  # New in Phase 1C

        # Check source structure
        assert "lat" in event["source"]
        assert "lng" in event["source"]
        assert "label" in event["source"]

        # Check target structure
        assert "lat" in event["target"]
        assert "lng" in event["target"]
        assert "node_id" in event["target"]

    def test_repelled_event_structure(self):
        """Test repelled event has correct structure."""
        gen = DemoDataGenerator()
        event = gen._generate_repelled()

        assert event["type"] == "attack_repelled"
        assert "mitigation" in event
        assert "response_ms" in event
        assert event["response_ms"] >= 1
        assert event["response_ms"] <= 200  # Updated range in Phase 3 (CAPTCHA can take up to 200ms)

        # Verify mitigation is valid (MITIGATION_METHODS is now tuples: name, min_ms, max_ms, desc)
        valid_methods = [m[0] for m in MITIGATION_METHODS]
        assert event["mitigation"] in valid_methods

    def test_node_status_event_structure(self):
        """Test node status event has correct structure."""
        gen = DemoDataGenerator()
        event = gen._generate_node_status()

        assert event["type"] == "node_status"
        assert "nodes" in event
        assert isinstance(event["nodes"], list)

        # Check first node structure
        node = event["nodes"][0]
        assert "id" in node
        assert "tier" in node
        assert "lat" in node
        assert "lng" in node
        assert "qsecbit" in node
        assert "status" in node
        assert "online" in node  # New in Phase 1C

        # Check qsecbit range
        assert 0.0 <= node["qsecbit"] <= 1.0

        # Check status is valid
        assert node["status"] in ["green", "amber", "red"]

    def test_qsecbit_update_event_structure(self):
        """Test Qsecbit update event has correct structure (new in Phase 1C)."""
        gen = DemoDataGenerator()
        event = gen._generate_qsecbit_update()

        assert event["type"] == "qsecbit_update"
        assert "node_id" in event
        assert "score" in event
        assert "components" in event
        assert "rag_status" in event

        # Check components
        assert "drift" in event["components"]
        assert "attack_probability" in event["components"]

        # Check RAG status
        assert event["rag_status"] in ["GREEN", "AMBER", "RED"]

    def test_severity_range(self):
        """Test that severity values are in valid range."""
        gen = DemoDataGenerator()
        for _ in range(100):
            event = gen._generate_attack()
            assert 0.0 <= event["severity"] <= 1.0

    def test_event_json_serializable(self):
        """Test that all events are JSON serializable."""
        gen = DemoDataGenerator()
        for _ in range(50):
            event = gen.generate_event()
            # Should not raise
            json_str = json.dumps(event)
            assert json_str

    def test_generate_burst(self):
        """Test burst event generation (new in Phase 1C)."""
        gen = DemoDataGenerator()
        burst = gen.generate_burst(count=5)

        assert len(burst) == 5
        for event in burst:
            assert event["type"] == "attack_detected"
            assert event.get("burst") is True

        # All should have same source (coordinated attack)
        first_source = burst[0]["source"]["label"]
        for event in burst:
            assert event["source"]["label"] == first_source

    def test_full_snapshot(self):
        """Test full snapshot generation."""
        gen = DemoDataGenerator()
        snapshot = gen.get_full_snapshot()

        # Phase 3: get_full_snapshot returns "snapshot" type with richer data
        assert snapshot["type"] == "snapshot"
        assert len(snapshot["nodes"]) == len(HOOKPROBE_NODES)
        assert "edges" in snapshot  # Mesh connections
        assert "stats" in snapshot  # Statistics
        assert "organizations" in snapshot  # Organization data

    def test_statistics(self):
        """Test statistics reporting."""
        gen = DemoDataGenerator()
        stats = gen.get_statistics()

        assert "total_nodes" in stats
        assert "nodes_by_tier" in stats
        assert "threat_sources" in stats
        assert "attack_types" in stats

        # Verify expanded data (~30% increase)
        assert stats["total_nodes"] >= 10  # Was 8, now 19
        assert stats["threat_sources"] >= 10  # Was 8, now 23
        assert stats["attack_types"] >= 15  # Was 6, now 21


class TestGeoResolver:
    """Tests for IP geolocation resolver."""

    def test_resolver_initialization(self):
        """Test resolver initializes without database."""
        resolver = GeoResolver()
        assert resolver.reader is None

    def test_resolve_known_ip(self):
        """Test resolving a known IP from fallback."""
        resolver = GeoResolver()
        lat, lng, info = resolver.resolve("8.8.8.8")

        assert lat is not None
        assert lng is not None
        assert info.get("source") == "fallback"

    def test_resolve_private_ip(self):
        """Test that private IPs return None."""
        resolver = GeoResolver()

        for ip in ["10.0.0.1", "172.16.0.1", "192.168.1.1"]:
            lat, lng, info = resolver.resolve(ip)
            assert lat is None
            assert lng is None
            assert info.get("error") == "Private IP"

    def test_resolve_caching(self):
        """Test that results are cached."""
        resolver = GeoResolver()

        # First call
        result1 = resolver.resolve("8.8.8.8")

        # Second call should hit cache
        result2 = resolver.resolve("8.8.8.8")

        assert result1 == result2

    def test_rough_estimate_fallback(self):
        """Test rough estimate for unknown IPs."""
        resolver = GeoResolver()
        lat, lng, info = resolver.resolve("200.100.50.25")

        # Should return some estimate
        assert lat is not None or info.get("error")


class TestNodeRegistry:
    """Tests for node registry (digital twin state)."""

    def test_registry_initialization(self):
        """Test registry initializes correctly."""
        registry = NodeRegistry()
        assert len(registry.nodes) == 0
        assert len(registry.edges) == 0

    def test_register_node(self):
        """Test node registration."""
        registry = NodeRegistry()
        node = registry.register_node(
            node_id="test-guardian-001",
            tier=NodeTier.GUARDIAN,
            lat=37.7749,
            lng=-122.4194,
            label="Test Guardian",
        )

        assert node.node_id == "test-guardian-001"
        assert node.tier == NodeTier.GUARDIAN
        assert registry.get_node("test-guardian-001") is node

    def test_register_node_update(self):
        """Test that re-registering updates existing node."""
        registry = NodeRegistry()
        registry.register_node(
            node_id="test-001",
            tier=NodeTier.GUARDIAN,
            lat=0.0,
            lng=0.0,
            label="Original",
        )

        registry.register_node(
            node_id="test-001",
            tier=NodeTier.GUARDIAN,
            lat=10.0,
            lng=20.0,
            label="Updated",
        )

        assert len(registry.nodes) == 1
        node = registry.get_node("test-001")
        assert node.lat == 10.0
        assert node.lng == 20.0
        assert node.label == "Updated"

    def test_on_heartbeat(self):
        """Test heartbeat updates."""
        registry = NodeRegistry()
        node = registry.register_node(
            node_id="test-001",
            tier=NodeTier.GUARDIAN,
            lat=0.0,
            lng=0.0,
        )

        assert node.online is False
        registry.on_heartbeat("test-001")
        assert node.online is True
        assert node.last_heartbeat is not None

    def test_qsecbit_update(self):
        """Test Qsecbit score updates."""
        registry = NodeRegistry()
        node = registry.register_node(
            node_id="test-001",
            tier=NodeTier.GUARDIAN,
            lat=0.0,
            lng=0.0,
        )

        # Test GREEN status
        registry.on_qsecbit_update("test-001", 0.30)
        assert node.qsecbit_score == 0.30
        assert node.qsecbit_status == QsecbitStatus.GREEN

        # Test AMBER status
        registry.on_qsecbit_update("test-001", 0.55)
        assert node.qsecbit_status == QsecbitStatus.AMBER

        # Test RED status
        registry.on_qsecbit_update("test-001", 0.85)
        assert node.qsecbit_status == QsecbitStatus.RED

    def test_snapshot(self):
        """Test snapshot generation."""
        registry = NodeRegistry()
        registry.register_node("node-1", NodeTier.GUARDIAN, 0.0, 0.0)
        registry.register_node("node-2", NodeTier.FORTRESS, 10.0, 20.0)

        snapshot = registry.get_snapshot()

        assert snapshot["type"] == "snapshot"
        assert len(snapshot["nodes"]) == 2
        assert "timestamp" in snapshot

    def test_event_callback(self):
        """Test event callback system."""
        registry = NodeRegistry()
        events_received = []

        def callback(event):
            events_received.append(event)

        registry.add_event_callback(callback)
        registry.register_node("test-001", NodeTier.GUARDIAN, 0.0, 0.0)
        registry.on_heartbeat("test-001")  # Should trigger node_online event

        assert len(events_received) == 1
        assert events_received[0]["type"] == "node_online"


class TestNodeTwin:
    """Tests for NodeTwin data model."""

    def test_node_twin_creation(self):
        """Test NodeTwin creation."""
        node = NodeTwin(
            node_id="test-001",
            tier=NodeTier.GUARDIAN,
            lat=37.7749,
            lng=-122.4194,
            label="Test Guardian",
        )

        assert node.node_id == "test-001"
        assert node.tier == NodeTier.GUARDIAN
        assert node.qsecbit_score == 0.0
        assert node.qsecbit_status == QsecbitStatus.GREEN
        assert node.online is False

    def test_update_qsecbit_threshold_detection(self):
        """Test Qsecbit threshold crossing detection."""
        node = NodeTwin(
            node_id="test-001",
            tier=NodeTier.GUARDIAN,
        )

        # No event for same status
        result = node.update_qsecbit(0.30)
        assert result is None

        # Event for crossing to AMBER
        result = node.update_qsecbit(0.50)
        assert result == "qsecbit_amber"

        # Event for crossing to RED
        result = node.update_qsecbit(0.80)
        assert result == "qsecbit_red"

        # Event for crossing back to GREEN
        result = node.update_qsecbit(0.20)
        assert result == "qsecbit_green"

    def test_qsecbit_history(self):
        """Test Qsecbit history tracking."""
        node = NodeTwin(
            node_id="test-001",
            tier=NodeTier.GUARDIAN,
        )

        for i in range(100):
            node.update_qsecbit(i / 100.0)

        # Should only keep last 60 readings
        assert len(node.qsecbit_history) == 60

    def test_to_dict(self):
        """Test serialization to dictionary."""
        node = NodeTwin(
            node_id="test-001",
            tier=NodeTier.GUARDIAN,
            lat=37.7749,
            lng=-122.4194,
            label="Test Guardian",
        )
        node.update_qsecbit(0.35)
        node.update_heartbeat()

        data = node.to_dict()

        assert data["id"] == "test-001"
        assert data["tier"] == "guardian"
        assert data["lat"] == 37.7749
        assert data["lng"] == -122.4194
        assert data["qsecbit"] == 0.35
        assert data["status"] == "green"
        assert data["online"] is True


class TestDataIntegrity:
    """Tests for data integrity and consistency."""

    def test_hookprobe_nodes_valid(self):
        """Test that all predefined nodes have valid data."""
        for node in HOOKPROBE_NODES:
            assert "id" in node
            assert "tier" in node
            assert "lat" in node
            assert "lng" in node
            assert "label" in node

            # Valid latitude
            assert -90 <= node["lat"] <= 90

            # Valid longitude
            assert -180 <= node["lng"] <= 180

            # Valid tier
            assert node["tier"] in ["sentinel", "guardian", "fortress", "nexus"]

    def test_threat_sources_valid(self):
        """Test that all threat sources have valid data."""
        for source in THREAT_SOURCES:
            assert "lat" in source
            assert "lng" in source
            assert "label" in source

            # Valid latitude
            assert -90 <= source["lat"] <= 90

            # Valid longitude
            assert -180 <= source["lng"] <= 180

    def test_attack_types_valid(self):
        """Test that all attack types have valid data (Phase 3 expanded format)."""
        for attack in ATTACK_TYPES:
            # Phase 3: (name, severity, description, category, weight)
            assert len(attack) == 5
            name, severity, description, category, weight = attack

            assert isinstance(name, str)
            assert 0.0 <= severity <= 1.0
            assert isinstance(description, str)
            assert isinstance(category, str)
            assert category in ["ddos", "credential", "malware", "web", "api", "advanced", "scan", "bruteforce"]
            assert isinstance(weight, (int, float))
            assert weight > 0

    def test_expanded_data_coverage(self):
        """Test that data has been expanded to enterprise scale (Phase 3)."""
        # Phase 3: Enterprise scale for collective defense visualization
        # 5 organizations with 75+ nodes total
        assert len(HOOKPROBE_NODES) >= 70  # Enterprise scale
        assert len(THREAT_SOURCES) >= 30  # Global threat sources
        assert len(ATTACK_TYPES) >= 20  # Comprehensive attack types


class TestHTPBridgeConfig:
    """Tests for HTP Bridge configuration."""

    def test_htp_bridge_config(self):
        """Test HTP bridge configuration dataclass."""
        from htp_bridge import HTPBridgeConfig

        config = HTPBridgeConfig(
            bootstrap_nodes=[("localhost", 8144)],
            node_id="test-bridge",
            lat=0.0,
            lng=0.0,
        )

        assert config.node_id == "test-bridge"
        assert len(config.bootstrap_nodes) == 1
        assert config.tier == "nexus"  # Bridge presents as nexus

    def test_create_bridge_factory(self):
        """Test bridge factory function."""
        from htp_bridge import create_bridge

        bridge = create_bridge(
            bootstrap_nodes=[("localhost", 8144)],
            node_id="test-bridge",
        )

        assert bridge.config.node_id == "test-bridge"
        assert bridge.running is False

    def test_bridge_stats(self):
        """Test bridge statistics."""
        from htp_bridge import create_bridge

        bridge = create_bridge(node_id="test-bridge")
        stats = bridge.get_stats()

        assert "htp_messages_received" in stats
        assert "threats_detected" in stats
        assert "qsecbit_updates" in stats
        assert "htp_available" in stats
        assert "qsecbit_available" in stats


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
