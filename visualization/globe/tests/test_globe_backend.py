#!/usr/bin/env python3
"""
Tests for HookProbe Globe Visualization Backend

Run with: pytest visualization/globe/tests/
"""

import pytest
import json
from datetime import datetime

# Add parent to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from demo_data import DemoDataGenerator, HOOKPROBE_NODES, THREAT_SOURCES
from geo_resolver import GeoResolver


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
        assert event["response_ms"] <= 50

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

        # Check qsecbit range
        assert 0.0 <= node["qsecbit"] <= 1.0

        # Check status is valid
        assert node["status"] in ["green", "amber", "red"]

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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
