#!/usr/bin/env python3
"""
Phase 2 City View Tests

Tests for the Deck.gl + MapLibre GL city-level visualization.
Tests verify:
- Backend node registry cluster support methods
- Snapshot generation with stats
- Geographic bounds calculation
- Node filtering by region
"""

import sys
import os
import unittest

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from node_registry import (
    NodeRegistry,
    NodeTwin,
    NodeTier,
    QsecbitStatus,
    get_registry
)


def approx_equal(actual, expected, rel=0.01):
    """Check if two floats are approximately equal."""
    return abs(actual - expected) <= abs(expected * rel)


class TestNodeRegistryClusterSupport(unittest.TestCase):
    """Tests for Phase 2 cluster support methods in NodeRegistry."""

    def setUp(self):
        """Create a fresh registry with test nodes."""
        self.registry = NodeRegistry()

        # Add test nodes in different locations
        self.registry.register_node(
            node_id="guardian-nyc-001",
            tier=NodeTier.GUARDIAN,
            lat=40.7128,
            lng=-74.0060,
            label="NYC Guardian",
            country_code="US"
        )
        self.registry.register_node(
            node_id="fortress-nyc-002",
            tier=NodeTier.FORTRESS,
            lat=40.7580,
            lng=-73.9855,
            label="Midtown Fortress",
            country_code="US"
        )
        self.registry.register_node(
            node_id="sentinel-sf-001",
            tier=NodeTier.SENTINEL,
            lat=37.7749,
            lng=-122.4194,
            label="SF Sentinel",
            country_code="US"
        )
        self.registry.register_node(
            node_id="nexus-london-001",
            tier=NodeTier.NEXUS,
            lat=51.5074,
            lng=-0.1278,
            label="London Nexus",
            country_code="GB"
        )
        self.registry.register_node(
            node_id="guardian-tokyo-001",
            tier=NodeTier.GUARDIAN,
            lat=35.6762,
            lng=139.6503,
            label="Tokyo Guardian",
            country_code="JP"
        )

    def test_get_nodes_by_region_nyc(self):
        """Test filtering nodes by NYC geographic bounds."""
        nyc_bounds = {
            'west': -74.5,
            'south': 40.5,
            'east': -73.5,
            'north': 41.0
        }

        nodes = self.registry.get_nodes_by_region(nyc_bounds)

        self.assertEqual(len(nodes), 2)
        node_ids = [n.node_id for n in nodes]
        self.assertIn("guardian-nyc-001", node_ids)
        self.assertIn("fortress-nyc-002", node_ids)

    def test_get_nodes_by_region_empty(self):
        """Test filtering returns empty list for region with no nodes."""
        empty_bounds = {
            'west': 0,
            'south': 0,
            'east': 1,
            'north': 1
        }

        nodes = self.registry.get_nodes_by_region(empty_bounds)
        self.assertEqual(len(nodes), 0)

    def test_get_nodes_by_region_global(self):
        """Test filtering with global bounds returns all nodes."""
        global_bounds = {
            'west': -180,
            'south': -90,
            'east': 180,
            'north': 90
        }

        nodes = self.registry.get_nodes_by_region(global_bounds)
        self.assertEqual(len(nodes), 5)

    def test_get_cluster_stats(self):
        """Test cluster statistics generation."""
        stats = self.registry.get_cluster_stats()

        self.assertEqual(stats['total_nodes'], 5)
        self.assertEqual(stats['by_tier']['guardian'], 2)
        self.assertEqual(stats['by_tier']['fortress'], 1)
        self.assertEqual(stats['by_tier']['sentinel'], 1)
        self.assertEqual(stats['by_tier']['nexus'], 1)

        # Check country distribution
        self.assertEqual(stats['by_country']['US'], 3)
        self.assertEqual(stats['by_country']['GB'], 1)
        self.assertEqual(stats['by_country']['JP'], 1)

    def test_get_cluster_stats_geographic_bounds(self):
        """Test geographic bounds in cluster stats."""
        stats = self.registry.get_cluster_stats()

        bounds = stats['geographic_bounds']
        # London is northernmost
        self.assertTrue(approx_equal(bounds['north'], 51.5074))
        # Tokyo is easternmost
        self.assertTrue(approx_equal(bounds['east'], 139.6503))
        # SF is westernmost
        self.assertTrue(approx_equal(bounds['west'], -122.4194))
        # Tokyo is southernmost of our nodes
        self.assertTrue(approx_equal(bounds['south'], 35.6762))

    def test_get_cluster_stats_by_status(self):
        """Test status distribution in cluster stats."""
        # Set varied statuses
        self.registry.nodes["guardian-nyc-001"].update_qsecbit(0.3)  # Green
        self.registry.nodes["fortress-nyc-002"].update_qsecbit(0.5)  # Amber
        self.registry.nodes["sentinel-sf-001"].update_qsecbit(0.8)   # Red
        self.registry.nodes["nexus-london-001"].update_qsecbit(0.2)  # Green
        self.registry.nodes["guardian-tokyo-001"].update_qsecbit(0.6)  # Amber

        stats = self.registry.get_cluster_stats()

        self.assertEqual(stats['by_status']['green'], 2)
        self.assertEqual(stats['by_status']['amber'], 2)
        self.assertEqual(stats['by_status']['red'], 1)

    def test_get_nodes_for_clustering(self):
        """Test node format for frontend clustering."""
        nodes = self.registry.get_nodes_for_clustering()

        self.assertEqual(len(nodes), 5)

        # Check required fields for clustering
        nyc_node = next(n for n in nodes if n['id'] == 'guardian-nyc-001')
        self.assertIn('lat', nyc_node)
        self.assertIn('lng', nyc_node)
        self.assertIn('tier', nyc_node)
        self.assertIn('status', nyc_node)
        self.assertIn('qsecbit', nyc_node)
        self.assertIn('label', nyc_node)
        self.assertIn('country_code', nyc_node)

        self.assertEqual(nyc_node['tier'], 'guardian')
        self.assertTrue(approx_equal(nyc_node['lat'], 40.7128))

    def test_get_snapshot_with_stats(self):
        """Test enhanced snapshot includes cluster stats."""
        snapshot = self.registry.get_snapshot_with_stats()

        # Should have all standard snapshot fields
        self.assertIn('type', snapshot)
        self.assertEqual(snapshot['type'], 'snapshot')
        self.assertIn('nodes', snapshot)
        self.assertIn('edges', snapshot)
        self.assertIn('timestamp', snapshot)

        # Should have cluster stats
        self.assertIn('stats', snapshot)
        self.assertIn('total_nodes', snapshot['stats'])
        self.assertEqual(snapshot['stats']['total_nodes'], 5)

    def test_avg_qsecbit_calculation(self):
        """Test average Qsecbit calculation."""
        # Set known scores
        self.registry.nodes["guardian-nyc-001"].qsecbit_score = 0.2
        self.registry.nodes["fortress-nyc-002"].qsecbit_score = 0.4
        self.registry.nodes["sentinel-sf-001"].qsecbit_score = 0.6
        self.registry.nodes["nexus-london-001"].qsecbit_score = 0.3
        self.registry.nodes["guardian-tokyo-001"].qsecbit_score = 0.5

        stats = self.registry.get_cluster_stats()

        # Average should be (0.2+0.4+0.6+0.3+0.5) / 5 = 0.4
        self.assertTrue(approx_equal(stats['avg_qsecbit'], 0.4))


class TestNodeTwinClusterFields(unittest.TestCase):
    """Tests for NodeTwin serialization for clustering."""

    def test_to_dict_includes_all_fields(self):
        """Test NodeTwin.to_dict() includes fields needed for clustering."""
        node = NodeTwin(
            node_id="test-001",
            tier=NodeTier.GUARDIAN,
            lat=40.7128,
            lng=-74.0060,
            label="Test Node",
            country_code="US"
        )
        node.qsecbit_score = 0.35
        node.qsecbit_status = QsecbitStatus.GREEN
        node.online = True

        data = node.to_dict()

        # Verify all clustering-relevant fields
        self.assertEqual(data['id'], "test-001")
        self.assertEqual(data['tier'], "guardian")
        self.assertEqual(data['lat'], 40.7128)
        self.assertEqual(data['lng'], -74.0060)
        self.assertEqual(data['label'], "Test Node")
        self.assertEqual(data['country_code'], "US")
        self.assertTrue(approx_equal(data['qsecbit'], 0.35))
        self.assertEqual(data['status'], "green")
        self.assertTrue(data['online'])


class TestGlobalRegistry(unittest.TestCase):
    """Tests for global registry singleton."""

    def test_get_registry_returns_same_instance(self):
        """Test get_registry returns singleton."""
        reg1 = get_registry()
        reg2 = get_registry()
        self.assertIs(reg1, reg2)

    def test_get_registry_has_cluster_methods(self):
        """Test global registry has Phase 2 methods."""
        reg = get_registry()

        self.assertTrue(hasattr(reg, 'get_nodes_by_region'))
        self.assertTrue(hasattr(reg, 'get_cluster_stats'))
        self.assertTrue(hasattr(reg, 'get_nodes_for_clustering'))
        self.assertTrue(hasattr(reg, 'get_snapshot_with_stats'))


class TestPhase2Integration(unittest.TestCase):
    """Integration tests for Phase 2 components."""

    def setUp(self):
        """Create registry with realistic node distribution."""
        self.registry = NodeRegistry()

        # NYC cluster (3 nodes)
        self.registry.register_node("nyc-g1", NodeTier.GUARDIAN, 40.7128, -74.0060, "NYC-G1", "US")
        self.registry.register_node("nyc-f1", NodeTier.FORTRESS, 40.7580, -73.9855, "NYC-F1", "US")
        self.registry.register_node("nyc-s1", NodeTier.SENTINEL, 40.7308, -73.9973, "NYC-S1", "US")

        # SF cluster (2 nodes)
        self.registry.register_node("sf-g1", NodeTier.GUARDIAN, 37.7749, -122.4194, "SF-G1", "US")
        self.registry.register_node("sf-s1", NodeTier.SENTINEL, 37.7849, -122.4094, "SF-S1", "US")

        # London cluster (2 nodes)
        self.registry.register_node("lon-n1", NodeTier.NEXUS, 51.5074, -0.1278, "LON-N1", "GB")
        self.registry.register_node("lon-g1", NodeTier.GUARDIAN, 51.5174, -0.1378, "LON-G1", "GB")

        # Set varied statuses
        self.registry.nodes["nyc-g1"].update_qsecbit(0.3)
        self.registry.nodes["nyc-f1"].update_qsecbit(0.5)
        self.registry.nodes["nyc-s1"].update_qsecbit(0.8)
        self.registry.nodes["sf-g1"].update_qsecbit(0.2)
        self.registry.nodes["sf-s1"].update_qsecbit(0.3)
        self.registry.nodes["lon-n1"].update_qsecbit(0.4)
        self.registry.nodes["lon-g1"].update_qsecbit(0.6)

    def test_city_level_filtering(self):
        """Test filtering works for city-level view."""
        # NYC bounds
        nyc_bounds = {'west': -74.5, 'south': 40.5, 'east': -73.5, 'north': 41.0}
        nyc_nodes = self.registry.get_nodes_by_region(nyc_bounds)
        self.assertEqual(len(nyc_nodes), 3)

        # SF bounds
        sf_bounds = {'west': -123.0, 'south': 37.5, 'east': -122.0, 'north': 38.0}
        sf_nodes = self.registry.get_nodes_by_region(sf_bounds)
        self.assertEqual(len(sf_nodes), 2)

        # London bounds
        lon_bounds = {'west': -1.0, 'south': 51.0, 'east': 1.0, 'north': 52.0}
        lon_nodes = self.registry.get_nodes_by_region(lon_bounds)
        self.assertEqual(len(lon_nodes), 2)

    def test_cluster_stats_for_city(self):
        """Test cluster statistics are accurate for clustering UI."""
        stats = self.registry.get_cluster_stats()

        self.assertEqual(stats['total_nodes'], 7)
        self.assertEqual(stats['online_nodes'], 0)  # None marked online
        self.assertEqual(stats['by_country']['US'], 5)
        self.assertEqual(stats['by_country']['GB'], 2)

    def test_snapshot_suitable_for_frontend(self):
        """Test snapshot format is suitable for Deck.gl rendering."""
        snapshot = self.registry.get_snapshot_with_stats()

        # Verify structure
        self.assertIn('nodes', snapshot)
        self.assertIn('stats', snapshot)

        # Verify node data has all needed fields
        for node_data in snapshot['nodes']:
            self.assertIn('id', node_data)
            self.assertIn('lat', node_data)
            self.assertIn('lng', node_data)
            self.assertIn('tier', node_data)
            self.assertIn('status', node_data)

        # Verify stats
        self.assertEqual(snapshot['stats']['total_nodes'], 7)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
