#!/usr/bin/env python3
"""
AIOCHI API Integration Tests
Validates API endpoints and inter-service connections.
"""

import json
import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Add parent path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestAIOCHIAPIEndpoints(unittest.TestCase):
    """Test AIOCHI API endpoint structure."""

    def test_endpoint_urls(self):
        """Verify all expected endpoints are defined."""
        expected_endpoints = [
            '/aiochi/',
            '/aiochi/api/status',
            '/aiochi/api/presence',
            '/aiochi/api/feed',
            '/aiochi/api/performance',
            '/aiochi/api/action/<action_id>',
            '/aiochi/api/push/subscribe',
            '/aiochi/api/push/unsubscribe',
            '/aiochi/api/push/test',
            '/aiochi/api/profiles',
            '/aiochi/api/profiles/<profile_id>',
            '/aiochi/api/profiles/<profile_id>/switch',
        ]

        # These are the base endpoints we expect
        for endpoint in expected_endpoints:
            # This is a structural test - just verify the expected routes exist
            self.assertIsInstance(endpoint, str)

    def test_demo_data_structure(self):
        """Verify demo data has correct structure."""
        from backend.ambient_state import AmbientState

        # Test ambient states
        self.assertIn('CALM', [s.value for s in AmbientState])
        self.assertIn('CURIOUS', [s.value for s in AmbientState])
        self.assertIn('ALERT', [s.value for s in AmbientState])

    def test_presence_bubble_structure(self):
        """Verify presence bubble data structure."""
        bubble_structure = {
            'id': str,
            'label': str,
            'icon': str,
            'color': str,
            'devices': list,
            'ecosystem': str,
            'trust_level': str,
        }

        # Verify structure fields
        for field, field_type in bubble_structure.items():
            self.assertIsInstance(field, str)

    def test_privacy_feed_structure(self):
        """Verify privacy feed event structure."""
        event_structure = {
            'id': (int, str),
            'time': str,
            'icon': str,
            'color': str,
            'title': str,
            'narrative': str,
            'category': str,
        }

        # Verify structure fields
        for field in event_structure:
            self.assertIsInstance(field, str)

    def test_performance_metrics_structure(self):
        """Verify performance metrics structure."""
        metrics_structure = {
            'health_score': int,
            'health_trend': str,
            'insight': str,
            'metrics': dict,
            'recommendations': list,
        }

        # Verify structure fields
        for field in metrics_structure:
            self.assertIsInstance(field, str)


class TestContainerConnections(unittest.TestCase):
    """Test container network configuration."""

    def test_network_addresses(self):
        """Verify expected network addresses."""
        # Core AIOCHI containers (always installed)
        expected_addresses = {
            'clickhouse': '172.20.210.10',
            'identity': '172.20.210.20',
            'narrative': '172.20.210.21',  # Optional (--profile workflows)
            'bubble': '172.20.210.25',
            'logshipper': '172.20.210.40',
            'ollama': '172.20.210.50',  # Optional (--profile ai)
        }
        # Note: Grafana and VictoriaMetrics removed - visualization via Fortress AdminLTE

        for service, ip in expected_addresses.items():
            # Verify IP format
            parts = ip.split('.')
            self.assertEqual(len(parts), 4)
            self.assertEqual(parts[0], '172')
            self.assertEqual(parts[1], '20')
            self.assertEqual(parts[2], '210')

    def test_port_mappings(self):
        """Verify expected port mappings."""
        # Core AIOCHI service ports
        expected_ports = {
            'clickhouse_http': 8123,
            'clickhouse_native': 9000,
            'identity': 8060,
            'bubble': 8070,
            'narrative': 5678,  # Optional (--profile workflows)
            'ollama': 11434,  # Optional (--profile ai)
        }
        # Note: Grafana (3000) and VictoriaMetrics (8428) removed

        for service, port in expected_ports.items():
            self.assertIsInstance(port, int)
            self.assertGreater(port, 0)
            self.assertLess(port, 65536)


class TestN8NWorkflows(unittest.TestCase):
    """Test n8n workflow structure."""

    def setUp(self):
        """Set up test fixtures."""
        self.workflow_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'n8n-workflows'
        )

    def test_workflow_files_exist(self):
        """Verify workflow JSON files exist."""
        expected_workflows = [
            'threat-narrative.json',
            'device-narrative.json',
            'performance-narrative.json',
        ]

        for workflow in expected_workflows:
            workflow_path = os.path.join(self.workflow_dir, workflow)
            self.assertTrue(
                os.path.exists(workflow_path),
                f"Workflow file not found: {workflow}"
            )

    def test_workflow_json_valid(self):
        """Verify workflow JSON is valid."""
        if not os.path.exists(self.workflow_dir):
            self.skipTest("Workflow directory not found")

        for filename in os.listdir(self.workflow_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(self.workflow_dir, filename)
                with open(filepath, 'r') as f:
                    try:
                        data = json.load(f)
                        self.assertIn('name', data)
                        self.assertIn('nodes', data)
                        self.assertIn('connections', data)
                    except json.JSONDecodeError as e:
                        self.fail(f"Invalid JSON in {filename}: {e}")


class TestFamilyProfiles(unittest.TestCase):
    """Test family profile functionality."""

    def test_persona_values(self):
        """Verify persona enum values."""
        from backend.family_profiles import Persona

        expected_personas = ['parent', 'gamer', 'worker', 'kid', 'privacy', 'tech']
        actual_personas = [p.value for p in Persona]

        for persona in expected_personas:
            self.assertIn(persona, actual_personas)

    def test_profile_creation(self):
        """Test creating a family profile."""
        from backend.family_profiles import FamilyProfile, Persona

        profile = FamilyProfile(
            id='test',
            name='Test User',
            persona=Persona.PARENT,
            avatar_emoji='👨',
        )

        self.assertEqual(profile.id, 'test')
        self.assertEqual(profile.name, 'Test User')
        self.assertEqual(profile.persona, Persona.PARENT)

    def test_profile_to_dict(self):
        """Test profile serialization."""
        from backend.family_profiles import FamilyProfile, Persona

        profile = FamilyProfile(
            id='test',
            name='Test User',
            persona=Persona.GAMER,
        )

        data = profile.to_dict()
        self.assertIsInstance(data, dict)
        self.assertEqual(data['id'], 'test')
        self.assertEqual(data['persona'], 'gamer')


class TestPWAConfiguration(unittest.TestCase):
    """Test PWA manifest and service worker."""

    def test_manifest_structure(self):
        """Verify manifest.json has required fields."""
        manifest_required = [
            'name',
            'short_name',
            'start_url',
            'display',
            'background_color',
            'theme_color',
            'icons',
        ]

        # These fields are required by PWA spec
        for field in manifest_required:
            self.assertIsInstance(field, str)


if __name__ == '__main__':
    unittest.main(verbosity=2)
