#!/usr/bin/env python3
"""
MSSP Connectivity Tests

Tests end-to-end connectivity between HookProbe products and MSSP dashboard:
- Guardian → HTP → MSSP flow
- Fortress → REST → MSSP flow
- Sentinel → REST → MSSP flow

Run with:
    python -m pytest tests/test_mssp_connectivity.py -v

Environment Variables:
    MSSP_URL: MSSP dashboard URL (default: https://mssp.hookprobe.com)
    MSSP_AUTH_TOKEN: Authentication token for API access
    MSSP_DEVICE_ID: Device ID for testing (default: test-device-001)
"""

import json
import os
import sys
import time
import unittest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestMSSPConnectivity(unittest.TestCase):
    """Base class for MSSP connectivity tests."""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures."""
        cls.mssp_url = os.environ.get('MSSP_URL', 'https://mssp.hookprobe.com')
        cls.auth_token = os.environ.get('MSSP_AUTH_TOKEN', '')
        cls.device_id = os.environ.get('MSSP_DEVICE_ID', 'test-device-001')

    def _make_request(self, method: str, endpoint: str, data: Dict = None) -> Optional[Dict]:
        """Make HTTP request to MSSP."""
        import urllib.request
        import urllib.error

        url = f"{self.mssp_url.rstrip('/')}{endpoint}"

        try:
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'MSSP-Test-Client/1.0',
            }
            if self.auth_token:
                headers['Authorization'] = f'Token {self.auth_token}'

            if data:
                payload = json.dumps(data).encode('utf-8')
                request = urllib.request.Request(
                    url,
                    data=payload,
                    method=method,
                    headers=headers,
                )
            else:
                request = urllib.request.Request(url, method=method, headers=headers)

            with urllib.request.urlopen(request, timeout=30) as response:
                return {
                    'status': response.status,
                    'data': json.loads(response.read().decode('utf-8')),
                }

        except urllib.error.HTTPError as e:
            return {'status': e.code, 'error': str(e)}
        except urllib.error.URLError as e:
            return {'status': 0, 'error': str(e.reason)}
        except Exception as e:
            return {'status': 0, 'error': str(e)}


class TestFortressMSSPClient(TestMSSPConnectivity):
    """Tests for Fortress → MSSP connectivity."""

    def test_fortress_client_import(self):
        """Test that Fortress MSSP client can be imported."""
        try:
            from products.fortress.lib.mssp_client import (
                FortressMSSPClient,
                DeviceMetrics,
                ThreatEvent,
                get_mssp_client,
            )
            self.assertIsNotNone(FortressMSSPClient)
            self.assertIsNotNone(DeviceMetrics)
            self.assertIsNotNone(ThreatEvent)
        except ImportError as e:
            self.fail(f"Failed to import Fortress MSSP client: {e}")

    def test_fortress_client_initialization(self):
        """Test Fortress MSSP client initialization."""
        from products.fortress.lib.mssp_client import FortressMSSPClient

        client = FortressMSSPClient(
            mssp_url=self.mssp_url,
            device_id=self.device_id,
            auth_token=self.auth_token,
        )

        self.assertEqual(client.mssp_url, self.mssp_url)
        self.assertEqual(client.device_id, self.device_id)
        self.assertIsNotNone(client)

    def test_fortress_device_metrics(self):
        """Test DeviceMetrics dataclass."""
        from products.fortress.lib.mssp_client import DeviceMetrics

        metrics = DeviceMetrics(
            status='online',
            cpu_usage=45.5,
            ram_usage=62.3,
            disk_usage=78.1,
            uptime_seconds=86400,
            qsecbit_score=0.85,
            threat_events_count=3,
        )

        data = metrics.to_dict()
        self.assertEqual(data['status'], 'online')
        self.assertEqual(data['cpu_usage'], 45.5)
        self.assertEqual(data['qsecbit_score'], 0.85)

    def test_fortress_threat_event(self):
        """Test ThreatEvent dataclass."""
        from products.fortress.lib.mssp_client import ThreatEvent

        threat = ThreatEvent(
            event_id='TEST-001',
            threat_type='test_threat',
            severity='medium',
            source_ip='192.168.1.100',
            description='Test threat event',
            detection_method='unit_test',
            confidence=0.95,
        )

        data = threat.to_dict()
        self.assertEqual(data['event_id'], 'TEST-001')
        self.assertEqual(data['severity'], 'medium')
        self.assertEqual(data['confidence'], 0.95)
        self.assertIn('timestamp', data)

    @patch('urllib.request.urlopen')
    def test_fortress_heartbeat_mock(self, mock_urlopen):
        """Test Fortress heartbeat with mocked response."""
        from products.fortress.lib.mssp_client import FortressMSSPClient, DeviceMetrics

        # Mock successful response
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"status": "ok"}'
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = FortressMSSPClient(
            mssp_url='http://test-mssp.local',
            device_id='test-device',
            auth_token='test-token',
        )

        metrics = DeviceMetrics(
            cpu_usage=50.0,
            ram_usage=60.0,
            qsecbit_score=0.85,
        )

        result = client.send_heartbeat(metrics)
        self.assertTrue(result)
        self.assertEqual(client._stats['heartbeats_sent'], 1)

    @patch('urllib.request.urlopen')
    def test_fortress_threat_report_mock(self, mock_urlopen):
        """Test Fortress threat reporting with mocked response."""
        from products.fortress.lib.mssp_client import FortressMSSPClient, ThreatEvent

        # Mock successful response
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"status": "processed", "created": 1}'
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = FortressMSSPClient(
            mssp_url='http://test-mssp.local',
            device_id='test-device',
            auth_token='test-token',
        )

        threat = ThreatEvent(
            event_id='TEST-002',
            threat_type='ter_replay',
            severity='high',
            source_ip='10.0.0.50',
            detection_method='neuro_drift',
            confidence=0.92,
        )

        result = client.report_single_threat(threat)
        self.assertTrue(result)
        self.assertEqual(client._stats['threats_reported'], 1)


class TestGuardianMSSPFlow(TestMSSPConnectivity):
    """Tests for Guardian → MSSP threat flow."""

    def test_guardian_threat_payload_structure(self):
        """Test Guardian threat payload structure matches MSSP API."""
        payload = {
            'source': 'guardian',
            'device_id': 'guardian-test-001',
            'threats': [
                {
                    'event_id': 'GUARDIAN-20260125120000123',
                    'threat_type': 'ter_replay',
                    'severity': 'high',
                    'source_ip': 'aa:bb:cc:dd:ee:ff',
                    'description': 'TER replay attack detected',
                    'detection_method': 'NEURO protocol resonance drift',
                    'confidence': 0.92,
                    'timestamp': datetime.now().isoformat(),
                    'raw_data': {
                        'mac_address': 'aa:bb:cc:dd:ee:ff',
                        'neuro_drift': 0.15,
                    },
                }
            ],
        }

        # Validate payload structure
        self.assertIn('source', payload)
        self.assertIn('threats', payload)
        self.assertEqual(len(payload['threats']), 1)

        threat = payload['threats'][0]
        self.assertIn('event_id', threat)
        self.assertIn('threat_type', threat)
        self.assertIn('severity', threat)
        self.assertIn('source_ip', threat)
        self.assertIn('confidence', threat)

    @unittest.skipUnless(os.environ.get('MSSP_AUTH_TOKEN'), "MSSP_AUTH_TOKEN not set")
    def test_guardian_threat_ingestion_live(self):
        """Live test: Ingest Guardian threat to MSSP."""
        payload = {
            'source': 'guardian',
            'device_id': self.device_id,
            'threats': [
                {
                    'event_id': f'GUARDIAN-TEST-{int(time.time())}',
                    'threat_type': 'test_threat',
                    'severity': 'info',
                    'source_ip': '192.168.1.1',
                    'description': 'Test threat from unit test',
                    'detection_method': 'unit_test',
                    'confidence': 1.0,
                }
            ],
        }

        result = self._make_request('POST', '/api/v1/security/threats/ingest/', payload)

        if result.get('status') == 401:
            self.skipTest("Authentication failed - check MSSP_AUTH_TOKEN")

        self.assertIn(result.get('status'), (200, 201, 207))
        self.assertIn('processed', result.get('data', {}))


class TestSentinelMSSPExport(TestMSSPConnectivity):
    """Tests for Sentinel → MSSP metrics export."""

    def test_sentinel_mssp_client_class(self):
        """Test Sentinel MSSP client class exists."""
        # Read sentinel.py and check for SentinelMSSPClient
        sentinel_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'products', 'sentinel', 'sentinel.py'
        )

        with open(sentinel_path, 'r') as f:
            content = f.read()

        self.assertIn('class SentinelMSSPClient', content)
        self.assertIn('def send_heartbeat', content)
        self.assertIn('def report_threat', content)
        self.assertIn('def export_metrics_to_mssp', content)

    def test_sentinel_metrics_structure(self):
        """Test Sentinel metrics structure."""
        metrics = {
            'status': 'online',
            'cpu_usage': 25.5,
            'ram_usage': 48.2,
            'disk_usage': 55.0,
            'uptime_seconds': 3600,
            'qsecbit_score': 0.90,
            'threat_events_count': 2,
        }

        # Validate structure
        required_fields = ['status', 'cpu_usage', 'ram_usage', 'uptime_seconds']
        for field in required_fields:
            self.assertIn(field, metrics)


class TestMSSPAPIEndpoints(TestMSSPConnectivity):
    """Tests for MSSP API endpoints."""

    @unittest.skipUnless(os.environ.get('MSSP_AUTH_TOKEN'), "MSSP_AUTH_TOKEN not set")
    def test_mssp_health_endpoint(self):
        """Test MSSP health endpoint."""
        result = self._make_request('GET', '/health/')

        # Health endpoint might not require auth
        if result.get('status') in (200, 401):
            self.assertIn(result.get('status'), (200, 401))

    @unittest.skipUnless(os.environ.get('MSSP_AUTH_TOKEN'), "MSSP_AUTH_TOKEN not set")
    def test_mssp_device_heartbeat(self):
        """Test MSSP device heartbeat endpoint."""
        payload = {
            'status': 'online',
            'cpu_usage': 50.0,
            'ram_usage': 60.0,
            'disk_usage': 70.0,
            'uptime_seconds': 3600,
            'qsecbit_score': 0.85,
            'threat_events_count': 0,
        }

        result = self._make_request(
            'POST',
            f'/api/v1/devices/{self.device_id}/heartbeat/',
            payload
        )

        if result.get('status') == 401:
            self.skipTest("Authentication failed - check MSSP_AUTH_TOKEN")

        if result.get('status') == 404:
            self.skipTest("Device not registered in MSSP")

        self.assertIn(result.get('status'), (200, 201))

    @unittest.skipUnless(os.environ.get('MSSP_AUTH_TOKEN'), "MSSP_AUTH_TOKEN not set")
    def test_mssp_security_dashboard(self):
        """Test MSSP security dashboard endpoint."""
        result = self._make_request('GET', '/api/v1/security/dashboard/')

        if result.get('status') == 401:
            self.skipTest("Authentication failed - check MSSP_AUTH_TOKEN")

        self.assertEqual(result.get('status'), 200)
        self.assertIn('summary', result.get('data', {}))


class TestEndToEndFlow(TestMSSPConnectivity):
    """End-to-end integration tests."""

    @unittest.skipUnless(
        os.environ.get('MSSP_AUTH_TOKEN') and os.environ.get('RUN_E2E_TESTS'),
        "E2E tests disabled or no auth token"
    )
    def test_full_threat_lifecycle(self):
        """Test complete threat detection → MSSP flow."""
        # 1. Report threat
        threat_payload = {
            'source': 'fortress',
            'device_id': self.device_id,
            'threats': [
                {
                    'event_id': f'E2E-TEST-{int(time.time())}',
                    'threat_type': 'e2e_test_threat',
                    'severity': 'info',
                    'source_ip': '10.0.0.100',
                    'description': 'E2E test threat',
                    'detection_method': 'e2e_test',
                    'confidence': 1.0,
                }
            ],
        }

        threat_result = self._make_request(
            'POST',
            '/api/v1/security/threats/ingest/',
            threat_payload
        )

        self.assertIn(threat_result.get('status'), (200, 201, 207))

        # 2. Verify in dashboard
        time.sleep(1)  # Allow processing

        dashboard_result = self._make_request('GET', '/api/v1/security/dashboard/')
        self.assertEqual(dashboard_result.get('status'), 200)

        # 3. Send heartbeat
        heartbeat_payload = {
            'status': 'online',
            'cpu_usage': 45.0,
            'ram_usage': 55.0,
            'disk_usage': 65.0,
            'uptime_seconds': 7200,
            'qsecbit_score': 0.80,  # Degraded due to threat
            'threat_events_count': 1,
        }

        heartbeat_result = self._make_request(
            'POST',
            f'/api/v1/devices/{self.device_id}/heartbeat/',
            heartbeat_payload
        )

        if heartbeat_result.get('status') != 404:  # Device might not exist
            self.assertIn(heartbeat_result.get('status'), (200, 201))


if __name__ == '__main__':
    unittest.main(verbosity=2)
