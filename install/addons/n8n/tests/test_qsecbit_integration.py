#!/usr/bin/env python3
"""
Tests for QSECBIT integration
"""

import pytest
import requests_mock
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../integrations')))

from qsecbit.client import QsecbitClient, ThreatScore


class TestQsecbitClient:
    """Test suite for QSECBIT API client"""

    def test_client_initialization(self):
        """Test client initialization with default parameters"""
        client = QsecbitClient()
        assert client.api_url == "http://localhost:8888"
        assert client.timeout == 5

    def test_client_custom_url(self):
        """Test client initialization with custom URL"""
        client = QsecbitClient(api_url="http://custom:9999")
        assert client.api_url == "http://custom:9999"

    def test_score_event_success(self):
        """Test successful event scoring"""
        client = QsecbitClient()

        test_event = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.200.1.5",
            "event_type": "ssh_login_attempt"
        }

        mock_response = {
            "score": 0.85,
            "confidence": 0.92,
            "threat_type": "brute_force",
            "indicators": ["multiple_failed_attempts", "unusual_time"],
            "timestamp": "2025-11-26T10:00:00Z",
            "metadata": {"attempts": 5}
        }

        with requests_mock.Mocker() as m:
            m.post('http://localhost:8888/api/v1/score', json=mock_response)

            score = client.score_event(test_event)

            assert isinstance(score, ThreatScore)
            assert score.score == 0.85
            assert score.confidence == 0.92
            assert score.threat_type == "brute_force"
            assert len(score.indicators) == 2
            assert score.metadata["attempts"] == 5

    def test_score_event_api_error(self):
        """Test event scoring with API error"""
        client = QsecbitClient()

        test_event = {"source_ip": "192.168.1.100"}

        with requests_mock.Mocker() as m:
            m.post('http://localhost:8888/api/v1/score', status_code=500)

            with pytest.raises(requests.RequestException):
                client.score_event(test_event)

    def test_batch_score(self):
        """Test batch scoring of multiple events"""
        client = QsecbitClient()

        test_events = [
            {"source_ip": "192.168.1.100"},
            {"source_ip": "192.168.1.101"}
        ]

        mock_response = {
            "results": [
                {"score": 0.7, "confidence": 0.8, "threat_type": "scan"},
                {"score": 0.9, "confidence": 0.95, "threat_type": "exploit"}
            ]
        }

        with requests_mock.Mocker() as m:
            m.post('http://localhost:8888/api/v1/score/batch', json=mock_response)

            scores = client.batch_score(test_events)

            assert len(scores) == 2
            assert scores[0].score == 0.7
            assert scores[1].score == 0.9

    def test_get_statistics(self):
        """Test getting engine statistics"""
        client = QsecbitClient()

        mock_stats = {
            "events_processed": 1000,
            "average_score": 0.45,
            "high_risk_count": 50,
            "uptime": 3600
        }

        with requests_mock.Mocker() as m:
            m.get('http://localhost:8888/api/v1/stats', json=mock_stats)

            stats = client.get_statistics()

            assert stats["events_processed"] == 1000
            assert stats["average_score"] == 0.45
            assert stats["high_risk_count"] == 50

    def test_health_check_healthy(self):
        """Test health check with healthy service"""
        client = QsecbitClient()

        with requests_mock.Mocker() as m:
            m.get('http://localhost:8888/healthz', status_code=200)

            healthy = client.health_check()
            assert healthy is True

    def test_health_check_unhealthy(self):
        """Test health check with unhealthy service"""
        client = QsecbitClient()

        with requests_mock.Mocker() as m:
            m.get('http://localhost:8888/healthz', status_code=503)

            healthy = client.health_check()
            assert healthy is False

    def test_health_check_timeout(self):
        """Test health check with timeout"""
        client = QsecbitClient()

        with requests_mock.Mocker() as m:
            m.get('http://localhost:8888/healthz', exc=requests.Timeout)

            healthy = client.health_check()
            assert healthy is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
