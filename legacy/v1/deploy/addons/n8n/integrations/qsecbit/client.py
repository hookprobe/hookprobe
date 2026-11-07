#!/usr/bin/env python3
"""
QSECBIT API Client for N8N Integration
Provides risk scoring and threat analysis capabilities
"""

import requests
import json
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ThreatScore:
    """Threat score response from QSECBIT"""
    score: float
    confidence: float
    threat_type: str
    indicators: list
    timestamp: str
    metadata: Dict[str, Any]


class QsecbitClient:
    """
    Client for HookProbe QSECBIT threat scoring engine

    Usage:
        client = QsecbitClient(api_url="http://localhost:8888")
        score = client.score_event(event_data)
        print(f"Threat score: {score.score}")
    """

    def __init__(self, api_url: str = "http://localhost:8888", timeout: int = 5):
        self.api_url = api_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'HookProbe-N8N/1.0'
        })

    def score_event(self, event: Dict[str, Any]) -> ThreatScore:
        """
        Score a security event using QSECBIT algorithm

        Args:
            event: Security event data with fields:
                - source_ip: Source IP address
                - destination_ip: Destination IP
                - event_type: Type of event (e.g., 'login_attempt', 'port_scan')
                - payload: Event payload/data

        Returns:
            ThreatScore object with risk assessment

        Raises:
            requests.RequestException: On API error
        """
        try:
            response = self.session.post(
                f"{self.api_url}/api/v1/score",
                json=event,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()

            return ThreatScore(
                score=data.get('score', 0.0),
                confidence=data.get('confidence', 0.0),
                threat_type=data.get('threat_type', 'unknown'),
                indicators=data.get('indicators', []),
                timestamp=data.get('timestamp', datetime.utcnow().isoformat()),
                metadata=data.get('metadata', {})
            )

        except requests.RequestException as e:
            logger.error(f"QSECBIT API error: {e}")
            raise

    def batch_score(self, events: list[Dict[str, Any]]) -> list[ThreatScore]:
        """
        Score multiple events in batch

        Args:
            events: List of security events

        Returns:
            List of ThreatScore objects
        """
        try:
            response = self.session.post(
                f"{self.api_url}/api/v1/score/batch",
                json={'events': events},
                timeout=self.timeout * 2
            )
            response.raise_for_status()

            data = response.json()

            return [
                ThreatScore(
                    score=item.get('score', 0.0),
                    confidence=item.get('confidence', 0.0),
                    threat_type=item.get('threat_type', 'unknown'),
                    indicators=item.get('indicators', []),
                    timestamp=item.get('timestamp', datetime.utcnow().isoString()),
                    metadata=item.get('metadata', {})
                )
                for item in data.get('results', [])
            ]

        except requests.RequestException as e:
            logger.error(f"QSECBIT batch API error: {e}")
            raise

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get QSECBIT engine statistics

        Returns:
            Dictionary with statistics:
                - events_processed: Total events scored
                - average_score: Average threat score
                - high_risk_count: Count of high-risk events (score >= 0.7)
                - uptime: Engine uptime in seconds
        """
        try:
            response = self.session.get(
                f"{self.api_url}/api/v1/stats",
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()

        except requests.RequestException as e:
            logger.error(f"QSECBIT stats API error: {e}")
            raise

    def health_check(self) -> bool:
        """
        Check if QSECBIT engine is healthy

        Returns:
            True if healthy, False otherwise
        """
        try:
            response = self.session.get(
                f"{self.api_url}/healthz",
                timeout=2
            )
            return response.status_code == 200

        except requests.RequestException:
            return False


# Example usage
if __name__ == "__main__":
    client = QsecbitClient()

    # Test event
    test_event = {
        "source_ip": "192.168.1.100",
        "destination_ip": "10.200.1.5",
        "event_type": "ssh_login_attempt",
        "payload": {
            "username": "admin",
            "auth_method": "password",
            "failed_attempts": 5
        }
    }

    try:
        score = client.score_event(test_event)
        print(f"Threat Score: {score.score:.2f}")
        print(f"Confidence: {score.confidence:.2f}")
        print(f"Threat Type: {score.threat_type}")
        print(f"Indicators: {score.indicators}")

    except Exception as e:
        print(f"Error: {e}")
