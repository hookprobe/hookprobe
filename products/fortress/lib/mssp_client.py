#!/usr/bin/env python3
"""
Fortress MSSP Client — Backward Compatibility Wrapper

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2026 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

This module wraps the shared MSSP client (shared/mssp/) to maintain
backward compatibility for existing Fortress code. New code should
import directly from shared.mssp.

Migration:
    OLD:  from products.fortress.lib.mssp_client import FortressMSSPClient
    NEW:  from shared.mssp import HookProbeMSSPClient, get_mssp_client
"""

import logging
import threading
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional

# Import the shared universal client
from shared.mssp.client import HookProbeMSSPClient, get_mssp_client as _get_shared_client
from shared.mssp.types import (
    DeviceMetrics as SharedDeviceMetrics,
    ThreatFinding,
)

logger = logging.getLogger(__name__)


# Legacy dataclasses kept for backward compatibility
@dataclass
class DeviceMetrics:
    """Device telemetry metrics for heartbeat (legacy)."""
    status: str = 'online'
    cpu_usage: float = 0.0
    ram_usage: float = 0.0
    disk_usage: float = 0.0
    uptime_seconds: int = 0
    qsecbit_score: Optional[float] = None
    threat_events_count: int = 0
    network_rx_rate: float = 0.0
    network_tx_rate: float = 0.0

    def to_dict(self) -> Dict:
        return {k: v for k, v in asdict(self).items() if v is not None}

    def to_shared(self) -> SharedDeviceMetrics:
        """Convert to shared DeviceMetrics type."""
        return SharedDeviceMetrics(
            status=self.status,
            cpu_usage=self.cpu_usage,
            ram_usage=self.ram_usage,
            disk_usage=self.disk_usage,
            uptime_seconds=self.uptime_seconds,
            qsecbit_score=self.qsecbit_score,
            threat_events_count=self.threat_events_count,
            network_rx_rate=self.network_rx_rate,
            network_tx_rate=self.network_tx_rate,
            aegis_tier="fortress",
        )


@dataclass
class ThreatEvent:
    """Threat event for reporting to MSSP (legacy)."""
    event_id: str
    threat_type: str
    severity: str
    source_ip: str
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    description: str = ''
    detection_method: str = ''
    confidence: float = 0.0
    timestamp: Optional[str] = None
    raw_data: Optional[Dict] = None

    def to_dict(self) -> Dict:
        data = asdict(self)
        if self.timestamp is None:
            data['timestamp'] = datetime.now().isoformat()
        return {k: v for k, v in data.items() if v is not None}


class FortressMSSPClient:
    """Backward-compatible wrapper around HookProbeMSSPClient.

    Delegates all operations to shared.mssp.client.HookProbeMSSPClient.
    Maintains the same interface for existing Fortress code.
    """

    def __init__(
        self,
        mssp_url: str = None,
        device_id: str = None,
        auth_token: str = None,
        timeout: int = 10,
    ):
        self._client = HookProbeMSSPClient(
            tier="fortress",
            mssp_url=mssp_url,
            device_id=device_id,
            auth_token=auth_token,
            timeout=timeout,
        )

    @property
    def mssp_url(self) -> str:
        return self._client.mssp_url

    @property
    def device_id(self) -> str:
        return self._client.device_id

    def send_heartbeat(self, metrics: DeviceMetrics = None) -> bool:
        if metrics:
            return self._client.send_heartbeat(metrics.to_shared())
        return self._client.send_heartbeat()

    def set_metrics_callback(self, callback) -> None:
        self._client.set_metrics_callback(callback)

    def start_heartbeat(self, interval: int = 60) -> None:
        self._client.start_heartbeat(interval)

    def stop_heartbeat(self) -> None:
        self._client.stop_heartbeat()

    def report_threats(self, threats: List[ThreatEvent]) -> bool:
        threat_dicts = [t.to_dict() for t in threats]
        return self._client.report_threats(threat_dicts)

    def report_single_threat(self, threat: ThreatEvent) -> bool:
        return self.report_threats([threat])

    def forward_ids_alerts(
        self,
        source: str,
        events: List[Dict],
        log_type: str = 'alert',
    ) -> bool:
        return self._client.forward_ids_alerts(source, events, log_type)

    def report_guardian_threat(
        self,
        threat_type: str,
        severity: str,
        mac_address: str,
        detection_method: str,
        details: Dict = None,
    ) -> bool:
        threat = ThreatEvent(
            event_id=f"GUARDIAN-{datetime.now().strftime('%Y%m%d%H%M%S%f')[:17]}",
            threat_type=threat_type,
            severity=severity,
            source_ip=mac_address,
            description=f"Guardian detected: {threat_type}",
            detection_method=detection_method,
            confidence=details.get('confidence', 0.8) if details else 0.8,
            raw_data={
                'source': 'guardian',
                'mac_address': mac_address,
                **(details or {}),
            }
        )
        return self.report_single_threat(threat)

    def health_check(self) -> Dict:
        return self._client.health_check()

    def get_stats(self) -> Dict:
        return self._client.get_stats()

    # V2 Intelligence API — pass-through to shared client
    def submit_finding(self, finding: ThreatFinding):
        return self._client.submit_finding(finding)

    def poll_recommendations(self):
        return self._client.poll_recommendations()

    def acknowledge_recommendation(self, action_id: str) -> bool:
        return self._client.acknowledge_recommendation(action_id)


# =============================================================================
# SINGLETON (backward compat)
# =============================================================================

_client: Optional[FortressMSSPClient] = None
_client_lock = threading.Lock()


def get_mssp_client() -> FortressMSSPClient:
    """Get the singleton MSSP client (Fortress backward compat)."""
    global _client
    with _client_lock:
        if _client is None:
            _client = FortressMSSPClient()
        return _client


# =============================================================================
# CLI
# =============================================================================

if __name__ == '__main__':
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description='Fortress MSSP Client')
    parser.add_argument('command', choices=['health', 'heartbeat', 'threat', 'stats'])
    parser.add_argument('--url', help='MSSP URL override')
    parser.add_argument('--device-id', help='Device ID override')
    parser.add_argument('--token', help='Auth token override')
    args = parser.parse_args()

    client = FortressMSSPClient(
        mssp_url=args.url,
        device_id=args.device_id,
        auth_token=args.token,
    )

    if args.command == 'health':
        status = client.health_check()
        print("MSSP Connection Status:")
        for key, value in status.items():
            print(f"  {key}: {value}")

    elif args.command == 'heartbeat':
        success = client.send_heartbeat()
        print(f"Heartbeat: {'success' if success else 'failed'}")

    elif args.command == 'threat':
        threat = ThreatEvent(
            event_id='TEST-001',
            threat_type='test_threat',
            severity='low',
            source_ip='192.168.1.100',
            description='Test threat event',
            detection_method='manual_test',
            confidence=1.0,
        )
        success = client.report_single_threat(threat)
        print(f"Threat report: {'success' if success else 'failed'}")

    elif args.command == 'stats':
        stats = client.get_stats()
        print("Client Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
