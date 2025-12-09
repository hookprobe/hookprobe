#!/usr/bin/env python3
"""
MSSP Connector for Globe Visualization

Connects the MSSP product tier (cloud federation platform) to the globe
digital twin visualization.

The MSSP is the central brain of the HookProbe mesh, providing:
- Multi-tenant management
- Centralized threat intelligence
- Billing and customer management
- Global mesh coordination
- ML model distribution

Integration points:
- products/mssp/web/ - Django web portal
- products/mssp/device_registry.py - Device management
- products/mssp/geolocation.py - Location services

Usage (Django integration):
    # In products/mssp/web/apps/monitoring/views.py
    from visualization.globe.backend.connectors.mssp import create_django_connector

    globe_connector = create_django_connector()
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime

from .base import (
    ProductConnector,
    ConnectorConfig,
    ProductTier,
    ThreatEvent,
)

logger = logging.getLogger(__name__)


@dataclass
class MSSPConnectorConfig(ConnectorConfig):
    """MSSP-specific connector configuration."""

    tier: ProductTier = field(default=ProductTier.MSSP)

    # MSSP-specific settings
    django_host: str = "localhost"
    django_port: int = 8000
    api_base_url: str = "/api/v1"

    # Capabilities
    global_threat_intel: bool = True
    multi_tenant: bool = True
    ml_model_distribution: bool = True

    # Heartbeat (MSSP is always-on cloud service)
    heartbeat_interval: float = 60.0
    qsecbit_report_interval: float = 30.0

    # Resource allocation
    max_tenants: int = 1000
    max_devices_per_tenant: int = 100


class MSSPConnector(ProductConnector):
    """
    Connector for MSSP tier (cloud federation platform).

    The MSSP at mssp.hookprobe.com is the central brain that:
    - Manages all tenants and their devices
    - Aggregates global threat intelligence
    - Distributes ML model updates
    - Coordinates mesh-wide responses

    Globe visualization shows:
    - Central hub node (special visual treatment)
    - Lines to all managed devices
    - Global threat intelligence heatmap
    - Real-time attack streams to/from MSSP
    """

    def __init__(self, config: MSSPConnectorConfig):
        super().__init__(config)
        self.mssp_config = config

        # MSSP-specific state
        self._tenants: Dict[str, Dict[str, Any]] = {}
        self._managed_devices: Dict[str, Dict[str, Any]] = {}
        self._global_threat_intel = {
            "total_threats_24h": 0,
            "top_attack_types": [],
            "top_source_countries": [],
            "blocked_ips": set(),
        }
        self._ml_model_distribution = {
            "current_version": "1.0.0",
            "devices_updated": 0,
            "pending_updates": 0,
        }
        self._api_stats = {
            "requests_24h": 0,
            "errors_24h": 0,
            "avg_response_ms": 0.0,
        }

    async def collect_qsecbit(self) -> float:
        """
        Collect aggregate Qsecbit score across all managed devices.

        MSSP's Qsecbit represents the health of the entire mesh.
        """
        if not self._managed_devices:
            return 0.1  # Baseline when no devices

        # Calculate weighted average of all device Qsecbits
        total_score = 0.0
        total_weight = 0.0

        for device in self._managed_devices.values():
            score = device.get("qsecbit", 0.0)
            # Weight by device tier
            tier = device.get("tier", "sentinel")
            weight = {"sentinel": 1, "guardian": 2, "fortress": 4, "nexus": 8}.get(tier, 1)
            total_score += score * weight
            total_weight += weight

        if total_weight > 0:
            return total_score / total_weight

        return 0.1

    async def collect_qsecbit_components(self) -> Dict[str, float]:
        """Collect MSSP-specific Qsecbit components."""
        # MSSP components are aggregate metrics
        device_count = len(self._managed_devices)
        online_count = sum(1 for d in self._managed_devices.values() if d.get("online", False))
        online_ratio = online_count / device_count if device_count > 0 else 1.0

        return {
            "mesh_health": 1.0 - online_ratio,  # More offline = higher score
            "threat_intel": min(0.5, self._global_threat_intel["total_threats_24h"] / 10000),
            "api_errors": min(0.3, self._api_stats["errors_24h"] / 1000),
            "model_distribution": (
                self._ml_model_distribution["pending_updates"] /
                max(1, len(self._managed_devices))
            ) * 0.2,
        }

    async def collect_statistics(self) -> Dict[str, Any]:
        """Collect MSSP-specific statistics."""
        online_devices = sum(1 for d in self._managed_devices.values() if d.get("online", False))
        devices_by_tier = {}
        for device in self._managed_devices.values():
            tier = device.get("tier", "unknown")
            devices_by_tier[tier] = devices_by_tier.get(tier, 0) + 1

        stats = {
            "total_tenants": len(self._tenants),
            "total_devices": len(self._managed_devices),
            "online_devices": online_devices,
            "devices_by_tier": devices_by_tier,
            "global_threat_intel": {
                "threats_24h": self._global_threat_intel["total_threats_24h"],
                "top_attack_types": self._global_threat_intel["top_attack_types"][:5],
                "top_source_countries": self._global_threat_intel["top_source_countries"][:5],
                "blocked_ips_count": len(self._global_threat_intel["blocked_ips"]),
            },
            "ml_model_distribution": self._ml_model_distribution,
            "api_stats": self._api_stats,
        }

        self.state.metadata = {
            "product": "mssp",
            "version": "5.0",
            "capabilities": {
                "global_threat_intel": self.mssp_config.global_threat_intel,
                "multi_tenant": self.mssp_config.multi_tenant,
                "ml_model_distribution": self.mssp_config.ml_model_distribution,
            },
            **stats,
        }

        return stats

    async def get_recent_threats(self) -> List[ThreatEvent]:
        """Get global threats detected across all devices."""
        # In production, this would query the database
        # For now, return aggregated threats
        return []

    # =========================================================================
    # MSSP-specific methods
    # =========================================================================

    def register_tenant(self, tenant_id: str, info: Dict[str, Any]) -> None:
        """Register a tenant."""
        self._tenants[tenant_id] = {
            "info": info,
            "devices": [],
            "registered_at": datetime.utcnow(),
        }

    def register_device(self, device_id: str, tenant_id: str, info: Dict[str, Any]) -> None:
        """Register a device under a tenant."""
        self._managed_devices[device_id] = {
            "tenant_id": tenant_id,
            "tier": info.get("tier", "sentinel"),
            "lat": info.get("lat", 0),
            "lng": info.get("lng", 0),
            "label": info.get("label", device_id),
            "qsecbit": 0.0,
            "online": False,
            "last_seen": None,
            **info,
        }

        if tenant_id in self._tenants:
            self._tenants[tenant_id]["devices"].append(device_id)

    def update_device_state(self, device_id: str, state: Dict[str, Any]) -> None:
        """Update a managed device's state."""
        if device_id in self._managed_devices:
            self._managed_devices[device_id].update(state)
            self._managed_devices[device_id]["last_seen"] = datetime.utcnow()

    def report_global_threat(
        self,
        source_ip: str,
        attack_type: str,
        affected_devices: List[str]
    ) -> None:
        """Report a global threat affecting multiple devices."""
        self._global_threat_intel["total_threats_24h"] += 1

        # Update attack type stats
        for i, (t, count) in enumerate(self._global_threat_intel["top_attack_types"]):
            if t == attack_type:
                self._global_threat_intel["top_attack_types"][i] = (t, count + 1)
                break
        else:
            self._global_threat_intel["top_attack_types"].append((attack_type, 1))

        # Sort and trim
        self._global_threat_intel["top_attack_types"].sort(key=lambda x: -x[1])
        self._global_threat_intel["top_attack_types"] = (
            self._global_threat_intel["top_attack_types"][:10]
        )

    def block_ip_globally(self, ip: str, reason: str) -> None:
        """Block an IP across all managed devices."""
        self._global_threat_intel["blocked_ips"].add(ip)

    def report_ml_model_update(self, version: str, devices_updated: int) -> None:
        """Report ML model distribution progress."""
        self._ml_model_distribution["current_version"] = version
        self._ml_model_distribution["devices_updated"] = devices_updated
        self._ml_model_distribution["pending_updates"] = (
            len(self._managed_devices) - devices_updated
        )

    def get_all_devices(self) -> List[Dict[str, Any]]:
        """Get all managed devices for globe display."""
        return list(self._managed_devices.values())

    def get_devices_by_tenant(self, tenant_id: str) -> List[Dict[str, Any]]:
        """Get devices for a specific tenant."""
        return [
            d for d in self._managed_devices.values()
            if d.get("tenant_id") == tenant_id
        ]


def create_mssp_connector(
    node_id: str = "mssp-central",
    lat: float = 52.5200,  # Berlin (HookProbe HQ)
    lng: float = 13.4050,
    label: str = "MSSP Central",
    **kwargs
) -> MSSPConnector:
    """Factory function to create an MSSP connector."""
    config = MSSPConnectorConfig(
        node_id=node_id,
        lat=lat,
        lng=lng,
        label=label,
        **kwargs
    )
    return MSSPConnector(config)


def create_django_connector(settings_module: str = None) -> MSSPConnector:
    """
    Create an MSSP connector integrated with Django.

    Usage in Django settings:
        from visualization.globe.backend.connectors.mssp import create_django_connector
        GLOBE_CONNECTOR = create_django_connector()

    Usage in Django views:
        from django.conf import settings
        globe_connector = settings.GLOBE_CONNECTOR
    """
    try:
        import django
        from django.conf import settings

        # Get configuration from Django settings
        node_id = getattr(settings, 'GLOBE_NODE_ID', 'mssp-central')
        lat = getattr(settings, 'GLOBE_LAT', 52.5200)
        lng = getattr(settings, 'GLOBE_LNG', 13.4050)
        label = getattr(settings, 'GLOBE_LABEL', 'MSSP Central')

        config = MSSPConnectorConfig(
            node_id=node_id,
            lat=lat,
            lng=lng,
            label=label,
            django_host=getattr(settings, 'ALLOWED_HOSTS', ['localhost'])[0],
            django_port=getattr(settings, 'PORT', 8000),
        )

        return MSSPConnector(config)

    except ImportError:
        logger.warning("Django not available, using default configuration")
        return create_mssp_connector()
