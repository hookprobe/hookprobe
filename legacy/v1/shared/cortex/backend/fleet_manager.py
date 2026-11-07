#!/usr/bin/env python3
"""
HookProbe Cortex - Fleet Management & Multi-Tenant Access Control

Provides hierarchical access control for the Cortex visualization:
- Global Admin: God view - sees ALL endpoints across ALL customers
- Fleet Admin: Sees only their organization's endpoints
- End User: Sees only their own device

Location Privacy Model:
- Public mesh view: IP-based city-level geolocation
- Fleet admin view: User-declared precise locations (if provided)
- Privacy rule: Declared locations never leave the fleet

Usage:
    from fleet_manager import FleetManager, AccessLevel

    fm = FleetManager()
    fm.register_customer("acme-corp", "ACME Corporation")
    fm.register_device("device-001", "acme-corp", {...})

    # Get nodes based on access level
    nodes = fm.get_visible_nodes(user_id, access_level)
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from enum import Enum
import hashlib
import json

logger = logging.getLogger(__name__)


class AccessLevel(Enum):
    """User access levels for Cortex visualization."""
    GLOBAL_ADMIN = "global_admin"  # God view - all endpoints, all customers
    FLEET_ADMIN = "fleet_admin"    # Organization admin - all org endpoints
    END_USER = "end_user"          # Individual user - own devices only


class LocationPrivacy(Enum):
    """Location privacy settings."""
    IP_BASED = "ip_based"          # City-level from IP geolocation
    DECLARED = "declared"          # User-declared precise location
    HIDDEN = "hidden"              # Location not shared


@dataclass
class DeclaredLocation:
    """User-declared precise location (fleet-only visibility)."""
    lat: float
    lng: float
    label: str = ""
    floor: str = ""               # Building floor
    room: str = ""                # Room/desk identifier
    declared_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class IPBasedLocation:
    """IP-based city-level location (public mesh visibility)."""
    lat: float
    lng: float
    city: str = ""
    region: str = ""
    country_code: str = ""
    accuracy_km: float = 50.0     # City-level accuracy


@dataclass
class Device:
    """
    Device/endpoint in the fleet.

    Tracks both IP-based (public) and declared (fleet-only) locations.
    """
    device_id: str
    customer_id: str
    tier: str = "guardian"        # sentinel, guardian, fortress, nexus

    # Labels and metadata
    label: str = ""
    hostname: str = ""
    os_type: str = ""
    department: str = ""
    user_id: str = ""             # Owner/assigned user

    # IP-based location (always available, city-level)
    ip_location: Optional[IPBasedLocation] = None

    # User-declared location (fleet-only visibility)
    declared_location: Optional[DeclaredLocation] = None
    location_privacy: LocationPrivacy = LocationPrivacy.IP_BASED

    # Health metrics
    qsecbit_score: float = 0.0
    qsecbit_status: str = "green"
    last_heartbeat: Optional[datetime] = None
    heartbeat_interval_ms: int = 30000
    online: bool = False

    # Mesh participation
    neural_resonance: float = 0.0
    mesh_connections: List[str] = field(default_factory=list)

    # Timestamps
    registered_at: datetime = field(default_factory=datetime.utcnow)
    last_seen: Optional[datetime] = None

    def get_location(self, viewer_access: AccessLevel, viewer_customer: str = None) -> Dict[str, Any]:
        """
        Get device location based on viewer's access level.

        Global Admin and same-fleet admins see declared location if available.
        Everyone else sees IP-based city location.
        """
        # Global Admin sees everything
        if viewer_access == AccessLevel.GLOBAL_ADMIN:
            if self.declared_location and self.location_privacy == LocationPrivacy.DECLARED:
                return {
                    "lat": self.declared_location.lat,
                    "lng": self.declared_location.lng,
                    "label": self.declared_location.label,
                    "precision": "declared",
                    "floor": self.declared_location.floor,
                    "room": self.declared_location.room,
                }

        # Fleet admin sees declared location for their own fleet
        if viewer_access == AccessLevel.FLEET_ADMIN and viewer_customer == self.customer_id:
            if self.declared_location and self.location_privacy == LocationPrivacy.DECLARED:
                return {
                    "lat": self.declared_location.lat,
                    "lng": self.declared_location.lng,
                    "label": self.declared_location.label,
                    "precision": "declared",
                    "floor": self.declared_location.floor,
                    "room": self.declared_location.room,
                }

        # Default: IP-based city location
        if self.ip_location:
            return {
                "lat": self.ip_location.lat,
                "lng": self.ip_location.lng,
                "label": self.ip_location.city or "Unknown",
                "precision": "city",
                "city": self.ip_location.city,
                "region": self.ip_location.region,
                "country_code": self.ip_location.country_code,
            }

        return {"lat": 0, "lng": 0, "label": "Unknown", "precision": "unknown"}

    def to_dict(self, viewer_access: AccessLevel, viewer_customer: str = None) -> Dict[str, Any]:
        """Serialize device for API/WebSocket with access-appropriate data."""
        location = self.get_location(viewer_access, viewer_customer)

        base = {
            "id": self.device_id,
            "tier": self.tier,
            "lat": location["lat"],
            "lng": location["lng"],
            "label": self.label or location.get("label", ""),
            "qsecbit": round(self.qsecbit_score, 4),
            "status": self.qsecbit_status,
            "online": self.online,
            "location_precision": location["precision"],
        }

        # Fleet admin and Global admin see additional details
        if viewer_access in [AccessLevel.GLOBAL_ADMIN, AccessLevel.FLEET_ADMIN]:
            base.update({
                "customer_id": self.customer_id,
                "hostname": self.hostname,
                "department": self.department,
                "user_id": self.user_id,
                "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
                "resonance": round(self.neural_resonance, 4),
            })

        # Global admin sees everything
        if viewer_access == AccessLevel.GLOBAL_ADMIN:
            base.update({
                "os_type": self.os_type,
                "mesh_connections": self.mesh_connections,
                "registered_at": self.registered_at.isoformat(),
            })

        return base


@dataclass
class Customer:
    """
    Customer/Organization in the fleet management platform.

    Represents a fleet owner - a company using HookProbe.
    """
    customer_id: str
    name: str
    contact_email: str = ""

    # Subscription/tier
    subscription_tier: str = "professional"  # startup, professional, enterprise
    max_devices: int = 100

    # Fleet summary
    device_count: int = 0
    online_count: int = 0
    avg_qsecbit: float = 0.0
    worst_status: str = "green"

    # Geographic coverage
    primary_region: str = ""
    countries: Set[str] = field(default_factory=set)

    # Timestamps
    registered_at: datetime = field(default_factory=datetime.utcnow)
    last_activity: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize customer for API."""
        return {
            "id": self.customer_id,
            "name": self.name,
            "subscription_tier": self.subscription_tier,
            "device_count": self.device_count,
            "online_count": self.online_count,
            "avg_qsecbit": round(self.avg_qsecbit, 4),
            "worst_status": self.worst_status,
            "primary_region": self.primary_region,
            "countries": list(self.countries),
        }


@dataclass
class User:
    """
    User account for Cortex access.

    Defines what a user can see in the visualization.
    """
    user_id: str
    email: str
    name: str = ""
    access_level: AccessLevel = AccessLevel.END_USER
    customer_id: str = ""         # For fleet_admin and end_user
    device_ids: List[str] = field(default_factory=list)  # For end_user

    def to_dict(self) -> Dict[str, Any]:
        """Serialize user for API."""
        return {
            "id": self.user_id,
            "email": self.email,
            "name": self.name,
            "access_level": self.access_level.value,
            "customer_id": self.customer_id,
        }


class FleetManager:
    """
    Central manager for fleet data and access control.

    Provides:
    - Customer/organization registration
    - Device registration and tracking
    - Access-controlled data retrieval
    - City-level aggregation for clustering
    """

    def __init__(self):
        self.customers: Dict[str, Customer] = {}
        self.devices: Dict[str, Device] = {}
        self.users: Dict[str, User] = {}

        # City-level aggregation cache
        self._city_cache: Dict[str, List[str]] = {}  # city_key -> device_ids
        self._cache_valid = False

    # =========================================================================
    # Customer Management
    # =========================================================================

    def register_customer(
        self,
        customer_id: str,
        name: str,
        contact_email: str = "",
        subscription_tier: str = "professional",
        max_devices: int = 100,
    ) -> Customer:
        """Register a new customer/organization."""
        customer = Customer(
            customer_id=customer_id,
            name=name,
            contact_email=contact_email,
            subscription_tier=subscription_tier,
            max_devices=max_devices,
        )
        self.customers[customer_id] = customer
        logger.info(f"Registered customer: {customer_id} ({name})")
        return customer

    def get_customer(self, customer_id: str) -> Optional[Customer]:
        """Get customer by ID."""
        return self.customers.get(customer_id)

    def get_all_customers(self) -> List[Customer]:
        """Get all customers (Global admin only)."""
        return list(self.customers.values())

    # =========================================================================
    # Device Management
    # =========================================================================

    def register_device(
        self,
        device_id: str,
        customer_id: str,
        tier: str = "guardian",
        label: str = "",
        ip_location: Dict[str, Any] = None,
        declared_location: Dict[str, Any] = None,
        **kwargs
    ) -> Optional[Device]:
        """Register a new device under a customer."""
        if customer_id not in self.customers:
            logger.warning(f"Cannot register device: customer {customer_id} not found")
            return None

        # Create IP-based location if provided
        ip_loc = None
        if ip_location:
            ip_loc = IPBasedLocation(
                lat=ip_location.get("lat", 0),
                lng=ip_location.get("lng", 0),
                city=ip_location.get("city", ""),
                region=ip_location.get("region", ""),
                country_code=ip_location.get("country_code", ""),
            )

        # Create declared location if provided
        decl_loc = None
        if declared_location:
            decl_loc = DeclaredLocation(
                lat=declared_location.get("lat", 0),
                lng=declared_location.get("lng", 0),
                label=declared_location.get("label", ""),
                floor=declared_location.get("floor", ""),
                room=declared_location.get("room", ""),
            )

        device = Device(
            device_id=device_id,
            customer_id=customer_id,
            tier=tier,
            label=label,
            ip_location=ip_loc,
            declared_location=decl_loc,
            location_privacy=LocationPrivacy.DECLARED if decl_loc else LocationPrivacy.IP_BASED,
            **kwargs
        )

        self.devices[device_id] = device
        self.customers[customer_id].device_count += 1
        self._cache_valid = False

        logger.info(f"Registered device: {device_id} for {customer_id}")
        return device

    def update_device_location(
        self,
        device_id: str,
        ip_location: Dict[str, Any] = None,
        declared_location: Dict[str, Any] = None,
    ) -> bool:
        """Update device location (IP-based or declared)."""
        device = self.devices.get(device_id)
        if not device:
            return False

        if ip_location:
            device.ip_location = IPBasedLocation(
                lat=ip_location.get("lat", 0),
                lng=ip_location.get("lng", 0),
                city=ip_location.get("city", ""),
                region=ip_location.get("region", ""),
                country_code=ip_location.get("country_code", ""),
            )

        if declared_location:
            device.declared_location = DeclaredLocation(
                lat=declared_location.get("lat", 0),
                lng=declared_location.get("lng", 0),
                label=declared_location.get("label", ""),
                floor=declared_location.get("floor", ""),
                room=declared_location.get("room", ""),
            )
            device.location_privacy = LocationPrivacy.DECLARED

        self._cache_valid = False
        return True

    def update_device_health(
        self,
        device_id: str,
        qsecbit_score: float = None,
        online: bool = None,
        heartbeat: bool = False,
    ) -> bool:
        """Update device health metrics."""
        device = self.devices.get(device_id)
        if not device:
            return False

        if qsecbit_score is not None:
            device.qsecbit_score = qsecbit_score
            if qsecbit_score < 0.45:
                device.qsecbit_status = "green"
            elif qsecbit_score < 0.70:
                device.qsecbit_status = "amber"
            else:
                device.qsecbit_status = "red"

        if online is not None:
            device.online = online

        if heartbeat:
            device.last_heartbeat = datetime.utcnow()
            device.online = True
            device.last_seen = datetime.utcnow()

        # Update customer stats
        self._update_customer_stats(device.customer_id)
        return True

    def _update_customer_stats(self, customer_id: str) -> None:
        """Update aggregated customer statistics."""
        customer = self.customers.get(customer_id)
        if not customer:
            return

        devices = [d for d in self.devices.values() if d.customer_id == customer_id]
        if not devices:
            return

        customer.device_count = len(devices)
        customer.online_count = sum(1 for d in devices if d.online)

        total_qsecbit = sum(d.qsecbit_score for d in devices)
        customer.avg_qsecbit = total_qsecbit / len(devices) if devices else 0

        # Determine worst status
        statuses = [d.qsecbit_status for d in devices]
        if "red" in statuses:
            customer.worst_status = "red"
        elif "amber" in statuses:
            customer.worst_status = "amber"
        else:
            customer.worst_status = "green"

        # Update countries
        customer.countries = set()
        for d in devices:
            if d.ip_location and d.ip_location.country_code:
                customer.countries.add(d.ip_location.country_code)

        customer.last_activity = datetime.utcnow()

    # =========================================================================
    # User Management
    # =========================================================================

    def register_user(
        self,
        user_id: str,
        email: str,
        name: str = "",
        access_level: AccessLevel = AccessLevel.END_USER,
        customer_id: str = "",
        device_ids: List[str] = None,
    ) -> User:
        """Register a user for Cortex access."""
        user = User(
            user_id=user_id,
            email=email,
            name=name,
            access_level=access_level,
            customer_id=customer_id,
            device_ids=device_ids or [],
        )
        self.users[user_id] = user
        logger.info(f"Registered user: {user_id} ({access_level.value})")
        return user

    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        return self.users.get(user_id)

    # =========================================================================
    # Access-Controlled Data Retrieval
    # =========================================================================

    def get_visible_nodes(
        self,
        user_id: str,
        customer_filter: str = None,
    ) -> List[Dict[str, Any]]:
        """
        Get nodes visible to a user based on their access level.

        Global Admin: All nodes from all customers
        Fleet Admin: All nodes from their organization
        End User: Only their assigned devices
        """
        user = self.users.get(user_id)
        if not user:
            logger.warning(f"User not found: {user_id}")
            return []

        if user.access_level == AccessLevel.GLOBAL_ADMIN:
            # God view - all devices
            devices = list(self.devices.values())
            if customer_filter:
                devices = [d for d in devices if d.customer_id == customer_filter]
            return [
                d.to_dict(AccessLevel.GLOBAL_ADMIN, user.customer_id)
                for d in devices
            ]

        elif user.access_level == AccessLevel.FLEET_ADMIN:
            # Fleet view - organization devices only
            devices = [
                d for d in self.devices.values()
                if d.customer_id == user.customer_id
            ]
            return [
                d.to_dict(AccessLevel.FLEET_ADMIN, user.customer_id)
                for d in devices
            ]

        else:
            # End user - own devices only
            devices = [
                self.devices[did] for did in user.device_ids
                if did in self.devices
            ]
            return [
                d.to_dict(AccessLevel.END_USER, user.customer_id)
                for d in devices
            ]

    def get_visible_customers(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Get customers visible to a user.

        Global Admin: All customers
        Fleet Admin: Only their own customer
        End User: None
        """
        user = self.users.get(user_id)
        if not user:
            return []

        if user.access_level == AccessLevel.GLOBAL_ADMIN:
            return [c.to_dict() for c in self.customers.values()]

        elif user.access_level == AccessLevel.FLEET_ADMIN:
            customer = self.customers.get(user.customer_id)
            return [customer.to_dict()] if customer else []

        return []

    # =========================================================================
    # City-Level Aggregation
    # =========================================================================

    def get_city_key(self, lat: float, lng: float, precision: int = 1) -> str:
        """
        Generate a city-level grouping key from coordinates.

        Precision 1 = ~100km clusters (city level)
        Precision 0 = ~1000km clusters (region level)
        """
        lat_key = round(lat, precision)
        lng_key = round(lng, precision)
        return f"{lat_key},{lng_key}"

    def get_city_clusters(
        self,
        user_id: str,
        customer_filter: str = None,
    ) -> List[Dict[str, Any]]:
        """
        Get nodes aggregated by city for clustering visualization.

        Returns clusters with:
        - Centroid coordinates
        - Node count
        - Aggregate Qsecbit
        - Worst status
        - Breakdown by department/tier
        """
        nodes = self.get_visible_nodes(user_id, customer_filter)

        # Group by city
        city_groups: Dict[str, List[Dict]] = {}
        for node in nodes:
            key = self.get_city_key(node["lat"], node["lng"])
            if key not in city_groups:
                city_groups[key] = []
            city_groups[key].append(node)

        # Build clusters
        clusters = []
        for city_key, city_nodes in city_groups.items():
            if len(city_nodes) == 1:
                # Single node - no clustering needed
                clusters.append({
                    "type": "node",
                    **city_nodes[0]
                })
            else:
                # Multiple nodes - create cluster
                lat_sum = sum(n["lat"] for n in city_nodes)
                lng_sum = sum(n["lng"] for n in city_nodes)
                qsecbit_sum = sum(n["qsecbit"] for n in city_nodes)
                count = len(city_nodes)

                # Determine worst status
                statuses = [n["status"] for n in city_nodes]
                if "red" in statuses:
                    worst = "red"
                elif "amber" in statuses:
                    worst = "amber"
                else:
                    worst = "green"

                # Count by tier
                tier_counts = {}
                for n in city_nodes:
                    tier = n.get("tier", "guardian")
                    tier_counts[tier] = tier_counts.get(tier, 0) + 1

                # Count by department (if available)
                dept_counts = {}
                for n in city_nodes:
                    dept = n.get("department", "")
                    if dept:
                        dept_counts[dept] = dept_counts.get(dept, 0) + 1

                clusters.append({
                    "type": "cluster",
                    "id": f"cluster-{city_key}",
                    "lat": lat_sum / count,
                    "lng": lng_sum / count,
                    "count": count,
                    "avgQsecbit": qsecbit_sum / count,
                    "worstStatus": worst,
                    "tierCounts": tier_counts,
                    "departmentCounts": dept_counts,
                    "nodes": city_nodes,  # Include for drill-down
                })

        return clusters

    # =========================================================================
    # Statistics
    # =========================================================================

    def get_fleet_stats(self, user_id: str) -> Dict[str, Any]:
        """Get fleet statistics based on user access level."""
        user = self.users.get(user_id)
        if not user:
            return {}

        if user.access_level == AccessLevel.GLOBAL_ADMIN:
            # Global stats
            all_devices = list(self.devices.values())
            return {
                "total_customers": len(self.customers),
                "total_devices": len(all_devices),
                "online_devices": sum(1 for d in all_devices if d.online),
                "by_tier": self._count_by_tier(all_devices),
                "by_status": self._count_by_status(all_devices),
                "avg_qsecbit": self._avg_qsecbit(all_devices),
            }

        elif user.access_level == AccessLevel.FLEET_ADMIN:
            # Organization stats
            devices = [d for d in self.devices.values() if d.customer_id == user.customer_id]
            return {
                "total_devices": len(devices),
                "online_devices": sum(1 for d in devices if d.online),
                "by_tier": self._count_by_tier(devices),
                "by_status": self._count_by_status(devices),
                "by_department": self._count_by_department(devices),
                "avg_qsecbit": self._avg_qsecbit(devices),
            }

        else:
            # User stats
            devices = [self.devices[did] for did in user.device_ids if did in self.devices]
            return {
                "total_devices": len(devices),
                "online_devices": sum(1 for d in devices if d.online),
                "by_status": self._count_by_status(devices),
                "avg_qsecbit": self._avg_qsecbit(devices),
            }

    def _count_by_tier(self, devices: List[Device]) -> Dict[str, int]:
        counts = {"sentinel": 0, "guardian": 0, "fortress": 0, "nexus": 0}
        for d in devices:
            tier = d.tier.lower()
            if tier in counts:
                counts[tier] += 1
        return counts

    def _count_by_status(self, devices: List[Device]) -> Dict[str, int]:
        counts = {"green": 0, "amber": 0, "red": 0}
        for d in devices:
            status = d.qsecbit_status.lower()
            if status in counts:
                counts[status] += 1
        return counts

    def _count_by_department(self, devices: List[Device]) -> Dict[str, int]:
        counts = {}
        for d in devices:
            if d.department:
                counts[d.department] = counts.get(d.department, 0) + 1
        return counts

    def _avg_qsecbit(self, devices: List[Device]) -> float:
        if not devices:
            return 0.0
        return sum(d.qsecbit_score for d in devices) / len(devices)


# Global fleet manager instance
_fleet_manager: Optional[FleetManager] = None


def get_fleet_manager() -> FleetManager:
    """Get or create the global fleet manager."""
    global _fleet_manager
    if _fleet_manager is None:
        _fleet_manager = FleetManager()
    return _fleet_manager
