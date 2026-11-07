"""
AIOCHI Bubble Types and Data Classes
Defines core types for bubble management and policy resolution.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set


class BubbleState(Enum):
    """Lifecycle state of an ecosystem bubble."""
    FORMING = "forming"       # Being detected, not yet confirmed
    ACTIVE = "active"         # Confirmed and enforced
    DORMANT = "dormant"       # All devices gone, preserved for return
    DISSOLVED = "dissolved"   # No longer valid


class BubbleType(Enum):
    """Type of bubble determining default network policies."""
    FAMILY = "family"           # Full smart home access, D2D
    GUEST = "guest"             # Internet only, isolated
    CORPORATE = "corporate"     # Work devices, isolated
    SMART_HOME = "smart_home"   # IoT devices, limited LAN
    CUSTOM = "custom"           # User-defined


class NetworkPolicy(str, Enum):
    """
    Network access policies for devices.

    Maps to OpenFlow rule sets in nac-policy-sync.sh:
    - QUARANTINE: Priority 1000-1001, block all except DHCP/DNS
    - INTERNET_ONLY: Priority 700-850, internet yes, LAN no
    - LAN_ONLY: Priority 600-750, LAN yes, internet no
    - SMART_HOME: Priority 500 (base allow), full local access
    - FULL_ACCESS: Priority 500 (base allow), full access
    """
    QUARANTINE = "quarantine"           # No network access
    INTERNET_ONLY = "internet_only"     # Internet yes, LAN no
    LAN_ONLY = "lan_only"               # LAN yes, internet no
    SMART_HOME = "smart_home"           # Full local network (default)
    FULL_ACCESS = "full_access"         # Full access + management


# Bubble type -> Default network policy mapping
BUBBLE_TYPE_TO_POLICY: Dict[BubbleType, NetworkPolicy] = {
    BubbleType.FAMILY: NetworkPolicy.SMART_HOME,
    BubbleType.GUEST: NetworkPolicy.INTERNET_ONLY,
    BubbleType.CORPORATE: NetworkPolicy.INTERNET_ONLY,
    BubbleType.SMART_HOME: NetworkPolicy.LAN_ONLY,
    BubbleType.CUSTOM: NetworkPolicy.SMART_HOME,
}


# Policy display info for UI
POLICY_INFO = {
    NetworkPolicy.QUARANTINE: {
        'name': 'Quarantine',
        'icon': 'fa-ban',
        'color': 'danger',
        'description': 'No network access - unknown/suspicious device',
        'internet': False,
        'lan': False,
    },
    NetworkPolicy.INTERNET_ONLY: {
        'name': 'Internet Only',
        'icon': 'fa-globe',
        'color': 'info',
        'description': 'Can access internet but not local devices',
        'internet': True,
        'lan': False,
    },
    NetworkPolicy.LAN_ONLY: {
        'name': 'LAN Only',
        'icon': 'fa-network-wired',
        'color': 'warning',
        'description': 'Can access local network but not internet',
        'internet': False,
        'lan': True,
    },
    NetworkPolicy.SMART_HOME: {
        'name': 'Smart Home',
        'icon': 'fa-home',
        'color': 'success',
        'description': 'Full local network access with smart home',
        'internet': True,
        'lan': True,
    },
    NetworkPolicy.FULL_ACCESS: {
        'name': 'Full Access',
        'icon': 'fa-shield-alt',
        'color': 'primary',
        'description': 'Management device with full network access',
        'internet': True,
        'lan': True,
    },
}


# Bubble type policies (access flags)
BUBBLE_TYPE_POLICIES = {
    BubbleType.FAMILY: {
        'internet_access': True,
        'lan_access': True,
        'smart_home_access': True,
        'd2d_allowed': True,
        'shared_devices': True,
        'qos_priority': 'high',
        'bandwidth_limit': None,
        'mdns_allowed': True,
        'default_network_policy': NetworkPolicy.SMART_HOME,
        'description': 'Full network access with smart home integration',
    },
    BubbleType.GUEST: {
        'internet_access': True,
        'lan_access': False,
        'smart_home_access': False,
        'd2d_allowed': False,
        'shared_devices': False,
        'qos_priority': 'low',
        'bandwidth_limit': 50,
        'mdns_allowed': False,
        'default_network_policy': NetworkPolicy.INTERNET_ONLY,
        'description': 'Internet only - isolated from local network',
    },
    BubbleType.CORPORATE: {
        'internet_access': True,
        'lan_access': False,
        'smart_home_access': False,
        'd2d_allowed': False,
        'shared_devices': False,
        'qos_priority': 'medium',
        'bandwidth_limit': None,
        'mdns_allowed': False,
        'default_network_policy': NetworkPolicy.INTERNET_ONLY,
        'description': 'Work devices - isolated with internet access',
    },
    BubbleType.SMART_HOME: {
        'internet_access': True,
        'lan_access': True,
        'smart_home_access': True,
        'd2d_allowed': True,
        'shared_devices': True,
        'qos_priority': 'medium',
        'bandwidth_limit': 10,
        'mdns_allowed': True,
        'default_network_policy': NetworkPolicy.LAN_ONLY,
        'description': 'IoT and smart home devices',
    },
    BubbleType.CUSTOM: {
        'internet_access': True,
        'lan_access': False,
        'smart_home_access': False,
        'd2d_allowed': False,
        'shared_devices': False,
        'qos_priority': 'medium',
        'bandwidth_limit': None,
        'mdns_allowed': True,
        'default_network_policy': NetworkPolicy.SMART_HOME,
        'description': 'Custom configuration',
    },
}


@dataclass
class Bubble:
    """An ecosystem bubble - a group of devices belonging to one user."""
    bubble_id: str
    name: str
    ecosystem: str = "mixed"
    bubble_type: BubbleType = BubbleType.FAMILY
    devices: Set[str] = field(default_factory=set)  # MAC addresses
    state: BubbleState = BubbleState.FORMING
    confidence: float = 0.0

    # Policies
    policies: Dict = field(default_factory=dict)  # Override default policies
    pinned: bool = False  # If True, AI won't modify assignments
    is_manual: bool = False  # True if manually created

    # Per-device policy overrides: {mac: NetworkPolicy}
    device_policy_overrides: Dict[str, NetworkPolicy] = field(default_factory=dict)

    # Lifecycle
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_activity: str = field(default_factory=lambda: datetime.now().isoformat())

    # Identity hints
    owner_hint: Optional[str] = None
    primary_device: Optional[str] = None

    # Manual assignment tracking
    manually_assigned_devices: Set[str] = field(default_factory=set)

    # UI customization
    color: str = "#2196F3"
    icon: str = "fa-layer-group"

    def get_default_network_policy(self) -> NetworkPolicy:
        """Get the default network policy for this bubble type."""
        return BUBBLE_TYPE_TO_POLICY.get(self.bubble_type, NetworkPolicy.SMART_HOME)

    def get_device_policy(self, mac: str) -> NetworkPolicy:
        """Get effective policy for a device (override or default)."""
        mac_upper = mac.upper()
        if mac_upper in self.device_policy_overrides:
            return self.device_policy_overrides[mac_upper]
        return self.get_default_network_policy()

    def set_device_policy(self, mac: str, policy: NetworkPolicy) -> None:
        """Set a device-specific policy override."""
        self.device_policy_overrides[mac.upper()] = policy

    def clear_device_policy(self, mac: str) -> None:
        """Remove device-specific policy override (use bubble default)."""
        mac_upper = mac.upper()
        if mac_upper in self.device_policy_overrides:
            del self.device_policy_overrides[mac_upper]

    def get_effective_policies(self) -> Dict:
        """Get effective policies (type defaults + overrides)."""
        base_policies = BUBBLE_TYPE_POLICIES.get(self.bubble_type, {}).copy()
        base_policies.update(self.policies)
        return base_policies

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'bubble_id': self.bubble_id,
            'name': self.name,
            'ecosystem': self.ecosystem,
            'bubble_type': self.bubble_type.value,
            'devices': list(self.devices),
            'state': self.state.value,
            'confidence': self.confidence,
            'policies': self.get_effective_policies(),
            'pinned': self.pinned,
            'is_manual': self.is_manual,
            'device_policy_overrides': {
                mac: policy.value
                for mac, policy in self.device_policy_overrides.items()
            },
            'created_at': self.created_at,
            'last_activity': self.last_activity,
            'owner_hint': self.owner_hint,
            'device_count': len(self.devices),
            'manually_assigned_devices': list(self.manually_assigned_devices),
            'color': self.color,
            'icon': self.icon,
            'default_network_policy': self.get_default_network_policy().value,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "Bubble":
        """Create from dictionary."""
        bubble = cls(
            bubble_id=data.get('bubble_id', ''),
            name=data.get('name', ''),
            ecosystem=data.get('ecosystem', 'mixed'),
            bubble_type=BubbleType(data.get('bubble_type', 'family')),
            devices=set(data.get('devices', [])),
            state=BubbleState(data.get('state', 'forming')),
            confidence=data.get('confidence', 0.0),
            policies=data.get('policies', {}),
            pinned=data.get('pinned', False),
            is_manual=data.get('is_manual', False),
            created_at=data.get('created_at', datetime.now().isoformat()),
            last_activity=data.get('last_activity', datetime.now().isoformat()),
            owner_hint=data.get('owner_hint'),
            primary_device=data.get('primary_device'),
            manually_assigned_devices=set(data.get('manually_assigned_devices', [])),
            color=data.get('color', '#2196F3'),
            icon=data.get('icon', 'fa-layer-group'),
        )

        # Restore device policy overrides
        for mac, policy_str in data.get('device_policy_overrides', {}).items():
            try:
                bubble.device_policy_overrides[mac.upper()] = NetworkPolicy(policy_str)
            except ValueError:
                pass  # Invalid policy string

        return bubble


@dataclass
class BubbleEvent:
    """Event related to bubble lifecycle."""
    event_type: str  # 'created', 'device_joined', 'device_left', 'dissolved', 'policy_changed'
    bubble_id: str
    mac: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    details: Dict = field(default_factory=dict)
