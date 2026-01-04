"""
AIOCHI Presence Tracker
Tracks device presence and groups them into "bubbles" (user groups).

This module visualizes "Who's Home" by clustering devices that belong
to the same person or ecosystem.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class PresenceState(Enum):
    """Device/bubble presence states."""
    HOME = "home"
    AWAY = "away"
    ARRIVING = "arriving"
    LEAVING = "leaving"
    UNKNOWN = "unknown"


@dataclass
class DevicePresence:
    """Presence information for a single device."""
    mac: str
    label: str = ""
    state: PresenceState = PresenceState.UNKNOWN
    last_seen: datetime = field(default_factory=datetime.now)
    signal_strength: int = -100  # dBm
    ap_name: str = ""            # Connected access point
    ip_address: str = ""
    is_active: bool = False      # Actively generating traffic

    @property
    def is_online(self) -> bool:
        """Check if device was seen recently (last 5 minutes)."""
        return (datetime.now() - self.last_seen) < timedelta(minutes=5)

    @property
    def is_home(self) -> bool:
        """Check if device is considered 'home'."""
        return self.state in (PresenceState.HOME, PresenceState.ARRIVING)


@dataclass
class Bubble:
    """
    A bubble represents a group of devices belonging to the same user/ecosystem.

    Examples:
        - "Dad's Bubble": iPhone, MacBook, Apple Watch
        - "Kids' Bubble": iPad, Nintendo Switch
        - "Smart Home": Nest, Ring, Smart TV
    """
    id: str
    label: str                           # "Dad", "Kids", "Smart Home"
    icon: str = "user"                   # Icon for UI
    color: str = "#4CAF50"               # Color for visualization
    devices: List[DevicePresence] = field(default_factory=list)
    state: PresenceState = PresenceState.UNKNOWN
    last_updated: datetime = field(default_factory=datetime.now)

    @property
    def is_home(self) -> bool:
        """Check if any device in bubble is home."""
        return any(d.is_home for d in self.devices)

    @property
    def online_count(self) -> int:
        """Count of online devices in bubble."""
        return sum(1 for d in self.devices if d.is_online)

    @property
    def primary_device(self) -> Optional[DevicePresence]:
        """Get the most recently seen device."""
        if not self.devices:
            return None
        return max(self.devices, key=lambda d: d.last_seen)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "label": self.label,
            "icon": self.icon,
            "color": self.color,
            "state": self.state.value,
            "is_home": self.is_home,
            "online_count": self.online_count,
            "total_devices": len(self.devices),
            "devices": [
                {
                    "mac": d.mac,
                    "label": d.label,
                    "state": d.state.value,
                    "is_online": d.is_online,
                    "signal_strength": d.signal_strength,
                    "ap_name": d.ap_name,
                }
                for d in self.devices
            ],
            "last_updated": self.last_updated.isoformat(),
        }


class PresenceTracker:
    """
    Tracks device presence and manages bubbles.

    Features:
    - Real-time presence tracking
    - Automatic bubble creation from ecosystem detection
    - State machine for arriving/leaving detection
    - Integration with Fortress Ecosystem Bubble
    """

    # Thresholds for state transitions
    OFFLINE_THRESHOLD = timedelta(minutes=5)   # Consider offline after 5 min
    AWAY_THRESHOLD = timedelta(minutes=30)     # Consider away after 30 min
    ARRIVING_WINDOW = timedelta(minutes=2)     # New connection = arriving
    LEAVING_WINDOW = timedelta(minutes=2)      # About to disconnect

    def __init__(
        self,
        identity_engine=None,
        use_fortress_bubble: bool = True,
    ):
        """
        Initialize the Presence Tracker.

        Args:
            identity_engine: IdentityEngine instance for device lookups
            use_fortress_bubble: Use Fortress Ecosystem Bubble if available
        """
        self.identity_engine = identity_engine
        self.use_fortress_bubble = use_fortress_bubble

        # Device presence cache
        self._devices: Dict[str, DevicePresence] = {}

        # Bubble cache
        self._bubbles: Dict[str, Bubble] = {}

        # Try to load Fortress ecosystem bubble
        self._fortress_bubble = None
        if use_fortress_bubble:
            try:
                from products.fortress.lib.ecosystem_bubble import EcosystemBubble
                self._fortress_bubble = EcosystemBubble()
                logger.info("Using Fortress Ecosystem Bubble")
            except ImportError:
                logger.warning("Fortress Ecosystem Bubble not available")

    def update_device(
        self,
        mac: str,
        label: str = "",
        signal_strength: int = -100,
        ap_name: str = "",
        ip_address: str = "",
        is_active: bool = True,
    ) -> DevicePresence:
        """
        Update device presence information.

        Args:
            mac: Device MAC address
            label: Human-friendly label
            signal_strength: WiFi signal in dBm
            ap_name: Connected access point name
            ip_address: Device IP address
            is_active: Whether device is actively generating traffic

        Returns:
            Updated DevicePresence
        """
        mac = mac.upper().replace("-", ":")
        now = datetime.now()

        # Get or create device presence
        if mac in self._devices:
            device = self._devices[mac]
            old_state = device.state

            # Update fields
            device.last_seen = now
            if label:
                device.label = label
            device.signal_strength = signal_strength
            device.ap_name = ap_name
            device.ip_address = ip_address
            device.is_active = is_active

            # State transition
            if old_state == PresenceState.AWAY:
                device.state = PresenceState.ARRIVING
            elif old_state == PresenceState.UNKNOWN:
                device.state = PresenceState.HOME
            elif old_state == PresenceState.ARRIVING:
                # If seen multiple times, consider fully home
                device.state = PresenceState.HOME
        else:
            # New device
            device = DevicePresence(
                mac=mac,
                label=label or mac,
                state=PresenceState.ARRIVING,
                last_seen=now,
                signal_strength=signal_strength,
                ap_name=ap_name,
                ip_address=ip_address,
                is_active=is_active,
            )
            self._devices[mac] = device

            # Get label from identity engine if available
            if not label and self.identity_engine:
                identity = self.identity_engine.get_identity(mac)
                if identity:
                    device.label = identity.human_label

        # Update bubble containing this device
        self._update_bubble_for_device(device)

        return device

    def mark_device_offline(self, mac: str) -> Optional[DevicePresence]:
        """
        Mark a device as offline.

        Args:
            mac: Device MAC address

        Returns:
            Updated DevicePresence or None
        """
        mac = mac.upper().replace("-", ":")

        if mac not in self._devices:
            return None

        device = self._devices[mac]
        device.state = PresenceState.LEAVING
        device.is_active = False

        # Update bubble
        self._update_bubble_for_device(device)

        return device

    def get_device(self, mac: str) -> Optional[DevicePresence]:
        """Get presence information for a device."""
        mac = mac.upper().replace("-", ":")
        return self._devices.get(mac)

    def get_all_devices(self) -> List[DevicePresence]:
        """Get all tracked devices."""
        return list(self._devices.values())

    def get_online_devices(self) -> List[DevicePresence]:
        """Get all currently online devices."""
        return [d for d in self._devices.values() if d.is_online]

    def create_bubble(
        self,
        bubble_id: str,
        label: str,
        icon: str = "user",
        color: str = "#4CAF50",
    ) -> Bubble:
        """
        Create a new bubble.

        Args:
            bubble_id: Unique identifier
            label: Human-friendly label
            icon: Icon name for UI
            color: Color for visualization

        Returns:
            Created Bubble
        """
        bubble = Bubble(
            id=bubble_id,
            label=label,
            icon=icon,
            color=color,
        )
        self._bubbles[bubble_id] = bubble
        return bubble

    def add_device_to_bubble(self, mac: str, bubble_id: str) -> bool:
        """
        Add a device to a bubble.

        Args:
            mac: Device MAC address
            bubble_id: Bubble identifier

        Returns:
            True if successful
        """
        mac = mac.upper().replace("-", ":")

        if bubble_id not in self._bubbles:
            return False

        device = self._devices.get(mac)
        if not device:
            return False

        bubble = self._bubbles[bubble_id]

        # Remove from any existing bubble
        self._remove_device_from_bubbles(mac)

        # Add to new bubble
        bubble.devices.append(device)
        bubble.last_updated = datetime.now()

        return True

    def get_bubble(self, bubble_id: str) -> Optional[Bubble]:
        """Get a specific bubble."""
        return self._bubbles.get(bubble_id)

    def get_all_bubbles(self) -> List[Bubble]:
        """Get all bubbles."""
        self._refresh_bubble_states()
        return list(self._bubbles.values())

    def get_home_bubbles(self) -> List[Bubble]:
        """Get bubbles that are currently 'home'."""
        self._refresh_bubble_states()
        return [b for b in self._bubbles.values() if b.is_home]

    def get_presence_summary(self) -> Dict[str, Any]:
        """
        Get a summary of current presence state.

        Returns:
            Dictionary with presence summary for dashboard
        """
        self._refresh_bubble_states()

        online_devices = self.get_online_devices()
        home_bubbles = self.get_home_bubbles()

        return {
            "total_devices": len(self._devices),
            "online_devices": len(online_devices),
            "home_bubbles": len(home_bubbles),
            "bubbles": [b.to_dict() for b in self._bubbles.values()],
            "ungrouped_devices": [
                {
                    "mac": d.mac,
                    "label": d.label,
                    "is_online": d.is_online,
                }
                for d in online_devices
                if not self._device_in_bubble(d.mac)
            ],
            "timestamp": datetime.now().isoformat(),
        }

    def _update_bubble_for_device(self, device: DevicePresence) -> None:
        """Update the bubble containing this device."""
        for bubble in self._bubbles.values():
            for bd in bubble.devices:
                if bd.mac == device.mac:
                    # Update device in bubble
                    bubble.devices = [
                        device if d.mac == device.mac else d
                        for d in bubble.devices
                    ]
                    bubble.last_updated = datetime.now()
                    return

    def _remove_device_from_bubbles(self, mac: str) -> None:
        """Remove a device from all bubbles."""
        for bubble in self._bubbles.values():
            bubble.devices = [d for d in bubble.devices if d.mac != mac]

    def _device_in_bubble(self, mac: str) -> bool:
        """Check if device is in any bubble."""
        for bubble in self._bubbles.values():
            if any(d.mac == mac for d in bubble.devices):
                return True
        return False

    def _refresh_bubble_states(self) -> None:
        """Refresh state of all bubbles based on device states."""
        now = datetime.now()

        for bubble in self._bubbles.values():
            if not bubble.devices:
                bubble.state = PresenceState.UNKNOWN
                continue

            # Check device states
            home_count = sum(1 for d in bubble.devices if d.state == PresenceState.HOME)
            arriving_count = sum(1 for d in bubble.devices if d.state == PresenceState.ARRIVING)
            leaving_count = sum(1 for d in bubble.devices if d.state == PresenceState.LEAVING)

            if arriving_count > 0 and home_count == 0:
                bubble.state = PresenceState.ARRIVING
            elif leaving_count > 0 and home_count == 0:
                bubble.state = PresenceState.LEAVING
            elif home_count > 0 or arriving_count > 0:
                bubble.state = PresenceState.HOME
            else:
                bubble.state = PresenceState.AWAY

        # Also refresh device states based on last_seen
        for device in self._devices.values():
            time_since_seen = now - device.last_seen

            if device.state in (PresenceState.HOME, PresenceState.ARRIVING):
                if time_since_seen > self.AWAY_THRESHOLD:
                    device.state = PresenceState.AWAY
                elif time_since_seen > self.OFFLINE_THRESHOLD:
                    device.state = PresenceState.LEAVING

    def sync_from_fortress(self) -> int:
        """
        Sync presence data from Fortress Ecosystem Bubble.

        Returns:
            Number of bubbles synced
        """
        if not self._fortress_bubble:
            return 0

        try:
            fortress_bubbles = self._fortress_bubble.get_bubbles()
            for fb in fortress_bubbles:
                bubble = self.create_bubble(
                    bubble_id=fb["id"],
                    label=fb["label"],
                    icon=fb.get("icon", "user"),
                    color=fb.get("color", "#4CAF50"),
                )
                for device_mac in fb.get("devices", []):
                    self.add_device_to_bubble(device_mac, bubble.id)

            return len(fortress_bubbles)
        except Exception as e:
            logger.warning(f"Failed to sync from Fortress: {e}")
            return 0


# Pre-built bubble templates for common household patterns
BUBBLE_TEMPLATES = {
    "dad": {
        "id": "family_dad",
        "label": "Dad",
        "icon": "user",
        "color": "#2196F3",
    },
    "mom": {
        "id": "family_mom",
        "label": "Mom",
        "icon": "user",
        "color": "#E91E63",
    },
    "kids": {
        "id": "family_kids",
        "label": "Kids",
        "icon": "child_care",
        "color": "#FF9800",
    },
    "guest": {
        "id": "guests",
        "label": "Guests",
        "icon": "people",
        "color": "#9E9E9E",
    },
    "smart_home": {
        "id": "smart_home",
        "label": "Smart Home",
        "icon": "home",
        "color": "#4CAF50",
    },
    "work": {
        "id": "work_devices",
        "label": "Work",
        "icon": "work",
        "color": "#3F51B5",
    },
}


if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.DEBUG)

    tracker = PresenceTracker(use_fortress_bubble=False)

    # Create bubbles
    dad_bubble = tracker.create_bubble(**BUBBLE_TEMPLATES["dad"])
    kids_bubble = tracker.create_bubble(**BUBBLE_TEMPLATES["kids"])

    # Simulate device arrivals
    tracker.update_device(
        mac="00:1E:C2:12:34:56",
        label="Dad's iPhone",
        signal_strength=-45,
        ap_name="Living Room",
    )

    tracker.update_device(
        mac="00:1E:C2:12:34:57",
        label="Dad's MacBook",
        signal_strength=-55,
        ap_name="Living Room",
    )

    tracker.update_device(
        mac="00:1E:C2:12:34:58",
        label="Kids' iPad",
        signal_strength=-60,
        ap_name="Bedroom",
    )

    # Add to bubbles
    tracker.add_device_to_bubble("00:1E:C2:12:34:56", "family_dad")
    tracker.add_device_to_bubble("00:1E:C2:12:34:57", "family_dad")
    tracker.add_device_to_bubble("00:1E:C2:12:34:58", "family_kids")

    # Get summary
    summary = tracker.get_presence_summary()
    print(f"Online devices: {summary['online_devices']}")
    print(f"Home bubbles: {summary['home_bubbles']}")
    for bubble in summary['bubbles']:
        print(f"  {bubble['label']}: {bubble['online_count']} devices, state={bubble['state']}")
