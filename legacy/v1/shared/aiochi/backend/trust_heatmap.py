"""
AIOCHI Trust Heatmap
Visual representation of device trust over time.

Philosophy: Trust isn't binary. New devices start dim, trusted devices glow.
Users can see at a glance which devices have earned trust and which are still
being evaluated.

Visual representation:
  ████████████████████████  Dad's iPhone (TRUSTED - 6 months)
  ██████████████████████░░  MacBook (HIGH - 4 months)
  ████████████████░░░░░░░░  Smart TV (MEDIUM - 2 months)
  ██░░░░░░░░░░░░░░░░░░░░░░  Guest_Laptop (NEW - 1 hour)
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class TrustLevel(Enum):
    """Device trust levels (visual heatmap)."""
    UNKNOWN = 0       # ░░░░░░░░░░░░░░░░ - Just discovered
    NEW = 1           # ██░░░░░░░░░░░░░░ - Less than 1 hour
    LEARNING = 2      # ████░░░░░░░░░░░░ - 1 hour to 24 hours
    FAMILIAR = 3      # ██████░░░░░░░░░░ - 1 day to 7 days
    RECOGNIZED = 4    # ████████░░░░░░░░ - 1 week to 1 month
    TRUSTED = 5       # ██████████░░░░░░ - 1 month to 3 months
    ESTABLISHED = 6   # ████████████░░░░ - 3 months to 6 months
    VETERAN = 7       # ██████████████░░ - 6 months to 1 year
    CORE = 8          # ████████████████ - More than 1 year


class TrustAction(Enum):
    """Actions that affect trust score."""
    FIRST_SEEN = "first_seen"
    RECONNECT = "reconnect"
    STABLE_BEHAVIOR = "stable_behavior"
    NORMAL_TRAFFIC = "normal_traffic"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    BLOCKED_THREAT = "blocked_threat"
    MANUAL_TRUST = "manual_trust"
    MANUAL_DISTRUST = "manual_distrust"
    ANOMALY_DETECTED = "anomaly_detected"
    ATTESTATION_PASSED = "attestation_passed"


# Trust score adjustments for each action
TRUST_ADJUSTMENTS = {
    TrustAction.FIRST_SEEN: 0,
    TrustAction.RECONNECT: 1,
    TrustAction.STABLE_BEHAVIOR: 2,
    TrustAction.NORMAL_TRAFFIC: 1,
    TrustAction.SUSPICIOUS_ACTIVITY: -10,
    TrustAction.BLOCKED_THREAT: -25,
    TrustAction.MANUAL_TRUST: 50,
    TrustAction.MANUAL_DISTRUST: -50,
    TrustAction.ANOMALY_DETECTED: -5,
    TrustAction.ATTESTATION_PASSED: 20,
}

# Time-based trust thresholds (time -> minimum trust level)
TIME_TRUST_THRESHOLDS = [
    (timedelta(hours=1), TrustLevel.NEW),
    (timedelta(hours=24), TrustLevel.LEARNING),
    (timedelta(days=7), TrustLevel.FAMILIAR),
    (timedelta(days=30), TrustLevel.RECOGNIZED),
    (timedelta(days=90), TrustLevel.TRUSTED),
    (timedelta(days=180), TrustLevel.ESTABLISHED),
    (timedelta(days=365), TrustLevel.VETERAN),
    (timedelta(days=365 * 10), TrustLevel.CORE),  # 10 years = effectively infinite
]

# Trust level colors for visualization
TRUST_COLORS = {
    TrustLevel.UNKNOWN: "#9E9E9E",    # Gray
    TrustLevel.NEW: "#F44336",        # Red
    TrustLevel.LEARNING: "#FF9800",   # Orange
    TrustLevel.FAMILIAR: "#FFC107",   # Amber
    TrustLevel.RECOGNIZED: "#CDDC39", # Lime
    TrustLevel.TRUSTED: "#8BC34A",    # Light Green
    TrustLevel.ESTABLISHED: "#4CAF50",# Green
    TrustLevel.VETERAN: "#009688",    # Teal
    TrustLevel.CORE: "#00BCD4",       # Cyan
}


@dataclass
class TrustEvent:
    """An event that affected device trust."""
    timestamp: datetime
    action: TrustAction
    score_delta: int
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "action": self.action.value,
            "score_delta": self.score_delta,
            "reason": self.reason,
        }


@dataclass
class DeviceTrust:
    """Trust information for a single device."""
    mac: str
    label: str = ""
    trust_score: int = 0           # Raw score (can be negative)
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    total_connections: int = 0
    threat_count: int = 0
    anomaly_count: int = 0
    manual_override: Optional[TrustLevel] = None  # User manually set trust
    events: List[TrustEvent] = field(default_factory=list)
    max_events: int = 100

    def add_event(self, action: TrustAction, reason: str = "") -> int:
        """
        Add a trust event.

        Returns:
            Score delta applied
        """
        delta = TRUST_ADJUSTMENTS.get(action, 0)

        event = TrustEvent(
            timestamp=datetime.now(),
            action=action,
            score_delta=delta,
            reason=reason,
        )

        self.events.append(event)
        if len(self.events) > self.max_events:
            self.events.pop(0)

        self.trust_score += delta
        self.last_seen = datetime.now()

        # Update counters
        if action == TrustAction.RECONNECT:
            self.total_connections += 1
        elif action == TrustAction.BLOCKED_THREAT:
            self.threat_count += 1
        elif action == TrustAction.ANOMALY_DETECTED:
            self.anomaly_count += 1

        # Recalculate trust level
        self._calculate_trust_level()

        return delta

    def _calculate_trust_level(self) -> None:
        """Calculate trust level based on time and score."""
        # If manually overridden, use that
        if self.manual_override is not None:
            self.trust_level = self.manual_override
            return

        now = datetime.now()
        time_on_network = now - self.first_seen

        # Start with time-based trust
        base_level = TrustLevel.UNKNOWN
        for threshold_time, level in TIME_TRUST_THRESHOLDS:
            if time_on_network >= threshold_time:
                base_level = level
            else:
                break

        # Adjust based on score
        # Positive score can boost level by 1
        # Negative score can reduce level by 1-2
        level_value = base_level.value

        if self.trust_score > 50:
            level_value = min(level_value + 1, TrustLevel.CORE.value)
        elif self.trust_score < -20:
            level_value = max(level_value - 2, TrustLevel.UNKNOWN.value)
        elif self.trust_score < 0:
            level_value = max(level_value - 1, TrustLevel.UNKNOWN.value)

        # Convert back to enum
        for level in TrustLevel:
            if level.value == level_value:
                self.trust_level = level
                return

        self.trust_level = base_level

    @property
    def heatmap_progress(self) -> float:
        """
        Get heatmap progress as 0.0-1.0.

        Used for visual rendering.
        """
        return self.trust_level.value / TrustLevel.CORE.value

    @property
    def heatmap_bar(self) -> str:
        """
        Get ASCII heatmap bar.

        Returns:
            String like "██████████░░░░░░"
        """
        total_chars = 16
        filled = int(self.heatmap_progress * total_chars)
        empty = total_chars - filled
        return "█" * filled + "░" * empty

    @property
    def color(self) -> str:
        """Get color for this trust level."""
        return TRUST_COLORS.get(self.trust_level, "#9E9E9E")

    @property
    def time_description(self) -> str:
        """Get human-readable time on network."""
        now = datetime.now()
        delta = now - self.first_seen

        if delta < timedelta(hours=1):
            minutes = int(delta.total_seconds() / 60)
            return f"{minutes} minute{'s' if minutes != 1 else ''}"
        elif delta < timedelta(days=1):
            hours = int(delta.total_seconds() / 3600)
            return f"{hours} hour{'s' if hours != 1 else ''}"
        elif delta < timedelta(days=30):
            days = delta.days
            return f"{days} day{'s' if days != 1 else ''}"
        elif delta < timedelta(days=365):
            months = delta.days // 30
            return f"{months} month{'s' if months != 1 else ''}"
        else:
            years = delta.days // 365
            return f"{years} year{'s' if years != 1 else ''}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mac": self.mac,
            "label": self.label,
            "trust_score": self.trust_score,
            "trust_level": self.trust_level.name,
            "trust_level_value": self.trust_level.value,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "total_connections": self.total_connections,
            "threat_count": self.threat_count,
            "anomaly_count": self.anomaly_count,
            "heatmap_progress": self.heatmap_progress,
            "heatmap_bar": self.heatmap_bar,
            "color": self.color,
            "time_description": self.time_description,
            "manual_override": self.manual_override.name if self.manual_override else None,
            "recent_events": [e.to_dict() for e in self.events[-10:]],
        }


class TrustHeatmap:
    """
    Manages device trust and provides heatmap visualization.

    Features:
    - Time-based trust growth
    - Event-based trust adjustments
    - Manual trust overrides
    - Heatmap visualization data
    """

    def __init__(
        self,
        persistence_path: Optional[Path] = None,
    ):
        """
        Initialize the Trust Heatmap.

        Args:
            persistence_path: Path to save trust data
        """
        self.persistence_path = persistence_path or Path("/var/lib/hookprobe/aiochi/trust")

        # Device trust indexed by MAC
        self._devices: Dict[str, DeviceTrust] = {}

        # Load existing data
        self._load_data()

    def record_first_seen(self, mac: str, label: str = "") -> DeviceTrust:
        """
        Record a new device being seen for the first time.

        Args:
            mac: Device MAC address
            label: Human-friendly label

        Returns:
            Created DeviceTrust
        """
        mac = mac.upper().replace("-", ":")

        if mac in self._devices:
            # Already exists, just update
            device = self._devices[mac]
            device.add_event(TrustAction.RECONNECT, "Device reconnected")
            if label:
                device.label = label
            return device

        # New device
        device = DeviceTrust(
            mac=mac,
            label=label,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
        )
        device.add_event(TrustAction.FIRST_SEEN, "Device first seen on network")

        self._devices[mac] = device
        self._save_data()

        logger.info(f"New device tracked: {label or mac}")
        return device

    def record_reconnect(self, mac: str, label: str = "") -> Optional[DeviceTrust]:
        """Record a device reconnecting."""
        mac = mac.upper().replace("-", ":")

        if mac not in self._devices:
            return self.record_first_seen(mac, label)

        device = self._devices[mac]
        device.add_event(TrustAction.RECONNECT, "Device reconnected")
        if label:
            device.label = label

        return device

    def record_stable_behavior(self, mac: str) -> Optional[DeviceTrust]:
        """Record stable/expected device behavior (periodic boost)."""
        mac = mac.upper().replace("-", ":")

        if mac not in self._devices:
            return None

        device = self._devices[mac]
        device.add_event(TrustAction.STABLE_BEHAVIOR, "Consistent normal behavior")
        return device

    def record_suspicious_activity(self, mac: str, reason: str = "") -> Optional[DeviceTrust]:
        """Record suspicious activity (trust penalty)."""
        mac = mac.upper().replace("-", ":")

        if mac not in self._devices:
            return None

        device = self._devices[mac]
        device.add_event(TrustAction.SUSPICIOUS_ACTIVITY, reason or "Suspicious activity detected")
        self._save_data()

        logger.warning(f"Trust reduced for {device.label or mac}: {reason}")
        return device

    def record_blocked_threat(self, mac: str, threat_type: str = "") -> Optional[DeviceTrust]:
        """Record a blocked threat (significant trust penalty)."""
        mac = mac.upper().replace("-", ":")

        if mac not in self._devices:
            return None

        device = self._devices[mac]
        device.add_event(TrustAction.BLOCKED_THREAT, f"Threat blocked: {threat_type}" if threat_type else "Threat blocked")
        self._save_data()

        logger.warning(f"Threat blocked on {device.label or mac}, trust significantly reduced")
        return device

    def record_anomaly(self, mac: str, anomaly_description: str = "") -> Optional[DeviceTrust]:
        """Record a behavioral anomaly (minor trust penalty)."""
        mac = mac.upper().replace("-", ":")

        if mac not in self._devices:
            return None

        device = self._devices[mac]
        device.add_event(TrustAction.ANOMALY_DETECTED, anomaly_description or "Behavioral anomaly detected")
        return device

    def record_attestation(self, mac: str, passed: bool) -> Optional[DeviceTrust]:
        """Record attestation result (significant trust boost if passed)."""
        mac = mac.upper().replace("-", ":")

        if mac not in self._devices:
            return None

        device = self._devices[mac]
        if passed:
            device.add_event(TrustAction.ATTESTATION_PASSED, "Device attestation verified")
            self._save_data()
        return device

    def set_manual_trust(self, mac: str, level: TrustLevel, reason: str = "") -> Optional[DeviceTrust]:
        """
        Manually set trust level (user override).

        Args:
            mac: Device MAC address
            level: Trust level to set
            reason: Reason for override

        Returns:
            Updated DeviceTrust
        """
        mac = mac.upper().replace("-", ":")

        if mac not in self._devices:
            return None

        device = self._devices[mac]
        device.manual_override = level

        if level.value >= TrustLevel.TRUSTED.value:
            device.add_event(TrustAction.MANUAL_TRUST, reason or f"Manually trusted by user")
        else:
            device.add_event(TrustAction.MANUAL_DISTRUST, reason or f"Manually set to {level.name}")

        device._calculate_trust_level()
        self._save_data()

        logger.info(f"Manual trust set for {device.label or mac}: {level.name}")
        return device

    def clear_manual_trust(self, mac: str) -> Optional[DeviceTrust]:
        """Remove manual trust override."""
        mac = mac.upper().replace("-", ":")

        if mac not in self._devices:
            return None

        device = self._devices[mac]
        device.manual_override = None
        device._calculate_trust_level()
        self._save_data()

        return device

    def get_device_trust(self, mac: str) -> Optional[DeviceTrust]:
        """Get trust info for a device."""
        mac = mac.upper().replace("-", ":")
        return self._devices.get(mac)

    def get_all_devices(self) -> List[DeviceTrust]:
        """Get all tracked devices."""
        return list(self._devices.values())

    def get_heatmap_data(self) -> List[Dict[str, Any]]:
        """
        Get heatmap visualization data for all devices.

        Returns:
            List of device trust data sorted by trust level (highest first)
        """
        devices = sorted(
            self._devices.values(),
            key=lambda d: (d.trust_level.value, d.trust_score),
            reverse=True,
        )

        return [d.to_dict() for d in devices]

    def get_summary(self) -> Dict[str, Any]:
        """
        Get trust summary for dashboard.

        Returns:
            Summary statistics
        """
        devices = list(self._devices.values())

        if not devices:
            return {
                "total_devices": 0,
                "by_level": {},
                "average_score": 0,
                "high_risk_count": 0,
            }

        by_level = {}
        for level in TrustLevel:
            count = sum(1 for d in devices if d.trust_level == level)
            if count > 0:
                by_level[level.name] = count

        high_risk = sum(1 for d in devices if d.trust_score < 0 or d.threat_count > 0)
        avg_score = sum(d.trust_score for d in devices) / len(devices)

        return {
            "total_devices": len(devices),
            "by_level": by_level,
            "average_score": round(avg_score, 1),
            "high_risk_count": high_risk,
            "newest_device": min(devices, key=lambda d: d.first_seen).label if devices else None,
            "oldest_device": max(devices, key=lambda d: d.first_seen).label if devices else None,
        }

    def _load_data(self) -> None:
        """Load trust data from persistence."""
        data_file = self.persistence_path / "trust.json"
        if not data_file.exists():
            return

        try:
            with open(data_file) as f:
                data = json.load(f)

            for mac, device_data in data.items():
                device = DeviceTrust(
                    mac=mac,
                    label=device_data.get("label", ""),
                    trust_score=device_data.get("trust_score", 0),
                    first_seen=datetime.fromisoformat(device_data.get("first_seen", datetime.now().isoformat())),
                    last_seen=datetime.fromisoformat(device_data.get("last_seen", datetime.now().isoformat())),
                    total_connections=device_data.get("total_connections", 0),
                    threat_count=device_data.get("threat_count", 0),
                    anomaly_count=device_data.get("anomaly_count", 0),
                )

                if device_data.get("manual_override"):
                    device.manual_override = TrustLevel[device_data["manual_override"]]

                device._calculate_trust_level()
                self._devices[mac] = device

            logger.info(f"Loaded trust data for {len(self._devices)} devices")

        except Exception as e:
            logger.warning(f"Failed to load trust data: {e}")

    def _save_data(self) -> None:
        """Save trust data to persistence."""
        self.persistence_path.mkdir(parents=True, exist_ok=True)
        data_file = self.persistence_path / "trust.json"

        try:
            data = {}
            for mac, device in self._devices.items():
                data[mac] = {
                    "label": device.label,
                    "trust_score": device.trust_score,
                    "first_seen": device.first_seen.isoformat(),
                    "last_seen": device.last_seen.isoformat(),
                    "total_connections": device.total_connections,
                    "threat_count": device.threat_count,
                    "anomaly_count": device.anomaly_count,
                    "manual_override": device.manual_override.name if device.manual_override else None,
                }

            with open(data_file, "w") as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            logger.warning(f"Failed to save trust data: {e}")


if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.DEBUG)

    heatmap = TrustHeatmap(persistence_path=Path("/tmp/aiochi_trust"))

    # Add some devices at different trust levels
    print("Recording devices...")

    # New device (just joined)
    heatmap.record_first_seen("AA:BB:CC:DD:EE:01", "Guest Laptop")

    # Device seen for a few days
    dev2 = heatmap.record_first_seen("AA:BB:CC:DD:EE:02", "Smart TV")
    dev2.first_seen = datetime.now() - timedelta(days=3)
    for _ in range(10):
        heatmap.record_reconnect("AA:BB:CC:DD:EE:02")
    dev2._calculate_trust_level()

    # Device seen for a month
    dev3 = heatmap.record_first_seen("AA:BB:CC:DD:EE:03", "Dad's iPhone")
    dev3.first_seen = datetime.now() - timedelta(days=45)
    for _ in range(50):
        heatmap.record_stable_behavior("AA:BB:CC:DD:EE:03")
    dev3._calculate_trust_level()

    # Device seen for 6 months
    dev4 = heatmap.record_first_seen("AA:BB:CC:DD:EE:04", "MacBook Pro")
    dev4.first_seen = datetime.now() - timedelta(days=200)
    for _ in range(100):
        heatmap.record_stable_behavior("AA:BB:CC:DD:EE:04")
    dev4._calculate_trust_level()

    # Device with threat history
    dev5 = heatmap.record_first_seen("AA:BB:CC:DD:EE:05", "IoT Camera")
    dev5.first_seen = datetime.now() - timedelta(days=30)
    heatmap.record_blocked_threat("AA:BB:CC:DD:EE:05", "Malware C2")
    heatmap.record_suspicious_activity("AA:BB:CC:DD:EE:05", "Unusual outbound traffic")

    # Print heatmap
    print("\n" + "=" * 60)
    print("TRUST HEATMAP")
    print("=" * 60)

    for device_data in heatmap.get_heatmap_data():
        print(f"  {device_data['heatmap_bar']}  {device_data['label']:20} ({device_data['trust_level']} - {device_data['time_description']})")

    # Print summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    summary = heatmap.get_summary()
    print(f"  Total devices: {summary['total_devices']}")
    print(f"  High risk: {summary['high_risk_count']}")
    print(f"  Average score: {summary['average_score']}")
    print(f"  By level: {summary['by_level']}")
