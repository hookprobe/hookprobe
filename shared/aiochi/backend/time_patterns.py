"""
AIOCHI Time-Pattern Learning
Detects behavioral anomalies by learning device schedules.

Philosophy: A network has rhythms. Dad's phone connects at 6:30 AM (home from gym).
Kids' tablets go offline at 9 PM (bedtime). When these patterns break, something
interesting might be happening.

Example anomalies:
- "The garage door opened at 3 AM"
- "Dad's phone is still away at midnight (unusual)"
- "The printer is active on Sunday (never happens)"
"""

import json
import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class DeviceState(Enum):
    """Observed device states."""
    ONLINE = "online"
    OFFLINE = "offline"
    ACTIVE = "active"     # Generating significant traffic
    IDLE = "idle"         # Connected but minimal traffic


class DayOfWeek(Enum):
    """Days of the week."""
    MONDAY = 0
    TUESDAY = 1
    WEDNESDAY = 2
    THURSDAY = 3
    FRIDAY = 4
    SATURDAY = 5
    SUNDAY = 6


@dataclass
class TimeSlot:
    """A time slot for pattern learning (1-hour granularity)."""
    day_of_week: int      # 0-6 (Monday-Sunday)
    hour_of_day: int      # 0-23

    def __hash__(self):
        return hash((self.day_of_week, self.hour_of_day))

    def __eq__(self, other):
        if not isinstance(other, TimeSlot):
            return False
        return self.day_of_week == other.day_of_week and self.hour_of_day == other.hour_of_day

    @classmethod
    def from_datetime(cls, dt: datetime) -> "TimeSlot":
        """Create TimeSlot from datetime."""
        return cls(
            day_of_week=dt.weekday(),
            hour_of_day=dt.hour,
        )

    def to_dict(self) -> Dict[str, int]:
        return {"day_of_week": self.day_of_week, "hour_of_day": self.hour_of_day}

    def human_readable(self) -> str:
        """Get human-readable description."""
        day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        hour_str = f"{self.hour_of_day:02d}:00"
        return f"{day_names[self.day_of_week]} {hour_str}"


@dataclass
class PatternObservation:
    """An observation of device state at a time slot."""
    state: DeviceState
    count: int = 1
    last_seen: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state.value,
            "count": self.count,
            "last_seen": self.last_seen.isoformat(),
        }


@dataclass
class DevicePattern:
    """Learned patterns for a single device."""
    mac: str
    label: str = ""
    observations: Dict[TimeSlot, Dict[DeviceState, PatternObservation]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(PatternObservation))
    )
    total_observations: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)

    def get_typical_state(self, slot: TimeSlot) -> Tuple[Optional[DeviceState], float]:
        """
        Get the most likely state for this time slot.

        Returns:
            Tuple of (most_likely_state, confidence)
        """
        if slot not in self.observations:
            return None, 0.0

        slot_obs = self.observations[slot]
        if not slot_obs:
            return None, 0.0

        # Find state with highest count
        total_count = sum(obs.count for obs in slot_obs.values())
        if total_count == 0:
            return None, 0.0

        best_state = None
        best_count = 0
        for state, obs in slot_obs.items():
            if obs.count > best_count:
                best_count = obs.count
                best_state = state

        confidence = best_count / total_count if total_count > 0 else 0.0
        return best_state, confidence

    def is_anomaly(self, current_state: DeviceState, slot: TimeSlot, threshold: float = 0.8) -> Tuple[bool, str]:
        """
        Check if the current state is anomalous for this time slot.

        Args:
            current_state: Currently observed state
            slot: Current time slot
            threshold: Confidence threshold for anomaly detection

        Returns:
            Tuple of (is_anomaly, explanation)
        """
        typical_state, confidence = self.get_typical_state(slot)

        if typical_state is None:
            return False, "Not enough data to detect anomalies"

        if confidence < 0.5:
            return False, "Pattern not yet established (low confidence)"

        if current_state == typical_state:
            return False, f"Normal: {current_state.value} is typical at {slot.human_readable()}"

        if confidence >= threshold:
            # High confidence in different state = anomaly
            return True, f"Unusual: Device is {current_state.value} but is typically {typical_state.value} at {slot.human_readable()} ({confidence*100:.0f}% confidence)"

        return False, f"Minor deviation: {current_state.value} vs typical {typical_state.value}"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        obs_dict = {}
        for slot, states in self.observations.items():
            slot_key = f"{slot.day_of_week}_{slot.hour_of_day}"
            obs_dict[slot_key] = {
                state.value: obs.to_dict() for state, obs in states.items()
            }

        return {
            "mac": self.mac,
            "label": self.label,
            "observations": obs_dict,
            "total_observations": self.total_observations,
            "first_seen": self.first_seen.isoformat(),
            "last_updated": self.last_updated.isoformat(),
        }


@dataclass
class Anomaly:
    """A detected anomaly."""
    id: str
    timestamp: datetime
    device_mac: str
    device_label: str
    current_state: DeviceState
    expected_state: DeviceState
    confidence: float
    explanation: str
    severity: str = "medium"  # low, medium, high

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "device_mac": self.device_mac,
            "device_label": self.device_label,
            "current_state": self.current_state.value,
            "expected_state": self.expected_state.value,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "severity": self.severity,
        }


class TimePatternLearner:
    """
    Learns device behavior patterns over time and detects anomalies.

    Features:
    - Per-device pattern learning
    - Time-slot based analysis (hour of day, day of week)
    - Anomaly detection with confidence scoring
    - Persistence to ClickHouse

    Learning approach:
    - Observe device state every hour
    - Build histogram of states per time slot
    - Detect when current state deviates from typical pattern
    """

    # Minimum observations before detecting anomalies
    MIN_OBSERVATIONS_FOR_DETECTION = 7  # At least one week

    # Confidence threshold for anomaly
    ANOMALY_CONFIDENCE_THRESHOLD = 0.8

    # High severity threshold
    HIGH_SEVERITY_CONFIDENCE = 0.95

    def __init__(
        self,
        persistence_path: Optional[Path] = None,
        clickhouse_enabled: bool = False,
    ):
        """
        Initialize the Time Pattern Learner.

        Args:
            persistence_path: Path to save learned patterns
            clickhouse_enabled: Use ClickHouse for persistence
        """
        self.persistence_path = persistence_path or Path("/var/lib/hookprobe/aiochi/patterns")
        self.clickhouse_enabled = clickhouse_enabled

        # Device patterns indexed by MAC
        self._patterns: Dict[str, DevicePattern] = {}

        # Recent anomalies
        self._anomalies: List[Anomaly] = []
        self._max_anomalies = 100

        # Load existing patterns
        self._load_patterns()

    def observe(
        self,
        mac: str,
        state: DeviceState,
        label: str = "",
        timestamp: Optional[datetime] = None,
    ) -> Optional[Anomaly]:
        """
        Record an observation of device state.

        Args:
            mac: Device MAC address
            state: Current device state
            label: Human-friendly device label
            timestamp: Observation time (defaults to now)

        Returns:
            Anomaly if detected, None otherwise
        """
        mac = mac.upper().replace("-", ":")
        now = timestamp or datetime.now()
        slot = TimeSlot.from_datetime(now)

        # Get or create pattern
        if mac not in self._patterns:
            self._patterns[mac] = DevicePattern(
                mac=mac,
                label=label,
                first_seen=now,
            )

        pattern = self._patterns[mac]
        if label:
            pattern.label = label

        # Update observation
        if slot not in pattern.observations:
            pattern.observations[slot] = {}

        slot_obs = pattern.observations[slot]
        if state not in slot_obs:
            slot_obs[state] = PatternObservation(state=state, count=0)

        slot_obs[state].count += 1
        slot_obs[state].last_seen = now
        pattern.total_observations += 1
        pattern.last_updated = now

        # Check for anomaly if enough data
        anomaly = None
        if pattern.total_observations >= self.MIN_OBSERVATIONS_FOR_DETECTION:
            is_anomaly, explanation = pattern.is_anomaly(
                state, slot, self.ANOMALY_CONFIDENCE_THRESHOLD
            )

            if is_anomaly:
                typical_state, confidence = pattern.get_typical_state(slot)

                # Determine severity
                severity = "medium"
                if confidence >= self.HIGH_SEVERITY_CONFIDENCE:
                    severity = "high"
                elif confidence < 0.85:
                    severity = "low"

                anomaly = Anomaly(
                    id=f"{mac}_{now.strftime('%Y%m%d%H%M%S')}",
                    timestamp=now,
                    device_mac=mac,
                    device_label=pattern.label or mac,
                    current_state=state,
                    expected_state=typical_state,
                    confidence=confidence,
                    explanation=explanation,
                    severity=severity,
                )

                self._anomalies.append(anomaly)
                if len(self._anomalies) > self._max_anomalies:
                    self._anomalies.pop(0)

                logger.info(f"Anomaly detected: {explanation}")

        # Persist patterns periodically
        if pattern.total_observations % 10 == 0:
            self._save_patterns()

        return anomaly

    def get_device_pattern(self, mac: str) -> Optional[DevicePattern]:
        """Get learned pattern for a device."""
        mac = mac.upper().replace("-", ":")
        return self._patterns.get(mac)

    def get_all_patterns(self) -> List[DevicePattern]:
        """Get all learned patterns."""
        return list(self._patterns.values())

    def get_recent_anomalies(self, limit: int = 20) -> List[Anomaly]:
        """Get recent anomalies."""
        return list(reversed(self._anomalies[-limit:]))

    def get_device_schedule(self, mac: str) -> Dict[str, Any]:
        """
        Get a human-readable schedule for a device.

        Returns:
            Dictionary with typical schedule by day/hour
        """
        mac = mac.upper().replace("-", ":")
        pattern = self._patterns.get(mac)

        if not pattern:
            return {"error": "No pattern data for device"}

        schedule = {
            "mac": mac,
            "label": pattern.label,
            "total_observations": pattern.total_observations,
            "days": {},
        }

        day_names = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]

        for day_idx, day_name in enumerate(day_names):
            day_schedule = {}
            for hour in range(24):
                slot = TimeSlot(day_of_week=day_idx, hour_of_day=hour)
                state, confidence = pattern.get_typical_state(slot)
                if state:
                    day_schedule[f"{hour:02d}:00"] = {
                        "state": state.value,
                        "confidence": round(confidence, 2),
                    }
            schedule["days"][day_name] = day_schedule

        return schedule

    def predict_next_state(
        self,
        mac: str,
        future_time: Optional[datetime] = None,
        hours_ahead: int = 1,
    ) -> Tuple[Optional[DeviceState], float, str]:
        """
        Predict the most likely state at a future time.

        Args:
            mac: Device MAC address
            future_time: Specific time to predict (or now + hours_ahead)
            hours_ahead: Hours into the future to predict

        Returns:
            Tuple of (predicted_state, confidence, explanation)
        """
        mac = mac.upper().replace("-", ":")
        pattern = self._patterns.get(mac)

        if not pattern:
            return None, 0.0, "No pattern data for device"

        if future_time is None:
            future_time = datetime.now() + timedelta(hours=hours_ahead)

        slot = TimeSlot.from_datetime(future_time)
        state, confidence = pattern.get_typical_state(slot)

        if state is None:
            return None, 0.0, f"No data for {slot.human_readable()}"

        explanation = f"Device is typically {state.value} at {slot.human_readable()} ({confidence*100:.0f}% confidence)"
        return state, confidence, explanation

    def get_anomaly_narrative(self, anomaly: Anomaly) -> str:
        """
        Generate a human-readable narrative for an anomaly.

        Returns:
            Narrative string suitable for the Privacy feed
        """
        device_label = anomaly.device_label or anomaly.device_mac
        time_str = anomaly.timestamp.strftime("%I:%M %p")

        # Generate persona-aware narratives
        templates = {
            # Device online when usually offline
            ("offline", "online"): [
                f"{device_label} is active at {time_str}. This is unusual for this time.",
                f"Heads up: {device_label} connected at an unusual time ({time_str}).",
            ],
            # Device offline when usually online
            ("online", "offline"): [
                f"{device_label} is offline. It's usually on at this time.",
                f"Notice: {device_label} went offline earlier than usual.",
            ],
            # Device active when usually idle
            ("idle", "active"): [
                f"{device_label} is unusually active right now.",
                f"Interesting: {device_label} is generating more traffic than usual.",
            ],
            # Device idle when usually active
            ("active", "idle"): [
                f"{device_label} seems quieter than usual.",
                f"{device_label} isn't as active as it typically is at this time.",
            ],
        }

        key = (anomaly.expected_state.value, anomaly.current_state.value)
        if key in templates:
            import random
            return random.choice(templates[key])

        # Generic fallback
        return anomaly.explanation

    def _load_patterns(self) -> None:
        """Load patterns from persistence."""
        if self.clickhouse_enabled:
            self._load_from_clickhouse()
        else:
            self._load_from_file()

    def _save_patterns(self) -> None:
        """Save patterns to persistence."""
        if self.clickhouse_enabled:
            self._save_to_clickhouse()
        else:
            self._save_to_file()

    def _load_from_file(self) -> None:
        """Load patterns from JSON file."""
        pattern_file = self.persistence_path / "patterns.json"
        if not pattern_file.exists():
            return

        try:
            with open(pattern_file) as f:
                data = json.load(f)

            for mac, pattern_data in data.items():
                pattern = DevicePattern(
                    mac=mac,
                    label=pattern_data.get("label", ""),
                    total_observations=pattern_data.get("total_observations", 0),
                    first_seen=datetime.fromisoformat(pattern_data.get("first_seen", datetime.now().isoformat())),
                    last_updated=datetime.fromisoformat(pattern_data.get("last_updated", datetime.now().isoformat())),
                )

                # Reconstruct observations
                for slot_key, states in pattern_data.get("observations", {}).items():
                    day, hour = map(int, slot_key.split("_"))
                    slot = TimeSlot(day_of_week=day, hour_of_day=hour)
                    pattern.observations[slot] = {}

                    for state_str, obs_data in states.items():
                        state = DeviceState(state_str)
                        pattern.observations[slot][state] = PatternObservation(
                            state=state,
                            count=obs_data.get("count", 1),
                            last_seen=datetime.fromisoformat(obs_data.get("last_seen", datetime.now().isoformat())),
                        )

                self._patterns[mac] = pattern

            logger.info(f"Loaded {len(self._patterns)} device patterns from file")

        except Exception as e:
            logger.warning(f"Failed to load patterns: {e}")

    def _save_to_file(self) -> None:
        """Save patterns to JSON file."""
        self.persistence_path.mkdir(parents=True, exist_ok=True)
        pattern_file = self.persistence_path / "patterns.json"

        try:
            data = {mac: pattern.to_dict() for mac, pattern in self._patterns.items()}
            with open(pattern_file, "w") as f:
                json.dump(data, f, indent=2)

            logger.debug(f"Saved {len(self._patterns)} device patterns to file")

        except Exception as e:
            logger.warning(f"Failed to save patterns: {e}")

    def _load_from_clickhouse(self) -> None:
        """Load patterns from ClickHouse."""
        # In production, this would query the time_patterns table
        logger.info("ClickHouse pattern loading not yet implemented")

    def _save_to_clickhouse(self) -> None:
        """Save patterns to ClickHouse."""
        # In production, this would insert into the time_patterns table
        logger.debug("ClickHouse pattern saving not yet implemented")


if __name__ == "__main__":
    # Demo usage
    import random
    logging.basicConfig(level=logging.DEBUG)

    learner = TimePatternLearner(persistence_path=Path("/tmp/aiochi_patterns"))

    # Simulate a week of observations for "Dad's iPhone"
    print("Simulating a week of observations...")

    base_time = datetime(2024, 1, 15, 6, 0)  # Monday 6 AM

    for day in range(7):
        for hour in range(24):
            current_time = base_time + timedelta(days=day, hours=hour)

            # Dad's phone is online 6 AM - 11 PM
            if 6 <= hour <= 23:
                state = DeviceState.ONLINE
                # Active during work hours
                if 9 <= hour <= 17:
                    state = DeviceState.ACTIVE
            else:
                state = DeviceState.OFFLINE

            learner.observe(
                mac="00:1E:C2:12:34:56",
                state=state,
                label="Dad's iPhone",
                timestamp=current_time,
            )

    print(f"Total observations: {learner.get_device_pattern('00:1E:C2:12:34:56').total_observations}")

    # Test anomaly detection
    print("\nTesting anomaly detection...")

    # Normal case: Online at 10 AM Monday
    anomaly = learner.observe(
        mac="00:1E:C2:12:34:56",
        state=DeviceState.ONLINE,
        timestamp=datetime(2024, 1, 22, 10, 0),  # Monday 10 AM
    )
    print(f"10 AM Monday, Online: Anomaly={anomaly is not None}")

    # Anomaly: Offline at 10 AM Monday
    anomaly = learner.observe(
        mac="00:1E:C2:12:34:56",
        state=DeviceState.OFFLINE,
        timestamp=datetime(2024, 1, 22, 10, 1),  # Monday 10 AM
    )
    if anomaly:
        print(f"10 AM Monday, Offline: ANOMALY DETECTED!")
        print(f"  {learner.get_anomaly_narrative(anomaly)}")

    # Anomaly: Online at 3 AM
    anomaly = learner.observe(
        mac="00:1E:C2:12:34:56",
        state=DeviceState.ONLINE,
        timestamp=datetime(2024, 1, 22, 3, 0),  # Monday 3 AM
    )
    if anomaly:
        print(f"3 AM Monday, Online: ANOMALY DETECTED!")
        print(f"  {learner.get_anomaly_narrative(anomaly)}")

    # Get schedule
    print("\nDevice schedule (Tuesday):")
    schedule = learner.get_device_schedule("00:1E:C2:12:34:56")
    for hour, info in sorted(schedule["days"]["tuesday"].items()):
        print(f"  {hour}: {info['state']} ({info['confidence']*100:.0f}%)")

    # Predict future
    print("\nPrediction for tomorrow 10 AM:")
    state, confidence, explanation = learner.predict_next_state(
        "00:1E:C2:12:34:56",
        future_time=datetime.now().replace(hour=10, minute=0) + timedelta(days=1),
    )
    print(f"  {explanation}")
