"""
AIOCHI Ambient State Manager
Manages the "zero-attention" dashboard state.

Philosophy: Users shouldn't have to constantly monitor their network.
The Ambient State shows a single visual that indicates everything is fine,
and only demands attention when action is needed.

States:
- CALM (green): Everything is normal, no attention needed
- CURIOUS (yellow): Something interesting happened, optional viewing
- ALERT (red): Action required, user should look
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Callable
from threading import Lock

logger = logging.getLogger(__name__)


class AmbientState(Enum):
    """
    Ambient dashboard states.

    CALM: Green shield - everything is okay, don't look
    CURIOUS: Yellow pulse - something interesting, might want to look
    ALERT: Red glow - action required, please look
    """
    CALM = "calm"
    CURIOUS = "curious"
    ALERT = "alert"


@dataclass
class AmbientEvent:
    """An event that affects the ambient state."""
    id: str
    timestamp: datetime = field(default_factory=datetime.now)
    state: AmbientState = AmbientState.CALM
    headline: str = ""
    details: str = ""
    expires_at: Optional[datetime] = None
    requires_action: bool = False
    action_url: str = ""
    dismissed: bool = False

    def is_expired(self) -> bool:
        """Check if this event has expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "state": self.state.value,
            "headline": self.headline,
            "details": self.details,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "requires_action": self.requires_action,
            "action_url": self.action_url,
            "dismissed": self.dismissed,
        }


class AmbientStateManager:
    """
    Manages the ambient state of the AIOCHI dashboard.

    The ambient state is the "at a glance" indicator that tells users
    if they need to pay attention to their network.

    Design principles:
    1. Default to CALM - assume everything is okay
    2. Transient events (like new device) auto-expire to CURIOUS
    3. Only persistent issues (like attack) stay at ALERT
    4. Users can dismiss events to return to CALM
    """

    # How long different event types stay visible
    DEFAULT_EXPIRY = {
        AmbientState.CALM: None,  # Never expires
        AmbientState.CURIOUS: timedelta(hours=1),  # 1 hour
        AmbientState.ALERT: timedelta(hours=24),   # 24 hours
    }

    def __init__(
        self,
        on_state_change: Optional[Callable[[AmbientState, Optional[AmbientEvent]], None]] = None,
    ):
        """
        Initialize the Ambient State Manager.

        Args:
            on_state_change: Callback when state changes
        """
        self.on_state_change = on_state_change

        # Active events
        self._events: List[AmbientEvent] = []
        self._lock = Lock()

        # Current computed state
        self._current_state = AmbientState.CALM
        self._primary_event: Optional[AmbientEvent] = None

        # Statistics
        self._state_history: List[tuple] = []  # (timestamp, state)
        self._max_history = 1000

    @property
    def state(self) -> AmbientState:
        """Get current ambient state."""
        self._refresh_state()
        return self._current_state

    @property
    def primary_event(self) -> Optional[AmbientEvent]:
        """Get the primary event driving current state."""
        self._refresh_state()
        return self._primary_event

    def add_event(
        self,
        event_id: str,
        state: AmbientState,
        headline: str,
        details: str = "",
        expires_in: Optional[timedelta] = None,
        requires_action: bool = False,
        action_url: str = "",
    ) -> AmbientEvent:
        """
        Add an event that affects the ambient state.

        Args:
            event_id: Unique identifier for the event
            state: State this event represents
            headline: Short description
            details: Longer explanation
            expires_in: How long until event auto-expires
            requires_action: Whether user must take action
            action_url: URL for action button

        Returns:
            Created AmbientEvent
        """
        # Calculate expiry
        if expires_in is None:
            expires_in = self.DEFAULT_EXPIRY.get(state)

        expires_at = None
        if expires_in:
            expires_at = datetime.now() + expires_in

        event = AmbientEvent(
            id=event_id,
            state=state,
            headline=headline,
            details=details,
            expires_at=expires_at,
            requires_action=requires_action,
            action_url=action_url,
        )

        with self._lock:
            # Remove any existing event with same ID
            self._events = [e for e in self._events if e.id != event_id]
            self._events.append(event)

        self._refresh_state()

        return event

    def dismiss_event(self, event_id: str) -> bool:
        """
        Dismiss an event.

        Args:
            event_id: ID of event to dismiss

        Returns:
            True if event was found and dismissed
        """
        with self._lock:
            for event in self._events:
                if event.id == event_id:
                    event.dismissed = True
                    self._refresh_state()
                    return True
        return False

    def clear_events(self, state: Optional[AmbientState] = None) -> int:
        """
        Clear events, optionally filtered by state.

        Args:
            state: If provided, only clear events of this state

        Returns:
            Number of events cleared
        """
        with self._lock:
            if state is None:
                count = len(self._events)
                self._events = []
            else:
                original = len(self._events)
                self._events = [e for e in self._events if e.state != state]
                count = original - len(self._events)

        self._refresh_state()
        return count

    def get_active_events(self) -> List[AmbientEvent]:
        """Get all active (non-dismissed, non-expired) events."""
        with self._lock:
            return [
                e for e in self._events
                if not e.dismissed and not e.is_expired()
            ]

    def get_status(self) -> Dict[str, Any]:
        """
        Get current status for dashboard.

        Returns:
            Dictionary with state, primary event, and summary
        """
        self._refresh_state()

        active_events = self.get_active_events()

        # Count by state
        counts = {
            AmbientState.CALM: 0,
            AmbientState.CURIOUS: 0,
            AmbientState.ALERT: 0,
        }
        for event in active_events:
            counts[event.state] += 1

        return {
            "state": self._current_state.value,
            "primary_event": self._primary_event.to_dict() if self._primary_event else None,
            "event_counts": {s.value: c for s, c in counts.items()},
            "active_event_count": len(active_events),
            "message": self._get_ambient_message(),
            "timestamp": datetime.now().isoformat(),
        }

    def _refresh_state(self) -> None:
        """Recalculate current state based on active events."""
        with self._lock:
            # Remove expired events
            self._events = [e for e in self._events if not e.is_expired()]

            # Get non-dismissed events
            active = [e for e in self._events if not e.dismissed]

            old_state = self._current_state

            if not active:
                self._current_state = AmbientState.CALM
                self._primary_event = None
            else:
                # State is highest priority event
                # ALERT > CURIOUS > CALM
                alerts = [e for e in active if e.state == AmbientState.ALERT]
                curious = [e for e in active if e.state == AmbientState.CURIOUS]

                if alerts:
                    self._current_state = AmbientState.ALERT
                    # Most recent alert
                    self._primary_event = max(alerts, key=lambda e: e.timestamp)
                elif curious:
                    self._current_state = AmbientState.CURIOUS
                    self._primary_event = max(curious, key=lambda e: e.timestamp)
                else:
                    self._current_state = AmbientState.CALM
                    self._primary_event = None

            # Track state changes
            if old_state != self._current_state:
                self._state_history.append((datetime.now(), self._current_state))
                if len(self._state_history) > self._max_history:
                    self._state_history.pop(0)

                # Callback
                if self.on_state_change:
                    try:
                        self.on_state_change(self._current_state, self._primary_event)
                    except Exception as e:
                        logger.warning(f"State change callback failed: {e}")

    def _get_ambient_message(self) -> str:
        """Get human-friendly ambient message."""
        if self._current_state == AmbientState.CALM:
            return "Everything is quiet. Your network is healthy."
        elif self._current_state == AmbientState.CURIOUS:
            if self._primary_event:
                return self._primary_event.headline
            return "Something happened you might want to know about."
        else:  # ALERT
            if self._primary_event:
                return self._primary_event.headline
            return "Your attention is needed."


# Convenience functions for common events
def create_security_alert(
    manager: AmbientStateManager,
    event_id: str,
    headline: str,
    details: str = "",
    auto_resolved: bool = False,
) -> AmbientEvent:
    """Create a security alert event."""
    if auto_resolved:
        return manager.add_event(
            event_id=event_id,
            state=AmbientState.CURIOUS,
            headline=headline,
            details=details,
            expires_in=timedelta(hours=2),
            requires_action=False,
        )
    else:
        return manager.add_event(
            event_id=event_id,
            state=AmbientState.ALERT,
            headline=headline,
            details=details,
            requires_action=True,
            action_url="/security",
        )


def create_device_notification(
    manager: AmbientStateManager,
    event_id: str,
    headline: str,
    details: str = "",
) -> AmbientEvent:
    """Create a device notification event."""
    return manager.add_event(
        event_id=event_id,
        state=AmbientState.CURIOUS,
        headline=headline,
        details=details,
        expires_in=timedelta(minutes=30),
        requires_action=False,
    )


def create_performance_alert(
    manager: AmbientStateManager,
    event_id: str,
    headline: str,
    details: str = "",
    critical: bool = False,
) -> AmbientEvent:
    """Create a performance alert event."""
    return manager.add_event(
        event_id=event_id,
        state=AmbientState.ALERT if critical else AmbientState.CURIOUS,
        headline=headline,
        details=details,
        expires_in=timedelta(hours=1) if not critical else timedelta(hours=4),
        requires_action=critical,
        action_url="/performance" if critical else "",
    )


if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.DEBUG)

    def on_change(state: AmbientState, event: Optional[AmbientEvent]):
        print(f"State changed to: {state.value}")
        if event:
            print(f"  Primary event: {event.headline}")

    manager = AmbientStateManager(on_state_change=on_change)

    print(f"Initial state: {manager.state.value}")

    # Add a curious event
    create_device_notification(
        manager,
        event_id="device_001",
        headline="New device joined: Dad's iPhone",
        details="Connected to Living Room WiFi at 10:30 AM",
    )
    print(f"After device join: {manager.state.value}")

    # Add a security alert
    create_security_alert(
        manager,
        event_id="security_001",
        headline="Threat blocked on Smart TV",
        details="Malicious connection blocked",
        auto_resolved=True,
    )
    print(f"After security (resolved): {manager.state.value}")

    # Add an unresolved security alert
    create_security_alert(
        manager,
        event_id="security_002",
        headline="Suspicious activity on network",
        details="Unusual traffic pattern detected",
        auto_resolved=False,
    )
    print(f"After security (unresolved): {manager.state.value}")

    # Get status
    status = manager.get_status()
    print(f"\nStatus: {status['message']}")
    print(f"Active events: {status['active_event_count']}")
