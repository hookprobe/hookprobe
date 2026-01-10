"""
AIOCHI Whisper Mode
AI explains its reasoning in real-time.

Philosophy: Users want to know what the AI is thinking. Whisper Mode shows
the AI's reasoning process as it investigates events.

Example whisper stream:
  🤔 "I noticed unusual traffic from the printer at 3 AM..."
  🔍 "Checking if it's a software update..."
  ✅ "Confirmed: HP firmware update. All good!"

This builds trust by making the AI's decision-making transparent.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Awaitable
from threading import Lock
import uuid

logger = logging.getLogger(__name__)


class WhisperPhase(Enum):
    """Phases of AI reasoning."""
    OBSERVING = "observing"     # 👀 Initial observation
    THINKING = "thinking"       # 🤔 Analyzing the situation
    INVESTIGATING = "investigating"  # 🔍 Gathering more data
    CORRELATING = "correlating"  # 🔗 Connecting dots
    DECIDING = "deciding"       # ⚖️ Making a decision
    ACTING = "acting"           # ⚡ Taking action
    RESOLVED = "resolved"       # ✅ Issue resolved
    ESCALATING = "escalating"   # ⚠️ Needs human attention


class WhisperPriority(Enum):
    """Priority of whisper streams."""
    BACKGROUND = 1    # Low priority, can be ignored
    NORMAL = 2        # Standard investigation
    ELEVATED = 3      # Something interesting
    URGENT = 4        # Needs attention soon
    CRITICAL = 5      # Immediate attention required


# Emoji mapping for phases
PHASE_EMOJI = {
    WhisperPhase.OBSERVING: "👀",
    WhisperPhase.THINKING: "🤔",
    WhisperPhase.INVESTIGATING: "🔍",
    WhisperPhase.CORRELATING: "🔗",
    WhisperPhase.DECIDING: "⚖️",
    WhisperPhase.ACTING: "⚡",
    WhisperPhase.RESOLVED: "✅",
    WhisperPhase.ESCALATING: "⚠️",
}


@dataclass
class WhisperMessage:
    """A single whisper message in a stream."""
    timestamp: datetime
    phase: WhisperPhase
    message: str
    details: Optional[Dict[str, Any]] = None
    duration_ms: Optional[int] = None  # How long this phase took

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "phase": self.phase.value,
            "emoji": PHASE_EMOJI.get(self.phase, "💭"),
            "message": self.message,
            "details": self.details,
            "duration_ms": self.duration_ms,
        }

    def formatted(self) -> str:
        """Get formatted message with emoji."""
        emoji = PHASE_EMOJI.get(self.phase, "💭")
        return f'{emoji} "{self.message}"'


@dataclass
class WhisperStream:
    """A stream of whisper messages for a single investigation."""
    id: str
    started_at: datetime = field(default_factory=datetime.now)
    ended_at: Optional[datetime] = None
    trigger_event: str = ""           # What triggered this investigation
    device_mac: str = ""
    device_label: str = ""
    priority: WhisperPriority = WhisperPriority.NORMAL
    messages: List[WhisperMessage] = field(default_factory=list)
    final_outcome: str = ""
    resolved: bool = False

    def add_message(self, phase: WhisperPhase, message: str, details: Optional[Dict[str, Any]] = None) -> WhisperMessage:
        """Add a message to this stream."""
        now = datetime.now()

        # Calculate duration since last message
        duration_ms = None
        if self.messages:
            delta = now - self.messages[-1].timestamp
            duration_ms = int(delta.total_seconds() * 1000)

        msg = WhisperMessage(
            timestamp=now,
            phase=phase,
            message=message,
            details=details,
            duration_ms=duration_ms,
        )

        self.messages.append(msg)

        # Check for resolution phases
        if phase in (WhisperPhase.RESOLVED, WhisperPhase.ESCALATING):
            self.ended_at = now
            self.resolved = phase == WhisperPhase.RESOLVED
            self.final_outcome = message

        return msg

    @property
    def duration_seconds(self) -> float:
        """Get total investigation duration."""
        end = self.ended_at or datetime.now()
        return (end - self.started_at).total_seconds()

    @property
    def current_phase(self) -> WhisperPhase:
        """Get current phase."""
        if not self.messages:
            return WhisperPhase.OBSERVING
        return self.messages[-1].phase

    @property
    def is_active(self) -> bool:
        """Check if stream is still active."""
        return self.ended_at is None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "trigger_event": self.trigger_event,
            "device_mac": self.device_mac,
            "device_label": self.device_label,
            "priority": self.priority.value,
            "messages": [
                {
                    "timestamp": m.timestamp.isoformat(),
                    "phase": m.phase.value,
                    "emoji": PHASE_EMOJI.get(m.phase, "💭"),
                    "message": m.message,
                    "duration_ms": m.duration_ms,
                }
                for m in self.messages
            ],
            "final_outcome": self.final_outcome,
            "resolved": self.resolved,
            "duration_seconds": self.duration_seconds,
            "current_phase": self.current_phase.value,
            "is_active": self.is_active,
        }

    def get_summary(self) -> str:
        """Get a summary of this investigation."""
        if not self.messages:
            return "No investigation data"

        device = self.device_label or self.device_mac or "Unknown device"
        duration = f"{self.duration_seconds:.1f}s"

        if self.resolved:
            return f"✅ {device}: {self.final_outcome} ({duration})"
        elif self.ended_at:
            return f"⚠️ {device}: {self.final_outcome} ({duration})"
        else:
            return f"🔍 {device}: {self.messages[-1].message}..."


class WhisperEngine:
    """
    Manages whisper streams and provides real-time reasoning transparency.

    Features:
    - Create investigation streams
    - Add reasoning steps
    - Subscribe to real-time updates
    - Query active/recent investigations
    """

    def __init__(
        self,
        max_active_streams: int = 10,
        max_history: int = 50,
    ):
        """
        Initialize the Whisper Engine.

        Args:
            max_active_streams: Maximum concurrent investigations
            max_history: Maximum completed investigations to keep
        """
        self.max_active_streams = max_active_streams
        self.max_history = max_history

        # Active and completed streams
        self._active_streams: Dict[str, WhisperStream] = {}
        self._completed_streams: List[WhisperStream] = []
        self._lock = Lock()

        # Subscribers for real-time updates
        self._subscribers: List[Callable[[WhisperStream, WhisperMessage], Awaitable[None]]] = []

    def start_investigation(
        self,
        trigger_event: str,
        device_mac: str = "",
        device_label: str = "",
        priority: WhisperPriority = WhisperPriority.NORMAL,
        initial_message: str = "",
    ) -> WhisperStream:
        """
        Start a new investigation stream.

        Args:
            trigger_event: What triggered this investigation
            device_mac: Related device MAC
            device_label: Human-friendly device label
            priority: Investigation priority
            initial_message: First observation message

        Returns:
            Created WhisperStream
        """
        stream_id = str(uuid.uuid4())[:8]

        stream = WhisperStream(
            id=stream_id,
            trigger_event=trigger_event,
            device_mac=device_mac,
            device_label=device_label,
            priority=priority,
        )

        # Add initial observation
        if initial_message:
            stream.add_message(
                WhisperPhase.OBSERVING,
                initial_message,
            )

        with self._lock:
            # Enforce max active streams
            if len(self._active_streams) >= self.max_active_streams:
                # Remove oldest low-priority stream
                oldest = min(
                    self._active_streams.values(),
                    key=lambda s: (s.priority.value, s.started_at),
                )
                self._complete_stream(oldest.id)

            self._active_streams[stream_id] = stream

        logger.debug(f"Started whisper stream {stream_id}: {trigger_event}")
        return stream

    def whisper(
        self,
        stream_id: str,
        phase: WhisperPhase,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Optional[WhisperMessage]:
        """
        Add a whisper message to a stream.

        Args:
            stream_id: Stream to add to
            phase: Current reasoning phase
            message: What the AI is thinking
            details: Optional technical details

        Returns:
            Created WhisperMessage or None if stream not found
        """
        with self._lock:
            stream = self._active_streams.get(stream_id)
            if not stream:
                return None

            msg = stream.add_message(phase, message, details)

            # Notify subscribers
            self._notify_subscribers(stream, msg)

            # Check if stream completed
            if not stream.is_active:
                self._complete_stream(stream_id)

            return msg

    def resolve(self, stream_id: str, outcome: str) -> Optional[WhisperStream]:
        """
        Resolve an investigation.

        Args:
            stream_id: Stream to resolve
            outcome: Final outcome message

        Returns:
            Resolved WhisperStream
        """
        return self._finish_stream(stream_id, WhisperPhase.RESOLVED, outcome)

    def escalate(self, stream_id: str, reason: str) -> Optional[WhisperStream]:
        """
        Escalate an investigation (needs human attention).

        Args:
            stream_id: Stream to escalate
            reason: Why escalation is needed

        Returns:
            Escalated WhisperStream
        """
        return self._finish_stream(stream_id, WhisperPhase.ESCALATING, reason)

    def _finish_stream(self, stream_id: str, phase: WhisperPhase, message: str) -> Optional[WhisperStream]:
        """Finish a stream with given phase and message."""
        with self._lock:
            stream = self._active_streams.get(stream_id)
            if not stream:
                return None

            stream.add_message(phase, message)
            self._complete_stream(stream_id)

            return stream

    def _complete_stream(self, stream_id: str) -> None:
        """Move stream from active to completed."""
        if stream_id not in self._active_streams:
            return

        stream = self._active_streams.pop(stream_id)

        # Ensure it's marked as ended
        if not stream.ended_at:
            stream.ended_at = datetime.now()

        self._completed_streams.append(stream)

        # Enforce history limit
        if len(self._completed_streams) > self.max_history:
            self._completed_streams.pop(0)

    def get_active_streams(self) -> List[WhisperStream]:
        """Get all active investigation streams."""
        with self._lock:
            return list(self._active_streams.values())

    def get_stream(self, stream_id: str) -> Optional[WhisperStream]:
        """Get a specific stream by ID."""
        with self._lock:
            if stream_id in self._active_streams:
                return self._active_streams[stream_id]
            for stream in self._completed_streams:
                if stream.id == stream_id:
                    return stream
        return None

    def get_recent_completed(self, limit: int = 10) -> List[WhisperStream]:
        """Get recently completed investigations."""
        with self._lock:
            return list(reversed(self._completed_streams[-limit:]))

    def get_device_investigations(self, mac: str, limit: int = 10) -> List[WhisperStream]:
        """Get investigations for a specific device."""
        mac = mac.upper().replace("-", ":")
        results = []

        with self._lock:
            # Check active streams
            for stream in self._active_streams.values():
                if stream.device_mac == mac:
                    results.append(stream)

            # Check completed streams
            for stream in reversed(self._completed_streams):
                if stream.device_mac == mac:
                    results.append(stream)
                    if len(results) >= limit:
                        break

        return results[:limit]

    def subscribe(self, callback: Callable[[WhisperStream, WhisperMessage], Awaitable[None]]) -> None:
        """
        Subscribe to real-time whisper updates.

        Args:
            callback: Async function called with (stream, message) on updates
        """
        self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable) -> None:
        """Unsubscribe from updates."""
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    def _notify_subscribers(self, stream: WhisperStream, message: WhisperMessage) -> None:
        """Notify all subscribers of a new message."""
        for callback in self._subscribers:
            try:
                # Run async callback in background
                asyncio.create_task(callback(stream, message))
            except RuntimeError:
                # No event loop running, skip async notification
                pass
            except Exception as e:
                logger.warning(f"Subscriber notification failed: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Get whisper engine status."""
        with self._lock:
            active = list(self._active_streams.values())
            recent = list(reversed(self._completed_streams[-5:]))

        return {
            "active_count": len(active),
            "completed_count": len(self._completed_streams),
            "active_streams": [s.get_summary() for s in active],
            "recent_completed": [s.get_summary() for s in recent],
        }


# Pre-built investigation templates
class InvestigationTemplates:
    """Templates for common investigation scenarios."""

    @staticmethod
    async def investigate_unusual_traffic(
        engine: WhisperEngine,
        device_mac: str,
        device_label: str,
        traffic_type: str,
        destination: str,
    ) -> WhisperStream:
        """
        Investigate unusual traffic from a device.

        This is an example of a full investigation flow.
        """
        stream = engine.start_investigation(
            trigger_event="unusual_traffic",
            device_mac=device_mac,
            device_label=device_label,
            priority=WhisperPriority.ELEVATED,
            initial_message=f"I noticed unusual {traffic_type} traffic from {device_label}...",
        )

        # Simulate investigation steps
        await asyncio.sleep(0.5)
        engine.whisper(
            stream.id,
            WhisperPhase.THINKING,
            f"The traffic is going to {destination}. Let me check if this is expected...",
        )

        await asyncio.sleep(0.5)
        engine.whisper(
            stream.id,
            WhisperPhase.INVESTIGATING,
            "Checking against known good destinations...",
        )

        await asyncio.sleep(0.5)
        engine.whisper(
            stream.id,
            WhisperPhase.CORRELATING,
            f"Comparing with {device_label}'s normal behavior pattern...",
        )

        # Simulate finding it's okay
        await asyncio.sleep(0.5)
        engine.resolve(
            stream.id,
            f"Confirmed: This is a legitimate software update from {destination}. All good!",
        )

        return stream

    @staticmethod
    async def investigate_new_device(
        engine: WhisperEngine,
        device_mac: str,
        device_label: str,
        vendor: str,
    ) -> WhisperStream:
        """Investigate a new device joining the network."""
        stream = engine.start_investigation(
            trigger_event="new_device",
            device_mac=device_mac,
            device_label=device_label,
            priority=WhisperPriority.NORMAL,
            initial_message=f"A new device just joined the network: {device_label}",
        )

        await asyncio.sleep(0.3)
        engine.whisper(
            stream.id,
            WhisperPhase.THINKING,
            f"It's made by {vendor}. Let me identify what kind of device this is...",
        )

        await asyncio.sleep(0.5)
        engine.whisper(
            stream.id,
            WhisperPhase.INVESTIGATING,
            "Analyzing DHCP fingerprint and network behavior...",
        )

        await asyncio.sleep(0.3)
        engine.whisper(
            stream.id,
            WhisperPhase.DECIDING,
            "Determining appropriate trust level and network segment...",
        )

        await asyncio.sleep(0.2)
        engine.resolve(
            stream.id,
            f"Identified as {device_label}. Placed in standard segment with monitoring enabled.",
        )

        return stream

    @staticmethod
    async def investigate_blocked_threat(
        engine: WhisperEngine,
        device_mac: str,
        device_label: str,
        threat_type: str,
        source: str,
    ) -> WhisperStream:
        """Investigate a blocked threat."""
        stream = engine.start_investigation(
            trigger_event="blocked_threat",
            device_mac=device_mac,
            device_label=device_label,
            priority=WhisperPriority.URGENT,
            initial_message=f"ALERT: I just blocked a {threat_type} attempt on {device_label}!",
        )

        await asyncio.sleep(0.2)
        engine.whisper(
            stream.id,
            WhisperPhase.ACTING,
            f"Connection to {source} has been terminated.",
        )

        await asyncio.sleep(0.3)
        engine.whisper(
            stream.id,
            WhisperPhase.INVESTIGATING,
            f"Checking if {device_label} was compromised...",
        )

        await asyncio.sleep(0.5)
        engine.whisper(
            stream.id,
            WhisperPhase.CORRELATING,
            "Scanning for similar activity on other devices...",
        )

        await asyncio.sleep(0.3)
        engine.resolve(
            stream.id,
            f"Threat neutralized. {device_label} is clean. No other devices affected.",
        )

        return stream


if __name__ == "__main__":
    # Demo usage
    import asyncio
    logging.basicConfig(level=logging.DEBUG)

    async def main():
        engine = WhisperEngine()

        # Subscribe to updates
        async def on_whisper(stream: WhisperStream, message: WhisperMessage):
            print(message.formatted())

        engine.subscribe(on_whisper)

        print("=" * 60)
        print("WHISPER MODE DEMO")
        print("=" * 60)

        # Run investigation
        print("\n--- Investigating unusual traffic ---")
        stream = await InvestigationTemplates.investigate_unusual_traffic(
            engine=engine,
            device_mac="00:1E:C2:12:34:56",
            device_label="Smart Printer",
            traffic_type="HTTPS",
            destination="hp.com",
        )

        print(f"\n--- Investigation complete ---")
        print(f"Summary: {stream.get_summary()}")
        print(f"Duration: {stream.duration_seconds:.1f}s")

        # Show another investigation
        print("\n--- Investigating blocked threat ---")
        stream = await InvestigationTemplates.investigate_blocked_threat(
            engine=engine,
            device_mac="00:1E:C2:12:34:57",
            device_label="IoT Camera",
            threat_type="Malware C2",
            source="185.128.40.22",
        )

        print(f"\n--- Investigation complete ---")
        print(f"Summary: {stream.get_summary()}")

        # Show status
        print("\n--- Engine Status ---")
        status = engine.get_status()
        print(f"Active: {status['active_count']}")
        print(f"Completed: {status['completed_count']}")
        for summary in status['recent_completed']:
            print(f"  {summary}")

    asyncio.run(main())
