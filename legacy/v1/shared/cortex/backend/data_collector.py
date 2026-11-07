#!/usr/bin/env python3
"""
HookProbe Data Collectors — Live Data Sources for Cortex Globe

Three collectors feed real-time data into the Cortex Neural Command Center:
- HTPCollector: Mesh gossip events via unified_transport callback
- NeuroCollector: TER weight evolution events from neuro engine
- QsecbitCollector: RAG status from QSecBit stats file polling
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Callable, Optional, Dict, Any, List

logger = logging.getLogger(__name__)

# Default polling intervals
HTP_POLL_INTERVAL = 2.0  # seconds
NEURO_POLL_INTERVAL = 5.0
QSECBIT_POLL_INTERVAL = 5.0

# Default QSecBit stats file path
QSECBIT_STATS_PATH = os.environ.get(
    "QSECBIT_STATS_FILE",
    "/opt/hookprobe/data/qsecbit_stats.json",
)


class HTPCollector:
    """
    Collects threat events from HTP mesh network.

    Subscribes to the gossip protocol via unified_transport callback.
    Falls back to polling mesh state file if transport is unavailable.
    """

    def __init__(self, on_event: Callable[[Dict[str, Any]], None]):
        self.on_event = on_event
        self.running = False
        self._task: Optional[asyncio.Task] = None
        self._transport = None
        self._last_events: List[str] = []

    async def start(self) -> None:
        """Start collecting HTP events."""
        self.running = True

        # Try to subscribe to live mesh transport
        self._transport = self._try_connect_transport()
        if self._transport:
            logger.info("HTP Collector started (live transport mode)")
        else:
            logger.info("HTP Collector started (file polling mode)")

        while self.running:
            try:
                events = self._read_events()
                for event in events:
                    self._handle_htp_event(event)
            except Exception as e:
                logger.warning("HTP Collector error: %s", e)
            await asyncio.sleep(HTP_POLL_INTERVAL)

    async def stop(self) -> None:
        """Stop collecting."""
        self.running = False
        if self._task:
            self._task.cancel()

    def _try_connect_transport(self):
        """Try to get a reference to the mesh transport."""
        try:
            from shared.mesh.unified_transport import get_transport
            transport = get_transport()
            if transport:
                transport.on_gossip(self._on_gossip_message)
            return transport
        except (ImportError, Exception) as e:
            logger.debug("Mesh transport not available: %s", e)
            return None

    def _on_gossip_message(self, message: Dict[str, Any]) -> None:
        """Callback for live gossip messages."""
        self._handle_htp_event(message)

    def _read_events(self) -> List[Dict[str, Any]]:
        """Read events from mesh state file (polling fallback)."""
        state_file = os.environ.get(
            "MESH_STATE_FILE",
            "/opt/hookprobe/data/mesh_events.json",
        )
        try:
            with open(state_file) as f:
                data = json.load(f)
            events = data.get("events", [])
            # Deduplicate against last seen
            new_events = []
            for ev in events:
                ev_id = ev.get("id", str(ev))
                if ev_id not in self._last_events:
                    new_events.append(ev)
            self._last_events = [ev.get("id", str(ev)) for ev in events][-100:]
            return new_events
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _handle_htp_event(self, event: Dict[str, Any]) -> None:
        """Process incoming HTP event into globe visualization format."""
        globe_event = {
            "type": event.get("type", "attack_detected"),
            "source": {
                "lat": event.get("source_lat", 0),
                "lng": event.get("source_lng", 0),
                "label": event.get("source_label", "Unknown"),
            },
            "target": {
                "lat": event.get("target_lat", 0),
                "lng": event.get("target_lng", 0),
                "label": event.get("target_label", "Unknown"),
                "node_id": event.get("node_id", ""),
            },
            "severity": event.get("severity", "MEDIUM"),
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.on_event(globe_event)


class NeuroCollector:
    """
    Collects neural weight evolution events from Neuro protocol.

    Reads TER events from the neuro engine's dreamlog or event file.
    Falls back to polling the TER state file.
    """

    def __init__(self, on_event: Callable[[Dict[str, Any]], None]):
        self.on_event = on_event
        self.running = False
        self._last_sequence = 0

    async def start(self) -> None:
        """Start collecting Neuro events."""
        self.running = True
        logger.info("Neuro Collector started")

        while self.running:
            try:
                events = self._read_ter_events()
                for event in events:
                    self._handle_weight_event(event)
            except Exception as e:
                logger.warning("Neuro Collector error: %s", e)
            await asyncio.sleep(NEURO_POLL_INTERVAL)

    async def stop(self) -> None:
        """Stop collecting."""
        self.running = False

    def _read_ter_events(self) -> List[Dict[str, Any]]:
        """Read TER events from dreamlog or state file."""
        ter_file = os.environ.get(
            "NEURO_TER_FILE",
            "/opt/hookprobe/data/neuro_ter_state.json",
        )
        try:
            with open(ter_file) as f:
                data = json.load(f)
            events = data.get("events", [])
            # Only return events newer than last seen sequence
            new_events = [
                ev for ev in events
                if ev.get("sequence", 0) > self._last_sequence
            ]
            if new_events:
                self._last_sequence = max(
                    ev.get("sequence", 0) for ev in new_events
                )
            return new_events
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _handle_weight_event(self, event: Dict[str, Any]) -> None:
        """Process neural weight evolution event into globe format."""
        # Map resonance state to node status
        resonance = event.get("resonance", 0.0)
        if resonance > 0.8:
            status = "synchronized"
        elif resonance > 0.5:
            status = "aligned"
        else:
            status = "drifting"

        globe_event = {
            "type": "neuro_sync",
            "node_id": event.get("node_id", ""),
            "resonance_score": resonance,
            "weight_drift": event.get("drift", 0.0),
            "status": status,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.on_event(globe_event)


class QsecbitCollector:
    """
    Collects Qsecbit score updates from the local QSecBit stats file.

    Polls the stats JSON file (written by qsecbit-agent) and emits
    node status updates with RAG color changes.
    """

    def __init__(self, on_event: Callable[[Dict[str, Any]], None]):
        self.on_event = on_event
        self.running = False
        self._last_score: Optional[float] = None
        self._last_status: Optional[str] = None

    async def start(self) -> None:
        """Start collecting Qsecbit updates."""
        self.running = True
        logger.info("Qsecbit Collector started (polling %s)", QSECBIT_STATS_PATH)

        while self.running:
            try:
                update = self._read_qsecbit_stats()
                if update:
                    self._handle_score_update(update)
            except Exception as e:
                logger.warning("Qsecbit Collector error: %s", e)
            await asyncio.sleep(QSECBIT_POLL_INTERVAL)

    async def stop(self) -> None:
        """Stop collecting."""
        self.running = False

    def _read_qsecbit_stats(self) -> Optional[Dict[str, Any]]:
        """Read QSecBit stats from file."""
        try:
            with open(QSECBIT_STATS_PATH) as f:
                data = json.load(f)
            score = data.get("score", data.get("qsecbit_score", 0.0))
            status = data.get("status", data.get("rag_status", "unknown"))
            # Only emit if score or status changed
            if score != self._last_score or status != self._last_status:
                self._last_score = score
                self._last_status = status
                return {
                    "node_id": data.get("node_id", os.environ.get("HOSTNAME", "local")),
                    "score": score,
                    "status": status.lower() if isinstance(status, str) else "unknown",
                    "layers": data.get("layers", {}),
                }
            return None
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def _handle_score_update(self, update: Dict[str, Any]) -> None:
        """Process Qsecbit score update into globe format."""
        # Map RAG status to color
        status = update.get("status", "unknown")
        color_map = {"green": "#00ff00", "amber": "#ffaa00", "red": "#ff0000"}

        globe_event = {
            "type": "qsecbit_update",
            "node_id": update["node_id"],
            "score": update["score"],
            "status": status,
            "color": color_map.get(status, "#888888"),
            "layers": update.get("layers", {}),
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.on_event(globe_event)
