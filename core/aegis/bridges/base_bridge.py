"""
AEGIS Base Bridge — Abstract base class for signal bridges.

Each bridge watches a data source (file, API, socket) and emits
StandardSignal events to the orchestrator.
"""

import logging
import threading
import time
from abc import ABC, abstractmethod
from typing import Callable, List, Optional

from ..types import StandardSignal

logger = logging.getLogger(__name__)


class BaseBridge(ABC):
    """Abstract base class for signal bridges.

    Each bridge:
    - Watches a specific data source
    - Normalizes events to StandardSignal
    - Publishes signals to registered callbacks
    - Runs in a daemon thread
    """

    name: str = "base"
    poll_interval: float = 5.0  # seconds between polls

    def __init__(self):
        self._callbacks: List[Callable[[StandardSignal], None]] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def on_signal(self, callback: Callable[[StandardSignal], None]) -> None:
        """Register a callback for signals from this bridge."""
        self._callbacks.append(callback)

    def publish(self, signal: StandardSignal) -> None:
        """Publish a signal to all registered callbacks."""
        for cb in self._callbacks:
            try:
                cb(signal)
            except Exception as e:
                logger.error("Bridge %s callback error: %s", self.name, e)

    def start(self) -> None:
        """Start the bridge in a daemon thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop,
            name=f"aegis-bridge-{self.name}",
            daemon=True,
        )
        self._thread.start()
        logger.info("Bridge started: %s (poll=%ss)", self.name, self.poll_interval)

    def stop(self) -> None:
        """Stop the bridge."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=self.poll_interval * 2)
        logger.info("Bridge stopped: %s", self.name)

    @property
    def is_running(self) -> bool:
        return self._running

    @abstractmethod
    def poll(self) -> List[StandardSignal]:
        """Poll the data source and return new signals.

        Called periodically by the run loop. Return an empty list
        if no new signals are available.
        """
        ...

    def _run_loop(self) -> None:
        """Main polling loop."""
        while self._running:
            try:
                signals = self.poll()
                for signal in signals:
                    self.publish(signal)
            except Exception as e:
                logger.error("Bridge %s poll error: %s", self.name, e)

            time.sleep(self.poll_interval)
