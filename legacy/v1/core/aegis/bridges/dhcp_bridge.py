"""
DHCP Signal Bridge

Watches dnsmasq lease file for new device connections.
Emits device.new signals when unknown MACs appear.
"""

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import List, Set

from .base_bridge import BaseBridge
from ..types import StandardSignal

logger = logging.getLogger(__name__)


class DhcpBridge(BaseBridge):
    """Bridge for DHCP lease events (new device detection)."""

    name = "dhcp"
    poll_interval = 5.0

    def __init__(self, lease_file: str = "/var/lib/misc/dnsmasq.leases"):
        super().__init__()
        self._lease_file = Path(lease_file)
        self._known_macs: Set[str] = set()
        self._last_mtime: float = 0
        self._initialized = False

    def poll(self) -> List[StandardSignal]:
        """Poll DHCP lease file for new devices."""
        signals = []

        if not self._lease_file.exists():
            return signals

        try:
            mtime = self._lease_file.stat().st_mtime
            if mtime <= self._last_mtime:
                return signals
            self._last_mtime = mtime

            current_macs = set()
            lines = self._lease_file.read_text().strip().split("\n")

            for line in lines:
                parts = line.split()
                if len(parts) >= 4:
                    # dnsmasq format: timestamp mac ip hostname clientid
                    mac = parts[1].upper()
                    ip = parts[2]
                    hostname = parts[3] if parts[3] != "*" else ""
                    current_macs.add(mac)

                    # Signal new devices (skip first poll to build baseline)
                    if self._initialized and mac not in self._known_macs:
                        signals.append(StandardSignal(
                            source="dhcp",
                            event_type="device.new",
                            severity="INFO",
                            data={
                                "mac": mac,
                                "ip": ip,
                                "hostname": hostname,
                            },
                        ))

            self._known_macs = current_macs
            self._initialized = True

        except Exception as e:
            logger.debug("DHCP bridge poll error: %s", e)

        return signals
