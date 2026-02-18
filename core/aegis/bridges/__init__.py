"""
AEGIS Bridge Manager

Manages all signal bridges — starts, stops, and wires them
to the orchestrator for event processing.
"""

import logging
from typing import Callable, Dict, List, Optional

from .base_bridge import BaseBridge
from .qsecbit_bridge import QsecbitBridge
from .dnsxai_bridge import DnsxaiBridge
from .dhcp_bridge import DhcpBridge
from .wan_bridge import WanBridge
from .napse_bridge import NAPSEBridge
from ..types import StandardSignal

logger = logging.getLogger(__name__)


class BridgeManager:
    """Manages all signal bridges.

    Creates, configures, starts, and stops all bridges.
    Wires bridge signals to a callback (typically the orchestrator).
    """

    def __init__(self, signal_callback: Optional[Callable[[StandardSignal], None]] = None):
        self._bridges: Dict[str, BaseBridge] = {}
        self._callback = signal_callback
        self._create_default_bridges()

    def _create_default_bridges(self) -> None:
        """Create all built-in bridges with default config."""
        self._bridges["qsecbit"] = QsecbitBridge()
        self._bridges["dnsxai"] = DnsxaiBridge()
        self._bridges["dhcp"] = DhcpBridge()
        self._bridges["wan"] = WanBridge()
        self._bridges["napse"] = NAPSEBridge()

    def configure(
        self,
        qsecbit_path: str = "",
        dnsxai_url: str = "",
        dhcp_lease_file: str = "",
        slaai_path: str = "",
        napse_eve_path: str = "",
    ) -> None:
        """Reconfigure bridges with custom paths/URLs."""
        if qsecbit_path:
            self._bridges["qsecbit"] = QsecbitBridge(qsecbit_path)
        if dnsxai_url:
            self._bridges["dnsxai"] = DnsxaiBridge(dnsxai_url)
        if dhcp_lease_file:
            self._bridges["dhcp"] = DhcpBridge(dhcp_lease_file)
        if slaai_path:
            self._bridges["wan"] = WanBridge(slaai_path)
        if napse_eve_path:
            self._bridges["napse"] = NAPSEBridge(napse_eve_path)

    def set_callback(self, callback: Callable[[StandardSignal], None]) -> None:
        """Set the signal callback (usually orchestrator.process_signal)."""
        self._callback = callback
        # Re-wire all bridges
        for bridge in self._bridges.values():
            bridge.on_signal(callback)

    def start_all(self) -> None:
        """Start all bridges."""
        if self._callback:
            for bridge in self._bridges.values():
                bridge.on_signal(self._callback)

        for name, bridge in self._bridges.items():
            try:
                bridge.start()
            except Exception as e:
                logger.error("Failed to start bridge %s: %s", name, e)

    def stop_all(self) -> None:
        """Stop all bridges."""
        for name, bridge in self._bridges.items():
            try:
                bridge.stop()
            except Exception as e:
                logger.error("Failed to stop bridge %s: %s", name, e)

    def get_bridge(self, name: str) -> Optional[BaseBridge]:
        """Get a bridge by name."""
        return self._bridges.get(name)

    def list_bridges(self) -> List[str]:
        """List all bridge names."""
        return list(self._bridges.keys())

    def get_status(self) -> Dict[str, bool]:
        """Get running status of all bridges."""
        return {name: bridge.is_running for name, bridge in self._bridges.items()}


__all__ = [
    "BridgeManager",
    "BaseBridge",
    "QsecbitBridge",
    "DnsxaiBridge",
    "DhcpBridge",
    "WanBridge",
    "NAPSEBridge",
]
