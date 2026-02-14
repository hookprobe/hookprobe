"""
NAPSE D2D Bubble Feed

Replaces the Zeek dependency in the D2D bubble system by feeding
connection records and mDNS events directly from NAPSE to the
bubble system components:

  - ConnectionGraphAnalyzer (replaces conn.log parsing)
  - ZeekMDNSParser equivalent (replaces dns.log mDNS parsing)
  - DHCP Sentinel (replaces dhcp.log)

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
from typing import Any, Callable, Dict, List, Optional

from .event_bus import (
    ConnectionRecord, DNSRecord, MDNSRecord, DHCPRecord,
    EventType, NapseEventBus,
)

logger = logging.getLogger(__name__)


class BubbleFeed:
    """
    Feeds NAPSE events to the D2D bubble ecosystem.

    Replaces Zeek log file parsing with direct event delivery
    for real-time device relationship detection.
    """

    def __init__(
        self,
        connection_callback: Optional[Callable] = None,
        mdns_callback: Optional[Callable] = None,
        dhcp_callback: Optional[Callable] = None,
    ):
        """
        Args:
            connection_callback: Called with ConnectionRecord for D2D analysis.
                                Replaces ConnectionGraphAnalyzer.parse_conn_log()
            mdns_callback: Called with MDNSRecord for ecosystem detection.
                          Replaces ZeekMDNSParser.parse_line()
            dhcp_callback: Called with DHCPRecord for device discovery.
                          Replaces DHCP Sentinel file watcher.
        """
        self._connection_cb = connection_callback
        self._mdns_cb = mdns_callback
        self._dhcp_cb = dhcp_callback

        self._stats = {
            'connections_fed': 0,
            'mdns_fed': 0,
            'dhcp_fed': 0,
            'd2d_pairs_detected': 0,
        }

    def register(self, event_bus: NapseEventBus) -> None:
        """Register this feed with the NAPSE event bus."""
        event_bus.subscribe(EventType.CONNECTION, self._handle_connection)
        event_bus.subscribe(EventType.MDNS, self._handle_mdns)
        event_bus.subscribe(EventType.DNS, self._handle_dns)
        event_bus.subscribe(EventType.DHCP, self._handle_dhcp)
        logger.info("BubbleFeed registered with event bus")

    def _handle_connection(self, _event_type: EventType, record: ConnectionRecord) -> None:
        """Feed connection record to D2D graph analyzer."""
        if self._connection_cb:
            try:
                self._connection_cb(record)
                self._stats['connections_fed'] += 1
            except Exception as e:
                logger.error("Connection callback error: %s", e)

    def _handle_mdns(self, _event_type: EventType, record: MDNSRecord) -> None:
        """Feed mDNS record to ecosystem detector."""
        if self._mdns_cb:
            try:
                self._mdns_cb(record)
                self._stats['mdns_fed'] += 1
            except Exception as e:
                logger.error("mDNS callback error: %s", e)

    def _handle_dns(self, _event_type: EventType, record: DNSRecord) -> None:
        """Check if DNS record is mDNS and feed to ecosystem detector."""
        if record.is_mdns and self._mdns_cb:
            # Convert to MDNSRecord for the callback
            mdns = MDNSRecord(
                ts=record.ts,
                source_mac="",  # Not available in DNS record
                source_ip=record.id_orig_h,
                query=record.query,
                query_type=record.qtype_name,
                is_response=bool(record.answers),
                answers=record.answers,
                ecosystem=record.ecosystem,
            )
            try:
                self._mdns_cb(mdns)
                self._stats['mdns_fed'] += 1
            except Exception as e:
                logger.error("mDNS (from DNS) callback error: %s", e)

    def _handle_dhcp(self, _event_type: EventType, record: DHCPRecord) -> None:
        """Feed DHCP record to device discovery."""
        if self._dhcp_cb:
            try:
                self._dhcp_cb(record)
                self._stats['dhcp_fed'] += 1
            except Exception as e:
                logger.error("DHCP callback error: %s", e)

    def get_stats(self) -> Dict[str, Any]:
        """Get feed statistics."""
        return dict(self._stats)
