"""
NAPSE Event Bus - Central Event Distribution

Receives typed events from the Rust protocol engine via PyO3 callbacks
and distributes them to all registered HookProbe consumers.

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class EventType(Enum):
    """NAPSE event types corresponding to protocol parser outputs."""
    CONNECTION = auto()      # TCP/UDP connection record (replaces Zeek conn.log)
    DNS = auto()             # DNS query/response (replaces Zeek dns.log)
    HTTP = auto()            # HTTP request/response (replaces Zeek http.log)
    TLS = auto()             # TLS handshake (replaces Zeek ssl.log)
    DHCP = auto()            # DHCP lease event (replaces Zeek dhcp.log)
    SSH = auto()             # SSH session (replaces Zeek ssh.log)
    MDNS = auto()            # mDNS service discovery
    SSDP = auto()            # SSDP/UPnP discovery
    SMTP = auto()            # SMTP session
    SMB = auto()             # SMB file share
    MQTT = auto()            # MQTT pub/sub
    MODBUS = auto()          # Modbus ICS
    DNP3 = auto()            # DNP3 SCADA
    QUIC = auto()            # QUIC connection
    RDP = auto()             # RDP session
    FTP = auto()             # FTP session
    ALERT = auto()           # NAPSE alert (replaces Suricata EVE alert)
    NOTICE = auto()          # NAPSE notice (replaces Zeek Notice)
    FILE = auto()            # File extraction event
    FLOW_METADATA = auto()   # Lightweight flow metadata from eBPF ringbuf
    HONEYPOT_TOUCH = auto()  # Honeypot dark port interaction (from Mirage)
    INTENT_DETECTED = auto()   # SIA intent phase detected for an entity
    ENTITY_SANDBOXED = auto()  # Entity redirected to virtual sandbox
    PROCESS_EXEC = auto()      # Process execution event from eBPF tracer
    PROCESS_SUSPICIOUS = auto()  # Suspicious process detected by healing engine


@dataclass
class ConnectionRecord:
    """Connection record compatible with Zeek conn.log fields."""
    ts: float                          # Unix timestamp
    uid: str                           # Connection UID
    id_orig_h: str                     # Source IP
    id_orig_p: int                     # Source port
    id_resp_h: str                     # Destination IP
    id_resp_p: int                     # Destination port
    proto: str                         # tcp/udp/icmp
    service: str = ""                  # Detected protocol
    duration: float = 0.0              # Connection duration
    orig_bytes: int = 0                # Bytes from originator
    resp_bytes: int = 0                # Bytes from responder
    conn_state: str = ""               # S0/S1/SF/REJ/etc
    orig_pkts: int = 0                 # Packets from originator
    resp_pkts: int = 0                 # Packets from responder
    community_id: str = ""             # Community-ID v1 hash


@dataclass
class DNSRecord:
    """DNS record compatible with Zeek dns.log fields."""
    ts: float
    uid: str
    id_orig_h: str
    id_orig_p: int
    id_resp_h: str
    id_resp_p: int
    proto: str = "udp"
    query: str = ""
    qclass: int = 1
    qclass_name: str = "C_INTERNET"
    qtype: int = 1
    qtype_name: str = "A"
    rcode: int = 0
    rcode_name: str = "NOERROR"
    AA: bool = False
    answers: List[str] = field(default_factory=list)
    TTLs: List[float] = field(default_factory=list)
    rejected: bool = False
    # NAPSE extension
    is_mdns: bool = False
    ecosystem: str = ""                # apple/google/samsung/amazon


@dataclass
class HTTPRecord:
    """HTTP record compatible with Zeek http.log fields."""
    ts: float
    uid: str
    id_orig_h: str
    id_orig_p: int
    id_resp_h: str
    id_resp_p: int
    method: str = ""
    host: str = ""
    uri: str = ""
    referrer: str = ""
    user_agent: str = ""
    status_code: int = 0
    status_msg: str = ""
    content_type: str = ""
    request_body_len: int = 0
    response_body_len: int = 0


@dataclass
class TLSRecord:
    """TLS record compatible with Zeek ssl.log fields."""
    ts: float
    uid: str
    id_orig_h: str
    id_orig_p: int
    id_resp_h: str
    id_resp_p: int
    version: str = ""
    server_name: str = ""              # SNI
    subject: str = ""
    issuer: str = ""
    validation_status: str = ""
    ja3: str = ""                      # JA3 client hash
    ja3s: str = ""                     # JA3S server hash
    # NAPSE extensions
    ja3_string: str = ""
    is_malicious_ja3: bool = False
    malware_family: str = ""


@dataclass
class DHCPRecord:
    """DHCP record compatible with Zeek dhcp.log fields."""
    ts: float
    uid: str = ""
    client_addr: str = ""
    server_addr: str = ""
    mac: str = ""
    hostname: str = ""
    msg_type: str = ""                 # DISCOVER/OFFER/REQUEST/ACK
    # NAPSE extension: device fingerprinting
    option55: List[int] = field(default_factory=list)
    vendor_class: str = ""


@dataclass
class SSHRecord:
    """SSH session record."""
    ts: float
    uid: str
    id_orig_h: str
    id_orig_p: int
    id_resp_h: str
    id_resp_p: int
    version: int = 0
    client: str = ""
    server: str = ""
    auth_attempts: int = 0
    auth_success: bool = False


@dataclass
class MDNSRecord:
    """mDNS service discovery record for D2D bubble system."""
    ts: float
    source_mac: str
    source_ip: str
    query: str = ""
    query_type: str = ""
    is_response: bool = False
    answers: List[str] = field(default_factory=list)
    service_type: str = ""
    ecosystem: str = ""                # apple/google/samsung/amazon


@dataclass
class NapseAlert:
    """NAPSE alert compatible with Suricata EVE alert format."""
    timestamp: str                     # ISO8601
    src_ip: str = ""
    src_port: int = 0
    dest_ip: str = ""
    dest_port: int = 0
    proto: str = ""
    alert_action: str = "alert"
    alert_gid: int = 1
    alert_signature_id: int = 0
    alert_signature: str = ""
    alert_category: str = ""
    alert_severity: int = 3
    community_id: str = ""
    # NAPSE extensions
    confidence: float = 0.0
    layer: int = 7
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NapseNotice:
    """NAPSE notice compatible with Zeek Notice framework."""
    ts: float
    note: str                          # New_Device, Suspicious_DNS, etc.
    msg: str = ""
    src: str = ""
    dst: str = ""
    p: int = 0
    sub: str = ""
    actions: List[str] = field(default_factory=list)


# Type alias for event handler callbacks
EventHandler = Callable[[EventType, Any], None]


class NapseEventBus:
    """
    Central event distribution for NAPSE.

    Receives events from the Rust protocol engine and distributes
    them to registered handlers (log emitter, QSecBit feed, AEGIS
    bridge, D2D bubble feed, ClickHouse shipper, etc.).
    """

    def __init__(self, max_queue_size: int = 10000):
        self._handlers: Dict[EventType, List[EventHandler]] = {
            et: [] for et in EventType
        }
        self._global_handlers: List[EventHandler] = []
        self._queue: deque = deque(maxlen=max_queue_size)
        self._stats: Dict[str, int] = {
            'events_received': 0,
            'events_dispatched': 0,
            'events_dropped': 0,
        }
        self._running = False
        logger.info("NAPSE EventBus initialized (queue_size=%d)", max_queue_size)

    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Register a handler for a specific event type."""
        self._handlers[event_type].append(handler)
        logger.debug("Handler registered for %s", event_type.name)

    def subscribe_all(self, handler: EventHandler) -> None:
        """Register a handler for all event types."""
        self._global_handlers.append(handler)

    def emit(self, event_type: EventType, event: Any) -> None:
        """Emit an event to all registered handlers."""
        self._stats['events_received'] += 1

        # Dispatch to type-specific handlers
        for handler in self._handlers.get(event_type, []):
            try:
                handler(event_type, event)
                self._stats['events_dispatched'] += 1
            except Exception as e:
                logger.error("Handler error for %s: %s", event_type.name, e)

        # Dispatch to global handlers
        for handler in self._global_handlers:
            try:
                handler(event_type, event)
                self._stats['events_dispatched'] += 1
            except Exception as e:
                logger.error("Global handler error for %s: %s", event_type.name, e)

    # Convenience methods called by Rust engine via PyO3
    def on_connection(self, record: ConnectionRecord) -> None:
        """Called by Rust engine for each completed connection."""
        self.emit(EventType.CONNECTION, record)

    def on_dns(self, record: DNSRecord) -> None:
        """Called by Rust engine for each DNS transaction."""
        self.emit(EventType.DNS, record)

    def on_http(self, record: HTTPRecord) -> None:
        """Called by Rust engine for each HTTP transaction."""
        self.emit(EventType.HTTP, record)

    def on_tls(self, record: TLSRecord) -> None:
        """Called by Rust engine for each TLS handshake."""
        self.emit(EventType.TLS, record)

    def on_dhcp(self, record: DHCPRecord) -> None:
        """Called by Rust engine for each DHCP transaction."""
        self.emit(EventType.DHCP, record)

    def on_ssh(self, record: SSHRecord) -> None:
        """Called by Rust engine for each SSH session."""
        self.emit(EventType.SSH, record)

    def on_mdns(self, record: MDNSRecord) -> None:
        """Called by Rust engine for each mDNS event."""
        self.emit(EventType.MDNS, record)

    def on_alert(self, alert: NapseAlert) -> None:
        """Called by Rust engine for signature/ML match alerts."""
        self.emit(EventType.ALERT, alert)

    def on_notice(self, notice: NapseNotice) -> None:
        """Called by Rust engine for notice events."""
        self.emit(EventType.NOTICE, notice)

    def on_flow_metadata(self, metadata: Dict[str, Any]) -> None:
        """Called for lightweight flow metadata from eBPF ringbuf."""
        self.emit(EventType.FLOW_METADATA, metadata)

    def get_stats(self) -> Dict[str, Any]:
        """Get event bus statistics."""
        return {
            **self._stats,
            'handler_counts': {
                et.name: len(handlers)
                for et, handlers in self._handlers.items()
                if handlers
            },
            'global_handlers': len(self._global_handlers),
        }
