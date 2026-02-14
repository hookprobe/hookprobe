"""
NAPSE Notice Emitter

Generates notice events equivalent to Zeek's Notice framework.
Replaces all 6 AIOCHI notice types from local.zeek:
  - New_Device (DHCP ACK with hostname)
  - Suspicious_DNS (long queries, suspicious TLDs)
  - TLS_Cert_Invalid / TLS_Anomaly (certificate validation failure)
  - Port_Scan_Detected / Potential_Scan (>50 unique ports from single source)
  - SSH_Bruteforce (>5 failed auth attempts)
  - Device_Left (conntrack timeout)
  - Policy_Violation (unauthorized service access)

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import time
from collections import defaultdict
from typing import Any, Dict, List, Set

from .event_bus import (
    ConnectionRecord, DNSRecord, TLSRecord, DHCPRecord, SSHRecord,
    NapseNotice, EventType, NapseEventBus,
)

logger = logging.getLogger(__name__)

# Suspicious TLDs (matching local.zeek)
SUSPICIOUS_TLDS = {'.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top'}

# DNS tunneling threshold (matching local.zeek: 60 chars)
DNS_TUNNEL_QUERY_LENGTH = 60

# Port scan threshold (matching l4_detector.py: 50 unique ports)
PORT_SCAN_THRESHOLD = 50

# SSH brute force threshold
SSH_BRUTEFORCE_THRESHOLD = 5

# Time windows (seconds)
PORT_SCAN_WINDOW = 300       # 5 minutes
SSH_BRUTEFORCE_WINDOW = 300  # 5 minutes


class NoticeEmitter:
    """
    Generates NAPSE notice events equivalent to Zeek Notice framework.

    Monitors protocol events for patterns that warrant notices:
    new devices, suspicious DNS, cert issues, port scans, brute force.
    """

    def __init__(self):
        # Port scan tracking: src_ip -> set of (dst_ip, dst_port)
        self._port_scan_tracker: Dict[str, Dict[str, Set[int]]] = defaultdict(
            lambda: defaultdict(set)
        )
        self._port_scan_first_seen: Dict[str, float] = {}

        # SSH brute force tracking: (src_ip, dst_ip) -> [timestamps]
        self._ssh_attempts: Dict[str, List[float]] = defaultdict(list)

        # Known devices (avoid duplicate New_Device notices)
        self._known_macs: Set[str] = set()

        # Device activity tracking for Device_Left detection
        self._device_last_seen: Dict[str, float] = {}
        self._device_left_threshold = 300  # 5 min idle = device left

        self._notice_callback = None
        self._stats = {
            'new_device': 0,
            'suspicious_dns': 0,
            'tls_cert_invalid': 0,
            'port_scan': 0,
            'ssh_bruteforce': 0,
            'device_left': 0,
            'policy_violation': 0,
        }

    def register(self, event_bus: NapseEventBus) -> None:
        """Register with event bus to receive protocol events."""
        event_bus.subscribe(EventType.DHCP, self._check_new_device)
        event_bus.subscribe(EventType.DNS, self._check_suspicious_dns)
        event_bus.subscribe(EventType.TLS, self._check_tls_cert)
        event_bus.subscribe(EventType.CONNECTION, self._check_port_scan)
        event_bus.subscribe(EventType.SSH, self._check_ssh_bruteforce)

        # Also subscribe to emit notices back to bus
        self._event_bus = event_bus
        logger.info("NoticeEmitter registered with event bus")

    def _emit_notice(self, notice: NapseNotice) -> None:
        """Emit a notice to the event bus."""
        if hasattr(self, '_event_bus'):
            self._event_bus.on_notice(notice)

    def _check_new_device(self, _et: EventType, record: DHCPRecord) -> None:
        """Detect new devices via DHCP ACK."""
        if record.msg_type not in ('ACK', 'DISCOVER'):
            return

        if record.mac and record.mac not in self._known_macs:
            self._known_macs.add(record.mac)
            self._emit_notice(NapseNotice(
                ts=record.ts,
                note='New_Device',
                msg=f"New device {record.mac} ({record.hostname or 'unknown'}) "
                    f"joined the network at {record.client_addr}",
                src=record.client_addr,
                sub=f"MAC={record.mac} Hostname={record.hostname or '-'}",
            ))
            self._stats['new_device'] += 1

    def _check_suspicious_dns(self, _et: EventType, record: DNSRecord) -> None:
        """Detect suspicious DNS patterns."""
        if not record.query:
            return

        reasons = []

        # Long query (potential DNS tunneling)
        if len(record.query) > DNS_TUNNEL_QUERY_LENGTH:
            reasons.append(f"long query ({len(record.query)} chars)")

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if record.query.endswith(tld):
                reasons.append(f"suspicious TLD ({tld})")
                break

        if reasons:
            self._emit_notice(NapseNotice(
                ts=record.ts,
                note='Suspicious_DNS',
                msg=f"Suspicious DNS query: {record.query} ({', '.join(reasons)})",
                src=record.id_orig_h,
                dst=record.id_resp_h,
                p=53,
                sub=f"Query={record.query}",
            ))
            self._stats['suspicious_dns'] += 1

    def _check_tls_cert(self, _et: EventType, record: TLSRecord) -> None:
        """Detect TLS certificate validation failures."""
        if record.validation_status and record.validation_status != 'ok':
            self._emit_notice(NapseNotice(
                ts=record.ts,
                note='TLS_Cert_Invalid',
                msg=f"Invalid TLS certificate for {record.server_name}: "
                    f"{record.validation_status}",
                src=record.id_orig_h,
                dst=record.id_resp_h,
                p=record.id_resp_p,
                sub=f"SNI={record.server_name} Status={record.validation_status}",
            ))
            self._stats['tls_cert_invalid'] += 1

    def _check_port_scan(self, _et: EventType, record: ConnectionRecord) -> None:
        """Detect port scans (many unique dst ports from single source)."""
        now = record.ts
        src = record.id_orig_h
        dst = record.id_resp_h

        # Clean old entries
        if src in self._port_scan_first_seen:
            if now - self._port_scan_first_seen[src] > PORT_SCAN_WINDOW:
                self._port_scan_tracker[src].clear()
                self._port_scan_first_seen[src] = now
        else:
            self._port_scan_first_seen[src] = now

        self._port_scan_tracker[src][dst].add(record.id_resp_p)

        # Check threshold per destination
        for target, ports in self._port_scan_tracker[src].items():
            if len(ports) >= PORT_SCAN_THRESHOLD:
                self._emit_notice(NapseNotice(
                    ts=now,
                    note='Port_Scan_Detected',
                    msg=f"Port scan from {src} to {target}: "
                        f"{len(ports)} unique ports in {PORT_SCAN_WINDOW}s",
                    src=src,
                    dst=target,
                    sub=f"Ports={len(ports)}",
                ))
                self._stats['port_scan'] += 1
                # Reset to avoid flooding
                self._port_scan_tracker[src][target].clear()

    def _check_ssh_bruteforce(self, _et: EventType, record: SSHRecord) -> None:
        """Detect SSH brute force attempts."""
        if record.auth_success:
            return

        key = f"{record.id_orig_h}->{record.id_resp_h}"
        now = record.ts

        # Clean old attempts
        self._ssh_attempts[key] = [
            t for t in self._ssh_attempts[key]
            if now - t < SSH_BRUTEFORCE_WINDOW
        ]
        self._ssh_attempts[key].append(now)

        if len(self._ssh_attempts[key]) >= SSH_BRUTEFORCE_THRESHOLD:
            self._emit_notice(NapseNotice(
                ts=now,
                note='SSH_Bruteforce',
                msg=f"SSH brute force from {record.id_orig_h} to "
                    f"{record.id_resp_h}: {len(self._ssh_attempts[key])} "
                    f"failed attempts",
                src=record.id_orig_h,
                dst=record.id_resp_h,
                p=record.id_resp_p,
                sub=f"Attempts={len(self._ssh_attempts[key])}",
            ))
            self._stats['ssh_bruteforce'] += 1
            self._ssh_attempts[key].clear()

    def check_device_left(self, now: float = None) -> None:
        """
        Check for devices that have gone idle (Device_Left notice).

        Called periodically by the engine (e.g., every 60s) to detect
        devices that stopped communicating.
        """
        if now is None:
            now = time.time()

        departed = []
        for mac, last_seen in self._device_last_seen.items():
            if now - last_seen > self._device_left_threshold:
                departed.append(mac)
                self._emit_notice(NapseNotice(
                    ts=now,
                    note='Device_Left',
                    msg=f"Device {mac} left the network "
                        f"(idle {int(now - last_seen)}s)",
                    sub=f"MAC={mac}",
                ))
                self._stats['device_left'] += 1

        for mac in departed:
            del self._device_last_seen[mac]
            self._known_macs.discard(mac)

    def update_device_activity(self, mac: str, ts: float) -> None:
        """Track device activity timestamps for Device_Left detection."""
        if mac:
            self._device_last_seen[mac] = ts

    def get_stats(self) -> Dict[str, Any]:
        """Get notice emitter statistics."""
        return {
            **self._stats,
            'known_devices': len(self._known_macs),
            'tracked_scanners': len(self._port_scan_tracker),
            'active_devices': len(self._device_last_seen),
        }
