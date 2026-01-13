#!/usr/bin/env python3
"""
Zeek mDNS Log Parser - Extracts mDNS queries from Zeek dns.log

This replaces live zeroconf mDNS capture, eliminating the need for:
- Host network mode
- Port 5353 binding (conflicts with avahi-daemon)
- Multicast group membership

Instead, we read mDNS data from Zeek's dns.log which captures ALL DNS traffic
including multicast DNS on 224.0.0.251:5353.

Usage:
    from zeek_mdns_parser import ZeekMDNSParser

    parser = ZeekMDNSParser('/opt/zeek/logs/current/dns.log')
    for event in parser.watch():
        print(f"mDNS: {event}")
"""

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator, List, Optional, Dict, Any
from collections import defaultdict

logger = logging.getLogger(__name__)

# mDNS multicast addresses
MDNS_MULTICAST_IPV4 = "224.0.0.251"
MDNS_MULTICAST_IPV6 = "ff02::fb"
MDNS_PORT = 5353

# Apple ecosystem mDNS services
APPLE_SERVICES = {
    "_airplay._tcp",
    "_raop._tcp",
    "_companion-link._tcp",
    "_homekit._tcp",
    "_hap._tcp",
    "_apple-mobdev2._tcp",
    "_sleep-proxy._udp",
    "_rdlink._tcp",
    "_touch-able._tcp",
}

# Google ecosystem services
GOOGLE_SERVICES = {
    "_googlecast._tcp",
    "_googlezone._tcp",
    "_googlerpc._tcp",
}

# Samsung/SmartThings services
SAMSUNG_SERVICES = {
    "_smartthings._tcp",
    "_samsungtv._tcp",
}

# Amazon services
AMAZON_SERVICES = {
    "_amzn-wplay._tcp",
    "_alexa._tcp",
}


@dataclass
class MDNSEvent:
    """Parsed mDNS event from Zeek dns.log."""
    timestamp: datetime
    source_mac: str  # Derived from IP via ARP/DHCP
    source_ip: str
    query: str
    query_type: str  # A, AAAA, PTR, SRV, TXT
    is_response: bool
    answers: List[str] = field(default_factory=list)
    ttl: int = 0
    ecosystem: str = "unknown"
    service_type: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_mac": self.source_mac,
            "source_ip": self.source_ip,
            "query": self.query,
            "query_type": self.query_type,
            "is_response": self.is_response,
            "answers": self.answers,
            "ttl": self.ttl,
            "ecosystem": self.ecosystem,
            "service_type": self.service_type,
        }


class ZeekMDNSParser:
    """
    Parses Zeek dns.log for mDNS traffic.

    Supports both JSON and TSV formats (Zeek default is TSV).

    TSV format has header lines starting with #:
        #fields ts uid id.orig_h id.orig_p ...

    JSON format (if configured):
        {"ts": 1234567890.123, "uid": "...", ...}
    """

    # Zeek query type mapping
    QTYPES = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        255: "ANY",
    }

    def __init__(self, dns_log_path: str = "/opt/zeek/logs/current/dns.log"):
        self.dns_log_path = Path(dns_log_path)
        self._position = 0
        self._mac_cache: Dict[str, str] = {}  # IP -> MAC cache
        self._discovery_pairs: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._fields: Optional[List[str]] = None  # TSV field names

    def _parse_tsv_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a TSV line into a dict using field names from header."""
        if not self._fields:
            return None

        values = line.split('\t')
        if len(values) != len(self._fields):
            return None

        record = {}
        for i, field in enumerate(self._fields):
            val = values[i]
            # Handle Zeek special values
            if val == '-' or val == '(empty)':
                val = None
            elif field in ('id.orig_p', 'id.resp_p', 'trans_id', 'qclass', 'qtype', 'rcode', 'Z'):
                try:
                    val = int(val) if val else 0
                except ValueError:
                    val = 0
            elif field == 'ts':
                try:
                    val = float(val) if val else 0.0
                except ValueError:
                    val = 0.0
            elif field in ('AA', 'TC', 'RD', 'RA', 'rejected'):
                val = val == 'T'
            elif field in ('answers', 'TTLs'):
                # Parse comma-separated lists
                val = val.split(',') if val else []
            record[field] = val

        return record

    def _parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a line (JSON or TSV) into a dict."""
        line = line.strip()
        if not line:
            return None

        # Handle TSV header lines
        if line.startswith('#fields'):
            self._fields = line.split('\t')[1:]  # Skip '#fields'
            logger.debug(f"Parsed {len(self._fields)} TSV fields")
            return None
        elif line.startswith('#'):
            return None  # Skip other comments

        # Try JSON first
        if line.startswith('{'):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                pass

        # Parse as TSV
        return self._parse_tsv_line(line)

    def _detect_ecosystem(self, query: str) -> tuple[str, Optional[str]]:
        """Detect ecosystem from mDNS query."""
        query_lower = query.lower()

        for service in APPLE_SERVICES:
            if service in query_lower:
                return "apple", service

        for service in GOOGLE_SERVICES:
            if service in query_lower:
                return "google", service

        for service in SAMSUNG_SERVICES:
            if service in query_lower:
                return "samsung", service

        for service in AMAZON_SERVICES:
            if service in query_lower:
                return "amazon", service

        # Generic service pattern
        match = re.search(r'_([a-z0-9-]+)\._(?:tcp|udp)', query_lower)
        if match:
            return "unknown", f"_{match.group(1)}._tcp"

        return "unknown", None

    def _get_mac_for_ip(self, ip: str) -> str:
        """
        Get MAC address for IP from cache or return placeholder.
        In production, this would query dnsmasq leases or ARP table.
        """
        if ip in self._mac_cache:
            return self._mac_cache[ip]

        # Try to read from dnsmasq leases
        try:
            leases_file = Path("/var/lib/misc/dnsmasq.leases")
            if leases_file.exists():
                with open(leases_file) as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 3 and parts[2] == ip:
                            mac = parts[1].upper()
                            self._mac_cache[ip] = mac
                            return mac
        except Exception as e:
            logger.debug(f"Could not read dnsmasq leases: {e}")

        # Return IP-based placeholder
        return f"IP:{ip}"

    def _is_mdns(self, record: Dict[str, Any]) -> bool:
        """Check if DNS record is mDNS (multicast)."""
        resp_h = record.get("id.resp_h", "")
        resp_p = record.get("id.resp_p", 0)
        orig_p = record.get("id.orig_p", 0)

        # mDNS uses port 5353 and multicast addresses
        is_mdns_port = resp_p == MDNS_PORT or orig_p == MDNS_PORT
        is_multicast = resp_h in (MDNS_MULTICAST_IPV4, MDNS_MULTICAST_IPV6)

        # Also check for .local domain
        query = record.get("query", "")
        is_local = query.endswith(".local") or ".local." in query

        return is_mdns_port or is_multicast or is_local

    def _parse_record(self, record: Dict[str, Any]) -> Optional[MDNSEvent]:
        """Parse a single Zeek DNS record into MDNSEvent."""
        if not self._is_mdns(record):
            return None

        try:
            # Parse timestamp
            ts = record.get("ts", 0)
            timestamp = datetime.fromtimestamp(ts) if ts else datetime.now()

            # Get source info
            source_ip = record.get("id.orig_h", "")
            source_mac = self._get_mac_for_ip(source_ip)

            # Get query info
            query = record.get("query", "")
            qtype_num = record.get("qtype", 0)
            query_type = self.QTYPES.get(qtype_num, str(qtype_num))

            # Is this a response?
            is_response = record.get("AA", False) or bool(record.get("answers"))

            # Get answers
            answers = record.get("answers", [])
            if isinstance(answers, str):
                answers = [answers]

            # Get TTL
            ttls = record.get("TTLs", [])
            ttl = ttls[0] if ttls else 0

            # Detect ecosystem
            ecosystem, service_type = self._detect_ecosystem(query)

            return MDNSEvent(
                timestamp=timestamp,
                source_mac=source_mac,
                source_ip=source_ip,
                query=query,
                query_type=query_type,
                is_response=is_response,
                answers=answers,
                ttl=ttl,
                ecosystem=ecosystem,
                service_type=service_type,
            )
        except Exception as e:
            logger.error(f"Failed to parse DNS record: {e}")
            return None

    def parse_log(self) -> Iterator[MDNSEvent]:
        """Parse entire dns.log file for mDNS events."""
        if not self.dns_log_path.exists():
            logger.warning(f"DNS log not found: {self.dns_log_path}")
            return

        try:
            with open(self.dns_log_path) as f:
                for line in f:
                    record = self._parse_line(line)
                    if not record:
                        continue

                    event = self._parse_record(record)
                    if event:
                        yield event
        except Exception as e:
            logger.error(f"Failed to parse dns.log: {e}")

    def watch(self, poll_interval: float = 1.0) -> Iterator[MDNSEvent]:
        """
        Watch dns.log for new mDNS events (tail -f style).

        Args:
            poll_interval: Seconds between checks for new data

        Yields:
            MDNSEvent for each new mDNS record
        """
        logger.info(f"Watching {self.dns_log_path} for mDNS events...")

        while True:
            try:
                if not self.dns_log_path.exists():
                    time.sleep(poll_interval)
                    continue

                with open(self.dns_log_path) as f:
                    # Seek to last position
                    f.seek(self._position)

                    for line in f:
                        record = self._parse_line(line)
                        if not record:
                            continue

                        event = self._parse_record(record)
                        if event:
                            yield event

                    # Save position for next iteration
                    self._position = f.tell()

            except FileNotFoundError:
                self._position = 0
                self._fields = None  # Reset fields on rotation
            except Exception as e:
                logger.error(f"Error watching dns.log: {e}")

            time.sleep(poll_interval)

    def get_discovery_pairs(self) -> Dict[str, Dict[str, int]]:
        """
        Get mDNS discovery pairs (which device queried which service).

        Returns:
            Dict mapping source_mac -> {target_service: hit_count}
        """
        return dict(self._discovery_pairs)

    def record_discovery(self, source_mac: str, query: str):
        """Record a discovery pair for affinity calculation."""
        if source_mac and query:
            self._discovery_pairs[source_mac][query] += 1


# Convenience function
def get_mdns_parser(log_path: Optional[str] = None) -> ZeekMDNSParser:
    """Get mDNS parser instance."""
    path = log_path or os.environ.get("ZEEK_DNS_LOG", "/opt/zeek/logs/current/dns.log")
    return ZeekMDNSParser(path)


if __name__ == "__main__":
    # Test mode - parse existing log
    import sys

    logging.basicConfig(level=logging.INFO)

    log_path = sys.argv[1] if len(sys.argv) > 1 else "/opt/zeek/logs/current/dns.log"
    parser = ZeekMDNSParser(log_path)

    print(f"Parsing mDNS from: {log_path}")
    count = 0
    for event in parser.parse_log():
        print(f"[{event.ecosystem}] {event.source_ip} -> {event.query} ({event.query_type})")
        count += 1

    print(f"\nTotal mDNS events: {count}")
