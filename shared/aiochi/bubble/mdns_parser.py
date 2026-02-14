#!/usr/bin/env python3
"""
mDNS Parser - Processes NAPSE MDNSRecord events for ecosystem detection

Consumes mDNS events from the NAPSE event bus to detect device ecosystems
(Apple, Google, Samsung, Amazon) for D2D bubble coloring.

Usage:
    from mdns_parser import MDNSParser

    parser = MDNSParser()
    event = parser.process_napse_mdns(record)  # MDNSRecord from NAPSE

Author: HookProbe Team
License: Proprietary
Version: 6.0.0
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from collections import defaultdict

logger = logging.getLogger(__name__)

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
    """Parsed mDNS event from NAPSE event bus."""
    timestamp: datetime
    source_mac: str
    source_ip: str
    query: str
    query_type: str  # A, AAAA, PTR, SRV, TXT
    is_response: bool
    answers: List[str] = field(default_factory=list)
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
            "ecosystem": self.ecosystem,
            "service_type": self.service_type,
        }


class MDNSParser:
    """
    Processes NAPSE MDNSRecord events for mDNS ecosystem detection.

    Replaces the old ZeekMDNSParser which parsed Zeek dns.log files.
    Now receives typed MDNSRecord objects directly from the NAPSE event bus.
    """

    def __init__(self):
        self._discovery_pairs: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    def _detect_ecosystem(self, query: str) -> tuple:
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

    def process_napse_mdns(self, record) -> Optional[MDNSEvent]:
        """
        Process a NAPSE MDNSRecord into an MDNSEvent.

        Args:
            record: MDNSRecord from NAPSE event bus

        Returns:
            MDNSEvent with ecosystem detection, or None on error
        """
        try:
            query = getattr(record, 'query', '') or ''
            source_mac = getattr(record, 'source_mac', '') or ''
            source_ip = getattr(record, 'source_ip', '') or ''

            if not query:
                return None

            # Parse timestamp
            ts = getattr(record, 'ts', 0)
            try:
                timestamp = datetime.fromtimestamp(ts) if ts else datetime.now()
            except (ValueError, OSError):
                timestamp = datetime.now()

            # Detect ecosystem (use record's ecosystem if available, else detect)
            ecosystem = getattr(record, 'ecosystem', '') or ''
            service_type = getattr(record, 'service_type', '') or ''

            if not ecosystem or ecosystem == 'unknown':
                ecosystem, service_type = self._detect_ecosystem(query)

            # Get answers
            answers = getattr(record, 'answers', []) or []
            if isinstance(answers, str):
                answers = [answers]

            event = MDNSEvent(
                timestamp=timestamp,
                source_mac=source_mac,
                source_ip=source_ip,
                query=query,
                query_type=getattr(record, 'query_type', '') or '',
                is_response=getattr(record, 'is_response', False),
                answers=answers,
                ecosystem=ecosystem or 'unknown',
                service_type=service_type,
            )

            # Track discovery pairs
            if source_mac and query:
                self._discovery_pairs[source_mac][query] += 1

            return event

        except Exception as e:
            logger.error(f"Failed to process NAPSE mDNS record: {e}")
            return None

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
def get_mdns_parser() -> MDNSParser:
    """Get mDNS parser instance."""
    return MDNSParser()
