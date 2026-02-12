"""
dnsXai Signal Bridge

Polls the dnsXai API for blocked domain events and protection status changes.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

from .base_bridge import BaseBridge
from ..types import StandardSignal

logger = logging.getLogger(__name__)


class DnsxaiBridge(BaseBridge):
    """Bridge for dnsXai DNS protection events."""

    name = "dnsxai"
    poll_interval = 5.0

    def __init__(self, api_url: str = "http://fts-dnsxai:8080"):
        super().__init__()
        self._api_url = api_url
        self._last_blocked_count: int = 0
        self._last_protection_level: Optional[int] = None

    def poll(self) -> List[StandardSignal]:
        """Poll dnsXai API for new events."""
        signals = []

        # Poll stats endpoint
        stats = self._fetch_json(f"{self._api_url}/api/stats")
        if stats:
            blocked = stats.get("blocked_today", 0)
            level = stats.get("protection_level", 3)

            # New blocks detected
            if blocked > self._last_blocked_count:
                new_blocks = blocked - self._last_blocked_count
                if new_blocks >= 10:  # Only signal significant bursts
                    signals.append(StandardSignal(
                        source="dnsxai",
                        event_type="dns.block_burst",
                        severity="LOW",
                        data={
                            "new_blocks": new_blocks,
                            "total_blocked": blocked,
                            "protection_level": level,
                        },
                    ))
                self._last_blocked_count = blocked

            # Protection level change
            if self._last_protection_level is not None and level != self._last_protection_level:
                signals.append(StandardSignal(
                    source="dnsxai",
                    event_type="dns.protection_change",
                    severity="INFO",
                    data={
                        "new_level": level,
                        "old_level": self._last_protection_level,
                    },
                ))
            self._last_protection_level = level

        # Poll blocked endpoint for DGA/tunnel detections
        blocked_data = self._fetch_json(f"{self._api_url}/api/blocked?hours=1")
        if blocked_data and isinstance(blocked_data, list):
            for entry in blocked_data[:5]:
                category = entry.get("category", "")
                if category in ("malware", "phishing", "dga"):
                    signals.append(StandardSignal(
                        source="dnsxai",
                        event_type=f"dns.{category}",
                        severity="HIGH" if category == "malware" else "MEDIUM",
                        data={
                            "domain": entry.get("domain", ""),
                            "category": category,
                            "dga_score": entry.get("dga_score", 0.0),
                        },
                    ))

        return signals

    def _fetch_json(self, url: str) -> Optional[Any]:
        """Fetch JSON from a URL with short timeout."""
        try:
            req = Request(url, method="GET")
            with urlopen(req, timeout=3) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (URLError, Exception):
            return None
