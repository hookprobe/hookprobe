"""
AEGIS Signal Fabric

Unified data access layer with caching.
Aggregates QSecBit, dnsXai, SLA AI, and device data into
structured summaries for the ORACLE agent.
"""

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

from .types import DeviceInfo, NetworkSummary, ThreatSummary

logger = logging.getLogger(__name__)

CACHE_TTL = 15.0  # seconds


class _CacheEntry:
    __slots__ = ("value", "expires")

    def __init__(self, value: Any, ttl: float):
        self.value = value
        self.expires = time.time() + ttl


class SignalFabric:
    """Unified data access layer for all Fortress signals."""

    def __init__(self):
        self._cache: Dict[str, _CacheEntry] = {}

    def _get_cached(self, key: str) -> Any:
        entry = self._cache.get(key)
        if entry and time.time() < entry.expires:
            return entry.value
        return None

    def _set_cached(self, key: str, value: Any, ttl: float = CACHE_TTL):
        self._cache[key] = _CacheEntry(value, ttl)

    # ------------------------------------------------------------------
    # QSecBit
    # ------------------------------------------------------------------

    def get_qsecbit_status(self) -> Dict[str, Any]:
        """Get current QSecBit score and RAG status.

        Priority: cache -> file -> defaults
        """
        cached = self._get_cached("qsecbit")
        if cached is not None:
            return cached

        result = {"score": 0.85, "status": "GREEN", "threats_detected": 0, "components": {}}

        # Read from agent data file
        try:
            stats_file = Path("/opt/hookprobe/fortress/data/qsecbit_stats.json")
            if stats_file.exists():
                qs = json.loads(stats_file.read_text())
                result = {
                    "score": qs.get("score", 0.85),
                    "status": qs.get("rag_status", "GREEN"),
                    "threats_detected": qs.get("threats_detected", 0),
                    "components": qs.get("components", {}),
                }
        except Exception:
            pass

        self._set_cached("qsecbit", result)
        return result

    # ------------------------------------------------------------------
    # Devices
    # ------------------------------------------------------------------

    def get_device_list(self) -> List[Dict[str, Any]]:
        """Get connected device list.

        Priority: cache -> devices.json -> ARP status -> empty
        """
        cached = self._get_cached("devices")
        if cached is not None:
            return cached

        devices: List[Dict[str, Any]] = []

        # Priority 1: Agent data file
        try:
            data_file = Path("/opt/hookprobe/fortress/data/devices.json")
            if data_file.exists():
                data = json.loads(data_file.read_text())
                if isinstance(data, dict) and "devices" in data:
                    devices = data["devices"]
                elif isinstance(data, list):
                    devices = data
        except Exception:
            pass

        # Priority 2: ARP status file
        if not devices:
            try:
                arp_file = Path("/var/lib/hookprobe/arp-status.json")
                if arp_file.exists():
                    arp_data = json.loads(arp_file.read_text())
                    for ip, info in arp_data.items():
                        if isinstance(info, dict) and info.get("online"):
                            devices.append({
                                "ip": ip,
                                "mac": info.get("mac", ""),
                                "hostname": info.get("hostname", ""),
                                "vendor": info.get("vendor", ""),
                            })
            except Exception:
                pass

        self._set_cached("devices", devices)
        return devices

    def get_device_info(self, mac_or_name: str) -> Optional[DeviceInfo]:
        """Look up a device by MAC address or hostname."""
        search = mac_or_name.upper().strip()
        for dev in self.get_device_list():
            mac = (dev.get("mac") or dev.get("mac_address") or "").upper()
            hostname = (dev.get("hostname") or "").upper()
            if search == mac or search in hostname or mac_or_name.lower() in hostname.lower():
                return DeviceInfo(
                    mac=mac,
                    ip=dev.get("ip"),
                    hostname=dev.get("hostname"),
                    vendor=dev.get("vendor"),
                    device_type=dev.get("device_type"),
                    bubble=dev.get("bubble"),
                    first_seen=str(dev["first_seen"]) if dev.get("first_seen") else None,
                    last_seen=str(dev["last_seen"]) if dev.get("last_seen") else None,
                )
        return None

    # ------------------------------------------------------------------
    # DNS / dnsXai
    # ------------------------------------------------------------------

    def get_dns_stats(self) -> Dict[str, Any]:
        """Get dnsXai protection statistics.

        Priority: cache -> dnsXai API -> file fallback -> defaults
        """
        cached = self._get_cached("dns")
        if cached is not None:
            return cached

        result = {"blocked_today": 0, "total_queries": 0, "protection_level": 3}

        # Try dnsXai API (container network)
        try:
            dnsxai_url = "http://fts-dnsxai:8080/api/stats"
            req = Request(dnsxai_url, method="GET")
            with urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                result = {
                    "blocked_today": data.get("blocked_today", 0),
                    "total_queries": data.get("total_queries", 0),
                    "protection_level": data.get("protection_level", 3),
                    "categories": data.get("categories", {}),
                }
        except (URLError, Exception):
            # Fallback to file
            try:
                dns_file = Path("/opt/hookprobe/fortress/data/dnsxai_stats.json")
                if dns_file.exists():
                    data = json.loads(dns_file.read_text())
                    result["blocked_today"] = data.get("blocked_today", 0)
                    result["total_queries"] = data.get("total_queries", 0)
            except Exception:
                pass

        self._set_cached("dns", result)
        return result

    # ------------------------------------------------------------------
    # WAN / SLA AI
    # ------------------------------------------------------------------

    def get_wan_status(self) -> Dict[str, Any]:
        """Get WAN connection status from SLA AI.

        Priority: cache -> recommendation file -> defaults
        """
        cached = self._get_cached("wan")
        if cached is not None:
            return cached

        result = {"status": "online", "primary_health": 95, "backup_health": 72}

        try:
            state_file = Path("/run/fortress/slaai-recommendation.json")
            if state_file.exists():
                sla = json.loads(state_file.read_text())
                primary = sla.get("primary_health", 0.95)
                backup = sla.get("backup_health", 0.72)
                result = {
                    "status": (
                        "online"
                        if sla.get("active_interface") == sla.get("primary_interface")
                        else "backup"
                    ),
                    "primary_health": int(primary * 100) if primary <= 1 else int(primary),
                    "backup_health": int(backup * 100) if backup <= 1 else int(backup),
                    "active_interface": sla.get("active_interface", ""),
                    "recommendation": sla.get("recommendation", ""),
                }
        except Exception:
            pass

        self._set_cached("wan", result)
        return result

    # ------------------------------------------------------------------
    # Threats
    # ------------------------------------------------------------------

    def get_recent_threats(self, hours: int = 24) -> List[ThreatSummary]:
        """Get recent threat events.

        Priority: cache -> threats file -> empty
        """
        cache_key = f"threats_{hours}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        threats: List[ThreatSummary] = []

        try:
            threats_file = Path("/opt/hookprobe/fortress/data/recent_threats.json")
            if threats_file.exists():
                raw = json.loads(threats_file.read_text())
                for t in raw[:50]:  # Limit to 50 for LLM context
                    threats.append(ThreatSummary(
                        type=t.get("type", t.get("attack_type", "UNKNOWN")),
                        severity=t.get("severity", "LOW"),
                        source_ip=t.get("source_ip"),
                        target=t.get("target", t.get("target_ip")),
                        description=t.get("description", ""),
                        recommendation=t.get("recommendation", ""),
                    ))
        except Exception:
            pass

        self._set_cached(cache_key, threats)
        return threats

    # ------------------------------------------------------------------
    # Aggregated Summary
    # ------------------------------------------------------------------

    def get_network_summary(self) -> NetworkSummary:
        """Aggregate all signals into a single NetworkSummary."""
        cached = self._get_cached("summary")
        if cached is not None:
            return cached

        qs = self.get_qsecbit_status()
        devices = self.get_device_list()
        dns = self.get_dns_stats()
        wan = self.get_wan_status()
        threats = self.get_recent_threats()

        summary = NetworkSummary(
            qsecbit_score=qs.get("score", 0.85),
            qsecbit_status=qs.get("status", "GREEN"),
            device_count=len(devices),
            threat_count=len(threats),
            dns_blocked_24h=dns.get("blocked_today", 0),
            wan_status=wan.get("status", "online"),
            wan_primary_health=wan.get("primary_health", 95),
        )

        self._set_cached("summary", summary)
        return summary


# Singleton
_fabric: Optional[SignalFabric] = None


def get_signal_fabric() -> SignalFabric:
    """Get or create the global SignalFabric instance."""
    global _fabric
    if _fabric is None:
        _fabric = SignalFabric()
    return _fabric
