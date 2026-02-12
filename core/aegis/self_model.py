"""
AEGIS Self-Model — System Self-Knowledge

Provides AEGIS with a 1:1 model of the system it lives in.
Discovers capabilities, topology, and health — stored as
institutional memory and refreshed periodically.
"""

import logging
import os
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SystemModel:
    """Live model of the HookProbe system AEGIS runs on.

    Discovers:
    - What product tier is installed
    - What containers are running
    - Network topology (interfaces, VLANs, WiFi)
    - System health (CPU, RAM, disk)
    - Configuration state

    Used by all agents for context-aware decision making.
    """

    def __init__(self):
        self._model: Dict[str, Any] = {}
        self._last_refresh: float = 0
        self._refresh_interval = 3600  # 1 hour

    def discover(self) -> Dict[str, Any]:
        """Full system discovery. Updates the internal model."""
        self._model = {
            "tier": self._detect_tier(),
            "capabilities": self.get_capabilities(),
            "topology": self.get_topology(),
            "health": self.get_health(),
            "config": self._read_config(),
            "discovered_at": time.time(),
        }
        self._last_refresh = time.time()
        return self._model

    def get_model(self) -> Dict[str, Any]:
        """Get the current system model, refreshing if stale."""
        if not self._model or (time.time() - self._last_refresh) > self._refresh_interval:
            self.discover()
        return self._model

    def get_capabilities(self) -> Dict[str, bool]:
        """Determine what this system can do."""
        return {
            "threat_detection": self._has_qsecbit(),
            "dns_protection": self._has_dnsxai(),
            "wan_failover": self._has_slaai(),
            "device_fingerprinting": self._has_device_manager(),
            "ids_suricata": self._has_service("suricata"),
            "nsm_zeek": self._has_service("zeek"),
            "local_llm": self._has_ollama(),
            "analytics_clickhouse": self._has_service("clickhouse"),
            "wifi_ap": os.path.exists("/etc/hookprobe/wifi-interfaces.conf"),
            "ovs_switching": os.path.exists("/usr/bin/ovs-vsctl"),
            "mesh_networking": os.path.exists("/opt/hookprobe/mesh"),
            "ecosystem_bubbles": True,  # Always available in Fortress
        }

    def get_topology(self) -> Dict[str, Any]:
        """Discover network topology."""
        topology: Dict[str, Any] = {
            "interfaces": [],
            "vlans": [],
            "wifi_bands": [],
            "wan_interfaces": [],
        }

        # Read config for network info
        config = self._read_config()

        if config.get("wan_interface"):
            topology["wan_interfaces"].append(config["wan_interface"])
        if config.get("wan_backup_interface"):
            topology["wan_interfaces"].append(config["wan_backup_interface"])
        if config.get("lan_subnet"):
            topology["lan_subnet"] = config["lan_subnet"]
        if config.get("wifi_ssid"):
            topology["wifi_bands"].append({
                "ssid": config["wifi_ssid"],
                "band": "dual",
            })

        return topology

    def get_health(self) -> Dict[str, Any]:
        """Get current system health metrics."""
        health: Dict[str, Any] = {
            "cpu_percent": 0.0,
            "ram_used_mb": 0.0,
            "ram_total_mb": 0.0,
            "disk_used_percent": 0.0,
        }

        try:
            # CPU from /proc/loadavg
            with open("/proc/loadavg") as f:
                load = float(f.read().split()[0])
                cpu_count = os.cpu_count() or 1
                health["cpu_percent"] = round(min(load / cpu_count * 100, 100), 1)
        except Exception:
            pass

        try:
            # Memory from /proc/meminfo
            with open("/proc/meminfo") as f:
                meminfo = {}
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        meminfo[parts[0].rstrip(":")] = int(parts[1])
                total = meminfo.get("MemTotal", 0) / 1024  # MB
                available = meminfo.get("MemAvailable", 0) / 1024
                health["ram_total_mb"] = round(total, 0)
                health["ram_used_mb"] = round(total - available, 0)
        except Exception:
            pass

        try:
            # Disk from os.statvfs
            st = os.statvfs("/")
            total = st.f_blocks * st.f_frsize
            free = st.f_bavail * st.f_frsize
            used_pct = ((total - free) / total) * 100 if total else 0
            health["disk_used_percent"] = round(used_pct, 1)
        except Exception:
            pass

        return health

    def get_context_for_llm(self) -> str:
        """Build a concise system context string for LLM injection."""
        model = self.get_model()
        cap = model.get("capabilities", {})
        health = model.get("health", {})

        active_caps = [k for k, v in cap.items() if v]
        lines = [
            f"System: HookProbe {model.get('tier', 'unknown').title()}",
            f"Capabilities: {', '.join(active_caps)}",
            f"Health: CPU {health.get('cpu_percent', 0)}%, "
            f"RAM {health.get('ram_used_mb', 0):.0f}/{health.get('ram_total_mb', 0):.0f}MB, "
            f"Disk {health.get('disk_used_percent', 0)}%",
        ]

        config = model.get("config", {})
        if config.get("lan_subnet"):
            lines.append(f"Network: {config['lan_subnet']}")
        if config.get("wifi_ssid"):
            lines.append(f"WiFi: {config['wifi_ssid']}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal discovery helpers
    # ------------------------------------------------------------------

    def _detect_tier(self) -> str:
        if os.path.exists("/etc/hookprobe/fortress.conf"):
            return "fortress"
        if os.path.exists("/opt/hookprobe/guardian"):
            return "guardian"
        if os.path.exists("/opt/hookprobe/sentinel"):
            return "sentinel"
        return "unknown"

    def _read_config(self) -> Dict[str, str]:
        """Read fortress.conf (or equivalent) into a dict."""
        config = {}
        for conf_path in ["/etc/hookprobe/fortress.conf", "/etc/hookprobe/guardian.conf"]:
            if os.path.exists(conf_path):
                try:
                    with open(conf_path) as f:
                        for line in f:
                            line = line.strip()
                            if "=" in line and not line.startswith("#"):
                                key, _, val = line.partition("=")
                                config[key.strip().lower()] = val.strip().strip('"\'')
                except Exception:
                    pass
                break
        return config

    def _has_qsecbit(self) -> bool:
        return any(os.path.exists(p) for p in [
            "/opt/hookprobe/fortress/data/qsecbit_stats.json",
            "/opt/hookprobe/guardian/data/qsecbit_stats.json",
        ])

    def _has_dnsxai(self) -> bool:
        return self._has_service("dnsxai") or os.path.exists("/opt/hookprobe/dnsxai")

    def _has_slaai(self) -> bool:
        return os.path.exists("/run/fortress/slaai-recommendation.json")

    def _has_device_manager(self) -> bool:
        return any(os.path.exists(p) for p in [
            "/opt/hookprobe/fortress/data/devices.json",
            "/var/lib/hookprobe/arp-status.json",
        ])

    def _has_ollama(self) -> bool:
        import socket
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                return s.connect_ex(("127.0.0.1", 11434)) == 0
        except Exception:
            return False

    @staticmethod
    def _has_service(name: str) -> bool:
        """Check if a container with this name substring is running."""
        try:
            import subprocess
            result = subprocess.run(
                ["podman", "ps", "--format", "{{.Names}}"],
                capture_output=True, text=True, timeout=3,
            )
            if result.returncode == 0:
                return any(name in n for n in result.stdout.split())
        except Exception:
            pass
        return False


# Singleton
_system_model: Optional[SystemModel] = None


def get_system_model() -> SystemModel:
    """Get or create the global SystemModel singleton."""
    global _system_model
    if _system_model is None:
        _system_model = SystemModel()
    return _system_model
