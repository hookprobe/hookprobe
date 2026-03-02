"""
Shared Telemetry Collector

Reads system metrics from /proc and standard utilities to populate
HeartbeatV2-compatible telemetry dicts. Used by all product agents
(Sentinel, Guardian, Fortress) to avoid duplicating collection code.
"""

import logging
import os
import platform
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class TelemetryCollector:
    """Collects system telemetry from /proc and standard tools."""

    @staticmethod
    def collect_all() -> dict:
        """Collect full HeartbeatV2-compatible telemetry dict."""
        telemetry: Dict[str, Any] = {"status": "online"}
        try:
            telemetry["system"] = TelemetryCollector.collect_system()
        except Exception as e:
            logger.debug("System telemetry error: %s", e)
        try:
            telemetry["network"] = TelemetryCollector.collect_network()
        except Exception as e:
            logger.debug("Network telemetry error: %s", e)
        try:
            telemetry["security"] = TelemetryCollector.collect_security()
        except Exception as e:
            logger.debug("Security telemetry error: %s", e)
        return telemetry

    @staticmethod
    def collect_system() -> dict:
        """Collect CPU, memory, disk, processes, uptime."""
        result: Dict[str, Any] = {}

        # OS info
        result["osName"] = platform.system()
        result["osVersion"] = platform.version()[:100]
        result["kernelVersion"] = platform.release()
        result["hostname"] = platform.node()

        # CPU from /proc/stat + /proc/loadavg
        result["cpu"] = _collect_cpu()

        # Memory from /proc/meminfo
        result["memory"] = _collect_memory()

        # Disk from statvfs
        result["disk"] = _collect_disk()

        # Processes
        result["processes"] = _collect_processes()

        # Uptime
        try:
            uptime_str = Path("/proc/uptime").read_text().split()[0]
            result["uptimeSeconds"] = int(float(uptime_str))
        except Exception:
            pass

        return result

    @staticmethod
    def collect_network() -> dict:
        """Collect network interfaces, listening ports, connections."""
        result: Dict[str, Any] = {}

        # Interfaces from /proc/net/dev + ip addr
        result["interfaces"] = _collect_interfaces()

        # Listening ports from /proc/net/tcp + /proc/net/tcp6
        result["listeningPorts"] = _collect_listening_ports()

        # Established connections count
        try:
            tcp = Path("/proc/net/tcp").read_text().splitlines()[1:]
            tcp6 = Path("/proc/net/tcp6").read_text().splitlines()[1:]
            established = sum(
                1 for line in tcp + tcp6
                if len(line.split()) > 3 and line.split()[3] == "01"
            )
            result["establishedConnections"] = established
        except Exception:
            pass

        return result

    @staticmethod
    def collect_security() -> dict:
        """Collect firewall, MAC, auth, updates info."""
        result: Dict[str, Any] = {}

        # Firewall
        result["firewall"] = _collect_firewall()

        # MAC (SELinux / AppArmor)
        result["mac"] = _collect_mac()

        # Auth: failed logins in last 24h
        result["auth"] = _collect_auth()

        # Updates
        result["updates"] = _collect_updates()

        return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _collect_cpu() -> dict:
    cpu: Dict[str, Any] = {}
    try:
        # Load average
        loadavg = Path("/proc/loadavg").read_text().split()
        cpu["loadAvg"] = [float(loadavg[0]), float(loadavg[1]), float(loadavg[2])]
    except Exception:
        pass

    # CPU count
    try:
        cpu["count"] = os.cpu_count() or 1
    except Exception:
        cpu["count"] = 1

    # CPU usage from /proc/stat (single sample, approximate)
    try:
        stat = Path("/proc/stat").read_text().splitlines()[0].split()
        # user, nice, system, idle, iowait, irq, softirq, steal
        vals = [int(x) for x in stat[1:9]]
        total = sum(vals)
        idle = vals[3] + vals[4]  # idle + iowait
        if total > 0:
            cpu["percent"] = round((1 - idle / total) * 100, 1)
    except Exception:
        pass

    return cpu


def _collect_memory() -> dict:
    mem: Dict[str, Any] = {}
    try:
        info = Path("/proc/meminfo").read_text()
        fields = {}
        for line in info.splitlines():
            parts = line.split(":")
            if len(parts) == 2:
                key = parts[0].strip()
                val = parts[1].strip().split()[0]
                fields[key] = int(val)

        total_kb = fields.get("MemTotal", 0)
        avail_kb = fields.get("MemAvailable", fields.get("MemFree", 0))
        swap_total_kb = fields.get("SwapTotal", 0)
        swap_free_kb = fields.get("SwapFree", 0)

        mem["totalMb"] = round(total_kb / 1024)
        mem["usedMb"] = round((total_kb - avail_kb) / 1024)
        mem["percent"] = round((total_kb - avail_kb) / max(total_kb, 1) * 100, 1)
        if swap_total_kb > 0:
            mem["swapTotalMb"] = round(swap_total_kb / 1024)
            mem["swapUsedMb"] = round((swap_total_kb - swap_free_kb) / 1024)
    except Exception:
        pass

    return mem


def _collect_disk() -> dict:
    disk: Dict[str, Any] = {}
    try:
        stat = os.statvfs("/")
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bfree * stat.f_frsize
        used = total - free
        disk["totalGb"] = round(total / (1024**3), 1)
        disk["usedGb"] = round(used / (1024**3), 1)
        disk["percent"] = round(used / max(total, 1) * 100, 1)
    except Exception:
        pass
    return disk


def _collect_processes() -> dict:
    procs: Dict[str, Any] = {}
    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
        procs["count"] = len(pids)
        # Count zombies
        zombies = 0
        for pid in pids[:500]:  # Limit scan
            try:
                status = Path(f"/proc/{pid}/status").read_text()
                if "State:\tZ" in status:
                    zombies += 1
            except Exception:
                pass
        procs["zombies"] = zombies
    except Exception:
        pass
    return procs


def _collect_interfaces() -> List[dict]:
    interfaces: List[dict] = []
    try:
        result = subprocess.run(
            ["ip", "-j", "addr", "show"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            import json
            for iface in json.loads(result.stdout):
                name = iface.get("ifname", "")
                if name == "lo":
                    continue
                entry: Dict[str, Any] = {
                    "name": name,
                    "state": "up" if iface.get("operstate") == "UP" else "down",
                }
                for addr_info in iface.get("addr_info", []):
                    if addr_info.get("family") == "inet":
                        entry["ipv4"] = addr_info.get("local", "")
                    elif addr_info.get("family") == "inet6":
                        entry.setdefault("ipv6", addr_info.get("local", ""))
                if iface.get("address"):
                    entry["mac"] = iface["address"]
                interfaces.append(entry)
    except Exception:
        pass
    return interfaces[:50]


def _collect_listening_ports() -> List[dict]:
    ports: List[dict] = []
    seen: set = set()
    try:
        for proto, path in [("tcp", "/proc/net/tcp"), ("tcp", "/proc/net/tcp6")]:
            try:
                lines = Path(path).read_text().splitlines()[1:]
                for line in lines:
                    fields = line.split()
                    if len(fields) < 4:
                        continue
                    state = fields[3]
                    if state != "0A":  # LISTEN
                        continue
                    local = fields[1]
                    port = int(local.split(":")[1], 16)
                    if port in seen:
                        continue
                    seen.add(port)
                    ports.append({"port": port, "protocol": proto})
            except Exception:
                pass
    except Exception:
        pass
    return sorted(ports, key=lambda p: p["port"])[:200]


def _collect_firewall() -> dict:
    fw: Dict[str, Any] = {"active": False}
    try:
        # Check nftables first
        result = subprocess.run(
            ["nft", "list", "ruleset"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and "table" in result.stdout:
            fw["active"] = True
            fw["type"] = "nftables"
            return fw
    except Exception:
        pass
    try:
        # Fallback: iptables
        result = subprocess.run(
            ["iptables", "-L", "-n", "--line-numbers"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            rules = [l for l in result.stdout.splitlines() if l.strip() and not l.startswith("Chain") and not l.startswith("num")]
            fw["active"] = len(rules) > 0
            fw["type"] = "iptables"
    except Exception:
        pass
    return fw


def _collect_mac() -> dict:
    mac: Dict[str, Any] = {"type": "none"}
    try:
        # SELinux
        if Path("/etc/selinux/config").exists():
            content = Path("/etc/selinux/config").read_text()
            if "SELINUX=enforcing" in content:
                mac = {"type": "selinux", "status": "enforcing"}
            elif "SELINUX=permissive" in content:
                mac = {"type": "selinux", "status": "permissive"}
            return mac
    except Exception:
        pass
    try:
        # AppArmor
        result = subprocess.run(
            ["aa-status", "--json"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            mac = {"type": "apparmor", "status": "enabled"}
    except Exception:
        pass
    return mac


def _collect_auth() -> dict:
    auth: Dict[str, Any] = {}
    try:
        # Failed logins in last 24h via journalctl (accurate window)
        result = subprocess.run(
            ["journalctl", "-u", "sshd", "--since", "24 hours ago",
             "--no-pager", "--output", "cat"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            auth["failedLogins24h"] = result.stdout.count("Failed password")
    except Exception:
        # Fallback: grep auth.log (may over-count if log not rotated daily)
        try:
            for log_path in ["/var/log/auth.log", "/var/log/secure"]:
                if Path(log_path).exists():
                    result = subprocess.run(
                        ["grep", "-c", "Failed password", log_path],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        auth["failedLogins24h"] = int(result.stdout.strip())
                    break
        except Exception:
            pass
    try:
        # SSH config checks
        sshd_config = Path("/etc/ssh/sshd_config")
        if sshd_config.exists():
            content = sshd_config.read_text()
            root_match = re.search(r"^\s*PermitRootLogin\s+(\w+)", content, re.MULTILINE)
            auth["rootLoginEnabled"] = root_match is None or root_match.group(1).lower() == "yes"
            pw_match = re.search(r"^\s*PasswordAuthentication\s+(\w+)", content, re.MULTILINE)
            auth["passwordAuthEnabled"] = pw_match is None or pw_match.group(1).lower() != "no"
            port_match = re.search(r"^\s*Port\s+(\d+)", content, re.MULTILINE)
            if port_match:
                auth["sshPort"] = int(port_match.group(1))
            else:
                auth["sshPort"] = 22
    except Exception:
        pass
    return auth


def _collect_updates() -> dict:
    updates: Dict[str, Any] = {}
    try:
        # APT-based systems
        result = subprocess.run(
            ["apt", "list", "--upgradable"],
            capture_output=True, text=True, timeout=10,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        )
        if result.returncode == 0:
            lines = [l for l in result.stdout.splitlines() if "/" in l]
            updates["packagesUpgradable"] = len(lines)
            updates["securityUpdates"] = sum(1 for l in lines if "security" in l.lower())
    except Exception:
        pass
    return updates
