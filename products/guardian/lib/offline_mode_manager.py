#!/usr/bin/env python3
"""
Guardian Offline Mode Manager

Manages Guardian's offline-first operation mode for scenarios where:
- No upstream WiFi is pre-configured
- User needs immediate hotspot access
- Congested environments require smart channel selection

Boot Sequence (Offline-First):
1. Check if upstream WiFi is configured and reachable
2. If not, scan RF environment for channel congestion
3. Select optimal channel using WiFiChannelScanner
4. Start hostapd with selected channel
5. Start dnsmasq (DHCP works without WAN)
6. Web UI shows "Configure Upstream WiFi" option
7. User connects, configures upstream via web UI
8. Guardian connects upstream, NAT enabled

Author: HookProbe Team
Version: 1.0.0
License: MIT
"""

import os
import json
import time
import logging
import subprocess
import shlex
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, Optional, List, Tuple, Union
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class OfflineState(Enum):
    """Guardian offline mode states"""
    INITIALIZING = "initializing"        # Boot sequence starting
    SCANNING = "scanning"                 # Scanning RF environment
    AP_STARTING = "ap_starting"           # Starting AP with optimal channel
    OFFLINE_READY = "offline_ready"       # AP running, no WAN
    CONNECTING_WAN = "connecting_wan"     # Attempting WAN connection
    ONLINE = "online"                     # Full connectivity
    ERROR = "error"                       # Error state


@dataclass
class OfflineModeConfig:
    """Configuration for offline mode"""
    # Enable offline-first boot
    enabled: bool = True

    # Interfaces
    ap_interface: str = "wlan0"           # Interface for AP mode
    wan_interface: str = "wlan1"          # Interface for upstream (if available)
    fallback_wan_interface: str = "eth0"  # Ethernet fallback

    # AP defaults
    default_ssid: str = "HookProbe-Guardian"
    default_channel_2_4: int = 6
    default_channel_5: int = 36

    # Network settings
    ap_ip: str = "192.168.4.1"
    ap_netmask: str = "255.255.255.224"  # /27 for 30 devices
    dhcp_range_start: str = "192.168.4.2"
    dhcp_range_end: str = "192.168.4.30"
    dhcp_lease_time: str = "24h"

    # Route metrics (lower = higher priority)
    # eth0 should always have priority over WiFi
    eth0_metric: int = 100                # Highest priority
    wlan_upstream_metric: int = 200       # WiFi upstream
    wlan_ap_metric: int = 600             # AP interface (no default route)

    # DHCP client settings
    dhcp_timeout: int = 30                # DHCP request timeout
    dhcp_retry_count: int = 3             # Retries before fallback

    # Timeouts
    wan_check_timeout: int = 10           # Seconds to wait for WAN check
    scan_timeout: int = 30                # Seconds for RF scan
    ap_start_timeout: int = 15            # Seconds to wait for AP start

    # Config paths
    hostapd_config_path: str = "/etc/hostapd/hostapd.conf"
    dnsmasq_config_path: str = "/etc/dnsmasq.conf"
    wpa_supplicant_config: str = "/etc/wpa_supplicant/wpa_supplicant.conf"
    dhcpcd_config_path: str = "/etc/dhcpcd.conf"
    state_file: str = "/var/lib/guardian/offline_state.json"

    # Auto-scan on congestion detection
    auto_channel_rescan_interval: int = 3600  # Rescan every hour
    congestion_threshold: float = 50.0        # Rescan if score > threshold


@dataclass
class OfflineModeState:
    """Current state of offline mode"""
    state: OfflineState = OfflineState.INITIALIZING
    current_channel: int = 6
    current_band: str = "2.4GHz"
    ap_ssid: str = ""
    ap_running: bool = False
    wan_connected: bool = False
    wan_ssid: Optional[str] = None
    wan_ip: Optional[str] = None
    clients_connected: int = 0
    last_scan_time: Optional[str] = None
    last_channel_score: float = 0.0
    networks_detected: int = 0
    error_message: Optional[str] = None
    uptime_seconds: int = 0

    def to_dict(self) -> dict:
        result = asdict(self)
        result['state'] = self.state.value
        return result


class OfflineModeManager:
    """
    Manages Guardian's offline-first operation.

    Handles:
    - Smart channel selection during boot
    - AP startup without WAN
    - wpa_supplicant override handling
    - Upstream WiFi connection management
    - State persistence and recovery
    """

    def __init__(self, config: Optional[OfflineModeConfig] = None):
        self.config = config or OfflineModeConfig()
        self.state = OfflineModeState()
        self._scanner = None
        self._start_time = time.time()

        # Ensure state directory exists
        Path(self.config.state_file).parent.mkdir(parents=True, exist_ok=True)

    def _run_command(
        self,
        cmd: Union[str, List[str]],
        timeout: int = 30,
        suppress_stderr: bool = False
    ) -> Tuple[str, bool]:
        """Run command safely without shell=True to prevent command injection

        Args:
            cmd: Command string or list of arguments
            timeout: Command timeout in seconds
            suppress_stderr: If True, redirect stderr to DEVNULL (like 2>/dev/null)
        """
        try:
            # Convert string to list for safe execution
            if isinstance(cmd, str):
                # Remove shell redirections before parsing (handle them via subprocess)
                clean_cmd = cmd.replace(" 2>/dev/null", "").replace("2>/dev/null", "")
                cmd_list = shlex.split(clean_cmd)
                # Auto-detect if stderr should be suppressed
                if "2>/dev/null" in cmd:
                    suppress_stderr = True
            else:
                cmd_list = cmd

            stderr_dest = subprocess.DEVNULL if suppress_stderr else subprocess.PIPE

            result = subprocess.run(
                cmd_list, capture_output=False,
                stdout=subprocess.PIPE,
                stderr=stderr_dest,
                text=True, timeout=timeout
            )
            return result.stdout.strip(), result.returncode == 0
        except subprocess.TimeoutExpired:
            logger.warning(f"Command timed out: {cmd}")
            return "", False
        except Exception as e:
            logger.error(f"Command failed: {e}")
            return str(e), False

    def _get_interface_ip(self, interface: str) -> Optional[str]:
        """Get IP address of an interface without shell pipes"""
        output, success = self._run_command(["ip", "addr", "show", interface])
        if not success:
            return None

        # Parse output to find inet line
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('inet ') and 'inet6' not in line:
                # Format: inet 192.168.1.1/24 brd ...
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1]  # Returns IP/prefix like 192.168.1.1/24
        return None

    def _get_default_gateway(self, interface: str) -> Optional[str]:
        """Get default gateway for an interface without shell pipes"""
        output, success = self._run_command(["ip", "route", "show", "dev", interface])
        if not success:
            return None

        for line in output.split('\n'):
            if 'default' in line:
                parts = line.split()
                # Format: default via 192.168.1.1 dev eth0
                if 'via' in parts:
                    via_idx = parts.index('via')
                    if via_idx + 1 < len(parts):
                        return parts[via_idx + 1]
        return None

    def _count_arp_entries(self, interface: str) -> int:
        """Count ARP entries for an interface without shell pipes"""
        output, _ = self._run_command(["arp", "-an"])
        count = 0
        for line in output.split('\n'):
            if interface in line:
                count += 1
        return count

    def _get_scanner(self):
        """Lazy load WiFi scanner"""
        if self._scanner is None:
            try:
                from wifi_channel_scanner import WiFiChannelScanner
                self._scanner = WiFiChannelScanner(interface=self.config.ap_interface)
            except ImportError:
                # Try relative import
                try:
                    from .wifi_channel_scanner import WiFiChannelScanner
                    self._scanner = WiFiChannelScanner(interface=self.config.ap_interface)
                except ImportError:
                    logger.error("WiFiChannelScanner not available")
                    return None
        return self._scanner

    # =========================================================================
    # STATE MANAGEMENT
    # =========================================================================

    def save_state(self):
        """Persist current state to file"""
        try:
            self.state.uptime_seconds = int(time.time() - self._start_time)
            with open(self.config.state_file, 'w') as f:
                json.dump(self.state.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def load_state(self) -> bool:
        """Load state from file"""
        try:
            if Path(self.config.state_file).exists():
                with open(self.config.state_file) as f:
                    data = json.load(f)
                    self.state.state = OfflineState(data.get('state', 'initializing'))
                    self.state.current_channel = data.get('current_channel', 6)
                    self.state.current_band = data.get('current_band', '2.4GHz')
                    self.state.ap_ssid = data.get('ap_ssid', '')
                    self.state.last_scan_time = data.get('last_scan_time')
                    self.state.last_channel_score = data.get('last_channel_score', 0.0)
                    return True
        except Exception as e:
            logger.warning(f"Failed to load state: {e}")
        return False

    # =========================================================================
    # WAN CONNECTIVITY CHECKS
    # =========================================================================

    def check_wpa_supplicant_configured(self) -> Tuple[bool, Optional[str]]:
        """
        Check if wpa_supplicant has a valid upstream network configured.

        Handles the scenario where user configured WiFi via Raspberry Pi Imager
        but that network isn't available in the current location.

        Returns:
            (is_configured, ssid) - Whether config exists and the SSID
        """
        try:
            if not Path(self.config.wpa_supplicant_config).exists():
                return False, None

            with open(self.config.wpa_supplicant_config) as f:
                content = f.read()

            # Look for network blocks
            import re
            networks = re.findall(r'ssid="([^"]+)"', content)

            if networks:
                return True, networks[0]  # Return first configured SSID
            return False, None
        except Exception as e:
            logger.warning(f"Error checking wpa_supplicant: {e}")
            return False, None

    def check_wan_connectivity(self) -> bool:
        """
        Check if we have WAN connectivity.

        Tests both WiFi and Ethernet.
        """
        # Check for any default route
        output, success = self._run_command("ip route show default")
        if not success or not output:
            return False

        # Try to reach the internet (quick ping to 8.8.8.8)
        _, success = self._run_command(
            "ping -c 1 -W 2 8.8.8.8",
            timeout=5
        )
        return success

    def get_wan_status(self) -> Dict:
        """Get detailed WAN status"""
        status = {
            'connected': False,
            'interface': None,
            'ip': None,
            'gateway': None,
            'ssid': None
        }

        # Check default route
        output, success = self._run_command("ip route show default")
        if success and output:
            # Parse: default via 192.168.1.1 dev wlan1
            parts = output.split()
            if 'via' in parts and 'dev' in parts:
                try:
                    status['gateway'] = parts[parts.index('via') + 1]
                    status['interface'] = parts[parts.index('dev') + 1]
                except (IndexError, ValueError):
                    pass

        # Get IP for WAN interface
        if status['interface']:
            ip_addr = self._get_interface_ip(status['interface'])
            if ip_addr:
                status['ip'] = ip_addr.split('/')[0]
                status['connected'] = True

            # Get SSID if WiFi
            if 'wlan' in status['interface']:
                output, _ = self._run_command(
                    ["iwgetid", status['interface'], "-r"]
                )
                if output:
                    status['ssid'] = output

        return status

    # =========================================================================
    # ROUTE METRICS AND DHCP CONFIGURATION
    # =========================================================================

    def configure_route_metrics(self) -> bool:
        """
        Configure proper route metrics for eth0 and wlan interfaces.

        On Raspberry Pi, without explicit metrics:
        - Both eth0 and wlan0 may get the same metric
        - This causes 169.254.x.x (link-local) addresses
        - eth0 should have priority (lower metric = higher priority)

        Route metric priority:
        - eth0: 100 (highest priority)
        - wlan upstream: 200
        - wlan AP: 600 (no default route needed)
        """
        logger.info("Configuring route metrics...")

        success = True

        # Generate dhcpcd.conf with proper metrics
        dhcpcd_config = self._generate_dhcpcd_config()

        try:
            # Backup existing config
            if Path(self.config.dhcpcd_config_path).exists():
                self._run_command(
                    f"sudo cp {self.config.dhcpcd_config_path} "
                    f"{self.config.dhcpcd_config_path}.guardian-backup"
                )

            # Write new config
            temp_path = "/tmp/dhcpcd.conf.guardian"
            with open(temp_path, 'w') as f:
                f.write(dhcpcd_config)

            _, copy_success = self._run_command(
                f"sudo cp {temp_path} {self.config.dhcpcd_config_path}"
            )

            if not copy_success:
                logger.error("Failed to write dhcpcd.conf")
                success = False
        except Exception as e:
            logger.error(f"Failed to configure dhcpcd: {e}")
            success = False

        # Apply metrics to existing routes immediately
        self._apply_route_metrics()

        return success

    def _generate_dhcpcd_config(self) -> str:
        """Generate dhcpcd.conf with proper route metrics"""
        return f"""# Guardian dhcpcd Configuration
# Generated: {datetime.now().isoformat()}
# Purpose: Proper route metrics for eth0/wlan priority

# Global settings
hostname
clientid
persistent
option rapid_commit
option domain_name_servers, domain_name, domain_search, host_name
option classless_static_routes
option interface_mtu
require dhcp_server_identifier
slaac private
noipv4ll  # Disable link-local (169.254.x.x) fallback on timeout

# ============================================
# Interface-specific configuration
# ============================================

# eth0 - Highest priority (metric {self.config.eth0_metric})
# Should always be preferred when cable is connected
interface eth0
metric {self.config.eth0_metric}
# Wait for DHCP before falling back
timeout {self.config.dhcp_timeout}

# wlan0 - Used as AP, no DHCP client needed
# Exclude from DHCP client
interface {self.config.ap_interface}
nohook wpa_supplicant
# Static IP for AP mode
static ip_address={self.config.ap_ip}/27
nogateway  # Don't add default route for AP interface

# wlan1 - Upstream WiFi (if available)
interface {self.config.wan_interface}
metric {self.config.wlan_upstream_metric}
timeout {self.config.dhcp_timeout}

# ============================================
# Fallback configuration
# ============================================
# If no DHCP response after timeout, don't use link-local
# This prevents 169.254.x.x addresses
fallback static_eth0

profile static_eth0
# No static fallback - just don't get an address
# This is better than 169.254.x.x which breaks routing
"""

    def _apply_route_metrics(self):
        """Apply route metrics to existing routes immediately"""
        # Get current default routes
        output, success = self._run_command("ip route show default")
        if not success or not output:
            return

        # Parse and fix routes
        for line in output.split('\n'):
            if not line.strip():
                continue

            # Extract interface
            parts = line.split()
            if 'dev' not in parts:
                continue

            try:
                dev_idx = parts.index('dev')
                interface = parts[dev_idx + 1]
                gateway = parts[parts.index('via') + 1] if 'via' in parts else None
            except (IndexError, ValueError):
                continue

            # Determine correct metric
            if interface == 'eth0':
                metric = self.config.eth0_metric
            elif interface == self.config.ap_interface:
                # AP interface shouldn't have default route
                logger.info(f"Removing default route from AP interface {interface}")
                self._run_command(
                    ["sudo", "ip", "route", "del", "default", "dev", interface],
                    suppress_stderr=True
                )
                continue
            elif 'wlan' in interface:
                metric = self.config.wlan_upstream_metric
            else:
                continue

            # Check if metric is already set
            if f'metric {metric}' in line:
                continue

            # Remove old route and add with correct metric
            logger.info(f"Setting metric {metric} for {interface}")
            self._run_command(
                ["sudo", "ip", "route", "del", "default", "dev", interface],
                suppress_stderr=True
            )
            if gateway:
                self._run_command([
                    "sudo", "ip", "route", "add", "default",
                    "via", gateway, "dev", interface, "metric", str(metric)
                ])

    def fix_eth0_dhcp(self) -> Tuple[bool, Optional[str]]:
        """
        Fix eth0 DHCP issues (169.254.x.x addresses).

        Returns:
            (success, ip_address) - Whether fix worked and the new IP
        """
        logger.info("Attempting to fix eth0 DHCP...")

        # Check if eth0 exists and is up
        output, success = self._run_command(["ip", "link", "show", "eth0"])
        if not success:
            logger.warning("eth0 interface not found")
            return False, None

        # Check current IP using helper method
        ip_addr = self._get_interface_ip("eth0")
        current_ip = ip_addr.split('/')[0] if ip_addr else None

        # Check if it's a link-local address
        if current_ip and current_ip.startswith('169.254.'):
            logger.info(f"eth0 has link-local address {current_ip}, attempting DHCP")

            # Release any existing lease
            self._run_command(["sudo", "dhclient", "-r", "eth0"], suppress_stderr=True)
            self._run_command(["sudo", "ip", "addr", "flush", "dev", "eth0"], suppress_stderr=True)

            # Bring interface down and up
            self._run_command(["sudo", "ip", "link", "set", "eth0", "down"])
            time.sleep(1)
            self._run_command(["sudo", "ip", "link", "set", "eth0", "up"])
            time.sleep(2)

            # Try dhclient with timeout
            _, success = self._run_command(
                ["sudo", "timeout", str(self.config.dhcp_timeout), "dhclient", "-v", "eth0"],
                timeout=self.config.dhcp_timeout + 5
            )

            if not success:
                # Try dhcpcd as fallback
                logger.info("dhclient failed, trying dhcpcd...")
                self._run_command(["sudo", "dhcpcd", "-n", "eth0"])
                time.sleep(5)

            # Check new IP using helper method
            ip_addr = self._get_interface_ip("eth0")
            new_ip = ip_addr.split('/')[0] if ip_addr else None

            if new_ip and not new_ip.startswith('169.254.'):
                logger.info(f"eth0 DHCP fix successful: {new_ip}")
                return True, new_ip
            else:
                logger.warning(f"eth0 DHCP fix failed, still has: {new_ip}")
                return False, new_ip

        elif current_ip:
            logger.info(f"eth0 already has valid IP: {current_ip}")
            return True, current_ip
        else:
            # No IP at all, try DHCP
            logger.info("eth0 has no IP, requesting DHCP...")
            self._run_command(["sudo", "ip", "link", "set", "eth0", "up"])
            time.sleep(1)
            self._run_command(
                ["sudo", "timeout", str(self.config.dhcp_timeout), "dhclient", "eth0"]
            )
            time.sleep(3)

            ip_addr = self._get_interface_ip("eth0")
            new_ip = ip_addr.split('/')[0] if ip_addr else None

            if new_ip and not new_ip.startswith('169.254.'):
                return True, new_ip
            return False, new_ip

    def detect_wan_interface(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Detect the best WAN interface and its IP.

        Priority:
        1. eth0 with valid (non-169.254) IP
        2. wlan with upstream connection
        3. None

        Returns:
            (interface, ip) - Best WAN interface and its IP
        """
        interfaces_priority = [
            ('eth0', self.config.eth0_metric),
            (self.config.wan_interface, self.config.wlan_upstream_metric),
        ]

        for interface, _ in interfaces_priority:
            # Check if interface exists
            output, success = self._run_command(
                ["ip", "link", "show", interface], suppress_stderr=True
            )
            if not success:
                continue

            # Get IP using helper method
            ip_addr = self._get_interface_ip(interface)
            if not ip_addr:
                continue

            ip = ip_addr.split('/')[0]

            # Skip link-local addresses
            if ip.startswith('169.254.'):
                logger.warning(f"{interface} has link-local address {ip}")
                continue

            # Skip AP interface IP
            if ip == self.config.ap_ip:
                continue

            # Check if we can reach gateway using helper method
            gateway = self._get_default_gateway(interface)
            if gateway:
                _, ping_success = self._run_command(
                    ["ping", "-c", "1", "-W", "2", "-I", interface, gateway],
                    timeout=5
                )
                if ping_success:
                    logger.info(f"Found working WAN interface: {interface} ({ip})")
                    return interface, ip

        return None, None

    # =========================================================================
    # CHANNEL SELECTION
    # =========================================================================

    def scan_and_select_channel(self) -> Tuple[int, float, int]:
        """
        Scan RF environment and select optimal channel.

        Returns:
            (channel, score, networks_count)
        """
        scanner = self._get_scanner()
        if not scanner:
            logger.warning("Scanner unavailable, using default channel")
            return self.config.default_channel_2_4, 0.0, 0

        self.state.state = OfflineState.SCANNING
        self.save_state()

        try:
            result = scanner.scan()

            self.state.last_scan_time = result.scan_timestamp
            self.state.networks_detected = len(result.networks)

            # Get the score for recommended channel
            score = 0.0
            if result.recommended_channel_2_4 in result.channel_scores:
                score = result.channel_scores[result.recommended_channel_2_4].score

            self.state.last_channel_score = score

            logger.info(
                f"Channel scan complete: {len(result.networks)} networks detected, "
                f"recommended channel: {result.recommended_channel_2_4} (score: {score:.1f})"
            )

            return result.recommended_channel_2_4, score, len(result.networks)

        except Exception as e:
            logger.error(f"Channel scan failed: {e}")
            return self.config.default_channel_2_4, 0.0, 0

    # =========================================================================
    # HOSTAPD MANAGEMENT
    # =========================================================================

    def generate_hostapd_config(
        self,
        channel: int,
        ssid: Optional[str] = None,
        password: Optional[str] = None
    ) -> str:
        """Generate hostapd configuration with dynamic channel"""
        ssid = ssid or self.config.default_ssid
        password = password or "hookprobe123"  # Default password

        # Determine band and mode based on channel
        if channel <= 14:
            hw_mode = "g"
            band = "2.4GHz"
        else:
            hw_mode = "a"
            band = "5GHz"

        config = f"""# HookProbe Guardian - Dynamic hostapd Configuration
# Generated: {datetime.now().isoformat()}
# Mode: Offline-First with Smart Channel Selection

# Interface configuration
interface={self.config.ap_interface}
driver=nl80211
bridge=br0

# SSID Configuration
ssid={ssid}
hw_mode={hw_mode}
channel={channel}
country_code=US

# 802.11n/ac support
ieee80211n=1
{'ieee80211ac=1' if hw_mode == 'a' else '# ieee80211ac disabled for 2.4GHz'}
wmm_enabled=1

# Security - WPA2
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
wpa_passphrase={password}

# Authentication
auth_algs=1
macaddr_acl=0

# Client isolation for security
ap_isolate=1

# Performance
max_num_sta=30
beacon_int=100
dtim_period=2

# Logging
logger_syslog=-1
logger_syslog_level=2
"""
        self.state.current_channel = channel
        self.state.current_band = band
        self.state.ap_ssid = ssid

        return config

    def write_hostapd_config(self, config: str) -> bool:
        """Write hostapd configuration file"""
        try:
            # Write to temp file first
            temp_path = "/tmp/hostapd.conf.new"
            with open(temp_path, 'w') as f:
                f.write(config)

            # Copy to actual location (requires sudo)
            _, success = self._run_command(
                ["sudo", "cp", temp_path, self.config.hostapd_config_path]
            )
            if not success:
                logger.error("Failed to copy hostapd config")
                return False

            return True
        except Exception as e:
            logger.error(f"Failed to write hostapd config: {e}")
            return False

    def start_ap(self) -> bool:
        """Start the access point"""
        self.state.state = OfflineState.AP_STARTING
        self.save_state()

        # Stop any existing instance
        self._run_command(
            ["sudo", "systemctl", "stop", "hostapd"], suppress_stderr=True
        )
        time.sleep(1)

        # Ensure interface is up
        self._run_command(
            ["sudo", "ip", "link", "set", self.config.ap_interface, "up"]
        )

        # Start hostapd
        _, success = self._run_command(["sudo", "systemctl", "start", "hostapd"])

        if success:
            # Wait a moment and verify
            time.sleep(2)
            output, _ = self._run_command("systemctl is-active hostapd")
            if output.strip() == "active":
                self.state.ap_running = True
                logger.info(
                    f"AP started successfully on channel {self.state.current_channel} "
                    f"({self.state.current_band})"
                )
                return True

        self.state.ap_running = False
        logger.error("Failed to start hostapd")
        return False

    def restart_ap_with_channel(self, channel: int) -> bool:
        """Restart AP with a new channel"""
        config = self.generate_hostapd_config(channel)
        if not self.write_hostapd_config(config):
            return False
        return self.start_ap()

    # =========================================================================
    # DNSMASQ MANAGEMENT
    # =========================================================================

    def generate_dnsmasq_config(self) -> str:
        """Generate dnsmasq configuration for offline mode"""
        return f"""# HookProbe Guardian - Offline Mode dnsmasq Configuration
# Generated: {datetime.now().isoformat()}

# Interface to listen on
interface=br0
bind-interfaces

# Don't read /etc/resolv.conf
no-resolv

# Upstream DNS (will be used when WAN is available)
server=8.8.8.8
server=1.1.1.1

# DHCP range
dhcp-range={self.config.dhcp_range_start},{self.config.dhcp_range_end},{self.config.ap_netmask},{self.config.dhcp_lease_time}

# Gateway
dhcp-option=3,{self.config.ap_ip}

# DNS server (self)
dhcp-option=6,{self.config.ap_ip}

# Domain
domain=guardian.local

# Captive portal detection responses
# iOS/macOS
address=/captive.apple.com/{self.config.ap_ip}
# Android
address=/connectivitycheck.gstatic.com/{self.config.ap_ip}
address=/connectivitycheck.android.com/{self.config.ap_ip}
# Windows
address=/www.msftconnecttest.com/{self.config.ap_ip}

# Local hostnames
address=/guardian.local/{self.config.ap_ip}
address=/hookprobe.local/{self.config.ap_ip}

# Logging
log-queries
log-dhcp
log-facility=/var/log/guardian/dnsmasq.log

# Security
bogus-priv
domain-needed
"""

    def start_dhcp(self) -> bool:
        """Start DHCP server (dnsmasq)"""
        # Generate config
        config = self.generate_dnsmasq_config()

        try:
            temp_path = "/tmp/dnsmasq.conf.new"
            with open(temp_path, 'w') as f:
                f.write(config)

            self._run_command(
                ["sudo", "cp", temp_path, self.config.dnsmasq_config_path]
            )
        except Exception as e:
            logger.error(f"Failed to write dnsmasq config: {e}")

        # Restart dnsmasq
        _, success = self._run_command(["sudo", "systemctl", "restart", "dnsmasq"])
        if success:
            logger.info("DHCP server started")
            return True

        logger.error("Failed to start dnsmasq")
        return False

    # =========================================================================
    # MAIN BOOT SEQUENCE
    # =========================================================================

    def initialize_offline_mode(self) -> bool:
        """
        Main entry point for offline-first boot sequence.

        Returns True if AP started successfully.
        """
        logger.info("=" * 60)
        logger.info("Guardian Offline Mode - Initialization Starting")
        logger.info("=" * 60)

        self.state.state = OfflineState.INITIALIZING
        self.save_state()

        # Step 0: Configure route metrics (eth0 priority over wlan)
        logger.info("Step 0: Configuring route metrics (eth0 priority)...")
        self.configure_route_metrics()

        # Step 1: Check eth0 first and fix DHCP if needed
        logger.info("Step 1: Checking eth0 connectivity...")
        eth0_success, eth0_ip = self.fix_eth0_dhcp()
        if eth0_success and eth0_ip:
            logger.info(f"eth0 connected with IP: {eth0_ip}")
            self.state.wan_connected = True
            self.state.wan_ip = eth0_ip
            self.state.wan_ssid = None  # Ethernet, no SSID
        else:
            # Check WAN connectivity via any interface
            logger.info("Step 1b: Checking other WAN interfaces...")
            wan_iface, wan_ip = self.detect_wan_interface()
            if wan_iface and wan_ip:
                logger.info(f"WAN connected via {wan_iface}: {wan_ip}")
                self.state.wan_connected = True
                self.state.wan_ip = wan_ip
                if 'wlan' in wan_iface:
                    output, _ = self._run_command(["iwgetid", wan_iface, "-r"])
                    self.state.wan_ssid = output if output else None
            else:
                logger.info("No WAN connectivity detected")
                self.state.wan_connected = False

                # Check if wpa_supplicant has config (from Pi Imager)
                has_config, ssid = self.check_wpa_supplicant_configured()
                if has_config:
                    logger.info(f"wpa_supplicant configured for '{ssid}' but not connected")
                    logger.info("Will start AP first, user can connect upstream via web UI")

        # Step 2: Scan RF environment
        logger.info("Step 2: Scanning RF environment for optimal channel...")
        channel, score, networks = self.scan_and_select_channel()
        logger.info(f"Scan complete: {networks} networks, best channel: {channel} (score: {score:.1f})")

        # Step 3: Generate and write hostapd config
        logger.info("Step 3: Configuring access point...")
        config = self.generate_hostapd_config(channel)
        if not self.write_hostapd_config(config):
            self.state.state = OfflineState.ERROR
            self.state.error_message = "Failed to write hostapd configuration"
            self.save_state()
            return False

        # Step 4: Setup bridge interface
        logger.info("Step 4: Setting up bridge interface...")
        self._setup_bridge()

        # Step 5: Start AP
        logger.info("Step 5: Starting access point...")
        if not self.start_ap():
            self.state.state = OfflineState.ERROR
            self.state.error_message = "Failed to start hostapd"
            self.save_state()
            return False

        # Step 6: Start DHCP
        logger.info("Step 6: Starting DHCP server...")
        self.start_dhcp()

        # Step 7: Set final state
        if self.state.wan_connected:
            self.state.state = OfflineState.ONLINE
            logger.info("Guardian is ONLINE with full connectivity")
        else:
            self.state.state = OfflineState.OFFLINE_READY
            logger.info("Guardian is OFFLINE but AP is ready for clients")
            logger.info(f"Connect to '{self.state.ap_ssid}' and visit http://{self.config.ap_ip}")

        self.save_state()

        logger.info("=" * 60)
        logger.info(f"Initialization complete - State: {self.state.state.value}")
        logger.info(f"AP SSID: {self.state.ap_ssid}")
        logger.info(f"Channel: {self.state.current_channel} ({self.state.current_band})")
        logger.info(f"IP: {self.config.ap_ip}")
        logger.info("=" * 60)

        return True

    def _setup_bridge(self):
        """Setup bridge interface if not exists"""
        # Check if br0 exists
        output, _ = self._run_command(
            ["ip", "link", "show", "br0"], suppress_stderr=True
        )
        if not output:
            # Create bridge
            # Calculate prefix length from netmask
            prefix_len = self.config.ap_netmask.count('255') * 8 + 5
            self._run_command(["sudo", "ip", "link", "add", "name", "br0", "type", "bridge"])
            self._run_command([
                "sudo", "ip", "addr", "add",
                f"{self.config.ap_ip}/{prefix_len}", "dev", "br0"
            ])
            self._run_command(["sudo", "ip", "link", "set", "br0", "up"])
            logger.info("Created bridge interface br0")
        else:
            # Ensure it's up
            self._run_command(["sudo", "ip", "link", "set", "br0", "up"])

    # =========================================================================
    # UPSTREAM CONNECTION
    # =========================================================================

    def connect_upstream(self, ssid: str, password: str) -> Tuple[bool, str]:
        """
        Connect to upstream WiFi network.

        Called from web UI when user configures upstream connection.
        """
        self.state.state = OfflineState.CONNECTING_WAN
        self.save_state()

        logger.info(f"Attempting to connect to upstream network: {ssid}")

        # Determine WAN interface
        wan_iface = self.config.wan_interface
        if wan_iface == self.config.ap_interface:
            # If only one WiFi interface, we need to use a different approach
            # This is a limitation - need two interfaces for simultaneous AP + client
            logger.warning("Single WiFi interface mode - cannot do simultaneous AP + upstream")
            wan_iface = self.config.fallback_wan_interface

        # Create wpa_supplicant config
        wpa_config = f"""ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=US

network={{
    ssid="{ssid}"
    psk="{password}"
    key_mgmt=WPA-PSK
}}
"""

        try:
            # Write config
            temp_path = "/tmp/wpa_supplicant_upstream.conf"
            with open(temp_path, 'w') as f:
                f.write(wpa_config)

            # If using Ethernet, just check connectivity
            if 'eth' in wan_iface:
                # Bring up interface
                self._run_command(["sudo", "ip", "link", "set", wan_iface, "up"])
                self._run_command(["sudo", "dhclient", wan_iface])
            else:
                # For WiFi, use wpa_supplicant
                self._run_command([
                    "sudo", "wpa_supplicant", "-B", "-i", wan_iface, "-c", temp_path
                ])
                time.sleep(2)
                self._run_command(["sudo", "dhclient", wan_iface])

            # Wait and check connectivity
            time.sleep(5)

            if self.check_wan_connectivity():
                wan_status = self.get_wan_status()
                self.state.wan_connected = True
                self.state.wan_ip = wan_status.get('ip')
                self.state.wan_ssid = ssid
                self.state.state = OfflineState.ONLINE

                # Enable NAT
                self._enable_nat(wan_iface)

                self.save_state()
                logger.info(f"Connected to upstream: {ssid}, IP: {self.state.wan_ip}")
                return True, f"Connected to {ssid}"
            else:
                self.state.state = OfflineState.OFFLINE_READY
                self.save_state()
                return False, "Connection failed - network unreachable"

        except Exception as e:
            logger.error(f"Upstream connection failed: {e}")
            self.state.state = OfflineState.OFFLINE_READY
            self.state.error_message = str(e)
            self.save_state()
            return False, str(e)

    def _enable_nat(self, wan_interface: str):
        """Enable NAT for internet sharing"""
        # Enable IP forwarding
        self._run_command(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"])

        # Setup iptables NAT
        self._run_command([
            "sudo", "iptables", "-t", "nat", "-A", "POSTROUTING",
            "-o", wan_interface, "-j", "MASQUERADE"
        ])
        self._run_command([
            "sudo", "iptables", "-A", "FORWARD",
            "-i", "br0", "-o", wan_interface, "-j", "ACCEPT"
        ])
        self._run_command([
            "sudo", "iptables", "-A", "FORWARD",
            "-i", wan_interface, "-o", "br0",
            "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"
        ])

        logger.info(f"NAT enabled for {wan_interface}")

    # =========================================================================
    # STATUS AND MONITORING
    # =========================================================================

    def get_status(self) -> Dict:
        """Get comprehensive status for web UI"""
        self.state.uptime_seconds = int(time.time() - self._start_time)

        # Count connected clients using helper method
        self.state.clients_connected = self._count_arp_entries("br0")

        return {
            'state': self.state.state.value,
            'ap': {
                'running': self.state.ap_running,
                'ssid': self.state.ap_ssid,
                'channel': self.state.current_channel,
                'band': self.state.current_band,
                'ip': self.config.ap_ip,
                'clients': self.state.clients_connected
            },
            'wan': {
                'connected': self.state.wan_connected,
                'ssid': self.state.wan_ssid,
                'ip': self.state.wan_ip
            },
            'scan': {
                'last_scan': self.state.last_scan_time,
                'networks_detected': self.state.networks_detected,
                'channel_score': self.state.last_channel_score
            },
            'uptime': self.state.uptime_seconds,
            'error': self.state.error_message
        }

    def rescan_if_needed(self) -> bool:
        """Check if channel rescan is needed due to congestion"""
        if not self.state.last_scan_time:
            return True

        # Check time since last scan
        try:
            last_scan = datetime.fromisoformat(self.state.last_scan_time)
            elapsed = (datetime.now() - last_scan).total_seconds()

            if elapsed > self.config.auto_channel_rescan_interval:
                return True

            if self.state.last_channel_score > self.config.congestion_threshold:
                return True
        except Exception:
            return True

        return False


# CLI interface
if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    parser = argparse.ArgumentParser(description="Guardian Offline Mode Manager")
    parser.add_argument('command', choices=['init', 'status', 'scan', 'connect'],
                        help='Command to execute')
    parser.add_argument('--ssid', help='SSID for connect command')
    parser.add_argument('--password', help='Password for connect command')
    parser.add_argument('--json', action='store_true', help='JSON output')

    args = parser.parse_args()

    manager = OfflineModeManager()

    if args.command == 'init':
        success = manager.initialize_offline_mode()
        if args.json:
            print(json.dumps({'success': success, 'status': manager.get_status()}))

    elif args.command == 'status':
        status = manager.get_status()
        if args.json:
            print(json.dumps(status, indent=2))
        else:
            print(f"State: {status['state']}")
            print(f"AP Running: {status['ap']['running']}")
            print(f"AP SSID: {status['ap']['ssid']}")
            print(f"Channel: {status['ap']['channel']} ({status['ap']['band']})")
            print(f"Clients: {status['ap']['clients']}")
            print(f"WAN Connected: {status['wan']['connected']}")
            if status['wan']['connected']:
                print(f"WAN SSID: {status['wan']['ssid']}")
                print(f"WAN IP: {status['wan']['ip']}")

    elif args.command == 'scan':
        channel, score, networks = manager.scan_and_select_channel()
        if args.json:
            print(json.dumps({
                'recommended_channel': channel,
                'score': score,
                'networks_detected': networks
            }))
        else:
            print(f"Recommended Channel: {channel}")
            print(f"Score: {score:.1f}")
            print(f"Networks Detected: {networks}")

    elif args.command == 'connect':
        if not args.ssid:
            print("Error: --ssid required for connect command")
            exit(1)
        success, message = manager.connect_upstream(args.ssid, args.password or "")
        if args.json:
            print(json.dumps({'success': success, 'message': message}))
        else:
            print(message)
