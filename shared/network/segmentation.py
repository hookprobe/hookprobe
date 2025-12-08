"""
Network Segmentation Module

Provides VLAN-based network segmentation using nftables for firewall rules,
traffic isolation, and inter-VLAN routing policies.

Guardian uses Bridge LAN port for wired WAN with dynamic VLAN assignment
based on MAC address. Unknown devices are automatically quarantined to VLAN 999.
FreeRADIUS queries Django API for VLAN lookup.

Pre-configured VLANs:
- VLAN 10: Smart Lights
- VLAN 20: Thermostats
- VLAN 30: Cameras
- VLAN 40: Voice Assistants
- VLAN 50: Appliances
- VLAN 60: Entertainment
- VLAN 70: Robots
- VLAN 80: Sensors
- VLAN 999: Quarantine

Author: HookProbe Team
Version: 5.0.0 Liberty
License: AGPL-3.0 - see LICENSE file
"""

import asyncio
import logging
import subprocess
import json
import re
import os
from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from collections import defaultdict
import ipaddress
import time

logger = logging.getLogger(__name__)


class VLANCategory(IntEnum):
    """
    VLAN categories for IoT device network segmentation

    Guardian dynamically assigns devices to VLANs based on MAC address.
    Unknown devices are automatically placed in QUARANTINE (999).
    """
    SMART_LIGHTS = 10
    THERMOSTATS = 20
    CAMERAS = 30
    VOICE_ASSISTANTS = 40
    APPLIANCES = 50
    ENTERTAINMENT = 60
    ROBOTS = 70
    SENSORS = 80
    QUARANTINE = 999


class SecurityZone(IntEnum):
    """Security zones for policy enforcement"""
    INTERNET = 0
    IOT_TRUSTED = 1      # Devices that need cloud access
    IOT_LOCAL = 2        # Devices that only need local access
    IOT_RESTRICTED = 3   # Devices with limited connectivity
    QUARANTINE = 4       # Unknown/untrusted devices
    MANAGEMENT = 5       # Guardian management interface


class TrafficAction(IntEnum):
    """Traffic action types"""
    ACCEPT = 0
    DROP = 1
    REJECT = 2
    LOG = 3
    RATE_LIMIT = 4
    REDIRECT = 5
    MARK = 6


@dataclass
class VLANConfig:
    """VLAN configuration"""
    vlan_id: int
    name: str
    category: VLANCategory
    subnet: str  # CIDR notation
    gateway: str
    dhcp_range: Optional[Tuple[str, str]] = None
    dns_servers: List[str] = field(default_factory=list)
    security_zone: SecurityZone = SecurityZone.IOT_LOCAL
    internet_access: bool = True
    inter_vlan_allowed: Set[int] = field(default_factory=set)
    rate_limit_mbps: Optional[int] = None
    max_connections: Optional[int] = None
    description: str = ""


@dataclass
class FirewallRule:
    """Firewall rule definition"""
    name: str
    chain: str = "forward"
    table: str = "filter"
    family: str = "inet"
    priority: int = 0
    source_vlan: Optional[int] = None
    dest_vlan: Optional[int] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[Union[int, str]] = None
    dest_port: Optional[Union[int, str]] = None
    protocol: Optional[str] = None
    action: TrafficAction = TrafficAction.ACCEPT
    log: bool = False
    log_prefix: str = ""
    rate_limit: Optional[str] = None  # e.g., "100/second"
    counter: bool = True
    comment: str = ""


@dataclass
class SegmentationPolicy:
    """Network segmentation policy"""
    name: str
    source_zones: Set[SecurityZone]
    dest_zones: Set[SecurityZone]
    allowed_services: List[str] = field(default_factory=list)
    denied_services: List[str] = field(default_factory=list)
    action: TrafficAction = TrafficAction.DROP
    log_violations: bool = True


# MAC OUI prefixes for common IoT manufacturers
IOT_VENDOR_VLANS = {
    # Smart Lights (VLAN 10)
    'b4:e6:2d': VLANCategory.SMART_LIGHTS,  # Philips Hue
    'ec:b5:fa': VLANCategory.SMART_LIGHTS,  # Philips Hue
    '00:17:88': VLANCategory.SMART_LIGHTS,  # Philips Lighting
    'b0:ce:18': VLANCategory.SMART_LIGHTS,  # LIFX
    'd0:73:d5': VLANCategory.SMART_LIGHTS,  # LIFX
    '94:10:3e': VLANCategory.SMART_LIGHTS,  # Belkin WeMo
    'ec:1a:59': VLANCategory.SMART_LIGHTS,  # Belkin

    # Thermostats (VLAN 20)
    '18:b4:30': VLANCategory.THERMOSTATS,   # Nest
    '64:16:66': VLANCategory.THERMOSTATS,   # Nest
    'f4:f5:d8': VLANCategory.THERMOSTATS,   # Google Nest
    '44:61:32': VLANCategory.THERMOSTATS,   # ecobee
    '00:d0:2d': VLANCategory.THERMOSTATS,   # Honeywell
    '5c:aa:fd': VLANCategory.THERMOSTATS,   # Sonoff

    # Cameras (VLAN 30)
    '9c:8e:cd': VLANCategory.CAMERAS,       # Amcrest
    'e8:ab:fa': VLANCategory.CAMERAS,       # Shenzhen Bilian
    '28:6c:07': VLANCategory.CAMERAS,       # XIAOMI
    '74:da:38': VLANCategory.CAMERAS,       # Edimax
    '00:62:6e': VLANCategory.CAMERAS,       # Dahua
    '3c:ef:8c': VLANCategory.CAMERAS,       # Ring
    'b0:09:da': VLANCategory.CAMERAS,       # Ring
    '00:18:dd': VLANCategory.CAMERAS,       # Hikvision
    'c0:56:e3': VLANCategory.CAMERAS,       # Hikvision

    # Voice Assistants (VLAN 40)
    'f0:f6:1c': VLANCategory.VOICE_ASSISTANTS,  # Amazon Echo
    '74:c2:46': VLANCategory.VOICE_ASSISTANTS,  # Amazon Echo
    'a4:08:ea': VLANCategory.VOICE_ASSISTANTS,  # Amazon Echo
    'fc:65:de': VLANCategory.VOICE_ASSISTANTS,  # Amazon Echo
    '48:d6:d5': VLANCategory.VOICE_ASSISTANTS,  # Google Home
    'f4:f5:d8': VLANCategory.VOICE_ASSISTANTS,  # Google Home
    '54:60:09': VLANCategory.VOICE_ASSISTANTS,  # Google Home
    '30:52:cb': VLANCategory.VOICE_ASSISTANTS,  # Google Home
    'b8:27:eb': VLANCategory.VOICE_ASSISTANTS,  # Raspberry Pi (HomePod)
    '00:25:00': VLANCategory.VOICE_ASSISTANTS,  # Apple

    # Appliances (VLAN 50)
    '50:dc:e7': VLANCategory.APPLIANCES,    # Amazon (smart plug)
    'cc:50:e3': VLANCategory.APPLIANCES,    # Amazon
    '68:54:fd': VLANCategory.APPLIANCES,    # Amazon
    'b4:7c:9c': VLANCategory.APPLIANCES,    # Amazon
    '38:f7:3d': VLANCategory.APPLIANCES,    # Amazon
    'ac:63:be': VLANCategory.APPLIANCES,    # Amazon
    '00:fc:8b': VLANCategory.APPLIANCES,    # Amazon
    '7c:61:66': VLANCategory.APPLIANCES,    # LG Electronics
    'a8:23:fe': VLANCategory.APPLIANCES,    # Samsung
    'bc:8c:cd': VLANCategory.APPLIANCES,    # Samsung
    'e4:7c:f9': VLANCategory.APPLIANCES,    # Samsung
    '78:ab:bb': VLANCategory.APPLIANCES,    # Samsung
    '84:25:db': VLANCategory.APPLIANCES,    # Samsung

    # Entertainment (VLAN 60)
    '70:ee:50': VLANCategory.ENTERTAINMENT, # Netatmo
    '00:04:4b': VLANCategory.ENTERTAINMENT, # Roku
    'ac:3a:7a': VLANCategory.ENTERTAINMENT, # Roku
    'd8:31:34': VLANCategory.ENTERTAINMENT, # Roku
    'b8:3e:59': VLANCategory.ENTERTAINMENT, # Roku
    'b0:a7:37': VLANCategory.ENTERTAINMENT, # Roku
    'dc:a6:32': VLANCategory.ENTERTAINMENT, # Roku
    '00:0d:4b': VLANCategory.ENTERTAINMENT, # Roku
    '08:05:81': VLANCategory.ENTERTAINMENT, # Roku
    '84:ea:ed': VLANCategory.ENTERTAINMENT, # Roku
    'c8:3a:6b': VLANCategory.ENTERTAINMENT, # Roku
    'd4:e2:2f': VLANCategory.ENTERTAINMENT, # Roku
    '5c:aa:fd': VLANCategory.ENTERTAINMENT, # Sonos
    '00:0e:58': VLANCategory.ENTERTAINMENT, # Sonos
    '94:9f:3e': VLANCategory.ENTERTAINMENT, # Sonos
    'b8:e9:37': VLANCategory.ENTERTAINMENT, # Sonos
    '78:28:ca': VLANCategory.ENTERTAINMENT, # Sonos
    '48:a6:b8': VLANCategory.ENTERTAINMENT, # Sonos
    '54:2a:1b': VLANCategory.ENTERTAINMENT, # Sonos
    '34:7e:5c': VLANCategory.ENTERTAINMENT, # Sonos
    'f0:f6:c1': VLANCategory.ENTERTAINMENT, # Sonos
    '7c:64:56': VLANCategory.ENTERTAINMENT, # Samsng TV

    # Robots (VLAN 70)
    '50:14:79': VLANCategory.ROBOTS,        # iRobot Roomba
    '70:66:55': VLANCategory.ROBOTS,        # iRobot Roomba
    '80:c5:f2': VLANCategory.ROBOTS,        # iRobot
    '74:f6:1c': VLANCategory.ROBOTS,        # iRobot
    'd4:6e:0e': VLANCategory.ROBOTS,        # TP-Link (robot vacuums)
    '60:a4:4c': VLANCategory.ROBOTS,        # TP-Link
    'b0:be:76': VLANCategory.ROBOTS,        # TP-Link
    '98:da:c4': VLANCategory.ROBOTS,        # TP-Link
    '50:c7:bf': VLANCategory.ROBOTS,        # TP-Link

    # Sensors (VLAN 80)
    '00:0b:57': VLANCategory.SENSORS,       # Silicon Labs (Zigbee)
    '84:71:27': VLANCategory.SENSORS,       # Silicon Labs
    '00:12:4b': VLANCategory.SENSORS,       # Texas Instruments (Z-Wave)
    '18:b4:30': VLANCategory.SENSORS,       # Nest Protect
    '64:16:66': VLANCategory.SENSORS,       # Nest Protect
    'ac:cf:85': VLANCategory.SENSORS,       # HUAWEI IoT
    'd8:f1:5b': VLANCategory.SENSORS,       # Espressif (ESP8266/ESP32)
    '24:62:ab': VLANCategory.SENSORS,       # Espressif
    '5c:cf:7f': VLANCategory.SENSORS,       # Espressif
    '60:01:94': VLANCategory.SENSORS,       # Espressif
    'a4:cf:12': VLANCategory.SENSORS,       # Espressif
    'bc:dd:c2': VLANCategory.SENSORS,       # Espressif
    'cc:50:e3': VLANCategory.SENSORS,       # Espressif
    '2c:f4:32': VLANCategory.SENSORS,       # Espressif
    '68:c6:3a': VLANCategory.SENSORS,       # Espressif
    '84:cc:a8': VLANCategory.SENSORS,       # Espressif
    '30:ae:a4': VLANCategory.SENSORS,       # Espressif
    '24:0a:c4': VLANCategory.SENSORS,       # Espressif
    '3c:71:bf': VLANCategory.SENSORS,       # Espressif
    'ac:67:b2': VLANCategory.SENSORS,       # Espressif
}


class NFTablesManager:
    """
    nftables firewall management for network segmentation

    Provides programmatic control over nftables for VLAN isolation,
    traffic policies, and security enforcement.
    """

    def __init__(self, table_name: str = "guardian"):
        self.table_name = table_name
        self.family = "inet"  # IPv4 and IPv6

        # VLAN configurations
        self.vlans: Dict[int, VLANConfig] = {}

        # Active rules
        self.rules: List[FirewallRule] = []

        # Policies
        self.policies: List[SegmentationPolicy] = []

        # Statistics
        self.stats = {
            'rules_installed': 0,
            'rules_removed': 0,
            'packets_dropped': 0,
            'packets_logged': 0,
            'policy_violations': 0
        }

        # nftables availability
        self._nft_available = None

        logger.info(f"NFTables Manager initialized with table '{table_name}'")

    async def _check_nftables(self) -> bool:
        """Check if nftables is available"""
        if self._nft_available is not None:
            return self._nft_available

        try:
            proc = await asyncio.create_subprocess_exec(
                'nft', '--version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.wait()
            self._nft_available = proc.returncode == 0
        except FileNotFoundError:
            self._nft_available = False

        if not self._nft_available:
            logger.warning("nftables not available")

        return self._nft_available

    async def _run_nft(self, *args) -> Tuple[int, str, str]:
        """Run nft command"""
        try:
            proc = await asyncio.create_subprocess_exec(
                'nft', *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            return proc.returncode, stdout.decode(), stderr.decode()
        except Exception as e:
            logger.error(f"nft command failed: {e}")
            return -1, "", str(e)

    async def initialize(self) -> bool:
        """Initialize nftables table and base chains"""
        if not await self._check_nftables():
            return False

        # Create main table
        rules = f"""
table {self.family} {self.table_name} {{
    # Connection tracking
    chain prerouting {{
        type filter hook prerouting priority -300; policy accept;
        ct state invalid drop
    }}

    # Input chain - traffic to Guardian itself
    chain input {{
        type filter hook input priority 0; policy drop;

        # Allow established connections
        ct state established,related accept

        # Allow loopback
        iif lo accept

        # Allow ICMP
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        # Allow SSH from any VLAN (for management)
        tcp dport 22 accept

        # Allow RADIUS
        udp dport {{ 1812, 1813 }} accept

        # Allow HTP (HookProbe Transport Protocol)
        udp dport 4719 accept

        # Allow OpenFlow
        tcp dport {{ 6633, 6653 }} accept

        # Allow web interface
        tcp dport {{ 80, 443, 8080 }} accept

        # Allow DHCP server
        udp dport {{ 67, 68 }} accept

        # Allow DNS
        udp dport 53 accept
        tcp dport 53 accept

        # Log dropped packets
        log prefix "[GUARDIAN-INPUT-DROP] " limit rate 10/minute
        drop
    }}

    # Forward chain - inter-VLAN traffic (default DROP for isolation)
    chain forward {{
        type filter hook forward priority 0; policy drop;

        # Allow established connections
        ct state established,related accept

        # Jump to threat response first
        jump threat_response

        # Jump to rate limiting
        jump rate_limit

        # Inter-VLAN rules - by default all inter-VLAN traffic is BLOCKED
        jump inter_vlan

        # Allow internet access for permitted VLANs
        jump internet_access

        # Default policy - DROP all inter-VLAN traffic
        log prefix "[GUARDIAN-INTER-VLAN-DROP] " limit rate 10/minute
        drop
    }}

    # Output chain - traffic from Guardian
    chain output {{
        type filter hook output priority 0; policy accept;
        accept
    }}

    # Postrouting - NAT for internet access
    chain postrouting {{
        type nat hook postrouting priority 100; policy accept;

        # Masquerade for internet access via WAN (eth0)
        oifname "eth0" masquerade
    }}

    # Inter-VLAN routing chain - EMPTY by default (all blocked)
    chain inter_vlan {{
        # By design, no inter-VLAN traffic is allowed
        # Rules can be added dynamically for specific use cases
    }}

    # Internet access chain
    chain internet_access {{
        # Rules for VLANs that can access internet
    }}

    # Rate limiting chain
    chain rate_limit {{
        # Per-VLAN rate limiting
    }}

    # Threat response chain
    chain threat_response {{
        # Threat-based blocking rules (highest priority)
    }}

    # Quarantine chain - all traffic to/from VLAN 999
    chain quarantine {{
        # Only allow DHCP and DNS for quarantined devices
        ip saddr 10.0.99.0/24 udp dport 53 accept
        ip saddr 10.0.99.0/24 udp dport 67 accept

        # Block all other quarantine traffic
        ip saddr 10.0.99.0/24 counter log prefix "[GUARDIAN-QUARANTINE-DROP] " drop
        ip daddr 10.0.99.0/24 counter log prefix "[GUARDIAN-QUARANTINE-DROP] " drop
    }}
}}
"""

        # Apply rules
        returncode, stdout, stderr = await self._run_nft('-f', '-', input=rules.encode())

        if returncode != 0:
            # Try to create just the table first
            await self._run_nft('add', 'table', self.family, self.table_name)

            # Then add chains individually
            chains = [
                ('prerouting', 'filter', 'prerouting', '-300', 'accept'),
                ('input', 'filter', 'input', '0', 'drop'),
                ('forward', 'filter', 'forward', '0', 'drop'),
                ('output', 'filter', 'output', '0', 'accept'),
                ('postrouting', 'nat', 'postrouting', '100', 'accept'),
            ]

            for chain_name, chain_type, hook, priority, policy in chains:
                await self._run_nft(
                    'add', 'chain', self.family, self.table_name, chain_name,
                    f'{{ type {chain_type} hook {hook} priority {priority}; policy {policy}; }}'
                )

            # Add custom chains
            for chain in ['inter_vlan', 'internet_access', 'rate_limit', 'threat_response', 'quarantine']:
                await self._run_nft('add', 'chain', self.family, self.table_name, chain)

            logger.info("nftables base structure created")
            return True

        logger.info("nftables initialized with base ruleset - inter-VLAN traffic blocked by default")
        return True

    async def add_vlan(self, config: VLANConfig) -> bool:
        """Add VLAN configuration and rules"""
        self.vlans[config.vlan_id] = config

        if not await self._check_nftables():
            return False

        # Add rate limiting if configured
        if config.rate_limit_mbps:
            await self._add_rate_limit_rule(config.vlan_id, config.rate_limit_mbps)

        # Add internet access rule if enabled (quarantine never gets internet)
        if config.internet_access and config.vlan_id != VLANCategory.QUARANTINE:
            await self._add_internet_access_rule(config.vlan_id)

        # Note: Inter-VLAN rules are NOT added by default for isolation
        # Only explicitly allowed inter-VLAN communication is permitted

        logger.info(f"Added VLAN {config.vlan_id} ({config.name}) - inter-VLAN isolated")
        return True

    async def allow_inter_vlan(self, src_vlan: int, dst_vlan: int, bidirectional: bool = False):
        """
        Explicitly allow inter-VLAN communication (use sparingly)

        By default, all inter-VLAN traffic is blocked for security.
        Only enable specific flows when absolutely necessary.
        """
        src_config = self.vlans.get(src_vlan)
        dst_config = self.vlans.get(dst_vlan)

        if not src_config or not dst_config:
            logger.warning(f"Cannot allow inter-VLAN: VLAN {src_vlan} or {dst_vlan} not found")
            return False

        # Add forward rule
        rule = f"ip saddr {src_config.subnet} ip daddr {dst_config.subnet} accept"
        await self._run_nft(
            'add', 'rule', self.family, self.table_name, 'inter_vlan', rule
        )
        self.stats['rules_installed'] += 1

        if bidirectional:
            rule = f"ip saddr {dst_config.subnet} ip daddr {src_config.subnet} accept"
            await self._run_nft(
                'add', 'rule', self.family, self.table_name, 'inter_vlan', rule
            )
            self.stats['rules_installed'] += 1

        logger.warning(f"Inter-VLAN access enabled: VLAN {src_vlan} -> VLAN {dst_vlan}")
        return True

    async def _add_rate_limit_rule(self, vlan_id: int, mbps: int):
        """Add rate limiting for VLAN"""
        config = self.vlans.get(vlan_id)
        if not config:
            return

        # Add meter-based rate limit
        rule = f"ip saddr {config.subnet} limit rate over {mbps}mbytes/second drop"

        await self._run_nft(
            'add', 'rule', self.family, self.table_name, 'rate_limit', rule
        )

        logger.info(f"Rate limit {mbps} Mbps applied to VLAN {vlan_id}")

    async def _add_internet_access_rule(self, vlan_id: int):
        """Add internet access rule for VLAN"""
        config = self.vlans.get(vlan_id)
        if not config:
            return

        # Allow outbound to WAN interface (eth0)
        rule = f'ip saddr {config.subnet} oifname "eth0" accept'

        await self._run_nft(
            'add', 'rule', self.family, self.table_name, 'internet_access', rule
        )

        logger.info(f"Internet access enabled for VLAN {vlan_id}")

    async def add_rule(self, rule: FirewallRule) -> bool:
        """Add custom firewall rule"""
        if not await self._check_nftables():
            return False

        nft_rule = self._build_nft_rule(rule)

        returncode, stdout, stderr = await self._run_nft(
            'add', 'rule', self.family, self.table_name, rule.chain, nft_rule
        )

        if returncode == 0:
            self.rules.append(rule)
            self.stats['rules_installed'] += 1
            logger.info(f"Added firewall rule: {rule.name}")
            return True

        logger.error(f"Failed to add rule {rule.name}: {stderr}")
        return False

    def _build_nft_rule(self, rule: FirewallRule) -> str:
        """Build nftables rule string"""
        parts = []

        # Source matching
        if rule.source_vlan is not None:
            vlan_config = self.vlans.get(rule.source_vlan)
            if vlan_config:
                parts.append(f"ip saddr {vlan_config.subnet}")

        if rule.source_ip:
            parts.append(f"ip saddr {rule.source_ip}")

        # Destination matching
        if rule.dest_vlan is not None:
            vlan_config = self.vlans.get(rule.dest_vlan)
            if vlan_config:
                parts.append(f"ip daddr {vlan_config.subnet}")

        if rule.dest_ip:
            parts.append(f"ip daddr {rule.dest_ip}")

        # Protocol matching
        if rule.protocol:
            proto = rule.protocol.lower()
            if proto in ['tcp', 'udp', 'icmp']:
                parts.append(f"ip protocol {proto}")

            if rule.source_port:
                parts.append(f"{proto} sport {rule.source_port}")

            if rule.dest_port:
                parts.append(f"{proto} dport {rule.dest_port}")

        # Rate limiting
        if rule.rate_limit:
            parts.append(f"limit rate {rule.rate_limit}")

        # Counter
        if rule.counter:
            parts.append("counter")

        # Logging
        if rule.log:
            prefix = rule.log_prefix or f"[{rule.name}]"
            parts.append(f'log prefix "{prefix} "')

        # Action
        action_map = {
            TrafficAction.ACCEPT: "accept",
            TrafficAction.DROP: "drop",
            TrafficAction.REJECT: "reject",
            TrafficAction.LOG: "log",
        }
        parts.append(action_map.get(rule.action, "drop"))

        # Comment
        if rule.comment:
            parts.append(f'comment "{rule.comment}"')

        return " ".join(parts)

    async def block_ip(self, ip: str, reason: str = "threat", duration: int = 3600) -> bool:
        """Block an IP address"""
        if not await self._check_nftables():
            return False

        rule = f'ip saddr {ip} counter log prefix "[GUARDIAN-BLOCK] " drop comment "blocked: {reason}"'

        returncode, _, stderr = await self._run_nft(
            'add', 'rule', self.family, self.table_name, 'threat_response', rule
        )

        if returncode == 0:
            logger.warning(f"Blocked IP {ip}: {reason}")
            self.stats['policy_violations'] += 1
            return True

        return False

    async def block_mac(self, mac: str, reason: str = "threat") -> bool:
        """Block traffic from MAC address"""
        if not await self._check_nftables():
            return False

        # Normalize MAC format
        mac = mac.lower().replace('-', ':')

        rule = f'ether saddr {mac} counter log prefix "[GUARDIAN-MAC-BLOCK] " drop comment "blocked: {reason}"'

        returncode, _, stderr = await self._run_nft(
            'add', 'rule', self.family, self.table_name, 'threat_response', rule
        )

        if returncode == 0:
            logger.warning(f"Blocked MAC {mac}: {reason}")
            return True

        return False

    async def quarantine_device(self, ip: str, mac: Optional[str] = None, reason: str = "unknown"):
        """
        Move device to quarantine (VLAN 999)

        Quarantined devices can only access DHCP and DNS.
        """
        if not await self._check_nftables():
            return False

        # Mark packets for quarantine VLAN
        mark = VLANCategory.QUARANTINE

        rule = f'ip saddr {ip} meta mark set {mark} counter log prefix "[GUARDIAN-QUARANTINE] " comment "quarantine: {reason}"'

        returncode, _, stderr = await self._run_nft(
            'add', 'rule', self.family, self.table_name, 'threat_response', rule
        )

        if returncode == 0:
            logger.warning(f"Quarantined device {ip}: {reason}")
            return True

        return False

    async def unblock_ip(self, ip: str) -> bool:
        """Remove IP block"""
        if not await self._check_nftables():
            return False

        # Get handle for the rule
        returncode, stdout, stderr = await self._run_nft(
            '-a', 'list', 'chain', self.family, self.table_name, 'threat_response'
        )

        if returncode != 0:
            return False

        # Find and delete rule by IP
        for line in stdout.split('\n'):
            if ip in line and 'handle' in line:
                match = re.search(r'handle (\d+)', line)
                if match:
                    handle = match.group(1)
                    await self._run_nft(
                        'delete', 'rule', self.family, self.table_name,
                        'threat_response', 'handle', handle
                    )
                    logger.info(f"Unblocked IP {ip}")
                    return True

        return False

    async def get_statistics(self) -> Dict[str, Any]:
        """Get firewall statistics"""
        if not await self._check_nftables():
            return self.stats

        # Get counter values
        returncode, stdout, stderr = await self._run_nft(
            '-j', 'list', 'table', self.family, self.table_name
        )

        if returncode == 0:
            try:
                data = json.loads(stdout)
                # Parse counters from JSON output
            except json.JSONDecodeError:
                pass

        return {
            'nftables': self.stats.copy(),
            'vlans': {
                vid: {
                    'name': cfg.name,
                    'subnet': cfg.subnet,
                    'zone': cfg.security_zone.name,
                    'internet_access': cfg.internet_access,
                    'rate_limit_mbps': cfg.rate_limit_mbps
                }
                for vid, cfg in self.vlans.items()
            },
            'rules_count': len(self.rules),
            'policies_count': len(self.policies),
            'inter_vlan_isolation': True
        }

    async def export_rules(self) -> str:
        """Export current ruleset"""
        if not await self._check_nftables():
            return ""

        returncode, stdout, stderr = await self._run_nft(
            'list', 'table', self.family, self.table_name
        )

        return stdout if returncode == 0 else ""

    async def flush_rules(self) -> bool:
        """Flush all rules from table"""
        if not await self._check_nftables():
            return False

        returncode, _, _ = await self._run_nft(
            'flush', 'table', self.family, self.table_name
        )

        if returncode == 0:
            self.rules.clear()
            self.stats['rules_removed'] += self.stats['rules_installed']
            self.stats['rules_installed'] = 0
            logger.info("Flushed all firewall rules")
            return True

        return False


def get_vlan_for_mac(mac: str) -> int:
    """
    Get VLAN assignment for MAC address based on vendor OUI

    Unknown devices are assigned to QUARANTINE (999).
    FreeRADIUS should also query Django API for custom mappings.
    """
    mac = mac.lower().replace('-', ':')
    oui = mac[:8]  # First 3 octets (XX:XX:XX)

    vlan = IOT_VENDOR_VLANS.get(oui)
    if vlan:
        return vlan

    # Unknown device - quarantine
    logger.info(f"Unknown MAC {mac} (OUI: {oui}) -> QUARANTINE (VLAN 999)")
    return VLANCategory.QUARANTINE


class NetworkSegmentation:
    """
    High-level network segmentation service

    Provides IoT device isolation using VLANs with nftables enforcement.
    All inter-VLAN traffic is blocked by default. Unknown devices are
    automatically quarantined to VLAN 999.
    """

    def __init__(self, table_name: str = "guardian"):
        self.nft = NFTablesManager(table_name)

        # IoT Device VLANs - fully isolated by default
        self._default_vlans = [
            VLANConfig(
                vlan_id=VLANCategory.SMART_LIGHTS,
                name="Smart Lights",
                category=VLANCategory.SMART_LIGHTS,
                subnet="10.0.10.0/24",
                gateway="10.0.10.1",
                dhcp_range=("10.0.10.100", "10.0.10.250"),
                dns_servers=["10.0.10.1"],
                security_zone=SecurityZone.IOT_TRUSTED,
                internet_access=True,  # Needs cloud connectivity
                rate_limit_mbps=10,
                description="Philips Hue, LIFX, smart bulbs"
            ),
            VLANConfig(
                vlan_id=VLANCategory.THERMOSTATS,
                name="Thermostats",
                category=VLANCategory.THERMOSTATS,
                subnet="10.0.20.0/24",
                gateway="10.0.20.1",
                dhcp_range=("10.0.20.100", "10.0.20.250"),
                dns_servers=["10.0.20.1"],
                security_zone=SecurityZone.IOT_TRUSTED,
                internet_access=True,  # Needs cloud connectivity
                rate_limit_mbps=5,
                description="Nest, ecobee, Honeywell thermostats"
            ),
            VLANConfig(
                vlan_id=VLANCategory.CAMERAS,
                name="Cameras",
                category=VLANCategory.CAMERAS,
                subnet="10.0.30.0/24",
                gateway="10.0.30.1",
                dhcp_range=("10.0.30.100", "10.0.30.250"),
                dns_servers=["10.0.30.1"],
                security_zone=SecurityZone.IOT_RESTRICTED,
                internet_access=True,  # Limited - cloud upload only
                rate_limit_mbps=50,  # Higher for video streams
                max_connections=100,
                description="Security cameras, video doorbells"
            ),
            VLANConfig(
                vlan_id=VLANCategory.VOICE_ASSISTANTS,
                name="Voice Assistants",
                category=VLANCategory.VOICE_ASSISTANTS,
                subnet="10.0.40.0/24",
                gateway="10.0.40.1",
                dhcp_range=("10.0.40.100", "10.0.40.250"),
                dns_servers=["10.0.40.1"],
                security_zone=SecurityZone.IOT_TRUSTED,
                internet_access=True,  # Needs cloud connectivity
                rate_limit_mbps=20,
                description="Amazon Echo, Google Home, HomePod"
            ),
            VLANConfig(
                vlan_id=VLANCategory.APPLIANCES,
                name="Appliances",
                category=VLANCategory.APPLIANCES,
                subnet="10.0.50.0/24",
                gateway="10.0.50.1",
                dhcp_range=("10.0.50.100", "10.0.50.250"),
                dns_servers=["10.0.50.1"],
                security_zone=SecurityZone.IOT_LOCAL,
                internet_access=True,  # For firmware updates
                rate_limit_mbps=10,
                description="Smart plugs, washers, refrigerators"
            ),
            VLANConfig(
                vlan_id=VLANCategory.ENTERTAINMENT,
                name="Entertainment",
                category=VLANCategory.ENTERTAINMENT,
                subnet="10.0.60.0/24",
                gateway="10.0.60.1",
                dhcp_range=("10.0.60.100", "10.0.60.250"),
                dns_servers=["10.0.60.1"],
                security_zone=SecurityZone.IOT_TRUSTED,
                internet_access=True,  # Streaming services
                rate_limit_mbps=100,  # High for streaming
                description="Roku, Sonos, smart TVs"
            ),
            VLANConfig(
                vlan_id=VLANCategory.ROBOTS,
                name="Robots",
                category=VLANCategory.ROBOTS,
                subnet="10.0.70.0/24",
                gateway="10.0.70.1",
                dhcp_range=("10.0.70.100", "10.0.70.250"),
                dns_servers=["10.0.70.1"],
                security_zone=SecurityZone.IOT_LOCAL,
                internet_access=True,  # For maps/updates
                rate_limit_mbps=10,
                description="iRobot Roomba, robot vacuums"
            ),
            VLANConfig(
                vlan_id=VLANCategory.SENSORS,
                name="Sensors",
                category=VLANCategory.SENSORS,
                subnet="10.0.80.0/24",
                gateway="10.0.80.1",
                dhcp_range=("10.0.80.100", "10.0.80.250"),
                dns_servers=["10.0.80.1"],
                security_zone=SecurityZone.IOT_LOCAL,
                internet_access=False,  # Local only
                rate_limit_mbps=1,
                description="Motion sensors, door sensors, ESP devices"
            ),
            VLANConfig(
                vlan_id=VLANCategory.QUARANTINE,
                name="Quarantine",
                category=VLANCategory.QUARANTINE,
                subnet="10.0.99.0/24",
                gateway="10.0.99.1",
                dhcp_range=("10.0.99.100", "10.0.99.250"),
                dns_servers=["10.0.99.1"],
                security_zone=SecurityZone.QUARANTINE,
                internet_access=False,  # NO internet access
                rate_limit_mbps=1,
                description="Unknown/untrusted devices - isolated"
            ),
        ]

        logger.info("Network Segmentation Service initialized - inter-VLAN isolation enabled")

    async def initialize(self, use_defaults: bool = True) -> bool:
        """Initialize segmentation service with full VLAN isolation"""
        # Initialize nftables
        if not await self.nft.initialize():
            return False

        if use_defaults:
            # Add all IoT VLANs
            for vlan in self._default_vlans:
                await self.nft.add_vlan(vlan)

        logger.info("Network segmentation initialized - all VLANs isolated")
        return True

    async def add_vlan(self, config: VLANConfig) -> bool:
        """Add new VLAN (isolated by default)"""
        return await self.nft.add_vlan(config)

    async def allow_inter_vlan(self, src_vlan: int, dst_vlan: int, bidirectional: bool = False) -> bool:
        """Explicitly allow inter-VLAN communication (use with caution)"""
        return await self.nft.allow_inter_vlan(src_vlan, dst_vlan, bidirectional)

    async def block_threat(self, ip: str, mac: Optional[str] = None, reason: str = "threat"):
        """Block threat by IP and optionally MAC"""
        await self.nft.block_ip(ip, reason)
        if mac:
            await self.nft.block_mac(mac, reason)

    async def quarantine_device(self, ip: str, mac: Optional[str] = None, reason: str = "unknown"):
        """Move device to quarantine VLAN 999"""
        await self.nft.quarantine_device(ip, mac, reason)

    async def release_device(self, ip: str):
        """Release device from quarantine/block"""
        await self.nft.unblock_ip(ip)

    async def get_status(self) -> Dict[str, Any]:
        """Get segmentation status"""
        return await self.nft.get_statistics()

    def get_vlan_for_mac(self, mac: str) -> int:
        """Get VLAN assignment for MAC (unknown -> QUARANTINE)"""
        return get_vlan_for_mac(mac)


# Predefined service ports for policy configuration
SERVICE_PORTS = {
    'ssh': ('tcp', 22),
    'http': ('tcp', 80),
    'https': ('tcp', 443),
    'dns': ('udp', 53),
    'dhcp': ('udp', '67-68'),
    'ntp': ('udp', 123),
    'mqtt': ('tcp', 1883),
    'mqtts': ('tcp', 8883),
    'coap': ('udp', 5683),
    'coaps': ('udp', 5684),
    'rtsp': ('tcp', 554),
    'hue': ('tcp', 80),
    'homekit': ('tcp', 51827),
    'matter': ('udp', 5540),
    'zigbee': ('tcp', 8080),
    'zwave': ('tcp', 4200),
    'radius_auth': ('udp', 1812),
    'radius_acct': ('udp', 1813),
    'htp': ('udp', 4719),
    'openflow': ('tcp', '6633,6653'),
}


# Export classes
__all__ = [
    'NFTablesManager',
    'NetworkSegmentation',
    'VLANConfig',
    'FirewallRule',
    'SegmentationPolicy',
    'VLANCategory',
    'SecurityZone',
    'TrafficAction',
    'SERVICE_PORTS',
    'IOT_VENDOR_VLANS',
    'get_vlan_for_mac'
]
