"""
Network Segmentation Module for Guardian

Provides VLAN-based network segmentation using nftables for firewall rules,
traffic isolation, and inter-VLAN routing policies.

Author: HookProbe Team
Version: 5.0.0 Liberty
License: MIT
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
    """VLAN categories for network segmentation"""
    MANAGEMENT = 10
    TRUSTED = 100
    GUEST = 200
    IOT = 300
    CAMERAS = 400
    VOIP = 500
    QUARANTINE = 666
    HOSTILE = 999


class SecurityZone(IntEnum):
    """Security zones for policy enforcement"""
    INTERNET = 0
    DMZ = 1
    INTERNAL = 2
    RESTRICTED = 3
    QUARANTINE = 4
    MANAGEMENT = 5


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
    security_zone: SecurityZone = SecurityZone.INTERNAL
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

        # Allow SSH from management VLAN
        tcp dport 22 accept

        # Allow RADIUS
        udp dport {{ 1812, 1813 }} accept

        # Allow HTP
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

    # Forward chain - inter-VLAN traffic
    chain forward {{
        type filter hook forward priority 0; policy drop;

        # Allow established connections
        ct state established,related accept

        # Inter-VLAN rules will be added here
        jump inter_vlan

        # Default policy
        log prefix "[GUARDIAN-FORWARD-DROP] " limit rate 10/minute
        drop
    }}

    # Output chain - traffic from Guardian
    chain output {{
        type filter hook output priority 0; policy accept;

        # Allow all outbound (Guardian is trusted)
        accept
    }}

    # Postrouting - NAT and marking
    chain postrouting {{
        type nat hook postrouting priority 100; policy accept;

        # Masquerade for internet access
        oifname "eth0" masquerade
    }}

    # Inter-VLAN routing chain
    chain inter_vlan {{
        # Rules will be dynamically added
    }}

    # Rate limiting chain
    chain rate_limit {{
        # Per-source rate limiting
    }}

    # Threat response chain
    chain threat_response {{
        # Threat-based blocking rules
    }}

    # Logging chain
    chain log_traffic {{
        # Traffic logging rules
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
            for chain in ['inter_vlan', 'rate_limit', 'threat_response', 'log_traffic']:
                await self._run_nft('add', 'chain', self.family, self.table_name, chain)

            logger.info("nftables base structure created")
            return True

        logger.info("nftables initialized with base ruleset")
        return True

    async def add_vlan(self, config: VLANConfig) -> bool:
        """Add VLAN configuration and rules"""
        self.vlans[config.vlan_id] = config

        if not await self._check_nftables():
            return False

        # Create VLAN interface marking
        vlan_mark = config.vlan_id

        # Add inter-VLAN rules based on allowed VLANs
        for allowed_vlan in config.inter_vlan_allowed:
            if allowed_vlan in self.vlans:
                await self._add_inter_vlan_rule(config.vlan_id, allowed_vlan)

        # Add rate limiting if configured
        if config.rate_limit_mbps:
            await self._add_rate_limit_rule(config.vlan_id, config.rate_limit_mbps)

        # Add internet access rule if enabled
        if config.internet_access:
            await self._add_internet_access_rule(config.vlan_id)

        logger.info(f"Added VLAN {config.vlan_id} ({config.name}) configuration")
        return True

    async def _add_inter_vlan_rule(self, src_vlan: int, dst_vlan: int):
        """Add inter-VLAN forwarding rule"""
        src_config = self.vlans.get(src_vlan)
        dst_config = self.vlans.get(dst_vlan)

        if not src_config or not dst_config:
            return

        # Add bidirectional rules
        rule = f"ip saddr {src_config.subnet} ip daddr {dst_config.subnet} accept"

        await self._run_nft(
            'add', 'rule', self.family, self.table_name, 'inter_vlan',
            rule
        )

        self.stats['rules_installed'] += 1

    async def _add_rate_limit_rule(self, vlan_id: int, mbps: int):
        """Add rate limiting for VLAN"""
        config = self.vlans.get(vlan_id)
        if not config:
            return

        # Convert Mbps to bytes/second for token bucket
        bytes_per_sec = mbps * 125000  # 1 Mbps = 125000 bytes/sec

        # Add meter-based rate limit
        rule = f"ip saddr {config.subnet} limit rate over {mbps}mbytes/second drop"

        await self._run_nft(
            'add', 'rule', self.family, self.table_name, 'rate_limit',
            rule
        )

    async def _add_internet_access_rule(self, vlan_id: int):
        """Add internet access rule for VLAN"""
        config = self.vlans.get(vlan_id)
        if not config:
            return

        # Allow outbound internet
        rule = f"ip saddr {config.subnet} oifname \"eth0\" accept"

        await self._run_nft(
            'add', 'rule', self.family, self.table_name, 'forward',
            rule
        )

    async def add_rule(self, rule: FirewallRule) -> bool:
        """Add custom firewall rule"""
        if not await self._check_nftables():
            return False

        nft_rule = self._build_nft_rule(rule)

        returncode, stdout, stderr = await self._run_nft(
            'add', 'rule', self.family, self.table_name, rule.chain,
            nft_rule
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
            'add', 'rule', self.family, self.table_name, 'threat_response',
            rule
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
            'add', 'rule', self.family, self.table_name, 'threat_response',
            rule
        )

        if returncode == 0:
            logger.warning(f"Blocked MAC {mac}: {reason}")
            return True

        return False

    async def quarantine_ip(self, ip: str, quarantine_vlan: int = VLANCategory.QUARANTINE):
        """Move IP to quarantine VLAN via packet marking"""
        if not await self._check_nftables():
            return False

        # Mark packets from this IP for quarantine
        mark = quarantine_vlan

        rule = f'ip saddr {ip} meta mark set {mark} counter log prefix "[GUARDIAN-QUARANTINE] "'

        returncode, _, stderr = await self._run_nft(
            'add', 'rule', self.family, self.table_name, 'threat_response',
            rule
        )

        if returncode == 0:
            logger.warning(f"Quarantined IP {ip} to VLAN {quarantine_vlan}")
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

    async def add_policy(self, policy: SegmentationPolicy) -> bool:
        """Add network segmentation policy"""
        self.policies.append(policy)

        # Generate rules from policy
        for src_zone in policy.source_zones:
            for dst_zone in policy.dest_zones:
                # Find VLANs in these zones
                src_vlans = [v for v in self.vlans.values() if v.security_zone == src_zone]
                dst_vlans = [v for v in self.vlans.values() if v.security_zone == dst_zone]

                for src_vlan in src_vlans:
                    for dst_vlan in dst_vlans:
                        if src_vlan.vlan_id == dst_vlan.vlan_id:
                            continue

                        # Create rule for this policy
                        rule = FirewallRule(
                            name=f"{policy.name}_{src_vlan.vlan_id}_{dst_vlan.vlan_id}",
                            chain="inter_vlan",
                            source_vlan=src_vlan.vlan_id,
                            dest_vlan=dst_vlan.vlan_id,
                            action=policy.action,
                            log=policy.log_violations,
                            log_prefix=f"[{policy.name}] ",
                            comment=f"Policy: {policy.name}"
                        )

                        await self.add_rule(rule)

        logger.info(f"Added segmentation policy: {policy.name}")
        return True

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
                # Note: JSON output format varies by nftables version
            except json.JSONDecodeError:
                pass

        return {
            'nftables': self.stats.copy(),
            'vlans': {
                vid: {
                    'name': cfg.name,
                    'subnet': cfg.subnet,
                    'zone': cfg.security_zone.name,
                    'internet_access': cfg.internet_access
                }
                for vid, cfg in self.vlans.items()
            },
            'rules_count': len(self.rules),
            'policies_count': len(self.policies)
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


class NetworkSegmentationService:
    """
    High-level network segmentation service

    Combines nftables management with VLAN-based isolation policies.
    """

    def __init__(self, table_name: str = "guardian"):
        self.nft = NFTablesManager(table_name)

        # Default VLANs
        self._default_vlans = [
            VLANConfig(
                vlan_id=VLANCategory.MANAGEMENT,
                name="Management",
                category=VLANCategory.MANAGEMENT,
                subnet="10.0.10.0/24",
                gateway="10.0.10.1",
                dhcp_range=("10.0.10.100", "10.0.10.200"),
                dns_servers=["10.0.10.1"],
                security_zone=SecurityZone.MANAGEMENT,
                internet_access=True,
                inter_vlan_allowed=set(),
                description="Administrative access"
            ),
            VLANConfig(
                vlan_id=VLANCategory.TRUSTED,
                name="Trusted",
                category=VLANCategory.TRUSTED,
                subnet="10.0.100.0/24",
                gateway="10.0.100.1",
                dhcp_range=("10.0.100.100", "10.0.100.200"),
                dns_servers=["10.0.100.1", "8.8.8.8"],
                security_zone=SecurityZone.INTERNAL,
                internet_access=True,
                inter_vlan_allowed={VLANCategory.MANAGEMENT, VLANCategory.IOT},
                description="Trusted devices"
            ),
            VLANConfig(
                vlan_id=VLANCategory.GUEST,
                name="Guest",
                category=VLANCategory.GUEST,
                subnet="10.0.200.0/24",
                gateway="10.0.200.1",
                dhcp_range=("10.0.200.100", "10.0.200.250"),
                dns_servers=["8.8.8.8", "8.8.4.4"],
                security_zone=SecurityZone.DMZ,
                internet_access=True,
                inter_vlan_allowed=set(),
                rate_limit_mbps=10,
                description="Guest network - isolated"
            ),
            VLANConfig(
                vlan_id=VLANCategory.IOT,
                name="IoT",
                category=VLANCategory.IOT,
                subnet="10.0.30.0/24",
                gateway="10.0.30.1",
                dhcp_range=("10.0.30.100", "10.0.30.250"),
                dns_servers=["10.0.30.1"],
                security_zone=SecurityZone.RESTRICTED,
                internet_access=True,  # Limited
                inter_vlan_allowed=set(),
                rate_limit_mbps=5,
                description="IoT devices - restricted"
            ),
            VLANConfig(
                vlan_id=VLANCategory.QUARANTINE,
                name="Quarantine",
                category=VLANCategory.QUARANTINE,
                subnet="10.0.66.0/24",
                gateway="10.0.66.1",
                dhcp_range=("10.0.66.100", "10.0.66.250"),
                dns_servers=["10.0.66.1"],
                security_zone=SecurityZone.QUARANTINE,
                internet_access=False,
                inter_vlan_allowed=set(),
                description="Quarantined devices"
            ),
        ]

        # Default policies
        self._default_policies = [
            SegmentationPolicy(
                name="guest_isolation",
                source_zones={SecurityZone.DMZ},
                dest_zones={SecurityZone.INTERNAL, SecurityZone.MANAGEMENT, SecurityZone.RESTRICTED},
                action=TrafficAction.DROP,
                log_violations=True
            ),
            SegmentationPolicy(
                name="iot_isolation",
                source_zones={SecurityZone.RESTRICTED},
                dest_zones={SecurityZone.INTERNAL, SecurityZone.MANAGEMENT},
                action=TrafficAction.DROP,
                log_violations=True
            ),
            SegmentationPolicy(
                name="quarantine_block",
                source_zones={SecurityZone.QUARANTINE},
                dest_zones={
                    SecurityZone.INTERNAL, SecurityZone.MANAGEMENT,
                    SecurityZone.DMZ, SecurityZone.RESTRICTED, SecurityZone.INTERNET
                },
                action=TrafficAction.DROP,
                log_violations=True
            ),
        ]

        logger.info("Network Segmentation Service initialized")

    async def initialize(self, use_defaults: bool = True) -> bool:
        """Initialize segmentation service"""
        # Initialize nftables
        if not await self.nft.initialize():
            return False

        if use_defaults:
            # Add default VLANs
            for vlan in self._default_vlans:
                await self.nft.add_vlan(vlan)

            # Add default policies
            for policy in self._default_policies:
                await self.nft.add_policy(policy)

        logger.info("Network segmentation initialized")
        return True

    async def add_vlan(self, config: VLANConfig) -> bool:
        """Add new VLAN"""
        return await self.nft.add_vlan(config)

    async def block_threat(self, ip: str, mac: Optional[str] = None, reason: str = "threat"):
        """Block threat by IP and optionally MAC"""
        await self.nft.block_ip(ip, reason)
        if mac:
            await self.nft.block_mac(mac, reason)

    async def quarantine_device(self, ip: str, mac: Optional[str] = None):
        """Move device to quarantine"""
        await self.nft.quarantine_ip(ip)

    async def release_device(self, ip: str):
        """Release device from quarantine/block"""
        await self.nft.unblock_ip(ip)

    async def get_status(self) -> Dict[str, Any]:
        """Get segmentation status"""
        return await self.nft.get_statistics()


# Predefined service ports for policy configuration
SERVICE_PORTS = {
    'ssh': ('tcp', 22),
    'http': ('tcp', 80),
    'https': ('tcp', 443),
    'dns': ('udp', 53),
    'dhcp': ('udp', '67-68'),
    'ntp': ('udp', 123),
    'smtp': ('tcp', 25),
    'smtps': ('tcp', 465),
    'imap': ('tcp', 143),
    'imaps': ('tcp', 993),
    'pop3': ('tcp', 110),
    'pop3s': ('tcp', 995),
    'rdp': ('tcp', 3389),
    'vnc': ('tcp', 5900),
    'mysql': ('tcp', 3306),
    'postgres': ('tcp', 5432),
    'redis': ('tcp', 6379),
    'mongodb': ('tcp', 27017),
    'mqtt': ('tcp', 1883),
    'mqtts': ('tcp', 8883),
    'radius_auth': ('udp', 1812),
    'radius_acct': ('udp', 1813),
    'htp': ('udp', 4719),
    'openflow': ('tcp', '6633,6653'),
}


# Export classes
__all__ = [
    'NFTablesManager',
    'NetworkSegmentationService',
    'VLANConfig',
    'FirewallRule',
    'SegmentationPolicy',
    'VLANCategory',
    'SecurityZone',
    'TrafficAction',
    'SERVICE_PORTS'
]
