#!/usr/bin/env python3
"""
Fortress Configuration Module

Centralized configuration management for the Fortress tier.
Loads configuration from files and environment variables.
"""

import os
import configparser
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, List


@dataclass
class DatabaseConfig:
    """Database connection configuration."""
    host: str = "localhost"
    port: int = 5432
    database: str = "fortress"
    user: str = "fortress"
    password: str = ""
    min_connections: int = 2
    max_connections: int = 10


@dataclass
class RedisConfig:
    """Redis cache configuration."""
    host: str = "localhost"
    port: int = 6379
    password: str = ""
    db: int = 0


@dataclass
class VLANConfig:
    """VLAN configuration."""
    id: int
    name: str
    subnet: str
    gateway: str
    dhcp_enabled: bool = True
    dns_policy: str = "standard"
    is_isolated: bool = False
    is_logical: bool = False  # True for segment VLANs (OpenFlow tags within VLAN 100)
    trust_floor: int = 1  # Minimum trust level required (0-4)


@dataclass
class VXLANConfig:
    """VXLAN tunnel configuration."""
    name: str
    vni: int
    port: int
    psk_file: str
    remote_ip: Optional[str] = None


@dataclass
class FortressConfig:
    """Main Fortress configuration."""

    # General
    node_id: str = ""
    tier: str = "fortress"
    version: str = "5.4.0"
    data_dir: str = "/opt/hookprobe/fortress/data"
    config_dir: str = "/etc/hookprobe"
    secrets_dir: str = "/etc/hookprobe/secrets"

    # Network - FTS is the standard OVS bridge name used by install scripts
    ovs_bridge: str = "FTS"
    wan_interface: str = ""
    lan_interfaces: List[str] = field(default_factory=list)
    lan_subnet: str = "10.200.0.0/24"  # User-configurable during install (/29 to /23)
    lan_gateway: str = "10.200.0.1"
    mgmt_subnet: str = "10.200.100.0/30"  # Fixed management subnet
    mgmt_gateway: str = "10.200.100.1"
    network_mode: str = "filter"  # "filter" or "vlan"

    # Database
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    redis: RedisConfig = field(default_factory=RedisConfig)

    # VLANs
    vlans: Dict[str, VLANConfig] = field(default_factory=dict)

    # VXLAN
    vxlan_tunnels: Dict[str, VXLANConfig] = field(default_factory=dict)

    # QSecBit
    qsecbit_enabled: bool = True
    qsecbit_interval: int = 10

    # Web UI
    web_host: str = "0.0.0.0"
    web_port: int = 8443
    web_ssl: bool = True

    # Features
    macsec_enabled: bool = True
    openflow_enabled: bool = True
    monitoring_enabled: bool = True

    def __post_init__(self):
        """Initialize default VLANs and VXLAN tunnels if empty."""
        # Load network configuration from install state if available
        self._load_network_state()

        if not self.vlans:
            # Physical VLANs (infrastructure layer)
            # VLAN 100 = LAN - All WiFi clients, LAN devices (user-selected subnet)
            # VLAN 200 = MGMT - Admin access, container network (fixed /30)
            #
            # Segment VLANs (logical layer via OpenFlow rules within VLAN 100)
            # These are NOT separate subnets - they share LAN subnet with isolation via OVS flows
            self.vlans = {
                # Physical VLANs (actual tagged traffic)
                "lan": VLANConfig(100, "LAN", self.lan_subnet, self.lan_gateway,
                                  dhcp_enabled=True, is_logical=False, trust_floor=0),
                "mgmt": VLANConfig(200, "MGMT", self.mgmt_subnet, self.mgmt_gateway,
                                   dhcp_enabled=True, is_logical=False, trust_floor=4, is_isolated=False),
                # Segment VLANs (logical tags within VLAN 100 for device classification)
                # These share the LAN subnet - segmentation is via OpenFlow, not IP
                "secmon": VLANConfig(10, "Security Monitor", self.lan_subnet, self.lan_gateway,
                                     dhcp_enabled=False, is_logical=True, trust_floor=3, is_isolated=False),
                "pos": VLANConfig(20, "POS", self.lan_subnet, self.lan_gateway,
                                  dhcp_enabled=False, is_logical=True, trust_floor=3, is_isolated=True),
                "staff": VLANConfig(30, "Staff", self.lan_subnet, self.lan_gateway,
                                    dhcp_enabled=False, is_logical=True, trust_floor=2, is_isolated=False),
                "guest": VLANConfig(40, "Guest", self.lan_subnet, self.lan_gateway,
                                    dhcp_enabled=False, is_logical=True, trust_floor=1, is_isolated=True),
                "cameras": VLANConfig(50, "Cameras", self.lan_subnet, self.lan_gateway,
                                      dhcp_enabled=False, is_logical=True, trust_floor=2, is_isolated=True),
                "iiot": VLANConfig(60, "Industrial IoT", self.lan_subnet, self.lan_gateway,
                                   dhcp_enabled=False, is_logical=True, trust_floor=2, is_isolated=True),
                "quarantine": VLANConfig(99, "Quarantine", self.lan_subnet, self.lan_gateway,
                                         dhcp_enabled=False, is_logical=True, trust_floor=0, is_isolated=True),
            }

        # Initialize VXLAN tunnels
        self._init_vxlan_tunnels()

    def _load_network_state(self):
        """Load network configuration from install state file."""
        import json
        state_file = Path(self.config_dir) / "fortress-state.json"
        if state_file.exists():
            try:
                state = json.loads(state_file.read_text())
                # Load subnet configuration from install
                if 'lan_subnet' in state:
                    self.lan_subnet = state['lan_subnet']
                if 'lan_gateway' in state:
                    self.lan_gateway = state['lan_gateway']
                if 'network_mode' in state:
                    self.network_mode = state['network_mode']
                if 'ovs_bridge' in state:
                    self.ovs_bridge = state['ovs_bridge']
            except (json.JSONDecodeError, IOError):
                pass  # Use defaults if state file is invalid

    def _init_vxlan_tunnels(self):
        """Initialize VXLAN tunnels if empty."""
        if not self.vxlan_tunnels:
            self.vxlan_tunnels = {
                "core": VXLANConfig("fts-core", 1000, 4800, f"{self.secrets_dir}/vxlan/core.psk"),
                "mssp": VXLANConfig("mssp-uplink", 2000, 4900, f"{self.secrets_dir}/vxlan/mssp.psk"),
            }

    @classmethod
    def from_file(cls, config_path: str) -> "FortressConfig":
        """Load configuration from file."""
        config = cls()
        path = Path(config_path)

        if not path.exists():
            return config

        parser = configparser.ConfigParser()
        parser.read(path)

        # General section
        if parser.has_section('general'):
            config.node_id = parser.get('general', 'node_id', fallback=config.node_id)
            config.tier = parser.get('general', 'tier', fallback=config.tier)
            config.version = parser.get('general', 'version', fallback=config.version)

        # Network section
        if parser.has_section('network'):
            config.ovs_bridge = parser.get('network', 'ovs_bridge', fallback=config.ovs_bridge)
            config.macsec_enabled = parser.getboolean('network', 'macsec_enabled', fallback=config.macsec_enabled)

        # Security section
        if parser.has_section('security'):
            config.qsecbit_enabled = parser.getboolean('security', 'qsecbit_enabled', fallback=config.qsecbit_enabled)
            config.openflow_enabled = parser.getboolean('security', 'openflow_enabled', fallback=config.openflow_enabled)

        # Load secrets
        config._load_secrets()

        return config

    def _load_secrets(self):
        """Load secrets from files."""
        secrets_dir = Path(self.secrets_dir)

        # Database password
        db_password_file = secrets_dir / "database" / "postgres_password"
        if db_password_file.exists():
            self.database.password = db_password_file.read_text().strip()

        # Redis password
        redis_password_file = secrets_dir / "database" / "redis_password"
        if redis_password_file.exists():
            self.redis.password = redis_password_file.read_text().strip()

    def get_database_url(self) -> str:
        """Get PostgreSQL connection URL."""
        return (
            f"postgresql://{self.database.user}:{self.database.password}"
            f"@{self.database.host}:{self.database.port}/{self.database.database}"
        )

    def get_redis_url(self) -> str:
        """Get Redis connection URL."""
        if self.redis.password:
            return f"redis://:{self.redis.password}@{self.redis.host}:{self.redis.port}/{self.redis.db}"
        return f"redis://{self.redis.host}:{self.redis.port}/{self.redis.db}"


# Global config instance
_config: Optional[FortressConfig] = None


def load_config(config_path: str = "/etc/hookprobe/fortress.conf") -> FortressConfig:
    """Load and cache configuration."""
    global _config
    if _config is None:
        _config = FortressConfig.from_file(config_path)
    return _config


def get_config() -> FortressConfig:
    """Get cached configuration."""
    global _config
    if _config is None:
        _config = load_config()
    return _config
