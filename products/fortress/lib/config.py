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
    version: str = "5.0.0"
    data_dir: str = "/opt/hookprobe/fortress/data"
    config_dir: str = "/etc/hookprobe"
    secrets_dir: str = "/etc/hookprobe/secrets"

    # Network
    ovs_bridge: str = "fortress"
    wan_interface: str = ""
    lan_interfaces: List[str] = field(default_factory=list)

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
        if not self.vlans:
            self.vlans = {
                "management": VLANConfig(10, "Management", "10.250.10.0/24", "10.250.10.1", is_isolated=False),
                "pos": VLANConfig(20, "POS", "10.250.20.0/24", "10.250.20.1", is_isolated=True),
                "staff": VLANConfig(30, "Staff", "10.250.30.0/24", "10.250.30.1", is_isolated=False),
                "guest": VLANConfig(40, "Guest", "10.250.40.0/24", "10.250.40.1", is_isolated=True),
                "iot": VLANConfig(99, "IoT", "10.250.99.0/24", "10.250.99.1", is_isolated=True),
            }

        if not self.vxlan_tunnels:
            self.vxlan_tunnels = {
                "core": VXLANConfig("fortress-core", 1000, 4800, f"{self.secrets_dir}/vxlan/core.psk"),
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
