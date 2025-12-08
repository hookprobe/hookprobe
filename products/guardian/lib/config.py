"""
Guardian Configuration Module

Provides unified configuration management for Guardian with sensible defaults.
Configuration can be loaded from YAML file or environment variables.

Configuration file: /etc/guardian/guardian.yaml

Author: HookProbe Team
Version: 5.0.0 Liberty
License: AGPL-3.0 - see LICENSE in this directory
"""

import os
import logging
import yaml
import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
from enum import Enum
import secrets
import hashlib

logger = logging.getLogger(__name__)

# Default configuration paths
DEFAULT_CONFIG_PATH = "/etc/guardian/guardian.yaml"
DEFAULT_CONFIG_DIR = "/etc/guardian"
DEFAULT_DATA_DIR = "/var/lib/guardian"
DEFAULT_LOG_DIR = "/var/log/guardian"
DEFAULT_RUN_DIR = "/run/guardian"


class ConfigValidationError(Exception):
    """Configuration validation error"""
    pass


# RADIUS configuration removed - Guardian uses HTP mesh for device tracking
# Device categorization is now handled via DHCP lease monitoring
# See mesh_integration.py for the new approach


@dataclass
class VLANConfig:
    """VLAN segmentation configuration"""
    enabled: bool = True

    # VLAN definitions
    vlans: Dict[int, Dict[str, Any]] = field(default_factory=lambda: {
        10: {"name": "Smart Lights", "subnet": "10.0.10.0/24", "gateway": "10.0.10.1", "internet": True},
        20: {"name": "Thermostats", "subnet": "10.0.20.0/24", "gateway": "10.0.20.1", "internet": True},
        30: {"name": "Cameras", "subnet": "10.0.30.0/24", "gateway": "10.0.30.1", "internet": True},
        40: {"name": "Voice Assistants", "subnet": "10.0.40.0/24", "gateway": "10.0.40.1", "internet": True},
        50: {"name": "Appliances", "subnet": "10.0.50.0/24", "gateway": "10.0.50.1", "internet": True},
        60: {"name": "Entertainment", "subnet": "10.0.60.0/24", "gateway": "10.0.60.1", "internet": True},
        70: {"name": "Robots", "subnet": "10.0.70.0/24", "gateway": "10.0.70.1", "internet": True},
        80: {"name": "Sensors", "subnet": "10.0.80.0/24", "gateway": "10.0.80.1", "internet": False},
        999: {"name": "Quarantine", "subnet": "10.0.99.0/24", "gateway": "10.0.99.1", "internet": False},
    })

    # Inter-VLAN isolation
    inter_vlan_blocked: bool = True

    # Rate limits (Mbps) per VLAN
    rate_limits: Dict[int, int] = field(default_factory=lambda: {
        10: 10, 20: 5, 30: 50, 40: 20, 50: 10, 60: 100, 70: 10, 80: 1, 999: 1
    })


@dataclass
class OpenFlowConfig:
    """OpenFlow SDN controller configuration"""
    enabled: bool = True
    listen_address: str = "0.0.0.0"
    listen_port: int = 6653
    legacy_port: int = 6633  # For older switches

    # OVS bridge configuration
    ovs_bridge: str = "br-guardian"
    ovs_datapath: str = "system"

    # Flow timeouts
    idle_timeout: int = 300
    hard_timeout: int = 3600

    # Table-miss behavior
    table_miss_to_controller: bool = True


@dataclass
class HTPConfig:
    """HookProbe Transport Protocol configuration"""
    enabled: bool = True

    # MSSP connection
    mssp_host: str = "mssp.hookprobe.com"
    mssp_port: int = 4719
    mssp_websocket_port: int = 443
    mssp_websocket_path: str = "/ws/guardian"

    # Guardian identity
    guardian_id: str = ""  # Auto-generated if empty
    guardian_name: str = "guardian"

    # Encryption
    private_key_path: str = "/etc/guardian/keys/guardian.key"
    public_key_path: str = "/etc/guardian/keys/guardian.pub"
    mssp_public_key: str = ""  # MSSP's public key for verification

    # Connection settings
    heartbeat_interval: int = 30
    reconnect_delay: int = 5
    max_reconnect_delay: int = 300
    connection_timeout: int = 30

    # Telemetry reporting
    telemetry_enabled: bool = True
    telemetry_interval: int = 60
    threat_report_enabled: bool = True

    def __post_init__(self):
        if not self.guardian_id:
            # Generate deterministic ID based on hostname
            import socket
            hostname = socket.gethostname()
            self.guardian_id = hashlib.sha256(f"guardian:{hostname}".encode()).hexdigest()[:16]


@dataclass
class HTPFileConfig:
    """HTP-based secure file transfer configuration"""
    enabled: bool = True

    # File transfer settings
    chunk_size: int = 8192          # 8KB chunks (optimized for SBC memory)
    max_file_size_mb: int = 1024    # 1GB max file size
    transfer_timeout: int = 300     # 5 minutes timeout
    max_concurrent_transfers: int = 16

    # Allowed paths for file access
    base_path: str = "/srv/guardian"
    allowed_paths: List[str] = field(default_factory=lambda: ["/home", "/srv/files", "/var/log/guardian"])

    # Security settings
    compression_enabled: bool = True
    verify_hash: bool = True         # SHA256 integrity verification
    atomic_writes: bool = True       # Write to temp, then rename

    # Extension whitelist (empty = allow all)
    allowed_extensions: List[str] = field(default_factory=lambda: [
        ".txt", ".log", ".json", ".yaml", ".yml", ".csv",
        ".conf", ".cfg", ".ini", ".xml", ".html", ".css", ".js",
        ".py", ".sh", ".bash", ".md", ".rst"
    ])

    # Size quotas per user/session
    quota_enabled: bool = False
    quota_mb_per_session: int = 500

    # Read-only mode (for restricted access)
    read_only: bool = False


@dataclass
class NetworkConfig:
    """Network interface configuration"""
    # WAN interface (internet uplink)
    wan_interface: str = "eth0"
    wan_dhcp: bool = True
    wan_static_ip: str = ""
    wan_gateway: str = ""
    wan_dns: List[str] = field(default_factory=lambda: ["8.8.8.8", "8.8.4.4"])

    # LAN interface (local network / bridge)
    lan_interface: str = "eth1"
    lan_bridge: str = "br-lan"
    lan_ip: str = "10.0.1.1"
    lan_netmask: str = "255.255.255.0"

    # DHCP server
    dhcp_enabled: bool = True
    dhcp_range_start: str = "10.0.1.100"
    dhcp_range_end: str = "10.0.1.250"
    dhcp_lease_time: str = "12h"

    # DNS server
    dns_enabled: bool = True
    dns_upstream: List[str] = field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])


@dataclass
class SecurityConfig:
    """Security and threat detection configuration"""
    # Suricata IDS/IPS
    suricata_enabled: bool = True
    suricata_mode: str = "ips"  # ids or ips
    suricata_rules_update: bool = True
    suricata_rules_url: str = "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz"

    # Zeek network analysis
    zeek_enabled: bool = True
    zeek_log_dir: str = "/var/log/zeek"

    # ModSecurity WAF
    modsecurity_enabled: bool = True
    modsecurity_mode: str = "DetectionOnly"  # On, Off, DetectionOnly

    # XDP/eBPF
    xdp_enabled: bool = True
    xdp_mode: str = "native"  # native, skb, offload

    # Layer threat detection
    layer_detection_enabled: bool = True

    # QSecBit scoring
    qsecbit_enabled: bool = True
    qsecbit_threshold_warning: float = 70.0
    qsecbit_threshold_critical: float = 40.0

    # Auto-response
    auto_block_enabled: bool = True
    auto_quarantine_enabled: bool = True
    block_duration: int = 3600  # seconds


@dataclass
class WebUIConfig:
    """Web interface configuration"""
    enabled: bool = True
    bind_address: str = "0.0.0.0"
    http_port: int = 80
    https_port: int = 443

    # TLS
    tls_enabled: bool = True
    tls_cert_path: str = "/etc/guardian/certs/server.crt"
    tls_key_path: str = "/etc/guardian/certs/server.key"

    # Authentication
    admin_username: str = "admin"
    admin_password_hash: str = ""  # bcrypt hash
    session_timeout: int = 3600


@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    log_dir: str = DEFAULT_LOG_DIR
    max_file_size_mb: int = 100
    max_backup_count: int = 5
    syslog_enabled: bool = False
    syslog_host: str = "localhost"
    syslog_port: int = 514


@dataclass
class GuardianConfig:
    """
    Main Guardian configuration

    All settings have sensible defaults for immediate deployment.
    """
    # Version
    version: str = "5.0.0"
    name: str = "Guardian Liberty"

    # Component configurations
    vlan: VLANConfig = field(default_factory=VLANConfig)
    openflow: OpenFlowConfig = field(default_factory=OpenFlowConfig)
    htp: HTPConfig = field(default_factory=HTPConfig)
    htp_file: HTPFileConfig = field(default_factory=HTPFileConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    webui: WebUIConfig = field(default_factory=WebUIConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    # Paths
    config_dir: str = DEFAULT_CONFIG_DIR
    data_dir: str = DEFAULT_DATA_DIR
    log_dir: str = DEFAULT_LOG_DIR
    run_dir: str = DEFAULT_RUN_DIR

    def validate(self) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []

        # Validate VLANs
        if self.vlan.enabled:
            for vlan_id in self.vlan.vlans:
                if not 1 <= vlan_id <= 4094:
                    errors.append(f"Invalid VLAN ID: {vlan_id}")

        # Validate HTP
        if self.htp.enabled:
            if not self.htp.mssp_host:
                errors.append("HTP enabled but no MSSP host specified")

        # HTP File Transfer validation (replaces WebSocket VPN)
        if self.htp_file.enabled and not self.htp.enabled:
            errors.append("HTP File Transfer requires HTP to be enabled")

        return errors

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return asdict(self)

    def to_yaml(self) -> str:
        """Convert configuration to YAML string"""
        return yaml.dump(self.to_dict(), default_flow_style=False, sort_keys=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'GuardianConfig':
        """Create configuration from dictionary"""
        config = cls()

        # Update nested configs (RADIUS removed - using HTP mesh instead)
        if 'vlan' in data:
            config.vlan = VLANConfig(**data['vlan'])
        if 'openflow' in data:
            config.openflow = OpenFlowConfig(**data['openflow'])
        if 'htp' in data:
            config.htp = HTPConfig(**data['htp'])
        if 'htp_file' in data:
            config.htp_file = HTPFileConfig(**data['htp_file'])
        if 'network' in data:
            config.network = NetworkConfig(**data['network'])
        if 'security' in data:
            config.security = SecurityConfig(**data['security'])
        if 'webui' in data:
            config.webui = WebUIConfig(**data['webui'])
        if 'logging' in data:
            config.logging = LoggingConfig(**data['logging'])

        # Update top-level settings
        for key in ['version', 'name', 'config_dir', 'data_dir', 'log_dir', 'run_dir']:
            if key in data:
                setattr(config, key, data[key])

        return config

    @classmethod
    def from_yaml(cls, yaml_str: str) -> 'GuardianConfig':
        """Create configuration from YAML string"""
        data = yaml.safe_load(yaml_str)
        return cls.from_dict(data) if data else cls()

    @classmethod
    def from_file(cls, path: str) -> 'GuardianConfig':
        """Load configuration from file"""
        path = Path(path)

        if not path.exists():
            logger.warning(f"Config file not found: {path}, using defaults")
            return cls()

        with open(path, 'r') as f:
            content = f.read()

        if path.suffix in ['.yaml', '.yml']:
            return cls.from_yaml(content)
        elif path.suffix == '.json':
            return cls.from_dict(json.loads(content))
        else:
            # Try YAML first, then JSON
            try:
                return cls.from_yaml(content)
            except yaml.YAMLError:
                return cls.from_dict(json.loads(content))

    def save(self, path: Optional[str] = None):
        """Save configuration to file"""
        if path is None:
            path = os.path.join(self.config_dir, "guardian.yaml")

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'w') as f:
            f.write(self.to_yaml())

        logger.info(f"Configuration saved to {path}")


class ConfigManager:
    """
    Configuration manager singleton

    Provides centralized access to Guardian configuration.
    """
    _instance: Optional['ConfigManager'] = None
    _config: Optional[GuardianConfig] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def load(self, path: Optional[str] = None) -> GuardianConfig:
        """Load configuration from file or use defaults"""
        if path is None:
            # Check environment variable
            path = os.environ.get('GUARDIAN_CONFIG', DEFAULT_CONFIG_PATH)

        self._config = GuardianConfig.from_file(path)

        # Apply environment variable overrides
        self._apply_env_overrides()

        # Validate
        errors = self._config.validate()
        if errors:
            for error in errors:
                logger.error(f"Config validation error: {error}")

        return self._config

    def _apply_env_overrides(self):
        """Apply environment variable overrides"""
        if not self._config:
            return

        env_mappings = {
            'GUARDIAN_MSSP_HOST': ('htp', 'mssp_host'),
            'GUARDIAN_MSSP_PORT': ('htp', 'mssp_port'),
            'GUARDIAN_RADIUS_SECRET': ('radius', 'secret'),
            'GUARDIAN_RADIUS_PORT': ('radius', 'auth_port'),
            'GUARDIAN_ADMIN_PASSWORD': ('webui', 'admin_password_hash'),
            'GUARDIAN_LOG_LEVEL': ('logging', 'level'),
        }

        for env_var, (section, key) in env_mappings.items():
            value = os.environ.get(env_var)
            if value:
                section_obj = getattr(self._config, section)
                # Convert type if needed
                current_value = getattr(section_obj, key)
                if isinstance(current_value, int):
                    value = int(value)
                elif isinstance(current_value, float):
                    value = float(value)
                elif isinstance(current_value, bool):
                    value = value.lower() in ('true', '1', 'yes')
                setattr(section_obj, key, value)

    @property
    def config(self) -> GuardianConfig:
        """Get current configuration"""
        if self._config is None:
            self.load()
        return self._config

    def reload(self, path: Optional[str] = None) -> GuardianConfig:
        """Reload configuration"""
        return self.load(path)

    def get(self, *keys: str, default: Any = None) -> Any:
        """Get configuration value by dotted path"""
        if self._config is None:
            self.load()

        obj = self._config
        for key in keys:
            if hasattr(obj, key):
                obj = getattr(obj, key)
            elif isinstance(obj, dict) and key in obj:
                obj = obj[key]
            else:
                return default
        return obj


def get_config() -> GuardianConfig:
    """Get current Guardian configuration"""
    return ConfigManager().config


def load_config(path: Optional[str] = None) -> GuardianConfig:
    """Load Guardian configuration from file"""
    return ConfigManager().load(path)


def generate_default_config() -> str:
    """Generate default configuration YAML"""
    config = GuardianConfig()
    return config.to_yaml()


# Default configuration template
DEFAULT_CONFIG_TEMPLATE = """# Guardian Configuration
# Version: 5.0.0 Liberty
#
# This file contains all configuration settings for Guardian.
# Edit values as needed, then restart Guardian services.

version: "5.0.0"
name: "Guardian Liberty"

# ============================================================================
# Device Tracking
# ============================================================================
# RADIUS has been removed from Guardian - device tracking is now handled
# via DHCP lease monitoring and HTP mesh integration.
# See mesh_integration.py for the new approach.

# ============================================================================
# VLAN Segmentation
# ============================================================================
vlan:
  enabled: true
  inter_vlan_blocked: true  # Block all inter-VLAN traffic by default

  # VLAN definitions
  vlans:
    10:
      name: "Smart Lights"
      subnet: "10.0.10.0/24"
      gateway: "10.0.10.1"
      internet: true
    20:
      name: "Thermostats"
      subnet: "10.0.20.0/24"
      gateway: "10.0.20.1"
      internet: true
    30:
      name: "Cameras"
      subnet: "10.0.30.0/24"
      gateway: "10.0.30.1"
      internet: true
    40:
      name: "Voice Assistants"
      subnet: "10.0.40.0/24"
      gateway: "10.0.40.1"
      internet: true
    50:
      name: "Appliances"
      subnet: "10.0.50.0/24"
      gateway: "10.0.50.1"
      internet: true
    60:
      name: "Entertainment"
      subnet: "10.0.60.0/24"
      gateway: "10.0.60.1"
      internet: true
    70:
      name: "Robots"
      subnet: "10.0.70.0/24"
      gateway: "10.0.70.1"
      internet: true
    80:
      name: "Sensors"
      subnet: "10.0.80.0/24"
      gateway: "10.0.80.1"
      internet: false
    999:
      name: "Quarantine"
      subnet: "10.0.99.0/24"
      gateway: "10.0.99.1"
      internet: false

  # Rate limits per VLAN (Mbps)
  rate_limits:
    10: 10
    20: 5
    30: 50
    40: 20
    50: 10
    60: 100
    70: 10
    80: 1
    999: 1

# ============================================================================
# OpenFlow SDN Controller
# ============================================================================
openflow:
  enabled: true
  listen_address: "0.0.0.0"
  listen_port: 6653
  legacy_port: 6633
  ovs_bridge: "br-guardian"
  idle_timeout: 300
  hard_timeout: 3600

# ============================================================================
# HookProbe Transport Protocol (HTP)
# ============================================================================
htp:
  enabled: true
  mssp_host: "mssp.hookprobe.com"
  mssp_port: 4719
  mssp_websocket_port: 443
  mssp_websocket_path: "/ws/guardian"

  guardian_id: ""  # Auto-generated from hostname
  guardian_name: "guardian"

  private_key_path: "/etc/guardian/keys/guardian.key"
  public_key_path: "/etc/guardian/keys/guardian.pub"

  heartbeat_interval: 30
  reconnect_delay: 5
  max_reconnect_delay: 300

  telemetry_enabled: true
  telemetry_interval: 60
  threat_report_enabled: true

# WebSocket VPN removed - Guardian now uses HTP Mesh for secure file transfer
# See htp_file section above for file transfer configuration

# ============================================================================
# Network Configuration
# ============================================================================
network:
  # WAN interface (internet uplink)
  wan_interface: "eth0"
  wan_dhcp: true

  # LAN interface (local network)
  lan_interface: "eth1"
  lan_bridge: "br-lan"
  lan_ip: "10.0.1.1"
  lan_netmask: "255.255.255.0"

  # DHCP server
  dhcp_enabled: true
  dhcp_range_start: "10.0.1.100"
  dhcp_range_end: "10.0.1.250"
  dhcp_lease_time: "12h"

  # DNS
  dns_enabled: true
  dns_upstream:
    - "8.8.8.8"
    - "1.1.1.1"

# ============================================================================
# Security & Threat Detection
# ============================================================================
security:
  # Suricata IDS/IPS
  suricata_enabled: true
  suricata_mode: "ips"  # ids or ips

  # Zeek network analysis
  zeek_enabled: true

  # ModSecurity WAF
  modsecurity_enabled: true
  modsecurity_mode: "DetectionOnly"

  # XDP/eBPF acceleration
  xdp_enabled: true
  xdp_mode: "native"

  # Layer-based threat detection
  layer_detection_enabled: true

  # QSecBit scoring
  qsecbit_enabled: true
  qsecbit_threshold_warning: 70.0
  qsecbit_threshold_critical: 40.0

  # Auto-response
  auto_block_enabled: true
  auto_quarantine_enabled: true
  block_duration: 3600

# ============================================================================
# Web Interface
# ============================================================================
webui:
  enabled: true
  bind_address: "0.0.0.0"
  http_port: 80
  https_port: 443
  tls_enabled: true
  tls_cert_path: "/etc/guardian/certs/server.crt"
  tls_key_path: "/etc/guardian/certs/server.key"
  admin_username: "admin"
  session_timeout: 3600

# ============================================================================
# Logging
# ============================================================================
logging:
  level: "INFO"
  log_dir: "/var/log/guardian"
  max_file_size_mb: 100
  max_backup_count: 5
  syslog_enabled: false
"""


# Export classes and functions
__all__ = [
    'GuardianConfig',
    'RADIUSConfig',
    'VLANConfig',
    'OpenFlowConfig',
    'HTPConfig',
    'HTPFileConfig',
    'NetworkConfig',
    'SecurityConfig',
    'WebUIConfig',
    'LoggingConfig',
    'ConfigManager',
    'ConfigValidationError',
    'get_config',
    'load_config',
    'generate_default_config',
    'DEFAULT_CONFIG_TEMPLATE',
    'DEFAULT_CONFIG_PATH',
]
