"""
SLA AI Configuration Management

Loads and validates configuration from YAML or environment variables.
"""

import os
import yaml
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from pathlib import Path


@dataclass
class InterfaceConfig:
    """Configuration for a WAN interface."""
    name: str
    type: str  # ethernet, lte, wifi
    metered: bool = False
    daily_budget_mb: int = 0
    monthly_budget_mb: int = 0
    cost_per_gb: float = 0.0


@dataclass
class FailoverConfig:
    """Failover behavior configuration."""
    prediction_threshold: float = 0.6
    immediate_threshold: float = 0.8
    min_failover_duration_s: int = 120


@dataclass
class FailbackConfig:
    """Failback behavior configuration."""
    enabled: bool = True
    min_primary_stable_s: int = 60
    health_checks_required: int = 5
    metered_urgency_multiplier: float = 1.5
    business_hours: str = "09:00-18:00"
    business_hours_multiplier: float = 1.2


@dataclass
class PredictorConfig:
    """LSTM predictor configuration."""
    enabled: bool = True
    model_path: str = "/var/lib/hookprobe/slaai/model.pt"
    retrain_interval_days: int = 7
    min_training_samples: int = 1000
    lookback_window: int = 12  # Number of samples for prediction


@dataclass
class DNSProviderConfig:
    """DNS provider configuration."""
    name: str
    primary: str
    secondary: str
    priority: int = 1


@dataclass
class DNSConfig:
    """DNS intelligence configuration."""
    enabled: bool = True
    providers: List[DNSProviderConfig] = field(default_factory=list)
    health_check_interval_s: int = 60
    switch_threshold_ms: int = 100


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"
    file: str = "/var/log/hookprobe/slaai.log"
    max_size_mb: int = 50
    retention_days: int = 30


@dataclass
class SLAAIConfig:
    """Main SLA AI configuration."""
    enabled: bool = True
    check_interval_s: int = 5
    prediction_interval_s: int = 30
    database_path: str = "/var/lib/hookprobe/slaai/metrics.db"

    primary_interface: Optional[InterfaceConfig] = None
    backup_interface: Optional[InterfaceConfig] = None

    failover: FailoverConfig = field(default_factory=FailoverConfig)
    failback: FailbackConfig = field(default_factory=FailbackConfig)
    predictor: PredictorConfig = field(default_factory=PredictorConfig)
    dns: DNSConfig = field(default_factory=DNSConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    # Health check targets
    ping_targets: List[str] = field(
        default_factory=lambda: ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    )
    ping_count: int = 2
    ping_timeout_s: int = 3

    # HTTP health check
    http_check_enabled: bool = True
    http_check_url: str = "http://httpbin.org/ip"
    http_check_timeout_s: int = 5


def _parse_interface(data: Dict) -> InterfaceConfig:
    """Parse interface configuration from dict."""
    return InterfaceConfig(
        name=data.get("name", ""),
        type=data.get("type", "ethernet"),
        metered=data.get("metered", False),
        daily_budget_mb=data.get("daily_budget_mb", 0),
        monthly_budget_mb=data.get("monthly_budget_mb", 0),
        cost_per_gb=data.get("cost_per_gb", 0.0),
    )


def _parse_dns_provider(data: Dict) -> DNSProviderConfig:
    """Parse DNS provider configuration from dict."""
    return DNSProviderConfig(
        name=data.get("name", ""),
        primary=data.get("primary", ""),
        secondary=data.get("secondary", ""),
        priority=data.get("priority", 1),
    )


def load_config(config_path: Optional[str] = None) -> SLAAIConfig:
    """
    Load SLA AI configuration from file or environment.

    Priority:
        1. Environment variables (SLAAI_*)
        2. Config file (/etc/hookprobe/slaai.conf or custom path)
        3. Default values

    Args:
        config_path: Optional path to config file

    Returns:
        SLAAIConfig instance
    """
    config = SLAAIConfig()

    # Default config paths
    config_paths = [
        config_path,
        os.environ.get("SLAAI_CONFIG"),
        "/etc/hookprobe/slaai.conf",
        "/etc/hookprobe/slaai.yaml",
        str(Path.home() / ".config/hookprobe/slaai.conf"),
    ]

    # Load from file
    for path in config_paths:
        if path and os.path.exists(path):
            with open(path, "r") as f:
                data = yaml.safe_load(f)
                if data:
                    _apply_config_data(config, data)
            break

    # Override with environment variables
    _apply_env_overrides(config)

    # Set default DNS providers if none configured
    if not config.dns.providers:
        config.dns.providers = [
            DNSProviderConfig("cloudflare", "1.1.1.1", "1.0.0.1", 1),
            DNSProviderConfig("google", "8.8.8.8", "8.8.4.4", 2),
            DNSProviderConfig("quad9", "9.9.9.9", "149.112.112.112", 3),
        ]

    return config


def _apply_config_data(config: SLAAIConfig, data: Dict) -> None:
    """Apply configuration data from dict to config object."""
    if "enabled" in data:
        config.enabled = data["enabled"]
    if "check_interval_s" in data:
        config.check_interval_s = data["check_interval_s"]
    if "prediction_interval_s" in data:
        config.prediction_interval_s = data["prediction_interval_s"]
    if "database_path" in data:
        config.database_path = data["database_path"]

    # Interfaces
    if "interfaces" in data:
        ifaces = data["interfaces"]
        if "primary" in ifaces:
            config.primary_interface = _parse_interface(ifaces["primary"])
        if "backup" in ifaces:
            config.backup_interface = _parse_interface(ifaces["backup"])

    # Failover
    if "failover" in data:
        fo = data["failover"]
        config.failover.prediction_threshold = fo.get(
            "prediction_threshold", config.failover.prediction_threshold
        )
        config.failover.immediate_threshold = fo.get(
            "immediate_threshold", config.failover.immediate_threshold
        )
        config.failover.min_failover_duration_s = fo.get(
            "min_failover_duration_s", config.failover.min_failover_duration_s
        )

    # Failback
    if "failback" in data:
        fb = data["failback"]
        config.failback.enabled = fb.get("enabled", config.failback.enabled)
        config.failback.min_primary_stable_s = fb.get(
            "min_primary_stable_s", config.failback.min_primary_stable_s
        )
        config.failback.health_checks_required = fb.get(
            "health_checks_required", config.failback.health_checks_required
        )
        config.failback.metered_urgency_multiplier = fb.get(
            "metered_urgency_multiplier", config.failback.metered_urgency_multiplier
        )
        config.failback.business_hours = fb.get(
            "business_hours", config.failback.business_hours
        )
        config.failback.business_hours_multiplier = fb.get(
            "business_hours_multiplier", config.failback.business_hours_multiplier
        )

    # Predictor
    if "predictor" in data:
        pred = data["predictor"]
        config.predictor.enabled = pred.get("enabled", config.predictor.enabled)
        config.predictor.model_path = pred.get("model_path", config.predictor.model_path)
        config.predictor.retrain_interval_days = pred.get(
            "retrain_interval_days", config.predictor.retrain_interval_days
        )
        config.predictor.min_training_samples = pred.get(
            "min_training_samples", config.predictor.min_training_samples
        )
        config.predictor.lookback_window = pred.get(
            "lookback_window", config.predictor.lookback_window
        )

    # DNS
    if "dns" in data:
        dns = data["dns"]
        config.dns.enabled = dns.get("enabled", config.dns.enabled)
        config.dns.health_check_interval_s = dns.get(
            "health_check_interval_s", config.dns.health_check_interval_s
        )
        config.dns.switch_threshold_ms = dns.get(
            "switch_threshold_ms", config.dns.switch_threshold_ms
        )
        if "providers" in dns:
            config.dns.providers = [
                _parse_dns_provider(p) for p in dns["providers"]
            ]

    # Ping targets
    if "ping_targets" in data:
        config.ping_targets = data["ping_targets"]
    if "ping_count" in data:
        config.ping_count = data["ping_count"]
    if "ping_timeout_s" in data:
        config.ping_timeout_s = data["ping_timeout_s"]

    # HTTP check
    if "http_check_enabled" in data:
        config.http_check_enabled = data["http_check_enabled"]
    if "http_check_url" in data:
        config.http_check_url = data["http_check_url"]
    if "http_check_timeout_s" in data:
        config.http_check_timeout_s = data["http_check_timeout_s"]

    # Logging
    if "logging" in data:
        log = data["logging"]
        config.logging.level = log.get("level", config.logging.level)
        config.logging.file = log.get("file", config.logging.file)
        config.logging.max_size_mb = log.get("max_size_mb", config.logging.max_size_mb)
        config.logging.retention_days = log.get(
            "retention_days", config.logging.retention_days
        )


def _apply_env_overrides(config: SLAAIConfig) -> None:
    """Apply environment variable overrides."""
    if os.environ.get("SLAAI_ENABLED"):
        config.enabled = os.environ["SLAAI_ENABLED"].lower() == "true"
    if os.environ.get("SLAAI_CHECK_INTERVAL"):
        config.check_interval_s = int(os.environ["SLAAI_CHECK_INTERVAL"])
    if os.environ.get("SLAAI_DATABASE"):
        config.database_path = os.environ["SLAAI_DATABASE"]
    if os.environ.get("SLAAI_PRIMARY_IFACE"):
        config.primary_interface = InterfaceConfig(
            name=os.environ["SLAAI_PRIMARY_IFACE"],
            type="ethernet",
        )
    if os.environ.get("SLAAI_BACKUP_IFACE"):
        config.backup_interface = InterfaceConfig(
            name=os.environ["SLAAI_BACKUP_IFACE"],
            type=os.environ.get("SLAAI_BACKUP_TYPE", "lte"),
            metered=os.environ.get("SLAAI_BACKUP_METERED", "true").lower() == "true",
        )
    if os.environ.get("SLAAI_LOG_LEVEL"):
        config.logging.level = os.environ["SLAAI_LOG_LEVEL"]
