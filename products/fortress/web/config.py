"""
Fortress Web Configuration

Simple, secure configuration for small business security gateway.
Uses local authentication with max 5 users.
"""

import os
from pathlib import Path


def load_config_file(filepath):
    """Load a shell-style config file into a dict."""
    config = {}
    if filepath.exists():
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    # Remove quotes
                    value = value.strip().strip('"').strip("'")
                    config[key.strip()] = value
    return config


class Config:
    """Base configuration for Fortress admin portal."""

    # Flask
    SECRET_KEY = os.environ.get('FORTRESS_SECRET_KEY')
    DEBUG = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

    # Paths
    BASE_DIR = Path(__file__).parent
    DATA_DIR = Path('/opt/hookprobe/fortress/data')
    CONFIG_DIR = Path('/etc/hookprobe')
    SECRETS_DIR = CONFIG_DIR / 'secrets'

    # User database (JSON file - simple and sufficient for 5 users)
    USERS_FILE = CONFIG_DIR / 'users.json'
    MAX_USERS = 5  # Small business limit

    # Session
    SESSION_TYPE = 'filesystem'
    PERMANENT_SESSION_LIFETIME = 28800  # 8 hours

    # Security
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour

    # Fortress-specific
    FORTRESS_CONFIG_FILE = CONFIG_DIR / 'fortress.conf'
    QSECBIT_STATS_FILE = DATA_DIR / 'qsecbit_stats.json'
    VLANS_CONFIG_FILE = CONFIG_DIR / 'vlans.conf'

    # API URLs (internal services)
    QSECBIT_API_URL = 'http://localhost:9090'
    GUARDIAN_API_URL = 'http://localhost:8080'

    # AdminLTE settings
    ADMINLTE_SKIN = 'dark'  # dark, light
    SIDEBAR_COLLAPSED = False

    # =========================================
    # Grafana Integration (optional)
    # =========================================
    _grafana_config = load_config_file(SECRETS_DIR / 'grafana.conf')

    GRAFANA_URL = _grafana_config.get('GRAFANA_URL', 'http://localhost:3000')
    GRAFANA_ADMIN_USER = _grafana_config.get('GRAFANA_ADMIN_USER', 'admin')
    GRAFANA_ADMIN_PASSWORD = _grafana_config.get('GRAFANA_ADMIN_PASSWORD', '')


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    WTF_CSRF_ENABLED = False  # Disable for testing


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    SESSION_COOKIE_SECURE = True
