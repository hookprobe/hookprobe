"""
Fortress Web Configuration

Supports:
- Local authentication (default)
- Logto IAM (if configured)
- PostgreSQL database (if available)
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

    # User database (JSON for MVP, can migrate to SQLite later)
    USERS_FILE = CONFIG_DIR / 'users.json'

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
    # Logto IAM Configuration (optional)
    # =========================================
    # Load from /etc/hookprobe/logto.conf if available
    _logto_config = load_config_file(CONFIG_DIR / 'logto.conf')

    LOGTO_ENABLED = _logto_config.get('LOGTO_LOCAL', 'false').lower() == 'true'
    LOGTO_ENDPOINT = _logto_config.get('LOGTO_ENDPOINT', '')
    LOGTO_APP_ID = _logto_config.get('LOGTO_APP_ID', '')
    LOGTO_APP_SECRET = _logto_config.get('LOGTO_APP_SECRET', '')

    # OAuth2 redirect URI (for Logto)
    LOGTO_REDIRECT_URI = os.environ.get(
        'LOGTO_REDIRECT_URI',
        'https://localhost:8443/auth/callback'
    )

    # =========================================
    # PostgreSQL Database (optional)
    # =========================================
    # Load from /etc/hookprobe/secrets/postgres.conf if available
    _pg_config = load_config_file(SECRETS_DIR / 'postgres.conf')

    DATABASE_URL = _pg_config.get(
        'DATABASE_URL',
        os.environ.get('DATABASE_URL', '')
    )
    POSTGRES_HOST = _pg_config.get('POSTGRES_HOST', 'localhost')
    POSTGRES_PORT = int(_pg_config.get('POSTGRES_PORT', '5432'))
    POSTGRES_DB = _pg_config.get('POSTGRES_DB', 'fortress')
    POSTGRES_USER = _pg_config.get('POSTGRES_USER', 'fortress')
    POSTGRES_PASSWORD = _pg_config.get('POSTGRES_PASSWORD', '')

    # Use PostgreSQL if configured, else use JSON files
    USE_DATABASE = bool(DATABASE_URL or POSTGRES_PASSWORD)

    # =========================================
    # Grafana Integration
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
