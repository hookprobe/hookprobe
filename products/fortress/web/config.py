"""
Fortress Web Configuration
"""

import os
from pathlib import Path


class Config:
    """Base configuration for Fortress admin portal."""

    # Flask
    SECRET_KEY = os.environ.get('FORTRESS_SECRET_KEY')
    DEBUG = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

    # Paths
    BASE_DIR = Path(__file__).parent
    DATA_DIR = Path('/opt/hookprobe/fortress/data')
    CONFIG_DIR = Path('/etc/hookprobe')

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


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    WTF_CSRF_ENABLED = False  # Disable for testing


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    SESSION_COOKIE_SECURE = True
