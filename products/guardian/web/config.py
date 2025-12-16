"""
Guardian Web Application Configuration
"""
import os
import secrets


class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('GUARDIAN_SECRET_KEY') or secrets.token_hex(32)

    # Guardian paths
    GUARDIAN_BASE = '/opt/hookprobe/guardian'
    LOG_PATH = '/var/log/hookprobe'
    THREAT_FILE = f'{LOG_PATH}/threats/aggregated.json'
    BLOCK_FILE = f'{LOG_PATH}/security/blocks.json'

    # dnsXai paths
    DNSXAI_CONFIG = f'{GUARDIAN_BASE}/dnsxai/config.json'
    DNSXAI_STATS = f'{GUARDIAN_BASE}/dnsxai/stats.json'
    DNSXAI_WHITELIST = f'{GUARDIAN_BASE}/dnsxai/whitelist.txt'
    DNSXAI_BLOCKLIST = f'{GUARDIAN_BASE}/dnsxai/blocklist.txt'
    DNSXAI_PAUSE = f'{GUARDIAN_BASE}/dnsxai/pause_state.json'

    # Network interfaces
    WAN_INTERFACE = os.environ.get('GUARDIAN_WAN', 'eth0')
    LAN_INTERFACE = os.environ.get('GUARDIAN_LAN', 'wlan0')

    # Container settings
    CONTAINER_RUNTIME = 'podman'

    # Debug mode
    DEBUG = os.environ.get('GUARDIAN_DEBUG', 'false').lower() == 'true'


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False


# Config selector
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': ProductionConfig
}
