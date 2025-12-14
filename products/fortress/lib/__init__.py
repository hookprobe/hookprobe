"""
HookProbe Fortress Library

Core modules for the Fortress small business security gateway.
Extends Guardian capabilities with:
- PostgreSQL database integration
- VLAN management
- Device tracking with network segmentation
- Business reporting
"""

from .config import FortressConfig, load_config
from .database import Database, get_db

__all__ = [
    'FortressConfig',
    'load_config',
    'Database',
    'get_db',
]

__version__ = '5.0.0'
