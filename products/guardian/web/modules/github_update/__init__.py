"""
GitHub Update Module - Pull updates from GitHub via Web UI

This module provides a web interface for updating Guardian from GitHub
without requiring CLI access. Scope is limited to networking components
for safety.
"""
from flask import Blueprint

github_update_bp = Blueprint(
    'github_update',
    __name__,
    template_folder='../../templates'
)

from . import views  # noqa: F401, E402
