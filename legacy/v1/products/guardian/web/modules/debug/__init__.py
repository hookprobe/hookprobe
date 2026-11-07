"""
Debug Module - Browser-based CLI for Guardian debugging

Provides a terminal-like interface in the browser for running
diagnostic commands without direct CLI access.
"""
from flask import Blueprint

debug_bp = Blueprint(
    'debug',
    __name__,
    template_folder='../../templates'
)

from . import views  # noqa: F401, E402
