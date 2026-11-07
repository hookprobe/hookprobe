"""
AEGIS - AI-Enhanced Guardian Intelligence System

Flask blueprint for the ORACLE chat interface.
"""

from flask import Blueprint

aegis_bp = Blueprint(
    'aegis',
    __name__,
    template_folder='../../templates/aegis',
    url_prefix='/aegis'
)

from . import views  # noqa: F401, E402
