"""
AIOCHI - AI Eyes Module for Fortress Dashboard
Cognitive Network Layer with human-readable narratives.

The Three Pillars:
- PRESENCE: Who's Home (device bubbles, ecosystem detection)
- PRIVACY: What's Happening (narrative feed of events)
- PERFORMANCE: How Fast (network health score)
"""

from flask import Blueprint

aiochi_bp = Blueprint(
    'aiochi',
    __name__,
    template_folder='../../templates/aiochi',
    url_prefix='/aiochi'
)

from . import views  # noqa: F401, E402
