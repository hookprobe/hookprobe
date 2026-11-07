"""
Fortress Bubble Management Module

Provides API and UI for managing device bubbles (user groupings).

Bubble Types:
- FAMILY: Dad, Mom, Kids - Smart Home access, D2D communication
- GUEST: Visitors - Internet only, isolated
- CORPORATE: Work devices - Separate, controlled access
- SMART_HOME: IoT devices - Shared smart home components
"""
from flask import Blueprint

bubbles_bp = Blueprint('bubbles', __name__, url_prefix='/bubbles')

from . import views  # noqa
