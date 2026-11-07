"""
Cortex Module - HookProbe Neural Command Center Integration

Provides endpoints for Cortex digital twin visualization:
- /cortex - Full-page Cortex visualization
- /api/cortex/node - Node status for Cortex integration
"""
from flask import Blueprint

cortex_bp = Blueprint('cortex', __name__)

from . import views  # noqa: F401, E402
