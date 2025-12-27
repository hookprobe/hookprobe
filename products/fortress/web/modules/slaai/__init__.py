"""
Fortress SLA AI Module - Business Continuity Dashboard

Provides real-time RTO/RPO visualization, failover status,
and cost tracking for WAN connections.
"""

from flask import Blueprint

slaai_bp = Blueprint(
    'slaai',
    __name__,
    url_prefix='/slaai',
    template_folder='../../templates/slaai'
)

from . import views  # noqa: F401, E402
