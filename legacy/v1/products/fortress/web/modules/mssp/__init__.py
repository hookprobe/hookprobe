"""
Fortress MSSP Module — Managed Security Service Provider integration.

Handles claim code provisioning, MSSP status display, and manual registration.
All provisioning writes happen in fts-web (this container) which has rw access
to /etc/hookprobe.  fts-qsecbit reads the resulting API_KEY as a consumer.
"""

from flask import Blueprint

mssp_bp = Blueprint(
    'mssp',
    __name__,
    template_folder='../../templates/mssp',
    url_prefix='/mssp',
)

from . import views  # noqa: F401, E402
