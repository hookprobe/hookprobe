"""
MSSP Dashboard App Configuration
"""

from django.apps import AppConfig


class MSSPDashboardConfig(AppConfig):
    """MSSP Dashboard application configuration."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.mssp_dashboard'
    verbose_name = 'MSSP Dashboard'

    def ready(self):
        """Initialize app when Django starts."""
        # Import signal handlers if needed
        pass
