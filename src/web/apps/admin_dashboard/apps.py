"""
Admin Dashboard App Configuration
"""

from django.apps import AppConfig


class AdminDashboardConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.admin_dashboard'
    verbose_name = 'Admin Dashboard'

    def ready(self):
        # Import signals if any
        pass
