"""SDN app configuration."""

from django.apps import AppConfig


class SdnConfig(AppConfig):
    """SDN application config."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.sdn'
    verbose_name = 'Software-Defined Networking'

    def ready(self):
        """Initialize SDN app."""
        pass
