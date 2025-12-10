"""
Cortex App Configuration
"""

from django.apps import AppConfig


class CortexConfig(AppConfig):
    """Configuration for Cortex Django app."""

    name = 'apps.cortex'
    verbose_name = 'HookProbe Cortex'

    def ready(self):
        """Called when Django is ready."""
        # Import signals if needed
        pass
