"""
Merchandise App Configuration
"""

from django.apps import AppConfig


class MerchandiseConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.merchandise'
    verbose_name = 'Merchandise Store'

    def ready(self):
        # Import signals if any
        pass
