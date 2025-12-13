"""
Django app configuration for Adversarial Security Framework
"""

from django.apps import AppConfig


class AdversarialConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.adversarial'
    verbose_name = 'Adversarial Security Testing'

    def ready(self):
        # Import signals if needed
        pass
