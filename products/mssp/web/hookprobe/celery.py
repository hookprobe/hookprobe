"""
Celery application configuration for HookProbe MSSP.

This module configures Celery for async task processing in the MSSP platform.
Tasks include:
- Security event processing
- Device telemetry aggregation
- Report generation
- Email notifications
- Scheduled maintenance tasks
"""

import os

from celery import Celery

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'hookprobe.settings')

app = Celery('hookprobe')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix in Django settings.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()


@app.task(bind=True, ignore_result=True)
def debug_task(self):
    """Debug task for testing Celery connectivity."""
    print(f'Request: {self.request!r}')
