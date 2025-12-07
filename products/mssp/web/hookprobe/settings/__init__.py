"""
HookProbe Django Settings
Conditional import based on environment
"""

import os

environment = os.getenv('DJANGO_ENV', 'development')

if environment == 'production':
    from .production import *
else:
    from .development import *
