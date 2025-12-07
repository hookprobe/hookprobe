"""
Django settings for HookProbe project - Test/CI Configuration
"""

from .base import *

# Test mode
DEBUG = True

# Allow all hosts in test
ALLOWED_HOSTS = ['*']

# Disable Logto authentication in tests (not configured in CI)
os.environ.setdefault('LOGTO_ENDPOINT', '')
os.environ.setdefault('LOGTO_APP_ID', '')
os.environ.setdefault('LOGTO_APP_SECRET', '')

# Don't use django-debug-toolbar in tests (it's optional)
try:
    INSTALLED_APPS.remove('debug_toolbar')
    MIDDLEWARE.remove('debug_toolbar.middleware.DebugToolbarMiddleware')
except (ValueError, AttributeError):
    pass

# Use simple password hashers for faster tests
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# Use faster cache backend for tests
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}

# Override session engine to use cache
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'

# Disable migrations for faster tests (optional)
# class DisableMigrations:
#     def __contains__(self, item):
#         return True
#
#     def __getitem__(self, item):
#         return None
#
# MIGRATION_MODULES = DisableMigrations()

# Email backend for tests
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Disable HTTPS redirect in tests
SECURE_SSL_REDIRECT = False

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
    },
}

# Static files - ensure directory exists
STATIC_ROOT = BASE_DIR / 'staticfiles'
if not STATIC_ROOT.exists():
    STATIC_ROOT.mkdir(parents=True, exist_ok=True)
