"""
Django settings for HookProbe project - Production Configuration
"""

from .base import *

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

# Parse ALLOWED_HOSTS from environment (comma-separated)
# Security: External requests go through nginx which preserves the original Host header.
# localhost/127.0.0.1 are only reachable from inside containers (for health checks).
# Host header injection via external requests is not possible because nginx forwards
# the actual client Host header, not a spoofed one.
_allowed_hosts_env = os.getenv('DJANGO_ALLOWED_HOSTS', '')
ALLOWED_HOSTS = [
    'mssp.hookprobe.com',   # Production domain (external HTTPS access)
    'localhost',            # Internal container health checks only
    '127.0.0.1',            # Internal container health checks only
] + [h.strip() for h in _allowed_hosts_env.split(',') if h.strip()]

# Database connection pooling and optimization
DATABASES['default'].update({
    'CONN_MAX_AGE': 600,  # Keep connections alive for 10 minutes (connection pooling)
    'OPTIONS': {
        'connect_timeout': 10,  # Connection timeout in seconds
        'options': '-c statement_timeout=30000',  # 30 second query timeout
    },
    'ATOMIC_REQUESTS': True,  # Wrap each request in a transaction
    'AUTOCOMMIT': True,
})

# Security settings
SECURE_SSL_REDIRECT = False  # Disabled for POC
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Email configuration (use environment variables)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', '587'))
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', '')
DEFAULT_FROM_EMAIL = os.getenv('DEFAULT_FROM_EMAIL', 'noreply@hookprobe.com')

# Logging configuration
# For containerized deployments, logs go to stdout/stderr
# Container orchestrators (Podman/Docker) capture and manage logs
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
            'level': 'INFO',
        },
        'console_error': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
            'level': 'ERROR',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'console_error'],
            'level': 'INFO',
            'propagate': False,
        },
        'django.request': {
            'handlers': ['console_error'],
            'level': 'ERROR',
            'propagate': False,
        },
        'apps': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
