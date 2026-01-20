"""
Django settings for HookProbe MSSP project - Base Configuration

Unified IAM Integration:
This configuration integrates with Logto (POD-002) for centralized identity
management. The unified role system supports: admin, editor, customer, soc_analyst.

IAM Module:
Uses the shared IAM module at /home/ubuntu/hookprobe/shared/iam/ which provides:
- UNIFIED_ROLES: Single source of truth for role definitions
- LogtoAuthenticationBackend: JWT-based authentication
- LogtoMiddleware: Bearer token extraction from Authorization headers
- Helper functions: user_is_admin(), user_can_access_mssp(), etc.

Authentication Flow:
1. LogtoAuthenticationBackend authenticates via JWT tokens
2. LogtoMiddleware extracts Bearer tokens from Authorization headers
3. Django ModelBackend provides fallback for local accounts
"""

import os
from pathlib import Path

# Build paths inside the project
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
# Generate a secure key with: python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY')
if not SECRET_KEY:
    # In production, this will raise an error - SECRET_KEY is required
    import sys
    if 'test' not in sys.argv and os.getenv('DJANGO_ENV') == 'production':
        raise ValueError('DJANGO_SECRET_KEY environment variable must be set in production')
    # Development/test fallback
    SECRET_KEY = 'django-insecure-dev-only-DO-NOT-USE-IN-PRODUCTION-' + 'x' * 50

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Third-party apps
    'rest_framework',
    'corsheaders',
    'django_filters',
    'django_celery_beat',      # Periodic task scheduling
    'django_celery_results',   # Task result storage

    # HookProbe apps
    # NOTE: cms and merchandise apps moved to hookprobe.com repository
    'apps.dashboard',
    'apps.admin_dashboard',  # AdminLTE dashboard for team management
    'apps.mssp_dashboard',    # Customer-facing MSSP dashboard (AIOCHI)
    'apps.devices',
    'apps.monitoring',
    'apps.security',
    'apps.vpn',               # IKEv2 VPN profile generation and management
    'apps.sdn',               # MAC-based VLAN assignment for IoT segmentation
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'shared.iam.middleware.LogtoMiddleware',  # Unified IAM - Logto token authentication
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'hookprobe.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            BASE_DIR / 'templates',
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.media',
                'django.template.context_processors.static',
            ],
        },
    },
]

WSGI_APPLICATION = 'hookprobe.wsgi.application'

# Database
# Default to PostgreSQL in POD-003
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('POSTGRES_DB', 'hookprobe'),
        'USER': os.getenv('POSTGRES_USER', 'hookprobe'),
        'PASSWORD': os.getenv('POSTGRES_PASSWORD', 'hookprobe'),
        'HOST': os.getenv('POSTGRES_HOST', '10.200.3.12'),
        'PORT': os.getenv('POSTGRES_PORT', '5432'),
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Authentication backends - Logto ONLY (no local password auth)
# All authentication is handled by Logto IAM (centralized identity provider)
# Users are created as "shadow" records in Django for foreign key relationships
AUTHENTICATION_BACKENDS = [
    'shared.iam.backends.LogtoAuthenticationBackend',  # Unified IAM backend
]

# Authentication URLs
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/mssp/'
LOGOUT_REDIRECT_URL = '/login/'

# Logto IAM Configuration (POD-002)
# Central identity provider for unified roles: admin, editor, customer, soc_analyst
LOGTO_ENDPOINT = os.getenv('LOGTO_ENDPOINT', 'http://10.200.2.12:3001')
LOGTO_APP_ID = os.getenv('LOGTO_APP_ID', '')
LOGTO_APP_SECRET = os.getenv('LOGTO_APP_SECRET', '')
LOGTO_ISSUER = os.getenv('LOGTO_ISSUER', f"{LOGTO_ENDPOINT}/oidc")

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [
    BASE_DIR / 'static',
]

# Media files (User uploads)
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Django REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 50,
}

# CORS settings
CORS_ALLOWED_ORIGINS = [
    'http://localhost:3000',  # Grafana
    'http://localhost:5678',  # n8n
]

# HookProbe specific settings
HOOKPROBE = {
    # Qsecbit API configuration (POD-006)
    'QSECBIT_API_URL': os.getenv('QSECBIT_API_URL', 'http://10.200.6.12:8888'),
    'QSECBIT_API_KEY': os.getenv('QSECBIT_API_KEY', ''),  # API key for authentication
    'QSECBIT_TIMEOUT': int(os.getenv('QSECBIT_TIMEOUT', '30')),  # Request timeout in seconds

    # ClickHouse configuration (POD-005)
    'CLICKHOUSE_HOST': os.getenv('CLICKHOUSE_HOST', '10.200.5.12'),
    'CLICKHOUSE_PORT': int(os.getenv('CLICKHOUSE_PORT', '8123')),
    'CLICKHOUSE_DATABASE': os.getenv('CLICKHOUSE_DATABASE', 'security'),
    'CLICKHOUSE_USER': os.getenv('CLICKHOUSE_USER', 'default'),
    'CLICKHOUSE_PASSWORD': os.getenv('CLICKHOUSE_PASSWORD', ''),

    # Redis configuration (POD-004)
    'REDIS_HOST': os.getenv('REDIS_HOST', '10.200.4.12'),
    'REDIS_PORT': int(os.getenv('REDIS_PORT', '6379')),
    'REDIS_PASSWORD': os.getenv('REDIS_PASSWORD', ''),
    'REDIS_DB': int(os.getenv('REDIS_DB', '1')),
}

# Cache configuration (Redis in POD-004)
redis_url = f"redis://"
if HOOKPROBE['REDIS_PASSWORD']:
    redis_url += f":{HOOKPROBE['REDIS_PASSWORD']}@"
redis_url += f"{HOOKPROBE['REDIS_HOST']}:{HOOKPROBE['REDIS_PORT']}/{HOOKPROBE['REDIS_DB']}"

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': redis_url,
        'OPTIONS': {
            'max_connections': 50,  # Connection pooling
            'socket_connect_timeout': 5,  # seconds
            'socket_timeout': 5,  # seconds
            'retry_on_timeout': True,
        }
    }
}

# Session configuration
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'

# Celery Configuration
CELERY_BROKER_URL = redis_url
CELERY_RESULT_BACKEND = 'django-db'  # Store results in Django database
CELERY_CACHE_BACKEND = 'default'     # Use Django cache as Celery cache

# Celery settings
CELERY_TIMEZONE = 'UTC'
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 30 * 60  # 30 minutes max task time
CELERY_RESULT_EXTENDED = True

# Celery beat scheduler
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'

# Task serialization
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'

# Security settings (override in production)
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
