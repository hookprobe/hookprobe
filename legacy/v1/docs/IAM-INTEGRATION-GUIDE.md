# HookProbe IAM Integration Guide

This guide explains how HookProbe's Django applications integrate with Logto for **unified, centralized identity and access management**.

## Architecture: One Database, One Identity, One Login

```
┌─────────────────────────────────────────────────────────────────┐
│                    LOGTO (POD-002)                              │
│                 Central Identity Provider                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   Users     │  │   Roles     │  │   OIDC      │             │
│  │ (accounts)  │  │  (groups)   │  │  (clients)  │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
└───────────────────────────┬─────────────────────────────────────┘
                            │
            ┌───────────────┴───────────────┐
            │                               │
     ┌──────▼──────┐               ┌───────▼───────┐
     │    Mesh     │               │ hookprobe.com │
     │  Dashboard  │               │   Website     │
     │  (JWT auth) │               │  (OIDC auth)  │
     └──────┬──────┘               └───────┬───────┘
            │                               │
            └───────────────┬───────────────┘
                            │
                   ┌────────▼────────┐
                   │   PostgreSQL    │
                   │   (POD-003)     │
                   │  Shared Users   │
                   └─────────────────┘
```

**Key Principles:**
- **ONE database** - PostgreSQL for all user data
- **ONE identity provider** - Logto handles all authentication
- **ONE login flow** - OIDC for website, JWT for API
- **NO local password auth** - ModelBackend is removed
- **Shadow users** - Django keeps User records for foreign keys only

## Overview

HookProbe uses [Logto](https://logto.io/) as its Identity and Access Management (IAM) solution. Logto runs in POD-002 and provides:

- **OAuth 2.0 / OpenID Connect (OIDC)** authentication
- **Centralized user management** across all HookProbe services
- **Role-based access control (RBAC)**
- **Single Sign-On (SSO)** capabilities
- **Social login** support (Google, GitHub, etc.)
- **Multi-factor authentication (MFA)**

## Architecture

```
┌─────────────────┐
│   User Browser  │
└────────┬────────┘
         │
         │ 1. Login Request
         ▼
┌─────────────────┐
│   POD-001       │
│ Django Web App  │
│   (10.200.1.12) │
└────────┬────────┘
         │
         │ 2. Authenticate
         ▼
┌─────────────────┐
│   POD-002       │
│   Logto IAM     │
│   (10.200.2.12) │
└────────┬────────┘
         │
         │ 3. Verify User
         ▼
┌─────────────────┐
│   POD-003       │
│  PostgreSQL DB  │
│   (10.200.3.12) │
└─────────────────┘
```

## Configuration

### 1. Logto Setup (POD-002)

First, set up Logto in POD-002:

```bash
# Create Logto application in Logto Admin Console
# Navigate to: http://10.200.2.12:3002/console

# 1. Go to Applications → Create Application
# 2. Choose "Traditional Web Application"
# 3. Note down:
#    - Application ID (Client ID)
#    - Application Secret (Client Secret)
#    - Redirect URIs: http://<your-domain>/auth/callback
```

### 2. Django Configuration

Add the following to your Django environment configuration (`.env` or `config/webserver-config.sh`):

```bash
# Logto IAM Configuration (POD-002)
export LOGTO_ENDPOINT="http://10.200.2.12:3001"
export LOGTO_APP_ID="your-application-id-from-logto"
export LOGTO_APP_SECRET="your-application-secret-from-logto"

# Optional: Override default issuer
export LOGTO_ISSUER="http://10.200.2.12:3001/oidc"
```

### 3. Django Settings Update

Add the Logto authentication backend to your `settings/base.py` or `settings/production.py`:

```python
# Authentication Backends
AUTHENTICATION_BACKENDS = [
    'apps.dashboard.authentication.LogtoAuthenticationBackend',
    'django.contrib.auth.backends.ModelBackend',  # Fallback to local auth
]

# Middleware (add LogtoMiddleware for API token authentication)
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'apps.dashboard.authentication.LogtoMiddleware',  # Add this
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Logto Configuration
LOGTO = {
    'ENDPOINT': os.getenv('LOGTO_ENDPOINT', 'http://10.200.2.12:3001'),
    'APP_ID': os.getenv('LOGTO_APP_ID', ''),
    'APP_SECRET': os.getenv('LOGTO_APP_SECRET', ''),
    'ISSUER': os.getenv('LOGTO_ISSUER', ''),
}
```

### 4. Install Dependencies

Ensure required packages are installed:

```bash
cd src/web
pip install -r requirements.txt
```

Required packages:
- `pyjwt==2.8.0` - JWT token verification
- `cryptography==42.0.0` - RSA key cryptography for JWT
- `requests==2.31.0` - HTTP client for Logto API calls

## Authentication Flows

### 1. Password-Based Authentication

For traditional login forms:

```python
from django.contrib.auth import authenticate, login

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        # Authenticate against Logto
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('dashboard:home')
        else:
            messages.error(request, 'Invalid credentials')

    return render(request, 'auth/login.html')
```

### 2. Token-Based Authentication (API)

For REST API requests with Bearer tokens:

```python
# Client sends request with Authorization header:
# Authorization: Bearer <access_token>

# LogtoMiddleware automatically:
# 1. Extracts token from header
# 2. Verifies JWT signature
# 3. Authenticates user
# 4. Sets request.user

# In your API view:
from rest_framework.decorators import api_view
from rest_framework.response import Response

@api_view(['GET'])
def protected_api(request):
    # User is already authenticated by LogtoMiddleware
    if not request.user.is_authenticated:
        return Response({'error': 'Unauthorized'}, status=401)

    return Response({'message': f'Hello {request.user.username}!'})
```

### 3. OAuth/OIDC Flow

For full OAuth 2.0 flow (recommended for production):

```python
# 1. Redirect user to Logto authorization endpoint
authorization_url = f"{LOGTO_ENDPOINT}/oidc/auth"
params = {
    'client_id': LOGTO_APP_ID,
    'redirect_uri': 'http://your-domain/auth/callback',
    'response_type': 'code',
    'scope': 'openid profile email offline_access',
}

# 2. Handle callback and exchange code for tokens
# (This is handled by django-allauth or custom view)

# 3. Use access token to authenticate
user = authenticate(request, access_token=access_token)
```

## User Synchronization

The Logto backend automatically synchronizes user data:

### User Creation

When a user logs in via Logto for the first time:

1. **New Django User** is created
2. **Email** is synced from Logto
3. **Username** is synced from Logto
4. **First/Last Name** from JWT claims
5. **Groups** mapped from Logto roles

### User Updates

On subsequent logins:

- Username updates if changed in Logto
- Email updates if changed in Logto
- Groups re-synchronized with Logto roles

### Role Mapping

Logto roles are mapped to Django groups:

| Logto Role | Django Permission |
|------------|-------------------|
| `admin` | `is_superuser=True, is_staff=True` |
| `staff` | `is_staff=True` |
| `user` | Standard user (default) |
| Custom roles | Mapped to Django groups |

## API Authentication

### REST API with Bearer Tokens

```bash
# 1. Get access token from Logto
curl -X POST http://10.200.2.12:3001/oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "username=your-username" \
  -d "password=your-password" \
  -d "client_id=your-app-id" \
  -d "client_secret=your-app-secret" \
  -d "scope=openid profile email"

# Response:
# {
#   "access_token": "eyJhbGci...",
#   "token_type": "Bearer",
#   "expires_in": 3600
# }

# 2. Use token in API requests
curl -X GET http://10.200.1.12:8000/api/v1/devices/ \
  -H "Authorization: Bearer eyJhbGci..."
```

## Security Considerations

### 1. JWT Validation

The backend validates:
- **Signature** using JWKS from Logto
- **Issuer** matches configured Logto endpoint
- **Audience** matches application ID
- **Expiration** token is not expired

### 2. Token Storage

**Recommended approach:**
- Store tokens in **HTTP-only cookies** for web apps
- Use **secure storage** for mobile apps
- **Never** expose tokens in URLs or client-side JavaScript

### 3. HTTPS in Production

**Always use HTTPS** in production:

```bash
# Update Django settings
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
```

### 4. Refresh Tokens

For long-lived sessions, use refresh tokens:

```python
# Request with offline_access scope
scope = 'openid profile email offline_access'

# Exchange refresh token for new access token
response = requests.post(
    f"{LOGTO_ENDPOINT}/oidc/token",
    data={
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': LOGTO_APP_ID,
        'client_secret': LOGTO_APP_SECRET,
    }
)
```

## Testing

### Local Development Testing

```bash
# 1. Start Logto (if not running)
podman start hookprobe-logto

# 2. Create test user in Logto Admin Console
# http://10.200.2.12:3002/console

# 3. Test authentication
cd src/web
python manage.py shell

>>> from django.contrib.auth import authenticate
>>> user = authenticate(username='test@example.com', password='password')
>>> print(user)
<User: test@example.com>
```

### Integration Tests

```python
# tests/test_logto_auth.py
from django.test import TestCase, Client
from django.contrib.auth.models import User

class LogtoAuthenticationTest(TestCase):
    def setUp(self):
        self.client = Client()

    def test_password_authentication(self):
        """Test password-based authentication"""
        response = self.client.post('/auth/login/', {
            'username': 'test@example.com',
            'password': 'test-password'
        })

        # Should redirect to dashboard on success
        self.assertEqual(response.status_code, 302)

    def test_token_authentication(self):
        """Test token-based authentication"""
        response = self.client.get(
            '/api/v1/devices/',
            HTTP_AUTHORIZATION='Bearer test-token-here'
        )

        # Should return 200 for valid token
        self.assertEqual(response.status_code, 200)
```

## Troubleshooting

### Common Issues

#### 1. "Failed to fetch JWKS"

**Cause**: Cannot connect to Logto endpoint

**Solution**:
```bash
# Check network connectivity
ping 10.200.2.12

# Verify Logto is running
podman ps | grep logto

# Check firewall rules
sudo firewall-cmd --list-all
```

#### 2. "Token verification failed"

**Cause**: Invalid token or signature mismatch

**Solution**:
```bash
# Verify token issuer matches configuration
echo $LOGTO_ENDPOINT

# Check application credentials
echo $LOGTO_APP_ID

# Clear JWKS cache
python manage.py shell
>>> from django.core.cache import cache
>>> cache.delete('logto_jwks')
```

#### 3. "User not created in Django"

**Cause**: Missing email or username in JWT claims

**Solution**:
```python
# Add required scopes in Logto application
# Scopes: openid, profile, email

# Verify claims in token
import jwt
payload = jwt.decode(token, options={"verify_signature": False})
print(payload)
```

## Advanced Configuration

### Custom User Creation Logic

Override `_get_or_create_user` method:

```python
from shared.iam import LogtoAuthenticationBackend

class CustomLogtoBackend(LogtoAuthenticationBackend):
    def _get_or_create_user(self, logto_user_id, username, email, payload):
        # Custom logic here
        user = super()._get_or_create_user(logto_user_id, username, email, payload)

        # Add custom fields
        user.department = payload.get('custom:department', '')
        user.save()

        return user
```

### Role-Based Permissions

```python
# In your views
from django.contrib.auth.decorators import login_required, user_passes_test

def is_admin(user):
    return user.groups.filter(name='admin').exists()

@login_required
@user_passes_test(is_admin)
def admin_only_view(request):
    return render(request, 'admin/dashboard.html')
```

## References

- [Logto Documentation](https://docs.logto.io/)
- [OAuth 2.0 RFC](https://datatracker.ietf.org/doc/html/rfc6749)
- [OpenID Connect Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [Django Authentication](https://docs.djangoproject.com/en/5.0/topics/auth/)
- [PyJWT Documentation](https://pyjwt.readthedocs.io/)

## Support

For HookProbe IAM integration support:
- **GitHub Issues**: https://github.com/hookprobe/hookprobe/issues
- **Documentation**: https://docs.hookprobe.com
- **Community**: https://community.hookprobe.com

---

**Last Updated**: 2025-11-25
**HookProbe Version**: 5.0+
**Logto Version**: Latest
