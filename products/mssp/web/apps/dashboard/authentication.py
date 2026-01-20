"""
HookProbe Unified IAM Authentication Backend

This module provides authentication integration with Logto (POD-002)
for centralized identity and access management across all HookProbe services.

Unified Role System:
- admin: Full access to CMS, MSSP Dashboard, Merchandise management
- editor: Blog editing and approvals, read-only MSSP access
- customer: E-commerce/merchandise access only (shop, cart, orders)
- soc_analyst: MSSP security dashboard only (no CMS access)

Features:
- OAuth 2.0 / OIDC authentication
- JWT token validation
- User synchronization between Logto and Django
- Unified role and permission mapping
"""

import os
import logging
from typing import Optional, Dict, Any, List

from django.contrib.auth.models import User, Group, Permission
from django.contrib.auth.backends import BaseBackend
from django.core.cache import cache

try:
    import jwt
    from jwt import PyJWK
    from jwt.exceptions import PyJWTError
except ImportError:
    jwt = None
    PyJWK = None
    PyJWTError = Exception

try:
    import requests
except ImportError:
    requests = None

logger = logging.getLogger(__name__)

# Unified role definitions - shared across all HookProbe services
UNIFIED_ROLES = {
    'admin': {
        'is_staff': True,
        'is_superuser': True,
        'description': 'Full access to CMS, MSSP, and Merchandise management',
        'mssp_access': True,
        'cms_access': True,
        'merchandise_access': True,
    },
    'editor': {
        'is_staff': True,
        'is_superuser': False,
        'description': 'Blog editing and approvals, read-only MSSP',
        'mssp_access': False,  # Read-only via separate check
        'cms_access': True,
        'merchandise_access': False,
    },
    'customer': {
        'is_staff': False,
        'is_superuser': False,
        'description': 'E-commerce access - browse, cart, orders',
        'mssp_access': False,
        'cms_access': False,
        'merchandise_access': True,
    },
    'soc_analyst': {
        'is_staff': False,
        'is_superuser': False,
        'description': 'MSSP security dashboard access only',
        'mssp_access': True,
        'cms_access': False,
        'merchandise_access': False,
    },
}

# OIDC-managed groups for synchronization
OIDC_MANAGED_GROUPS = list(UNIFIED_ROLES.keys())

# Legacy role mapping for backward compatibility
LEGACY_ROLE_MAPPING = {
    'cms_editor': 'editor',
    'cms_viewer': 'customer',
    'staff': 'editor',
}


class LogtoAuthenticationBackend(BaseBackend):
    """
    Unified authentication backend for Logto IAM integration.

    This backend authenticates users against Logto (POD-002) and creates
    or updates local Django user accounts for session management.
    Supports the unified role system across hookprobe.com and mssp.hookprobe.com.
    """

    def __init__(self):
        """Initialize the Logto authentication backend."""
        self.logto_endpoint = os.getenv('LOGTO_ENDPOINT', 'http://10.200.2.12:3001')
        self.logto_app_id = os.getenv('LOGTO_APP_ID', '')
        self.logto_app_secret = os.getenv('LOGTO_APP_SECRET', '')
        self.logto_issuer = os.getenv('LOGTO_ISSUER', f"{self.logto_endpoint}/oidc")

        # Cache keys for JWKS
        self.jwks_cache_key = 'logto_jwks'
        self.jwks_cache_timeout = 3600  # 1 hour

        # Check if Logto is configured
        self.is_configured = bool(self.logto_app_id and self.logto_app_secret)

    def authenticate(self, request, username=None, password=None, access_token=None):
        """
        Authenticate user against Logto IAM.

        Args:
            request: Django HTTP request object
            username: Username for password-based auth
            password: Password for password-based auth
            access_token: OAuth access token for token-based auth

        Returns:
            User object if authentication succeeds, None otherwise
        """
        # Skip Logto authentication if not configured (fall back to ModelBackend)
        if not self.is_configured:
            logger.debug("Logto not configured, skipping Logto authentication")
            return None

        try:
            if access_token:
                # Token-based authentication (OAuth/OIDC)
                return self._authenticate_with_token(access_token)
            elif username and password:
                # Password-based authentication
                return self._authenticate_with_password(username, password)
            else:
                logger.warning("Authentication attempted without credentials")
                return None

        except Exception as e:
            logger.error(f"Authentication error: {str(e)}", exc_info=True)
            return None

    def _authenticate_with_token(self, access_token: str) -> Optional[User]:
        """
        Authenticate using JWT access token from Logto.

        Args:
            access_token: JWT access token

        Returns:
            User object if valid, None otherwise
        """
        try:
            # Verify and decode JWT token
            payload = self._verify_jwt_token(access_token)

            if not payload:
                return None

            # Extract user information from token
            logto_user_id = payload.get('sub')
            email = payload.get('email', '')
            username = payload.get('username', logto_user_id)

            if not logto_user_id:
                logger.error("Token missing 'sub' claim")
                return None

            # Get or create Django user
            user = self._get_or_create_user(
                logto_user_id=logto_user_id,
                username=username,
                email=email,
                payload=payload
            )

            return user

        except Exception as e:
            logger.error(f"Token authentication error: {str(e)}", exc_info=True)
            return None

    def _authenticate_with_password(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate using username and password via Logto.

        This uses Logto's Resource Owner Password Credentials (ROPC) flow.

        Args:
            username: User's username or email
            password: User's password

        Returns:
            User object if valid, None otherwise
        """
        if not requests:
            logger.error("requests library not available")
            return None

        try:
            # Call Logto token endpoint
            token_url = f"{self.logto_endpoint}/oidc/token"

            data = {
                'grant_type': 'password',
                'username': username,
                'password': password,
                'client_id': self.logto_app_id,
                'client_secret': self.logto_app_secret,
                'scope': 'openid profile email roles offline_access'
            }

            response = requests.post(
                token_url,
                data=data,
                timeout=10,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )

            if response.status_code != 200:
                logger.warning(f"Logto authentication failed for user: {username}")
                return None

            token_data = response.json()
            access_token = token_data.get('access_token')

            if not access_token:
                return None

            # Authenticate with the received token
            return self._authenticate_with_token(access_token)

        except requests.RequestException as e:
            logger.error(f"Network error during password authentication: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Password authentication error: {str(e)}", exc_info=True)
            return None

    def _verify_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify JWT token signature and decode payload.

        Args:
            token: JWT access token

        Returns:
            Decoded token payload if valid, None otherwise
        """
        if not jwt:
            logger.error("PyJWT library not available")
            return None

        try:
            # Get JWKS (JSON Web Key Set) from Logto
            jwks = self._get_jwks()

            if not jwks:
                logger.error("Failed to retrieve JWKS")
                return None

            # Decode header to get kid
            header = jwt.get_unverified_header(token)
            kid = header.get('kid')

            if not kid:
                logger.error("Token missing 'kid' in header")
                return None

            # Find the correct key
            key = None
            for jwk in jwks.get('keys', []):
                if jwk.get('kid') == kid:
                    if PyJWK:
                        key = PyJWK.from_dict(jwk).key
                    break

            if not key:
                logger.error(f"No matching key found for kid: {kid}")
                return None

            # Verify and decode
            payload = jwt.decode(
                token,
                key=key,
                algorithms=['RS256', 'ES256'],
                audience=self.logto_app_id,
                issuer=self.logto_issuer,
                options={'verify_exp': True}
            )

            return payload

        except PyJWTError as e:
            logger.error(f"JWT verification failed: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Token verification error: {str(e)}", exc_info=True)
            return None

    def _get_jwks(self) -> Optional[Dict[str, Any]]:
        """
        Get JSON Web Key Set from Logto.

        Returns JWKS from cache if available, otherwise fetches from Logto.

        Returns:
            JWKS dictionary or None if unavailable
        """
        if not requests:
            return None

        # Try cache first
        jwks = cache.get(self.jwks_cache_key)

        if jwks:
            return jwks

        try:
            # Fetch from Logto
            jwks_url = f"{self.logto_endpoint}/oidc/jwks"
            response = requests.get(jwks_url, timeout=10)

            if response.status_code == 200:
                jwks = response.json()
                # Cache for 1 hour
                cache.set(self.jwks_cache_key, jwks, self.jwks_cache_timeout)
                return jwks
            else:
                logger.error(f"Failed to fetch JWKS: HTTP {response.status_code}")
                return None

        except requests.RequestException as e:
            logger.error(f"Network error fetching JWKS: {str(e)}")
            return None

    def _extract_roles(self, payload: Dict[str, Any]) -> List[str]:
        """
        Extract and normalize roles from JWT payload.

        Args:
            payload: Decoded JWT payload

        Returns:
            List of normalized role names
        """
        roles = payload.get('roles', [])

        # Also check custom claims that Logto might use
        if not roles:
            roles = payload.get('custom:roles', [])
        if not roles:
            # Check for role in organization context
            org_roles = payload.get('organization_roles', [])
            roles = [r.get('name') for r in org_roles if isinstance(r, dict)]
        if not roles:
            # Check for scope-based roles
            scope = payload.get('scope', '')
            if isinstance(scope, str):
                for potential_role in OIDC_MANAGED_GROUPS:
                    if potential_role in scope:
                        roles.append(potential_role)

        # Normalize role names (handle legacy role names)
        normalized_roles = []
        for role in roles:
            normalized = LEGACY_ROLE_MAPPING.get(role, role)
            normalized_roles.append(normalized)

        return list(set(normalized_roles))  # Remove duplicates

    def _get_or_create_user(
        self,
        logto_user_id: str,
        username: str,
        email: str,
        payload: Dict[str, Any]
    ) -> User:
        """
        Get existing Django user or create new one from Logto data.

        Args:
            logto_user_id: Unique Logto user ID
            username: User's username
            email: User's email address
            payload: Full JWT payload with user claims

        Returns:
            Django User object
        """
        try:
            # Try to find user by email first (most reliable)
            if email:
                try:
                    user = User.objects.get(email=email)
                    # Update username if changed in Logto
                    if user.username != username:
                        user.username = username
                        user.save()
                    # Sync roles on each login
                    self._sync_user_permissions(user, payload)
                    return user
                except User.DoesNotExist:
                    pass

            # Try by username
            try:
                user = User.objects.get(username=username)
                # Update email if changed
                if email and user.email != email:
                    user.email = email
                    user.save()
                # Sync roles on each login
                self._sync_user_permissions(user, payload)
                return user
            except User.DoesNotExist:
                pass

            # Create new user
            user = User.objects.create_user(
                username=username,
                email=email,
                first_name=payload.get('given_name', ''),
                last_name=payload.get('family_name', ''),
            )

            # Set permissions based on Logto roles
            self._sync_user_permissions(user, payload)

            logger.info(f"Created new user from Logto: {username}")
            return user

        except Exception as e:
            logger.error(f"Error creating/updating user: {str(e)}", exc_info=True)
            raise

    def _sync_user_permissions(self, user: User, payload: Dict[str, Any]):
        """
        Synchronize Django user permissions with Logto roles.

        Unified Role System:
        - admin: is_staff=True, is_superuser=True (full access)
        - editor: is_staff=True (CMS admin access)
        - customer: is_staff=False (merchandise access only)
        - soc_analyst: is_staff=False (MSSP dashboard only)
        """
        roles = self._extract_roles(payload)

        # Default: no admin access
        user.is_staff = False
        user.is_superuser = False

        # Apply highest privilege role
        if 'admin' in roles:
            user.is_staff = True
            user.is_superuser = True
            logger.info(f"User {user.username} granted admin access")
        elif 'editor' in roles:
            user.is_staff = True
            logger.info(f"User {user.username} granted editor access")
        elif 'soc_analyst' in roles:
            # SOC analyst gets staff for MSSP admin access
            user.is_staff = True
            logger.info(f"User {user.username} granted SOC analyst access")
        elif 'customer' in roles:
            logger.info(f"User {user.username} granted customer access")

        user.save()

        # Sync Django groups
        self._sync_user_groups(user, roles)

    def _sync_user_groups(self, user: User, roles: List[str]):
        """
        Synchronize Django groups with Logto roles.

        Args:
            user: Django User object
            roles: List of role names from Logto
        """
        try:
            # Remove user from all OIDC-managed groups first
            for group_name in OIDC_MANAGED_GROUPS:
                try:
                    group = Group.objects.get(name=group_name)
                    user.groups.remove(group)
                except Group.DoesNotExist:
                    pass

            # Add groups based on current roles
            for role_name in roles:
                if role_name in UNIFIED_ROLES:
                    group, created = Group.objects.get_or_create(name=role_name)
                    user.groups.add(group)

                    if created:
                        logger.info(f"Created new group: {role_name}")

        except Exception as e:
            logger.error(f"Error syncing user groups: {str(e)}", exc_info=True)

    def get_user(self, user_id):
        """
        Get user by ID (required by Django auth backend interface).

        Args:
            user_id: Django user primary key

        Returns:
            User object or None
        """
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


class LogtoMiddleware:
    """
    Middleware to handle Logto OAuth tokens in request headers.

    Checks for Bearer token in Authorization header and authenticates user.
    """

    def __init__(self, get_response):
        """Initialize middleware."""
        self.get_response = get_response
        self.backend = LogtoAuthenticationBackend()

    def __call__(self, request):
        """
        Process request and authenticate if token is present.

        Args:
            request: Django HTTP request

        Returns:
            HTTP response
        """
        # Check for Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')

        if auth_header.startswith('Bearer '):
            token = auth_header[7:]  # Remove 'Bearer ' prefix

            # Authenticate user with token
            user = self.backend.authenticate(request, access_token=token)

            if user:
                # Set authenticated user on request
                request.user = user

        response = self.get_response(request)
        return response


# Helper functions for role checking in views
def user_is_admin(user) -> bool:
    """Check if user has admin role."""
    if not user.is_authenticated:
        return False
    return user.is_superuser or user.groups.filter(name='admin').exists()


def user_is_editor(user) -> bool:
    """Check if user has editor role or higher."""
    if not user.is_authenticated:
        return False
    return user_is_admin(user) or user.groups.filter(name='editor').exists()


def user_is_customer(user) -> bool:
    """Check if user has customer role or higher."""
    if not user.is_authenticated:
        return False
    return user.is_authenticated  # Any authenticated user can be a customer


def user_is_soc_analyst(user) -> bool:
    """Check if user has SOC analyst role or higher."""
    if not user.is_authenticated:
        return False
    return user_is_admin(user) or user.groups.filter(name='soc_analyst').exists()


def user_can_access_mssp(user) -> bool:
    """Check if user can access MSSP dashboard."""
    if not user.is_authenticated:
        return False
    # Admin and soc_analyst can access MSSP
    return user.groups.filter(name__in=['admin', 'soc_analyst']).exists() or user.is_superuser


def user_can_access_cms(user) -> bool:
    """Check if user can access CMS/blog management."""
    if not user.is_authenticated:
        return False
    # Admin and editor can access CMS
    return user.groups.filter(name__in=['admin', 'editor']).exists() or user.is_superuser


def user_can_access_merchandise(user) -> bool:
    """Check if user can access merchandise/e-commerce features."""
    if not user.is_authenticated:
        return False
    # Admin and customer can access merchandise
    return user.groups.filter(name__in=['admin', 'customer']).exists() or user.is_superuser


def get_user_roles(user) -> List[str]:
    """Get list of role names for a user."""
    if not user.is_authenticated:
        return []
    return list(user.groups.filter(name__in=OIDC_MANAGED_GROUPS).values_list('name', flat=True))


def get_role_config(role_name: str) -> Dict[str, Any]:
    """Get configuration for a specific role."""
    return UNIFIED_ROLES.get(role_name, {})
