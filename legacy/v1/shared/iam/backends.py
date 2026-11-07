"""
HookProbe Unified IAM Authentication Backends

This module provides authentication integration with Logto (POD-002)
for centralized identity and access management across all HookProbe services.

Two backends are provided:
1. LogtoAuthenticationBackend - For JWT token validation (MSSP, API)
2. LogtoOIDCBackend - For OIDC flows (hookprobe.com via mozilla-django-oidc)

Unified Role System:
- admin: Full access to CMS, MSSP Dashboard, Merchandise management
- soc_analyst: MSSP security dashboard only (no CMS access)
- editor: Blog editing and approvals, read-only MSSP access
- customer: E-commerce/merchandise access only (shop, cart, orders)
"""

import os
import logging
from typing import Optional, Dict, Any, List, TYPE_CHECKING

from django.contrib.auth.models import User, Group, Permission
from django.contrib.auth.backends import BaseBackend
from django.core.cache import cache

from .roles import (
    UNIFIED_ROLES,
    OIDC_MANAGED_GROUPS,
    normalize_role,
)
from .exceptions import TokenError, JWKSError, AuthenticationError

if TYPE_CHECKING:
    from django.http import HttpRequest

# Conditional imports for JWT validation
try:
    import jwt
    from jwt import PyJWK
    from jwt.exceptions import PyJWTError
except ImportError:
    jwt = None
    PyJWK = None
    PyJWTError = Exception

# Conditional imports for HTTP requests
try:
    import requests
except ImportError:
    requests = None

# Conditional import for OIDC backend
try:
    from mozilla_django_oidc.auth import OIDCAuthenticationBackend
    HAS_OIDC = True
except ImportError:
    OIDCAuthenticationBackend = BaseBackend  # Fallback
    HAS_OIDC = False

logger = logging.getLogger(__name__)


class LogtoAuthenticationBackend(BaseBackend):
    """
    Unified authentication backend for Logto IAM integration (JWT-based).

    This backend authenticates users against Logto (POD-002) using JWT tokens
    and creates or updates local Django user accounts for session management.

    Used by:
    - MSSP Dashboard (mssp.hookprobe.com)
    - API endpoints with Bearer token authentication

    Configuration (environment variables):
    - LOGTO_ENDPOINT: Logto server URL (default: http://10.200.2.12:3001)
    - LOGTO_APP_ID: Application client ID
    - LOGTO_APP_SECRET: Application client secret
    - LOGTO_ISSUER: Token issuer (default: {LOGTO_ENDPOINT}/oidc)
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

    def authenticate(
        self,
        request: Optional['HttpRequest'] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        access_token: Optional[str] = None,
        **kwargs
    ) -> Optional[User]:
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
                # Password-based authentication (ROPC flow)
                return self._authenticate_with_password(username, password)
            else:
                logger.debug("No credentials provided for Logto authentication")
                return None

        except AuthenticationError as e:
            logger.warning(f"Authentication failed: {e.message}")
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

        except TokenError as e:
            logger.warning(f"Token authentication failed: {e.message}")
            return None
        except Exception as e:
            logger.error(f"Token authentication error: {str(e)}", exc_info=True)
            return None

    def _authenticate_with_password(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate using username and password via Logto ROPC flow.

        Note: ROPC (Resource Owner Password Credentials) should only be used
        when other OAuth flows are not possible.

        Args:
            username: User's username or email
            password: User's password

        Returns:
            User object if valid, None otherwise
        """
        if not requests:
            logger.error("requests library not available for ROPC flow")
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
                logger.warning(f"Logto ROPC authentication failed for user: {username}")
                return None

            token_data = response.json()
            access_token = token_data.get('access_token')

            if not access_token:
                return None

            # Authenticate with the received token
            return self._authenticate_with_token(access_token)

        except requests.RequestException as e:
            logger.error(f"Network error during ROPC authentication: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"ROPC authentication error: {str(e)}", exc_info=True)
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
                raise JWKSError("Failed to retrieve JWKS")

            # Decode header to get kid
            header = jwt.get_unverified_header(token)
            kid = header.get('kid')

            if not kid:
                raise TokenError("Token missing 'kid' in header")

            # Find the correct key
            key = None
            for jwk in jwks.get('keys', []):
                if jwk.get('kid') == kid:
                    if PyJWK:
                        key = PyJWK.from_dict(jwk).key
                    break

            if not key:
                raise TokenError(f"No matching key found for kid: {kid}")

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
        except JWKSError:
            raise
        except TokenError:
            raise
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

        Checks multiple claim formats that Logto might use:
        - roles: Direct role array
        - custom:roles: Custom claims
        - organization_roles: Organization context
        - scope: Scope-based roles

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

        # Normalize role names
        normalized_roles = [normalize_role(role) for role in roles]

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
                        user.save(update_fields=['username'])
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
                    user.save(update_fields=['email'])
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
        - soc_analyst: is_staff=True (MSSP admin access)
        - editor: is_staff=True (CMS admin access)
        - customer: is_staff=False (merchandise access only)

        Args:
            user: Django User object
            payload: JWT payload containing role claims
        """
        roles = self._extract_roles(payload)

        # Default: no admin access
        user.is_staff = False
        user.is_superuser = False

        # Apply permissions based on highest privilege role
        if 'admin' in roles:
            user.is_staff = True
            user.is_superuser = True
            logger.info(f"User {user.username} granted admin access")
        elif 'soc_analyst' in roles:
            # SOC analyst gets staff for MSSP admin access
            user.is_staff = True
            logger.info(f"User {user.username} granted SOC analyst access")
        elif 'editor' in roles:
            user.is_staff = True
            logger.info(f"User {user.username} granted editor access")
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
                        # Set up default permissions for new group
                        self._setup_group_permissions(group, role_name)

        except Exception as e:
            logger.error(f"Error syncing user groups: {str(e)}", exc_info=True)

    def _setup_group_permissions(self, group: Group, role_name: str):
        """
        Set up default permissions for a group based on role definition.

        Args:
            group: Django Group object
            role_name: Role name to get permissions for
        """
        role_config = UNIFIED_ROLES.get(role_name, {})
        permission_codes = role_config.get('permissions', [])

        if 'all' in permission_codes:
            # Admin gets all permissions - handled by is_superuser
            return

        for perm_code in permission_codes:
            try:
                if '.' in perm_code:
                    app_label, codename = perm_code.split('.', 1)
                    permission = Permission.objects.get(
                        content_type__app_label=app_label,
                        codename=codename
                    )
                    group.permissions.add(permission)
            except Permission.DoesNotExist:
                logger.warning(f"Permission not found: {perm_code}")
            except Exception as e:
                logger.error(f"Error setting permission {perm_code}: {e}")

    def get_user(self, user_id: int) -> Optional[User]:
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


# OIDC Backend (for hookprobe.com using mozilla-django-oidc)
if HAS_OIDC:
    class LogtoOIDCBackend(OIDCAuthenticationBackend):
        """
        OIDC authentication backend for Logto integration.

        This backend uses mozilla-django-oidc to handle the OIDC flow
        and synchronizes users with the unified role system.

        Used by:
        - hookprobe.com (public website)

        Configuration (Django settings):
        - OIDC_OP_* settings for Logto endpoints
        - OIDC_RP_* settings for client credentials
        """

        def filter_users_by_claims(self, claims: Dict[str, Any]):
            """
            Find existing users by email or Logto sub (user ID).
            """
            email = claims.get('email')
            sub = claims.get('sub')

            if email:
                users = self.UserModel.objects.filter(email__iexact=email)
                if users.exists():
                    return users

            # Try by username (Logto sub)
            if sub:
                users = self.UserModel.objects.filter(username=sub)
                if users.exists():
                    return users

            return self.UserModel.objects.none()

        def create_user(self, claims: Dict[str, Any]) -> User:
            """
            Create a new user from Logto claims.
            """
            email = claims.get('email', '')
            sub = claims.get('sub', '')

            # Use email prefix as username if available, otherwise use sub
            if email:
                username = email.split('@')[0]
                # Ensure uniqueness
                base_username = username
                counter = 1
                while self.UserModel.objects.filter(username=username).exists():
                    username = f"{base_username}{counter}"
                    counter += 1
            else:
                username = sub

            user = self.UserModel.objects.create_user(
                username=username,
                email=email,
                first_name=claims.get('given_name', claims.get('name', '')),
                last_name=claims.get('family_name', ''),
            )

            # Set permissions based on Logto roles
            self._sync_user_permissions(user, claims)

            logger.info(f"Created user from Logto OIDC: {username} ({email})")
            return user

        def update_user(self, user: User, claims: Dict[str, Any]) -> User:
            """
            Update existing user from Logto claims on each login.
            """
            # Update basic info
            user.email = claims.get('email', user.email)
            user.first_name = claims.get('given_name', claims.get('name', user.first_name))
            user.last_name = claims.get('family_name', user.last_name)

            # Sync permissions
            self._sync_user_permissions(user, claims)

            user.save()
            logger.debug(f"Updated user from Logto OIDC: {user.username}")
            return user

        def _extract_roles(self, claims: Dict[str, Any]) -> List[str]:
            """
            Extract and normalize roles from OIDC claims.
            """
            roles = claims.get('roles', [])

            # Also check custom claims that Logto might use
            if not roles:
                roles = claims.get('custom:roles', [])
            if not roles:
                # Check for role in organization context
                org_roles = claims.get('organization_roles', [])
                roles = [r.get('name') for r in org_roles if isinstance(r, dict)]
            if not roles:
                # Check for scope-based roles
                scope = claims.get('scope', '')
                if isinstance(scope, str):
                    for potential_role in OIDC_MANAGED_GROUPS:
                        if potential_role in scope:
                            roles.append(potential_role)

            # Normalize role names
            normalized_roles = [normalize_role(role) for role in roles]

            return list(set(normalized_roles))

        def _sync_user_permissions(self, user: User, claims: Dict[str, Any]):
            """
            Sync Django user permissions based on Logto roles.
            """
            roles = self._extract_roles(claims)

            # Default: no admin access
            user.is_staff = False
            user.is_superuser = False

            # Apply highest privilege role
            if 'admin' in roles:
                user.is_staff = True
                user.is_superuser = True
                logger.info(f"User {user.username} granted admin access")
            elif 'soc_analyst' in roles:
                user.is_staff = True
                logger.info(f"User {user.username} granted SOC analyst access")
            elif 'editor' in roles:
                user.is_staff = True
                logger.info(f"User {user.username} granted editor access")
            elif 'customer' in roles:
                logger.info(f"User {user.username} granted customer access")

            # Sync Django groups
            self._sync_groups(user, roles)

            user.save()

        def _sync_groups(self, user: User, roles: List[str]):
            """
            Sync Django groups with Logto roles.
            """
            # Remove user from all OIDC-managed groups first
            for group_name in OIDC_MANAGED_GROUPS:
                try:
                    group = Group.objects.get(name=group_name)
                    user.groups.remove(group)
                except Group.DoesNotExist:
                    pass

            # Add groups based on current roles
            for role in roles:
                if role in UNIFIED_ROLES:
                    group, created = Group.objects.get_or_create(name=role)
                    if created:
                        logger.info(f"Created group: {role}")
                        self._setup_group_permissions(group, role)
                    user.groups.add(group)

        def _setup_group_permissions(self, group: Group, role_name: str):
            """
            Set up default permissions for a group based on role definition.
            """
            role_config = UNIFIED_ROLES.get(role_name, {})
            permission_codes = role_config.get('permissions', [])

            if 'all' in permission_codes:
                return

            for perm_code in permission_codes:
                try:
                    if '.' in perm_code:
                        app_label, codename = perm_code.split('.', 1)
                        permission = Permission.objects.get(
                            content_type__app_label=app_label,
                            codename=codename
                        )
                        group.permissions.add(permission)
                except Permission.DoesNotExist:
                    logger.warning(f"Permission not found: {perm_code}")
                except Exception as e:
                    logger.error(f"Error setting permission {perm_code}: {e}")

        def verify_claims(self, claims: Dict[str, Any]) -> bool:
            """
            Verify required claims are present.
            """
            if not claims.get('sub'):
                logger.error("OIDC claims missing 'sub'")
                return False
            return True


    class LogtoOIDCBackendAllowAll(LogtoOIDCBackend):
        """
        Variant that allows all authenticated Logto users.

        Use this if you want any MSSP user to access the site.
        Default role assigned: customer
        """

        def _extract_roles(self, claims: Dict[str, Any]) -> List[str]:
            """
            Extract roles, defaulting to 'customer' if none specified.
            """
            roles = super()._extract_roles(claims)

            # Default to customer role if no recognized role
            if not any(r in UNIFIED_ROLES for r in roles):
                roles.append('customer')

            return roles

        def verify_claims(self, claims: Dict[str, Any]) -> bool:
            """Allow all users with valid sub claim."""
            return bool(claims.get('sub'))

else:
    # Fallback when mozilla-django-oidc is not installed
    class LogtoOIDCBackend(BaseBackend):
        """Placeholder when mozilla-django-oidc is not installed."""

        def authenticate(self, request=None, **kwargs):
            logger.warning("LogtoOIDCBackend requires mozilla-django-oidc package")
            return None

        def get_user(self, user_id):
            return None

    class LogtoOIDCBackendAllowAll(LogtoOIDCBackend):
        """Placeholder when mozilla-django-oidc is not installed."""
        pass
