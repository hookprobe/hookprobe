"""
HookProbe IAM Authentication Backend

This module provides authentication integration with Logto (POD-002)
for centralized identity and access management.

Features:
- OAuth 2.0 / OIDC authentication
- JWT token validation
- User synchronization between Logto and Django
- Role and permission mapping
"""

import os
import json
import logging
import requests
from typing import Optional, Dict, Any

from django.contrib.auth.models import User, Group
from django.contrib.auth.backends import BaseBackend
from django.core.cache import cache
from jwt import decode as jwt_decode, PyJWK, PyJWKClient, PyJWTError

logger = logging.getLogger(__name__)


class LogtoAuthenticationBackend(BaseBackend):
    """
    Custom authentication backend for Logto IAM integration.

    This backend authenticates users against Logto (POD-002) and creates
    or updates local Django user accounts for session management.
    """

    def __init__(self):
        """Initialize the Logto authentication backend."""
        self.logto_endpoint = os.getenv('LOGTO_ENDPOINT', 'http://10.200.2.12:3001')
        self.logto_app_id = os.getenv('LOGTO_APP_ID', '')
        self.logto_app_secret = os.getenv('LOGTO_APP_SECRET', '')
        self.logto_issuer = f"{self.logto_endpoint}/oidc"

        # Cache keys for JWKS
        self.jwks_cache_key = 'logto_jwks'
        self.jwks_cache_timeout = 3600  # 1 hour

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
        try:
            # Call Logto token endpoint
            token_url = f"{self.logto_endpoint}/oidc/token"

            data = {
                'grant_type': 'password',
                'username': username,
                'password': password,
                'client_id': self.logto_app_id,
                'client_secret': self.logto_app_secret,
                'scope': 'openid profile email offline_access'
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
        try:
            # Get JWKS (JSON Web Key Set) from Logto
            jwks = self._get_jwks()

            if not jwks:
                logger.error("Failed to retrieve JWKS")
                return None

            # Decode and verify token
            header = jwt_decode(token, options={"verify_signature": False})
            kid = header.get('kid')

            if not kid:
                logger.error("Token missing 'kid' in header")
                return None

            # Find the correct key
            key = None
            for jwk in jwks.get('keys', []):
                if jwk.get('kid') == kid:
                    key = PyJWK(jwk).key
                    break

            if not key:
                logger.error(f"No matching key found for kid: {kid}")
                return None

            # Verify and decode
            payload = jwt_decode(
                token,
                key=key,
                algorithms=['RS256', 'ES256'],
                audience=self.logto_app_id,
                issuer=self.logto_issuer
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

            # Set staff status based on Logto roles
            roles = payload.get('roles', [])
            if 'admin' in roles or 'staff' in roles:
                user.is_staff = True
                user.is_superuser = 'admin' in roles
                user.save()

            # Sync groups/roles
            self._sync_user_groups(user, roles)

            logger.info(f"Created new user from Logto: {username}")
            return user

        except Exception as e:
            logger.error(f"Error creating/updating user: {str(e)}", exc_info=True)
            raise

    def _sync_user_groups(self, user: User, roles: list):
        """
        Synchronize Django groups with Logto roles.

        Args:
            user: Django User object
            roles: List of role names from Logto
        """
        try:
            # Clear existing groups
            user.groups.clear()

            # Add groups based on Logto roles
            for role_name in roles:
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
