"""
HookProbe IAM Middleware

Middleware components for authentication and authorization.
"""

import logging
from typing import Callable, TYPE_CHECKING

from django.http import HttpResponse

if TYPE_CHECKING:
    from django.http import HttpRequest

logger = logging.getLogger(__name__)


class LogtoMiddleware:
    """
    Middleware to handle Logto OAuth tokens in request headers.

    Checks for Bearer token in Authorization header and authenticates user.
    This is used for API endpoints that receive JWT tokens from clients.

    Usage:
        # In settings.py MIDDLEWARE list
        MIDDLEWARE = [
            ...
            'shared.iam.middleware.LogtoMiddleware',
            ...
        ]
    """

    def __init__(self, get_response: Callable):
        """
        Initialize middleware.

        Args:
            get_response: Django's response callable
        """
        self.get_response = get_response
        # Lazy import to avoid circular imports
        self._backend = None

    @property
    def backend(self):
        """Lazy-load the authentication backend."""
        if self._backend is None:
            from .backends import LogtoAuthenticationBackend
            self._backend = LogtoAuthenticationBackend()
        return self._backend

    def __call__(self, request: 'HttpRequest') -> HttpResponse:
        """
        Process request and authenticate if Bearer token is present.

        Args:
            request: Django HTTP request

        Returns:
            HTTP response
        """
        # Check for Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')

        if auth_header.startswith('Bearer '):
            token = auth_header[7:]  # Remove 'Bearer ' prefix

            # Only authenticate if user is not already authenticated
            if not hasattr(request, 'user') or not request.user.is_authenticated:
                # Authenticate user with token
                user = self.backend.authenticate(request, access_token=token)

                if user:
                    # Set authenticated user on request
                    request.user = user
                    logger.debug(f"Authenticated user via Bearer token: {user.username}")

        response = self.get_response(request)
        return response


class RoleEnforcementMiddleware:
    """
    Middleware to enforce role-based access on URL paths.

    Configure URL path prefixes that require specific roles.
    Requests without required roles will receive a 403 Forbidden response.

    Usage:
        # In settings.py
        MIDDLEWARE = [
            ...
            'shared.iam.middleware.RoleEnforcementMiddleware',
            ...
        ]

        # Configure protected paths
        IAM_PROTECTED_PATHS = {
            '/mssp/': ['admin', 'soc_analyst'],
            '/admin/cms/': ['admin', 'editor'],
            '/shop/checkout/': ['admin', 'customer'],
        }
    """

    def __init__(self, get_response: Callable):
        """
        Initialize middleware.

        Args:
            get_response: Django's response callable
        """
        self.get_response = get_response
        self._protected_paths = None

    @property
    def protected_paths(self):
        """Lazy-load protected paths from settings."""
        if self._protected_paths is None:
            from django.conf import settings
            self._protected_paths = getattr(settings, 'IAM_PROTECTED_PATHS', {})
        return self._protected_paths

    def __call__(self, request: 'HttpRequest') -> HttpResponse:
        """
        Process request and enforce role requirements.

        Args:
            request: Django HTTP request

        Returns:
            HTTP response or 403 Forbidden
        """
        from .helpers import user_has_any_role

        path = request.path

        # Check each protected path prefix
        for path_prefix, required_roles in self.protected_paths.items():
            if path.startswith(path_prefix):
                # Path is protected
                if not request.user.is_authenticated:
                    from django.conf import settings
                    from django.shortcuts import redirect
                    login_url = getattr(settings, 'LOGIN_URL', '/login/')
                    return redirect(f"{login_url}?next={path}")

                # Check if user has required role
                if not user_has_any_role(request.user, required_roles):
                    from django.http import HttpResponseForbidden
                    return HttpResponseForbidden(
                        f"Access denied. Required roles: {', '.join(required_roles)}"
                    )

                # User has access, continue
                break

        response = self.get_response(request)
        return response


class UserRoleContextMiddleware:
    """
    Middleware to add user role information to request.

    Adds convenient role-checking attributes to the request object
    that can be used in views and templates.

    Usage:
        # In settings.py
        MIDDLEWARE = [
            ...
            'shared.iam.middleware.UserRoleContextMiddleware',
            ...
        ]

        # In views
        if request.is_admin:
            ...

        # In templates
        {% if request.is_editor %}
            ...
        {% endif %}
    """

    def __init__(self, get_response: Callable):
        """
        Initialize middleware.

        Args:
            get_response: Django's response callable
        """
        self.get_response = get_response

    def __call__(self, request: 'HttpRequest') -> HttpResponse:
        """
        Process request and add role context.

        Args:
            request: Django HTTP request

        Returns:
            HTTP response
        """
        from .helpers import (
            user_is_admin,
            user_is_editor,
            user_is_soc_analyst,
            user_can_access_mssp,
            user_can_access_cms,
            user_can_access_merchandise,
            get_user_roles,
            get_user_primary_role,
        )

        # Add role-checking attributes to request
        # These are computed lazily using descriptors would be better,
        # but for simplicity we compute them once per request
        if hasattr(request, 'user') and request.user.is_authenticated:
            request.is_admin = user_is_admin(request.user)
            request.is_editor = user_is_editor(request.user)
            request.is_soc_analyst = user_is_soc_analyst(request.user)
            request.can_access_mssp = user_can_access_mssp(request.user)
            request.can_access_cms = user_can_access_cms(request.user)
            request.can_access_merchandise = user_can_access_merchandise(request.user)
            request.user_roles = get_user_roles(request.user)
            request.primary_role = get_user_primary_role(request.user)
        else:
            request.is_admin = False
            request.is_editor = False
            request.is_soc_analyst = False
            request.can_access_mssp = False
            request.can_access_cms = False
            request.can_access_merchandise = False
            request.user_roles = []
            request.primary_role = ''

        response = self.get_response(request)
        return response
