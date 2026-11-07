"""
HookProbe IAM Custom Exceptions

Custom exceptions for authentication and authorization errors.
"""

from typing import Optional, List


class IAMError(Exception):
    """Base exception for IAM-related errors."""

    def __init__(self, message: str, code: Optional[str] = None):
        self.message = message
        self.code = code or 'iam_error'
        super().__init__(self.message)


class AuthenticationError(IAMError):
    """Raised when authentication fails."""

    def __init__(self, message: str = "Authentication failed", code: str = "auth_failed"):
        super().__init__(message, code)


class TokenError(AuthenticationError):
    """Raised when token validation fails."""

    def __init__(self, message: str = "Invalid or expired token", code: str = "invalid_token"):
        super().__init__(message, code)


class JWKSError(AuthenticationError):
    """Raised when JWKS retrieval or parsing fails."""

    def __init__(self, message: str = "Failed to retrieve JWKS", code: str = "jwks_error"):
        super().__init__(message, code)


class AuthorizationError(IAMError):
    """Raised when authorization fails (user lacks permissions)."""

    def __init__(
        self,
        message: str = "Access denied",
        code: str = "access_denied",
        required_roles: Optional[List[str]] = None
    ):
        self.required_roles = required_roles or []
        super().__init__(message, code)


class RoleNotFoundError(IAMError):
    """Raised when a role doesn't exist in the system."""

    def __init__(self, role_name: str):
        self.role_name = role_name
        super().__init__(f"Role not found: {role_name}", "role_not_found")


class UserSyncError(IAMError):
    """Raised when user synchronization with Logto fails."""

    def __init__(self, message: str = "Failed to sync user from identity provider"):
        super().__init__(message, "user_sync_error")


class ConfigurationError(IAMError):
    """Raised when IAM configuration is missing or invalid."""

    def __init__(self, message: str = "IAM configuration error"):
        super().__init__(message, "config_error")
