"""
HookProbe Unified IAM Module

Centralized Identity and Access Management for all HookProbe services.
This module provides the single source of truth for:
- Role definitions (UNIFIED_ROLES)
- Authentication backends (Logto JWT and OIDC)
- Authorization helpers and decorators
- Middleware for token and role handling

Usage:
    # Import roles
    from shared.iam import UNIFIED_ROLES, OIDC_MANAGED_GROUPS

    # Import helpers
    from shared.iam import user_is_admin, user_can_access_mssp

    # Import decorators
    from shared.iam import admin_required, role_required

    # Import backends
    from shared.iam import LogtoAuthenticationBackend, LogtoOIDCBackend

    # Import middleware
    from shared.iam import LogtoMiddleware

Supported services:
- hookprobe.com (public website, blog, merchandise)
- mssp.hookprobe.com (MSSP security dashboard)

Role hierarchy:
1. admin - Full access to everything
2. soc_analyst - MSSP dashboard only
3. editor - CMS/blog editing only
4. customer - Shop/merchandise only
"""

# Version
__version__ = '1.0.0'

# Role definitions (single source of truth)
from .roles import (
    UNIFIED_ROLES,
    OIDC_MANAGED_GROUPS,
    get_role_config,
    get_role_priority,
    get_highest_privilege_role,
    normalize_role,
    role_can_access,
)

# Helper functions
from .helpers import (
    user_is_admin,
    user_is_editor,
    user_is_customer,
    user_is_soc_analyst,
    user_can_access_mssp,
    user_can_access_cms,
    user_can_access_merchandise,
    get_user_roles,
    get_user_primary_role,
    user_has_role,
    user_has_any_role,
    user_has_all_roles,
    get_user_access_list,
)

# Decorators
from .decorators import (
    role_required,
    roles_required,
    admin_required,
    mssp_access_required,
    cms_access_required,
    merchandise_access_required,
)

# Exceptions
from .exceptions import (
    IAMError,
    AuthenticationError,
    TokenError,
    JWKSError,
    AuthorizationError,
    RoleNotFoundError,
    UserSyncError,
    ConfigurationError,
)

# Authentication backends
from .backends import (
    LogtoAuthenticationBackend,
    LogtoOIDCBackend,
    LogtoOIDCBackendAllowAll,
)

# Middleware
from .middleware import (
    LogtoMiddleware,
    RoleEnforcementMiddleware,
    UserRoleContextMiddleware,
)

__all__ = [
    # Version
    '__version__',
    # Roles
    'UNIFIED_ROLES',
    'OIDC_MANAGED_GROUPS',
    'get_role_config',
    'get_role_priority',
    'get_highest_privilege_role',
    'normalize_role',
    'role_can_access',
    # Helpers
    'user_is_admin',
    'user_is_editor',
    'user_is_customer',
    'user_is_soc_analyst',
    'user_can_access_mssp',
    'user_can_access_cms',
    'user_can_access_merchandise',
    'get_user_roles',
    'get_user_primary_role',
    'user_has_role',
    'user_has_any_role',
    'user_has_all_roles',
    'get_user_access_list',
    # Decorators
    'role_required',
    'roles_required',
    'admin_required',
    'mssp_access_required',
    'cms_access_required',
    'merchandise_access_required',
    # Exceptions
    'IAMError',
    'AuthenticationError',
    'TokenError',
    'JWKSError',
    'AuthorizationError',
    'RoleNotFoundError',
    'UserSyncError',
    'ConfigurationError',
    # Backends
    'LogtoAuthenticationBackend',
    'LogtoOIDCBackend',
    'LogtoOIDCBackendAllowAll',
    # Middleware
    'LogtoMiddleware',
    'RoleEnforcementMiddleware',
    'UserRoleContextMiddleware',
]
