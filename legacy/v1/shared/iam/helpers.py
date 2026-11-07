"""
HookProbe IAM Helper Functions

Utility functions for role checking and access control.
These can be used in views, templates, and APIs.
"""

from typing import List, TYPE_CHECKING

from .roles import UNIFIED_ROLES, OIDC_MANAGED_GROUPS

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractUser


def user_is_admin(user: 'AbstractUser') -> bool:
    """
    Check if user has admin role.

    Admin users have full access to all services:
    - CMS/Blog management
    - MSSP Dashboard
    - Merchandise management

    Args:
        user: Django User object

    Returns:
        True if user is an admin
    """
    if not user.is_authenticated:
        return False
    return user.is_superuser or user.groups.filter(name='admin').exists()


def user_is_editor(user: 'AbstractUser') -> bool:
    """
    Check if user has editor role or higher.

    Editor users can:
    - Create and edit blog posts
    - Manage CMS content

    Args:
        user: Django User object

    Returns:
        True if user is an editor or admin
    """
    if not user.is_authenticated:
        return False
    return user_is_admin(user) or user.groups.filter(name='editor').exists()


def user_is_customer(user: 'AbstractUser') -> bool:
    """
    Check if user has customer role or is authenticated.

    Any authenticated user can be a customer.

    Args:
        user: Django User object

    Returns:
        True if user is authenticated
    """
    if not user.is_authenticated:
        return False
    return True  # Any authenticated user can be a customer


def user_is_soc_analyst(user: 'AbstractUser') -> bool:
    """
    Check if user has SOC analyst role or higher.

    SOC analysts can:
    - Access MSSP security dashboard
    - View security metrics and alerts

    Args:
        user: Django User object

    Returns:
        True if user is a SOC analyst or admin
    """
    if not user.is_authenticated:
        return False
    return user_is_admin(user) or user.groups.filter(name='soc_analyst').exists()


def user_can_access_mssp(user: 'AbstractUser') -> bool:
    """
    Check if user can access MSSP dashboard.

    MSSP access is granted to:
    - admin: Full access
    - soc_analyst: Dashboard access

    Args:
        user: Django User object

    Returns:
        True if user can access MSSP
    """
    if not user.is_authenticated:
        return False
    return (
        user.is_superuser or
        user.groups.filter(name__in=['admin', 'soc_analyst']).exists()
    )


def user_can_access_cms(user: 'AbstractUser') -> bool:
    """
    Check if user can access CMS/blog management.

    CMS access is granted to:
    - admin: Full access
    - editor: Create/edit blog posts

    Args:
        user: Django User object

    Returns:
        True if user can access CMS
    """
    if not user.is_authenticated:
        return False
    return (
        user.is_superuser or
        user.groups.filter(name__in=['admin', 'editor']).exists()
    )


def user_can_access_merchandise(user: 'AbstractUser') -> bool:
    """
    Check if user can access merchandise/e-commerce features.

    Merchandise access is granted to:
    - admin: Full access
    - customer: Browse, cart, orders

    Args:
        user: Django User object

    Returns:
        True if user can access merchandise
    """
    if not user.is_authenticated:
        return False
    return (
        user.is_superuser or
        user.groups.filter(name__in=['admin', 'customer']).exists()
    )


def get_user_roles(user: 'AbstractUser') -> List[str]:
    """
    Get list of role names for a user.

    Args:
        user: Django User object

    Returns:
        List of role names the user belongs to
    """
    if not user.is_authenticated:
        return []
    return list(
        user.groups.filter(name__in=OIDC_MANAGED_GROUPS)
        .values_list('name', flat=True)
    )


def get_user_primary_role(user: 'AbstractUser') -> str:
    """
    Get the user's primary (highest privilege) role.

    Args:
        user: Django User object

    Returns:
        Name of the user's primary role, or 'customer' if none
    """
    roles = get_user_roles(user)
    if not roles:
        return 'customer' if user.is_authenticated else ''

    # Sort by priority (admin=1, soc_analyst=2, editor=3, customer=4)
    priority_order = {'admin': 1, 'soc_analyst': 2, 'editor': 3, 'customer': 4}
    return min(roles, key=lambda r: priority_order.get(r, 99))


def user_has_role(user: 'AbstractUser', role_name: str) -> bool:
    """
    Check if user has a specific role.

    Args:
        user: Django User object
        role_name: Name of the role to check

    Returns:
        True if user has the role
    """
    if not user.is_authenticated:
        return False

    # Admin has all roles implicitly
    if user.is_superuser:
        return True

    return user.groups.filter(name=role_name).exists()


def user_has_any_role(user: 'AbstractUser', role_names: List[str]) -> bool:
    """
    Check if user has any of the specified roles.

    Args:
        user: Django User object
        role_names: List of role names to check

    Returns:
        True if user has at least one of the roles
    """
    if not user.is_authenticated:
        return False

    # Admin has all roles implicitly
    if user.is_superuser:
        return True

    return user.groups.filter(name__in=role_names).exists()


def user_has_all_roles(user: 'AbstractUser', role_names: List[str]) -> bool:
    """
    Check if user has all of the specified roles.

    Args:
        user: Django User object
        role_names: List of role names to check

    Returns:
        True if user has all of the roles
    """
    if not user.is_authenticated:
        return False

    # Admin has all roles implicitly
    if user.is_superuser:
        return True

    user_roles = set(get_user_roles(user))
    return set(role_names).issubset(user_roles)


def get_user_access_list(user: 'AbstractUser') -> List[str]:
    """
    Get the combined access list for a user's roles.

    Args:
        user: Django User object

    Returns:
        List of resource identifiers the user can access
    """
    if not user.is_authenticated:
        return []

    if user.is_superuser:
        return ['all', 'mssp', 'cms', 'shop', 'dashboard', 'blog', 'profile']

    access = set()
    for role_name in get_user_roles(user):
        role_config = UNIFIED_ROLES.get(role_name, {})
        access.update(role_config.get('access', []))

    return list(access)
