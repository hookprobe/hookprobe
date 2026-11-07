"""
HookProbe Unified Role System - Single Source of Truth

This module defines the unified role system used across all HookProbe services:
- hookprobe.com (public website, blog, merchandise)
- mssp.hookprobe.com (MSSP security dashboard)

Role Hierarchy:
1. admin: Full access to everything
2. soc_analyst: MSSP security dashboard only
3. editor: CMS/blog editing only
4. customer: Shop/merchandise access only

Access Matrix:
+-------------+------+-------------+----------------+
| Role        | Shop | Blog Editor | MSSP Dashboard |
+-------------+------+-------------+----------------+
| customer    | Yes  | No          | No             |
| editor      | No   | Yes         | No             |
| soc_analyst | No   | No          | Yes            |
| admin       | Yes  | Yes         | Yes            |
+-------------+------+-------------+----------------+
"""

from typing import Dict, Any, List

# Unified role definitions - single source of truth for all HookProbe services
UNIFIED_ROLES: Dict[str, Dict[str, Any]] = {
    'admin': {
        'priority': 1,
        'is_staff': True,
        'is_superuser': True,
        'description': 'Full access to CMS, MSSP, and Merchandise management',
        'access': ['mssp', 'cms', 'shop', 'all'],
        'mssp_access': True,
        'cms_access': True,
        'merchandise_access': True,
        'permissions': ['all'],
    },
    'soc_analyst': {
        'priority': 2,
        'is_staff': True,  # Staff for MSSP admin access
        'is_superuser': False,
        'description': 'MSSP security dashboard access only',
        'access': ['mssp', 'dashboard'],
        'mssp_access': True,
        'cms_access': False,
        'merchandise_access': False,
        'permissions': [],
    },
    'editor': {
        'priority': 3,
        'is_staff': True,  # Staff for Django admin CMS access
        'is_superuser': False,
        'description': 'Blog editing and approvals, read-only MSSP',
        'access': ['cms', 'blog'],
        'mssp_access': False,
        'cms_access': True,
        'merchandise_access': False,
        'permissions': ['cms.add_blogpost', 'cms.change_blogpost', 'cms.view_blogpost'],
    },
    'customer': {
        'priority': 4,
        'is_staff': False,
        'is_superuser': False,
        'description': 'E-commerce access - browse, cart, orders',
        'access': ['shop', 'profile'],
        'mssp_access': False,
        'cms_access': False,
        'merchandise_access': True,
        'permissions': ['merchandise.view_product', 'merchandise.add_order', 'merchandise.view_order'],
    },
}

# OIDC-managed groups for synchronization (groups that sync with Logto)
OIDC_MANAGED_GROUPS: List[str] = list(UNIFIED_ROLES.keys())


def get_role_config(role_name: str) -> Dict[str, Any]:
    """
    Get configuration for a specific role.

    Args:
        role_name: Name of the role

    Returns:
        Role configuration dictionary, or empty dict if role not found
    """
    return UNIFIED_ROLES.get(role_name, {})


def get_role_priority(role_name: str) -> int:
    """
    Get the priority of a role (lower is higher privilege).

    Args:
        role_name: Name of the role

    Returns:
        Priority number (1=highest), or 999 if role not found
    """
    config = UNIFIED_ROLES.get(role_name, {})
    return config.get('priority', 999)


def get_highest_privilege_role(roles: List[str]) -> str:
    """
    Get the highest privilege role from a list of roles.

    Args:
        roles: List of role names

    Returns:
        Name of the highest privilege role, or 'customer' if none found
    """
    valid_roles = [r for r in roles if r in UNIFIED_ROLES]
    if not valid_roles:
        return 'customer'
    return min(valid_roles, key=lambda r: get_role_priority(r))


def normalize_role(role_name: str) -> str:
    """
    Normalize a role name.

    Args:
        role_name: Original role name

    Returns:
        Normalized role name (lowercase, stripped)
    """
    return role_name.lower().strip() if role_name else ''


def role_can_access(role_name: str, resource: str) -> bool:
    """
    Check if a role can access a specific resource.

    Args:
        role_name: Name of the role
        resource: Resource identifier ('mssp', 'cms', 'shop', 'all')

    Returns:
        True if role can access the resource
    """
    config = UNIFIED_ROLES.get(role_name, {})
    access_list = config.get('access', [])
    return 'all' in access_list or resource in access_list
