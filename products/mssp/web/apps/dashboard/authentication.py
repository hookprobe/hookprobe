"""
Module moved to shared.iam

All IAM functionality is now in the shared module:

    from shared.iam import (
        LogtoAuthenticationBackend,
        LogtoMiddleware,
        user_is_admin,
        user_can_access_mssp,
        UNIFIED_ROLES,
        # ... etc
    )
"""

raise ImportError(
    "apps.dashboard.authentication has been removed. "
    "Import from shared.iam instead."
)
