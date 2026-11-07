"""
HookProbe IAM Decorators

View decorators for role-based access control.
Use these to protect views with specific role requirements.
"""

from functools import wraps
from typing import Callable, List, Optional, Union

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect

from .helpers import (
    user_is_admin,
    user_is_editor,
    user_is_soc_analyst,
    user_can_access_mssp,
    user_can_access_cms,
    user_can_access_merchandise,
    user_has_role,
    user_has_any_role,
)


def role_required(
    role_name: str,
    login_url: Optional[str] = None,
    raise_exception: bool = False,
    redirect_url: Optional[str] = None
) -> Callable:
    """
    Decorator that requires a specific role to access a view.

    Usage:
        @role_required('admin')
        def admin_only_view(request):
            ...

        @role_required('editor', redirect_url='/unauthorized/')
        def editor_view(request):
            ...

    Args:
        role_name: Required role name
        login_url: URL to redirect unauthenticated users (default: LOGIN_URL)
        raise_exception: If True, raise PermissionDenied instead of redirect
        redirect_url: URL to redirect unauthorized users

    Returns:
        Decorated view function
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
            if not request.user.is_authenticated:
                if login_url:
                    return redirect(login_url)
                from django.conf import settings
                return redirect(getattr(settings, 'LOGIN_URL', '/login/'))

            if not user_has_role(request.user, role_name):
                if raise_exception:
                    raise PermissionDenied(f"Role '{role_name}' required")
                if redirect_url:
                    return redirect(redirect_url)
                raise PermissionDenied(f"Role '{role_name}' required")

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def roles_required(
    role_names: List[str],
    require_all: bool = False,
    login_url: Optional[str] = None,
    raise_exception: bool = False,
    redirect_url: Optional[str] = None
) -> Callable:
    """
    Decorator that requires one or more roles to access a view.

    Usage:
        @roles_required(['admin', 'soc_analyst'])  # Any of these roles
        def analyst_view(request):
            ...

        @roles_required(['admin', 'editor'], require_all=True)  # Must have ALL
        def special_view(request):
            ...

    Args:
        role_names: List of required role names
        require_all: If True, user must have ALL roles; if False, any role suffices
        login_url: URL to redirect unauthenticated users
        raise_exception: If True, raise PermissionDenied instead of redirect
        redirect_url: URL to redirect unauthorized users

    Returns:
        Decorated view function
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
            if not request.user.is_authenticated:
                if login_url:
                    return redirect(login_url)
                from django.conf import settings
                return redirect(getattr(settings, 'LOGIN_URL', '/login/'))

            has_access = False
            if require_all:
                from .helpers import user_has_all_roles
                has_access = user_has_all_roles(request.user, role_names)
            else:
                has_access = user_has_any_role(request.user, role_names)

            if not has_access:
                if raise_exception:
                    raise PermissionDenied(
                        f"Required roles: {', '.join(role_names)}"
                    )
                if redirect_url:
                    return redirect(redirect_url)
                raise PermissionDenied(
                    f"Required roles: {', '.join(role_names)}"
                )

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def admin_required(
    login_url: Optional[str] = None,
    raise_exception: bool = False,
    redirect_url: Optional[str] = None
) -> Callable:
    """
    Decorator that requires admin role.

    Usage:
        @admin_required()
        def admin_view(request):
            ...

    Args:
        login_url: URL to redirect unauthenticated users
        raise_exception: If True, raise PermissionDenied instead of redirect
        redirect_url: URL to redirect unauthorized users

    Returns:
        Decorated view function
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
            if not request.user.is_authenticated:
                if login_url:
                    return redirect(login_url)
                from django.conf import settings
                return redirect(getattr(settings, 'LOGIN_URL', '/login/'))

            if not user_is_admin(request.user):
                if raise_exception:
                    raise PermissionDenied("Admin role required")
                if redirect_url:
                    return redirect(redirect_url)
                raise PermissionDenied("Admin role required")

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def mssp_access_required(
    login_url: Optional[str] = None,
    raise_exception: bool = False,
    redirect_url: Optional[str] = None
) -> Callable:
    """
    Decorator that requires MSSP dashboard access.

    Allows: admin, soc_analyst

    Usage:
        @mssp_access_required()
        def security_dashboard(request):
            ...

    Args:
        login_url: URL to redirect unauthenticated users
        raise_exception: If True, raise PermissionDenied instead of redirect
        redirect_url: URL to redirect unauthorized users

    Returns:
        Decorated view function
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
            if not request.user.is_authenticated:
                if login_url:
                    return redirect(login_url)
                from django.conf import settings
                return redirect(getattr(settings, 'LOGIN_URL', '/login/'))

            if not user_can_access_mssp(request.user):
                if raise_exception:
                    raise PermissionDenied("MSSP access required (admin or soc_analyst)")
                if redirect_url:
                    return redirect(redirect_url)
                raise PermissionDenied("MSSP access required (admin or soc_analyst)")

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def cms_access_required(
    login_url: Optional[str] = None,
    raise_exception: bool = False,
    redirect_url: Optional[str] = None
) -> Callable:
    """
    Decorator that requires CMS/blog access.

    Allows: admin, editor

    Usage:
        @cms_access_required()
        def blog_editor(request):
            ...

    Args:
        login_url: URL to redirect unauthenticated users
        raise_exception: If True, raise PermissionDenied instead of redirect
        redirect_url: URL to redirect unauthorized users

    Returns:
        Decorated view function
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
            if not request.user.is_authenticated:
                if login_url:
                    return redirect(login_url)
                from django.conf import settings
                return redirect(getattr(settings, 'LOGIN_URL', '/login/'))

            if not user_can_access_cms(request.user):
                if raise_exception:
                    raise PermissionDenied("CMS access required (admin or editor)")
                if redirect_url:
                    return redirect(redirect_url)
                raise PermissionDenied("CMS access required (admin or editor)")

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def merchandise_access_required(
    login_url: Optional[str] = None,
    raise_exception: bool = False,
    redirect_url: Optional[str] = None
) -> Callable:
    """
    Decorator that requires merchandise/e-commerce access.

    Allows: admin, customer

    Usage:
        @merchandise_access_required()
        def checkout(request):
            ...

    Args:
        login_url: URL to redirect unauthenticated users
        raise_exception: If True, raise PermissionDenied instead of redirect
        redirect_url: URL to redirect unauthorized users

    Returns:
        Decorated view function
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
            if not request.user.is_authenticated:
                if login_url:
                    return redirect(login_url)
                from django.conf import settings
                return redirect(getattr(settings, 'LOGIN_URL', '/login/'))

            if not user_can_access_merchandise(request.user):
                if raise_exception:
                    raise PermissionDenied("Merchandise access required (admin or customer)")
                if redirect_url:
                    return redirect(redirect_url)
                raise PermissionDenied("Merchandise access required (admin or customer)")

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator
