"""
HookProbe AIOCHI MSSP URL Configuration

Authentication:
All authentication is handled by Logto (centralized IAM).
- Login redirects to Logto OIDC
- Logout clears session and redirects to Logto
- Password reset is handled in Logto admin console

NOTE: Public website (CMS, blog, merchandise) has been moved to hookprobe.com repository.
This MSSP platform (aiochi.hookprobe.com) handles only dashboard and API functionality.
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView
from django.contrib.auth import logout as auth_logout
from django.http import HttpResponse
from django.shortcuts import redirect
from apps.dashboard.oidc_views import LogtoCallbackView


def health_check(request):
    """Health check endpoint for container orchestration."""
    return HttpResponse("mssp-healthy\n", content_type="text/plain")


def logto_login(request):
    """
    Login view - redirects to Logto OIDC.

    All authentication is handled by Logto (centralized IAM).
    """
    if request.user.is_authenticated:
        return redirect('/mssp/')

    # Build Logto authorization URL
    logto_endpoint = getattr(settings, 'LOGTO_ENDPOINT', 'http://10.200.2.12:3001')
    client_id = getattr(settings, 'LOGTO_APP_ID', '')
    redirect_uri = request.build_absolute_uri('/oidc/callback/')

    if not client_id:
        # Logto not configured - show error
        return HttpResponse(
            "Logto IAM not configured. Please set LOGTO_APP_ID environment variable.",
            status=503,
            content_type="text/plain"
        )

    auth_url = (
        f"{logto_endpoint}/oidc/auth?"
        f"client_id={client_id}&"
        f"redirect_uri={redirect_uri}&"
        f"response_type=code&"
        f"scope=openid%20profile%20email%20roles"
    )
    return redirect(auth_url)


def logto_logout(request):
    """
    Logout view - clears Django session and redirects to Logto logout.
    """
    # Clear Django session
    auth_logout(request)

    # Redirect to Logto end session
    logto_endpoint = getattr(settings, 'LOGTO_ENDPOINT', 'http://10.200.2.12:3001')
    post_logout_uri = request.build_absolute_uri('/login/')
    logout_url = f"{logto_endpoint}/oidc/session/end?post_logout_redirect_uri={post_logout_uri}"

    return redirect(logout_url)


urlpatterns = [
    # Health check (before auth)
    path('health/', health_check, name='health_check'),

    # Admin interface
    path('admin/', admin.site.urls),

    # Root redirects to MSSP dashboard
    path('', RedirectView.as_view(url='/mssp/', permanent=False), name='home'),

    # Authentication URLs - Logto OIDC
    path('login/', logto_login, name='login'),
    path('sign-in/', RedirectView.as_view(url='/login/', permanent=True), name='sign_in'),
    path('signin/', RedirectView.as_view(url='/login/', permanent=True), name='signin'),
    path('logout/', logto_logout, name='logout'),
    path('oidc/callback/', LogtoCallbackView.as_view(), name='oidc_callback'),

    # Password reset - handled by Logto (redirect to Logto)
    path('password-reset/', lambda r: redirect(
        getattr(settings, 'LOGTO_ENDPOINT', 'http://10.200.2.12:3001') + '/forgot-password'
    ), name='password_reset'),

    # Admin Dashboard (AdminLTE) - Internal team management
    path('dashboard/', include('apps.dashboard.urls', namespace='dashboard')),

    # Admin Dashboard - HookProbe Team (AdminLTE with AI features)
    path('admin-dashboard/', include('apps.admin_dashboard.urls', namespace='admin_dashboard')),

    # MSSP Dashboard - Customer-Facing (AIOCHI - main entry point)
    path('mssp/', include('apps.mssp_dashboard.urls', namespace='mssp_dashboard')),

    # Device Management API
    path('devices/', include('apps.devices.urls', namespace='devices')),

    # Monitoring
    path('monitoring/', include('apps.monitoring.urls', namespace='monitoring')),

    # Security & Qsecbit
    path('security/', include('apps.security.urls', namespace='security')),

    # SDN - MAC-based VLAN assignment for IoT segmentation
    path('sdn/', include('apps.sdn.urls', namespace='sdn')),

    # API endpoints
    path('api/v1/devices/', include('apps.devices.api.urls')),
    path('api/v1/security/', include('apps.security.api.urls')),
    path('api/v1/vpn/', include('apps.vpn.api.urls')),
]

# Serve static and media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

    # Debug toolbar
    try:
        import debug_toolbar
        urlpatterns += [
            path('__debug__/', include(debug_toolbar.urls)),
        ]
    except ImportError:
        pass

# Admin site customization
admin.site.site_header = "AIOCHI Administration"
admin.site.site_title = "AIOCHI Admin"
admin.site.index_title = "Welcome to AIOCHI MSSP Administration"
