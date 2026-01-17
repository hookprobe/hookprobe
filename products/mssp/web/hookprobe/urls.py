"""
HookProbe AIOCHI MSSP URL Configuration

NOTE: Public website (CMS, blog, merchandise) has been moved to hookprobe.com repository.
This MSSP platform (aiochi.hookprobe.com) handles only dashboard and API functionality.
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView
from django.contrib.auth import views as auth_views

urlpatterns = [
    # Admin interface
    path('admin/', admin.site.urls),

    # Root redirects to MSSP dashboard
    path('', RedirectView.as_view(url='/mssp/', permanent=False), name='home'),

    # Authentication URLs (using admin_dashboard templates)
    path('login/', auth_views.LoginView.as_view(template_name='admin_dashboard/auth/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='/login/'), name='logout'),
    path('password-reset/', auth_views.PasswordResetView.as_view(
        template_name='admin_dashboard/auth/password_reset.html',
        email_template_name='admin_dashboard/auth/password_reset_email.html',
        subject_template_name='admin_dashboard/auth/password_reset_subject.txt',
    ), name='password_reset'),
    path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(
        template_name='admin_dashboard/auth/password_reset_done.html'
    ), name='password_reset_done'),
    path('password-reset-confirm/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(
        template_name='admin_dashboard/auth/password_reset_confirm.html'
    ), name='password_reset_confirm'),
    path('password-reset-complete/', auth_views.PasswordResetCompleteView.as_view(
        template_name='admin_dashboard/auth/password_reset_complete.html'
    ), name='password_reset_complete'),

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

    # API endpoints
    path('api/v1/devices/', include('apps.devices.api.urls')),
    path('api/v1/security/', include('apps.security.api.urls')),
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
