"""
HookProbe URL Configuration
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView

urlpatterns = [
    # Admin interface
    path('admin/', admin.site.urls),

    # Public CMS (Forty theme)
    path('', include('apps.cms.urls', namespace='cms')),

    # Admin Dashboard (AdminLTE)
    path('dashboard/', include('apps.dashboard.urls', namespace='dashboard')),

    # Device Management
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

# Custom error handlers
handler404 = 'apps.cms.views.error_404'
handler500 = 'apps.cms.views.error_500'
handler403 = 'apps.cms.views.error_403'

# Admin site customization
admin.site.site_header = "HookProbe Administration"
admin.site.site_title = "HookProbe Admin"
admin.site.index_title = "Welcome to HookProbe Administration"
