"""SDN API URL configuration."""

from django.urls import path
from . import views

app_name = 'sdn_api'

urlpatterns = [
    # RADIUS integration
    path('radius/authorize/', views.radius_authorize, name='radius_authorize'),
    path('radius/accounting/', views.radius_accounting, name='radius_accounting'),

    # Guardian API
    path('guardian/<uuid:guardian_id>/config/', views.guardian_config, name='guardian_config'),
    path('guardian/scan-results/', views.guardian_scan_results, name='guardian_scan_results'),
]
