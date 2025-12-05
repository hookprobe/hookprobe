"""
VPN App URL Configuration
"""

from django.urls import path, include

app_name = 'vpn'

urlpatterns = [
    path('api/v1/vpn/', include('apps.vpn.api.urls')),
]
