"""
VPN API URL Configuration
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    VPNProfileViewSet,
    VPNCertificateViewSet,
    VPNSessionViewSet,
    VPNAccessLogViewSet,
)

router = DefaultRouter()
router.register(r'profiles', VPNProfileViewSet, basename='vpn-profile')
router.register(r'certificates', VPNCertificateViewSet, basename='vpn-certificate')
router.register(r'sessions', VPNSessionViewSet, basename='vpn-session')
router.register(r'logs', VPNAccessLogViewSet, basename='vpn-log')

urlpatterns = [
    path('', include(router.urls)),
]
