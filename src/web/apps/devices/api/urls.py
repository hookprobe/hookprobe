"""
Device Management API URLs
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'customers', views.CustomerViewSet)
router.register(r'devices', views.DeviceViewSet)
router.register(r'logs', views.DeviceLogViewSet)
router.register(r'metrics', views.DeviceMetricViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
