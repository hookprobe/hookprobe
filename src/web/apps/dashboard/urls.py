"""
Dashboard URL Configuration
"""

from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    # Dashboard pages
    path('', views.dashboard_home, name='home'),
    path('system-status/', views.system_status, name='system_status'),

    # Health check & monitoring endpoints
    path('health/', views.health_check, name='health_check'),
    path('health/pods/', views.pods_health_aggregator, name='pods_health'),
    path('metrics/', views.metrics_prometheus, name='metrics'),
    path('readiness/', views.readiness_check, name='readiness'),
    path('liveness/', views.liveness_check, name='liveness'),
]
