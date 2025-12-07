"""
Monitoring URL Configuration
"""

from django.urls import path
from . import views

app_name = 'monitoring'

urlpatterns = [
    path('', views.monitoring_overview, name='overview'),
]
