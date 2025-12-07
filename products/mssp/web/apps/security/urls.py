"""
Security URL Configuration
"""

from django.urls import path
from . import views

app_name = 'security'

urlpatterns = [
    path('events/', views.security_events, name='events'),
    path('qsecbit/', views.qsecbit_dashboard, name='qsecbit'),
]
