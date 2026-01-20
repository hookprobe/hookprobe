"""
Security URL Configuration
"""

from django.urls import path
from django.views.generic import RedirectView
from . import views

app_name = 'security'

urlpatterns = [
    # Root redirects to events
    path('', RedirectView.as_view(pattern_name='security:events', permanent=False), name='index'),
    path('events/', views.security_events, name='events'),
    path('qsecbit/', views.qsecbit_dashboard, name='qsecbit'),
]
