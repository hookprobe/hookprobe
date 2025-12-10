"""
Cortex URL Configuration

Maps URLs to Cortex views for MSSP dashboard integration.
"""

from django.urls import path
from . import views

app_name = 'cortex'

urlpatterns = [
    # Page routes
    path('', views.cortex_view, name='index'),
    path('embedded/', views.cortex_embedded, name='embedded'),
    path('fullscreen/', views.cortex_fullscreen, name='fullscreen'),

    # API routes
    path('api/status/', views.api_cortex_status, name='api_status'),
    path('api/nodes/', views.api_cortex_nodes, name='api_nodes'),
    path('api/events/', views.api_cortex_events, name='api_events'),
    path('api/stats/', views.api_cortex_stats, name='api_stats'),
    path('api/mode/', views.api_cortex_mode, name='api_mode'),
    path('api/node/<str:node_id>/', views.api_cortex_node_detail, name='api_node_detail'),
]
