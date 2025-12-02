"""
MSSP Dashboard URL Configuration
"""

from django.urls import path
from . import views

app_name = 'mssp_dashboard'

urlpatterns = [
    # Main dashboard tabs
    path('', views.dashboard_home, name='home'),
    path('endpoints/', views.endpoints_map, name='endpoints'),
    path('vulnerabilities/', views.vulnerabilities_list, name='vulnerabilities'),
    path('vulnerabilities/<int:vuln_id>/', views.vulnerability_detail, name='vulnerability_detail'),
    path('soar/', views.soar_playbooks, name='soar'),
    path('xsoc/', views.xsoc_dashboard, name='xsoc'),

    # API endpoints
    path('api/endpoints/geojson/', views.endpoints_geojson, name='endpoints_geojson'),
]
