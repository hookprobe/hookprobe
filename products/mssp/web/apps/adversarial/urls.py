"""
Adversarial Security Framework - URL Configuration

"One node's detection → Everyone's protection"
"""

from django.urls import path
from . import views

app_name = 'adversarial'

urlpatterns = [
    # Dashboard
    path('', views.dashboard, name='dashboard'),

    # Tests
    path('tests/', views.tests_list, name='tests_list'),
    path('tests/<uuid:test_id>/', views.test_detail, name='test_detail'),
    path('tests/schedule/', views.schedule_test, name='schedule_test'),

    # Vulnerabilities
    path('vulnerabilities/', views.vulnerabilities_list, name='vulnerabilities_list'),
    path('vulnerabilities/<uuid:vuln_id>/', views.vulnerability_detail, name='vulnerability_detail'),

    # Mitigations
    path('mitigations/', views.mitigations_list, name='mitigations_list'),
    path('mitigations/<uuid:mitigation_id>/', views.mitigation_detail, name='mitigation_detail'),

    # Alerts
    path('alerts/', views.alerts_list, name='alerts_list'),
    path('alerts/<uuid:alert_id>/acknowledge/', views.alert_acknowledge, name='alert_acknowledge'),

    # Reports
    path('reports/risk/', views.risk_report, name='risk_report'),

    # API endpoints
    path('api/stats/', views.api_dashboard_stats, name='api_stats'),
    path('api/vulnerability-trend/', views.api_vulnerability_trend, name='api_vulnerability_trend'),
]
