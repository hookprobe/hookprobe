"""
Security API URLs

Endpoints:
- /api/v1/security/events/         - Security events CRUD
- /api/v1/security/quarantine/     - Quarantine actions CRUD
- /api/v1/security/rules/          - Detection rules CRUD
- /api/v1/security/alerts/ingest/  - IDS alert ingestion
- /api/v1/security/quarantine/block/  - Manual IP blocking
- /api/v1/security/dashboard/      - Dashboard summary
- /api/v1/security/qsecbit/        - Qsecbit scores
- /api/v1/security/kali/           - Kali responses
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'events', views.SecurityEventViewSet)
router.register(r'quarantine', views.QuarantineActionViewSet)
router.register(r'rules', views.DetectionRuleViewSet)
router.register(r'qsecbit', views.QsecbitScoreViewSet)
router.register(r'kali', views.KaliResponseViewSet)

urlpatterns = [
    # ViewSet routes
    path('', include(router.urls)),

    # IDS Alert Ingestion
    path('alerts/ingest/', views.AlertIngestionView.as_view(), name='alert-ingest'),

    # Manual Quarantine
    path('quarantine/block/', views.QuarantineRequestView.as_view(), name='quarantine-block'),

    # Dashboard
    path('dashboard/', views.SecurityDashboardView.as_view(), name='security-dashboard'),
]
