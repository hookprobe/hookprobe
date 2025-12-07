"""
Security API Views
"""

from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend

from apps.security.models import SecurityEvent, QsecbitScore, KaliResponse
from .serializers import (
    SecurityEventSerializer, QsecbitScoreSerializer, KaliResponseSerializer
)


class SecurityEventViewSet(viewsets.ModelViewSet):
    queryset = SecurityEvent.objects.all()
    serializer_class = SecurityEventSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['source_type', 'severity', 'is_resolved']
    ordering_fields = ['timestamp']


class QsecbitScoreViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = QsecbitScore.objects.all()
    serializer_class = QsecbitScoreSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['rag_status']
    ordering_fields = ['timestamp']


class KaliResponseViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = KaliResponse.objects.all()
    serializer_class = KaliResponseSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['status']
    ordering_fields = ['triggered_at']
