"""
Security API Views

Provides endpoints for:
- Security event management
- IDS alert ingestion (Suricata EVE, Zeek)
- IPS quarantine management
- Qsecbit score tracking
- Kali response orchestration
"""

import logging

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend

from django.utils import timezone

from apps.security.models import (
    SecurityEvent, QsecbitScore, KaliResponse,
    QuarantineAction, DetectionRule
)
from apps.security.services import (
    SuricataParser, ZeekParser, HybridClassifier, QuarantineManager
)
from .serializers import (
    SecurityEventSerializer, QsecbitScoreSerializer, KaliResponseSerializer,
    QuarantineActionSerializer, DetectionRuleSerializer,
    AlertIngestionSerializer, QuarantineRequestSerializer
)

logger = logging.getLogger(__name__)


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


class QuarantineActionViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing IPS quarantine actions.

    Provides CRUD operations plus:
    - POST /quarantine/release/ - Release a quarantined IP
    - POST /quarantine/expire/ - Process expired quarantines
    """
    queryset = QuarantineAction.objects.all()
    serializer_class = QuarantineActionSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['status', 'confidence_level', 'action_type']
    ordering_fields = ['created_at', 'expires_at']

    @action(detail=True, methods=['post'])
    def release(self, request, pk=None):
        """Manually release a quarantined IP"""
        action_obj = self.get_object()
        reason = request.data.get('reason', 'Manual release')

        manager = QuarantineManager()
        success = manager.release_ip(
            action_obj.target_ip,
            released_by=request.user.username,
            reason=reason
        )

        if success:
            action_obj.refresh_from_db()
            return Response(
                QuarantineActionSerializer(action_obj).data,
                status=status.HTTP_200_OK
            )
        return Response(
            {'error': 'Failed to release quarantine'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    @action(detail=False, methods=['post'])
    def expire(self, request):
        """Process all expired quarantines"""
        manager = QuarantineManager()
        count = manager.expire_quarantines()
        return Response({'released_count': count})

    @action(detail=False, methods=['get'])
    def active(self, request):
        """Get all currently active quarantines"""
        manager = QuarantineManager()
        quarantines = manager.get_active_quarantines()
        return Response(quarantines)


class DetectionRuleViewSet(viewsets.ModelViewSet):
    """ViewSet for managing custom detection rules"""
    queryset = DetectionRule.objects.all()
    serializer_class = DetectionRuleSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['status', 'rule_type', 'severity']
    ordering_fields = ['hit_count', 'created_at']

    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        """Enable or disable a detection rule"""
        rule = self.get_object()
        new_status = request.data.get('status')

        if new_status not in ('active', 'disabled', 'testing'):
            return Response(
                {'error': 'Invalid status'},
                status=status.HTTP_400_BAD_REQUEST
            )

        rule.status = new_status
        rule.save()
        return Response(DetectionRuleSerializer(rule).data)

    @action(detail=True, methods=['post'])
    def report_false_positive(self, request, pk=None):
        """Report a false positive for a detection rule"""
        rule = self.get_object()
        rule.false_positive_count += 1
        rule.save()
        return Response({
            'rule_id': rule.rule_id,
            'false_positive_count': rule.false_positive_count,
            'accuracy': rule.accuracy
        })


class AlertIngestionView(APIView):
    """
    IDS Alert Ingestion Endpoint

    Accepts alerts from Suricata EVE JSON or Zeek logs,
    processes them through the hybrid classifier,
    and optionally triggers autonomous quarantine.

    POST /api/v1/security/alerts/ingest/
    {
        "source": "suricata" | "zeek",
        "log_type": "conn" | "http" | "dns" | ... (zeek only),
        "events": [
            { ... raw EVE JSON or Zeek JSON ... }
        ]
    }
    """
    permission_classes = [IsAuthenticated]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.suricata_parser = SuricataParser()
        self.zeek_parser = ZeekParser()
        self.classifier = HybridClassifier()
        self.quarantine_mgr = QuarantineManager()

    def post(self, request):
        """Ingest and process IDS alerts"""
        serializer = AlertIngestionSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        source = serializer.validated_data['source']
        events = serializer.validated_data['events']
        log_type = serializer.validated_data.get('log_type', 'alert')

        results = {
            'processed': 0,
            'created': 0,
            'quarantined': 0,
            'errors': 0,
            'events': []
        }

        for raw_event in events:
            try:
                # Parse the raw event
                if source == 'suricata':
                    parsed = self.suricata_parser.parse(raw_event)
                elif source == 'zeek':
                    parsed = self.zeek_parser.parse(raw_event, log_type)
                else:
                    results['errors'] += 1
                    continue

                if not parsed:
                    # Skipped event type (e.g., stats)
                    continue

                results['processed'] += 1

                # Classify the event
                classification = self.classifier.classify(parsed)

                # Create SecurityEvent record
                security_event = SecurityEvent.objects.create(
                    event_id=parsed.event_id,
                    source_type=parsed.source_type,
                    severity=classification.severity,
                    attack_type=classification.attack_type,
                    src_ip=parsed.src_ip,
                    dst_ip=parsed.dst_ip,
                    src_port=parsed.src_port,
                    dst_port=parsed.dst_port,
                    protocol=parsed.protocol,
                    description=classification.narrative,
                    raw_data={
                        'original': parsed.raw_data,
                        'classification': {
                            'confidence': classification.confidence,
                            'confidence_level': classification.confidence_level,
                            'method': classification.classification_method,
                            'signature': classification.signature_match,
                            'ml_features': classification.ml_features,
                        }
                    },
                    timestamp=parsed.timestamp,
                )
                results['created'] += 1

                # Auto-quarantine if recommended
                if classification.should_quarantine:
                    quarantine_action = self.quarantine_mgr.quarantine_ip(
                        ip_address=parsed.src_ip,
                        duration_minutes=60,  # Default 1 hour
                        reason=f"Auto-quarantine: {classification.attack_type}",
                        security_event=security_event,
                        confidence_score=classification.confidence,
                        classification_method=classification.classification_method,
                        signature_match=classification.signature_match,
                    )
                    if quarantine_action:
                        results['quarantined'] += 1

                # Add to response (limited info)
                results['events'].append({
                    'event_id': security_event.event_id,
                    'severity': classification.severity,
                    'confidence': classification.confidence,
                    'quarantined': classification.should_quarantine,
                })

            except Exception as e:
                logger.error(f"Error processing alert: {e}")
                results['errors'] += 1
                continue

        return Response(results, status=status.HTTP_200_OK)


class QuarantineRequestView(APIView):
    """
    Manual quarantine endpoint for blocking specific IPs.

    POST /api/v1/security/quarantine/block/
    {
        "ip_address": "1.2.3.4",
        "duration_minutes": 60,
        "reason": "Manual block - suspected attacker"
    }
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Manually quarantine an IP"""
        serializer = QuarantineRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        ip_address = serializer.validated_data['ip_address']
        duration = serializer.validated_data.get('duration_minutes', 60)
        reason = serializer.validated_data.get('reason', 'Manual quarantine')

        manager = QuarantineManager()

        # Check if already quarantined
        if manager.is_quarantined(ip_address):
            return Response(
                {'error': f'IP {ip_address} is already quarantined'},
                status=status.HTTP_409_CONFLICT
            )

        action = manager.quarantine_ip(
            ip_address=ip_address,
            duration_minutes=duration,
            reason=f"Manual: {reason} (by {request.user.username})",
            confidence_score=1.0,  # Manual = full confidence
            classification_method='manual',
        )

        if action:
            return Response(
                QuarantineActionSerializer(action).data,
                status=status.HTTP_201_CREATED
            )

        return Response(
            {'error': 'Failed to quarantine IP'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


class SecurityDashboardView(APIView):
    """
    Security dashboard summary endpoint.

    GET /api/v1/security/dashboard/
    Returns aggregated security metrics for the dashboard.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Get dashboard summary"""
        now = timezone.now()
        last_24h = now - timezone.timedelta(hours=24)
        last_7d = now - timezone.timedelta(days=7)

        # Event counts by severity (last 24h)
        severity_counts = {}
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            severity_counts[severity] = SecurityEvent.objects.filter(
                severity=severity,
                timestamp__gte=last_24h
            ).count()

        # Active quarantines
        active_quarantines = QuarantineAction.objects.filter(
            status='active'
        ).count()

        # Top attack types (last 7 days)
        from django.db.models import Count
        top_attacks = SecurityEvent.objects.filter(
            timestamp__gte=last_7d
        ).values('attack_type').annotate(
            count=Count('id')
        ).order_by('-count')[:10]

        # Top source IPs (last 7 days)
        top_sources = SecurityEvent.objects.filter(
            timestamp__gte=last_7d,
            severity__in=['critical', 'high']
        ).values('src_ip').annotate(
            count=Count('id')
        ).order_by('-count')[:10]

        # Recent critical events
        recent_critical = SecurityEvent.objects.filter(
            severity='critical',
            timestamp__gte=last_24h
        ).order_by('-timestamp')[:5]

        return Response({
            'summary': {
                'events_24h': sum(severity_counts.values()),
                'severity_counts': severity_counts,
                'active_quarantines': active_quarantines,
            },
            'top_attacks': list(top_attacks),
            'top_sources': list(top_sources),
            'recent_critical': SecurityEventSerializer(recent_critical, many=True).data,
            'generated_at': now.isoformat(),
        })
