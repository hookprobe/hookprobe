"""
Device Management API Views
"""

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django_filters.rest_framework import DjangoFilterBackend

from apps.devices.models import Device, Customer, DeviceLog, DeviceMetric
from .serializers import (
    DeviceSerializer, CustomerSerializer, DeviceLogSerializer,
    DeviceMetricSerializer, DeviceHeartbeatSerializer
)


class CustomerViewSet(viewsets.ModelViewSet):
    """Customer API viewset"""
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['is_active']
    search_fields = ['name', 'tenant_id']
    ordering_fields = ['name', 'created_at']


class DeviceViewSet(viewsets.ModelViewSet):
    """Device API viewset"""
    queryset = Device.objects.select_related('customer').all()
    serializer_class = DeviceSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['customer', 'status', 'deployment_type', 'architecture']
    search_fields = ['name', 'device_id', 'hostname', 'ip_address']
    ordering_fields = ['name', 'last_seen', 'created_at']
    lookup_field = 'device_id'

    @action(detail=True, methods=['post'])
    def heartbeat(self, request, device_id=None):
        """Receive device heartbeat with metrics"""
        device = self.get_object()

        serializer = DeviceHeartbeatSerializer(data=request.data)
        if serializer.is_valid():
            data = serializer.validated_data

            # Update device status and metrics
            device.status = data['status']
            device.last_seen = timezone.now()
            device.uptime_seconds = data['uptime_seconds']
            device.cpu_usage_percent = data['cpu_usage']
            device.ram_usage_percent = data['ram_usage']
            device.disk_usage_percent = data['disk_usage']
            device.save()

            # Create metric record
            DeviceMetric.objects.create(
                device=device,
                cpu_usage=data['cpu_usage'],
                ram_usage=data['ram_usage'],
                disk_usage=data['disk_usage'],
                network_rx_rate=data.get('network_rx_rate', 0),
                network_tx_rate=data.get('network_tx_rate', 0),
                qsecbit_score=data.get('qsecbit_score'),
                threat_events_count=data.get('threat_events_count', 0)
            )

            return Response({'status': 'ok'})

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['get'])
    def metrics(self, request, device_id=None):
        """Get device metrics history"""
        device = self.get_object()
        hours = int(request.query_params.get('hours', 24))

        start_time = timezone.now() - timezone.timedelta(hours=hours)
        metrics = device.metrics.filter(timestamp__gte=start_time)

        serializer = DeviceMetricSerializer(metrics, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def logs(self, request, device_id=None):
        """Get device logs"""
        device = self.get_object()
        limit = int(request.query_params.get('limit', 100))

        logs = device.logs.all()[:limit]

        serializer = DeviceLogSerializer(logs, many=True)
        return Response(serializer.data)


class DeviceLogViewSet(viewsets.ReadOnlyModelViewSet):
    """Device log API viewset (read-only)"""
    queryset = DeviceLog.objects.select_related('device').all()
    serializer_class = DeviceLogSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['device', 'log_type']
    ordering_fields = ['timestamp']


class DeviceMetricViewSet(viewsets.ReadOnlyModelViewSet):
    """Device metric API viewset (read-only)"""
    queryset = DeviceMetric.objects.select_related('device').all()
    serializer_class = DeviceMetricSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['device']
    ordering_fields = ['timestamp']
