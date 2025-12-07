"""
Device Management API Serializers
"""

from rest_framework import serializers
from apps.devices.models import Device, Customer, DeviceLog, DeviceMetric


class CustomerSerializer(serializers.ModelSerializer):
    """Customer serializer"""
    device_count = serializers.IntegerField(source='devices.count', read_only=True)

    class Meta:
        model = Customer
        fields = ['id', 'name', 'tenant_id', 'contact_email', 'contact_phone',
                  'is_active', 'device_count', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']


class DeviceSerializer(serializers.ModelSerializer):
    """Device serializer"""
    customer_name = serializers.CharField(source='customer.name', read_only=True)
    is_online = serializers.BooleanField(read_only=True)

    class Meta:
        model = Device
        fields = [
            'id', 'device_id', 'customer', 'customer_name', 'name', 'hostname',
            'ip_address', 'mac_address', 'architecture', 'cpu_model',
            'cpu_cores', 'ram_gb', 'storage_gb', 'nic_model', 'os_version',
            'hookprobe_version', 'deployment_type', 'status', 'last_seen',
            'uptime_seconds', 'cpu_usage_percent', 'ram_usage_percent',
            'disk_usage_percent', 'network_rx_bytes', 'network_tx_bytes',
            'location', 'description', 'is_active', 'is_online',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['device_id', 'last_seen', 'created_at', 'updated_at']


class DeviceLogSerializer(serializers.ModelSerializer):
    """Device log serializer"""
    device_name = serializers.CharField(source='device.name', read_only=True)

    class Meta:
        model = DeviceLog
        fields = ['id', 'device', 'device_name', 'log_type', 'message',
                  'details', 'timestamp']
        read_only_fields = ['timestamp']


class DeviceMetricSerializer(serializers.ModelSerializer):
    """Device metric serializer"""
    device_name = serializers.CharField(source='device.name', read_only=True)

    class Meta:
        model = DeviceMetric
        fields = ['id', 'device', 'device_name', 'timestamp', 'cpu_usage',
                  'ram_usage', 'disk_usage', 'network_rx_rate', 'network_tx_rate',
                  'qsecbit_score', 'threat_events_count']
        read_only_fields = ['timestamp']


class DeviceHeartbeatSerializer(serializers.Serializer):
    """Device heartbeat for status updates"""
    device_id = serializers.CharField()
    status = serializers.ChoiceField(choices=Device.STATUS_CHOICES)
    cpu_usage = serializers.FloatField()
    ram_usage = serializers.FloatField()
    disk_usage = serializers.FloatField()
    network_rx_rate = serializers.IntegerField(default=0)
    network_tx_rate = serializers.IntegerField(default=0)
    uptime_seconds = serializers.IntegerField()
    qsecbit_score = serializers.FloatField(required=False, allow_null=True)
    threat_events_count = serializers.IntegerField(default=0)
