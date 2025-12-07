"""
VPN API Serializers
"""

from rest_framework import serializers
from django.contrib.auth.models import User

from apps.devices.models import Device
from apps.vpn.models import VPNProfile, VPNCertificate, VPNSession, VPNAccessLog


class VPNCertificateSerializer(serializers.ModelSerializer):
    """Serializer for VPN certificates."""

    is_valid = serializers.SerializerMethodField()

    class Meta:
        model = VPNCertificate
        fields = [
            'id', 'serial_number', 'common_name', 'status',
            'issued_at', 'expires_at', 'fingerprint_sha256',
            'is_valid',
        ]
        read_only_fields = ['id', 'serial_number', 'issued_at', 'fingerprint_sha256']

    def get_is_valid(self, obj):
        return obj.is_valid()


class VPNProfileListSerializer(serializers.ModelSerializer):
    """Serializer for VPN profile list view."""

    device_name = serializers.CharField(source='device.name', read_only=True)
    device_type = serializers.CharField(source='device.deployment_type', read_only=True)
    certificate_status = serializers.CharField(source='certificate.status', read_only=True)
    is_valid = serializers.SerializerMethodField()

    class Meta:
        model = VPNProfile
        fields = [
            'id', 'name', 'profile_type', 'platform',
            'device_name', 'device_type', 'vpn_server',
            'is_active', 'bandwidth_limit_mbps',
            'certificate_status', 'is_valid',
            'created_at', 'updated_at',
        ]

    def get_is_valid(self, obj):
        return obj.is_valid()


class VPNProfileDetailSerializer(serializers.ModelSerializer):
    """Serializer for VPN profile detail view."""

    device_name = serializers.CharField(source='device.name', read_only=True)
    device_id = serializers.CharField(source='device.device_id', read_only=True)
    certificate = VPNCertificateSerializer(read_only=True)
    download_url = serializers.SerializerMethodField()

    class Meta:
        model = VPNProfile
        fields = [
            'id', 'name', 'profile_type', 'platform',
            'device', 'device_name', 'device_id',
            'vpn_server', 'vpn_remote_id', 'local_identifier',
            'route_all_traffic', 'split_tunnel_routes', 'dns_servers',
            'on_demand_enabled', 'on_demand_rules',
            'bandwidth_limit_mbps',
            'is_active', 'valid_from', 'valid_until',
            'download_count', 'max_downloads', 'last_downloaded',
            'certificate',
            'download_url',
            'created_at', 'updated_at',
        ]
        read_only_fields = [
            'id', 'download_token', 'download_count',
            'last_downloaded', 'created_at', 'updated_at',
        ]

    def get_download_url(self, obj):
        request = self.context.get('request')
        if request and obj.is_valid():
            return request.build_absolute_uri(f'/api/v1/vpn/profiles/{obj.id}/download/')
        return None


class VPNProfileCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating VPN profiles."""

    device_id = serializers.PrimaryKeyRelatedField(
        queryset=Device.objects.all(),
        source='device',
        write_only=True
    )

    class Meta:
        model = VPNProfile
        fields = [
            'name', 'device_id', 'profile_type', 'platform',
            'route_all_traffic', 'split_tunnel_routes', 'dns_servers',
            'on_demand_enabled', 'bandwidth_limit_mbps',
            'valid_until',
        ]

    def validate_device_id(self, device):
        """Validate user has access to this device."""
        user = self.context['request'].user

        # Check if user has access to device's customer
        # (In production, implement proper authorization)
        if not device.is_active:
            raise serializers.ValidationError("Device is not active")

        return device

    def create(self, validated_data):
        """Create profile with certificate."""
        from apps.vpn.services import CertificateManager, VPNProfileGenerator

        user = self.context['request'].user
        device = validated_data['device']

        # Generate certificate for user
        cert_manager = CertificateManager()
        cert_pem, public_key_pem, encrypted_key, iv = cert_manager.issue_user_certificate(
            user, device.name
        )

        # Create certificate record
        certificate = VPNCertificate.objects.create(
            user=user,
            serial_number=cert_manager.get_serial_number(cert_pem),
            common_name=user.email or user.username,
            public_key_pem=public_key_pem.decode(),
            certificate_pem=cert_pem.decode(),
            encrypted_private_key=encrypted_key,
            key_encryption_iv=iv,
            expires_at=timezone.now() + timedelta(days=365),
            status='active',
            fingerprint_sha256=cert_manager.get_certificate_fingerprint(cert_pem),
        )

        # Set default VPN server
        import os
        vpn_server = os.getenv('VPN_SERVER_HOST', 'vpn.hookprobe.com')

        # Create profile
        profile = VPNProfile.objects.create(
            user=user,
            device=device,
            certificate=certificate,
            vpn_server=vpn_server,
            vpn_remote_id=vpn_server,
            local_identifier=user.email or str(user.id),
            **validated_data
        )

        return profile


class VPNSessionSerializer(serializers.ModelSerializer):
    """Serializer for VPN sessions."""

    profile_name = serializers.CharField(source='profile.name', read_only=True)
    device_name = serializers.CharField(source='profile.device.name', read_only=True)
    duration_seconds = serializers.SerializerMethodField()
    bandwidth_mb = serializers.SerializerMethodField()

    class Meta:
        model = VPNSession
        fields = [
            'id', 'profile_name', 'device_name',
            'started_at', 'ended_at', 'is_active',
            'client_ip', 'assigned_ip',
            'bytes_in', 'bytes_out',
            'duration_seconds', 'bandwidth_mb',
            'avg_latency_ms', 'packet_loss_percent',
        ]

    def get_duration_seconds(self, obj):
        return int(obj.duration)

    def get_bandwidth_mb(self, obj):
        return round(obj.bandwidth_used_mb, 2)


class VPNAccessLogSerializer(serializers.ModelSerializer):
    """Serializer for VPN access logs."""

    username = serializers.CharField(source='user.username', read_only=True)
    profile_name = serializers.CharField(source='profile.name', read_only=True)

    class Meta:
        model = VPNAccessLog
        fields = [
            'id', 'username', 'action', 'profile_name',
            'ip_address', 'user_agent', 'details', 'timestamp',
        ]


# Required imports
from datetime import timedelta
from django.utils import timezone
