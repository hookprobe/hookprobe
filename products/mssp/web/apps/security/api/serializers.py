"""
Security API Serializers

Provides serialization for:
- Security events
- Quarantine actions
- Detection rules
- Alert ingestion
- Qsecbit scores
"""

import re
from rest_framework import serializers
from apps.security.models import (
    SecurityEvent, QsecbitScore, KaliResponse,
    QuarantineAction, DetectionRule
)


class SecurityEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityEvent
        fields = '__all__'


class QsecbitScoreSerializer(serializers.ModelSerializer):
    class Meta:
        model = QsecbitScore
        fields = '__all__'


class KaliResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = KaliResponse
        fields = '__all__'


class QuarantineActionSerializer(serializers.ModelSerializer):
    """Serializer for quarantine actions"""
    is_expired = serializers.ReadOnlyField()

    class Meta:
        model = QuarantineAction
        fields = '__all__'
        read_only_fields = [
            'action_id', 'created_at', 'nft_rule_handle',
            'released_at', 'released_by', 'release_reason'
        ]


class DetectionRuleSerializer(serializers.ModelSerializer):
    """Serializer for detection rules"""
    accuracy = serializers.ReadOnlyField()

    class Meta:
        model = DetectionRule
        fields = '__all__'
        read_only_fields = ['hit_count', 'false_positive_count', 'created_at', 'updated_at']


class AlertIngestionSerializer(serializers.Serializer):
    """
    Serializer for IDS alert ingestion.

    Accepts batch alerts from Suricata EVE or Zeek JSON.
    """
    SOURCE_CHOICES = [
        ('suricata', 'Suricata EVE JSON'),
        ('zeek', 'Zeek JSON Logs'),
    ]

    ZEEK_LOG_TYPES = [
        'conn', 'http', 'dns', 'ssl', 'notice', 'weird',
        'files', 'x509', 'smtp', 'ssh', 'ftp'
    ]

    source = serializers.ChoiceField(choices=SOURCE_CHOICES)
    log_type = serializers.CharField(required=False, default='alert')
    events = serializers.ListField(
        child=serializers.DictField(),
        min_length=1,
        max_length=1000,  # Batch limit
        help_text='List of raw IDS events (Suricata EVE or Zeek JSON)'
    )

    def validate_log_type(self, value):
        """Validate log_type for Zeek logs"""
        if value and value not in self.ZEEK_LOG_TYPES + ['alert']:
            raise serializers.ValidationError(
                f"Invalid log_type. Must be one of: {', '.join(self.ZEEK_LOG_TYPES)}"
            )
        return value

    def validate_events(self, value):
        """Basic validation of event structure"""
        if not value:
            raise serializers.ValidationError("Events list cannot be empty")

        # Check first event has expected structure
        first_event = value[0]
        source = self.initial_data.get('source')

        if source == 'suricata':
            # Suricata EVE should have event_type or timestamp
            if not ('event_type' in first_event or 'timestamp' in first_event):
                raise serializers.ValidationError(
                    "Suricata events should contain 'event_type' or 'timestamp' field"
                )
        elif source == 'zeek':
            # Zeek logs should have ts (timestamp) or uid
            if not ('ts' in first_event or 'uid' in first_event):
                raise serializers.ValidationError(
                    "Zeek logs should contain 'ts' or 'uid' field"
                )

        return value


class QuarantineRequestSerializer(serializers.Serializer):
    """
    Serializer for manual quarantine requests.
    """
    # IPv4 and IPv6 pattern
    IP_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|'
        r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|'
        r'^(?:[0-9a-fA-F]{1,4}:){1,7}:$|'
        r'^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$'
    )

    # Reserved IPs that cannot be blocked
    RESERVED_IPS = {'127.0.0.1', '::1', '0.0.0.0', '255.255.255.255'}

    ip_address = serializers.CharField(max_length=45)
    duration_minutes = serializers.IntegerField(
        min_value=1,
        max_value=43200,  # Max 30 days
        default=60,
        required=False
    )
    reason = serializers.CharField(
        max_length=500,
        required=False,
        default='Manual quarantine'
    )

    def validate_ip_address(self, value):
        """Validate IP address format and check reserved"""
        if not self.IP_PATTERN.match(value):
            raise serializers.ValidationError("Invalid IP address format")

        if value in self.RESERVED_IPS:
            raise serializers.ValidationError(
                f"Cannot quarantine reserved IP: {value}"
            )

        return value


class ThreatIntelligenceSerializer(serializers.Serializer):
    """Serializer for threat intelligence updates"""
    threat_type = serializers.ChoiceField(choices=[
        ('ip', 'Malicious IP'),
        ('domain', 'Malicious Domain'),
        ('hash', 'Malicious Hash'),
        ('cve', 'CVE'),
        ('signature', 'Attack Signature'),
    ])
    indicator = serializers.CharField(max_length=500)
    description = serializers.CharField()
    severity = serializers.ChoiceField(choices=[
        ('info', 'Info'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ])
    source = serializers.CharField(max_length=200)
    metadata = serializers.DictField(required=False)
