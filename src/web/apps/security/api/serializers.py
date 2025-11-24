"""
Security API Serializers
"""

from rest_framework import serializers
from apps.security.models import SecurityEvent, QsecbitScore, KaliResponse


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
