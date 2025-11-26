"""
Security Admin Configuration
"""

from django.contrib import admin
from .models import SecurityEvent, QsecbitScore, KaliResponse, ThreatIntelligence


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ['event_id', 'source_type', 'severity', 'attack_type',
                    'src_ip', 'dst_ip', 'timestamp', 'is_resolved']
    list_filter = ['source_type', 'severity', 'is_resolved', 'timestamp']
    search_fields = ['event_id', 'src_ip', 'dst_ip', 'attack_type']
    readonly_fields = ['timestamp', 'resolved_at']
    list_editable = ['is_resolved']
    date_hierarchy = 'timestamp'


@admin.register(QsecbitScore)
class QsecbitScoreAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'score', 'rag_status', 'attack_probability',
                    'drift']
    list_filter = ['rag_status', 'timestamp']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'


@admin.register(KaliResponse)
class KaliResponseAdmin(admin.ModelAdmin):
    list_display = ['triggered_at', 'status', 'qsecbit_score', 'completed_at']
    list_filter = ['status', 'triggered_at']
    readonly_fields = ['triggered_at', 'completed_at']
    date_hierarchy = 'triggered_at'


@admin.register(ThreatIntelligence)
class ThreatIntelligenceAdmin(admin.ModelAdmin):
    list_display = ['threat_type', 'indicator', 'severity', 'source',
                    'first_seen', 'last_seen', 'is_active']
    list_filter = ['threat_type', 'severity', 'is_active', 'source']
    search_fields = ['indicator', 'description']
    readonly_fields = ['first_seen', 'last_seen']
    list_editable = ['is_active']
