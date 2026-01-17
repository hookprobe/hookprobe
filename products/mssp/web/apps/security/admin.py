"""
Security Admin Configuration

Admin interfaces for:
- Security events
- Quarantine actions (IPS)
- Detection rules
- Qsecbit scores
- Kali responses
- Threat intelligence
"""

from django.contrib import admin
from .models import (
    SecurityEvent, QsecbitScore, KaliResponse, ThreatIntelligence,
    QuarantineAction, DetectionRule
)


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


@admin.register(QuarantineAction)
class QuarantineActionAdmin(admin.ModelAdmin):
    """Admin for IPS quarantine actions"""
    list_display = [
        'action_id', 'target_ip', 'action_type', 'confidence_level',
        'status', 'created_at', 'expires_at'
    ]
    list_filter = ['status', 'action_type', 'confidence_level', 'classification_method']
    search_fields = ['action_id', 'target_ip', 'reason']
    readonly_fields = [
        'action_id', 'created_at', 'nft_rule_handle',
        'released_at', 'released_by', 'release_reason'
    ]
    date_hierarchy = 'created_at'
    raw_id_fields = ['security_event']

    fieldsets = (
        ('Action Details', {
            'fields': ('action_id', 'action_type', 'target_ip', 'target_port', 'protocol')
        }),
        ('Classification', {
            'fields': (
                'confidence_level', 'confidence_score', 'classification_method',
                'signature_match', 'ml_model_version'
            )
        }),
        ('Timing', {
            'fields': ('created_at', 'expires_at', 'status')
        }),
        ('Audit', {
            'fields': ('reason', 'released_at', 'released_by', 'release_reason')
        }),
        ('Related', {
            'fields': ('security_event', 'nft_rule_handle')
        }),
    )

    actions = ['release_selected']

    @admin.action(description="Release selected quarantines")
    def release_selected(self, request, queryset):
        from .services import QuarantineManager
        manager = QuarantineManager()
        count = 0
        for action in queryset.filter(status='active'):
            manager.release_ip(
                action.target_ip,
                released_by=request.user.username,
                reason='Released via admin'
            )
            count += 1
        self.message_user(request, f"Released {count} quarantine(s)")


@admin.register(DetectionRule)
class DetectionRuleAdmin(admin.ModelAdmin):
    """Admin for custom detection rules"""
    list_display = [
        'rule_id', 'name', 'rule_type', 'severity',
        'status', 'hit_count', 'false_positive_count', 'accuracy_display'
    ]
    list_filter = ['status', 'rule_type', 'severity', 'auto_quarantine']
    search_fields = ['rule_id', 'name', 'description', 'pattern']
    readonly_fields = ['hit_count', 'false_positive_count', 'created_at', 'updated_at']
    list_editable = ['status']

    fieldsets = (
        ('Rule Identity', {
            'fields': ('rule_id', 'name', 'description', 'status')
        }),
        ('Detection', {
            'fields': ('rule_type', 'pattern', 'threshold', 'window_seconds')
        }),
        ('Classification', {
            'fields': ('severity', 'attack_type', 'mitre_tactic', 'mitre_technique')
        }),
        ('Auto-Response', {
            'fields': ('auto_quarantine', 'quarantine_duration_minutes', 'min_confidence_for_quarantine')
        }),
        ('Statistics', {
            'fields': ('hit_count', 'false_positive_count', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    @admin.display(description='Accuracy')
    def accuracy_display(self, obj):
        return f"{obj.accuracy * 100:.1f}%"
