"""
Django Admin configuration for Adversarial Security Framework

"One node's detection → Everyone's protection"
"""

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone

from .models import (
    AdversarialTest,
    Vulnerability,
    Mitigation,
    DesignerAlert,
    TestSchedule,
)


@admin.register(AdversarialTest)
class AdversarialTestAdmin(admin.ModelAdmin):
    """Admin for adversarial security tests"""
    list_display = [
        'name', 'target_component', 'status_badge',
        'vulnerabilities_found', 'highest_cvss_badge',
        'scheduled_at', 'duration_display'
    ]
    list_filter = ['status', 'target_component', 'target_tier']
    search_fields = ['name', 'description', 'target_component']
    readonly_fields = ['id', 'created_at', 'updated_at', 'results_summary']
    date_hierarchy = 'scheduled_at'

    fieldsets = [
        ('Test Configuration', {
            'fields': ['name', 'description', 'target_component', 'target_tier', 'attack_vectors']
        }),
        ('Scheduling', {
            'fields': ['scheduled_by', 'scheduled_at', 'started_at', 'completed_at', 'status']
        }),
        ('Results', {
            'fields': ['results_summary', 'vulnerabilities_found', 'highest_cvss'],
            'classes': ['collapse']
        }),
        ('Metadata', {
            'fields': ['id', 'created_at', 'updated_at'],
            'classes': ['collapse']
        }),
    ]

    def status_badge(self, obj):
        colors = {
            'scheduled': '#6c757d',
            'running': '#007bff',
            'completed': '#28a745',
            'failed': '#dc3545',
            'cancelled': '#ffc107',
        }
        color = colors.get(obj.status, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 11px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'

    def highest_cvss_badge(self, obj):
        if obj.highest_cvss >= 9.0:
            color = '#dc3545'  # Critical - Red
        elif obj.highest_cvss >= 7.0:
            color = '#fd7e14'  # High - Orange
        elif obj.highest_cvss >= 4.0:
            color = '#ffc107'  # Medium - Yellow
        else:
            color = '#28a745'  # Low - Green
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-weight: bold;">{:.1f}</span>',
            color, obj.highest_cvss
        )
    highest_cvss_badge.short_description = 'CVSS'

    def duration_display(self, obj):
        if obj.duration:
            return str(obj.duration).split('.')[0]
        return '-'
    duration_display.short_description = 'Duration'


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    """Admin for discovered vulnerabilities"""
    list_display = [
        'title', 'severity_badge', 'cvss_badge', 'attack_vector',
        'is_verified', 'is_mitigated', 'discovered_at'
    ]
    list_filter = ['severity', 'attack_vector', 'is_verified', 'is_mitigated', 'is_false_positive']
    search_fields = ['title', 'description', 'technical_details']
    readonly_fields = ['id', 'discovered_at', 'severity']
    date_hierarchy = 'discovered_at'

    fieldsets = [
        ('Vulnerability Details', {
            'fields': ['title', 'description', 'technical_details', 'attack_vector']
        }),
        ('Affected Components', {
            'fields': ['affected_components', 'affected_files']
        }),
        ('Scoring', {
            'fields': ['cvss_score', 'severity', 'cvss_vector', 'exploitability']
        }),
        ('Proof of Concept', {
            'fields': ['proof_of_concept'],
            'classes': ['collapse']
        }),
        ('Status', {
            'fields': ['is_verified', 'verified_at', 'is_mitigated', 'mitigated_at', 'is_false_positive']
        }),
        ('Context', {
            'fields': ['test', 'id', 'discovered_at'],
            'classes': ['collapse']
        }),
    ]

    def severity_badge(self, obj):
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745',
            'info': '#6c757d',
        }
        color = colors.get(obj.severity, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 11px; text-transform: uppercase;">{}</span>',
            color, obj.severity
        )
    severity_badge.short_description = 'Severity'

    def cvss_badge(self, obj):
        return format_html(
            '<strong>{:.1f}</strong>',
            obj.cvss_score
        )
    cvss_badge.short_description = 'CVSS'


@admin.register(Mitigation)
class MitigationAdmin(admin.ModelAdmin):
    """Admin for vulnerability mitigations"""
    list_display = [
        'title', 'priority_badge', 'vulnerability_link',
        'is_implemented', 'is_verified', 'estimated_effort'
    ]
    list_filter = ['priority', 'is_implemented', 'is_verified']
    search_fields = ['title', 'description', 'implementation_guide']
    readonly_fields = ['id', 'created_at', 'updated_at']

    fieldsets = [
        ('Mitigation Details', {
            'fields': ['title', 'description', 'implementation_guide', 'vulnerability']
        }),
        ('Priority & Effort', {
            'fields': ['priority', 'estimated_effort']
        }),
        ('Code Changes', {
            'fields': ['code_changes'],
            'classes': ['collapse']
        }),
        ('Implementation Status', {
            'fields': ['is_implemented', 'implemented_by', 'implemented_at', 'implementation_notes']
        }),
        ('Verification', {
            'fields': ['is_verified', 'verified_by', 'verified_at']
        }),
        ('Metadata', {
            'fields': ['id', 'created_at', 'updated_at'],
            'classes': ['collapse']
        }),
    ]

    def priority_badge(self, obj):
        colors = {
            'immediate': '#dc3545',
            'urgent': '#fd7e14',
            'standard': '#ffc107',
            'low': '#28a745',
            'backlog': '#6c757d',
        }
        color = colors.get(obj.priority, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 11px; text-transform: uppercase;">{}</span>',
            color, obj.priority
        )
    priority_badge.short_description = 'Priority'

    def vulnerability_link(self, obj):
        if obj.vulnerability:
            url = reverse('admin:adversarial_vulnerability_change', args=[obj.vulnerability.id])
            return format_html('<a href="{}">{}</a>', url, obj.vulnerability.title[:50])
        return '-'
    vulnerability_link.short_description = 'Vulnerability'


@admin.register(DesignerAlert)
class DesignerAlertAdmin(admin.ModelAdmin):
    """Admin for designer security alerts"""
    list_display = [
        'alert_icon', 'title', 'level_badge',
        'is_acknowledged', 'created_at'
    ]
    list_filter = ['level', 'is_acknowledged']
    search_fields = ['title', 'message']
    readonly_fields = ['id', 'created_at', 'details']
    date_hierarchy = 'created_at'

    actions = ['acknowledge_alerts']

    fieldsets = [
        ('Alert Content', {
            'fields': ['level', 'title', 'message', 'details']
        }),
        ('Related Objects', {
            'fields': ['vulnerability', 'test']
        }),
        ('Acknowledgement', {
            'fields': ['is_acknowledged', 'acknowledged_by', 'acknowledged_at', 'acknowledgement_notes']
        }),
        ('Metadata', {
            'fields': ['id', 'created_at'],
            'classes': ['collapse']
        }),
    ]

    def alert_icon(self, obj):
        if obj.is_acknowledged:
            return format_html('<span style="color: #28a745;">✓</span>')
        icons = {
            'critical': '🔴',
            'high': '🟠',
            'warning': '🟡',
            'info': '🔵',
        }
        return icons.get(obj.level, '⚪')
    alert_icon.short_description = ''

    def level_badge(self, obj):
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'warning': '#ffc107',
            'info': '#17a2b8',
        }
        color = colors.get(obj.level, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-size: 11px; text-transform: uppercase;">{}</span>',
            color, obj.level
        )
    level_badge.short_description = 'Level'

    @admin.action(description='Acknowledge selected alerts')
    def acknowledge_alerts(self, request, queryset):
        count = queryset.filter(is_acknowledged=False).update(
            is_acknowledged=True,
            acknowledged_by=request.user,
            acknowledged_at=timezone.now()
        )
        self.message_user(request, f'{count} alerts acknowledged.')


@admin.register(TestSchedule)
class TestScheduleAdmin(admin.ModelAdmin):
    """Admin for test schedules"""
    list_display = [
        'status_icon', 'name', 'frequency', 'is_active',
        'last_run', 'next_run'
    ]
    list_filter = ['frequency', 'is_active']
    search_fields = ['name', 'description']
    readonly_fields = ['id', 'created_at', 'updated_at', 'last_run']

    fieldsets = [
        ('Schedule Configuration', {
            'fields': ['name', 'description', 'frequency', 'is_active']
        }),
        ('Test Configuration', {
            'fields': ['test_config', 'attack_vectors', 'target_components']
        }),
        ('Timing', {
            'fields': ['last_run', 'next_run']
        }),
        ('Metadata', {
            'fields': ['id', 'created_by', 'created_at', 'updated_at'],
            'classes': ['collapse']
        }),
    ]

    def status_icon(self, obj):
        if obj.is_active:
            return format_html('<span style="color: #28a745;">●</span>')
        return format_html('<span style="color: #dc3545;">●</span>')
    status_icon.short_description = ''
