"""
MSSP Dashboard Admin Configuration
"""

from django.contrib import admin
from .models import (
    SecurityDevice, SecurityMetric, Vulnerability,
    SOARPlaybook, PlaybookExecution, ThreatIntelligence
)


@admin.register(SecurityDevice)
class SecurityDeviceAdmin(admin.ModelAdmin):
    """Admin interface for security devices."""

    list_display = ['name', 'device_type', 'ip_address', 'location_name', 'status', 'last_seen']
    list_filter = ['device_type', 'status', 'customer']
    search_fields = ['name', 'ip_address', 'location_name']
    readonly_fields = ['created_at', 'updated_at']

    fieldsets = [
        ('Device Information', {
            'fields': ['name', 'device_type', 'ip_address', 'mac_address', 'firmware_version']
        }),
        ('Location', {
            'fields': ['latitude', 'longitude', 'location_name']
        }),
        ('Status', {
            'fields': ['status', 'last_seen']
        }),
        ('Ownership', {
            'fields': ['customer']
        }),
        ('Metadata', {
            'fields': ['created_at', 'updated_at'],
            'classes': ['collapse']
        }),
    ]


@admin.register(SecurityMetric)
class SecurityMetricAdmin(admin.ModelAdmin):
    """Admin interface for security metrics."""

    list_display = ['device', 'metric_type', 'severity', 'value', 'unit', 'source_tool', 'timestamp']
    list_filter = ['metric_type', 'severity', 'source_tool', 'timestamp']
    search_fields = ['device__name', 'description']
    date_hierarchy = 'timestamp'


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    """Admin interface for vulnerabilities."""

    list_display = ['cve_id', 'title', 'severity', 'cvss_score', 'status', 'discovered_at', 'assigned_to']
    list_filter = ['severity', 'status', 'discovered_at']
    search_fields = ['cve_id', 'title', 'description']
    filter_horizontal = ['affected_devices']
    readonly_fields = ['created_at', 'updated_at']

    fieldsets = [
        ('Vulnerability Details', {
            'fields': ['cve_id', 'title', 'description', 'severity', 'cvss_score']
        }),
        ('Affected Systems', {
            'fields': ['affected_devices']
        }),
        ('Status', {
            'fields': ['status', 'discovered_at', 'resolved_at', 'assigned_to', 'customer']
        }),
        ('AI Recommendations', {
            'fields': ['ai_mitigation_recommendation', 'ai_confidence_score']
        }),
        ('References', {
            'fields': ['references'],
            'classes': ['collapse']
        }),
        ('Metadata', {
            'fields': ['created_at', 'updated_at'],
            'classes': ['collapse']
        }),
    ]


@admin.register(SOARPlaybook)
class SOARPlaybookAdmin(admin.ModelAdmin):
    """Admin interface for SOAR playbooks."""

    list_display = ['name', 'status', 'execution_count', 'success_count', 'success_rate_display', 'created_at']
    list_filter = ['status', 'trigger_on_vulnerability', 'trigger_on_alert']
    search_fields = ['name', 'description']
    readonly_fields = ['execution_count', 'success_count', 'created_at', 'updated_at']

    def success_rate_display(self, obj):
        return f"{obj.success_rate:.1f}%"
    success_rate_display.short_description = 'Success Rate'


@admin.register(PlaybookExecution)
class PlaybookExecutionAdmin(admin.ModelAdmin):
    """Admin interface for playbook executions."""

    list_display = ['playbook', 'status', 'started_at', 'completed_at', 'vulnerability']
    list_filter = ['status', 'started_at']
    search_fields = ['playbook__name', 'error_message']
    readonly_fields = ['started_at']


@admin.register(ThreatIntelligence)
class ThreatIntelligenceAdmin(admin.ModelAdmin):
    """Admin interface for threat intelligence."""

    list_display = ['title', 'threat_type', 'confidence', 'threat_actor', 'source', 'published_at']
    list_filter = ['threat_type', 'confidence', 'published_at']
    search_fields = ['title', 'description', 'threat_actor']
    date_hierarchy = 'published_at'
    readonly_fields = ['created_at']
