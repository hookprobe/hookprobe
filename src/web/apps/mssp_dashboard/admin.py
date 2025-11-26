"""
MSSP Dashboard Admin Configuration
"""

from django.contrib import admin
from .models import (
    SecurityDevice, SecurityMetric, Vulnerability,
    SOARPlaybook, PlaybookExecution, ThreatIntelligence,
    IndicatorOfCompromise, IoC_Report
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


@admin.register(IndicatorOfCompromise)
class IndicatorOfCompromiseAdmin(admin.ModelAdmin):
    """Admin interface for Indicators of Compromise."""

    list_display = [
        'value', 'ioc_type', 'severity', 'confidence_score', 'detection_count',
        'risk_score_display', 'is_active', 'first_seen', 'last_seen'
    ]
    list_filter = [
        'ioc_type', 'severity', 'is_active', 'is_false_positive', 'is_whitelisted',
        'detected_by_qsecbit', 'detected_by_openflow', 'detected_by_suricata',
        'detected_by_snort', 'detected_by_zeek', 'detected_by_xdp',
        'detected_by_ebpf', 'detected_by_siem', 'detected_by_threat_intel',
        'first_seen', 'last_seen'
    ]
    search_fields = ['value', 'description', 'tags']
    date_hierarchy = 'first_seen'
    filter_horizontal = ['related_iocs']
    readonly_fields = ['detection_count', 'first_seen', 'last_seen', 'risk_score_display', 'created_at', 'updated_at']

    fieldsets = [
        ('IoC Details', {
            'fields': ['customer', 'ioc_type', 'value', 'description', 'tags']
        }),
        ('Severity & Confidence', {
            'fields': ['severity', 'confidence_score', 'risk_score_display', 'detection_count']
        }),
        ('Detection Sources (One Brain)', {
            'fields': [
                'detected_by_qsecbit', 'detected_by_openflow', 'detected_by_suricata',
                'detected_by_snort', 'detected_by_zeek', 'detected_by_xdp',
                'detected_by_ebpf', 'detected_by_siem', 'detected_by_threat_intel'
            ],
            'description': 'Which security systems detected this IoC'
        }),
        ('QSECBIT AI Analysis', {
            'fields': ['qsecbit_score', 'qsecbit_rag_status', 'qsecbit_metadata'],
            'classes': ['collapse']
        }),
        ('Status & Timing', {
            'fields': ['is_active', 'is_false_positive', 'is_whitelisted', 'first_seen', 'last_seen']
        }),
        ('Correlations', {
            'fields': ['related_iocs'],
            'description': 'Related IoCs that appear together'
        }),
        ('Additional Data', {
            'fields': ['metadata', 'raw_data'],
            'classes': ['collapse']
        }),
        ('Timestamps', {
            'fields': ['created_at', 'updated_at'],
            'classes': ['collapse']
        }),
    ]

    def risk_score_display(self, obj):
        """Display risk score with color coding."""
        score = obj.risk_score
        if score >= 80:
            color = 'red'
        elif score >= 60:
            color = 'orange'
        elif score >= 40:
            color = 'yellow'
        else:
            color = 'green'
        return f"{score:.1f}"
    risk_score_display.short_description = 'Risk Score'


@admin.register(IoC_Report)
class IoC_ReportAdmin(admin.ModelAdmin):
    """Admin interface for IoC Reports."""

    list_display = [
        'title', 'severity', 'status', 'overall_risk_score',
        'systems_compromised', 'created_by', 'created_at', 'updated_at'
    ]
    list_filter = ['severity', 'status', 'created_at', 'updated_at']
    search_fields = ['title', 'summary', 'mitigation_steps']
    date_hierarchy = 'created_at'
    filter_horizontal = ['iocs']
    readonly_fields = ['overall_risk_score', 'created_at', 'updated_at']

    fieldsets = [
        ('Report Details', {
            'fields': ['customer', 'title', 'summary', 'severity', 'status']
        }),
        ('Associated IoCs', {
            'fields': ['iocs'],
            'description': 'Indicators of Compromise included in this report'
        }),
        ('Impact Assessment', {
            'fields': ['systems_compromised', 'data_exfiltrated', 'estimated_impact', 'overall_risk_score']
        }),
        ('Analysis from Security Systems', {
            'fields': [
                'qsecbit_analysis', 'openflow_metrics', 'ids_alerts',
                'network_analysis', 'packet_analysis'
            ],
            'classes': ['collapse'],
            'description': 'Aggregated data from all security vectors'
        }),
        ('Response', {
            'fields': ['mitigation_steps', 'mitigation_status', 'assigned_to', 'resolved_at']
        }),
        ('Report Management', {
            'fields': ['created_by', 'created_at', 'updated_at']
        }),
    ]

    def save_model(self, request, obj, form, change):
        """Auto-calculate risk score on save."""
        if not change:  # New object
            obj.created_by = request.user
        obj.overall_risk_score = obj.calculate_overall_risk()
        super().save_model(request, obj, form, change)
