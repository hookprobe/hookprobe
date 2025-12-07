"""
VPN Admin Configuration
"""

from django.contrib import admin
from django.utils.html import format_html

from .models import VPNCertificate, VPNProfile, VPNSession, VPNAccessLog


@admin.register(VPNCertificate)
class VPNCertificateAdmin(admin.ModelAdmin):
    list_display = [
        'common_name', 'user', 'status', 'issued_at', 'expires_at',
        'is_valid_display',
    ]
    list_filter = ['status', 'issued_at']
    search_fields = ['common_name', 'user__username', 'user__email', 'serial_number']
    readonly_fields = [
        'id', 'serial_number', 'fingerprint_sha256',
        'issued_at', 'revoked_at',
    ]

    def is_valid_display(self, obj):
        if obj.is_valid():
            return format_html('<span style="color: green;">Valid</span>')
        return format_html('<span style="color: red;">Invalid</span>')
    is_valid_display.short_description = 'Valid'

    actions = ['revoke_certificates']

    def revoke_certificates(self, request, queryset):
        count = 0
        for cert in queryset.filter(status='active'):
            cert.revoke(reason=f"Revoked by admin: {request.user.username}")
            count += 1
        self.message_user(request, f"Revoked {count} certificate(s)")
    revoke_certificates.short_description = "Revoke selected certificates"


@admin.register(VPNProfile)
class VPNProfileAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'user', 'device', 'profile_type', 'platform',
        'is_active', 'download_count', 'created_at',
    ]
    list_filter = ['profile_type', 'platform', 'is_active', 'created_at']
    search_fields = ['name', 'user__username', 'device__name']
    readonly_fields = ['id', 'download_token', 'download_count', 'last_downloaded', 'created_at']

    fieldsets = (
        (None, {
            'fields': ('name', 'user', 'device', 'certificate')
        }),
        ('VPN Configuration', {
            'fields': (
                'profile_type', 'platform', 'vpn_server', 'vpn_remote_id',
                'local_identifier',
            )
        }),
        ('Routing', {
            'fields': (
                'route_all_traffic', 'split_tunnel_routes', 'dns_servers',
            )
        }),
        ('On-Demand', {
            'fields': ('on_demand_enabled', 'on_demand_rules'),
            'classes': ('collapse',),
        }),
        ('Limits', {
            'fields': (
                'bandwidth_limit_mbps', 'is_active',
                'valid_from', 'valid_until',
            )
        }),
        ('Download Tracking', {
            'fields': (
                'download_token', 'download_count', 'max_downloads',
                'last_downloaded',
            ),
            'classes': ('collapse',),
        }),
        ('Metadata', {
            'fields': ('id', 'created_at', 'updated_at'),
            'classes': ('collapse',),
        }),
    )


@admin.register(VPNSession)
class VPNSessionAdmin(admin.ModelAdmin):
    list_display = [
        'profile', 'is_active', 'client_ip', 'assigned_ip',
        'started_at', 'duration_display', 'bandwidth_display',
    ]
    list_filter = ['is_active', 'started_at']
    search_fields = ['profile__name', 'profile__user__username', 'client_ip']
    readonly_fields = ['id', 'started_at', 'ended_at']

    def duration_display(self, obj):
        duration = obj.duration
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        return f"{hours}h {minutes}m"
    duration_display.short_description = 'Duration'

    def bandwidth_display(self, obj):
        return f"{obj.bandwidth_used_mb:.2f} MB"
    bandwidth_display.short_description = 'Bandwidth'


@admin.register(VPNAccessLog)
class VPNAccessLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'action', 'profile', 'ip_address', 'timestamp']
    list_filter = ['action', 'timestamp']
    search_fields = ['user__username', 'ip_address']
    readonly_fields = ['id', 'timestamp']
    date_hierarchy = 'timestamp'
