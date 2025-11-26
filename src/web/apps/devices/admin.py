"""
Device Management Admin Configuration
"""

from django.contrib import admin
from .models import Customer, Device, DeviceLog, DeviceMetric


@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    list_display = ['name', 'tenant_id', 'contact_email', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'tenant_id', 'contact_email']
    readonly_fields = ['created_at', 'updated_at']
    list_editable = ['is_active']


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ['name', 'customer', 'device_id', 'ip_address', 'status',
                    'last_seen', 'architecture']
    list_filter = ['status', 'deployment_type', 'architecture', 'customer']
    search_fields = ['name', 'device_id', 'hostname', 'ip_address']
    readonly_fields = ['device_id', 'last_seen', 'created_at', 'updated_at',
                       'cpu_usage_percent', 'ram_usage_percent', 'disk_usage_percent']
    list_editable = ['status']
    date_hierarchy = 'last_seen'

    fieldsets = (
        ('Basic Information', {
            'fields': ('customer', 'name', 'device_id', 'hostname',
                      'ip_address', 'mac_address')
        }),
        ('Hardware', {
            'fields': ('architecture', 'cpu_model', 'cpu_cores', 'ram_gb',
                      'storage_gb', 'nic_model')
        }),
        ('Software', {
            'fields': ('os_version', 'hookprobe_version', 'deployment_type')
        }),
        ('Status', {
            'fields': ('status', 'last_seen', 'uptime_seconds', 'is_active')
        }),
        ('Metrics', {
            'fields': ('cpu_usage_percent', 'ram_usage_percent',
                      'disk_usage_percent', 'network_rx_bytes', 'network_tx_bytes'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('location', 'description', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(DeviceLog)
class DeviceLogAdmin(admin.ModelAdmin):
    list_display = ['device', 'log_type', 'message', 'timestamp']
    list_filter = ['log_type', 'timestamp', 'device']
    search_fields = ['message', 'device__name']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'

    def has_add_permission(self, request):
        return False


@admin.register(DeviceMetric)
class DeviceMetricAdmin(admin.ModelAdmin):
    list_display = ['device', 'timestamp', 'cpu_usage', 'ram_usage',
                    'disk_usage', 'qsecbit_score']
    list_filter = ['device', 'timestamp']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'

    def has_add_permission(self, request):
        return False
