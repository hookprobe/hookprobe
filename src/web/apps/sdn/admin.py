"""Django admin configuration for SDN app."""

from django.contrib import admin
from .models import DeviceCategory, VLAN, RegisteredDevice, GuardianConfig, NetworkScan


@admin.register(DeviceCategory)
class DeviceCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'default_vlan', 'allow_internet', 'isolate_clients']
    search_fields = ['name', 'description']


@admin.register(VLAN)
class VLANAdmin(admin.ModelAdmin):
    list_display = ['vlan_id', 'name', 'subnet', 'category', 'is_active']
    list_filter = ['is_active', 'category']
    search_fields = ['name', 'subnet']


@admin.register(RegisteredDevice)
class RegisteredDeviceAdmin(admin.ModelAdmin):
    list_display = ['friendly_name', 'mac_address', 'category', 'get_vlan_id', 'is_active', 'last_seen']
    list_filter = ['category', 'is_active', 'is_blocked']
    search_fields = ['friendly_name', 'mac_address', 'hostname']
    readonly_fields = ['last_seen', 'last_ip']


@admin.register(GuardianConfig)
class GuardianConfigAdmin(admin.ModelAdmin):
    list_display = ['guardian', 'hotspot_ssid', 'upstream_ssid', 'upstream_connected', 'is_active']
    list_filter = ['is_active', 'upstream_connected']


@admin.register(NetworkScan)
class NetworkScanAdmin(admin.ModelAdmin):
    list_display = ['ssid', 'bssid', 'channel', 'signal_strength', 'security', 'scanned_at']
    list_filter = ['security', 'scanned_at']
    search_fields = ['ssid', 'bssid']
