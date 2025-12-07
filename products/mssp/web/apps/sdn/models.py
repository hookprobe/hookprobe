"""
SDN Models for VLAN and Device Management

Provides MAC-based VLAN assignment for IoT device segmentation.
"""

import uuid
from django.db import models
from django.contrib.auth import get_user_model
from django.core.validators import MinValueValidator, MaxValueValidator


User = get_user_model()


class DeviceCategory(models.Model):
    """
    Category for IoT devices (lights, thermostats, cameras, etc.)
    Each category maps to a specific VLAN.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=64, unique=True)
    description = models.TextField(blank=True)
    icon = models.CharField(max_length=32, default='device_hub')  # Material icon name
    color = models.CharField(max_length=7, default='#607D8B')  # Hex color

    # Default VLAN for this category
    default_vlan = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(4094)],
        help_text='Default VLAN ID for devices in this category'
    )

    # Security settings
    allow_internet = models.BooleanField(default=False, help_text='Allow internet access')
    allow_local_network = models.BooleanField(default=False, help_text='Allow access to local network')
    isolate_clients = models.BooleanField(default=True, help_text='Isolate clients from each other')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = 'Device categories'
        ordering = ['name']

    def __str__(self):
        return f"{self.name} (VLAN {self.default_vlan})"


class VLAN(models.Model):
    """
    VLAN configuration for network segmentation.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vlan_id = models.PositiveIntegerField(
        unique=True,
        validators=[MinValueValidator(1), MaxValueValidator(4094)],
        help_text='VLAN ID (1-4094)'
    )
    name = models.CharField(max_length=64)
    description = models.TextField(blank=True)

    # Network configuration
    subnet = models.CharField(max_length=18, help_text='CIDR notation, e.g., 192.168.10.0/24')
    gateway = models.GenericIPAddressField(protocol='IPv4', help_text='Gateway IP address')
    dhcp_start = models.GenericIPAddressField(protocol='IPv4', help_text='DHCP range start')
    dhcp_end = models.GenericIPAddressField(protocol='IPv4', help_text='DHCP range end')

    # Associated category (optional)
    category = models.ForeignKey(
        DeviceCategory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='vlans'
    )

    # Owner (for multi-tenant)
    owner = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='vlans'
    )

    # Guardian assignment
    guardian = models.ForeignKey(
        'devices.Device',
        on_delete=models.CASCADE,
        related_name='vlans',
        limit_choices_to={'device_type': 'guardian'},
        null=True,
        blank=True
    )

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'VLAN'
        verbose_name_plural = 'VLANs'
        ordering = ['vlan_id']

    def __str__(self):
        return f"VLAN {self.vlan_id}: {self.name}"


class RegisteredDevice(models.Model):
    """
    Registered IoT device with MAC address and VLAN assignment.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Device identification
    mac_address = models.CharField(
        max_length=17,
        help_text='MAC address in format XX:XX:XX:XX:XX:XX'
    )
    hostname = models.CharField(max_length=64, blank=True)
    friendly_name = models.CharField(max_length=128, help_text='User-friendly device name')

    # Classification
    category = models.ForeignKey(
        DeviceCategory,
        on_delete=models.SET_NULL,
        null=True,
        related_name='devices'
    )

    # VLAN assignment (overrides category default if set)
    vlan = models.ForeignKey(
        VLAN,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='devices',
        help_text='Specific VLAN assignment (overrides category default)'
    )

    # Owner
    owner = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='registered_devices'
    )

    # Guardian where device connects
    guardian = models.ForeignKey(
        'devices.Device',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='registered_clients',
        limit_choices_to={'device_type': 'guardian'}
    )

    # Status
    is_active = models.BooleanField(default=True)
    is_blocked = models.BooleanField(default=False, help_text='Block device from network')
    last_seen = models.DateTimeField(null=True, blank=True)
    last_ip = models.GenericIPAddressField(null=True, blank=True)

    # Metadata
    manufacturer = models.CharField(max_length=128, blank=True)
    model = models.CharField(max_length=128, blank=True)
    notes = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['friendly_name']
        constraints = [
            models.UniqueConstraint(
                fields=['mac_address', 'owner'],
                name='unique_mac_per_owner'
            )
        ]

    def __str__(self):
        return f"{self.friendly_name} ({self.mac_address})"

    def get_vlan_id(self):
        """Get effective VLAN ID for this device."""
        if self.vlan:
            return self.vlan.vlan_id
        if self.category:
            return self.category.default_vlan
        return 1  # Default VLAN

    def save(self, *args, **kwargs):
        # Normalize MAC address format
        self.mac_address = self.mac_address.upper().replace('-', ':')
        super().save(*args, **kwargs)


class GuardianConfig(models.Model):
    """
    Guardian AP configuration for network bridging and VLAN management.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    guardian = models.OneToOneField(
        'devices.Device',
        on_delete=models.CASCADE,
        related_name='sdn_config',
        limit_choices_to={'device_type': 'guardian'}
    )

    # Upstream connection (WiFi client mode)
    upstream_ssid = models.CharField(max_length=32, blank=True)
    upstream_password = models.CharField(max_length=64, blank=True)  # Encrypted in practice
    upstream_security = models.CharField(
        max_length=16,
        choices=[
            ('open', 'Open'),
            ('wpa2', 'WPA2-PSK'),
            ('wpa3', 'WPA3-SAE'),
            ('wpa2_enterprise', 'WPA2-Enterprise'),
        ],
        default='wpa2'
    )
    upstream_connected = models.BooleanField(default=False)

    # Hotspot configuration
    hotspot_ssid = models.CharField(max_length=32, default='HookProbe-Guardian')
    hotspot_password = models.CharField(max_length=64)
    hotspot_channel = models.PositiveIntegerField(default=6)
    hotspot_band = models.CharField(
        max_length=8,
        choices=[('2.4GHz', '2.4 GHz'), ('5GHz', '5 GHz'), ('dual', 'Dual Band')],
        default='dual'
    )

    # Bridge mode
    bridge_lan = models.BooleanField(default=True, help_text='Bridge LAN port to network')
    bridge_upstream = models.BooleanField(default=True, help_text='Bridge to upstream WiFi')

    # RADIUS configuration
    radius_server = models.GenericIPAddressField(default='127.0.0.1')
    radius_secret = models.CharField(max_length=64, default='hookprobe_radius')
    radius_port = models.PositiveIntegerField(default=1812)

    # VLAN settings
    management_vlan = models.PositiveIntegerField(default=1)
    quarantine_vlan = models.PositiveIntegerField(
        default=999,
        help_text='VLAN for unknown/unregistered devices'
    )

    # Status
    is_active = models.BooleanField(default=True)
    last_config_push = models.DateTimeField(null=True, blank=True)
    config_version = models.PositiveIntegerField(default=1)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Guardian Configuration'
        verbose_name_plural = 'Guardian Configurations'

    def __str__(self):
        return f"Config for {self.guardian}"


class NetworkScan(models.Model):
    """
    Record of WiFi network scans for upstream SSID selection.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    guardian = models.ForeignKey(
        'devices.Device',
        on_delete=models.CASCADE,
        related_name='network_scans'
    )

    ssid = models.CharField(max_length=32)
    bssid = models.CharField(max_length=17)
    channel = models.PositiveIntegerField()
    signal_strength = models.IntegerField(help_text='Signal strength in dBm')
    security = models.CharField(max_length=32)
    frequency = models.PositiveIntegerField(help_text='Frequency in MHz')

    scanned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-signal_strength']

    def __str__(self):
        return f"{self.ssid} ({self.signal_strength} dBm)"
