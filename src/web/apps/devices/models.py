"""
Device Management Models - MSSP Edge Devices
"""

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class Customer(models.Model):
    """MSSP Customer/Tenant"""
    name = models.CharField(max_length=200)
    tenant_id = models.CharField(max_length=100, unique=True)
    contact_email = models.EmailField()
    contact_phone = models.CharField(max_length=20, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ['name']
        verbose_name = 'Customer'
        verbose_name_plural = 'Customers'

    def __str__(self):
        return self.name


class Device(models.Model):
    """Edge Device (SBC/Server running HookProbe)"""

    STATUS_CHOICES = [
        ('online', 'Online'),
        ('offline', 'Offline'),
        ('warning', 'Warning'),
        ('maintenance', 'Maintenance'),
    ]

    DEPLOYMENT_TYPE_CHOICES = [
        ('edge', 'Edge Deployment'),
        ('cloud', 'Cloud Backend'),
        ('hybrid', 'Hybrid'),
    ]

    ARCHITECTURE_CHOICES = [
        ('x86_64', 'x86_64 (Intel/AMD)'),
        ('arm64', 'ARM64 (ARMv8)'),
    ]

    customer = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE,
        related_name='devices'
    )
    name = models.CharField(max_length=200)
    device_id = models.CharField(max_length=100, unique=True)
    hostname = models.CharField(max_length=200)
    ip_address = models.GenericIPAddressField()
    mac_address = models.CharField(max_length=17, blank=True)

    # Hardware specs
    architecture = models.CharField(
        max_length=20,
        choices=ARCHITECTURE_CHOICES,
        default='x86_64'
    )
    cpu_model = models.CharField(max_length=200, blank=True)
    cpu_cores = models.IntegerField(null=True, blank=True)
    ram_gb = models.IntegerField(null=True, blank=True)
    storage_gb = models.IntegerField(null=True, blank=True)
    nic_model = models.CharField(max_length=200, blank=True)

    # Software
    os_version = models.CharField(max_length=100, blank=True)
    hookprobe_version = models.CharField(max_length=20, blank=True)
    deployment_type = models.CharField(
        max_length=20,
        choices=DEPLOYMENT_TYPE_CHOICES,
        default='edge'
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='offline'
    )
    last_seen = models.DateTimeField(null=True, blank=True)
    uptime_seconds = models.BigIntegerField(default=0)

    # Metrics
    cpu_usage_percent = models.FloatField(default=0)
    ram_usage_percent = models.FloatField(default=0)
    disk_usage_percent = models.FloatField(default=0)
    network_rx_bytes = models.BigIntegerField(default=0)
    network_tx_bytes = models.BigIntegerField(default=0)

    # Metadata
    location = models.CharField(max_length=200, blank=True)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['customer', 'name']
        verbose_name = 'Device'
        verbose_name_plural = 'Devices'

    def __str__(self):
        return f"{self.customer.name} - {self.name}"

    def is_online(self):
        """Check if device is online (seen in last 5 minutes)"""
        if not self.last_seen:
            return False
        threshold = timezone.now() - timezone.timedelta(minutes=5)
        return self.last_seen >= threshold


class DeviceLog(models.Model):
    """Device activity logs"""

    LOG_TYPE_CHOICES = [
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('error', 'Error'),
        ('critical', 'Critical'),
    ]

    device = models.ForeignKey(
        Device,
        on_delete=models.CASCADE,
        related_name='logs'
    )
    log_type = models.CharField(max_length=20, choices=LOG_TYPE_CHOICES)
    message = models.TextField()
    details = models.JSONField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Device Log'
        verbose_name_plural = 'Device Logs'

    def __str__(self):
        return f"{self.device.name} - {self.log_type} - {self.timestamp}"


class DeviceMetric(models.Model):
    """Time-series device metrics"""

    device = models.ForeignKey(
        Device,
        on_delete=models.CASCADE,
        related_name='metrics'
    )
    timestamp = models.DateTimeField(default=timezone.now)
    cpu_usage = models.FloatField()
    ram_usage = models.FloatField()
    disk_usage = models.FloatField()
    network_rx_rate = models.BigIntegerField(default=0)
    network_tx_rate = models.BigIntegerField(default=0)
    qsecbit_score = models.FloatField(null=True, blank=True)
    threat_events_count = models.IntegerField(default=0)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Device Metric'
        verbose_name_plural = 'Device Metrics'
        indexes = [
            models.Index(fields=['device', '-timestamp']),
        ]

    def __str__(self):
        return f"{self.device.name} - {self.timestamp}"
