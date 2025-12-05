"""
VPN Profile and Session Models

Manages VPN profiles for iOS/Android devices connecting via IKEv2 to
Guardian/Fortress devices behind CGNAT/NAT.

Architecture:
    Phone ←──IKEv2──→ Nexus (MSSP) ←──HTP──→ Guardian/Fortress
"""

import uuid
import secrets
import hashlib
from datetime import timedelta

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator

from apps.devices.models import Device, Customer


class VPNCertificate(models.Model):
    """
    User certificate for IKEv2 EAP-TLS authentication.

    Each user gets a unique certificate signed by the Nexus CA.
    Certificate is embedded in .mobileconfig for iOS or used for Android.
    """

    STATUS_CHOICES = [
        ('active', 'Active'),
        ('revoked', 'Revoked'),
        ('expired', 'Expired'),
        ('pending', 'Pending Issuance'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='vpn_certificates'
    )

    # Certificate details
    serial_number = models.CharField(
        max_length=40,
        unique=True,
        help_text="Certificate serial number (hex)"
    )
    common_name = models.CharField(
        max_length=255,
        help_text="Certificate CN (usually user email)"
    )
    subject_alt_name = models.CharField(
        max_length=255,
        blank=True,
        help_text="SAN for certificate"
    )

    # Key material (encrypted at rest)
    public_key_pem = models.TextField(
        help_text="Public key in PEM format"
    )
    certificate_pem = models.TextField(
        help_text="X.509 certificate in PEM format"
    )
    # Private key stored encrypted - only decrypted for profile generation
    encrypted_private_key = models.BinaryField(
        help_text="AES-256-GCM encrypted private key"
    )
    key_encryption_iv = models.BinaryField(
        max_length=12,
        help_text="IV for private key encryption"
    )

    # Validity
    issued_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'
    )

    # Revocation
    revoked_at = models.DateTimeField(null=True, blank=True)
    revocation_reason = models.CharField(max_length=255, blank=True)

    # Fingerprints for validation
    fingerprint_sha256 = models.CharField(
        max_length=64,
        help_text="SHA256 fingerprint of certificate"
    )

    class Meta:
        ordering = ['-issued_at']
        verbose_name = 'VPN Certificate'
        verbose_name_plural = 'VPN Certificates'
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['serial_number']),
            models.Index(fields=['fingerprint_sha256']),
        ]

    def __str__(self):
        return f"{self.common_name} ({self.status})"

    def is_valid(self):
        """Check if certificate is currently valid."""
        now = timezone.now()
        return (
            self.status == 'active' and
            self.issued_at <= now <= self.expires_at
        )

    def revoke(self, reason: str = ""):
        """Revoke this certificate."""
        self.status = 'revoked'
        self.revoked_at = timezone.now()
        self.revocation_reason = reason
        self.save()


class VPNProfile(models.Model):
    """
    VPN Profile for a user-device pair.

    Each profile connects a user's phone to a specific Guardian/Fortress.
    Profile can be exported as iOS .mobileconfig or Android VPN settings.
    """

    PROFILE_TYPE_CHOICES = [
        ('guardian', 'Guardian (Travel)'),
        ('fortress', 'Fortress (Home/Business)'),
    ]

    PLATFORM_CHOICES = [
        ('ios', 'iOS'),
        ('android', 'Android'),
        ('macos', 'macOS'),
        ('windows', 'Windows'),
        ('universal', 'Universal'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='vpn_profiles'
    )
    device = models.ForeignKey(
        Device,
        on_delete=models.CASCADE,
        related_name='vpn_profiles',
        help_text="Target Guardian/Fortress device"
    )
    certificate = models.ForeignKey(
        VPNCertificate,
        on_delete=models.SET_NULL,
        null=True,
        related_name='profiles'
    )

    # Profile identification
    name = models.CharField(
        max_length=100,
        help_text="User-friendly profile name"
    )
    profile_type = models.CharField(
        max_length=20,
        choices=PROFILE_TYPE_CHOICES,
        default='fortress'
    )
    platform = models.CharField(
        max_length=20,
        choices=PLATFORM_CHOICES,
        default='universal'
    )

    # VPN Configuration
    vpn_server = models.CharField(
        max_length=255,
        help_text="Nexus VPN gateway hostname/IP"
    )
    vpn_remote_id = models.CharField(
        max_length=255,
        help_text="IKEv2 remote identifier"
    )
    local_identifier = models.CharField(
        max_length=255,
        help_text="User's local identifier (email or UUID)"
    )

    # Routing
    route_all_traffic = models.BooleanField(
        default=False,
        help_text="Route all traffic through VPN (vs split tunnel)"
    )
    split_tunnel_routes = models.JSONField(
        default=list,
        blank=True,
        help_text="List of CIDR ranges for split tunneling"
    )
    dns_servers = models.JSONField(
        default=list,
        blank=True,
        help_text="DNS servers to use when VPN is active"
    )

    # On-demand rules (iOS/macOS)
    on_demand_enabled = models.BooleanField(
        default=True,
        help_text="Auto-connect on specific networks"
    )
    on_demand_rules = models.JSONField(
        default=list,
        blank=True,
        help_text="On-demand connection rules"
    )

    # Bandwidth allocation
    bandwidth_limit_mbps = models.IntegerField(
        default=50,
        validators=[MinValueValidator(1), MaxValueValidator(1000)],
        help_text="Maximum bandwidth allocation in Mbps"
    )

    # Access control
    is_active = models.BooleanField(default=True)
    valid_from = models.DateTimeField(default=timezone.now)
    valid_until = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Profile expiration (null = no expiry)"
    )

    # Download tracking
    download_token = models.CharField(
        max_length=64,
        unique=True,
        help_text="One-time download token"
    )
    download_count = models.IntegerField(default=0)
    last_downloaded = models.DateTimeField(null=True, blank=True)
    max_downloads = models.IntegerField(
        default=5,
        help_text="Max profile downloads before regeneration required"
    )

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'VPN Profile'
        verbose_name_plural = 'VPN Profiles'
        unique_together = [['user', 'device', 'platform']]
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['download_token']),
            models.Index(fields=['device', 'is_active']),
        ]

    def __str__(self):
        return f"{self.user.username} → {self.device.name} ({self.platform})"

    def save(self, *args, **kwargs):
        if not self.download_token:
            self.download_token = secrets.token_urlsafe(48)
        super().save(*args, **kwargs)

    def is_valid(self):
        """Check if profile is currently valid."""
        now = timezone.now()
        if not self.is_active:
            return False
        if self.valid_until and now > self.valid_until:
            return False
        if self.download_count >= self.max_downloads:
            return False
        return True

    def regenerate_token(self):
        """Regenerate download token and reset counter."""
        self.download_token = secrets.token_urlsafe(48)
        self.download_count = 0
        self.save()


class VPNSession(models.Model):
    """
    Active VPN session tracking.

    Tracks connected users, bandwidth usage, and session metadata.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    profile = models.ForeignKey(
        VPNProfile,
        on_delete=models.CASCADE,
        related_name='sessions'
    )

    # Session details
    started_at = models.DateTimeField(auto_now_add=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    # Connection info
    client_ip = models.GenericIPAddressField(
        help_text="Client's public IP address"
    )
    assigned_ip = models.GenericIPAddressField(
        help_text="IP assigned to client in VPN tunnel"
    )
    client_user_agent = models.CharField(
        max_length=255,
        blank=True,
        help_text="Client device/OS info"
    )

    # IKEv2 session
    ike_sa_id = models.CharField(
        max_length=64,
        blank=True,
        help_text="IKE Security Association ID"
    )
    child_sa_id = models.CharField(
        max_length=64,
        blank=True,
        help_text="Child SA ID for ESP"
    )

    # Bandwidth tracking
    bytes_in = models.BigIntegerField(default=0)
    bytes_out = models.BigIntegerField(default=0)
    packets_in = models.BigIntegerField(default=0)
    packets_out = models.BigIntegerField(default=0)

    # Quality metrics
    last_activity = models.DateTimeField(auto_now=True)
    avg_latency_ms = models.FloatField(default=0)
    packet_loss_percent = models.FloatField(default=0)

    # HTP tunnel to Guardian/Fortress
    htp_flow_token = models.CharField(
        max_length=32,
        blank=True,
        help_text="HTP flow token for Nexus→Device tunnel"
    )
    htp_session_state = models.CharField(
        max_length=20,
        default='init',
        help_text="HTP session state"
    )

    class Meta:
        ordering = ['-started_at']
        verbose_name = 'VPN Session'
        verbose_name_plural = 'VPN Sessions'
        indexes = [
            models.Index(fields=['profile', 'is_active']),
            models.Index(fields=['-started_at']),
            models.Index(fields=['client_ip']),
        ]

    def __str__(self):
        status = "active" if self.is_active else "ended"
        return f"{self.profile.user.username} - {status} - {self.started_at}"

    @property
    def duration(self):
        """Session duration in seconds."""
        end = self.ended_at or timezone.now()
        return (end - self.started_at).total_seconds()

    @property
    def bandwidth_used_mb(self):
        """Total bandwidth used in MB."""
        return (self.bytes_in + self.bytes_out) / (1024 * 1024)

    def end_session(self):
        """End this VPN session."""
        self.is_active = False
        self.ended_at = timezone.now()
        self.save()


class VPNAccessLog(models.Model):
    """
    Audit log for VPN access and profile operations.
    """

    ACTION_CHOICES = [
        ('profile_created', 'Profile Created'),
        ('profile_downloaded', 'Profile Downloaded'),
        ('profile_revoked', 'Profile Revoked'),
        ('session_started', 'Session Started'),
        ('session_ended', 'Session Ended'),
        ('auth_success', 'Authentication Success'),
        ('auth_failed', 'Authentication Failed'),
        ('cert_issued', 'Certificate Issued'),
        ('cert_revoked', 'Certificate Revoked'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='vpn_access_logs'
    )
    action = models.CharField(max_length=30, choices=ACTION_CHOICES)

    # Context
    profile = models.ForeignKey(
        VPNProfile,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    session = models.ForeignKey(
        VPNSession,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    # Request info
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)

    # Details
    details = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'VPN Access Log'
        verbose_name_plural = 'VPN Access Logs'
        indexes = [
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['action', '-timestamp']),
        ]

    def __str__(self):
        return f"{self.user} - {self.action} - {self.timestamp}"
