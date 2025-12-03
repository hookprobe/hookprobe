"""
Security & Qsecbit Models
"""

from django.db import models
from django.utils import timezone


class SecurityEvent(models.Model):
    """Security events from IDS/IPS/WAF"""

    SEVERITY_CHOICES = [
        ('info', 'Info'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    SOURCE_TYPE_CHOICES = [
        ('snort', 'Snort 3'),
        ('zeek', 'Zeek'),
        ('suricata', 'Suricata'),
        ('waf', 'Web Application Firewall'),
        ('qsecbit', 'Qsecbit'),
        ('custom', 'Custom'),
    ]

    event_id = models.CharField(max_length=100, unique=True)
    source_type = models.CharField(max_length=20, choices=SOURCE_TYPE_CHOICES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    attack_type = models.CharField(max_length=100)
    src_ip = models.GenericIPAddressField()
    dst_ip = models.GenericIPAddressField()
    src_port = models.IntegerField(null=True, blank=True)
    dst_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=20, blank=True)
    description = models.TextField()
    raw_data = models.JSONField(null=True, blank=True)
    timestamp = models.DateTimeField(default=timezone.now)
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Security Event'
        verbose_name_plural = 'Security Events'
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['severity', '-timestamp']),
            models.Index(fields=['src_ip']),
            models.Index(fields=['attack_type', '-timestamp']),  # Fast filtering by attack type
            models.Index(fields=['source_type', '-timestamp']),  # Fast filtering by source
        ]

    def __str__(self):
        return f"{self.source_type} - {self.attack_type} - {self.timestamp}"


class QsecbitScore(models.Model):
    """Qsecbit threat scores"""

    RAG_STATUS_CHOICES = [
        ('GREEN', 'Green'),
        ('AMBER', 'Amber'),
        ('RED', 'Red'),
    ]

    timestamp = models.DateTimeField(default=timezone.now)
    score = models.FloatField()
    rag_status = models.CharField(max_length=10, choices=RAG_STATUS_CHOICES)
    attack_probability = models.FloatField()
    drift = models.FloatField()
    classifier_decay = models.FloatField()
    quantum_drift = models.FloatField()
    energy_anomaly = models.FloatField(null=True, blank=True)
    components = models.JSONField()
    metadata = models.JSONField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Qsecbit Score'
        verbose_name_plural = 'Qsecbit Scores'
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['rag_status', '-timestamp']),
        ]

    def __str__(self):
        return f"{self.rag_status} - {self.score:.4f} - {self.timestamp}"


class KaliResponse(models.Model):
    """Kali Linux automated responses"""

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    qsecbit_score = models.ForeignKey(
        QsecbitScore,
        on_delete=models.CASCADE,
        related_name='kali_responses'
    )
    triggered_at = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    recommended_actions = models.JSONField()
    executed_actions = models.JSONField(default=list)
    results = models.JSONField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-triggered_at']
        verbose_name = 'Kali Response'
        verbose_name_plural = 'Kali Responses'

    def __str__(self):
        return f"Kali Response - {self.status} - {self.triggered_at}"


class ThreatIntelligence(models.Model):
    """Threat intelligence data"""

    THREAT_TYPE_CHOICES = [
        ('ip', 'Malicious IP'),
        ('domain', 'Malicious Domain'),
        ('hash', 'Malicious Hash'),
        ('cve', 'CVE'),
        ('signature', 'Attack Signature'),
    ]

    threat_type = models.CharField(max_length=20, choices=THREAT_TYPE_CHOICES)
    indicator = models.CharField(max_length=500)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SecurityEvent.SEVERITY_CHOICES)
    source = models.CharField(max_length=200)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    metadata = models.JSONField(null=True, blank=True)

    class Meta:
        ordering = ['-last_seen']
        verbose_name = 'Threat Intelligence'
        verbose_name_plural = 'Threat Intelligence'
        indexes = [
            models.Index(fields=['indicator']),
            models.Index(fields=['threat_type', '-last_seen']),
        ]

    def __str__(self):
        return f"{self.threat_type} - {self.indicator}"
