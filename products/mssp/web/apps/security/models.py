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


class QuarantineAction(models.Model):
    """IPS quarantine actions - autonomous threat response"""

    ACTION_TYPE_CHOICES = [
        ('block_ip', 'Block IP Address'),
        ('block_port', 'Block Port'),
        ('rate_limit', 'Rate Limit'),
        ('redirect', 'Redirect to Honeypot'),
        ('isolate', 'Network Isolation'),
    ]

    STATUS_CHOICES = [
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('manual_release', 'Manual Release'),
        ('auto_release', 'Auto Release'),
    ]

    CONFIDENCE_CHOICES = [
        ('low', 'Low (< 50%)'),
        ('medium', 'Medium (50-80%)'),
        ('high', 'High (80-95%)'),
        ('critical', 'Critical (> 95%)'),
    ]

    action_id = models.CharField(max_length=100, unique=True)
    action_type = models.CharField(max_length=20, choices=ACTION_TYPE_CHOICES)
    target_ip = models.GenericIPAddressField()
    target_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=20, default='all')

    # Confidence and classification
    confidence_level = models.CharField(max_length=20, choices=CONFIDENCE_CHOICES)
    confidence_score = models.FloatField()  # 0.0 - 1.0
    classification_method = models.CharField(max_length=50)  # signature, ml, hybrid
    signature_match = models.CharField(max_length=200, blank=True)  # SID if signature
    ml_model_version = models.CharField(max_length=50, blank=True)

    # Triggering event
    security_event = models.ForeignKey(
        SecurityEvent,
        on_delete=models.SET_NULL,
        null=True,
        related_name='quarantine_actions'
    )

    # Timing
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    released_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')

    # Audit
    reason = models.TextField()
    released_by = models.CharField(max_length=100, blank=True)  # user or 'auto'
    release_reason = models.TextField(blank=True)

    # nftables integration
    nft_rule_handle = models.CharField(max_length=50, blank=True)  # nftables handle

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Quarantine Action'
        verbose_name_plural = 'Quarantine Actions'
        indexes = [
            models.Index(fields=['target_ip']),
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['action_type', '-created_at']),
            models.Index(fields=['confidence_level', '-created_at']),
        ]

    def __str__(self):
        return f"{self.action_type} - {self.target_ip} - {self.status}"

    @property
    def is_expired(self):
        from django.utils import timezone
        return timezone.now() > self.expires_at

    def release(self, by='auto', reason=''):
        """Release the quarantine"""
        from django.utils import timezone
        self.status = 'auto_release' if by == 'auto' else 'manual_release'
        self.released_at = timezone.now()
        self.released_by = by
        self.release_reason = reason
        self.save()


class DetectionRule(models.Model):
    """Custom detection rules for AIOCHI hybrid classifier"""

    RULE_TYPE_CHOICES = [
        ('signature', 'Signature-based'),
        ('behavioral', 'Behavioral/ML'),
        ('threshold', 'Threshold-based'),
        ('correlation', 'Correlation'),
    ]

    STATUS_CHOICES = [
        ('active', 'Active'),
        ('disabled', 'Disabled'),
        ('testing', 'Testing'),
    ]

    rule_id = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=200)
    description = models.TextField()
    rule_type = models.CharField(max_length=20, choices=RULE_TYPE_CHOICES)

    # Rule definition
    pattern = models.TextField(help_text='Regex pattern or ML feature definition')
    threshold = models.FloatField(default=0.8, help_text='Detection threshold')
    window_seconds = models.IntegerField(default=60, help_text='Time window for correlation')

    # Classification
    severity = models.CharField(max_length=20, choices=SecurityEvent.SEVERITY_CHOICES)
    attack_type = models.CharField(max_length=100)
    mitre_tactic = models.CharField(max_length=100, blank=True)
    mitre_technique = models.CharField(max_length=100, blank=True)

    # Auto-response
    auto_quarantine = models.BooleanField(default=False)
    quarantine_duration_minutes = models.IntegerField(default=60)
    min_confidence_for_quarantine = models.FloatField(default=0.9)

    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    hit_count = models.IntegerField(default=0)
    false_positive_count = models.IntegerField(default=0)

    class Meta:
        ordering = ['-hit_count']
        verbose_name = 'Detection Rule'
        verbose_name_plural = 'Detection Rules'

    def __str__(self):
        return f"{self.rule_id} - {self.name}"

    @property
    def accuracy(self):
        """Calculate rule accuracy based on false positives"""
        if self.hit_count == 0:
            return 1.0
        return 1.0 - (self.false_positive_count / self.hit_count)
