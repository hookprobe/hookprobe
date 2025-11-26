"""
MSSP Dashboard Models

Models for storing and aggregating security metrics from various sources:
- Suricata IDS/IPS
- Zeek network analysis
- OpenFlow SDN metrics
- XDP (eXpress Data Path) packet processing
- eBPF system monitoring
"""

from django.db import models
from django.contrib.auth.models import User
from django.utils.timezone import now


class SecurityDevice(models.Model):
    """
    Security devices/endpoints monitored by HookProbe.
    Displayed on the Endpoints tab with geographic visualization.
    """

    DEVICE_TYPE_CHOICES = [
        ('suricata', 'Suricata IDS/IPS'),
        ('zeek', 'Zeek Network Monitor'),
        ('openflow', 'OpenFlow Switch'),
        ('xdp', 'XDP Packet Filter'),
        ('ebpf', 'eBPF Monitor'),
        ('firewall', 'Firewall'),
        ('endpoint', 'Endpoint Agent'),
    ]

    STATUS_CHOICES = [
        ('online', 'Online'),
        ('offline', 'Offline'),
        ('degraded', 'Degraded'),
        ('maintenance', 'Maintenance'),
    ]

    name = models.CharField(max_length=200)
    device_type = models.CharField(max_length=20, choices=DEVICE_TYPE_CHOICES)
    ip_address = models.GenericIPAddressField()
    mac_address = models.CharField(max_length=17, blank=True)

    # Geographic location for MapBox visualization
    latitude = models.FloatField(help_text="Geographic latitude")
    longitude = models.FloatField(help_text="Geographic longitude")
    location_name = models.CharField(max_length=200, help_text="City, Country")

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='online')
    last_seen = models.DateTimeField(default=now)

    # Customer/Organization
    customer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='security_devices')

    # Metadata
    firmware_version = models.CharField(max_length=50, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'mssp_security_device'
        ordering = ['-last_seen']
        indexes = [
            models.Index(fields=['customer', 'status']),
            models.Index(fields=['device_type']),
        ]

    def __str__(self):
        return f"{self.name} ({self.device_type})"

    @property
    def is_online(self):
        """Check if device is currently online (seen in last 5 minutes)."""
        from django.utils.timezone import now
        from datetime import timedelta
        return self.last_seen >= now() - timedelta(minutes=5)


class SecurityMetric(models.Model):
    """
    Real-time security metrics aggregated from all monitoring tools.
    Used for dashboard home page statistics.
    """

    METRIC_TYPE_CHOICES = [
        ('alert', 'Security Alert'),
        ('connection', 'Network Connection'),
        ('packet', 'Packet Count'),
        ('bandwidth', 'Bandwidth Usage'),
        ('threat', 'Threat Detection'),
        ('anomaly', 'Anomaly Detection'),
    ]

    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    ]

    device = models.ForeignKey(SecurityDevice, on_delete=models.CASCADE, related_name='metrics')
    metric_type = models.CharField(max_length=20, choices=METRIC_TYPE_CHOICES)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='info')

    # Metric data
    value = models.FloatField(help_text="Numeric metric value")
    unit = models.CharField(max_length=20, help_text="e.g., 'count', 'Mbps', 'packets/sec'")

    # Additional context
    source_tool = models.CharField(max_length=50, help_text="Suricata, Zeek, etc.")
    description = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    timestamp = models.DateTimeField(default=now, db_index=True)

    class Meta:
        db_table = 'mssp_security_metric'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['device', 'metric_type', '-timestamp']),
            models.Index(fields=['severity', '-timestamp']),
        ]

    def __str__(self):
        return f"{self.metric_type} - {self.value} {self.unit} ({self.timestamp})"


class Vulnerability(models.Model):
    """
    Security vulnerabilities detected and tracked.
    Displayed on the Vulnerabilities tab with AI-powered mitigation recommendations.
    """

    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('mitigated', 'Mitigated'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    ]

    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]

    # Vulnerability identification
    cve_id = models.CharField(max_length=20, blank=True, help_text="CVE-2024-XXXXX")
    title = models.CharField(max_length=300)
    description = models.TextField()

    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    cvss_score = models.FloatField(null=True, blank=True, help_text="CVSS 3.1 score (0-10)")

    # Affected systems
    affected_devices = models.ManyToManyField(SecurityDevice, related_name='vulnerabilities')

    # Status tracking
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    discovered_at = models.DateTimeField(default=now)
    resolved_at = models.DateTimeField(null=True, blank=True)

    # AI-powered recommendations
    ai_mitigation_recommendation = models.TextField(blank=True, help_text="AI-generated mitigation steps")
    ai_confidence_score = models.FloatField(null=True, blank=True, help_text="AI confidence (0-1)")

    # References
    references = models.JSONField(default=list, blank=True, help_text="URLs to CVE databases, advisories")

    # Assignment
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_vulnerabilities')
    customer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='customer_vulnerabilities')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'mssp_vulnerability'
        verbose_name_plural = 'Vulnerabilities'
        ordering = ['-severity', '-discovered_at']
        indexes = [
            models.Index(fields=['customer', 'status']),
            models.Index(fields=['severity', 'status']),
        ]

    def __str__(self):
        return f"{self.cve_id or 'VULN'} - {self.title}"

    @property
    def is_critical(self):
        return self.severity == 'critical' or (self.cvss_score and self.cvss_score >= 9.0)


class SOARPlaybook(models.Model):
    """
    Security Orchestration, Automation and Response (SOAR) playbooks.
    Automated remediation workflows for common security scenarios.
    """

    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('active', 'Active'),
        ('paused', 'Paused'),
        ('archived', 'Archived'),
    ]

    name = models.CharField(max_length=200)
    description = models.TextField()

    # Trigger conditions
    trigger_on_vulnerability = models.BooleanField(default=False)
    trigger_on_alert = models.BooleanField(default=False)
    trigger_severity = models.CharField(max_length=10, blank=True)

    # Playbook steps (JSON workflow definition)
    steps = models.JSONField(default=list, help_text="Ordered list of automation steps")

    # Integration
    n8n_webhook_url = models.URLField(blank=True, help_text="n8n webhook for automation")

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')

    # Metrics
    execution_count = models.IntegerField(default=0)
    success_count = models.IntegerField(default=0)

    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_playbooks')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'mssp_soar_playbook'
        ordering = ['-created_at']

    def __str__(self):
        return self.name

    @property
    def success_rate(self):
        """Calculate success rate as percentage."""
        if self.execution_count == 0:
            return 0
        return (self.success_count / self.execution_count) * 100


class PlaybookExecution(models.Model):
    """
    Execution log for SOAR playbooks.
    Tracks each time a playbook runs.
    """

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]

    playbook = models.ForeignKey(SOARPlaybook, on_delete=models.CASCADE, related_name='executions')
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, null=True, blank=True, related_name='playbook_executions')

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    # Execution data
    started_at = models.DateTimeField(default=now)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Results
    result_data = models.JSONField(default=dict, blank=True, help_text="Execution results and logs")
    error_message = models.TextField(blank=True)

    class Meta:
        db_table = 'mssp_playbook_execution'
        ordering = ['-started_at']
        indexes = [
            models.Index(fields=['playbook', '-started_at']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return f"{self.playbook.name} - {self.status} ({self.started_at})"


class ThreatIntelligence(models.Model):
    """
    Threat intelligence feed for xSOC (Red/Blue team dashboards).
    """

    THREAT_TYPE_CHOICES = [
        ('malware', 'Malware'),
        ('phishing', 'Phishing'),
        ('ransomware', 'Ransomware'),
        ('apt', 'Advanced Persistent Threat'),
        ('ddos', 'DDoS Attack'),
        ('data_breach', 'Data Breach'),
        ('zero_day', 'Zero-Day Exploit'),
    ]

    CONFIDENCE_CHOICES = [
        ('high', 'High Confidence'),
        ('medium', 'Medium Confidence'),
        ('low', 'Low Confidence'),
    ]

    title = models.CharField(max_length=300)
    description = models.TextField()
    threat_type = models.CharField(max_length=20, choices=THREAT_TYPE_CHOICES)
    confidence = models.CharField(max_length=10, choices=CONFIDENCE_CHOICES)

    # Indicators of Compromise (IoCs)
    iocs = models.JSONField(default=list, help_text="IP addresses, domains, file hashes")

    # Attribution
    threat_actor = models.CharField(max_length=200, blank=True)
    source = models.CharField(max_length=200, help_text="Intelligence source")

    # Temporal
    published_at = models.DateTimeField(default=now)
    expires_at = models.DateTimeField(null=True, blank=True)

    # References
    references = models.JSONField(default=list, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'mssp_threat_intelligence'
        ordering = ['-published_at']
        indexes = [
            models.Index(fields=['threat_type', '-published_at']),
        ]

    def __str__(self):
        return f"{self.threat_type} - {self.title}"
