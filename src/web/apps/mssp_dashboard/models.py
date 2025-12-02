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
        ('edge', 'HookProbe Edge Node'),
        ('validator', 'DSM Validator'),
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
        ('quarantine', 'Quarantine - Weight Divergence'),
    ]

    name = models.CharField(max_length=200)
    device_type = models.CharField(max_length=20, choices=DEVICE_TYPE_CHOICES)
    ip_address = models.GenericIPAddressField()
    mac_address = models.CharField(max_length=17, blank=True)

    # Liberty Architecture - Hardware Fingerprinting
    hardware_fingerprint = models.CharField(
        max_length=64,
        blank=True,
        help_text="SHA256 of CPU+MAC+disk+DMI+hostname (no TPM required)"
    )
    public_key_ed25519 = models.CharField(
        max_length=64,
        blank=True,
        help_text="Device Ed25519 public key"
    )

    # Neuro Protocol - Neural Resonance Authentication
    neural_weight_fingerprint = models.CharField(
        max_length=128,
        blank=True,
        help_text="SHA512 of current neural weight state"
    )
    last_posf_signature = models.CharField(
        max_length=64,
        blank=True,
        help_text="Last Proof-of-Sensor-Fusion signature"
    )
    weight_divergence_detected = models.BooleanField(
        default=False,
        help_text="Offline tampering detected via weight mismatch"
    )

    # HTP Protocol
    htp_session_active = models.BooleanField(
        default=False,
        help_text="Active HTP session"
    )
    last_htp_heartbeat = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last HTP heartbeat"
    )

    # DSM - Decentralized Security Mesh
    dsm_participant = models.BooleanField(
        default=False,
        help_text="Participating in DSM consensus"
    )
    validator_id = models.CharField(
        max_length=100,
        blank=True,
        help_text="Managing validator ID"
    )
    kyc_verified = models.BooleanField(
        default=False,
        help_text="KYC verified (validators only)"
    )

    # Geographic location for MapBox visualization
    latitude = models.FloatField(help_text="Geographic latitude")
    longitude = models.FloatField(help_text="Geographic longitude")
    location_name = models.CharField(max_length=200, help_text="City, Country")
    country = models.CharField(max_length=100, blank=True)
    asn = models.IntegerField(null=True, blank=True, help_text="Autonomous System Number")
    isp = models.CharField(max_length=200, blank=True, help_text="Internet Service Provider")

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


class IndicatorOfCompromise(models.Model):
    """
    Unified Indicators of Compromise (IoC) aggregated from ALL security vectors.
    Acts as "one brain" collecting data from:
    - QSECBIT AI threat scoring
    - OpenFlow SDN
    - Suricata/Snort IDS/IPS
    - Zeek network analysis
    - XDP packet filtering
    - eBPF monitoring
    - SIEM correlations
    - Threat intelligence feeds
    """

    IOC_TYPE_CHOICES = [
        ('ip', 'IP Address'),
        ('domain', 'Domain Name'),
        ('url', 'URL'),
        ('email', 'Email Address'),
        ('file_hash', 'File Hash (MD5/SHA256)'),
        ('mac_address', 'MAC Address'),
        ('user_agent', 'User Agent'),
        ('certificate', 'SSL Certificate'),
        ('registry_key', 'Registry Key'),
        ('process', 'Process Name'),
        ('command', 'Command Line'),
        ('behavior', 'Behavioral Pattern'),
    ]

    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    ]

    # IoC identification
    ioc_type = models.CharField(max_length=20, choices=IOC_TYPE_CHOICES)
    value = models.CharField(max_length=500, help_text="The actual IoC value")
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)

    # Source tracking - which system detected this IoC
    detected_by_qsecbit = models.BooleanField(default=False)
    detected_by_openflow = models.BooleanField(default=False)
    detected_by_suricata = models.BooleanField(default=False)
    detected_by_snort = models.BooleanField(default=False)
    detected_by_zeek = models.BooleanField(default=False)
    detected_by_xdp = models.BooleanField(default=False)
    detected_by_ebpf = models.BooleanField(default=False)
    detected_by_siem = models.BooleanField(default=False)
    detected_by_threat_intel = models.BooleanField(default=False)

    # Correlation scoring - how many systems agree this is malicious
    detection_count = models.IntegerField(default=0, help_text="Number of systems that detected this")
    confidence_score = models.FloatField(default=0.0, help_text="0-100: Confidence this is malicious")

    # QSECBIT AI scoring
    qsecbit_score = models.FloatField(null=True, blank=True, help_text="QSECBIT threat score")
    qsecbit_rag_status = models.CharField(max_length=10, blank=True, help_text="RED/AMBER/GREEN")

    # Context and metadata
    description = models.TextField(blank=True)
    first_seen = models.DateTimeField(default=now)
    last_seen = models.DateTimeField(default=now)
    occurrence_count = models.IntegerField(default=1, help_text="How many times observed")

    # Related threat intelligence
    threat_intel = models.ForeignKey(ThreatIntelligence, on_delete=models.SET_NULL, null=True, blank=True, related_name='related_iocs')

    # Affected systems
    affected_devices = models.ManyToManyField(SecurityDevice, related_name='detected_iocs')

    # Additional data from various sources
    source_data = models.JSONField(default=dict, blank=True, help_text="Raw data from detection sources")

    # Relationships with other IoCs
    related_iocs = models.ManyToManyField('self', blank=True, symmetrical=False, related_name='correlations')

    # Status
    is_active = models.BooleanField(default=True)
    is_false_positive = models.BooleanField(default=False)
    is_whitelisted = models.BooleanField(default=False)

    # Assignment
    customer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='customer_iocs')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'mssp_indicator_of_compromise'
        verbose_name = 'Indicator of Compromise'
        verbose_name_plural = 'Indicators of Compromise'
        ordering = ['-severity', '-confidence_score', '-last_seen']
        indexes = [
            models.Index(fields=['customer', 'is_active']),
            models.Index(fields=['ioc_type', 'value']),
            models.Index(fields=['severity', '-confidence_score']),
            models.Index(fields=['-last_seen']),
        ]
        unique_together = [['customer', 'ioc_type', 'value']]

    def __str__(self):
        return f"{self.ioc_type}: {self.value} ({self.severity})"

    @property
    def detection_sources(self):
        """Return list of systems that detected this IoC."""
        sources = []
        if self.detected_by_qsecbit:
            sources.append('QSECBIT')
        if self.detected_by_openflow:
            sources.append('OpenFlow')
        if self.detected_by_suricata:
            sources.append('Suricata')
        if self.detected_by_snort:
            sources.append('Snort')
        if self.detected_by_zeek:
            sources.append('Zeek')
        if self.detected_by_xdp:
            sources.append('XDP')
        if self.detected_by_ebpf:
            sources.append('eBPF')
        if self.detected_by_siem:
            sources.append('SIEM')
        if self.detected_by_threat_intel:
            sources.append('Threat Intel')
        return sources

    @property
    def is_high_confidence(self):
        """High confidence if detected by 3+ systems or confidence > 80."""
        return self.detection_count >= 3 or self.confidence_score > 80

    @property
    def risk_score(self):
        """Calculate overall risk score (0-100) based on all factors."""
        score = 0

        # Base severity score
        severity_scores = {
            'critical': 40,
            'high': 30,
            'medium': 20,
            'low': 10,
            'info': 5
        }
        score += severity_scores.get(self.severity, 0)

        # Confidence contribution (0-30 points)
        score += (self.confidence_score * 0.3)

        # Detection count (0-20 points, max at 5 systems)
        score += min(self.detection_count * 4, 20)

        # QSECBIT contribution (0-10 points)
        if self.qsecbit_score:
            score += self.qsecbit_score * 10

        return min(score, 100)


class IoC_Report(models.Model):
    """
    Comprehensive IoC-based security reports.
    Aggregates data from all vectors to create unified incident reports.
    """

    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('active', 'Active Investigation'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
        ('archived', 'Archived'),
    ]

    SEVERITY_CHOICES = [
        ('critical', 'Critical Incident'),
        ('high', 'High Severity'),
        ('medium', 'Medium Severity'),
        ('low', 'Low Severity'),
        ('info', 'Informational'),
    ]

    # Report identification
    title = models.CharField(max_length=300)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')

    # Associated IoCs
    iocs = models.ManyToManyField(IndicatorOfCompromise, related_name='reports')

    # Affected systems
    affected_devices = models.ManyToManyField(SecurityDevice, related_name='ioc_reports')

    # Timeline
    incident_start = models.DateTimeField(help_text="When the incident started")
    incident_end = models.DateTimeField(null=True, blank=True, help_text="When resolved")

    # Analysis
    attack_vector = models.CharField(max_length=100, blank=True, help_text="How the attack occurred")
    attack_stages = models.JSONField(default=list, blank=True, help_text="Kill chain stages observed")

    # Impact assessment
    impact_assessment = models.TextField(blank=True)
    data_exfiltrated = models.BooleanField(default=False)
    systems_compromised = models.IntegerField(default=0)

    # Attribution
    threat_actor = models.CharField(max_length=200, blank=True)
    related_threat_intel = models.ManyToManyField(ThreatIntelligence, blank=True, related_name='related_reports')

    # Response actions
    response_actions = models.JSONField(default=list, blank=True, help_text="Actions taken to respond")
    playbooks_executed = models.ManyToManyField(PlaybookExecution, blank=True, related_name='related_reports')

    # Recommendations
    recommendations = models.TextField(blank=True, help_text="Recommendations to prevent recurrence")

    # Aggregated scores from all systems
    overall_risk_score = models.FloatField(default=0.0, help_text="Aggregated risk score 0-100")
    qsecbit_analysis = models.JSONField(default=dict, blank=True, help_text="QSECBIT AI analysis")
    openflow_metrics = models.JSONField(default=dict, blank=True, help_text="OpenFlow SDN data")
    ids_alerts = models.JSONField(default=dict, blank=True, help_text="Suricata/Snort alerts")
    network_analysis = models.JSONField(default=dict, blank=True, help_text="Zeek network analysis")
    packet_analysis = models.JSONField(default=dict, blank=True, help_text="XDP/eBPF data")

    # Assignment and tracking
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_ioc_reports')
    customer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='customer_ioc_reports')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'mssp_ioc_report'
        verbose_name = 'IoC Report'
        verbose_name_plural = 'IoC Reports'
        ordering = ['-severity', '-created_at']
        indexes = [
            models.Index(fields=['customer', 'status']),
            models.Index(fields=['severity', 'status']),
            models.Index(fields=['-created_at']),
        ]

    def __str__(self):
        return f"{self.title} ({self.severity})"

    @property
    def duration(self):
        """Calculate incident duration."""
        if self.incident_end:
            return self.incident_end - self.incident_start
        return now() - self.incident_start

    @property
    def is_ongoing(self):
        """Check if incident is still active."""
        return self.status in ['draft', 'active']

    def calculate_overall_risk(self):
        """Calculate overall risk score based on all IoCs and data sources."""
        if not self.iocs.exists():
            return 0.0

        # Average IoC risk scores
        ioc_scores = [ioc.risk_score for ioc in self.iocs.all()]
        avg_ioc_score = sum(ioc_scores) / len(ioc_scores) if ioc_scores else 0

        # Severity multiplier
        severity_multipliers = {
            'critical': 1.5,
            'high': 1.2,
            'medium': 1.0,
            'low': 0.8,
            'info': 0.5
        }
        multiplier = severity_multipliers.get(self.severity, 1.0)

        # Number of affected systems factor
        systems_factor = min(self.systems_compromised * 2, 20)

        # Calculate final score
        risk = (avg_ioc_score * multiplier) + systems_factor

        return min(risk, 100.0)
