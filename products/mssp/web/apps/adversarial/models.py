"""
Adversarial Security Framework - Django Models

"One node's detection → Everyone's protection"

Models for tracking adversarial tests, vulnerabilities, mitigations,
and designer alerts.
"""

from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
import uuid

User = get_user_model()


class AttackVectorCategory(models.TextChoices):
    """Categories of attack vectors"""
    REPLAY = 'replay', 'Replay Attack'
    TIMING = 'timing', 'Timing Side-Channel'
    ENTROPY = 'entropy', 'Entropy Attack'
    WEIGHT = 'weight', 'Weight Prediction'
    COLLISION = 'collision', 'Collision Attack'
    FORGERY = 'forgery', 'Signature Forgery'
    MEMORY = 'memory', 'Memory Extraction'
    SIDE_CHANNEL = 'side_channel', 'Side Channel'


class VulnerabilitySeverity(models.TextChoices):
    """CVSS-based severity levels"""
    CRITICAL = 'critical', 'Critical (9.0-10.0)'
    HIGH = 'high', 'High (7.0-8.9)'
    MEDIUM = 'medium', 'Medium (4.0-6.9)'
    LOW = 'low', 'Low (0.1-3.9)'
    INFO = 'info', 'Informational (0.0)'


class MitigationPriority(models.TextChoices):
    """Mitigation priority levels"""
    IMMEDIATE = 'immediate', 'Immediate (24h)'
    URGENT = 'urgent', 'Urgent (7 days)'
    STANDARD = 'standard', 'Standard (30 days)'
    LOW = 'low', 'Low (90 days)'
    BACKLOG = 'backlog', 'Backlog'


class TestStatus(models.TextChoices):
    """Status of adversarial tests"""
    SCHEDULED = 'scheduled', 'Scheduled'
    RUNNING = 'running', 'Running'
    COMPLETED = 'completed', 'Completed'
    FAILED = 'failed', 'Failed'
    CANCELLED = 'cancelled', 'Cancelled'


class AdversarialTest(models.Model):
    """
    Represents a scheduled or completed adversarial security test.

    Tests are run by the AI Red Team to discover vulnerabilities
    in the HTP-DSM-NEURO-QSECBIT-NSE stack.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)

    # Target configuration
    target_component = models.CharField(max_length=100)  # e.g., 'nse', 'htp', 'dsm'
    target_tier = models.CharField(max_length=50, blank=True)  # e.g., 'guardian', 'fortress'
    attack_vectors = models.JSONField(default=list)  # List of attack vector names

    # Scheduling
    scheduled_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True,
        related_name='scheduled_tests'
    )
    scheduled_at = models.DateTimeField(default=timezone.now)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Status and results
    status = models.CharField(
        max_length=20,
        choices=TestStatus.choices,
        default=TestStatus.SCHEDULED
    )
    results_summary = models.JSONField(default=dict)
    vulnerabilities_found = models.IntegerField(default=0)
    highest_cvss = models.FloatField(default=0.0)

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-scheduled_at']
        verbose_name = 'Adversarial Test'
        verbose_name_plural = 'Adversarial Tests'

    def __str__(self):
        return f"{self.name} ({self.status})"

    @property
    def duration(self):
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None


class Vulnerability(models.Model):
    """
    Represents a discovered vulnerability in the NSE stack.

    Vulnerabilities are discovered by adversarial tests and
    tracked until mitigated.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Discovery context
    test = models.ForeignKey(
        AdversarialTest, on_delete=models.CASCADE,
        related_name='vulnerabilities'
    )
    attack_vector = models.CharField(
        max_length=50,
        choices=AttackVectorCategory.choices
    )

    # Vulnerability details
    title = models.CharField(max_length=300)
    description = models.TextField()
    technical_details = models.TextField(blank=True)
    affected_components = models.JSONField(default=list)
    affected_files = models.JSONField(default=list)

    # Scoring
    cvss_score = models.FloatField(default=0.0)
    severity = models.CharField(
        max_length=20,
        choices=VulnerabilitySeverity.choices,
        default=VulnerabilitySeverity.INFO
    )
    cvss_vector = models.CharField(max_length=100, blank=True)

    # Exploitation context
    exploitability = models.CharField(max_length=50, default='theoretical')
    proof_of_concept = models.TextField(blank=True)

    # Status
    is_verified = models.BooleanField(default=False)
    is_mitigated = models.BooleanField(default=False)
    is_false_positive = models.BooleanField(default=False)

    # Timestamps
    discovered_at = models.DateTimeField(default=timezone.now)
    verified_at = models.DateTimeField(null=True, blank=True)
    mitigated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-cvss_score', '-discovered_at']
        verbose_name = 'Vulnerability'
        verbose_name_plural = 'Vulnerabilities'

    def __str__(self):
        return f"[{self.severity.upper()}] {self.title}"

    def save(self, *args, **kwargs):
        # Auto-set severity based on CVSS
        if self.cvss_score >= 9.0:
            self.severity = VulnerabilitySeverity.CRITICAL
        elif self.cvss_score >= 7.0:
            self.severity = VulnerabilitySeverity.HIGH
        elif self.cvss_score >= 4.0:
            self.severity = VulnerabilitySeverity.MEDIUM
        elif self.cvss_score > 0:
            self.severity = VulnerabilitySeverity.LOW
        else:
            self.severity = VulnerabilitySeverity.INFO
        super().save(*args, **kwargs)


class Mitigation(models.Model):
    """
    Represents a suggested or implemented mitigation for a vulnerability.

    Mitigations are suggested by the AI Blue Team and tracked
    through implementation.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Link to vulnerability
    vulnerability = models.ForeignKey(
        Vulnerability, on_delete=models.CASCADE,
        related_name='mitigations'
    )

    # Mitigation details
    title = models.CharField(max_length=300)
    description = models.TextField()
    implementation_guide = models.TextField(blank=True)
    code_changes = models.JSONField(default=list)  # List of file changes

    # Priority and effort
    priority = models.CharField(
        max_length=20,
        choices=MitigationPriority.choices,
        default=MitigationPriority.STANDARD
    )
    estimated_effort = models.CharField(max_length=50, blank=True)

    # Implementation status
    is_implemented = models.BooleanField(default=False)
    implemented_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='implemented_mitigations'
    )
    implemented_at = models.DateTimeField(null=True, blank=True)
    implementation_notes = models.TextField(blank=True)

    # Verification
    is_verified = models.BooleanField(default=False)
    verified_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='verified_mitigations'
    )
    verified_at = models.DateTimeField(null=True, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['priority', '-created_at']
        verbose_name = 'Mitigation'
        verbose_name_plural = 'Mitigations'

    def __str__(self):
        return f"[{self.priority.upper()}] {self.title}"


class DesignerAlert(models.Model):
    """
    Security alerts for designers/developers to review.

    Alerts are generated when high-severity vulnerabilities are
    discovered or when security regressions occur.
    """
    ALERT_LEVELS = [
        ('info', 'Informational'),
        ('warning', 'Warning'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Alert content
    level = models.CharField(max_length=20, choices=ALERT_LEVELS, default='info')
    title = models.CharField(max_length=300)
    message = models.TextField()
    details = models.JSONField(default=dict)

    # Related objects
    vulnerability = models.ForeignKey(
        Vulnerability, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='alerts'
    )
    test = models.ForeignKey(
        AdversarialTest, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='alerts'
    )

    # Status
    is_acknowledged = models.BooleanField(default=False)
    acknowledged_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='acknowledged_alerts'
    )
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    acknowledgement_notes = models.TextField(blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Designer Alert'
        verbose_name_plural = 'Designer Alerts'

    def __str__(self):
        ack = '✓' if self.is_acknowledged else '!'
        return f"[{ack}] [{self.level.upper()}] {self.title}"


class TestSchedule(models.Model):
    """
    Recurring test schedules for automated adversarial testing.
    """
    FREQUENCY_CHOICES = [
        ('hourly', 'Hourly'),
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)

    # Schedule configuration
    frequency = models.CharField(max_length=20, choices=FREQUENCY_CHOICES)
    is_active = models.BooleanField(default=True)
    last_run = models.DateTimeField(null=True, blank=True)
    next_run = models.DateTimeField(null=True, blank=True)

    # Test configuration
    test_config = models.JSONField(default=dict)
    attack_vectors = models.JSONField(default=list)
    target_components = models.JSONField(default=list)

    # Ownership
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True,
        related_name='test_schedules'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        verbose_name = 'Test Schedule'
        verbose_name_plural = 'Test Schedules'

    def __str__(self):
        status = '🟢' if self.is_active else '🔴'
        return f"{status} {self.name} ({self.frequency})"
