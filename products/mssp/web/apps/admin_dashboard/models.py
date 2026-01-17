"""
Admin Dashboard Models
Models for AI-powered content generation and management.

NOTE: Blog publishing has been moved to hookprobe.com.
Content drafts are managed here and can be exported via API to hookprobe.com.
"""

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class AIContentDraft(models.Model):
    """
    AI-generated content drafts for blog posts.

    NOTE: Publishing to blog now requires hookprobe.com API integration.
    """
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('review', 'Under Review'),
        ('approved', 'Approved'),
        ('exported', 'Exported to hookprobe.com'),
        ('rejected', 'Rejected'),
    ]

    title = models.CharField(max_length=300)
    content = models.TextField()
    summary = models.TextField(blank=True)

    # AI metadata
    ai_provider = models.CharField(max_length=50, choices=[
        ('openai', 'OpenAI'),
        ('anthropic', 'Anthropic'),
        ('manual', 'Manual'),
    ])
    ai_model = models.CharField(max_length=100, blank=True)
    ai_confidence_score = models.FloatField(null=True, blank=True, help_text="AI confidence score (0-1)")
    ai_prompt = models.TextField(blank=True, help_text="Prompt used for generation")

    # SEO fields
    seo_title = models.CharField(max_length=200, blank=True)
    seo_description = models.TextField(max_length=300, blank=True)
    seo_keywords = models.CharField(max_length=500, blank=True)
    seo_score = models.IntegerField(default=0, help_text="SEO score (0-100)")

    # Research sources
    research_sources = models.JSONField(default=list, help_text="List of URLs used for research")
    research_summary = models.TextField(blank=True)

    # Status and workflow
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='ai_drafts_created')
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='ai_drafts_reviewed')

    # External reference (when exported to hookprobe.com)
    external_blog_id = models.IntegerField(null=True, blank=True, help_text="Blog post ID on hookprobe.com")
    external_blog_url = models.URLField(blank=True, help_text="URL of published post on hookprobe.com")

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    exported_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'AI Content Draft'
        verbose_name_plural = 'AI Content Drafts'

    def __str__(self):
        return f"{self.title} ({self.get_status_display()})"

    def approve(self, reviewer):
        """Approve the draft for exporting."""
        self.status = 'approved'
        self.reviewed_by = reviewer
        self.save()

    def mark_exported(self, blog_id, blog_url):
        """Mark the draft as exported to hookprobe.com."""
        self.status = 'exported'
        self.external_blog_id = blog_id
        self.external_blog_url = blog_url
        self.exported_at = timezone.now()
        self.save()

    def to_export_dict(self):
        """Return dict for exporting to hookprobe.com API."""
        return {
            'title': self.title,
            'content': self.content,
            'excerpt': self.summary,
            'seo_title': self.seo_title,
            'seo_description': self.seo_description,
            'seo_keywords': self.seo_keywords,
            'ai_generated': True,
            'source_draft_id': self.id,
        }


class ContentResearchTask(models.Model):
    """
    Research tasks for AI content generation.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    topic = models.CharField(max_length=300)
    description = models.TextField()
    keywords = models.CharField(max_length=500, blank=True)

    # Research parameters
    max_sources = models.IntegerField(default=10)
    include_cve = models.BooleanField(default=False, help_text="Include CVE database search")
    include_news = models.BooleanField(default=True, help_text="Include security news")
    include_blogs = models.BooleanField(default=True, help_text="Include security blogs")

    # Results
    research_data = models.JSONField(default=dict, help_text="Collected research data")
    sources_found = models.IntegerField(default=0)

    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)

    # Related draft (if generated)
    generated_draft = models.ForeignKey(AIContentDraft, on_delete=models.SET_NULL, null=True, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Content Research Task'
        verbose_name_plural = 'Content Research Tasks'

    def __str__(self):
        return f"{self.topic} ({self.get_status_display()})"


class N8NWebhookLog(models.Model):
    """
    Log of n8n webhook calls for auditing and debugging.
    """
    webhook_type = models.CharField(max_length=100)
    payload = models.JSONField(default=dict)
    response_status = models.IntegerField()
    response_data = models.JSONField(default=dict)

    # Error handling
    success = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)

    # Related objects
    related_draft = models.ForeignKey(AIContentDraft, on_delete=models.SET_NULL, null=True, blank=True)
    related_research = models.ForeignKey(ContentResearchTask, on_delete=models.SET_NULL, null=True, blank=True)

    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'n8n Webhook Log'
        verbose_name_plural = 'n8n Webhook Logs'

    def __str__(self):
        return f"{self.webhook_type} - {self.timestamp} ({'success' if self.success else 'failed'})"
