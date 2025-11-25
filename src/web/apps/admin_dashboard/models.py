"""
Admin Dashboard Models
Models for AI-powered content generation and management.
"""

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class AIContentDraft(models.Model):
    """
    AI-generated content drafts for blog posts.
    """
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('review', 'Under Review'),
        ('approved', 'Approved'),
        ('published', 'Published'),
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

    # Publishing
    blog_post = models.ForeignKey('cms.BlogPost', on_delete=models.SET_NULL, null=True, blank=True, related_name='ai_draft')
    scheduled_publish_date = models.DateTimeField(null=True, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    published_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'AI Content Draft'
        verbose_name_plural = 'AI Content Drafts'

    def __str__(self):
        return f"{self.title} ({self.get_status_display()})"

    def approve(self, reviewer):
        """Approve the draft for publishing."""
        self.status = 'approved'
        self.reviewed_by = reviewer
        self.save()

    def publish_to_blog(self, user):
        """Convert draft to published blog post."""
        from apps.cms.models import BlogPost

        blog_post = BlogPost.objects.create(
            title=self.title,
            content=self.content,
            excerpt=self.summary,
            author=user,
            status='published',
            ai_generated=True,
        )

        self.blog_post = blog_post
        self.status = 'published'
        self.published_at = timezone.now()
        self.save()

        return blog_post


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
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)

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
