"""
Admin Dashboard Admin Interface
"""

from django.contrib import admin
from django.utils.html import format_html
from .models import AIContentDraft, ContentResearchTask, N8NWebhookLog


@admin.register(AIContentDraft)
class AIContentDraftAdmin(admin.ModelAdmin):
    """Admin interface for AI content drafts."""
    list_display = [
        'title',
        'status_display',
        'ai_provider_display',
        'confidence_display',
        'seo_score_display',
        'created_by',
        'created_at'
    ]
    list_filter = ['status', 'ai_provider', 'created_at']
    search_fields = ['title', 'content', 'summary']
    readonly_fields = ['created_at', 'updated_at', 'published_at']
    filter_horizontal = []

    fieldsets = (
        ('Content', {
            'fields': ('title', 'summary', 'content')
        }),
        ('AI Metadata', {
            'fields': ('ai_provider', 'ai_model', 'ai_confidence_score', 'ai_prompt'),
            'classes': ('collapse',)
        }),
        ('SEO', {
            'fields': ('seo_title', 'seo_description', 'seo_keywords', 'seo_score'),
            'classes': ('collapse',)
        }),
        ('Research', {
            'fields': ('research_sources', 'research_summary'),
            'classes': ('collapse',)
        }),
        ('Workflow', {
            'fields': ('status', 'created_by', 'reviewed_by', 'scheduled_publish_date')
        }),
        ('Publishing', {
            'fields': ('blog_post', 'created_at', 'updated_at', 'published_at'),
            'classes': ('collapse',)
        }),
    )

    def status_display(self, obj):
        """Display status with color coding."""
        colors = {
            'draft': '#95a5a6',
            'review': '#f39c12',
            'approved': '#3498db',
            'published': '#27ae60',
            'rejected': '#e74c3c',
        }
        color = colors.get(obj.status, '#000')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display()
        )
    status_display.short_description = 'Status'

    def ai_provider_display(self, obj):
        """Display AI provider with icon."""
        icons = {
            'openai': '🤖',
            'anthropic': '🔮',
            'manual': '✏️',
        }
        icon = icons.get(obj.ai_provider, '')
        return f'{icon} {obj.get_ai_provider_display()}'
    ai_provider_display.short_description = 'AI Provider'

    def confidence_display(self, obj):
        """Display confidence score as percentage."""
        if obj.ai_confidence_score is not None:
            percentage = int(obj.ai_confidence_score * 100)
            if percentage >= 90:
                color = '#27ae60'
            elif percentage >= 70:
                color = '#f39c12'
            else:
                color = '#e74c3c'
            return format_html(
                '<span style="color: {};">{}%</span>',
                color,
                percentage
            )
        return '-'
    confidence_display.short_description = 'Confidence'

    def seo_score_display(self, obj):
        """Display SEO score with color coding."""
        if obj.seo_score >= 80:
            color = '#27ae60'
        elif obj.seo_score >= 60:
            color = '#f39c12'
        else:
            color = '#e74c3c'
        return format_html(
            '<span style="color: {};"><strong>{}</strong>/100</span>',
            color,
            obj.seo_score
        )
    seo_score_display.short_description = 'SEO Score'

    actions = ['approve_drafts', 'publish_to_blog']

    def approve_drafts(self, request, queryset):
        """Approve selected drafts."""
        for draft in queryset.filter(status='review'):
            draft.approve(request.user)
        self.message_user(request, f'{queryset.count()} drafts approved.')
    approve_drafts.short_description = 'Approve selected drafts'

    def publish_to_blog(self, request, queryset):
        """Publish approved drafts to blog."""
        published = 0
        for draft in queryset.filter(status='approved'):
            draft.publish_to_blog(request.user)
            published += 1
        self.message_user(request, f'{published} drafts published to blog.')
    publish_to_blog.short_description = 'Publish to blog'


@admin.register(ContentResearchTask)
class ContentResearchTaskAdmin(admin.ModelAdmin):
    """Admin interface for research tasks."""
    list_display = [
        'topic',
        'status_display',
        'sources_found',
        'created_by',
        'created_at',
        'completed_at'
    ]
    list_filter = ['status', 'include_cve', 'include_news', 'include_blogs', 'created_at']
    search_fields = ['topic', 'description', 'keywords']
    readonly_fields = ['created_at', 'completed_at', 'sources_found']

    fieldsets = (
        ('Task Information', {
            'fields': ('topic', 'description', 'keywords')
        }),
        ('Research Parameters', {
            'fields': ('max_sources', 'include_cve', 'include_news', 'include_blogs')
        }),
        ('Results', {
            'fields': ('research_data', 'sources_found', 'generated_draft'),
            'classes': ('collapse',)
        }),
        ('Status', {
            'fields': ('status', 'created_by', 'created_at', 'completed_at')
        }),
    )

    def status_display(self, obj):
        """Display status with color coding."""
        colors = {
            'pending': '#95a5a6',
            'in_progress': '#3498db',
            'completed': '#27ae60',
            'failed': '#e74c3c',
        }
        color = colors.get(obj.status, '#000')
        return format_html(
            '<span style="color: {};">{}</span>',
            color,
            obj.get_status_display()
        )
    status_display.short_description = 'Status'


@admin.register(N8NWebhookLog)
class N8NWebhookLogAdmin(admin.ModelAdmin):
    """Admin interface for n8n webhook logs."""
    list_display = [
        'webhook_type',
        'success_display',
        'response_status',
        'timestamp'
    ]
    list_filter = ['success', 'webhook_type', 'timestamp']
    search_fields = ['webhook_type', 'error_message']
    readonly_fields = ['timestamp']

    fieldsets = (
        ('Webhook Information', {
            'fields': ('webhook_type', 'payload', 'response_status', 'response_data')
        }),
        ('Status', {
            'fields': ('success', 'error_message')
        }),
        ('Related Objects', {
            'fields': ('related_draft', 'related_research'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('timestamp',)
        }),
    )

    def success_display(self, obj):
        """Display success status with icon."""
        if obj.success:
            return format_html('<span style="color: #27ae60;"> Success</span>')
        return format_html('<span style="color: #e74c3c;">✗ Failed</span>')
    success_display.short_description = 'Status'

    def has_add_permission(self, request):
        """Webhook logs are created automatically."""
        return False
