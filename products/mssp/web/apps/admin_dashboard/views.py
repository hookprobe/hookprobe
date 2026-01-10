"""
Admin Dashboard Views
AdminLTE-based interface for content and merchandise management.
"""

from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Q, Count, Sum
from django.utils import timezone
from datetime import timedelta
import json

from .models import AIContentDraft, ContentResearchTask, N8NWebhookLog
from apps.cms.models import BlogPost, BlogCategory
from apps.merchandise.models import Product, ProductCategory, Order


def is_staff(user):
    """Check if user is staff."""
    return user.is_staff


@login_required
@user_passes_test(is_staff)
def dashboard_home(request):
    """
    Admin dashboard homepage with overview statistics.
    """
    # Get counts
    blog_post_count = BlogPost.objects.filter(is_published=True).count()
    ai_drafts_pending = AIContentDraft.objects.filter(
        status__in=['draft', 'review']
    ).count()
    product_count = Product.objects.filter(active=True).count()
    pending_orders = Order.objects.filter(
        status__in=['pending', 'processing']
    ).count()

    # Recent AI drafts
    recent_ai_drafts = AIContentDraft.objects.all()[:5]

    # Recent orders
    recent_orders = Order.objects.all()[:5]

    # Low stock products
    low_stock_products = Product.objects.filter(
        track_inventory=True,
        stock_quantity__lte=5
    ).order_by('stock_quantity')[:10]

    # Active research tasks
    active_research_tasks = ContentResearchTask.objects.filter(
        status__in=['pending', 'in_progress']
    )[:5]

    context = {
        'blog_post_count': blog_post_count,
        'ai_drafts_pending': ai_drafts_pending,
        'product_count': product_count,
        'pending_orders': pending_orders,
        'recent_ai_drafts': recent_ai_drafts,
        'recent_orders': recent_orders,
        'low_stock_products': low_stock_products,
        'active_research_tasks': active_research_tasks,
        'pending_drafts_count': ai_drafts_pending,  # For navbar
    }

    return render(request, 'admin_dashboard/home.html', context)


@login_required
@user_passes_test(is_staff)
def ai_drafts_list(request):
    """
    List all AI content drafts with filtering.
    """
    status_filter = request.GET.get('status', '')
    provider_filter = request.GET.get('provider', '')

    drafts = AIContentDraft.objects.all()

    if status_filter:
        drafts = drafts.filter(status=status_filter)
    if provider_filter:
        drafts = drafts.filter(ai_provider=provider_filter)

    drafts = drafts.order_by('-created_at')

    context = {
        'drafts': drafts,
        'status_filter': status_filter,
        'provider_filter': provider_filter,
        'pending_drafts_count': AIContentDraft.objects.filter(
            status__in=['draft', 'review']
        ).count(),
    }

    return render(request, 'admin_dashboard/ai_drafts_list.html', context)


@login_required
@user_passes_test(is_staff)
def ai_draft_detail(request, draft_id):
    """
    View and edit an AI content draft.
    """
    draft = get_object_or_404(AIContentDraft, id=draft_id)

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'approve':
            draft.approve(request.user)
            messages.success(request, f'Draft "{draft.title}" approved.')
            return redirect('admin_dashboard:ai_drafts')

        elif action == 'publish':
            blog_post = draft.publish_to_blog(request.user)
            messages.success(request, f'Draft published as blog post: {blog_post.title}')
            return redirect('cms:post_detail', slug=blog_post.slug)

        elif action == 'reject':
            draft.status = 'rejected'
            draft.save()
            messages.warning(request, f'Draft "{draft.title}" rejected.')
            return redirect('admin_dashboard:ai_drafts')

    context = {
        'draft': draft,
        'pending_drafts_count': AIContentDraft.objects.filter(
            status__in=['draft', 'review']
        ).count(),
    }

    return render(request, 'admin_dashboard/ai_draft_detail.html', context)


@login_required
@user_passes_test(is_staff)
def ai_generate(request):
    """
    AI content generation interface.
    """
    if request.method == 'POST':
        # This will be handled by the AI service
        topic = request.POST.get('topic')
        keywords = request.POST.get('keywords')
        provider = request.POST.get('provider', 'anthropic')

        # TODO: Implement AI generation service
        messages.info(request, 'AI content generation will be implemented soon.')
        return redirect('admin_dashboard:ai_drafts')

    context = {
        'pending_drafts_count': AIContentDraft.objects.filter(
            status__in=['draft', 'review']
        ).count(),
    }

    return render(request, 'admin_dashboard/ai_generate.html', context)


@login_required
@user_passes_test(is_staff)
def research_tasks_list(request):
    """
    List all research tasks.
    """
    tasks = ContentResearchTask.objects.all().order_by('-created_at')

    context = {
        'tasks': tasks,
        'pending_drafts_count': AIContentDraft.objects.filter(
            status__in=['draft', 'review']
        ).count(),
    }

    return render(request, 'admin_dashboard/research_tasks.html', context)


@login_required
@user_passes_test(is_staff)
def products_list(request):
    """
    List all products with filtering and search.
    """
    category_filter = request.GET.get('category', '')
    search_query = request.GET.get('q', '')

    products = Product.objects.filter(active=True)

    if category_filter:
        products = products.filter(category_id=category_filter)
    if search_query:
        products = products.filter(
            Q(name__icontains=search_query) |
            Q(sku__icontains=search_query)
        )

    products = products.order_by('-created_at')
    categories = ProductCategory.objects.filter(active=True)

    context = {
        'products': products,
        'categories': categories,
        'category_filter': category_filter,
        'search_query': search_query,
        'pending_drafts_count': AIContentDraft.objects.filter(
            status__in=['draft', 'review']
        ).count(),
    }

    return render(request, 'admin_dashboard/products_list.html', context)


@login_required
@user_passes_test(is_staff)
def orders_list(request):
    """
    List all orders with filtering.
    """
    status_filter = request.GET.get('status', '')

    orders = Order.objects.all()

    if status_filter:
        orders = orders.filter(status=status_filter)

    orders = orders.order_by('-created_at')

    context = {
        'orders': orders,
        'status_filter': status_filter,
        'pending_drafts_count': AIContentDraft.objects.filter(
            status__in=['draft', 'review']
        ).count(),
    }

    return render(request, 'admin_dashboard/orders_list.html', context)


@login_required
@user_passes_test(is_staff)
def order_detail(request, order_id):
    """
    View order details.
    """
    order = get_object_or_404(Order, id=order_id)

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'mark_paid':
            order.mark_as_paid(transaction_id=f'MOCK-{order.order_number}')
            messages.success(request, f'Order {order.order_number} marked as paid.')

        elif action == 'mark_shipped':
            order.mark_as_shipped()
            messages.success(request, f'Order {order.order_number} marked as shipped.')

        elif action == 'mark_delivered':
            order.mark_as_delivered()
            messages.success(request, f'Order {order.order_number} marked as delivered.')

        elif action == 'cancel':
            order.cancel()
            messages.warning(request, f'Order {order.order_number} cancelled.')

        return redirect('admin_dashboard:order_detail', order_id=order.id)

    context = {
        'order': order,
        'pending_drafts_count': AIContentDraft.objects.filter(
            status__in=['draft', 'review']
        ).count(),
    }

    return render(request, 'admin_dashboard/order_detail.html', context)


@login_required
@user_passes_test(is_staff)
def categories_list(request):
    """
    List all product categories.
    """
    categories = ProductCategory.objects.all().order_by('order', 'name')

    context = {
        'categories': categories,
        'pending_drafts_count': AIContentDraft.objects.filter(
            status__in=['draft', 'review']
        ).count(),
    }

    return render(request, 'admin_dashboard/categories_list.html', context)


# ====================
# n8n Webhook API Endpoints
# ====================

@csrf_exempt
@require_http_methods(["POST"])
def n8n_webhook_create_draft(request):
    """
    n8n webhook endpoint to create a new AI draft.
    """
    try:
        data = json.loads(request.body)

        # Validate webhook secret
        webhook_secret = request.headers.get('X-Webhook-Secret')
        expected_secret = getattr(settings, 'N8N_WEBHOOK_SECRET', None)

        if expected_secret and webhook_secret != expected_secret:
            return JsonResponse({'error': 'Invalid webhook secret'}, status=403)

        # Create draft
        draft = AIContentDraft.objects.create(
            title=data.get('title'),
            content=data.get('content'),
            summary=data.get('summary', ''),
            ai_provider=data.get('ai_provider', 'manual'),
            ai_model=data.get('ai_model', ''),
            ai_confidence_score=data.get('ai_confidence_score'),
            research_sources=data.get('research_sources', []),
            seo_title=data.get('seo_title', ''),
            seo_description=data.get('seo_description', ''),
            seo_keywords=data.get('seo_keywords', ''),
            status='review',
            created_by=None  # n8n webhooks don't have a user
        )

        # Log webhook
        N8NWebhookLog.objects.create(
            webhook_type='create_draft',
            payload=data,
            response_status=200,
            response_data={'draft_id': draft.id},
            success=True,
            related_draft=draft
        )

        return JsonResponse({
            'success': True,
            'draft_id': draft.id,
            'message': 'Draft created successfully'
        })

    except Exception as e:
        # Log error
        N8NWebhookLog.objects.create(
            webhook_type='create_draft',
            payload=data if 'data' in locals() else {},
            response_status=500,
            response_data={},
            success=False,
            error_message=str(e)
        )

        return JsonResponse({
            'success': False,
            'error': 'An internal error occurred.'
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def n8n_webhook_publish_draft(request):
    """
    n8n webhook endpoint to publish an approved draft.
    """
    try:
        data = json.loads(request.body)

        # Validate webhook secret
        webhook_secret = request.headers.get('X-Webhook-Secret')
        expected_secret = getattr(settings, 'N8N_WEBHOOK_SECRET', None)

        if expected_secret and webhook_secret != expected_secret:
            return JsonResponse({'error': 'Invalid webhook secret'}, status=403)

        draft_id = data.get('draft_id')
        draft = AIContentDraft.objects.get(id=draft_id)

        if draft.status != 'approved':
            return JsonResponse({
                'success': False,
                'error': 'Draft must be approved before publishing'
            }, status=400)

        # Publish to blog
        blog_post = draft.publish_to_blog(user=None)

        # Log webhook
        N8NWebhookLog.objects.create(
            webhook_type='publish_draft',
            payload=data,
            response_status=200,
            response_data={'blog_post_id': blog_post.id},
            success=True,
            related_draft=draft
        )

        return JsonResponse({
            'success': True,
            'blog_post_id': blog_post.id,
            'blog_post_slug': blog_post.slug,
            'message': 'Draft published successfully'
        })

    except Exception as e:
        # Log error
        N8NWebhookLog.objects.create(
            webhook_type='publish_draft',
            payload=data if 'data' in locals() else {},
            response_status=500,
            response_data={},
            success=False,
            error_message=str(e)
        )

        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def n8n_webhook_research(request):
    """
    n8n webhook endpoint to create a research task.
    """
    try:
        data = json.loads(request.body)

        # Validate webhook secret
        webhook_secret = request.headers.get('X-Webhook-Secret')
        expected_secret = getattr(settings, 'N8N_WEBHOOK_SECRET', None)

        if expected_secret and webhook_secret != expected_secret:
            return JsonResponse({'error': 'Invalid webhook secret'}, status=403)

        # Create research task
        task = ContentResearchTask.objects.create(
            topic=data.get('topic'),
            description=data.get('description', ''),
            keywords=data.get('keywords', ''),
            max_sources=data.get('max_sources', 10),
            include_cve=data.get('include_cve', False),
            include_news=data.get('include_news', True),
            include_blogs=data.get('include_blogs', True),
            research_data=data.get('research_data', {}),
            sources_found=data.get('sources_found', 0),
            status='completed' if data.get('research_data') else 'pending',
            created_by=None
        )

        # Log webhook
        N8NWebhookLog.objects.create(
            webhook_type='research',
            payload=data,
            response_status=200,
            response_data={'task_id': task.id},
            success=True,
            related_research=task
        )

        return JsonResponse({
            'success': True,
            'task_id': task.id,
            'message': 'Research task created successfully'
        })

    except Exception as e:
        # Log error
        N8NWebhookLog.objects.create(
            webhook_type='research',
            payload=data if 'data' in locals() else {},
            response_status=500,
            response_data={},
            success=False,
            error_message=str(e)
        )

        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)
