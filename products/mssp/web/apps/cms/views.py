"""
CMS Views - Public-facing pages with Forty theme
"""

from django.shortcuts import render, get_object_or_404, redirect
from django.views.generic import ListView, DetailView, FormView
from django.contrib import messages
from django.urls import reverse_lazy
from django.db.models import Q
from .models import Page, BlogPost, BlogCategory, ContactSubmission
from .forms import ContactForm


def home(request):
    """Homepage view"""
    featured_posts = BlogPost.objects.filter(
        is_published=True,
        is_featured=True
    )[:3]

    latest_posts = BlogPost.objects.filter(
        is_published=True
    )[:6]

    context = {
        'featured_posts': featured_posts,
        'latest_posts': latest_posts,
    }
    return render(request, 'public/home.html', context)


def about(request):
    """About page view"""
    return render(request, 'public/about.html')


def merchandise(request):
    """Merchandise page view"""
    return render(request, 'public/merchandise.html')


class BlogListView(ListView):
    """Blog post list view"""
    model = BlogPost
    template_name = 'public/blog/list.html'
    context_object_name = 'posts'
    paginate_by = 12

    def get_queryset(self):
        queryset = BlogPost.objects.filter(is_published=True)

        # Search functionality
        query = self.request.GET.get('q')
        if query:
            queryset = queryset.filter(
                Q(title__icontains=query) |
                Q(content__icontains=query) |
                Q(excerpt__icontains=query)
            )

        # Category filter
        category = self.request.GET.get('category')
        if category:
            queryset = queryset.filter(category__slug=category)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Featured post
        context['featured_post'] = BlogPost.objects.filter(
            is_published=True,
            is_featured=True
        ).first()

        # Popular posts
        context['popular_posts'] = BlogPost.objects.filter(
            is_published=True
        ).order_by('-views')[:5]

        return context


class BlogDetailView(DetailView):
    """Blog post detail view"""
    model = BlogPost
    template_name = 'public/blog/detail.html'
    context_object_name = 'post'

    def get_queryset(self):
        return BlogPost.objects.filter(is_published=True)

    def get_object(self, queryset=None):
        obj = super().get_object(queryset)
        # Increment view count
        obj.views += 1
        obj.save(update_fields=['views'])
        return obj

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Related posts (same category, excluding current)
        context['related_posts'] = BlogPost.objects.filter(
            is_published=True
        ).exclude(id=self.object.id)[:3]

        return context


class ContactFormView(FormView):
    """Contact form view"""
    template_name = 'public/contact.html'
    form_class = ContactForm
    success_url = reverse_lazy('cms:contact')

    def form_valid(self, form):
        # Save the contact submission
        submission = form.save(commit=False)
        submission.ip_address = self.get_client_ip()
        submission.save()

        messages.success(
            self.request,
            'Thank you for your message. We will get back to you soon!'
        )
        return super().form_valid(form)

    def get_client_ip(self):
        """Get client IP address"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip


def page_detail(request, slug):
    """Generic page detail view"""
    page = get_object_or_404(Page, slug=slug, is_published=True)
    return render(request, 'public/page.html', {'page': page})


def newsletter_signup(request):
    """Newsletter signup handler"""
    if request.method == 'POST':
        name = request.POST.get('name', '')
        email = request.POST.get('email')
        gdpr_consent = request.POST.get('gdpr_consent')
        marketing_consent = request.POST.get('marketing_consent', False)

        if email and gdpr_consent:
            # TODO: Save to newsletter database model
            messages.success(request, 'Thank you for subscribing! Check your email to confirm.')
        else:
            messages.error(request, 'Please provide your email and consent to GDPR policy.')

        # Redirect back to referring page or home
        return redirect(request.META.get('HTTP_REFERER', '/'))

    return redirect('cms:home')


def privacy_policy(request):
    """Privacy policy page"""
    return render(request, 'public/privacy_policy.html')


def terms_of_service(request):
    """Terms of service page"""
    return render(request, 'public/terms_of_service.html')


def gdpr(request):
    """GDPR compliance page"""
    return render(request, 'public/gdpr.html')


# Error handlers
def error_404(request, exception=None):
    """Custom 404 error handler"""
    return render(request, 'base/errors/404.html', status=404)


def error_500(request):
    """Custom 500 error handler"""
    return render(request, 'base/errors/500.html', status=500)


def error_403(request, exception=None):
    """Custom 403 error handler"""
    return render(request, 'base/errors/403.html', status=403)
