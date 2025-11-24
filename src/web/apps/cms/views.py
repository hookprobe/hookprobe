"""
CMS Views - Public-facing pages with Forty theme
"""

from django.shortcuts import render, get_object_or_404
from django.views.generic import ListView, DetailView, FormView
from django.contrib import messages
from django.urls import reverse_lazy
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


class BlogListView(ListView):
    """Blog post list view"""
    model = BlogPost
    template_name = 'public/blog/list.html'
    context_object_name = 'posts'
    paginate_by = 12

    def get_queryset(self):
        return BlogPost.objects.filter(is_published=True)


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
