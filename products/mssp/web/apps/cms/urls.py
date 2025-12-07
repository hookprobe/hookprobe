"""
CMS URL Configuration
"""

from django.urls import path
from . import views

app_name = 'cms'

urlpatterns = [
    path('', views.home, name='home'),
    path('about/', views.about, name='about'),
    path('merchandise/', views.merchandise, name='merchandise'),
    path('contact/', views.ContactFormView.as_view(), name='contact'),
    path('blog/', views.BlogListView.as_view(), name='blog_list'),
    path('blog/<slug:slug>/', views.BlogDetailView.as_view(), name='blog_detail'),
    path('page/<slug:slug>/', views.page_detail, name='page_detail'),

    # Newsletter signup
    path('newsletter/signup/', views.newsletter_signup, name='newsletter_signup'),

    # Legal pages
    path('privacy/', views.privacy_policy, name='privacy_policy'),
    path('terms/', views.terms_of_service, name='terms_of_service'),
    path('gdpr/', views.gdpr, name='gdpr'),
]
