"""
Admin Dashboard URL Configuration
"""

from django.urls import path
from . import views

app_name = 'admin_dashboard'

urlpatterns = [
    # Dashboard home
    path('', views.dashboard_home, name='home'),

    # AI Content Management
    path('ai/drafts/', views.ai_drafts_list, name='ai_drafts'),
    path('ai/drafts/<int:draft_id>/', views.ai_draft_detail, name='ai_draft_detail'),
    path('ai/generate/', views.ai_generate, name='ai_generate'),
    path('ai/research/', views.research_tasks_list, name='research_tasks'),

    # Merchandise Management
    path('products/', views.products_list, name='products'),
    path('orders/', views.orders_list, name='orders'),
    path('orders/<int:order_id>/', views.order_detail, name='order_detail'),
    path('categories/', views.categories_list, name='categories'),

    # n8n Webhook API Endpoints
    path('api/n8n/create-draft/', views.n8n_webhook_create_draft, name='n8n_create_draft'),
    path('api/n8n/publish-draft/', views.n8n_webhook_publish_draft, name='n8n_publish_draft'),
    path('api/n8n/research/', views.n8n_webhook_research, name='n8n_research'),
]
