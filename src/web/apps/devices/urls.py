"""
Device Management URL Configuration
"""

from django.urls import path
from . import views

app_name = 'devices'

urlpatterns = [
    path('', views.device_list, name='list'),
    path('<str:device_id>/', views.device_detail, name='detail'),
    path('customers/', views.CustomerListView.as_view(), name='customer_list'),
    path('customers/<str:tenant_id>/', views.CustomerDetailView.as_view(), name='customer_detail'),
]
