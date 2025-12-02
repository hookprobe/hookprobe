"""
Merchandise URL Configuration
"""

from django.urls import path
from . import views

app_name = 'merchandise'

urlpatterns = [
    # Merchandise store views will be added here
    # path('', views.store, name='store'),
    # path('product/<int:pk>/', views.product_detail, name='product_detail'),
    # path('cart/', views.cart, name='cart'),
    # path('checkout/', views.checkout, name='checkout'),
]
