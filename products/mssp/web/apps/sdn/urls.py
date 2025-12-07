"""SDN URL configuration."""

from django.urls import path
from . import views

app_name = 'sdn'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('devices/', views.device_list, name='device_list'),
    path('devices/<uuid:device_id>/', views.device_edit, name='device_edit'),
    path('devices/<uuid:device_id>/delete/', views.device_delete, name='device_delete'),
    path('vlans/', views.vlan_list, name='vlan_list'),
    path('categories/', views.category_list, name='category_list'),
    path('guardian/', views.guardian_setup, name='guardian_setup_list'),
    path('guardian/<uuid:guardian_id>/', views.guardian_setup, name='guardian_setup'),
]
