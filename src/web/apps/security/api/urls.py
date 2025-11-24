"""
Security API URLs
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'events', views.SecurityEventViewSet)
router.register(r'qsecbit', views.QsecbitScoreViewSet)
router.register(r'kali', views.KaliResponseViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
