"""
Basic smoke tests for HookProbe Django application.

These tests ensure the application can start and basic functionality works.
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User


class SmokeTests(TestCase):
    """Basic smoke tests to ensure the application works."""

    def setUp(self):
        """Set up test fixtures."""
        self.client = Client()

    def test_imports(self):
        """Test that all apps can be imported."""
        try:
            from apps.cms import models as cms_models
            from apps.dashboard import models as dashboard_models
            from apps.devices import models as devices_models
            from apps.monitoring import models as monitoring_models
            from apps.security import models as security_models
            self.assertTrue(True, "All apps imported successfully")
        except ImportError as e:
            self.fail(f"Import failed: {e}")

    def test_authentication_backend_import(self):
        """Test that authentication backend can be imported."""
        try:
            from apps.dashboard.authentication import LogtoAuthenticationBackend
            backend = LogtoAuthenticationBackend()
            self.assertIsNotNone(backend)
            # Should not be configured in test environment
            self.assertFalse(backend.is_configured)
        except ImportError as e:
            self.fail(f"Authentication backend import failed: {e}")

    def test_admin_accessible(self):
        """Test that admin login page is accessible."""
        response = self.client.get('/admin/login/')
        self.assertEqual(response.status_code, 200)

    def test_health_check_endpoint(self):
        """Test that health check endpoint exists."""
        response = self.client.get('/dashboard/health/')
        # Should return 200 or 500 depending on services
        self.assertIn(response.status_code, [200, 500, 503])

    def test_user_creation(self):
        """Test that users can be created."""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.assertEqual(user.username, 'testuser')
        self.assertEqual(user.email, 'test@example.com')
        self.assertTrue(user.check_password('testpass123'))
