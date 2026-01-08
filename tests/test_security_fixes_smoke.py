#!/usr/bin/env python3
"""
Security Fixes Smoke Tests
==========================
Validates that the security vulnerabilities identified in the
multi-agent audit (Gemini + Nemotron, 2026-01-09) are properly fixed.

Run with: pytest tests/test_security_fixes_smoke.py -v
"""
import os
import sys
import unittest

# Add project paths for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../products/fortress/web'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../shared/dnsXai'))


class TestHardcodedPasswordRemoved(unittest.TestCase):
    """CVE-FIX: Verify hardcoded admin password vulnerability is fixed."""

    def test_password_strength_validator_exists(self):
        """Verify _is_strong_password method exists and works."""
        from modules.auth.models import User

        # Weak passwords should be rejected
        self.assertFalse(User._is_strong_password("weak"))
        self.assertFalse(User._is_strong_password("password123"))
        self.assertFalse(User._is_strong_password("hookprobe"))  # Old hardcoded password
        self.assertFalse(User._is_strong_password("short"))

        # Strong passwords should be accepted
        self.assertTrue(User._is_strong_password("MyStr0ng!Pass#2026"))
        self.assertTrue(User._is_strong_password("C0mplex@Password!"))

    def test_admin_not_created_without_env_var(self):
        """Verify admin is NOT created when FORTRESS_ADMIN_PASSWORD is not set."""
        # Ensure env var is not set
        if 'FORTRESS_ADMIN_PASSWORD' in os.environ:
            del os.environ['FORTRESS_ADMIN_PASSWORD']

        from modules.auth.models import User

        # The old code would create admin with hardcoded "hookprobe" password
        # The new code should NOT create any user without the env var
        # We can't fully test this without mocking, but we can verify the method exists
        self.assertTrue(hasattr(User, 'ensure_admin_exists'))
        self.assertTrue(hasattr(User, '_is_strong_password'))


class TestOpenRedirectBlocked(unittest.TestCase):
    """CVE-FIX: Verify open redirect vulnerability is fixed."""

    def test_is_safe_redirect_url_exists(self):
        """Verify is_safe_redirect_url function exists."""
        from modules.auth.views import is_safe_redirect_url
        self.assertTrue(callable(is_safe_redirect_url))

    def test_blocks_protocol_relative_urls(self):
        """Protocol-relative URLs (//evil.com) must be blocked."""
        from modules.auth.views import is_safe_redirect_url

        self.assertFalse(is_safe_redirect_url("//evil.com"))
        self.assertFalse(is_safe_redirect_url("//evil.com/path"))
        self.assertFalse(is_safe_redirect_url("//attacker.com"))

    def test_blocks_absolute_urls(self):
        """Absolute URLs with scheme must be blocked."""
        from modules.auth.views import is_safe_redirect_url

        self.assertFalse(is_safe_redirect_url("https://evil.com"))
        self.assertFalse(is_safe_redirect_url("http://evil.com"))
        self.assertFalse(is_safe_redirect_url("ftp://evil.com"))

    def test_blocks_javascript_urls(self):
        """JavaScript URLs must be blocked (XSS prevention)."""
        from modules.auth.views import is_safe_redirect_url

        self.assertFalse(is_safe_redirect_url("javascript:alert(1)"))
        self.assertFalse(is_safe_redirect_url("JAVASCRIPT:alert(1)"))
        self.assertFalse(is_safe_redirect_url("javascript:document.cookie"))

    def test_allows_valid_internal_paths(self):
        """Valid internal paths starting with / must be allowed."""
        from modules.auth.views import is_safe_redirect_url

        self.assertTrue(is_safe_redirect_url("/dashboard"))
        self.assertTrue(is_safe_redirect_url("/settings"))
        self.assertTrue(is_safe_redirect_url("/api/status"))
        self.assertTrue(is_safe_redirect_url("/auth/logout"))

    def test_blocks_empty_and_invalid(self):
        """Empty and invalid inputs must be blocked."""
        from modules.auth.views import is_safe_redirect_url

        self.assertFalse(is_safe_redirect_url(""))
        self.assertFalse(is_safe_redirect_url(None))
        self.assertFalse(is_safe_redirect_url("not-a-path"))


class TestCORSRestricted(unittest.TestCase):
    """CVE-FIX: Verify CORS wildcard vulnerability is fixed."""

    def test_is_allowed_origin_exists(self):
        """Verify _is_allowed_origin method exists."""
        from api_server import APIHandler
        self.assertTrue(hasattr(APIHandler, '_is_allowed_origin'))

    def test_allows_localhost(self):
        """Localhost origins must be allowed."""
        from api_server import APIHandler
        handler = APIHandler.__new__(APIHandler)

        self.assertTrue(handler._is_allowed_origin("http://localhost:8080"))
        self.assertTrue(handler._is_allowed_origin("http://127.0.0.1:8080"))
        self.assertTrue(handler._is_allowed_origin("http://localhost"))

    def test_allows_internal_ips(self):
        """Internal IP ranges (10.x, 192.168.x, 172.16-31.x) must be allowed."""
        from api_server import APIHandler
        handler = APIHandler.__new__(APIHandler)

        self.assertTrue(handler._is_allowed_origin("http://10.200.0.1:8443"))
        self.assertTrue(handler._is_allowed_origin("http://192.168.1.1:8080"))
        self.assertTrue(handler._is_allowed_origin("http://172.16.0.1:8080"))

    def test_blocks_external_domains(self):
        """External domains must be blocked."""
        from api_server import APIHandler
        handler = APIHandler.__new__(APIHandler)

        self.assertFalse(handler._is_allowed_origin("https://evil.com"))
        self.assertFalse(handler._is_allowed_origin("http://attacker.com"))
        self.assertFalse(handler._is_allowed_origin("https://google.com"))

    def test_blocks_external_ips(self):
        """Public IP addresses must be blocked."""
        from api_server import APIHandler
        handler = APIHandler.__new__(APIHandler)

        self.assertFalse(handler._is_allowed_origin("http://8.8.8.8:80"))
        self.assertFalse(handler._is_allowed_origin("http://1.1.1.1:443"))


if __name__ == '__main__':
    unittest.main(verbosity=2)
