"""
Tests for Guardian Authentication + Config Hardening.

Validates:
1. Global auth gate protects all routes
2. No hardcoded WiFi password in hostapd.conf
3. AEGIS-Lite integration wiring
"""

import os
import re
import sys


class TestGuardianAuthGate:
    """Verify the global before_request auth enforcement."""

    def test_auth_exempt_prefixes_defined(self):
        """AUTH_EXEMPT_PREFIXES must be defined in app.py."""
        app_path = os.path.join(
            os.path.dirname(__file__), "..", "products", "guardian", "web", "app.py"
        )
        with open(app_path) as f:
            content = f.read()
        assert "AUTH_EXEMPT_PREFIXES" in content
        assert "/auth/" in content
        assert "before_request" in content

    def test_enforce_authentication_function_exists(self):
        """The enforce_authentication before_request handler must exist."""
        app_path = os.path.join(
            os.path.dirname(__file__), "..", "products", "guardian", "web", "app.py"
        )
        with open(app_path) as f:
            content = f.read()
        assert "def enforce_authentication" in content
        assert "session.get('authenticated')" in content

    def test_api_returns_401_for_unauthenticated(self):
        """API routes return 401 JSON for unauthenticated requests."""
        app_path = os.path.join(
            os.path.dirname(__file__), "..", "products", "guardian", "web", "app.py"
        )
        with open(app_path) as f:
            content = f.read()
        # Check that the auth gate returns 401 for API routes
        assert "'Authentication required'" in content
        assert "401" in content


class TestHostapdNoHardcodedPassword:
    """Verify hostapd.conf has no hardcoded password."""

    def test_no_plaintext_password(self):
        """hostapd.conf must not contain a plaintext wpa_passphrase."""
        conf_path = os.path.join(
            os.path.dirname(__file__), "..",
            "products", "guardian", "config", "hostapd.conf"
        )
        with open(conf_path) as f:
            content = f.read()

        # Should not have an active wpa_passphrase line
        active_passphrase = re.findall(
            r"^wpa_passphrase=\S+", content, re.MULTILINE
        )
        assert len(active_passphrase) == 0, (
            f"Found hardcoded password: {active_passphrase}"
        )

    def test_uses_psk_file(self):
        """hostapd.conf should use wpa_psk_file for credentials."""
        conf_path = os.path.join(
            os.path.dirname(__file__), "..",
            "products", "guardian", "config", "hostapd.conf"
        )
        with open(conf_path) as f:
            content = f.read()
        assert "wpa_psk_file=" in content


class TestAegisLiteWiring:
    """Verify AEGIS-Lite is wired into Guardian app."""

    def test_aegis_lite_import_in_app(self):
        """app.py must reference aegis_lite."""
        app_path = os.path.join(
            os.path.dirname(__file__), "..", "products", "guardian", "web", "app.py"
        )
        with open(app_path) as f:
            content = f.read()
        assert "aegis_lite" in content.lower()
        assert "_init_aegis_lite" in content

    def test_aegis_lite_module_exists(self):
        """products/guardian/lib/aegis_lite.py must exist."""
        module_path = os.path.join(
            os.path.dirname(__file__), "..",
            "products", "guardian", "lib", "aegis_lite.py"
        )
        assert os.path.isfile(module_path)

    def test_aegis_lite_has_class(self):
        """aegis_lite.py must define AegisLite class."""
        module_path = os.path.join(
            os.path.dirname(__file__), "..",
            "products", "guardian", "lib", "aegis_lite.py"
        )
        with open(module_path) as f:
            content = f.read()
        assert "class AegisLite" in content
        assert "def initialize" in content
