"""Pytest path bootstrap for the HookProbe engine test suite.

The engines are COPY'd flat into their container workdirs (/app) at build time,
so at runtime a module does e.g. `from hydra.trusted_networks import ...` with
`core/` on the path, or a bare `from trusted_networks import ...` with the
module's own dir on the path. Bare `pytest` from the repo root has neither, so
unit tests that import an engine failed with `No module named 'hydra'` /
"attempted relative import" — a HARNESS gap, not a code defect (the modules run
fine live). This conftest reproduces the runtime import surface so the
no-service unit tests can actually run + gate in CI.
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Order matters: repo root first (so `core.*`/`shared.*` package imports work),
# then the per-engine dirs (so flat `from <sibling> import ...` works), then
# `core/` (so `from hydra.* import ...` / `from cno.* import ...` resolve).
_PATHS = [
    _ROOT,
    os.path.join(_ROOT, "core"),
    os.path.join(_ROOT, "core", "hydra"),
    os.path.join(_ROOT, "core", "cno"),
    os.path.join(_ROOT, "core", "napse"),
    os.path.join(_ROOT, "shared"),
]
for _p in _PATHS:
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

import pytest  # noqa: E402

# Tests that need live services (ClickHouse, running containers, cross-tier
# wiring) or a separate product's runtime (fortress Flask web app + its data
# dir). These can't pass in a bare unit run; they belong to a separate
# integration lane with a service harness. Marked centrally here so the unit
# gate (`pytest -m "not integration and not product"`) stays green + meaningful
# without scattering markers across files. Triage to un-mark as harnesses land.
_INTEGRATION_FILES = {
    "test_cross_tier_integration",
    "test_e2e_integration",
    "test_mssp_connectivity",
    "test_aegis_full",
    "test_guardian_offline_mode",
}
_PRODUCT_FILES = {
    "test_security_fixes_smoke",  # products/fortress/web Flask app (needs flask)
}


def pytest_collection_modifyitems(config, items):
    for item in items:
        stem = os.path.splitext(os.path.basename(str(item.fspath)))[0]
        if stem in _INTEGRATION_FILES:
            item.add_marker(pytest.mark.integration)
        elif stem in _PRODUCT_FILES:
            item.add_marker(pytest.mark.product)
