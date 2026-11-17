#!/usr/bin/env python3
"""tools/ci/npm_audit_gate.py — high+ npm advisories fail unless a reviewed, unexpired, unpatched exception covers them."""
import datetime
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import npm_audit_gate as g  # noqa: E402

AUDIT = {"vulnerabilities": {
    "picomatch": {"via": [{"source": 1, "name": "picomatch", "severity": "high", "title": "ReDoS",
                           "url": "https://github.com/advisories/GHSA-fc5q-39xc-vjpf"}]},
    "vite": {"via": ["picomatch", "tinyglobby"]},                       # a dependent: not a root cause
    "low-thing": {"via": [{"source": 2, "name": "low-thing", "severity": "moderate", "title": "meh",
                           "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"}]},
}}
D = datetime.date(2026, 11, 17)
EX = {"GHSA-fc5q-39xc-vjpf": {"package": "picomatch", "expires": datetime.date(2026, 12, 17), "reason": "build-time only"}}


class Gate(unittest.TestCase):
    def test_roots_only_high_plus(self):
        self.assertEqual(set(g.root_advisories(AUDIT)), {"GHSA-fc5q-39xc-vjpf"})

    def test_unlisted_advisory_fails(self):
        f, a = g.decide(g.root_advisories(AUDIT), {}, D, patched=lambda _: None)
        self.assertEqual((len(f), a), (1, []))

    def test_listed_unpatched_unexpired_is_accepted(self):
        f, a = g.decide(g.root_advisories(AUDIT), EX, D, patched=lambda _: None)
        self.assertEqual((f, len(a)), ([], 1))

    def test_expired_exception_fails(self):
        f, _ = g.decide(g.root_advisories(AUDIT), EX, datetime.date(2026, 12, 18), patched=lambda _: None)
        self.assertIn("EXPIRED", f[0])

    def test_patch_published_fails(self):
        f, _ = g.decide(g.root_advisories(AUDIT), EX, D, patched=lambda _: "4.0.8")
        self.assertIn("patched release exists", f[0])

    def test_lookup_failure_keeps_exception_until_expiry(self):
        f, a = g.decide(g.root_advisories(AUDIT), EX, D, patched=lambda _: "unknown")
        self.assertEqual(f, [])
        self.assertIn("not checked", a[0])

    def test_exceptions_file_format(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# c\nGHSA-fc5q-39xc-vjpf | picomatch | 2026-12-17 | why\n")
        self.assertEqual(g.load_exceptions(fh.name)["GHSA-fc5q-39xc-vjpf"]["package"], "picomatch")
        with open(fh.name, "w") as w:
            w.write("GHSA-fc5q-39xc-vjpf | picomatch | 2026-12-17\n")      # no reason
        with self.assertRaises(ValueError):
            g.load_exceptions(fh.name)
        os.unlink(fh.name)

    def test_real_exceptions_file_parses(self):
        ex = g.load_exceptions()
        for k, v in ex.items():
            self.assertTrue(v["reason"])


if __name__ == "__main__":
    unittest.main()
