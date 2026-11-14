"""Self-tests for tools/ci/release_check.py (run by gate g0: CI tooling self-tests)."""
import json
import os
import tempfile
import unittest

import release_check as rc

RELEASE_RS = '''pub const PRODUCT: &str = "HookProbe OS";
pub const VERSION: &str = "0.0-26";
pub const CODENAME: &str = "Zamolxis";
pub const SEMVER: &str = "0.0.26";
'''


def write(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(text)


class ReleaseCheck(unittest.TestCase):
    def tree(self, crate_version="0.0.26", lock_version="0.0.26", pkg_version="0.0.26", note=True):
        d = tempfile.mkdtemp()
        write(d, "os/kernel/hal/src/release.rs", RELEASE_RS)
        write(d, "os/kernel/hal/Cargo.toml", f'[package]\nname = "hal"\nversion = "{crate_version}"\n\n[dependencies]\nx = {{ version = "1.0" }}\n')
        write(d, "os/kernel/Cargo.lock",
              f'version = 4\n\n[[package]]\nname = "hal"\nversion = "{lock_version}"\n\n'
              '[[package]]\nname = "serde"\nversion = "1.0.200"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n')
        write(d, "os/mission-control/package.json", json.dumps({"name": "mc", "version": pkg_version}))
        write(d, "legacy/v1/sdk/package.json", json.dumps({"name": "old", "version": "9.9.9"}))
        if note:
            write(d, "docs/releases/v0.0-26.md", "# note\n")
        return d

    def test_aligned_tree_passes(self):
        ident, problems = rc.check(self.tree())
        self.assertEqual(ident, ("0.0-26", "Zamolxis", "0.0.26"))
        self.assertEqual(problems, [])

    def test_crate_drift_fails(self):
        _, problems = rc.check(self.tree(crate_version="0.1.0"))
        self.assertTrue(any("Cargo.toml" in p for p in problems))

    def test_lock_drift_fails_but_registry_crates_ignored(self):
        _, problems = rc.check(self.tree(lock_version="0.1.0"))
        self.assertEqual(len([p for p in problems if "Cargo.lock" in p]), 1)

    def test_package_json_drift_fails_and_legacy_ignored(self):
        _, problems = rc.check(self.tree(pkg_version="0.1.0"))
        self.assertEqual([p for p in problems if "package.json" in p], ["os/mission-control/package.json: version 0.1.0 != 0.0.26"])

    def test_missing_release_note_fails(self):
        _, problems = rc.check(self.tree(note=False))
        self.assertTrue(any("release note missing" in p for p in problems))


if __name__ == "__main__":
    unittest.main()
