"""Self-tests of the g0 driver-provenance check (tools/ci/provenance_check.py, ADR 0067 D11)."""
import os
import tempfile
import unittest

import provenance_check as pc


class Provenance(unittest.TestCase):
    def test_missing_lists_only_files_without_a_backticked_row(self):
        files = ["arch-aarch64/src/gem.rs", "hboot/src/rng.rs"]
        text = "| `arch-aarch64/src/gem.rs` | WAN NIC | ... |\nhboot/src/rng.rs without backticks\n"
        self.assertEqual(pc.missing(files, text), ["hboot/src/rng.rs"])

    def test_a_longer_path_does_not_satisfy_a_shorter_one(self):
        self.assertEqual(pc.missing(["arch-aarch64/src/rp1.rs"], "`arch-aarch64/src/rp1_gpio.rs`"), ["arch-aarch64/src/rp1.rs"])

    def test_driver_files_walks_both_directories_and_only_rust(self):
        with tempfile.TemporaryDirectory() as d:
            for rel in ("arch-aarch64/src/a.rs", "arch-aarch64/src/boot.s", "hboot/src/sub/b.rs", "kernel/src/c.rs"):
                p = os.path.join(d, rel)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                open(p, "w").close()
            self.assertEqual(pc.driver_files(d), ["arch-aarch64/src/a.rs", "hboot/src/sub/b.rs"])


if __name__ == "__main__":
    unittest.main()
