"""Self-tests of the g0 SPDX check (tools/ci/spdx_check.py, ADR 0067 D11)."""
import os
import tempfile
import unittest

import spdx_check as sc


def write(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(text)
    return p


class Spdx(unittest.TestCase):
    def test_identifier_is_read_from_the_first_three_lines_only(self):
        self.assertEqual(sc.identifier("// SPDX-License-Identifier: AGPL-3.0-only\nfn main() {}\n"), "AGPL-3.0-only")
        self.assertEqual(sc.identifier("//! doc\n//\n// SPDX-License-Identifier: MIT\n"), "MIT")
        self.assertIsNone(sc.identifier("a\nb\nc\n// SPDX-License-Identifier: AGPL-3.0-only\n"))

    def test_classify_separates_missing_from_foreign(self):
        with tempfile.TemporaryDirectory() as d:
            ok = write(d, "k/a.rs", sc.HEADER + "fn a() {}\n")
            none = write(d, "k/b.s", "// boot\n")
            gpl = write(d, "k/c.rs", "// SPDX-License-Identifier: GPL-2.0-only\n")
            self.assertEqual(sc.classify([ok, none, gpl]), ([none], [(gpl, "GPL-2.0-only")]))

    def test_source_files_skips_build_output_and_other_types(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "kernel/src/main.rs", "")
            write(d, "arch/boot.s", "")
            write(d, "target/debug/gen.rs", "")
            write(d, "kernel/notes.md", "")
            got = [os.path.relpath(p, d) for p in sc.source_files(d)]
            self.assertEqual(got, ["arch/boot.s", "kernel/src/main.rs"])


if __name__ == "__main__":
    unittest.main()
