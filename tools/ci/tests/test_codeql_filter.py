#!/usr/bin/env python3
"""tools/ci/codeql_test_filter.py — which CodeQL results count as Rust test code."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import codeql_test_filter as f  # noqa: E402

SRC = r'''pub fn production() -> [u8; 4] {
    let s = "}{ not a brace";         // a } in a comment
    let c = '{';
    let r = r#"raw } string"#;
    let b = b"}";
    [1, 2, 3, 4]
}

pub fn wpa_selftest<'a>(x: &'a [u8]) -> bool {
    let pw = b"correct horse battery";
    x.len() == pw.len()
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    fn helper() -> u8 { 7 }
    #[test]
    fn t() {
        let key = [0x42u8; 32];
        assert_eq!(helper(), 7);
    }
}

pub fn after() -> u8 {
    let k = [9u8; 16];
    k[0]
}
'''


def line_of(text):
    return SRC.split("\n").index(next(l for l in SRC.split("\n") if text in l)) + 1


class Ranges(unittest.TestCase):
    def setUp(self):
        self.r = f.test_ranges(SRC)

    def kind_at(self, text):
        n = line_of(text)
        return {k for a, b, k in self.r if a <= n <= b}

    def test_cfg_all_test_module_is_test(self):
        self.assertIn("test", self.kind_at("let key = [0x42u8; 32];"))
        self.assertIn("test", self.kind_at("fn helper()"))

    def test_selftest_fn_is_selftest_not_test(self):
        self.assertEqual(self.kind_at("correct horse battery"), {"selftest"})

    def test_production_code_is_not_test(self):
        # braces inside strings, comments, raw / byte strings and char literals must not end a block early
        self.assertEqual(self.kind_at("[1, 2, 3, 4]"), set())
        self.assertEqual(self.kind_at("let k = [9u8; 16];"), set())


def sarif(results):
    return {"runs": [{"results": [
        {"ruleId": rule, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/x.rs"}, "region": {"startLine": n}}}]}
        for rule, n in results]}]}


class Filter(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.root, "src"))
        with open(os.path.join(self.root, "src/x.rs"), "w") as fh:
            fh.write(SRC)

    def run_filter(self, results):
        doc = sarif(results)
        n = f.filter_sarif(doc, self.root, log=lambda *_: None)
        return n, [(r["ruleId"], r["locations"][0]["physicalLocation"]["region"]["startLine"]) for r in doc["runs"][0]["results"]]

    def test_test_module_dropped_for_every_rule(self):
        n, kept = self.run_filter([(f.CRYPTO_RULE, line_of("0x42u8")), ("rust/uncontrolled-allocation", line_of("0x42u8"))])
        self.assertEqual((n, kept), (2, []))

    def test_selftest_dropped_only_for_the_crypto_rule(self):
        ln = line_of("correct horse battery")
        n, kept = self.run_filter([(f.CRYPTO_RULE, ln), ("rust/access-invalid-pointer", ln)])
        self.assertEqual(n, 1)
        self.assertEqual(kept, [("rust/access-invalid-pointer", ln)])

    def test_production_results_kept(self):
        res = [(f.CRYPTO_RULE, line_of("let k = [9u8; 16];")), (f.CRYPTO_RULE, line_of("[1, 2, 3, 4]"))]
        n, kept = self.run_filter(res)
        self.assertEqual((n, kept), (0, res))

    def test_non_rust_and_missing_files_kept(self):
        doc = {"runs": [{"results": [
            {"ruleId": "py/x", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}]},
            {"ruleId": f.CRYPTO_RULE, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "gone.rs"}, "region": {"startLine": 1}}}]}]}]}
        self.assertEqual(f.filter_sarif(doc, self.root, log=lambda *_: None), 0)
        self.assertEqual(len(doc["runs"][0]["results"]), 2)


class TestOnlyFiles(unittest.TestCase):
    """A file whose `mod` declaration is under #[cfg(test)] is test code as a whole (#1370 / #1371: evidence-export's
    `#[cfg(test)] mod testutil;`), while a sibling declared without it is production code (#1369: anon.rs)."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        src = os.path.join(self.root, "src")
        os.makedirs(os.path.join(src, "helpers"))
        os.makedirs(os.path.join(src, "net", "wire"))
        files = {
            "lib.rs": "pub mod anon;\n\n#[cfg(test)]\nmod testutil;\n#[cfg(test)]\nmod helpers;\npub mod net;\n",
            "anon.rs": "pub fn k() -> [u8; 4] { [1, 2, 3, 4] }\n",
            "testutil.rs": "pub const KEY: [u8; 4] = [9, 9, 9, 9];\n",
            "helpers/mod.rs": "pub mod vectors;\n",
            "helpers/vectors.rs": "pub const V: [u8; 2] = [7, 7];\n",
            "net.rs": "pub mod wire;\n#[cfg(all(test, feature = \"x\"))]\nmod fixtures;\n",
            "net/wire/mod.rs": "pub fn parse() {}\n",
            "net/fixtures.rs": "pub const F: [u8; 1] = [5];\n",
        }
        for name, body in files.items():
            with open(os.path.join(src, name), "w") as fh:
                fh.write(body)

    def p(self, rel):
        return os.path.join(self.root, "src", rel)

    def test_cfg_test_mod_file_is_test_only(self):
        self.assertTrue(f.test_only_file(self.p("testutil.rs")))

    def test_sibling_production_file_is_not(self):
        self.assertFalse(f.test_only_file(self.p("anon.rs")))
        self.assertFalse(f.test_only_file(self.p("lib.rs")))

    def test_nested_under_test_only_parent(self):
        self.assertTrue(f.test_only_file(self.p("helpers/mod.rs")))
        self.assertTrue(f.test_only_file(self.p("helpers/vectors.rs")))

    def test_parent_module_file_layout(self):
        self.assertTrue(f.test_only_file(self.p("net/fixtures.rs")))      # declared in net.rs under cfg(all(test, ..))
        self.assertFalse(f.test_only_file(self.p("net/wire/mod.rs")))     # `pub mod wire;` in net.rs: production

    def test_filter_drops_whole_test_only_file_for_every_rule(self):
        doc = {"runs": [{"results": [
            {"ruleId": rule, "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 1}}}]}
            for rule, uri in ((f.CRYPTO_RULE, "src/testutil.rs"), ("rust/other", "src/testutil.rs"), (f.CRYPTO_RULE, "src/anon.rs"))]}]}
        self.assertEqual(f.filter_sarif(doc, self.root, log=lambda *_: None), 2)
        self.assertEqual([r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in doc["runs"][0]["results"]], ["src/anon.rs"])


if __name__ == "__main__":
    unittest.main()
