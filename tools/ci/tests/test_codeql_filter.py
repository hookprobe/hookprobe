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


if __name__ == "__main__":
    unittest.main()
