"""Self-tests for the L2 heal loop: classifier, autofix guard, GitHub triage mapping (ADR 0052)."""
import os
import sys
import unittest

CI = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path[:0] = [CI, os.path.join(CI, "heal")]
import autofix_guard  # noqa: E402
import classify  # noqa: E402
import triage_run  # noqa: E402

# Realistic log excerpts (trimmed from real runs on this repo).
LOGS = {
    "secret_leak": "::error::SECRET TRIPWIRE [PEM private key] matched:\n./x.pem:1:-----BEGIN",
    "vulnerable_dependency": (
        "error[vulnerability]: Multiple timing variability issues in operations intended to be constant-time\n"
        "   ├ ID: RUSTSEC-2026-0387\n   ├ Solution: Upgrade to >=0.7.6\n"),
    "supply_chain_policy": "error[rejected]: failed to satisfy license requirements\n license = \"GPL-3.0\"",
    "ci_wiring": "  FAIL: W1 nested os/kernel/.github/ is never read by GitHub\nG0 wiring: 5 workflows",
    "shell_lint": "In tools/x.sh line 3:\ncd \"$R\"\n^--^ SC2164 (warning): Use 'cd ... || exit'",
    "phase_downgrade": "  RATCHET VIOLATION: phase P8sep was downgraded impl -> plan",
    "clippy_regression": "clippy findings: 232 (baseline 231)\n  RATCHET VIOLATION: kernel: clippy::op_ref 9 -> 10 (+1)",
    "toolchain_env": "error: 'cargo-clippy' is not installed for the toolchain 'nightly-x86_64-unknown-linux-gnu'.",
    "infra_transient": "error: failed to download from `https://static.crates.io/x`\nCaused by: Could not resolve host: static.crates.io",
    "qemu_budget": "TIMEOUT after 150s (load: 7.9) — missing markers below may be phantom",
    "build_error": "error[E0599]: no method named `to_encoded_point` found\nerror: could not compile `heqk-tlsprov`",
    "test_failure": "thread 'tests::small_order_peer_key_refused' panicked at src/lib.rs:456:38:\ntest result: FAILED. 2 passed; 2 failed",
    "qemu_phase_regression": " built phases failing : 1\n VERDICT: REGRESSION — heal required (diagnostics above).",
    "e2e_failure": "  PASS  address obtained by DHCP\n  FAIL  API reachable without a session\nMC-E2E: FAIL (1)",
}


class Classifier(unittest.TestCase):
    def test_every_category_is_recognised(self):
        for cat, text in LOGS.items():
            with self.subTest(cat=cat):
                self.assertEqual(classify.classify_text(text)["category"], cat)

    def test_actions(self):
        act = {c: classify.classify_text(t)["action"] for c, t in LOGS.items()}
        for c in ("secret_leak", "supply_chain_policy", "ci_wiring", "phase_downgrade", "toolchain_env"):
            self.assertEqual(act[c], "human", c)   # decisions, never autofixed
        for c in ("infra_transient", "qemu_budget"):
            self.assertEqual(act[c], "rerun", c)
        for c in ("vulnerable_dependency", "shell_lint", "build_error", "test_failure", "e2e_failure", "clippy_regression"):
            self.assertEqual(act[c], "autofix", c)

    def test_secret_outranks_everything(self):
        d = classify.classify_text(LOGS["build_error"] + "\n" + LOGS["secret_leak"])
        self.assertEqual(d["category"], "secret_leak")

    def test_vuln_ids_extracted(self):
        self.assertEqual(classify.classify_text(LOGS["vulnerable_dependency"])["ids"], ["RUSTSEC-2026-0387"])

    def test_signature_stable_across_noise(self):
        a = classify.classify_text("2026-11-07T21:00:01.123Z test result: FAILED. took 1.23s at 0xdeadbeef")
        b = classify.classify_text("2026-11-08T03:17:44.999Z test result: FAILED. took 9.87s at 0xcafef00d")
        self.assertEqual(a["signature"], b["signature"])

    def test_unknown_goes_to_human(self):
        d = classify.classify_text("something odd happened\nexit 1")
        self.assertEqual((d["category"], d["action"]), ("unknown", "human"))


DIFF_OK = """diff --git a/os/kernel/tlsprov/src/lib.rs b/os/kernel/tlsprov/src/lib.rs
--- a/os/kernel/tlsprov/src/lib.rs
+++ b/os/kernel/tlsprov/src/lib.rs
@@ -1,3 +1,4 @@
-    let ep = k.verifying_key().to_encoded_point(false);
+    let ep = k.verifying_key().to_sec1_point(false);
+    assert_eq!(ep.len(), 65);
"""


def mkdiff(path, add=(), rm=()):
    body = "".join(f"-{l}\n" for l in rm) + "".join(f"+{l}\n" for l in add)
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n{body}"


class Guard(unittest.TestCase):
    def setUp(self):
        self.prot = autofix_guard.load_protected()

    def ev(self, diff, branch="autofix/x-a1"):
        return autofix_guard.evaluate(autofix_guard.parse_diff(diff), self.prot, branch, True)

    def test_honest_fix_passes(self):
        self.assertEqual(self.ev(DIFF_OK), [])

    def test_gaming_attempts_are_blocked(self):
        cases = {
            "edit the gate": mkdiff("tools/ci/deny.toml", add=['ignore = ["RUSTSEC-2026-0387"]']),
            "edit a workflow": mkdiff(".github/workflows/ci.yml", add=["continue-on-error: true"]),
            "lower the ratchet": mkdiff("tools/ci/baselines/clippy.json", add=['"op_ref": 99']),
            "downgrade a phase": mkdiff("os/kernel/validate.sh", add=['"P8sep|x|plan|v|w"'], rm=['"P8sep|x|impl|v|w"']),
            "delete a test": mkdiff("os/kernel/tlsprov/src/lib.rs", rm=["    #[test]", "        assert!(x.is_ok());"]),
            "ignore a test": mkdiff("os/kernel/tlsprov/src/lib.rs", add=["    #[ignore]"]),
            "silence a lint": mkdiff("os/kernel/kernel/src/net.rs", add=["#[allow(dead_code)]"]),
            "swallow a failure": mkdiff("os/build/x.sh", add=["make check || true"]),
            "touch signing keys": mkdiff("os/kernel/hboot/src/attest_keys.rs", add=["const K: [u8; 32] = [0; 32];"]),
            "rewrite an ADR": mkdiff("docs/adr/0023-enforcement-separation.md", add=["drops are fine now"]),
        }
        for name, diff in cases.items():
            with self.subTest(name=name):
                self.assertTrue(self.ev(diff), f"guard let '{name}' through")

    def test_rename_or_delete_a_protected_file_is_blocked(self):
        rename = ("diff --git a/tools/ci/deny.toml b/notes.toml\nsimilarity index 100%\n"
                  "rename from tools/ci/deny.toml\nrename to notes.toml\n")
        delete = ("diff --git a/tools/ci/deny.toml b/tools/ci/deny.toml\ndeleted file mode 100644\n"
                  "--- a/tools/ci/deny.toml\n+++ /dev/null\n@@ -1 +0,0 @@\n-[advisories]\n")
        # header-only: the protected source appears ONLY as the a/ side (no rename lines) —
        # each defence layer must hold on its own.
        header_only = ("diff --git a/tools/ci/deny.toml b/notes.toml\n--- a/tools/ci/deny.toml\n"
                       "+++ b/notes.toml\n@@ -1 +1 @@\n-[advisories]\n+[advisories]\n")
        for name, d in (("rename away", rename), ("delete", delete), ("header only", header_only)):
            with self.subTest(name=name):
                self.assertTrue(any(v.startswith("A1") for v in self.ev(d)), name)

    def test_unparseable_header_fails_closed(self):
        d = 'diff --git "a/odd name" "b/odd name"\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n+y\n'
        self.assertTrue(any("could not be parsed" in v for v in self.ev(d)))

    def test_guard_is_always_the_trusted_copy(self):
        # heal.py must run the guard from its own (operator) tree, and ci.yml from the base branch —
        # never the copy inside the change under review (an agent could rewrite it to pass).
        with open(os.path.join(CI, "heal", "heal.py")) as f:
            heal_src = f.read()
        self.assertIn('os.path.join(HERE, "autofix_guard.py")', heal_src)
        self.assertNotIn('os.path.join(wt, "tools/ci/heal/autofix_guard.py")', heal_src)
        with open(os.path.join(CI, "..", "..", ".github", "workflows", "ci.yml")) as f:
            ci_yml = f.read()
        self.assertIn('git show "origin/$BASE_REF:tools/ci/heal/autofix_guard.py"', ci_yml)

    def test_wrong_branch_blocked(self):
        self.assertTrue(any(v.startswith("A5") for v in self.ev(DIFF_OK, branch="main")))

    def test_too_big_blocked(self):
        big = mkdiff("os/kernel/kernel/src/net.rs", add=[f"let x{i} = {i};" for i in range(500)])
        self.assertTrue(any(v.startswith("A4") for v in self.ev(big)))

    def test_moving_tests_is_not_weakening(self):
        d = mkdiff("a.rs", add=["#[test]", "assert!(a);"], rm=["#[test]", "assert!(b);"])
        self.assertEqual(self.ev(d), [])


class Triage(unittest.TestCase):
    def test_gate_mapping(self):
        self.assertEqual(triage_run.gate_for("ci", "g1 · clippy ratchet + unit tests"), "g1")
        self.assertEqual(triage_run.gate_for("nightly", "g4r · reproducible prod kernel"), "g4r")
        self.assertEqual(triage_run.gate_for("build-heqk", "heqk QEMU gate (validate.sh)"), "g2")
        self.assertEqual(triage_run.gate_for("secrets-scan", "gitleaks"), "secrets")

    def test_most_severe_wins(self):
        ds = [classify.classify_text(LOGS["infra_transient"]), classify.classify_text(LOGS["vulnerable_dependency"])]
        self.assertEqual(triage_run.pick(ds)["category"], "vulnerable_dependency")


if __name__ == "__main__":
    unittest.main()
