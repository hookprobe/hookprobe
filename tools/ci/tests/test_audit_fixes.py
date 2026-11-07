"""Regression tests for the security-auditor findings on the heal loop (ADR 0048, 2026-11-08).

Each test pins one finding so it can never silently come back: C1 (secrets around agent code),
H1 (.gitattributes blinding), H2 (gate-feeding files / comment-out / lint tables / PASS markers),
M2 (default-branch spoofing), M4 (SHA pins for privileged jobs), L1 (issue-body injection).
"""
import os
import sys
import tempfile
import unittest

CI = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path[:0] = [CI, os.path.join(CI, "heal")]
import autofix_guard  # noqa: E402
import g0_wiring  # noqa: E402
import heal  # noqa: E402
import triage_run  # noqa: E402


def mkdiff(path, add=(), rm=(), header_extra=""):
    body = "".join(f"-{l}\n" for l in rm) + "".join(f"+{l}\n" for l in add)
    return f"diff --git a/{path} b/{path}\n{header_extra}--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n{body}"


class GuardH1H2(unittest.TestCase):
    def ev(self, diff):
        return autofix_guard.evaluate(autofix_guard.parse_diff(diff), autofix_guard.load_protected(),
                                      "autofix/x-a1", True)

    def test_blocked(self):
        cases = {
            "H1 plant .gitattributes": mkdiff(".gitattributes", add=["*.rs -diff"]),
            "H2 browser assertions": mkdiff("os/kernel/tools/mc-e2e/ui-check.mjs", add=["// nothing"]),
            "H2 tls provisioning tool": mkdiff("os/kernel/tools/mctls-provision.py", add=["x = 1"]),
            "H2 build script": mkdiff("os/kernel/kernel/build.rs", add=["// x"]),
            "H2 cargo config (runner/rustflags)": mkdiff("os/kernel/.cargo/config.toml", add=["runner = 'true'"]),
            "H2 clippy.toml": mkdiff("os/kernel/clippy.toml", add=["too-many-arguments-threshold = 99"]),
            "H2 comment out an assert": mkdiff("a.rs", add=["        // assert_eq!(a, b);"], rm=["        assert_eq!(a, b);"]),
            "H2 Cargo [lints] table": mkdiff("os/kernel/kernel/Cargo.toml", add=["[lints.clippy]", "all = \"allow\""]),
            "H2 cfg_attr allow": mkdiff("a.rs", add=["#![cfg_attr(test, allow(unused))]"]),
            "H2 rustflags -A": mkdiff("Makefile", add=["RUSTFLAGS='-A warnings' cargo build"]),
            "H2 [patch] redirect": mkdiff("os/kernel/tlsprov/Cargo.toml", add=["[patch.crates-io]"]),
            "A6 forge a PASS marker": mkdiff("os/kernel/kernel/src/main.rs", add=['    kprint!(" [P8sep] PASS\\n");']),
            "A7 symlink": mkdiff("notes.md", header_extra="new file mode 120000\n", add=["../.git/config"]),
            "A7 submodule": mkdiff("vendor/x", header_extra="new file mode 160000\n", add=["Subproject commit 0"]),
        }
        for name, d in cases.items():
            with self.subTest(name=name):
                self.assertTrue(self.ev(d), f"guard let '{name}' through")

    def test_binary_flag_from_header(self):
        d = "diff --git a/x.bin b/x.bin\nBinary files a/x.bin and b/x.bin differ\n"
        self.assertTrue(any(v.startswith("A7") for v in self.ev(d)))

    def test_honest_dependency_bump_still_passes(self):
        d = mkdiff("os/kernel/tlsprov/Cargo.toml",
                   add=['p256 = { version = "0.14", default-features = false }'],
                   rm=['p256 = { version = "0.13", default-features = false }'])
        self.assertEqual(self.ev(d), [])


class HealC1(unittest.TestCase):
    def test_safe_env_drops_tokens(self):
        os.environ.update(GH_TOKEN="t1", GITHUB_TOKEN="t2", AUTOFIX_TOKEN="t3", ANTHROPIC_API_KEY="k",
                          AWS_SECRET_ACCESS_KEY="a")
        try:
            env = heal.safe_env(CI_OUT="/x")
            for k in ("GH_TOKEN", "GITHUB_TOKEN", "AUTOFIX_TOKEN", "ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY"):
                self.assertNotIn(k, env)
            self.assertEqual(env["CI_OUT"], "/x")
            self.assertIn("PATH", env)
        finally:
            for k in ("GH_TOKEN", "GITHUB_TOKEN", "AUTOFIX_TOKEN", "ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY"):
                os.environ.pop(k, None)

    def test_symlinked_notes_are_not_followed(self):
        d = tempfile.mkdtemp()
        secret = os.path.join(d, "config")
        with open(secret, "w") as f:
            f.write("extraheader = AUTHORIZATION: basic SECRET")
        link = os.path.join(d, "AUTOFIX-NOTES.md")
        os.symlink(secret, link)
        out = heal.read_agent_file(link)
        self.assertNotIn("SECRET", out)
        self.assertFalse(os.path.lexists(link))   # always removed from the tree

    def test_root_is_the_repo_root(self):
        # heal.py lives one level deeper than gates.sh; a wrong ROOT made it run gates from tools/.
        self.assertTrue(os.path.isfile(os.path.join(heal.ROOT, "tools", "ci", "gates.sh")))
        with open(os.path.join(CI, "heal", "drill.sh")) as f:
            self.assertIn('/../../.." && pwd)', f.read())

    def test_worktrees_outside_repo_and_hooks_off(self):
        with open(os.path.join(CI, "heal", "heal.py")) as f:
            src = f.read()
        self.assertIn("core.hooksPath=/dev/null", src)
        self.assertIn("tempfile.gettempdir()", src)
        self.assertIn("tamper_detected", src)


class TriageM2L1(unittest.TestCase):
    SHA = "a" * 40

    def run_(self, **kw):
        r = {"event": "push", "head_branch": "main", "head_sha": self.SHA}
        r.update(kw)
        return r

    def test_eligibility(self):
        ok = lambda s: "identical"  # noqa: E731
        self.assertTrue(triage_run.autofix_eligible(self.run_(), "main", "o/r", ok))
        self.assertFalse(triage_run.autofix_eligible(self.run_(event="workflow_dispatch"), "main", "o/r", ok))
        self.assertFalse(triage_run.autofix_eligible(self.run_(event="pull_request"), "main", "o/r", ok))
        self.assertFalse(triage_run.autofix_eligible(self.run_(head_sha="zz"), "main", "o/r", ok))
        # a tag named `main` pointing at a commit NOT on the default branch → "diverged"/"behind"
        self.assertFalse(triage_run.autofix_eligible(self.run_(), "main", "o/r", lambda s: "diverged"))

        def boom(s):
            raise RuntimeError("api down")
        self.assertFalse(triage_run.autofix_eligible(self.run_(), "main", "o/r", boom))  # fail-closed

    def test_issue_body_sanitized(self):
        d = {"category": "unknown", "gate": "g1", "action": "human", "ids": [], "job": "g1 @evil",
             "evidence": ["~~~~", "```", "ping @org/security-team please"]}
        body = triage_run.issue_body(d, "https://x", {"head_branch": "main", "head_sha": self.SHA})
        inner = body.split("~~~~text\n", 1)[1].rsplit("\n~~~~", 1)[0]
        self.assertNotIn("~~~", inner)
        self.assertNotIn("```", inner)
        self.assertNotIn("@", body)


PRIV = """
name: x
on: [push]
permissions: { contents: read }
jobs:
  a:
    runs-on: ubuntu-24.04
    permissions: { contents: write }
    steps:
      - uses: actions/checkout@v4
"""


class WiringM4(unittest.TestCase):
    def test_privileged_job_needs_sha(self):
        self.assertTrue(g0_wiring.check_workflow("x.yml", PRIV))
        self.assertEqual(g0_wiring.check_workflow(
            "x.yml", PRIV.replace("checkout@v4", "checkout@11d5960a326750d5838078e36cf38b85af677262")), [])

    def test_secret_makes_job_privileged(self):
        wf = PRIV.replace("permissions: { contents: write }", "env: { K: '${{ secrets.ANTHROPIC_API_KEY }}' }")
        self.assertTrue(g0_wiring.check_workflow("x.yml", wf))

    def test_read_only_default_token_job_may_use_tags(self):
        wf = PRIV.replace("    permissions: { contents: write }\n", "")
        self.assertEqual(g0_wiring.check_workflow("x.yml", wf), [])


if __name__ == "__main__":
    unittest.main()
