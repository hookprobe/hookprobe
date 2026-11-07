"""Self-tests for the gate spine tooling: wiring meta-gate, ratchets, Cortex feed (ADR 0052)."""
import json
import os
import sys
import tempfile
import unittest

CI = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ROOT = os.path.abspath(os.path.join(CI, "..", ".."))
sys.path[:0] = [CI, os.path.join(CI, "cortex")]
import ci_to_cortex  # noqa: E402
import clippy_ratchet  # noqa: E402
import g0_wiring  # noqa: E402
import phase_ratchet  # noqa: E402

GOOD_WF = """
name: x
on: [push]
permissions: { contents: read }
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - run: tools/ci/gates.sh g0
"""


class Wiring(unittest.TestCase):
    def test_good_workflow(self):
        self.assertEqual(g0_wiring.check_workflow("x.yml", GOOD_WF), [])

    def test_bad_workflows(self):
        cases = {
            "unpinned action": GOOD_WF.replace("checkout@v4", "checkout@main"),
            "no permissions": GOOD_WF.replace("permissions: { contents: read }\n", ""),
            "pull_request_target": GOOD_WF.replace("on: [push]", "on: [pull_request_target]"),
            "PR reaches metal": GOOD_WF.replace("on: [push]", "on: [pull_request]").replace(
                "ubuntu-24.04", "[self-hosted, linux, cm5-bench]"),
            "broken yaml": "name: x\non: [push\n",
        }
        for name, wf in cases.items():
            with self.subTest(name=name):
                self.assertTrue(g0_wiring.check_workflow("x.yml", wf), f"{name} not caught")

    def test_bare_on_key_parsed(self):  # YAML 1.1 turns `on:` into True
        self.assertEqual(g0_wiring.check_workflow("x.yml", GOOD_WF.replace("on: [push]", "on:\n  push: {}")), [])

    def test_every_real_workflow_is_clean(self):
        wdir = os.path.join(ROOT, ".github", "workflows")
        for fn in sorted(os.listdir(wdir)):
            with self.subTest(workflow=fn), open(os.path.join(wdir, fn)) as f:
                self.assertEqual(g0_wiring.check_workflow(fn, f.read()), [])

    def test_script_refs(self):
        self.assertEqual(g0_wiring.script_refs("run: tools/ci/gates.sh g1 && os/kernel/tools/mc-e2e.sh"),
                         ["os/kernel/tools/mc-e2e.sh", "tools/ci/gates.sh"])


class PhaseRatchet(unittest.TestCase):
    def test_parse_and_check(self):
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
            f.write('PHASES=(\n  "P0|[P0] PASS|impl|x|boot"\n  "P1|[P1] PASS|plan|x|sched"\n)\n')
        ph = phase_ratchet.parse_phases(f.name)
        os.unlink(f.name)
        self.assertEqual(ph, {"P0": "impl", "P1": "plan"})
        self.assertEqual(phase_ratchet.check(ph, ["P0"]), ([], []))
        errs, _ = phase_ratchet.check(ph, ["P0", "P1"])
        self.assertIn("downgraded", errs[0])
        errs, _ = phase_ratchet.check({"P1": "plan"}, ["P0"])
        self.assertIn("GONE", errs[0])
        self.assertEqual(phase_ratchet.check({"P0": "impl", "P9": "impl"}, ["P0"])[1], ["P9"])

    def test_real_validate_sh_parses(self):
        ph = phase_ratchet.parse_phases(os.path.join(ROOT, "os/kernel/validate.sh"))
        self.assertGreater(sum(1 for s in ph.values() if s == "impl"), 50)
        self.assertEqual(ph.get("P8sep"), "impl")  # the ADR 0023 separation keystone


def msg(crate, code, level="warning", file="kernel/src/x.rs"):
    return json.dumps({"reason": "compiler-message", "target": {"name": crate},
                       "message": {"level": level, "code": {"code": code},
                                   "spans": [{"is_primary": True, "file_name": file, "line_start": 1}]}})


class ClippyRatchet(unittest.TestCase):
    def test_collect_filters(self):
        lines = [msg("kernel", "clippy::op_ref"), msg("kernel", "clippy::op_ref"), msg("smoltcp", "dead_code"),
                 msg("kernel", "dead_code", file="target/x/out/policy_key.rs"), "noise",
                 json.dumps({"reason": "compiler-message", "target": {"name": "kernel"},
                             "message": {"level": "warning", "code": None, "spans": []}})]
        counts, errors = clippy_ratchet.collect(lines)
        self.assertEqual(dict(counts), {("kernel", "clippy::op_ref"): 2})
        self.assertEqual(errors, [])

    def test_compare(self):
        base = {"kernel": {"clippy::op_ref": 2}}
        c, _ = clippy_ratchet.collect([msg("kernel", "clippy::op_ref")] * 3)
        self.assertTrue(clippy_ratchet.compare(c, base)[0])           # 2 -> 3 rises
        c, _ = clippy_ratchet.collect([msg("kernel", "clippy::new_lint")])
        v, impr = clippy_ratchet.compare(c, base)
        self.assertTrue(v and impr)                                    # new lint; op_ref fell
        _, errs = clippy_ratchet.collect([msg("kernel", "clippy::x", level="error")])
        self.assertTrue(errs)


class Cortex(unittest.TestCase):
    def test_events(self):
        doc = {"workflow": "ci", "run_id": "42", "ts": "t", "sha": "abc",
               "gates": [{"gate": "g4", "status": "fail", "seconds": 3, "desc": "supply chain", "failed_steps": 1}]}
        ev = ci_to_cortex.events_from_results(doc)
        self.assertEqual(ev[0]["kind"], "gate")
        self.assertEqual(ev[0]["schema"], 1)
        self.assertIn("g4 FAIL", ev[0]["summary"])
        self.assertTrue(all(k in ev[0] for k in ("session", "ts", "summary", "detail")))


if __name__ == "__main__":
    unittest.main()
