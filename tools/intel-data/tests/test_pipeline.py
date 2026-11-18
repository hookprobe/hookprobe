# SPDX-License-Identifier: AGPL-3.0-only
"""End to end on fixtures: register -> normalise -> licence gate -> build -> split -> export, plus the
reproducibility, immutability, contamination and licence-exclusion properties."""
import json
import os
import unittest

from helpers import FIX, FIXTURE_FILES, Sandbox
from heqkdata import export, normalize, registry, schema
from heqkdata.store import Store


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sb = Sandbox()
        cls.reg = registry.Registry(cls.sb.reg)
        cls.st = Store(cls.sb.data)
        cls.counts = {}
        for sid, rel in FIXTURE_FILES.items():
            purpose = "research" if sid == "f-cic" else "live_intel"
            acq = cls.st.register(cls.reg, sid, os.path.join(FIX, rel), purpose)
            n, rej = normalize.normalize(cls.st, cls.reg, acq)
            cls.counts[sid] = (n, len(rej))

    @classmethod
    def tearDownClass(cls):
        cls.sb.close()

    def test_registry_fixture_consistent(self):
        self.assertEqual(self.reg.check(), [])

    def test_adapter_counts_and_rejects(self):
        self.assertEqual(self.counts["f-attack"], (3, 1))     # 3 techniques incl. deprecated; 1 without id
        self.assertEqual(self.counts["f-kev"], (2, 1))        # NOT-A-CVE rejected
        self.assertEqual(self.counts["f-urlhaus"], (3, 2))    # "not a url" + broken row
        self.assertEqual(self.counts["f-feodo"], (2, 1))
        self.assertEqual(self.counts["f-tranco"], (5, 2))     # bad rank + invalid domain
        self.assertEqual(self.counts["f-iot23"], (3, 1))      # garbage line
        self.assertEqual(self.counts["f-cic"], (2, 1))        # short row
        self.assertEqual(self.counts["f-iocv1"], (2, 1))
        self.assertEqual(self.counts["f-dga"], (3, 1))        # duplicate skipped, invalid rejected

    def test_dga_list_family_and_benchmark(self):
        recs = list(self.st.records("f-dga"))
        self.assertTrue(all(r["labels"]["family"] == "necurs" and r["labels"]["label"] == "malicious" for r in recs))
        _out, _man, rep = self._build("evaluation")
        for k, v in rep["dga_baseline"].items():  # every row is a well-formed rate over the test split
            self.assertTrue(k.split("@")[0] in ("malicious", "benign"))
            self.assertLessEqual(v["flagged"], v["n"])

    def test_every_record_valid_and_traceable(self):
        v = schema.default()
        acq_ids = {a["acquisition_id"] for a in self.st.acquisitions()}
        n = 0
        for r in self.st.records():
            self.assertEqual(v.errors(r, "security-event.schema.json"), [])
            self.assertIn(r["provenance"]["acquisition_id"], acq_ids)
            n += 1
        self.assertGreater(n, 15)

    def test_raw_is_immutable(self):
        a = self.st.acquisitions("f-kev")[0]
        self.assertEqual(os.stat(self.st.raw_path(a)).st_mode & 0o222, 0)
        with self.assertRaises(PermissionError):
            open(self.st.raw_path(a), "a").close()

    def test_register_same_file_is_idempotent(self):
        before = len(self.st.acquisitions("f-kev"))
        self.st.register(self.reg, "f-kev", os.path.join(FIX, "kev.json"), "live_intel")
        self.assertEqual(len(self.st.acquisitions("f-kev")), before)

    def test_licence_gate_blocks_research_only_source_at_acquisition(self):
        from heqkdata.licensing import LicenseDenied
        with self.assertRaises(LicenseDenied):
            self.st.register(self.reg, "f-cic", os.path.join(FIX, "cic.csv"), "commercial_training")

    def test_zeek_labels_and_scenario(self):
        flows = [r for r in self.st.records("f-iot23")]
        labels = sorted(r["labels"]["label"] for r in flows)
        self.assertEqual(labels, ["benign", "malicious", "malicious"])
        self.assertTrue(all(r["provenance"]["source_record_id"].startswith("CTU-IoT-Fixture-1-1:") for r in flows))
        scan = next(r for r in flows if r["labels"]["family"] == "PartOfAHorizontalPortScan")
        self.assertEqual(scan["labels"]["attack_mapping"]["techniques"], ["T1046"])
        self.assertEqual(scan["labels"]["attack_mapping"]["mapping_source"], "heuristic")

    def test_canary_never_labelled_malicious(self):
        recs = list(self.st.records("f-iocv1"))
        canary = next(r for r in recs if "canary" in r["body"]["tags"])
        self.assertIsNone(canary["labels"]["label"])

    def _build(self, purpose):
        return export.build(self.st, self.reg, purpose, out_root=os.path.join(self.sb.dir, "builds-" + purpose))

    def test_commercial_build(self):
        out, man, rep = self._build("commercial_training")
        self.assertEqual(rep["contamination_problems"], [])
        # research-only CIC data and share-alike ioc-v1 never reach a commercial build
        self.assertGreater(man["excluded"].get("licence_gate:f-cic", 0), 0)
        self.assertGreater(man["excluded"].get("licence_gate:f-iocv1", 0), 0)
        v = schema.default()
        ids = set()
        for o in man["outputs"]:
            if o["path"].startswith("examples/"):
                with open(os.path.join(out, o["path"]), encoding="utf-8") as f:
                    for line in f:
                        e = json.loads(line)
                        self.assertEqual(v.errors(e, "training-example.schema.json"), [])
                        self.assertNotIn("f-cic", e["provenance"]["source_ids"])
                        ids.add(e["id"])
        self.assertEqual(len(ids), rep["examples"])
        self.assertIn("soc_reasoning", man["counts"])
        self.assertGreater(man["counts"]["soc_reasoning"], 0)
        # Tranco's compromised-blog.example is dropped: URLhaus lists that registrable domain
        self.assertEqual(rep["build_stats"]["dns_benign_dropped_conflict"], 1)

    def test_research_build_includes_research_source(self):
        _out, man, _rep = self._build("research")
        self.assertNotIn("licence_gate:f-cic", man["excluded"])

    def test_reproducible(self):
        _o1, m1, _ = self._build("evaluation")
        _o2, m2, _ = self._build("evaluation")
        self.assertEqual(m1["dataset_version"], m2["dataset_version"])
        self.assertEqual(m1["outputs"], m2["outputs"])

    def test_live_intel_ioc_pack(self):
        out, man, _ = self._build("live_intel")
        with open(os.path.join(out, "ioc", "IOC.TXT"), encoding="ascii") as f:
            lines = [ln.strip() for ln in f if not ln.startswith("#")]
        self.assertIn("ip 198.51.100.23", lines)       # online Feodo C2
        self.assertNotIn("ip 198.51.100.24", lines)    # offline
        self.assertNotIn("domain c2.canary.example", lines)  # canary never shipped as intel

    def test_synthetic_examples_are_marked(self):
        out, man, _ = self._build("commercial_training")
        for o in man["outputs"]:
            if o["path"].startswith("examples/soc_reasoning"):
                with open(os.path.join(out, o["path"]), encoding="utf-8") as f:
                    for line in f:
                        e = json.loads(line)
                        self.assertEqual(e["ground_truth"]["type"], "synthetic")
                        self.assertFalse(e["ground_truth"]["verified"])
                        self.assertTrue(e["target"]["reasoning"].startswith("SYNTHETIC: "))

    def test_store_refuses_repo_root(self):
        with self.assertRaises(RuntimeError):
            Store(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


if __name__ == "__main__":
    unittest.main()
