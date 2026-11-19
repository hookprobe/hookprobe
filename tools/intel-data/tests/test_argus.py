# SPDX-License-Identifier: AGPL-3.0-only
"""argus_binetflow (CTU-13 labelled bidirectional NetFlow). The fixture is synthetic, in the CTU-13
column layout, with RFC 5737 addresses only."""
import os
import unittest

from helpers import FIX, Sandbox
from heqkdata import registry, schema
from heqkdata.adapters import Ctx, Reject, argus_binetflow

PATH = os.path.join(FIX, "argus", "1", "capture-fixture.binetflow")


class ArgusBinetflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sb = Sandbox()
        reg = registry.Registry(sb.reg)
        src = dict(reg.source("f-cic"), id="f-ctu13")
        ctx = Ctx(src, {"acquisition_id": "b" * 64, "fetched_at": "2026-11-19T00:00:00.000Z", "source_id": "f-ctu13",
                        "license_id": src["license_id"]}, "argus_binetflow", argus_binetflow.VERSION, b"k" * 32)
        # the store names a registered file '<scenario dir>__<file>'
        import shutil
        import tempfile
        cls.tmp = tempfile.mkdtemp()
        p = os.path.join(cls.tmp, "1__capture-fixture.binetflow")
        shutil.copyfile(PATH, p)
        out = list(argus_binetflow.parse(p, ctx))
        cls.recs = [r for r in out if isinstance(r, dict)]
        cls.rej = [r for r in out if isinstance(r, Reject)]
        sb.close()
        shutil.rmtree(cls.tmp)

    def test_counts_and_reject(self):
        self.assertEqual(len(self.recs), 5)
        self.assertEqual(len(self.rej), 1)  # month 13
        self.assertIn("StartTime", self.rej[0].reason)

    def test_labels(self):
        labs = [r["labels"]["label"] for r in self.recs]
        self.assertEqual(labs, ["malicious", "malicious", "benign", None, None])  # Background is unknown, not benign
        self.assertEqual(self.recs[0]["labels"]["attack_mapping"]["techniques"], ["T1071"])  # CC
        self.assertEqual(self.recs[1]["labels"]["attack_mapping"]["techniques"], [])  # plain DNS: no mapping
        self.assertEqual(self.recs[4]["labels"]["original_label"], "Background-TCP-Attempt")  # no flow= prefix

    def test_body(self):
        b = self.recs[0]["body"]
        self.assertEqual((b["orig_ip"], b["orig_port"], b["resp_port"], b["proto"]), ("192.0.2.165", 1027, 80, "tcp"))
        self.assertEqual((b["orig_bytes"], b["resp_bytes"], b["orig_pkts"], b["conn_state"]), (800, 3400, None, None))
        self.assertEqual(b["ts_start"], "2011-08-10T09:46:53.047Z")
        icmp = self.recs[3]["body"]
        self.assertEqual((icmp["proto"], icmp["orig_port"], icmp["resp_port"]), ("icmp", None, None))

    def test_scenario_groups_and_schema(self):
        v = schema.default()
        for r in self.recs:
            self.assertTrue(r["provenance"]["source_record_id"].startswith("CTU-13-1:"))
            self.assertEqual(v.errors(r, "security-event.schema.json"), [])


if __name__ == "__main__":
    unittest.main()
