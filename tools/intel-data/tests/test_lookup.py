# SPDX-License-Identifier: AGPL-3.0-only
"""lookup.py: CVE / ATT&CK lookup tables. Inputs are the SYNTHETIC vulnlookup fixtures (CVE-2099-*), the
synthetic KEV fixture and the synthetic STIX bundle."""
import json
import os
import shutil
import unittest

from helpers import FIX, Sandbox
from heqkdata import lookup, normalize, registry
from heqkdata.store import Store


class Lookup(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.addCleanup(self.sb.close)
        self.reg = registry.Registry(self.sb.reg)
        self.st = Store(self.sb.data)

    def _add(self, sid, path, adapter):
        d = os.path.join(self.sb.dir, "in", sid)
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, os.path.basename(path))
        shutil.copyfile(path, p)
        acq = self.st.register(self.reg, sid, p, "commercial_training")
        normalize.normalize(self.st, self.reg, acq, adapter_name=adapter)

    def test_tables_facts_precedence_and_immutability(self):
        self._add("f-kev", os.path.join(FIX, "vulnlookup", "cvelistv5.ndjson"), "cve_record_v5")
        self._add("f-urlhaus", os.path.join(FIX, "vulnlookup", "github.ndjson"), "osv_advisory")
        self._add("f-attack", os.path.join(FIX, "stix_bundle.json"), "mitre_attack_stix")
        out = os.path.join(self.sb.dir, "lk")
        kw = dict(cve_sources=("f-kev", "f-urlhaus"), attack_sources={"f-attack": "enterprise"}, kev_source="none")
        d, man = lookup.build(self.st, self.reg, "commercial_training", out_root=out, **kw)
        with open(os.path.join(d, "cve.jsonl")) as f:
            cve = {r["cve"]: r for r in map(json.loads, f)}
        a = cve["CVE-2099-0001"]
        self.assertEqual((a["cwe"], a["cvss"], a["vendor"], a["src"]),
                         (["CWE-787"], {"version": "3.1", "score": 9.8, "band": "critical"}, "Fixture", ["f-kev"]))
        self.assertTrue(cve["CVE-2099-0002"]["kev"])          # CISA-ADP KEV marker
        self.assertFalse(a["kev"])
        self.assertEqual(cve["CVE-2099-0005"]["vendor"], "PyPI")  # only the advisory knows it
        self.assertEqual(cve["CVE-2099-0005"]["src"], ["f-urlhaus"])
        with open(os.path.join(d, "attack.jsonl")) as f:
            att = [json.loads(l) for l in f]
        self.assertTrue(att and all(set(r) == {"id", "name", "tactics", "domains"} for r in att))
        for f in man["files"]:
            self.assertEqual(f["sha256"], lookup._sha(os.path.join(d, f["file"])))
            self.assertEqual(os.stat(os.path.join(d, f["file"])).st_mode & 0o222, 0)
        with self.assertRaises(RuntimeError):
            lookup.build(self.st, self.reg, "commercial_training", out_root=out, **kw)


class AttackDomains(unittest.TestCase):
    def test_mobile_and_ics_kill_chains_give_tactics(self):
        from heqkdata.adapters import Ctx, mitre_attack_stix
        import tempfile
        with open(os.path.join(FIX, "stix_bundle.json")) as f:
            d = json.load(f)
        for o in d["objects"]:
            for ph in o.get("kill_chain_phases", []):
                ph["kill_chain_name"] = "mitre-ics-attack"
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        p = os.path.join(tmp, "ics.json")
        with open(p, "w") as f:
            json.dump(d, f)
        ctx = Ctx({"id": "f-attack"}, {"acquisition_id": "d" * 64, "fetched_at": "2026-11-21T00:00:00.000Z",
                                       "license_id": "t-open"}, "mitre_attack_stix", mitre_attack_stix.VERSION, b"k" * 32)
        recs = {r["body"]["technique_id"]: r["body"] for r in mitre_attack_stix.parse(p, ctx) if isinstance(r, dict)}
        self.assertEqual(recs["T1046"]["tactics"], ["discovery"])


if __name__ == "__main__":
    unittest.main()
