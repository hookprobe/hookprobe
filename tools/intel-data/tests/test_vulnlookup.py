# SPDX-License-Identifier: AGPL-3.0-only
"""cve_record_v5 + osv_advisory (CIRCL Vulnerability-Lookup dumps), the CVSS v3 scorer and the CVE knowledge
builder. The fixtures are SYNTHETIC records in the CVE JSON 5 / OSV layouts (CVE-2099-* ids, invented text)."""
import io
import os
import unittest

from helpers import FIX
from heqkdata import builders, cvss, safeio, schema
from heqkdata.adapters import Ctx, Reject, cve_record_v5, osv_advisory

D = os.path.join(FIX, "vulnlookup")


def run(mod, name, sid, lic):
    ctx = Ctx({"id": sid}, {"acquisition_id": "c" * 64, "fetched_at": "2099-01-01T00:00:00.000Z", "source_id": sid,
                            "license_id": lic, "bytes": None}, mod.__name__.rsplit(".", 1)[1], mod.VERSION, b"k" * 32)
    out = list(mod.parse(os.path.join(D, name), ctx))
    return [r for r in out if isinstance(r, dict)], [r for r in out if isinstance(r, Reject)]


class Cvss(unittest.TestCase):
    def test_reference_vectors(self):
        for v, s in [("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8), ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
                     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0), ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
                     ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4), ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0)]:
            self.assertEqual(cvss.base_score_v3(v), s, v)

    def test_rejects_incomplete_or_other_versions(self):
        for v in ("CVSS:3.1/AV:N/AC:L", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                  "AV:N/AC:L/Au:N/C:P/I:P/A:P", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", None):
            self.assertIsNone(cvss.base_score_v3(v), v)
        self.assertEqual([cvss.severity(x) for x in (9.0, 7.0, 4.0, 0.1, 0.0)], ["critical", "high", "medium", "low", "info"])


class CveRecordV5(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.recs, cls.rej = run(cve_record_v5, "cvelistv5.ndjson", "cve-list-v5", "t-open")

    def test_counts_and_rejects(self):
        self.assertEqual([r["body"]["cve_id"] for r in self.recs], ["CVE-2099-0001", "CVE-2099-0002"])
        reasons = " | ".join(r.reason for r in self.rej)
        for want in ("REJECTED", "no English CNA description", "bad JSON"):
            self.assertIn(want, reasons)

    def test_cna_first_then_cisa_adp_and_kev(self):
        a, b = (r["body"] for r in self.recs)
        self.assertEqual((a["vendor"], a["product"], a["cwe_ids"], a["cvss"]["base_score"]), ("Fixture", "Router", ["CWE-787"], 9.8))
        self.assertIsNone(a["known_exploited"])  # no KEV marker: unknown, never false
        self.assertEqual((b["vendor"], b["product"], b["cwe_ids"]), ("fixturevendor", "widget", ["CWE-79"]))
        self.assertEqual((b["known_exploited"], b["kev_date_added"], b["cvss"]["version"]), (True, "2099-02-01", "3.1"))

    def test_dump_metadata_is_not_carried(self):
        for r in self.recs:
            self.assertNotIn("epss", str(r["body"]))
        v = schema.default()
        for r in self.recs:
            self.assertEqual(v.errors(r, "security-event.schema.json"), [])


class OsvAdvisory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.recs, cls.rej = run(osv_advisory, "github.ndjson", "github-advisory-db", "t-open")

    def test_one_record_per_cve_alias(self):
        self.assertEqual(sorted(r["body"]["cve_id"] for r in self.recs), ["CVE-2099-0001", "CVE-2099-0005", "CVE-2099-0006"])
        self.assertEqual(sorted(r.reason.split(" ", 1)[1] for r in self.rej), ["has no CVE alias", "withdrawn"])

    def test_package_cvss_and_review_flag(self):
        r = next(r for r in self.recs if r["body"]["cve_id"] == "CVE-2099-0001")
        b = r["body"]
        self.assertEqual((b["vendor"], b["product"], b["cvss"]["base_score"], b["cvss"]["version"]), ("npm", "fixture-pkg", 9.8, "3.1"))
        self.assertEqual(r["labels"]["original_label"], "github_reviewed")
        v4 = next(r for r in self.recs if r["body"]["cve_id"] == "CVE-2099-0005")
        self.assertIsNone(v4["body"]["cvss"])  # v4 vectors are not scored
        v = schema.default()
        for r in self.recs:
            self.assertEqual(v.errors(r, "security-event.schema.json"), [])


class CveKnowledge(unittest.TestCase):
    def test_prefers_cve_program_record_and_states_only_record_facts(self):
        cve, _ = run(cve_record_v5, "cvelistv5.ndjson", "cve-list-v5", "t-open")
        gh, _ = run(osv_advisory, "github.ndjson", "github-advisory-db", "t-open")
        ex = builders.build_cve_knowledge(cve + gh)
        by = {e["split"]["group_key"]: e for e in ex}
        self.assertEqual(sorted(by), ["CVE-2099-0001", "CVE-2099-0002"])  # 0005/0006: no CWE, no CVSS
        e = by["CVE-2099-0001"]
        self.assertEqual(e["provenance"]["source_ids"], ["cve-list-v5"])
        self.assertEqual(e["target"]["severity"], "critical")
        self.assertIn("CVSS v3.1 base score 9.8", e["target"]["answer"])
        self.assertNotIn("exploit", e["target"]["answer"].lower())
        v = schema.default()
        for x in ex:
            self.assertEqual(v.errors(x, "training-example.schema.json"), [])


class Ndjson(unittest.TestCase):
    def test_overlong_and_non_object_lines_are_reported_not_fatal(self):
        s = io.StringIO('{"a":1}\n' + "x" * 50 + "\n[1]\nNaN\n{\"b\":2}\n")
        got = list(safeio.ndjson(s, limit=20))
        self.assertEqual([o for _, o, _ in got], [{"a": 1}, None, None, None, {"b": 2}])
        self.assertIn("longer than", got[1][2])


if __name__ == "__main__":
    unittest.main()
