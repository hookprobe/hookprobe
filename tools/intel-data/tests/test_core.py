# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests: schemas, canonical forms, the licence gate, safe archive handling, the DGA reference."""
import os
import re
import tempfile
import unittest
import zipfile

from helpers import LICENSES, TOOL  # noqa: F401  (sets sys.path)
from heqkdata import canon, dga_ref, licensing, safeio, schema

REPO = os.path.abspath(os.path.join(TOOL, "..", ".."))


class SchemaTests(unittest.TestCase):
    def test_all_schema_files_supported_and_resolvable(self):
        self.assertEqual(schema.check_schema_files(), [])

    def test_unsupported_keyword_fails_closed(self):
        v = schema.Validator()
        v._docs["x.schema.json"] = {"type": "string", "contentEncoding": "base64"}
        with self.assertRaises(schema.SchemaError):
            v.errors("a", "x.schema.json")

    def test_if_then_dispatch_and_null_handling(self):
        v = schema.default()
        rec = {"schema": "heqk.security-event/1", "record_id": "dns:" + "a" * 24, "kind": "dns", "observed_at": None,
               "sensor": {"type": "dataset", "name": "x"},
               "body": {"schema": "heqk.network-flow/1"},  # wrong body for kind dns
               "labels": {"label": None, "family": None, "label_source": "none", "original_label": None,
                          "attack_mapping": {"framework": "MITRE ATT&CK", "version": None, "techniques": [], "tactics": [], "mapping_source": "none"}},
               "provenance": {"source_id": "xx", "source_record_id": None, "acquisition_id": "synthetic:t", "raw_sha256": None,
                              "license_id": "xx", "transform": {"name": "tt", "version": "1.0.0"}, "created_at": "2026-11-18T00:00:00.000Z"}}
        errs = v.errors(rec, "security-event.schema.json")
        self.assertTrue(any("heqk.dns-event/1" in e for e in errs), errs)
        rec["body"] = {"schema": "heqk.dns-event/1", "qname": "Example.COM", "qtype": "A", "rcode": None, "answers": [],
                       "client_ref": None, "transport": None, "window": None}
        self.assertTrue(any("domain-canonical" in e for e in v.errors(rec, "security-event.schema.json")))
        rec["body"]["qname"] = "example.com"
        self.assertEqual(v.errors(rec, "security-event.schema.json"), [])

    def test_bool_is_not_integer(self):
        v = schema.Validator()
        v._docs["i.schema.json"] = {"type": "integer"}
        self.assertFalse(v.is_valid(True, "i.schema.json"))


class CanonTests(unittest.TestCase):
    def test_timestamps(self):
        self.assertEqual(canon.ts(0), "1970-01-01T00:00:00.000Z")
        self.assertEqual(canon.ts("2026-11-01 10:00:00"), "2026-11-01T10:00:00.000Z")
        self.assertEqual(canon.ts("2026-11-01T12:00:00+02:00"), "2026-11-01T10:00:00.000Z")
        self.assertEqual(canon.ts("1525879831.015811"), "2018-05-09T15:30:31.015Z")
        self.assertIsNone(canon.ts("-"))
        self.assertIsNone(canon.ts("garbage"))

    def test_ip(self):
        self.assertEqual(canon.ip("::ffff:192.0.2.1"), "192.0.2.1")
        self.assertEqual(canon.ip("2001:DB8:0:0::1"), "2001:db8::1")
        self.assertIsNone(canon.ip("example.com"))

    def test_domain(self):
        self.assertEqual(canon.domain("WWW.Example.COM."), "www.example.com")
        self.assertEqual(canon.domain("bücher.example"), "xn--bcher-kva.example")
        self.assertEqual(canon.domain("_dmarc.example.org"), "_dmarc.example.org")
        for bad in ("192.0.2.1", "-bad-.example", "localhost", "a..b", "x" * 64 + ".com", "example.123"):
            self.assertIsNone(canon.domain(bad), bad)

    def test_registrable_matches_dga_split(self):
        self.assertEqual(canon.registrable("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(canon.registrable("www.example.com"), "example.com")

    def test_pseudonym_keyed(self):
        a = canon.pseudonym(b"k1", "192.168.1.2")
        self.assertRegex(a, r"^c:[0-9a-f]{16}$")
        self.assertNotEqual(a, canon.pseudonym(b"k2", "192.168.1.2"))


class LicenceGateTests(unittest.TestCase):
    L = {x["id"]: x for x in LICENSES}

    def test_open(self):
        for p in licensing.PURPOSES:
            self.assertTrue(licensing.decide(self.L["t-open"], p)[0], p)

    def test_research_only(self):
        r = self.L["t-research"]
        self.assertTrue(licensing.decide(r, "research")[0])
        for p in ("commercial_training", "evaluation", "live_intel"):
            self.assertFalse(licensing.decide(r, p)[0], p)

    def test_share_alike_blocks_training_only(self):
        sa = self.L["t-cc-by-sa"]
        self.assertFalse(licensing.decide(sa, "commercial_training")[0])
        self.assertTrue(licensing.decide(sa, "live_intel")[0])

    def test_unknown_and_restricted_deny_everything(self):
        for cls in ("UNKNOWN", "RESTRICTED"):
            l = dict(self.L["t-open"], **{"class": cls})
            for p in licensing.PURPOSES:
                self.assertFalse(licensing.decide(l, p)[0])

    def test_unclear_is_no(self):
        l = dict(self.L["t-open"], training_use="unclear")
        self.assertFalse(licensing.decide(l, "commercial_training")[0])

    def test_evaluation_accepts_unclear_commercial_use_only(self):
        # operator decision 2026-11-22: verified licence, commercial_use unclear -> evaluation only
        for cls in ("RESEARCH", "COMMERCIAL", "OPEN"):
            l = dict(self.L["t-open"], **{"class": cls, "commercial_use": "unclear", "training_use": "unclear",
                                          "derivatives": "unclear", "redistribution": "unclear"})
            self.assertEqual(licensing.decide(l, "evaluation"), (True, licensing.EVALUATION_UNCLEAR))
            for p in ("commercial_training", "live_intel"):
                self.assertFalse(licensing.decide(l, p)[0], p)
        base = dict(self.L["t-open"], commercial_use="unclear")
        for cu in ("no", "requires_agreement"):
            self.assertFalse(licensing.decide(dict(base, commercial_use=cu), "evaluation")[0], cu)
        self.assertFalse(licensing.decide(dict(base, training_use="no", derivatives="no"), "evaluation")[0])
        for cls in ("UNKNOWN", "RESTRICTED"):  # never verified / needs an agreement: still no
            self.assertFalse(licensing.decide(dict(base, **{"class": cls}), "evaluation")[0], cls)
        self.assertEqual(licensing.decide(self.L["t-open"], "evaluation"), (True, "commercial evaluation permitted"))

    def test_manifest_schema_takes_licence_caveats(self):
        from heqkdata import schema
        v = schema.default()
        m = {"schema": "heqk.manifest/1", "dataset_version": "2026.11.22-0123456789ab", "purpose": "evaluation",
             "tool_version": "x", "schema_versions": {}, "created_at": "2026-11-22T00:00:00.000Z", "acquisitions": [],
             "outputs": [], "counts": {}, "excluded": {}, "licence_caveats": {"cic-ids2017": licensing.EVALUATION_UNCLEAR}}
        self.assertEqual(v.errors(m, "manifest.schema.json"), [])


class SafeIOTests(unittest.TestCase):
    def _zip(self, members):
        fd, p = tempfile.mkstemp(suffix=".zip")
        os.close(fd)
        with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
            for name, data in members:
                z.writestr(name, data)
        self.addCleanup(os.unlink, p)
        return p

    def test_traversal_refused(self):
        p = self._zip([("../evil.csv", "x")])
        with tempfile.TemporaryDirectory() as d, self.assertRaises(safeio.UnsafeContent):
            safeio.extract_zip(p, os.path.join(d, "out"))

    def test_executable_refused(self):
        p = self._zip([("sample.exe", "MZ")])
        with tempfile.TemporaryDirectory() as d, self.assertRaises(safeio.UnsafeContent):
            safeio.extract_zip(p, os.path.join(d, "out"))

    def test_ratio_bomb_refused(self):
        p = self._zip([("big.csv", "0" * (5 << 20))])
        with tempfile.TemporaryDirectory() as d, self.assertRaises(safeio.UnsafeContent):
            safeio.extract_zip(p, os.path.join(d, "out"))

    def test_normal_extract(self):
        p = self._zip([("dir/top.csv", "1,example.com\n")])
        with tempfile.TemporaryDirectory() as d:
            out = safeio.extract_zip(p, os.path.join(d, "out"))
            self.assertEqual(len(out), 1)

    def test_json_nan_refused(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write('{"a": NaN}')
        self.addCleanup(os.unlink, f.name)
        with self.assertRaises(safeio.UnsafeContent):
            safeio.load_json(f.name)


class DgaReferenceTests(unittest.TestCase):
    """The kernel's own [P-dga] self-test corpus, parsed from dga.rs, must pass against the Python port."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(REPO, "os/kernel/kernel/src/dga.rs"), encoding="utf-8") as f:
            cls.src = f.read()

    def _list(self, name):
        m = re.search(r"let " + name + r": &\[&\[u8\]\] = &\[(.*?)\];", self.src, re.S)
        self.assertIsNotNone(m, f"{name} list not found in dga.rs (did the self-test change?)")
        return re.findall(r'b"([^"]*)"', m.group(1))

    def test_kernel_selftest_corpus(self):
        bad, good = self._list("bad"), self._list("good")
        self.assertGreater(len(bad), 5)
        for n in bad:
            self.assertGreaterEqual(dga_ref.score(n), dga_ref.DGA_THRESHOLD, n)
        for n in good:
            self.assertLess(dga_ref.score(n), dga_ref.DGA_THRESHOLD, n)

    def test_constants_match_rust(self):
        self.assertIn(f"pub const DGA_THRESHOLD: u32 = {dga_ref.DGA_THRESHOLD};", self.src)
        for const, py in (("SUFFIX2", dga_ref.SUFFIX2), ("SUS_TLD", dga_ref.SUS_TLD), ("BRANDS", dga_ref.BRANDS), ("PHISH", dga_ref.PHISH)):
            m = re.search(r"const " + const + r": &\[&\[u8\]\] = &\[(.*?)\];", self.src, re.S)
            self.assertEqual(tuple(x.encode() for x in re.findall(r'b"([^"]*)"', m.group(1))), py, const)

    def test_split_and_entropy(self):
        self.assertEqual(dga_ref.split(b"www.xjw3k.co.uk")[:2], (b"xjw3k", b"www"))
        self.assertEqual(dga_ref.entropy_q8(b"aaaa"), 0)
        self.assertLessEqual(abs(dga_ref.entropy_q8(b"abcd") - 512), 24)
        self.assertEqual(dga_ref.score(b""), 0)
        self.assertEqual(dga_ref.score(b"com"), 0)


class StratifiedSplitTests(unittest.TestCase):
    def test_few_groups_every_split_gets_both_labels_and_no_leak(self):
        from heqkdata import splits
        sizes = [(500, 0.99), (500, 0.9), (460, 1.0), (200, 0.95), (88, 0.9), (66, 0.5), (64, 0.5), (28, 0.0), (9, 0.0), (5, 1.0), (3, 0.0)]
        ex = []
        for gi, (n, mal) in enumerate(sizes):
            for i in range(n):
                ex.append({"id": f"{gi}-{i}", "collection": "c", "content_sha256": f"{gi}-{i}",
                           "split": {"group_key": f"g{gi}", "name": None, "strategy": None},
                           "target": {"label": "malicious" if i < n * mal else "benign"},
                           "input": {"records": [{"record_id": f"r{gi}-{i}"}]}})
        splits.assign(ex, {"train": 0.7, "dev": 0.15, "test": 0.15}, "group_stratified")
        for s in ("train", "dev", "test"):
            labs = {e["target"]["label"] for e in ex if e["split"]["name"] == s}
            self.assertEqual(labs, {"benign", "malicious"}, s)
        self.assertEqual(splits.check_contamination(ex), [])
        again = [dict(e, split=dict(e["split"], name=None)) for e in ex]
        splits.assign(again, {"train": 0.7, "dev": 0.15, "test": 0.15}, "group_stratified")
        self.assertEqual([e["split"]["name"] for e in again], [e["split"]["name"] for e in ex])  # deterministic


class SampleTests(unittest.TestCase):
    def _log(self, d):
        p = os.path.join(d, "conn.log.labeled")
        with open(p, "w") as f:
            f.write("#separator \\x09\n#fields\tts\tuid\ttunnel_parents   label   detailed-label\n")
            for i in range(1000):
                f.write(f"{i}\tC{i}\t-   Malicious   PartOfAHorizontalPortScan\n")
                if i % 100 == 0:
                    f.write(f"{i}.5\tB{i}\t-   Benign   -\n")
            f.write("#close\t2026-11-19\n")
        return p

    def test_per_label_reservoir_keeps_rare_class_and_is_deterministic(self):
        from heqkdata import sample
        with tempfile.TemporaryDirectory() as d:
            src = self._log(d)
            a, b = os.path.join(d, "a"), os.path.join(d, "b")
            info = sample.zeek_per_label(src, a, 50, name="x")
            sample.zeek_per_label(src, b, 50, name="x")
            with open(a, "rb") as fa, open(b, "rb") as fb:
                self.assertEqual(fa.read(), fb.read())
            self.assertEqual(info["label_counts"], {"Benign/-": 10, "Malicious/PartOfAHorizontalPortScan": 1000})
            self.assertEqual(info["sample"]["kept"], {"Benign/-": 10, "Malicious/PartOfAHorizontalPortScan": 50})
            with open(a) as f:
                lines = f.read().splitlines()
            self.assertTrue(lines[0].startswith("#separator") and lines[1].startswith("#fields"))
            self.assertTrue(lines[-1].startswith("#close"))
            ts = [float(x.split("\t")[0]) for x in lines[2:-1]]
            self.assertEqual(ts, sorted(ts))  # original order kept
            self.assertEqual(len(ts), 60)


if __name__ == "__main__":
    unittest.main()
