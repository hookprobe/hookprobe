# SPDX-License-Identifier: AGPL-3.0-only
"""Regressions for the four open findings of the 2026-11-19 review (#1330): CIC flow keys, superseded
acquisitions and collection membership in build(), the line cap in safeio, and Zeek label columns."""
import io
import json
import os
import tempfile
import time
import unittest

from helpers import Sandbox
from heqkdata import export, normalize, registry, safeio, sample
from heqkdata.adapters import Ctx, cicflowmeter_csv
from heqkdata.store import Store

CIC_HEAD = "Flow ID,Source IP,Source Port,Destination IP,Destination Port,Protocol,Timestamp,Flow Duration," \
           "Total Fwd Packets,Total Backward Packets,Total Length of Fwd Packets,Total Length of Bwd Packets,Label\n"
FID = "192.0.2.5-198.51.100.3-50000-80-6"


class CicRepeatedFlowIds(unittest.TestCase):
    """FlowID@Timestamp is not unique in CIC-IDS: distinct flows were dropped as duplicates."""

    def _records(self, rows):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "cic.csv")
            with open(p, "w") as f:
                f.write(CIC_HEAD + "".join(rows))
            sb = Sandbox()
            self.addCleanup(sb.close)
            reg = registry.Registry(sb.reg)
            src = reg.source("f-cic")
            ctx = Ctx(src, {"acquisition_id": "a" * 64, "fetched_at": "2026-11-19T00:00:00.000Z", "source_id": "f-cic",
                            "license_id": src["license_id"]}, "cicflowmeter_csv", cicflowmeter_csv.VERSION, b"k" * 32)
            return [r for r in cicflowmeter_csv.parse(p, ctx) if isinstance(r, dict)]

    def test_same_flow_id_and_timestamp_different_flows_are_kept(self):
        rows = [f"{FID},192.0.2.5,50000,198.51.100.3,80,6,2017-07-07 03:30:00,1500000,10,8,1200,5400,BENIGN\n",
                f"{FID},192.0.2.5,50000,198.51.100.3,80,6,2017-07-07 03:30:00,90,1,0,0,0,BENIGN\n"]
        recs = self._records(rows)
        self.assertEqual(len({r["record_id"] for r in recs}), 2)

    def test_byte_identical_rows_still_collapse(self):
        row = f"{FID},192.0.2.5,50000,198.51.100.3,80,6,2017-07-07 03:30:00,90,1,0,0,0,BENIGN\n"
        recs = self._records([row, row])
        self.assertEqual(len({r["record_id"] for r in recs}), 1)


class BuildInputs(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.addCleanup(self.sb.close)
        self.reg = registry.Registry(self.sb.reg)
        self.st = Store(self.sb.data)

    def _register(self, top, names):
        d = os.path.join(self.sb.dir, top, "feed")  # same parent dir name -> same stored filename
        os.makedirs(d)
        p = os.path.join(d, "list.txt")
        with open(p, "w") as f:
            f.write("".join(n + "\n" for n in names))
        acq = self.st.register(self.reg, "f-dga", p, "commercial_training")
        normalize.normalize(self.st, self.reg, acq)
        return acq

    def _qnames(self, manifest_dir):
        out = set()
        for fn in os.listdir(os.path.join(manifest_dir, "examples")):
            if fn.startswith("dns_intelligence."):
                with open(os.path.join(manifest_dir, "examples", fn)) as f:
                    for ln in f:
                        out |= {r["body"]["qname"] for r in json.loads(ln)["input"]["records"]}
        return out

    def test_refetch_of_same_file_supersedes_older(self):
        old = self._register("v1", ["oldxjw3kq9vzt2l.example", "sharedq8zv3kx.example"])
        time.sleep(0.01)
        new = self._register("v2", ["newm4kq8vz3xtp.example", "sharedq8zv3kx.example"])
        self.assertEqual(old["filename"], new["filename"])
        out, manifest, _ = export.build(self.st, self.reg, "commercial_training", collections=["dns_intelligence"],
                                        out_root=os.path.join(self.sb.dir, "b"))
        names = self._qnames(out)
        self.assertIn("newm4kq8vz3xtp.example", names)
        self.assertNotIn("oldxjw3kq9vzt2l.example", names)
        self.assertEqual(manifest["excluded"].get("superseded_acquisition:f-dga"), 2)
        self.assertEqual([a["acquisition_id"] for a in manifest["acquisitions"]], [new["acquisition_id"]])

    def test_collection_membership(self):
        self.assertIn("f-cic", self.reg.collection_sources("network_intelligence"))
        self.assertNotIn("f-cic", self.reg.collection_sources("dns_intelligence"))
        self.assertIn("f-dga", self.reg.collection_sources("dns_intelligence"))


class MembershipAgreement(unittest.TestCase):
    def test_check_flags_one_sided_membership(self):
        sb = Sandbox()
        self.addCleanup(sb.close)
        reg = registry.Registry(sb.reg)
        self.assertEqual(reg.check(), [])
        reg.collections["dns_intelligence"]["sources"].append("f-cic")
        reg.sources["f-tranco"]["collections"] = ["dns_intelligence", "network_intelligence"]
        probs = reg.check()
        self.assertTrue(any("lists f-cic" in p for p in probs), probs)
        self.assertTrue(any("f-tranco names collection network_intelligence" in p for p in probs), probs)


class LineCap(unittest.TestCase):
    def setUp(self):
        self.old = safeio.MAX_LINE
        safeio.MAX_LINE = 64
        self.addCleanup(setattr, safeio, "MAX_LINE", self.old)

    def test_newline_free_stream_raises_without_reading_it_whole(self):
        class Counting(io.StringIO):
            read_chars = 0

            def readline(self, size=-1):
                line = super().readline(size)
                Counting.read_chars += len(line)
                return line

        s = Counting("x" * 10_000)
        with self.assertRaises(safeio.UnsafeContent):
            list(safeio.lines(s))
        self.assertLessEqual(Counting.read_chars, 65)

    def test_csv_rows_capped_too(self):
        with self.assertRaises(safeio.UnsafeContent):
            list(safeio.csv_rows(io.StringIO("a," * 1000)))

    def test_short_lines_pass(self):
        self.assertEqual(list(safeio.lines(io.StringIO("a\r\nb\n"))), [(1, "a"), (2, "b")])

    def test_plain_file_bounded_by_own_size_gzip_by_cap(self):
        # IoT-23 39-1 is a 10.9 GB plain conn.log: the 8 GiB cap is for decompression, not for plain files
        import gzip
        body = "line\n" * 100
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "big.log")
            with open(p, "w") as f:
                f.write(body)
            with safeio.open_text(p, max_bytes=10) as f:
                self.assertEqual(f.read(), body)
            g = p + ".gz"
            with gzip.open(g, "wt") as f:
                f.write(body)
            with self.assertRaises(safeio.UnsafeContent), safeio.open_text(g, max_bytes=10) as f:
                f.read()


class ZeekTabLabelColumns(unittest.TestCase):
    def test_label_columns_as_own_tab_fields(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "conn.log.labeled")
            with open(src, "w") as f:
                f.write("#fields\tts\tuid\ttunnel_parents\tlabel\tdetailed-label\n")
                for i in range(30):
                    f.write(f"{i}\tC{i}\t-\tMalicious\tPartOfAHorizontalPortScan\n")
                for i in range(3):
                    f.write(f"{i}.5\tB{i}\t-\tBenign\t-\n")
            info = sample.zeek_per_label(src, os.path.join(d, "out"), 10, name="t")
        self.assertEqual(info["label_counts"], {"Benign/-": 3, "Malicious/PartOfAHorizontalPortScan": 30})
        self.assertEqual(info["sample"]["kept"], {"Benign/-": 3, "Malicious/PartOfAHorizontalPortScan": 10})

    def test_iot23_space_tail_unchanged(self):
        self.assertEqual(sample._label_key(b"1\tC1\t-   Malicious   Okiru\n", None), ("Malicious", "Okiru"))
        cols = sample._label_cols(b"#fields\tts\tuid\ttunnel_parents   label   detailed-label\n")
        self.assertIsNone(cols)


if __name__ == "__main__":
    unittest.main()
