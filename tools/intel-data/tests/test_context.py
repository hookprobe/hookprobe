# SPDX-License-Identifier: AGPL-3.0-only
"""context.py + windows remote_context + lookup tables. Fixtures are SYNTHETIC (RFC 5737/3849 ranges)."""
import io
import json
import os
import shutil
import unittest

from helpers import FIX, Sandbox
from heqkdata import context, lookup, registry, windows
from heqkdata.store import Store
from test_windows import HEAD, H0, row

C = os.path.join(FIX, "context")


class Context(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.addCleanup(self.sb.close)
        self.reg = registry.Registry(self.sb.reg)
        self.st = Store(self.sb.data)
        for sid, f in (("f-asn", "ip2asn-combined.tsv.gz"), ("f-wl", "warninglists.zip")):
            d = os.path.join(self.sb.dir, "in", sid)
            os.makedirs(d)
            shutil.copyfile(os.path.join(C, f), os.path.join(d, f))
            self.st.register(self.reg, sid, os.path.join(d, f), "commercial_training")
        self.tables = context.load(self.st, self.reg, "commercial_training", ["f-asn", "f-wl"])

    def test_tables(self):
        asn, _ = self.tables["f-asn"]
        self.assertEqual(asn.lookup("198.51.100.53"), {"asn": 64500, "as_name": "EXAMPLE-NET Synthetic AS", "country": "ZZ"})
        self.assertIsNone(asn.lookup("203.0.113.5"))  # AS 0 = not routed
        self.assertEqual(asn.lookup("2001:db8::5")["asn"], 64501)
        wl, _ = self.tables["f-wl"]
        self.assertEqual(sorted(wl.lists), ["public-dns-v4", "tor-exit-nodes"])  # vpn (X4BNet) and ranking dropped
        self.assertEqual(wl.lookup("198.51.100.53"), ["Synthetic public DNS"])
        self.assertEqual(wl.lookup("198.51.100.7"), [])  # tor list: current snapshot, never on captures
        self.assertEqual(wl.lookup("198.51.100.7", for_capture=False), ["Synthetic Tor exits"])

    def test_windows_carry_remote_context_by_pseudonym_only(self):
        d = os.path.join(self.sb.dir, "cap", "Synthetic-C", "bro")
        os.makedirs(d)
        p = os.path.join(d, "conn.log.labeled")
        with open(p, "w") as f:
            f.write(HEAD + row(H0 + 1, "K1", "192.168.1.5", 4000, "198.51.100.53", 53)
                    + row(H0 + 2, "K2", "192.168.1.5", 4001, "224.0.0.251", 5353))
        acq = self.st.register(self.reg, "f-iot23", p, "commercial_training")
        buf = io.StringIO()
        windows.host_windows(self.st, self.reg, acq, buf, "dev", tables=self.tables)
        w = json.loads(buf.getvalue().splitlines()[0])
        rc = w["remote_context"]
        self.assertEqual(list(rc), [w["events"][0]["dst_ip"]])  # multicast carries no identity: no entry
        ctx = rc[w["events"][0]["dst_ip"]]
        self.assertEqual((ctx["asn"], ctx["country"], ctx["warninglists"]), (64500, "ZZ", ["Synthetic public DNS"]))
        self.assertNotIn("198.51.100.53", buf.getvalue())  # the real address never leaves the export

    def test_lookup_ships_the_same_tables(self):
        out = os.path.join(self.sb.dir, "lk")
        d, man = lookup.build(self.st, self.reg, "commercial_training", out_root=out, cve_sources=(),
                              attack_sources={"f-attack": "enterprise"}, kev_source="none", weakness_sources=(),
                              context_sources=("f-asn", "f-wl"))
        names = {f["file"] for f in man["files"]}
        self.assertTrue({"asn_ranges.tsv", "warninglists.jsonl"} <= names)
        with open(os.path.join(d, "warninglists.jsonl")) as f:
            wl = {json.loads(l)["id"]: json.loads(l) for l in f}
        self.assertTrue(wl["tor-exit-nodes"]["not_for_captures"])
        self.assertEqual(man["context"]["f-wl"]["lists_dropped"], {
            "tranco": "third-party ranking or vendor list with its own terms",
            "vpn-ipv4": "X4BNet-derived (MIT notice, not CC0)"})


if __name__ == "__main__":
    unittest.main()
