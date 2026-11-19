# SPDX-License-Identifier: AGPL-3.0-only
"""Regressions for the 2026-11-19 code review of the intel-data foundation (#1321)."""
import os
import shutil
import sqlite3
import tempfile
import unittest

from helpers import FIX, Sandbox
from heqkdata import builders, registry
from heqkdata.adapters import hookprobe_ioc_v1 as iocv1
from heqkdata.store import Store


class EicarIsACanary(unittest.TestCase):
    """The EICAR test file in the hookprobe-ioc-v1 snapshot was labelled malicious / botnet_cc."""

    def test_eicar_by_family_source_and_digest(self):
        snap = {"value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "ioc_type": "sha256",
                "family": "eicar-test-canary", "source": "EICAR (public AV-test standard, eicar.org)"}
        self.assertTrue(iocv1._is_canary(snap))
        self.assertTrue(iocv1._is_canary({"value": "44D88612FEA8A8F36DE82E1278ABB02F", "source": "some feed"}))
        self.assertTrue(iocv1._is_canary({"value": "x", "family": "eicar"}))

    def test_real_indicator_is_not(self):
        self.assertFalse(iocv1._is_canary({"value": "162.243.103.246", "family": "Emotet", "source": "abuse.ch Feodo Tracker"}))


class SocFalsePositiveTextIsFilled(unittest.TestCase):
    """False-positive considerations shipped the literal '{n}' into SFT targets."""

    def test_no_template_braces_in_targets(self):
        for ex in builders.build_soc_synthetic(n_per_scenario=2):
            fps = ex["target"]["false_positive_considerations"] if "target" in ex else []
            for s in fps:
                self.assertNotIn("{", s, s)
                self.assertNotIn("}", s, s)


class StoreKeys(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.addCleanup(self.sb.close)
        self.reg = registry.Registry(self.sb.reg)
        self.st = Store(self.sb.data)

    def _copy(self, rel, subdir):
        d = os.path.join(self.sb.dir, subdir)
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, os.path.basename(rel))
        shutil.copyfile(os.path.join(FIX, rel), p)
        return p

    def test_same_bytes_from_another_dir_is_a_duplicate_not_a_crash(self):
        a = self.st.register(self.reg, "f-dga", self._copy("dga/necurs.txt", "one"), "live_intel")
        b = self.st.register(self.reg, "f-dga", self._copy("dga/necurs.txt", "two"), "live_intel")
        self.assertEqual(a["acquisition_id"], b["acquisition_id"])
        self.assertEqual(a["filename"], b["filename"])  # the first registration stands
        raw = self.st.raw_dir("f-dga", a["acquisition_id"])
        self.assertEqual(sorted(os.listdir(raw)), sorted([a["filename"], "acquisition.json"]))  # no orphan

    def test_same_bytes_for_two_sources_keeps_both_rows(self):
        p = os.path.join(FIX, "dga/necurs.txt")
        self.st.register(self.reg, "f-dga", p, "live_intel")
        self.st.register(self.reg, "f-umudga", p, "live_intel")
        self.assertEqual(len(self.st.acquisitions("f-dga")), 1)
        self.assertEqual(len(self.st.acquisitions("f-umudga")), 1)

    def test_old_single_column_key_is_migrated(self):
        root = tempfile.mkdtemp(prefix="heqk-intel-mig-")
        self.addCleanup(shutil.rmtree, root, True)
        db = sqlite3.connect(os.path.join(root, "catalog.sqlite"))
        db.executescript("""
            CREATE TABLE acquisitions (acquisition_id TEXT PRIMARY KEY, source_id TEXT NOT NULL, license_id TEXT NOT NULL,
              url TEXT, filename TEXT NOT NULL, bytes INTEGER NOT NULL, fetched_at TEXT NOT NULL, method TEXT NOT NULL);
            INSERT INTO acquisitions VALUES ('d1','s1','l','u','f',1,'2026-11-18T00:00:00Z','register');
        """)
        db.close()
        st = Store(root)
        pk = [r[1] for r in st.db.execute("PRAGMA table_info(acquisitions)") if r[5]]
        self.assertEqual(sorted(pk), ["acquisition_id", "source_id"])
        self.assertEqual(st.db.execute("SELECT count(*) FROM acquisitions").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
