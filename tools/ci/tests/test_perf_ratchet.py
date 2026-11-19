"""Self-tests of the g2 performance ratchet (tools/ci/perf_ratchet.py, ADR 0067 D1/D2)."""
import unittest

import perf_ratchet as pr

LOG = """
 [P-nat-index] PASS — NAT table 4096 mappings
 [PERF] nat_newflow_scan_max=4096
 [PERF] nat_rewrite_csum_bytes=1500\r
 [PERF] nat_newflow_scan_max=32
 not a counter [PERF] broken = 7
"""


class PerfRatchet(unittest.TestCase):
    def test_parse_takes_the_last_value_and_ignores_malformed_lines(self):
        self.assertEqual(pr.parse_log(LOG), {"nat_newflow_scan_max": 32, "nat_rewrite_csum_bytes": 1500})

    def test_within_bounds_passes(self):
        base = {"nat_newflow_scan_max": {"max": 32}, "nat_rewrite_csum_bytes": {"max": 1500}}
        self.assertEqual(pr.check(base, pr.parse_log(LOG)), [])

    def test_worse_than_max_fails(self):
        fails = pr.check({"a": {"max": 10}}, {"a": 11})
        self.assertEqual(len(fails), 1)
        self.assertIn("worse", fails[0])

    def test_worse_than_min_fails(self):
        self.assertEqual(len(pr.check({"a": {"min": 8}}, {"a": 7})), 1)
        self.assertEqual(pr.check({"a": {"min": 8}}, {"a": 8}), [])

    def test_missing_counter_fails(self):
        fails = pr.check({"a": {"max": 10}}, {})
        self.assertEqual(len(fails), 1)
        self.assertIn("not printed", fails[0])

    def test_unbaselined_counter_fails(self):
        fails = pr.check({}, {"new": 1})
        self.assertEqual(len(fails), 1)
        self.assertIn("no baseline", fails[0])

    def test_entry_needs_exactly_one_bound(self):
        self.assertEqual(len(pr.check({"a": {}}, {"a": 1})), 1)
        self.assertEqual(len(pr.check({"a": {"max": 1, "min": 1}}, {"a": 1})), 1)


if __name__ == "__main__":
    unittest.main()
