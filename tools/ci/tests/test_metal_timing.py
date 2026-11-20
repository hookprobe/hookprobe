"""Self-tests of the g6 metal timing ratchet (tools/ci/metal_timing.py, ADR 0067 D1/D2)."""
import unittest

import metal_timing as mt

# the two lines of the 2026-11-20 trial boot on the bench CM5 (image am22F)
BOOT = """
 [P10-B] something else
 [IDS-BENCH] packet::verdict ns/pkt (all detection tiers, 2000 iters each): tcp-data-1400=342 tcp-ack=335 udp-dns=322 ipv6-tcp-1274=207 arp=95 | mix avg=322 ns -> 3105 kpps/core (34776 Mbps at 1400 B)
 [IDS-TIERS] tcp-data ns per tier: parse=11 l2-stateful=30 l2=30 flow=68 scan=30 conn-rate=15 resource-shed=28 ja4=4 tcp-flags=36 l4-rules=52 | sum=304
"""


def boot(mix, total):
    return {"ids.mix": mix, "tier.sum": total}


class MetalTiming(unittest.TestCase):
    def test_parses_both_lines(self):
        b = mt.parse_boot(BOOT)
        self.assertEqual(b["ids.mix"], 322)
        self.assertEqual(b["ids.tcp-data-1400"], 342)
        self.assertEqual(b["ids.arp"], 95)
        self.assertEqual(b["tier.l4-rules"], 52)
        self.assertEqual(b["tier.l2-stateful"], 30)
        self.assertEqual(b["tier.sum"], 304)
        self.assertNotIn("ids.iters", b)  # nothing from the text before the colon

    def test_a_log_without_the_lines_gives_nothing(self):
        self.assertEqual(mt.parse_boot("boot\n[IDS-BENCH] truncated"), {})

    def test_median_over_boots(self):
        med = mt.medians([boot(320, 300), boot(340, 310), boot(1000, 305)])
        self.assertEqual(med, {"ids.mix": 340, "tier.sum": 305})  # one slow boot does not decide

    def test_within_tolerance_passes_and_above_fails(self):
        base = {"tolerance_pct": 8, "timings": {"ids.mix": {"max_ns": 400}}}
        self.assertEqual(mt.check(base, {"ids.mix": 432}), [])  # exactly +8 %
        fails = mt.check(base, {"ids.mix": 433})
        self.assertEqual(len(fails), 1)
        self.assertIn("above", fails[0])

    def test_missing_timing_fails_and_unbaselined_is_ignored(self):
        base = {"timings": {"ids.mix": {"max_ns": 400}}}
        self.assertEqual(len(mt.check(base, {"tier.sum": 1})), 1)
        self.assertEqual(mt.check(base, {"ids.mix": 300, "tier.new": 99999}), [])


if __name__ == "__main__":
    unittest.main()
