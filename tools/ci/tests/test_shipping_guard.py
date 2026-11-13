"""W4 (task #55): the shipping-flavour guard (tools/ci/shipping_guard.py) — pure parsing + policy, no cargo."""
import os
import sys
import tempfile
import unittest

CI = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path[:0] = [CI]
import shipping_guard as sg  # noqa: E402

CLEAN = """kernel v0.1.0 (/src/os/kernel/kernel) |apmc,apmode,appersist,cm5,hboot,hsh,mcserve,securechannel,wpa3|
arch-aarch64 v0.1.0 (/src/os/kernel/arch-aarch64) |cm5,hboot,wifi-pmkid-fix,wpa3|
smoltcp v0.13.1 |medium-ethernet,proto-dhcpv4,socket-dhcpv4|
hal v0.1.0 (/src/os/kernel/hal) ||
"""


class ShippingGuard(unittest.TestCase):
    def run_tree(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write(text)
        try:
            return sg.main(["--tree", f.name, "--features", "x"])
        finally:
            os.unlink(f.name)

    def test_clean_graph_passes(self):
        self.assertEqual(self.run_tree(CLEAN), 0)
        self.assertIn(("smoltcp", "proto-dhcpv4"), sg.active(CLEAN))  # `dhcp` must match whole names only

    def test_dev_feature_in_any_crate_fails(self):
        for crate, feat in [("kernel", "hsh-dev"), ("kernel", "securechannel-selftest"), ("arch-aarch64", "wpa3probe"),
                            ("arch-aarch64", "wifi-pmkid-noexpire"), ("kernel", "p15-bench"), ("kernel", "crashtest"),
                            ("kernel", "wifiheal-bench"), ("kernel", "artstore-bench")]:
            bad = CLEAN + f"{crate} v0.1.0 (/src/x) |cm5,{feat}|\n"
            self.assertIn((crate, feat), sg.active(bad))
            self.assertEqual(self.run_tree(bad), 1, feat)

    def test_unresolvable_graph_is_never_clean(self):
        self.assertEqual(self.run_tree(""), 2)
        self.assertEqual(self.run_tree("error: package `kernel` not found\n"), 2)

    def test_shipping_list_itself(self):
        feats = sg.shipping_features().split(",")
        self.assertTrue(feats and "apmc" in feats)
        self.assertFalse(set(feats) & set(sg.FORBIDDEN), "a development-only feature is listed as shipping")
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("# comment\nhboot, apmc\nwpa3 ; rm -rf /\n")
        try:
            with self.assertRaises(ValueError):
                sg.shipping_features(f.name)
        finally:
            os.unlink(f.name)


if __name__ == "__main__":
    unittest.main()
