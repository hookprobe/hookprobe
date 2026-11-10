"""Serial parsing against recorded (synthesised) fixtures. Marker formats: see fixtures/README.md and
hqprov/serialparse.py (file:line citations into os/kernel)."""
import unittest

from common import MAC, PSK, QR, SSID, TLS_PUB, UNIT, read_fixture, Quiet
from hqprov import serialparse as sp


class ParseTest(Quiet):
    def test_first_boot_identity(self):
        p = sp.parse(read_fixture("boot1.log"))          # CRLF + ANSI reset on purpose
        self.assertEqual(p["wifi_mac"], MAC)
        self.assertEqual(p["setup_ssid"], SSID)
        self.assertEqual(p["setup_psk"], PSK)
        self.assertEqual(p["qr_payload"], QR)
        self.assertEqual(p["tls_pub"], TLS_PUB)
        self.assertEqual(p["owner"], "UNCLAIMED")
        self.assertEqual(p["psk_source"], "the per-device setup credential")
        self.assertEqual(p["ap_bssid"], MAC)
        self.assertEqual(p["secure_boot"], "PASS")
        self.assertTrue(p["hboot_ab"] and p["p10b"] and p["tls_nocert"])
        self.assertEqual(sp.unit_id(sp.require_identity(p)), UNIT)

    def test_second_boot_claimed_and_https(self):
        p = sp.parse(read_fixture("boot2.log"))
        self.assertEqual(p["owner"], "CLAIMED")
        self.assertTrue(p["tls_ready"])
        self.assertEqual(p["setup_psk"], PSK)

    def test_no_srk_unit_is_diagnosed(self):
        p = sp.parse(read_fixture("boot_nosrk.log"))
        self.assertTrue(p["no_ap"] and p["tls_off_nosrk"])
        with self.assertRaises(sp.ParseError) as cm:
            sp.require_identity(p)
        self.assertIn("NOT start", str(cm.exception))

    def test_wifitxt_image_has_no_setup_line(self):
        p = sp.parse(read_fixture("boot_wifitxt.log"))
        self.assertNotIn("setup_psk", p)
        with self.assertRaises(sp.ParseError) as cm:
            sp.require_identity(p)
        self.assertIn("factory image must have neither", str(cm.exception))

    def test_malformed_passphrase_rejected(self):
        bad = read_fixture("boot1.log").replace(PSK, "ABCD-efgh-ijkl-mnop")
        with self.assertRaises(sp.ParseError):
            sp.parse(bad)

    def test_qr_payload_mismatch_rejected(self):
        bad = read_fixture("boot1.log").replace(f"P:{PSK};;", "P:0000-0000-0000-0000;;")
        with self.assertRaises(sp.ParseError):
            sp.parse(bad)

    def test_two_units_in_one_log_rejected(self):
        a = read_fixture("boot1.log")
        b = read_fixture("boot1.log").replace(PSK, "zzzz-zzzz-zzzz-zzzz").replace("zzzz-zzzz-zzzz-zzzz;;", "zzzz-zzzz-zzzz-zzzz;;")
        with self.assertRaises(sp.ParseError):
            sp.parse(a + b)

    def test_non_derived_mac_rejected(self):
        with self.assertRaises(sp.ParseError):
            sp.parse(read_fixture("boot1.log").replace("per-device MAC 02:", "per-device MAC 00:"))

    def test_redact(self):
        t = sp.redact(sp.clean(read_fixture("boot1.log")), [PSK, QR])
        self.assertNotIn(PSK, t)
        self.assertIn("<redacted>", t)
        self.assertIn(SSID.split("-")[0], t)     # the rest of the log is intact


if __name__ == "__main__":
    unittest.main()
