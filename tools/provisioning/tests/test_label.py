import os
import shutil
import stat
import tempfile
import unittest

from common import PSK, QR, SSID, UNIT, Quiet
from hqprov import label, owner, qr


class LabelTest(Quiet):
    def test_svg_contents(self):
        svg = label.label_svg("HookProbe <CM5> & co", UNIT, SSID, PSK, QR, "fw abc")
        self.assertIn(SSID, svg)
        self.assertIn(PSK, svg)
        self.assertIn(UNIT, svg)
        self.assertIn("HookProbe &lt;CM5&gt; &amp; co", svg)          # escaped
        self.assertNotIn("HookProbe <CM5>", svg)
        self.assertRegex(svg, r"<path d=\"M")                          # the QR
        self.assertIn("10.99.0.1", svg)

    def test_qr_encodes_the_wifi_payload(self):
        mat, src = label.qr_matrix(QR)
        self.assertEqual(len(mat), len(mat[0]))
        if src == "builtin":
            self.assertEqual(mat, qr.encode(QR))
        self.assertEqual(QR, f"WIFI:T:WPA;S:{SSID};P:{PSK};;")           # the standard Wi-Fi QR form

    def test_owner_key_is_not_on_the_label(self):
        tok = owner.mint_token()
        with tempfile.TemporaryDirectory() as d:
            files = label.write_label_files(d, "m", UNIT, SSID, PSK, QR, tok)
            lab = open(os.path.join(d, "label.svg")).read()
            card = open(os.path.join(d, "owner-card.svg")).read()
            self.assertNotIn(tok, lab)
            self.assertIn(tok, card)
            self.assertNotIn(PSK, card)
            for f in files:
                self.assertEqual(stat.S_IMODE(os.stat(f).st_mode), 0o600, f)

    @unittest.skipUnless(label.png_converter() is None and any(shutil.which(x) for x in ("rsvg-convert", "inkscape", "convert")),
                         "no SVG->PNG converter")
    def test_png_when_converter_exists(self):
        os.environ.pop("HQPROV_NO_PNG", None)
        try:
            with tempfile.TemporaryDirectory() as d:
                files = label.write_label_files(d, "m", UNIT, SSID, PSK, QR, owner.mint_token())
                self.assertTrue(any(f.endswith("label.png") for f in files))
                self.assertEqual(open(os.path.join(d, "label.png"), "rb").read(8), b"\x89PNG\r\n\x1a\n")
        finally:
            os.environ["HQPROV_NO_PNG"] = "1"

    def test_token_format(self):
        t = owner.mint_token()
        self.assertRegex(t, owner.TOKEN_RE)
        self.assertNotEqual(t, owner.mint_token())
        b = owner.owner_file_bytes(t)
        self.assertEqual(len(b), 128)
        self.assertTrue(owner.token_matches(b, t))
        self.assertFalse(owner.token_matches(b, t[:-1] + ("A" if t[-1] != "A" else "B")))
        self.assertIsNone(owner.parse_owner_file(b"HQOWN0 unclaimed".ljust(127) + b"\n"))


if __name__ == "__main__":
    unittest.main()
