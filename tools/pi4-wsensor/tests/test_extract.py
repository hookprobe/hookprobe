"""Unit tests for wsensor_extract.rows_to_events (pure transform; no tshark needed).

Rows are synthetic tshark `-T fields` rows built with the same FIELDS order the extractor uses,
with value formats copied from real Wireshark 4.4 output on the bench Pi (booleans as
True/False, type_subtype as 0x00NN, multi-occurrence fields comma-aggregated).
Run: python3 -m unittest discover -s tools/pi4-wsensor/tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import wsensor_extract as wx  # noqa: E402

HASH = wx.SsidHasher(b"test-salt")
CM5 = "76:0d:02:f8:d2:da"


def row(**kw):
    r = [""] * len(wx.FIELDS)
    defaults = {"frame.time_epoch": "1731570020.5", "radiotap.channel.freq": "5180",
                "radiotap.dbm_antsignal": "-49"}
    for k, v in {**defaults, **kw}.items():
        r[wx.IDX[k]] = v
    return r


def beacon(**kw):
    base = {"wlan.fc.type_subtype": "0x0008", "wlan.bssid": CM5, "wlan.sa": CM5,
            "wlan.da": "ff:ff:ff:ff:ff:ff", "wlan.ssid": "HookProbe-Setup-R3Q1",
            "wlan.fixed.capabilities.privacy": "True", "wlan.rsn.akms.type": "2,8",
            "wlan.rsn.pcs.type": "4", "wlan.rsn.gcs.type": "4",
            "wlan.rsn.capabilities.mfpc": "True", "wlan.rsn.capabilities.mfpr": "False",
            "wlan.country_info.code": "RO"}
    base.update(kw)
    return row(**base)


def events(rows):
    return list(wx.rows_to_events(rows, "pi-test", HASH, "t.pcapng"))


class BeaconTests(unittest.TestCase):
    def test_cm5_transition_mode_matches_m0_observation(self):
        (ev,) = events([beacon()])
        self.assertEqual(ev["kind"], "beacon")
        self.assertEqual(ev["security"], "WPA2/WPA3-transition")
        self.assertEqual(ev["akm"], ["PSK", "SAE"])
        self.assertEqual(ev["pairwise"], ["CCMP-128"])
        self.assertIs(ev["pmf_capable"], True)
        self.assertIs(ev["pmf_required"], False)
        self.assertEqual(ev["channel"], 36)
        self.assertEqual(ev["dbm"], -49)
        self.assertEqual(ev["classification"], "observed")
        self.assertEqual(ev["country"], "RO")

    def test_security_classes(self):
        cases = [
            ({"wlan.rsn.akms.type": "8"}, "WPA3-SAE"),
            ({"wlan.rsn.akms.type": "2"}, "WPA2-PSK"),
            ({"wlan.rsn.akms.type": "1"}, "WPA2/3-Enterprise"),
            ({"wlan.rsn.akms.type": "18"}, "OWE"),
            ({"wlan.rsn.akms.type": "", "wlan.wfa.ie.type": "1"}, "WPA1"),
            ({"wlan.rsn.akms.type": "", "wlan.fixed.capabilities.privacy": "True"}, "WEP"),
            ({"wlan.rsn.akms.type": "", "wlan.fixed.capabilities.privacy": "False"}, "OPEN"),
        ]
        for kw, want in cases:
            with self.subTest(want=want):
                (ev,) = events([beacon(**kw)])
                self.assertEqual(ev["security"], want)

    def test_hidden_ssid_zero_filled(self):
        (ev,) = events([beacon(**{"wlan.ssid": "00" * 12})])
        self.assertTrue(ev["hidden"])
        self.assertEqual(ev["ssid"], "")

    def test_wps_and_h2e(self):
        (ev,) = events([beacon(**{"wps.config_methods": "0x0188", "wlan.rsnx.sae_hash_to_element": "True"})])
        self.assertTrue(ev["wps"])
        self.assertIs(ev["sae_h2e"], True)


class PrivacyTests(unittest.TestCase):
    def test_probe_request_ssid_is_hashed_never_clear(self):
        (ev,) = events([row(**{"wlan.fc.type_subtype": "0x0004", "wlan.sa": "da:11:22:33:44:55",
                               "wlan.ssid": "Grandmas-Home-WiFi"})])
        self.assertEqual(ev["kind"], "probe_req")
        self.assertNotIn("ssid", ev)
        self.assertEqual(ev["ssid_len"], len("Grandmas-Home-WiFi"))
        self.assertEqual(len(ev["ssid_hash"]), 16)
        self.assertTrue(ev["sa_randomized"])
        self.assertNotIn("Grandmas", repr(ev))

    def test_probe_hash_is_salted_and_stable(self):
        a = wx.SsidHasher(b"s1")("x")["ssid_hash"]
        self.assertEqual(a, wx.SsidHasher(b"s1")("x")["ssid_hash"])
        self.assertNotEqual(a, wx.SsidHasher(b"s2")("x")["ssid_hash"])

    def test_wildcard_probe(self):
        (ev,) = events([row(**{"wlan.fc.type_subtype": "0x0004", "wlan.sa": "00:11:22:33:44:55"})])
        self.assertTrue(ev["wildcard"])
        self.assertFalse(ev["sa_randomized"])

    def test_data_frames_become_counters_only(self):
        rows = [row(**{"wlan.fc.type_subtype": "0x0028", "wlan.bssid": CM5, "wlan.sa": "dc:a6:32:a4:b6:88",
                       "radiotap.dbm_antsignal": "-51"}) for _ in range(5)]
        rows.append(row(**{"wlan.fc.type_subtype": "0x0020", "wlan.bssid": CM5, "wlan.sa": CM5}))
        evs = events(rows)
        self.assertEqual([e["kind"] for e in evs], ["data_summary"])
        pairs = {(p["bssid"], p["sta"]): p["frames"] for p in evs[0]["pairs"]}
        self.assertEqual(pairs[(CM5, "dc:a6:32:a4:b6:88")], 5)
        self.assertEqual(pairs[(CM5, CM5)], 1)


class MgmtEventTests(unittest.TestCase):
    def test_deauth_reason(self):
        (ev,) = events([row(**{"wlan.fc.type_subtype": "0x000c", "wlan.bssid": CM5, "wlan.sa": CM5,
                               "wlan.da": "dc:a6:32:a4:b6:88", "wlan.fixed.reason_code": "0x0007"})])
        self.assertEqual(ev["kind"], "deauth")
        self.assertEqual(ev["reason_code"], 7)

    def test_auth_sae(self):
        (ev,) = events([row(**{"wlan.fc.type_subtype": "0x000b", "wlan.fixed.auth.alg": "3",
                               "wlan.fixed.status_code": "0x0000"})])
        self.assertEqual((ev["auth_alg"], ev["status_code"]), (3, 0))

    def test_control_frames_ignored_and_short_rows_padded(self):
        self.assertEqual(events([row(**{"wlan.fc.type_subtype": "0x001d"})]), [])
        short = beacon()[:12]
        (ev,) = events([short])
        self.assertEqual(ev["kind"], "beacon")

    def test_event_schema_fields(self):
        (ev,) = events([beacon()])
        for k in ("event_id", "ts", "sensor", "iface_role", "channel", "bssid", "classification", "source"):
            self.assertIn(k, ev)

    def test_freq_to_channel(self):
        self.assertEqual([wx.freq_to_channel(f) for f in (2412, 2437, 2484, 5180, 5745, 5955)],
                         [1, 6, 14, 36, 149, 1])


if __name__ == "__main__":
    unittest.main()
