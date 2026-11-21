# SPDX-License-Identifier: AGPL-3.0-only
"""windows.py: host-hour windows for Neuro. All flows below are SYNTHETIC (written by the test, RFC 5737 /
RFC 1918 addresses); no dataset content."""
import io
import json
import os
import unittest

from helpers import Sandbox
from heqkdata import export, registry, windows
from heqkdata.store import Store

HEAD = ("#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\t"
        "orig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\t"
        "resp_pkts\tresp_ip_bytes\ttunnel_parents   label   detailed-label\n")
H0 = 1_525_878_000  # an exact UTC hour boundary (2018-05-09T15:00:00Z)


def row(ts, uid, o, op, r, rp, state="SF", label="Benign", det="-"):
    return (f"{ts:.6f}\t{uid}\t{o}\t{op}\t{r}\t{rp}\ttcp\t-\t1.0\t100\t200\t{state}\t-\t-\t0\tSh\t2\t180\t2\t300\t"
            f"-   {label}   {det}\n")


class Pseudo(unittest.TestCase):
    def test_injective_ranges_and_no_broadcast_octets(self):
        P = windows.Pseudonyms()
        remote = [P.addr(f"203.0.{i // 250}.{i % 250 + 1}") for i in range(1200)]
        self.assertEqual(len(set(remote)), 1200)
        self.assertTrue(remote[0].startswith("198.51.100."))
        self.assertTrue(remote[300].startswith("203.0.113."))
        self.assertTrue(remote[600].startswith("198.18."))
        self.assertFalse(any(a.endswith((".0", ".255")) for a in remote))
        self.assertEqual(P.addr("203.0.0.1"), remote[0])  # stable
        self.assertTrue(P.addr("10.1.2.3").startswith("192.168."))
        self.assertEqual(windows.lan(P.addr("172.16.5.5")), True)
        self.assertEqual(P.addr("224.0.0.251"), "224.0.0.251")
        self.assertEqual(P.addr("255.255.255.255"), "255.255.255.255")

    def test_ipv6_local_addresses_are_lan_hosts(self):
        P = windows.Pseudonyms()
        for ip in ("fe80::5bcc:698e:39d5:cdf", "fd12:3456::1", "FC00::7"):
            self.assertTrue(windows.lan(ip), ip)
            self.assertTrue(P.addr(ip).startswith("192.168."), ip)
        for ip in ("2001:db8::1", "ff02::fb", "::", "0.0.0.0", "198.51.100.1"):
            self.assertFalse(windows.lan(ip), ip)
        self.assertTrue(P.addr("2001:db8::1").startswith("2001:db8::"))

    def test_last_remote_pseudonym_stays_below_255_255_255_0(self):
        total = sum(b * 254 for _, b in windows.REMOTE_POOLS)
        last = windows._alloc(total - 1, windows.REMOTE_POOLS)
        self.assertEqual(last, "255.255.254.254")
        with self.assertRaises(RuntimeError):
            windows._alloc(total, windows.REMOTE_POOLS)

    def test_domains_keep_registered_domain_grouping(self):
        P = windows.Pseudonyms()
        a, b, c = P.domain("a.x.foo.com"), P.domain("b.foo.com"), P.domain("foo.com")
        self.assertEqual(a.split(".", 1)[1], b.split(".", 1)[1])
        self.assertEqual(c, b.split(".", 1)[1])
        self.assertTrue(c.endswith(".example"))
        self.assertEqual(P.domain("a.x.foo.com"), a)


class HostWindows(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.addCleanup(self.sb.close)
        self.reg = registry.Registry(self.sb.reg)
        self.st = Store(self.sb.data)

    def _capture(self, name, rows):
        d = os.path.join(self.sb.dir, "cap", name, "bro")
        os.makedirs(d)
        p = os.path.join(d, "conn.log.labeled")
        with open(p, "w") as f:
            f.write(HEAD + "".join(rows))
        return self.st.register(self.reg, "f-iot23", p, "commercial_training")

    def _windows(self, acq, chunk=0):
        buf = io.StringIO()
        c = windows.host_windows(self.st, self.reg, acq, buf, "dev", chunk)
        return [json.loads(l) for l in buf.getvalue().splitlines()], c

    def test_hosts_orientation_baseline_and_state(self):
        acq = self._capture("Synthetic-1", [
            row(H0 + 10, "C1", "192.168.1.5", 40000, "198.51.100.7", 23, "S0", "Malicious", "PartOfAHorizontalPortScan"),
            row(H0 + 20, "C2", "198.51.100.66", 5555, "192.168.1.5", 22, "REJ"),      # inbound: the LAN host's window
            row(H0 + 30, "C3", "198.51.100.66", 1, "203.0.113.9", 2),                 # remote -> remote: no host
            row(H0 + 3600 + 5, "C4", "192.168.1.5", 40001, "198.51.100.7", 23),       # pair seen the hour before
            row(H0 + 3600 + 6, "C5", "192.168.1.5", 40002, "198.51.100.8", 80),       # new pair
        ])
        lines, c = self._windows(acq)
        self.assertEqual(c["flows_without_lan_host"], 1)
        self.assertEqual([w["hour_utc"] for w in lines], ["2018-05-09T15:00Z", "2018-05-09T16:00Z"])
        first, second = lines
        self.assertEqual(len({w["host"] for w in lines}), 1)
        self.assertTrue(first["host"].startswith("192.168."))
        inbound = first["events"][1]
        self.assertEqual(inbound["dst_ip"], first["host"])  # oriented by initiator, kept in the LAN host's window
        self.assertEqual([e["state"] for e in first["events"]], ["rst", "rst"])
        self.assertEqual(second["events"][0]["state"], "est")
        self.assertEqual(first["labels"], {"Benign": 1, "Malicious/PartOfAHorizontalPortScan": 1})
        self.assertEqual(first["baseline"]["pairs"], [])
        e0 = second["events"][0]
        self.assertEqual(second["baseline"]["pairs"], [[e0["src_ip"], e0["dst_ip"]]])
        self.assertEqual(e0["ts"], "2018-05-09T16:00:05.000Z")
        self.assertEqual(first["events"][0]["detailed_label"], "PartOfAHorizontalPortScan")

    def test_drops_are_counted_by_kind(self):
        acq = self._capture("Synthetic-4", [
            row(H0 + 1, "G1", "0.0.0.0", 68, "255.255.255.255", 67),               # DHCP discover: unattributed
            row(H0 + 2, "G2", "198.51.100.66", 1, "203.0.113.9", 2),              # remote -> remote
            row(H0 + 3, "G3", "fe80::1", 5353, "ff02::fb", 5353),                 # link-local host: kept
        ])
        lines, c = self._windows(acq)
        self.assertEqual((c["dropped_unattributed"], c["dropped_remote_to_remote"]), (1, 1))
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0]["host"].startswith("192.168."))
        self.assertEqual(lines[0]["events"][0]["dst_ip"], "ff02::fb")

    def test_baseline_forgets_after_24_hours(self):
        acq = self._capture("Synthetic-2", [
            row(H0 + 1, "D1", "192.168.1.5", 1, "198.51.100.7", 23),
            row(H0 + 25 * 3600 + 1, "D2", "192.168.1.5", 2, "198.51.100.7", 23),
        ])
        lines, _ = self._windows(acq)
        self.assertEqual(lines[1]["baseline"]["pairs"], [])

    def test_chunks_share_window_id_and_carry_every_flow(self):
        acq = self._capture("Synthetic-3", [row(H0 + i, f"E{i}", "192.168.1.5", 1000 + i, "198.51.100.7", 23)
                                            for i in range(5)])
        lines, _ = self._windows(acq, chunk=2)
        self.assertEqual([w["chunk"] for w in lines], [[0, 3], [1, 3], [2, 3]])
        self.assertEqual(len({w["window_id"] for w in lines}), 1)
        self.assertEqual(sum(len(w["events"]) for w in lines), 5)
        self.assertEqual(lines[0]["labels"], {"Benign": 5})
        self.assertEqual(lines[1]["labels"], {})


class ExportRules(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.addCleanup(self.sb.close)
        self.reg = registry.Registry(self.sb.reg)
        self.st = Store(self.sb.data)

    def _register(self, name, sample=None):
        d = os.path.join(self.sb.dir, "cap", name, "bro")
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, "conn.log.labeled")
        with open(p, "w") as f:
            f.write(HEAD + "".join(row(H0 + i, f"{name}{i}", "192.168.1.5", 1000 + i, "198.51.100.7", 23)
                                   for i in range(4)))
        return self.st.register(self.reg, "f-iot23", p, "commercial_training", sample_per_label=sample)

    def _seal(self, scope):
        with open(os.path.join(self.sb.reg, "sealed.json"), "w") as f:
            json.dump({"schema": "heqk.sealed/1", "sealed": [{"source_id": "f-iot23", "scope": scope,
                                                             "reason": "test holdout", "sealed_on": "2026-11-20"}]}, f)

    def test_sealed_split_refused_unless_unsealed_and_logged(self):
        rule = windows.SPLIT_RULES["neuro-sha256-mod3"]
        names = [f"Synthetic-{i}" for i in range(12)]
        test_name = next(n for n in names if rule(n) == "test")
        dev_name = next(n for n in names if rule(n) == "dev")
        self._register(test_name)
        self._register(dev_name)
        self._seal("split:test@neuro-sha256-mod3")
        out = os.path.join(self.sb.dir, "w")
        _, man = windows.export(self.st, self.reg, "f-iot23", "commercial_training", "neuro-sha256-mod3", out_root=out)
        self.assertEqual([f["scenario"] for f in man["files"]], [dev_name])
        self.assertIn("sealed", man["skipped"][test_name])
        _, man = windows.export(self.st, self.reg, "f-iot23", "commercial_training", "neuro-sha256-mod3", out_root=out,
                                unseal=["f-iot23"])
        self.assertEqual(man["unsealed"], [test_name])
        with self.assertRaises(RuntimeError):  # a finished export directory is never rewritten
            windows.export(self.st, self.reg, "f-iot23", "commercial_training", "neuro-sha256-mod3", out_root=out,
                           unseal=["f-iot23"])
        with open(os.path.join(self.sb.data, "audit.jsonl")) as f:
            self.assertTrue(any(json.loads(l)["action"] == "unseal" for l in f))

    def test_sampled_acquisitions_are_not_windowed_and_do_not_supersede_full(self):
        full = self._register("Synthetic-S")
        sampled = self._register("Synthetic-S", sample=1)
        self.assertNotEqual(full["acquisition_id"], sampled["acquisition_id"])
        _, man = windows.export(self.st, self.reg, "f-iot23", "commercial_training", "neuro-sha256-mod3",
                                out_root=os.path.join(self.sb.dir, "w"))
        self.assertEqual([f["acquisition_id"] for f in man["files"]], [full["acquisition_id"]])
        from heqkdata import normalize
        normalize.normalize(self.st, self.reg, sampled)
        _, bman, _ = export.build(self.st, self.reg, "commercial_training", collections=["network_intelligence"],
                                  out_root=os.path.join(self.sb.dir, "b"))
        self.assertNotIn("superseded_acquisition:f-iot23", bman["excluded"])


BINET_HEAD = "StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label\n"


def brow(sec, src, dst, dport, label):
    t = H0 + sec
    import datetime as _dt
    ts = _dt.datetime.fromtimestamp(t, tz=_dt.timezone.utc).strftime("%Y/%m/%d %H:%M:%S.%f")
    return f"{ts},0.5,tcp,{src},40000,   ->,{dst},{dport},FSPA_FSPA,0,0,4,400,100,flow={label}\n"


class BinetflowWindows(unittest.TestCase):
    """CTU-13 path. SYNTHETIC rows (RFC 5737 addresses) in the binetflow layout."""

    def setUp(self):
        self.sb = Sandbox()
        self.addCleanup(self.sb.close)
        self.reg = registry.Registry(self.sb.reg)
        self.st = Store(self.sb.data)

    def _capture(self, rows):
        d = os.path.join(self.sb.dir, "cap", "1")
        os.makedirs(d)
        p = os.path.join(d, "capture-synthetic.binetflow")
        with open(p, "w") as f:
            f.write(BINET_HEAD + "".join(rows))
        return self.st.register(self.reg, "f-ctu13", p, "commercial_training")

    def test_hosts_from_labels_background_as_context(self):
        bot, normal, other, remote = "192.0.2.165", "192.0.2.20", "192.0.2.99", "198.51.100.10"
        acq = self._capture([
            brow(1, bot, remote, 80, "From-Botnet-V42-TCP-CC6"),
            brow(2, remote, normal, 22, "To-Normal-V42-SSH"),           # 'To-': the responder is the host
            brow(3, bot, "203.0.113.5", 53, "Background-UDP-Established"),  # touches the botnet host: context
            brow(4, other, remote, 443, "Background-TCP-Established"),  # touches no labelled host: dropped
            brow(3600 + 5, normal, remote, 443, "Background-TCP-Attempt"),  # background-only host-hour: no window
        ])
        buf = io.StringIO()
        c = windows.binetflow_host_windows(self.st, self.reg, acq, buf, "dev")
        lines = [json.loads(l) for l in buf.getvalue().splitlines()]
        self.assertEqual(len(lines), 2)
        by = {l["labels"] and next(iter(l["labels"])).split("/")[0]: l for l in lines}
        b, n = by["Botnet"], by["Normal"]
        self.assertEqual((b["labels"], b["background_events"], len(b["events"])), ({"Botnet/From-Botnet-V42-TCP-CC6": 1}, 1, 2))
        self.assertIsNone(b["events"][1]["label"])           # background: unknown, never benign
        self.assertIsNone(b["events"][0]["state"])           # Argus State is not mapped to rst/est
        self.assertEqual(n["events"][0]["dst_ip"], n["host"])  # oriented by initiator, kept in the host's window
        self.assertTrue(b["host"].startswith("192.168.") and n["host"].startswith("192.168."))
        self.assertTrue(b["events"][0]["dst_ip"].startswith(("198.51.100.", "203.0.113.")))  # unlabelled = remote
        self.assertEqual((c["dropped_background_without_labelled_host"], c["host_hours_background_only_skipped"],
                          c["labelled_hosts"]), (1, 1, 2))

    def test_ctu13_split_names_are_the_frozen_mirror_names(self):
        rule = windows.SPLIT_RULES["neuro-sha256-mod3"]
        got = {n: rule(windows.scenario_name("ctu-13", f"{n}__x.binetflow")) for n in range(1, 14)}
        self.assertEqual(sorted(n for n, s in got.items() if s == "dev"), [1, 5, 8])
        self.assertEqual(windows.scenario_name("ctu-13", "1__capture20110810.binetflow"), "CTU-13.Dataset-42")
        self.assertEqual(windows.scenario_name("iot-23", "CTU-IoT-Malware-Capture-1-1__conn.log.labeled"),
                         "CTU-IoT-Malware-Capture-1-1")


if __name__ == "__main__":
    unittest.main()
