#!/usr/bin/env python3
"""Pi 4 wireless sensor — 802.11 metadata extractor (M1).

Turns a closed capture file into JSON Lines, one record per management frame (and a
per-file summary for data frames), using tshark field extraction. Receive-only tooling:
nothing here transmits.

Privacy (spec §5 "minimise personal data"):
  * no payloads are read; data frames are reduced to per-(BSSID, station) counters;
  * SSIDs in *probe requests* (which reveal networks a device remembers) are stored only as a
    salted SHA-256 prefix plus length; beacon/probe-response SSIDs are public broadcasts and kept.

Usage:
  wsensor_extract.py --pcap FILE --out FILE.jsonl [--sensor ID] [--salt-file PATH]
  (the pure function `rows_to_events` is what the unit tests exercise.)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import uuid
from collections import Counter
from typing import Iterable, Iterator

# Order matters: rows_to_events indexes by this list. Every name was validated against
# `tshark -G fields` (Wireshark 4.4) on the bench Pi — an unknown field makes tshark abort.
FIELDS = [
    "frame.time_epoch",
    "wlan.fc.type_subtype",
    "wlan.bssid",
    "wlan.sa",
    "wlan.da",
    "wlan.ta",
    "wlan.ra",
    "radiotap.channel.freq",
    "radiotap.dbm_antsignal",
    "wlan.ssid",
    "wlan.rsn.akms.type",
    "wlan.rsn.pcs.type",
    "wlan.rsn.gcs.type",
    "wlan.rsn.capabilities.mfpc",
    "wlan.rsn.capabilities.mfpr",
    "wlan.fixed.capabilities.privacy",
    "wlan.ds.current_channel",
    "wlan.fixed.reason_code",
    "wlan.fixed.status_code",
    "wlan.fixed.auth.alg",
    "wlan.fc.protected",
    "wlan.wfa.ie.type",
    "wlan.country_info.code",
    "wlan.ht.info.primarychannel",
    "wlan.vht.op.channelwidth",
    "wlan.vht.op.channelcenter0",
    "wlan.rsnx.sae_hash_to_element",
    "wps.config_methods",
]
IDX = {f: i for i, f in enumerate(FIELDS)}

SUBTYPES = {
    0: "assoc_req", 1: "assoc_resp", 2: "reassoc_req", 3: "reassoc_resp",
    4: "probe_req", 5: "probe_resp", 8: "beacon", 9: "atim", 10: "disassoc",
    11: "auth", 12: "deauth", 13: "action", 14: "action_noack",
}
AKM_NAMES = {
    "1": "8021X", "2": "PSK", "3": "FT-8021X", "4": "FT-PSK", "5": "8021X-SHA256",
    "6": "PSK-SHA256", "8": "SAE", "9": "FT-SAE", "11": "SUITE-B", "12": "SUITE-B-192",
    "18": "OWE", "24": "SAE-EXT-KEY", "25": "FT-SAE-EXT-KEY",
}
CIPHER_NAMES = {"1": "WEP40", "2": "TKIP", "4": "CCMP-128", "5": "WEP104", "8": "GCMP-128",
                "9": "GCMP-256", "10": "CCMP-256"}


def _truthy(v: str) -> bool | None:
    if v == "":
        return None
    return v.lower() in ("1", "true", "yes")


def _first(v: str) -> str:
    return v.split(",")[0] if v else ""


def _int(v: str) -> int | None:
    v = _first(v)
    try:
        return int(v, 0)
    except ValueError:
        try:
            return int(float(v))
        except ValueError:
            return None


def _list(v: str) -> list[str]:
    return [x for x in v.split(",") if x] if v else []


def freq_to_channel(freq: int | None) -> int | None:
    if freq is None:
        return None
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if 5000 <= freq <= 5900:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5
    return None


def security_label(privacy: bool | None, akms: list[str], wfa_types: list[str]) -> str:
    """Coarse security class of an AP advertisement (beacon / probe response)."""
    names = {AKM_NAMES.get(a, f"AKM{a}") for a in akms}
    if akms:
        if names <= {"SAE", "FT-SAE", "SAE-EXT-KEY", "FT-SAE-EXT-KEY"}:
            return "WPA3-SAE"
        if "OWE" in names:
            return "OWE"
        if names & {"SAE", "FT-SAE", "SAE-EXT-KEY"} and names & {"PSK", "FT-PSK", "PSK-SHA256"}:
            return "WPA2/WPA3-transition"
        if names & {"8021X", "FT-8021X", "8021X-SHA256", "SUITE-B", "SUITE-B-192"}:
            return "WPA2/3-Enterprise"
        return "WPA2-PSK"
    if "1" in wfa_types:  # WFA vendor IE type 1 = legacy WPA (v1)
        return "WPA1"
    if privacy:
        return "WEP"
    if privacy is False:
        return "OPEN"
    return "UNKNOWN"


class SsidHasher:
    def __init__(self, salt: bytes):
        self.salt = salt

    def __call__(self, ssid: str) -> dict:
        return {"ssid_hash": hashlib.sha256(self.salt + ssid.encode()).hexdigest()[:16],
                "ssid_len": len(ssid)}


def _decode_ssid(raw: str) -> str:
    # tshark prints SSIDs as text; non-printable SSIDs come out as hex (e.g. hidden 00-padded).
    if raw and all(c in "0123456789abcdef" for c in raw.lower()) and len(raw) % 2 == 0 and len(raw) >= 2:
        try:
            b = bytes.fromhex(raw)
            if all(x == 0 for x in b):
                return ""  # hidden SSID (zero-filled)
            txt = b.decode("utf-8")
            if txt.isprintable():
                return txt
        except (ValueError, UnicodeDecodeError):
            pass
    return raw


def rows_to_events(rows: Iterable[list[str]], sensor: str, hasher: SsidHasher,
                   source: str = "") -> Iterator[dict]:
    """Pure transform: tshark field rows -> event dicts (mgmt events + one data summary)."""
    data_ctr: Counter = Counter()
    data_sig: dict = {}
    first_ts = last_ts = None
    n_frames = 0
    for r in rows:
        if len(r) < len(FIELDS):
            r = r + [""] * (len(FIELDS) - len(r))
        n_frames += 1
        ts = float(r[IDX["frame.time_epoch"]] or 0)
        first_ts = ts if first_ts is None else min(first_ts, ts)
        last_ts = ts if last_ts is None else max(last_ts, ts)
        st = _int(r[IDX["wlan.fc.type_subtype"]])
        freq = _int(r[IDX["radiotap.channel.freq"]])
        dbm = _int(r[IDX["radiotap.dbm_antsignal"]])
        if st is None:
            continue
        ftype, sub = st >> 4, st & 0x0F
        bssid = _first(r[IDX["wlan.bssid"]])
        if ftype == 2:  # data: counters only, never payload
            sta = _first(r[IDX["wlan.sa"]]) or _first(r[IDX["wlan.ta"]])
            key = (bssid, sta)
            data_ctr[key] += 1
            if dbm is not None:
                data_sig[key] = dbm
            continue
        if ftype != 0:
            continue
        kind = SUBTYPES.get(sub, f"mgmt_{sub}")
        ev = {
            "event_id": str(uuid.uuid4()),
            "ts": round(ts, 6),
            "sensor": sensor,
            "iface_role": "monitor",
            "classification": "observed",
            "kind": kind,
            "freq_mhz": freq,
            "channel": freq_to_channel(freq),
            "dbm": dbm,
            "bssid": bssid or None,
            "sa": _first(r[IDX["wlan.sa"]]) or None,
            "da": _first(r[IDX["wlan.da"]]) or None,
            "protected": _truthy(r[IDX["wlan.fc.protected"]]),
        }
        if source:
            ev["source"] = source
        ssid = _decode_ssid(r[IDX["wlan.ssid"]])
        if kind in ("beacon", "probe_resp"):
            akms = _list(r[IDX["wlan.rsn.akms.type"]])
            ev.update({
                "ssid": ssid,
                "hidden": ssid == "",
                "ds_channel": _int(r[IDX["wlan.ds.current_channel"]]),
                "security": security_label(_truthy(r[IDX["wlan.fixed.capabilities.privacy"]]), akms,
                                           _list(r[IDX["wlan.wfa.ie.type"]])),
                "akm": [AKM_NAMES.get(a, f"AKM{a}") for a in akms],
                "pairwise": [CIPHER_NAMES.get(c, c) for c in _list(r[IDX["wlan.rsn.pcs.type"]])],
                "group": CIPHER_NAMES.get(_first(r[IDX["wlan.rsn.gcs.type"]]), _first(r[IDX["wlan.rsn.gcs.type"]])) or None,
                "pmf_capable": _truthy(_first(r[IDX["wlan.rsn.capabilities.mfpc"]])),
                "pmf_required": _truthy(_first(r[IDX["wlan.rsn.capabilities.mfpr"]])),
                "sae_h2e": _truthy(_first(r[IDX["wlan.rsnx.sae_hash_to_element"]])),
                "wps": bool(r[IDX["wps.config_methods"]]),
                "country": _first(r[IDX["wlan.country_info.code"]]) or None,
                "vht_width": _int(r[IDX["wlan.vht.op.channelwidth"]]),
                "vht_center0": _int(r[IDX["wlan.vht.op.channelcenter0"]]),
            })
        elif kind == "probe_req":
            ev["wildcard"] = ssid == ""
            if ssid:
                ev.update(hasher(ssid))  # never store the remembered-network name in clear
            sa = ev["sa"] or ""
            ev["sa_randomized"] = len(sa) >= 2 and sa[1].lower() in "26ae"
        elif kind in ("deauth", "disassoc"):
            ev["reason_code"] = _int(r[IDX["wlan.fixed.reason_code"]])
        elif kind in ("auth",):
            ev["auth_alg"] = _int(r[IDX["wlan.fixed.auth.alg"]])
            ev["status_code"] = _int(r[IDX["wlan.fixed.status_code"]])
        elif kind in ("assoc_resp", "reassoc_resp"):
            ev["status_code"] = _int(r[IDX["wlan.fixed.status_code"]])
        elif kind in ("assoc_req", "reassoc_req"):
            ev["ssid"] = ssid
        yield ev
    if data_ctr:
        yield {
            "event_id": str(uuid.uuid4()),
            "ts": round(last_ts or 0, 6),
            "ts_first": round(first_ts or 0, 6),
            "sensor": sensor,
            "iface_role": "monitor",
            "classification": "observed",
            "kind": "data_summary",
            "source": source or None,
            "pairs": [{"bssid": b or None, "sta": s or None, "frames": n, "last_dbm": data_sig.get((b, s))}
                      for (b, s), n in data_ctr.most_common()],
        }


def run_tshark(pcap: str) -> Iterator[list[str]]:
    cmd = ["tshark", "-n", "-r", pcap, "-T", "fields", "-E", "separator=\t",
           "-E", "occurrence=a", "-E", "aggregator=,", "-E", "quote=n"]
    for f in FIELDS:
        cmd += ["-e", f]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    assert proc.stdout is not None
    for line in proc.stdout:
        yield line.rstrip("\n").split("\t")
    proc.wait()


def load_salt(path: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except FileNotFoundError:
        salt = os.urandom(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(salt)
        return salt


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--sensor", default=os.uname().nodename)
    ap.add_argument("--salt-file", default="/var/lib/pi4-wsensor/ssid.salt")
    a = ap.parse_args(argv)
    hasher = SsidHasher(load_salt(a.salt_file))
    n = 0
    tmp = a.out + ".part"
    with open(tmp, "w") as out:
        for ev in rows_to_events(run_tshark(a.pcap), a.sensor, hasher, os.path.basename(a.pcap)):
            out.write(json.dumps(ev, separators=(",", ":")) + "\n")
            n += 1
    os.replace(tmp, a.out)
    print(f"{a.pcap}: {n} events -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
