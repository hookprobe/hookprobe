# SPDX-License-Identifier: AGPL-3.0-only
"""CICFlowMeter CSV (CIC-IDS2017, CSE-CIC-IDS2018, CIC-DDoS2019, CICIoT-style exports) -> flow.

Column names differ between releases (leading spaces, 'Src IP' vs 'Source IP', 'Tot Fwd Pkts' vs
'Total Fwd Packets'); they are matched case- and space-insensitively against ALIASES. Only the
fields of heqk.network-flow/1 are kept: the ~80 CICFlowMeter statistics are recomputable from
flows and are a known source of dataset artefacts (Engelen et al. 2021), so they are NOT carried
into training records.

Known label problems in CIC-IDS2017/2018 (mislabelled attempted attacks, TCP appendices) mean this
adapter's output gets label_quality 'low' unless the corrected releases are used; see the catalogue.
"""
import re

from .. import canon, safeio

VERSION = "1.0.0"

ALIASES = {
    "flow_id": ["flowid"],
    "src_ip": ["srcip", "sourceip"],
    "src_port": ["srcport", "sourceport"],
    "dst_ip": ["dstip", "destinationip"],
    "dst_port": ["dstport", "destinationport"],
    "proto": ["protocol"],
    "ts": ["timestamp"],
    "duration_us": ["flowduration"],
    "fwd_pkts": ["totfwdpkts", "totalfwdpackets"],
    "bwd_pkts": ["totbwdpkts", "totalbackwardpackets"],
    "fwd_bytes": ["totlenfwdpkts", "totallengthoffwdpackets"],
    "bwd_bytes": ["totlenbwdpkts", "totallengthofbwdpackets"],
    "label": ["label"],
}
PROTO = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}
ATTACK_MAP = [  # heuristic, mapping_source=heuristic
    (r"portscan", ["T1046"]), (r"ddos|dos", ["T1498"]), (r"brute|patator|ftp|ssh", ["T1110"]),
    (r"bot", ["T1071"]), (r"infiltration", ["T1190"]), (r"web attack|sql|xss", ["T1190"]),
    (r"heartbleed", ["T1190"]),
]


def _key(h):
    return re.sub(r"[^a-z0-9]", "", h.lower())


def _num(v, cast=int):
    try:
        x = cast(float(v))
    except (TypeError, ValueError):
        return None
    return x if x >= 0 else None


def parse(path, ctx):
    from . import Reject
    with safeio.open_text(path) as f:
        rows = safeio.csv_rows(f)
        header = next(rows, None)
        if not header:
            yield Reject(0, "empty file")
            return
        idx = {}
        keys = [_key(h) for h in header]
        for name, alts in ALIASES.items():
            for a in alts:
                if a in keys:
                    idx[name] = keys.index(a)
                    break
        if "label" not in idx:
            yield Reject(1, "no Label column")
            return
        for n, row in enumerate(rows, 2):
            if len(row) != len(header):
                yield Reject(n, f"{len(row)} columns, header has {len(header)}", ",".join(row)[:300])
                continue
            g = lambda k: row[idx[k]].strip() if k in idx else None  # noqa: E731
            raw_label = g("label") or ""
            lab = "benign" if raw_label.upper() == "BENIGN" else ("malicious" if raw_label else None)
            dur_us = _num(g("duration_us"), float)
            body = {
                "schema": "heqk.network-flow/1",
                "ts_start": canon.ts(g("ts")),
                "duration_s": None if dur_us is None else round(dur_us / 1e6, 6),
                "orig_ip": canon.ip(g("src_ip")),
                "orig_port": _num(g("src_port")),
                "resp_ip": canon.ip(g("dst_ip")),
                "resp_port": _num(g("dst_port")),
                "proto": PROTO.get(g("proto") or "", "other"),
                "service": None,
                "orig_bytes": _num(g("fwd_bytes")),
                "resp_bytes": _num(g("bwd_bytes")),
                "orig_pkts": _num(g("fwd_pkts")),
                "resp_pkts": _num(g("bwd_pkts")),
                "conn_state": None,
                "history": None,
            }
            for k in ("orig_port", "resp_port"):
                if body[k] is not None and body[k] > 65535:
                    body[k] = None
            techs = []
            if lab == "malicious":
                for rx, t in ATTACK_MAP:
                    if re.search(rx, raw_label.lower()):
                        techs = t
                        break
            line = ",".join(row)
            yield ctx.record(
                "flow", body, source_record_id=(g("flow_id") or None) and f"{g('flow_id')}@{g('ts')}", raw_bytes=line.encode(),
                observed_at=body["ts_start"], label=lab, family=None if lab != "malicious" else raw_label[:128],
                label_source="dataset" if lab else "none", original_label=raw_label[:512] or None,
                techniques=techs, mapping_source="heuristic",
            )
