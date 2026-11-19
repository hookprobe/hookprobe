# SPDX-License-Identifier: AGPL-3.0-only
"""Zeek conn.log (TSV), including Stratosphere's labelled variant (IoT-23, CTU-13 Zeek) -> flow.

IoT-23 quirk (same handling as tools/neuro-research/replay_iot23.py): the last TSV column holds
"tunnel_parents   label   detailed-label" separated by runs of spaces. A plain Zeek log without labels
gives label = null (not 'benign': an unlabelled flow is unknown).

The scenario is the parent directory name (e.g. CTU-IoT-Malware-Capture-1-1) and prefixes the
source_record_id, so the split can group by scenario (records of one capture never straddle splits).

The ATT&CK mapping of a detailed label is a HEURISTIC of this adapter (mapping_source=heuristic),
not an assertion of the dataset authors.
"""
import os
import re

from .. import canon, safeio

VERSION = "1.0.0"

DETAIL_MAP = [  # (regex on detailed-label, techniques, tactics)
    (r"PortScan", ["T1046"], ["TA0007"]),
    (r"C&C|HeartBeat", ["T1071"], ["TA0011"]),
    (r"DDoS", ["T1498"], ["TA0040"]),
    (r"FileDownload", ["T1105"], ["TA0011"]),
]
STATES = {"S0", "S1", "SF", "REJ", "S2", "S3", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"}


def _int(v):
    return int(v) if v not in (None, "", "-") and v.isdigit() else None


def _float(v):
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    return x if x >= 0 else None


def parse(path, ctx):
    from . import Reject
    # `register` stores files as '<parent dir>__<name>' so the capture scenario survives the raw store
    base = os.path.basename(path)
    scenario = base.split("__", 1)[0] if "__" in base else "zeek"
    fields = None
    with safeio.open_text(path) as f:
        for n, ln in safeio.lines(f):
            if ln.startswith("#fields"):
                fields = ln.split("\t")[1:]
                continue
            if not ln or ln.startswith("#"):
                continue
            if fields is None:
                yield Reject(n, "data before #fields header", ln)
                continue
            parts = ln.split("\t")
            label = detailed = None
            if len(parts) < len(fields) or re.search(r"\s{2,}", parts[-1]):
                tail = re.split(r"\s{2,}", parts[-1].strip())
                parts = parts[:-1] + [tail[0]]
                label = tail[1] if len(tail) > 1 else None
                detailed = tail[2] if len(tail) > 2 and tail[2] != "-" else None
            d = dict(zip(fields, parts))
            label = d.get("label", label)
            detailed = d.get("detailed-label", detailed)
            if detailed == "-":
                detailed = None
            proto = d.get("proto", "")
            uid = d.get("uid")
            if not uid:
                yield Reject(n, "no uid", ln)
                continue
            body = {
                "schema": "heqk.network-flow/1",
                "ts_start": canon.ts(d.get("ts")),
                "duration_s": _float(d.get("duration")),
                "orig_ip": canon.ip(d.get("id.orig_h")),
                "orig_port": _int(d.get("id.orig_p")),
                "resp_ip": canon.ip(d.get("id.resp_h")),
                "resp_port": _int(d.get("id.resp_p")),
                "proto": proto if proto in ("tcp", "udp", "icmp") else "other",
                "service": None if d.get("service") in (None, "", "-") else d["service"][:64],
                "orig_bytes": _int(d.get("orig_bytes")),
                "resp_bytes": _int(d.get("resp_bytes")),
                "orig_pkts": _int(d.get("orig_pkts")),
                "resp_pkts": _int(d.get("resp_pkts")),
                "conn_state": d.get("conn_state") if d.get("conn_state") in STATES else None,
                "history": None if d.get("history") in (None, "", "-") else d["history"][:64],
            }
            lab = {"malicious": "malicious", "benign": "benign"}.get((label or "").lower())
            techs, tacs = [], []
            for rx, t, ta in DETAIL_MAP:
                if detailed and re.search(rx, detailed):
                    techs += t
                    tacs += ta
            original = None if label is None else (f"{label}/{detailed}" if detailed else label)
            yield ctx.record(
                "flow", body, source_record_id=f"{scenario}:{uid}", raw_bytes=ln.encode("utf-8"),
                observed_at=body["ts_start"], label=lab, family=detailed, label_source="dataset" if lab else "none",
                original_label=original, techniques=techs, tactics=tacs, mapping_source="heuristic",
            )
