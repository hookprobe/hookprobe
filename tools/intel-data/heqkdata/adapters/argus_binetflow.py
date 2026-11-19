# SPDX-License-Identifier: AGPL-3.0-only
"""Argus bidirectional NetFlow, Stratosphere's labelled `.binetflow` CSV (CTU-13) -> flow.

Header: StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label
Columns are matched by name, so a file with extra or reordered columns still parses.

Labels (CTU-13 page and paper): `flow=From-Botnet-…` / `flow=To-Botnet-…` are botnet traffic
(malicious); `flow=From-Normal-…` / `flow=To-Normal-…` are verified normal hosts (benign);
`flow=Background-…` is the rest of the university network, which the authors say is NOT verified
benign, so it gets label = null (unknown), never benign. Files without the `flow=` prefix are handled.

What this adapter does NOT claim:
- Argus gives total packets for both directions, not per direction, so orig_pkts / resp_pkts are
  null; bytes split as orig = SrcBytes, resp = TotBytes - SrcBytes.
- Argus `State` (CON, FSPA_FSPA, INT, …) is not a Zeek conn_state, so conn_state is null.
- StartTime carries no zone; it is taken as written (not verified to be UTC).
- The ATT&CK mapping (C&C -> T1071) is a heuristic of this adapter, not the dataset authors'.

The scenario is the `<scenario>__` prefix the store gives a registered file (CTU-13's per-scenario
directories are 1..13) and prefixes source_record_id, so a scenario never straddles splits.
"""
import os
import re

from .. import canon, safeio

VERSION = "1.0.0"

PROTO = {"tcp": "tcp", "udp": "udp", "icmp": "icmp", "ipv6-icmp": "icmpv6", "icmp6": "icmpv6"}
DETAIL_MAP = [(r"(^|-)CC(\d|-|$)|C&C", ["T1071"], ["TA0011"])]
COLS = ("starttime", "dur", "proto", "srcaddr", "sport", "dstaddr", "dport", "totbytes", "srcbytes", "label")


def _port(v, proto):
    if proto in ("icmp", "icmpv6") or v in (None, ""):
        return None  # Argus puts ICMP type / code in the port columns
    try:
        p = int(v, 0) if v.lower().startswith("0x") else int(v)
    except ValueError:
        return None
    return p if 0 <= p <= 65535 else None


def _num(v, cast=int):
    try:
        x = cast(float(v))
    except (TypeError, ValueError):
        return None
    return x if x >= 0 else None


def _label(raw):
    s = raw.strip()
    tag = s[5:] if s.lower().startswith("flow=") else s
    low = tag.lower()
    if "botnet" in low:
        return "malicious", tag
    if "normal" in low:
        return "benign", tag
    return None, tag  # Background / unknown: never assumed benign


def parse(path, ctx):
    from . import Reject
    base = os.path.basename(path)
    scenario = base.split("__", 1)[0] if "__" in base else "argus"
    if scenario.isdigit():
        scenario = f"CTU-13-{scenario}"
    with safeio.open_text(path) as f:
        rows = safeio.csv_rows(f)
        header = next(rows, None)
        if not header:
            yield Reject(0, "empty file")
            return
        keys = [h.strip().lower() for h in header]
        missing = [c for c in COLS if c not in keys]
        if missing:
            yield Reject(1, f"missing columns {missing}", ",".join(header)[:300])
            return
        ix = {c: keys.index(c) for c in COLS}
        for n, row in enumerate(rows, 2):
            if len(row) < len(header):
                yield Reject(n, f"{len(row)} columns, header has {len(header)}", ",".join(row)[:300])
                continue
            g = lambda k: row[ix[k]].strip()  # noqa: E731
            proto = PROTO.get(g("proto").lower(), "other")
            tot, src = _num(g("totbytes")), _num(g("srcbytes"))
            lab, tag = _label(g("label"))
            ts = canon.ts(g("starttime").replace("/", "-"))
            if ts is None:
                yield Reject(n, "unparseable StartTime", ",".join(row)[:300])
                continue
            body = {
                "schema": "heqk.network-flow/1",
                "ts_start": ts,
                "duration_s": None if _num(g("dur"), float) is None else round(_num(g("dur"), float), 6),
                "orig_ip": canon.ip(g("srcaddr")),
                "orig_port": _port(g("sport"), proto),
                "resp_ip": canon.ip(g("dstaddr")),
                "resp_port": _port(g("dport"), proto),
                "proto": proto,
                "service": None,
                "orig_bytes": src,
                "resp_bytes": tot - src if tot is not None and src is not None and tot >= src else None,
                "orig_pkts": None,
                "resp_pkts": None,
                "conn_state": None,
                "history": None,
            }
            techs, tacs = [], []
            if lab == "malicious":
                for rx, t, ta in DETAIL_MAP:
                    if re.search(rx, tag):
                        techs, tacs = t, ta
            line = ",".join(row)
            yield ctx.record(
                "flow", body, source_record_id=f"{scenario}:{n}", raw_bytes=line.encode("utf-8"),
                observed_at=ts, label=lab, family=tag[:128] if lab == "malicious" else None,
                label_source="dataset" if lab else "none", original_label=tag[:512] or None,
                techniques=techs, tactics=tacs, mapping_source="heuristic",
            )
