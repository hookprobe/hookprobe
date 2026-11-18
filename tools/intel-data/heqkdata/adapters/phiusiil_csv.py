# SPDX-License-Identifier: AGPL-3.0-only
"""PhiUSIIL Phishing URL Dataset (UCI #967, CC BY 4.0) -> dns records.

UCI: "Label 1 corresponds to a legitimate URL, label 0 to a phishing URL" (235,795 rows: 134,850
legitimate, 100,945 phishing; verified 2026-11-18). Only the `Domain` column is used: the URL path and
query and the page `Title` can carry personal data and page text, and are not needed for name-level
classification. One record per distinct domain; a domain seen with both labels is rejected (ambiguous).
"""
from .. import canon, safeio

VERSION = "1.0.0"


def parse(path, ctx):
    from . import Reject
    seen = {}
    with safeio.open_text(path) as f:
        rows = safeio.csv_rows(f)
        header = next(rows, None)
        if not header:
            yield Reject(0, "empty file")
            return
        header = [h.lstrip("﻿").strip() for h in header]
        try:
            i_dom, i_lab = header.index("Domain"), header.index("label")
        except ValueError:
            yield Reject(1, "missing Domain or label column")
            return
        for n, row in enumerate(rows, 2):
            if len(row) != len(header):
                yield Reject(n, f"{len(row)} columns, header has {len(header)}")
                continue
            lab = {"1": "benign", "0": "malicious"}.get(row[i_lab].strip())
            d = canon.domain(row[i_dom])
            if lab is None or d is None:
                yield Reject(n, "bad label or domain", f"{row[i_dom][:100]},{row[i_lab][:5]}")
                continue
            if d in seen:
                if seen[d] != lab:
                    seen[d] = "conflict"
                continue
            seen[d] = lab
    for d in sorted(seen):
        lab = seen[d]
        if lab == "conflict":
            yield Reject(None, "domain carries both labels", d)
            continue
        body = {"schema": "heqk.dns-event/1", "qname": d, "qtype": "A", "rcode": None, "answers": [],
                "client_ref": None, "transport": None, "window": None}
        mal = lab == "malicious"
        yield ctx.record("dns", body, source_record_id=d, raw_bytes=f"{d},{lab}".encode(), label=lab,
                         family="phishing" if mal else None, label_source="dataset",
                         original_label="0 (phishing)" if mal else "1 (legitimate)",
                         techniques=["T1566"] if mal else [], tactics=["TA0001"] if mal else [],
                         mapping_source="heuristic")
