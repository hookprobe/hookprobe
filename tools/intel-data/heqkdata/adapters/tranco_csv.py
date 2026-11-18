# SPDX-License-Identifier: AGPL-3.0-only
"""Tranco top-sites list (rank,domain CSV, optionally inside a zip) -> dns records labelled benign.

A popularity list is a BENIGN BASELINE, not ground truth: popular names can be abused (free hosting,
dynamic DNS, URL shorteners) and some malicious domains briefly rank. The label quality is therefore
'medium', ranks beyond TOP_N are ignored, and the DNS builder drops any Tranco name that a malicious
source in the same build also lists (and reports how many it dropped).
"""
import os
import tempfile

from .. import canon, safeio

VERSION = "1.0.0"
TOP_N = 100_000


def _rows(path):
    if not path.endswith(".zip"):
        with safeio.open_text(path) as f:
            yield from safeio.lines(f)
        return
    with tempfile.TemporaryDirectory(prefix="tranco-") as tmp:
        dest = os.path.join(tmp, "x")
        files = safeio.extract_zip(path, dest, allow=lambda n: n.endswith(".csv"))
        if len(files) != 1:
            raise safeio.UnsafeContent(f"expected one CSV in the Tranco zip, found {len(files)}")
        with safeio.open_text(files[0]) as f:
            yield from safeio.lines(f)


def parse(path, ctx):
    from . import Reject
    for n, ln in _rows(path):
        if not ln:
            continue
        rank_s, _, name = ln.partition(",")
        if not rank_s.isdigit():
            yield Reject(n, "rank is not an integer", ln)
            continue
        rank = int(rank_s)
        if rank > TOP_N:
            continue
        d = canon.domain(name)
        if d is None:
            yield Reject(n, "not a canonical domain", ln)
            continue
        body = {"schema": "heqk.dns-event/1", "qname": d, "qtype": "A", "rcode": None, "answers": [],
                "client_ref": None, "transport": None, "window": None}
        yield ctx.record("dns", body, source_record_id=d, raw_bytes=ln.encode(), label="benign",
                         label_source="dataset", original_label=f"tranco_rank:{rank}")
