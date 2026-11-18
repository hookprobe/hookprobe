# SPDX-License-Identifier: AGPL-3.0-only
"""A labelled domain list (one name per line, optionally 'name,anything') -> dns records.

For DGA corpora distributed as one file per family (UMUDGA, MIT; 360netlab DGA output, MIT). The
label and family come from the STORED file name, which `register` writes as '<parent dir>__<file>':
  * a file under a directory called benign/legit/alexa/top  -> label benign
  * anything else                                           -> label malicious, family = file stem
The registry entry decides whether the source is a DGA corpus; this adapter never guesses beyond the
file layout, and every record keeps the file name in original_label for audit.
"""
import os
import re

from .. import canon, safeio

VERSION = "1.0.0"
BENIGN_DIRS = ("benign", "legit", "legitimate", "alexa", "top")


def parse(path, ctx):
    from . import Reject
    base = os.path.basename(path)
    parent, _, fname = base.partition("__") if "__" in base else ("", "", base)
    stem = re.sub(r"\.(txt|csv|list)(\.gz)?$", "", fname)
    benign = parent.lower() in BENIGN_DIRS or stem.lower() in BENIGN_DIRS
    label = "benign" if benign else "malicious"
    family = None if benign else stem[:128]
    seen = set()
    with safeio.open_text(path) as f:
        for n, ln in safeio.lines(f):
            if not ln or ln.startswith("#"):
                continue
            name = ln.split(",", 1)[0].strip()
            d = canon.domain(name)
            if d is None:
                yield Reject(n, "not a canonical domain", ln)
                continue
            if d in seen:
                continue
            seen.add(d)
            body = {"schema": "heqk.dns-event/1", "qname": d, "qtype": "A", "rcode": None, "answers": [],
                    "client_ref": None, "transport": None, "window": None}
            yield ctx.record("dns", body, source_record_id=f"{stem}:{d}", raw_bytes=ln.encode(), label=label,
                             family=family, label_source="dataset", original_label=f"{base}:{label}",
                             techniques=[] if benign else ["T1568.002"], tactics=[] if benign else ["TA0011"],
                             mapping_source="heuristic")
