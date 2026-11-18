# SPDX-License-Identifier: AGPL-3.0-only
"""Raw acquisition -> validated normalised records (+ rejects with reasons).

Output is written to a temp file and renamed, so a crash never leaves a half-written records.jsonl.
Records are sorted by record_id before writing: the same raw file and adapter version always produce
the same bytes (reproducibility).
"""
import json
import os
import tempfile

from . import adapters, canon, schema
from .adapters import Reject, Ctx


def normalize(store, registry, acq, adapter_name=None, pseudonym_key=None, validator=None):
    source = registry.source(acq["source_id"])
    name = adapter_name or (source["acquisition"] or {}).get("adapter")
    if not name:
        raise RuntimeError(f"{source['id']}: no adapter declared; pass --adapter")
    mod = adapters.get(name)
    key = pseudonym_key or store.pseudonym_key()
    ctx = Ctx(source, acq, name, mod.VERSION, key)
    v = validator or schema.default()
    raw = store.raw_path(acq)
    recs, rejects, seen = {}, [], set()
    for item in mod.parse(raw, ctx):
        if isinstance(item, Reject):
            rejects.append({"line": item.line, "reason": item.reason, "raw": item.raw})
            continue
        errs = v.errors(item, "security-event.schema.json")
        if errs:
            rejects.append({"line": None, "reason": "schema: " + "; ".join(errs[:5]),
                            "raw": item["provenance"]["source_record_id"]})
            continue
        rid = item["record_id"]
        if rid in seen:
            rejects.append({"line": None, "reason": "duplicate record_id within acquisition", "raw": rid})
            continue
        seen.add(rid)
        recs[rid] = item
    d = store.norm_dir(acq["source_id"], acq["acquisition_id"])
    os.makedirs(d, exist_ok=True)
    _atomic_jsonl(os.path.join(d, "records.jsonl"), (recs[k] for k in sorted(recs)))
    _atomic_jsonl(os.path.join(d, "rejects.jsonl"), rejects)
    store.record_normalization(acq, name, mod.VERSION, len(recs), len(rejects))
    return len(recs), rejects


def _atomic_jsonl(path, items):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        for it in items:
            f.write(canon.canonical_json(it) + "\n")
    os.replace(tmp, path)


def read_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)
