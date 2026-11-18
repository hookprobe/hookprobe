#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fetch the Phase-0 candidate models with provenance and integrity checks (operator-approved 2026-11-17).

For every file: the expected SHA-256 is read from the Hugging Face LFS record (`/api/models/<repo>/tree`),
the download is streamed to `<dest>/<file>.part`, hashed while it streams, and renamed only if the hash
matches. A `provenance.json` records repo, revision (commit), file, size, sha256, licence and fetch time.
Nothing is executed from a downloaded file. Same script on the dev host and on a CM5 lab unit, so both
evaluate byte-identical weights.

Usage: python3 -I fetch_models.py <dest dir> [--only name,name]
"""
import argparse
import hashlib
import json
import os
import sys
import time
import urllib.request

# (short name, HF repo, file, licence) -- all Apache-2.0, chosen fastest-first (Phase 0, NEURO_FINAL_RECOMMENDATION §7)
CANDIDATES = [
    ("granite-4.0-h-350m", "ibm-granite/granite-4.0-h-350m-GGUF", "granite-4.0-h-350m-Q4_0.gguf", "Apache-2.0"),
    ("qwen3-0.6b", "unsloth/Qwen3-0.6B-GGUF", "Qwen3-0.6B-Q4_0.gguf", "Apache-2.0"),
    ("qwen3.5-0.8b", "unsloth/Qwen3.5-0.8B-GGUF", "Qwen3.5-0.8B-Q4_0.gguf", "Apache-2.0"),
    ("granite-4.0-h-1b", "ibm-granite/granite-4.0-h-1b-GGUF", "granite-4.0-h-1b-Q4_0.gguf", "Apache-2.0"),
    ("qwen3-1.7b", "unsloth/Qwen3-1.7B-GGUF", "Qwen3-1.7B-Q4_0.gguf", "Apache-2.0"),
    ("qwen3.5-2b", "unsloth/Qwen3.5-2B-GGUF", "Qwen3.5-2B-Q4_0.gguf", "Apache-2.0"),
]
UA = {"User-Agent": "neuro-research-fetch/1.0"}


def api(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
        return json.loads(r.read())


def fetch(dest, name, repo, fname, lic):
    info = api("https://huggingface.co/api/models/%s" % repo)
    rev = info.get("sha")
    tree = api("https://huggingface.co/api/models/%s/tree/%s" % (repo, rev))
    ent = next(f for f in tree if f.get("path") == fname)
    want, size = ent["lfs"]["oid"], ent["size"]
    out = os.path.join(dest, fname)
    rec = {"name": name, "repo": repo, "revision": rev, "file": fname, "size": size, "sha256": want, "license": lic}
    if os.path.exists(out):
        h = hashlib.sha256()
        with open(out, "rb") as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                h.update(b)
        if h.hexdigest() == want:
            print("ok (cached) %s" % fname)
            return dict(rec, verified=True)
    url = "https://huggingface.co/%s/resolve/%s/%s" % (repo, rev, fname)
    h, n, t0 = hashlib.sha256(), 0, time.time()
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=120) as r, open(out + ".part", "wb") as f:
        for b in iter(lambda: r.read(1 << 20), b""):
            h.update(b)
            f.write(b)
            n += len(b)
    if h.hexdigest() != want or n != size:
        os.unlink(out + ".part")
        raise SystemExit("INTEGRITY FAILURE %s: sha256 %s != %s or size %d != %d" % (fname, h.hexdigest(), want, n, size))
    os.rename(out + ".part", out)
    print("ok %s %.0f MB in %.0f s, sha256 verified" % (fname, n / 1e6, time.time() - t0))
    return dict(rec, verified=True, fetched=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dest")
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    os.makedirs(a.dest, exist_ok=True)
    want = set(a.only.split(",")) if a.only else None
    recs = []
    for c in CANDIDATES:
        if want and c[0] not in want:
            continue
        recs.append(fetch(a.dest, *c))
    with open(os.path.join(a.dest, "provenance.json"), "w") as f:
        json.dump(recs, f, indent=1)
    print("provenance: %s" % os.path.join(a.dest, "provenance.json"))


if __name__ == "__main__":
    sys.exit(main())
