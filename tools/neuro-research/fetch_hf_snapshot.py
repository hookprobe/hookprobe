#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fetch a HF model snapshot at a PINNED revision; verify every file (LFS: sha256 == lfs.oid; others: git blob sha1 == oid).
Writes provenance.json. Usage: python3 -I fetch_hf_snapshot.py <repo> <revision> <dest>"""
import hashlib, json, os, sys, urllib.request, time
UA = {"User-Agent": "neuro-research-fetch/1.0"}
repo, rev, dest = sys.argv[1:4]
os.makedirs(dest, exist_ok=True)
tree = json.loads(urllib.request.urlopen(urllib.request.Request(
    "https://huggingface.co/api/models/%s/tree/%s" % (repo, rev), headers=UA), timeout=60).read())
rec = []
for f in tree:
    if f["type"] != "file":
        continue
    name, out = f["path"], os.path.join(dest, f["path"])
    lfs = f.get("lfs")
    url = "https://huggingface.co/%s/resolve/%s/%s" % (repo, rev, name)
    h256, h1, n = hashlib.sha256(), hashlib.sha1(), 0
    h1.update(b"blob %d\0" % f["size"])
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=120) as r, open(out + ".part", "wb") as w:
        while True:
            b = r.read(1 << 20)
            if not b:
                break
            w.write(b); h256.update(b); h1.update(b); n += 1 and len(b)
    ok = (h256.hexdigest() == lfs["oid"]) if lfs else (h1.hexdigest() == f["oid"])
    if not ok:
        os.remove(out + ".part"); sys.exit("HASH MISMATCH %s" % name)
    os.rename(out + ".part", out)
    rec.append({"file": name, "size": f["size"], "sha256": h256.hexdigest(), "verified_against": "lfs.sha256" if lfs else "git-blob-sha1"})
    print("OK", name, f["size"])
json.dump({"repo": repo, "revision": rev, "fetched": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "files": rec},
          open(os.path.join(dest, "provenance.json"), "w"), indent=1)
print("done:", len(rec), "files verified")
