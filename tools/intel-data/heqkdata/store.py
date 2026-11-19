# SPDX-License-Identifier: AGPL-3.0-only
"""The data store: immutable raw acquisitions, normalised records, an audit log, and a SQLite index.

Layout under data_root() (outside the repository):
  raw/<source_id>/<sha256>/<filename>        acquired bytes, chmod 0444, never modified
  raw/<source_id>/<sha256>/acquisition.json  who/what/when/licence-at-the-time
  normalized/<source_id>/<sha256>/records.jsonl   heqk.security-event/1, one per line
  normalized/<source_id>/<sha256>/rejects.jsonl   rows that failed parsing/validation, with the reason
  builds/<dataset_version>/...               exports + manifest.json
  audit.jsonl                                append-only log of every acquisition, normalisation, build
  catalog.sqlite                             index of the above (rebuildable from the files)
"""
import getpass
import json
import os
import shutil
import sqlite3
import tempfile
import urllib.request

from . import VERSION, canon, data_root
from . import licensing

USER_AGENT = f"hookprobe-intel-data/{VERSION} (+https://github.com/hookprobe/hookprobe)"


class Store:
    def __init__(self, root=None):
        self.root = os.path.abspath(root or data_root())
        repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        if self.root == repo or self.root.startswith(repo + os.sep):
            raise RuntimeError(f"data root {self.root} is inside the repository; real data is never committed")
        os.makedirs(self.root, exist_ok=True)
        self.db = sqlite3.connect(os.path.join(self.root, "catalog.sqlite"))
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS acquisitions (
              acquisition_id TEXT PRIMARY KEY, source_id TEXT NOT NULL, license_id TEXT NOT NULL,
              url TEXT, filename TEXT NOT NULL, bytes INTEGER NOT NULL, fetched_at TEXT NOT NULL, method TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS normalizations (
              acquisition_id TEXT NOT NULL, adapter TEXT NOT NULL, adapter_version TEXT NOT NULL,
              records INTEGER NOT NULL, rejects INTEGER NOT NULL, created_at TEXT NOT NULL,
              PRIMARY KEY (acquisition_id, adapter, adapter_version));
            """
        )

    def pseudonym_key(self):
        """Per-data-root secret for client pseudonyms (0600, never exported, never committed). Deleting it
        makes previously issued pseudonyms unlinkable to new ones (a crypto-shredding lever)."""
        p = os.path.join(self.root, "pseudonym.key")
        if not os.path.exists(p):
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(os.urandom(32))
        with open(p, "rb") as f:
            return f.read()

    # ------------------------------------------------------------------ audit
    def audit(self, action, **fields):
        rec = {"at": canon.now(), "action": action, "tool_version": VERSION, "user": _user(), **fields}
        with open(os.path.join(self.root, "audit.jsonl"), "a", encoding="utf-8") as f:
            f.write(canon.canonical_json(rec) + "\n")

    # ------------------------------------------------------------------ raw
    def raw_dir(self, source_id, acq_id):
        return os.path.join(self.root, "raw", source_id, acq_id)

    def _ingest_file(self, tmp_path, source, lic, filename, url, method, derived_from=None):
        digest = _sha256_file(tmp_path)
        d = self.raw_dir(source["id"], digest)
        target = os.path.join(d, filename)
        if os.path.exists(target):
            os.unlink(tmp_path)
            self.audit("acquire_duplicate", source_id=source["id"], acquisition_id=digest)
            return self.acquisition(source["id"], digest)
        os.makedirs(d, exist_ok=True)
        shutil.move(tmp_path, target)
        os.chmod(target, 0o444)
        size = os.path.getsize(target)
        acq = {
            "acquisition_id": digest, "source_id": source["id"], "license_id": lic["id"],
            "license_snapshot": lic, "url": url, "filename": filename, "bytes": size,
            "fetched_at": canon.now(), "method": method, "tool_version": VERSION,
        }
        if derived_from:
            acq["derived_from"] = derived_from
        with open(os.path.join(d, "acquisition.json"), "x", encoding="utf-8") as f:
            json.dump(acq, f, indent=2, sort_keys=True)
        os.chmod(os.path.join(d, "acquisition.json"), 0o444)
        self.db.execute("INSERT OR REPLACE INTO acquisitions VALUES (?,?,?,?,?,?,?,?)",
                        (digest, source["id"], lic["id"], url, filename, size, acq["fetched_at"], method))
        self.db.commit()
        self.audit("acquire", source_id=source["id"], acquisition_id=digest, bytes=size, url=url, method=method,
                   license_id=lic["id"])
        return acq

    def fetch(self, registry, source_id, purpose):
        """Download a registry source's declared acquisition URL. Refuses anything the licence gate denies
        for `purpose`, any non-HTTPS URL, and anything bigger than the declared max_bytes."""
        source = registry.source(source_id)
        lic = registry.license_of(source_id)
        licensing.require(lic, purpose)
        a = source["acquisition"]
        if not a:
            raise RuntimeError(f"{source_id}: no automated acquisition (access={source['access']}); use `register`")
        if not a["url"].startswith("https://"):
            raise RuntimeError("only https acquisitions are allowed")
        filename = os.path.basename(a["url"].split("?")[0]) or "download"
        req = urllib.request.Request(a["url"], headers={"User-Agent": USER_AGENT})
        fd, tmp = tempfile.mkstemp(dir=self.root, prefix=".partial-")
        n = 0
        try:
            with urllib.request.urlopen(req, timeout=60) as r, os.fdopen(fd, "wb") as out:
                if r.geturl().split(":", 1)[0] != "https":
                    raise RuntimeError(f"redirected to non-https {r.geturl()}")
                while True:
                    chunk = r.read(1 << 20)
                    if not chunk:
                        break
                    n += len(chunk)
                    if n > a["max_bytes"]:
                        raise RuntimeError(f"{source_id}: download exceeds max_bytes {a['max_bytes']}")
                    out.write(chunk)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        return self._ingest_file(tmp, source, lic, filename, a["url"], "fetch")

    def register(self, registry, source_id, path, purpose, url=None, sample_per_label=None):
        """Copy a manually obtained file (registration- or form-gated datasets) into the raw store.
        sample_per_label stores a per-label reservoir sample instead of the whole file (Zeek conn logs
        only; see sample.py); the original's hash, size and label counts go into `derived_from`."""
        source = registry.source(source_id)
        lic = registry.license_of(source_id)
        licensing.require(lic, purpose)
        fd, tmp = tempfile.mkstemp(dir=self.root, prefix=".partial-")
        os.close(fd)
        derived = None
        try:
            if sample_per_label:
                if source.get("adapter") != "zeek_conn_labeled":
                    raise RuntimeError(f"{source_id}: sampling at registration supports zeek_conn_labeled sources only")
                from . import sample
                derived = sample.zeek_per_label(path, tmp, sample_per_label, name=os.path.basename(path))
            else:
                shutil.copyfile(path, tmp)
        except BaseException:
            os.unlink(tmp)
            raise
        # keep the parent directory in the stored name: many datasets ship one file name per scenario dir
        # (IoT-23: <scenario>/bro/conn.log.labeled), and the scenario is the split group
        parent = os.path.basename(os.path.dirname(os.path.abspath(path)))
        if parent == "bro":
            parent = os.path.basename(os.path.dirname(os.path.dirname(os.path.abspath(path))))
        name = f"{parent}__{os.path.basename(path)}" if parent else os.path.basename(path)
        return self._ingest_file(tmp, source, lic, name, url or source["source_url"],
                                 "register_sampled" if derived else "register", derived)

    def acquisition(self, source_id, acq_id):
        with open(os.path.join(self.raw_dir(source_id, acq_id), "acquisition.json"), "r", encoding="utf-8") as f:
            return json.load(f)

    def acquisitions(self, source_id=None):
        q = "SELECT source_id, acquisition_id FROM acquisitions"
        args = ()
        if source_id:
            q += " WHERE source_id = ?"
            args = (source_id,)
        return [self.acquisition(s, a) for s, a in self.db.execute(q + " ORDER BY fetched_at", args)]

    def raw_path(self, acq):
        return os.path.join(self.raw_dir(acq["source_id"], acq["acquisition_id"]), acq["filename"])

    # ------------------------------------------------------------------ normalised
    def norm_dir(self, source_id, acq_id):
        return os.path.join(self.root, "normalized", source_id, acq_id)

    def record_normalization(self, acq, adapter, adapter_version, records, rejects):
        self.db.execute("INSERT OR REPLACE INTO normalizations VALUES (?,?,?,?,?,?)",
                        (acq["acquisition_id"], adapter, adapter_version, records, rejects, canon.now()))
        self.db.commit()
        self.audit("normalize", source_id=acq["source_id"], acquisition_id=acq["acquisition_id"], adapter=adapter,
                   adapter_version=adapter_version, records=records, rejects=rejects)

    def records(self, source_id=None):
        """Iterate every normalised record (optionally of one source), in a stable order."""
        base = os.path.join(self.root, "normalized")
        if not os.path.isdir(base):
            return
        for sid in sorted(os.listdir(base)):
            if source_id and sid != source_id:
                continue
            for acq in sorted(os.listdir(os.path.join(base, sid))):
                p = os.path.join(base, sid, acq, "records.jsonl")
                if os.path.exists(p):
                    with open(p, "r", encoding="utf-8") as f:
                        for line in f:
                            yield json.loads(line)


def _sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _user():
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 — audit must never fail on a missing login name
        return "unknown"
