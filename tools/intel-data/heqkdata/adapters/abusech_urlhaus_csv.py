# SPDX-License-Identifier: AGPL-3.0-only
"""abuse.ch URLhaus CSV export -> indicator (ioc_type url).

Format: '#'-comment preamble, then one quoted row per line
  id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
The reporter field is a person's handle: it is dropped (personal data, not needed). URL query strings
can carry victim identifiers (e-mail addresses, tokens); the DNS builder uses only the host.
"""
from .. import canon, safeio

VERSION = "1.0.0"
COLS = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"]
MAPPING = {"framework": "MITRE ATT&CK", "version": None, "techniques": ["T1105"], "tactics": [], "mapping_source": "heuristic"}


def parse(path, ctx):
    from . import Reject
    with safeio.open_text(path) as f:
        for n, ln in safeio.lines(f):
            if not ln or ln.startswith("#"):
                continue
            row = next(safeio.csv_rows([ln]), [])
            if len(row) < 8:
                yield Reject(n, f"{len(row)} columns, need >= 8", ln)
                continue
            r = dict(zip(COLS, row))
            url = r["url"].strip()
            if not canon.url_host(url):
                yield Reject(n, "URL without a host", url)
                continue
            tags = [t for t in (r["tags"] or "").split(",") if t and t != "None"][:32]
            body = {
                "schema": "heqk.indicator/1",
                "value": url[:2048],
                "ioc_type": "url",
                "family": tags[0][:128] if tags else None,
                "threat_type": "malware_download" if r["threat"] == "malware_download" else ("other" if r["threat"] else None),
                "confidence": None,
                "first_seen": canon.ts(r["dateadded"]),
                "last_seen": canon.ts(r["last_online"]) if r["last_online"] not in ("", "None") else None,
                "expires": None,
                "active": {"online": True, "offline": False}.get(r["url_status"]),
                "tlp": "clear",
                "attack_mapping": dict(MAPPING),
                "tags": [t[:64] for t in tags],
            }
            yield ctx.record(
                "indicator", body, source_record_id=r["id"], raw_bytes=ln.encode("utf-8"),
                observed_at=canon.ts(r["dateadded"]), label="malicious", family=body["family"], label_source="feed",
                original_label=r["threat"] or None, techniques=["T1105"], mapping_source="heuristic", sensor_type="feed",
            )
