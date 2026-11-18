# SPDX-License-Identifier: AGPL-3.0-only
"""abuse.ch Feodo Tracker IP blocklist (JSON) -> indicator (ioc_type ip, botnet C2).

Fields: ip_address, port, status (online/offline), hostname, as_number, as_name, country, first_seen,
last_online, malware. The heqk IOC.TXT pack (ioc.rs) is generated from these records.
"""
from .. import canon, safeio

VERSION = "1.0.0"


def parse(path, ctx):
    from . import Reject
    doc = safeio.load_json(path)
    if not isinstance(doc, list):
        yield Reject(0, "expected a JSON array")
        return
    for i, e in enumerate(doc):
        addr = canon.ip(e.get("ip_address"))
        if addr is None:
            yield Reject(i, "bad ip_address", str(e.get("ip_address")))
            continue
        fam = (e.get("malware") or None)
        body = {
            "schema": "heqk.indicator/1",
            "value": addr,
            "ioc_type": "ip",
            "family": fam[:128] if fam else None,
            "threat_type": "botnet_cc",
            "confidence": None,
            "first_seen": canon.ts(e.get("first_seen")),
            "last_seen": canon.ts(e.get("last_online")),
            "expires": None,
            "active": {"online": True, "offline": False}.get(e.get("status")),
            "tlp": "clear",
            "attack_mapping": {"framework": "MITRE ATT&CK", "version": None, "techniques": ["T1071.001"], "tactics": ["TA0011"], "mapping_source": "heuristic"},
            "tags": [f"port:{int(e['port'])}"] if isinstance(e.get("port"), int) else [],
        }
        yield ctx.record(
            "indicator", body, source_record_id=f"{addr}:{e.get('port')}", raw_bytes=canon.canonical_json(e).encode(),
            observed_at=canon.ts(e.get("first_seen")), label="malicious", family=body["family"], label_source="feed",
            original_label=f"botnet_cc:{fam}" if fam else "botnet_cc", techniques=["T1071.001"], tactics=["TA0011"],
            mapping_source="heuristic", sensor_type="feed",
        )
