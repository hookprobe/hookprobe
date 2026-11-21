# SPDX-License-Identifier: AGPL-3.0-only
"""Normalised records -> TrainingExamples (heqk.training-example/1), one builder per collection.

Principles enforced here:
  * the target carries only what the label source asserted; reasoning / confidence / recommended_action
    stay null unless a human or an explicitly synthetic generator supplied them;
  * every example names its group_key, so near-duplicates (same registrable domain, same capture
    scenario, same CVE) can never straddle train and test;
  * per-source caps use deterministic hash sampling, so a rebuild selects the same records.
"""
import random

from . import VERSION, canon

BUILDER = {"name": "heqk-intel-builders", "version": VERSION}
# Collections whose examples restate lookup-table facts (agreed with the Neuro session, 2026-11-21): kept in
# the general build, but a small model should look these facts up (heqk_data.py lookup), not memorise them.
USAGE_NOTES = {
    "vulnerability_intelligence": "lookup-backed, not for small-model fine-tuning: templated CVE/KEV facts that "
                                  "mirror lookup cve.jsonl; Neuro excludes this collection and uses the lookup table.",
    "attack_intelligence": "lookup-backed, not for small-model fine-tuning: templated ATT&CK technique facts that "
                           "mirror lookup attack.jsonl; Neuro excludes this collection and uses the lookup table.",
}
PREFIX = {"dns_intelligence": "dns", "network_intelligence": "net", "attack_intelligence": "atk",
          "malware_intelligence": "mal", "vulnerability_intelligence": "vuln", "soc_reasoning": "soc"}


def mapping(techniques=(), tactics=(), source="none", version=None):
    return {"framework": "MITRE ATT&CK", "version": version, "techniques": sorted(set(techniques)),
            "tactics": sorted(set(tactics)), "mapping_source": source if (techniques or tactics) else "none"}


def target(label=None, *, confidence=None, severity=None, attack=None, evidence=(), reasoning=None, fp=(),
           action=None, answer=None):
    return {"label": label, "confidence": confidence, "severity": severity, "attack_mapping": attack or mapping(),
            "evidence": list(evidence), "reasoning": reasoning, "false_positive_considerations": list(fp),
            "recommended_action": action, "answer": answer}


def truth(kind, verified, source, quality, notes=None):
    return {"type": kind, "verified": verified, "label_source": source, "label_quality": quality, "notes": notes}


def example(collection, task, records, question, tgt, gt, group_key, *, context=None, lang="en"):
    inp = {"records": records, "context": context or {}, "question": question}
    # content key excludes provenance so the same content from two sources is a duplicate
    content = {"collection": collection, "task": task, "lang": lang,
               "input": {"records": [{k: r[k] for k in ("kind", "body", "labels")} for r in records],
                         "context": inp["context"], "question": question},
               "target": tgt}
    digest = canon.sha256_obj(content)
    created = max(r["provenance"]["created_at"] for r in records)
    return {
        "schema": "heqk.training-example/1",
        "id": f"heqk-{PREFIX[collection]}-{digest[:16]}",
        "collection": collection,
        "task": task,
        "lang": lang,
        "input": inp,
        "target": tgt,
        "ground_truth": gt,
        "provenance": {
            "builder": dict(BUILDER),
            "source_ids": sorted({r["provenance"]["source_id"] for r in records}),
            "license_ids": sorted({r["provenance"]["license_id"] for r in records}),
            "created_at": created,
        },
        "split": {"name": None, "group_key": group_key[:256], "strategy": None},
        "content_sha256": digest,
    }


def _sample(records, cap, salt):
    """Deterministic cap: keep the `cap` records with the smallest hash(salt, record_id)."""
    if cap is None or len(records) <= cap:
        return records
    return sorted(records, key=lambda r: canon.sha256_obj([salt, r["record_id"]]))[:cap]


def _derived_dns(ind, host):
    """A dns record derived from an indicator's host (the feed asserted the URL/domain, so the name is the
    observable a resolver would see). Provenance points at the indicator's acquisition and raw row."""
    rid = canon.sha256_obj(["dns-from-indicator", ind["record_id"], host])[:24]
    prov = dict(ind["provenance"])
    prov["transform"] = {"name": "dns-from-indicator", "version": VERSION}
    labels = dict(ind["labels"])
    labels["attack_mapping"] = mapping()
    return {"schema": "heqk.security-event/1", "record_id": f"dns:{rid}", "kind": "dns",
            "observed_at": ind["observed_at"], "sensor": dict(ind["sensor"]),
            "body": {"schema": "heqk.dns-event/1", "qname": host, "qtype": "A", "rcode": None, "answers": [],
                     "client_ref": None, "transport": None, "window": None},
            "labels": labels, "provenance": prov}


# ---------------------------------------------------------------------------- 01 DNS intelligence
def build_dns(records, cap_per_source=None, stats=None):
    stats = stats if stats is not None else {}
    malicious, benign = {}, {}
    for r in records:
        if r["kind"] == "indicator" and r["labels"]["label"] == "malicious":
            b = r["body"]
            host = b["value"] if b["ioc_type"] == "domain" else (canon.url_host(b["value"]) if b["ioc_type"] == "url" else None)
            host = canon.domain(host) if host else None
            if host and host not in malicious:
                malicious[host] = _derived_dns(r, host)
        elif r["kind"] == "dns" and r["labels"]["label"] == "benign":
            benign.setdefault(r["body"]["qname"], r)
        elif r["kind"] == "dns" and r["labels"]["label"] == "malicious":
            malicious.setdefault(r["body"]["qname"], r)
    bad_reg = {canon.registrable(h) for h in malicious}
    conflicts = [q for q in benign if canon.registrable(q) in bad_reg]
    for q in conflicts:
        del benign[q]
    stats["dns_benign_dropped_conflict"] = len(conflicts)
    out = []
    by_src = {}
    for rec in list(malicious.values()) + list(benign.values()):
        by_src.setdefault(rec["provenance"]["source_id"], []).append(rec)
    for sid, recs in sorted(by_src.items()):
        for rec in _sample(recs, cap_per_source, "dns:" + sid):
            q = rec["body"]["qname"]
            mal = rec["labels"]["label"] == "malicious"
            if mal and rec["labels"]["label_source"] == "dataset":
                gt = truth("dataset_label", False, f"{sid} family {rec['labels']['family']!r}", "high",
                           "Algorithmically generated by the family's DGA: the label is correct by construction; "
                           "registration status of the name is unknown.")
            elif mal:
                gt = truth("feed_assertion", False, f"{sid} listed a URL/domain on this host",
                           "low" if rec["labels"].get("original_label") == "malware_download" else "medium",
                           "Feed listings are true at listing time; many listed hosts are compromised legitimate sites.")
            else:
                gt = truth("dataset_label", False, f"{sid} popularity rank", "medium",
                           "Popularity is a benign baseline, not proof of benignity.")
            tgt = target(rec["labels"]["label"], evidence=[rec["record_id"]])
            out.append(example("dns_intelligence", "classify", [rec], "Classify the queried name.", tgt, gt,
                               canon.registrable(q) or q))
    return out


# ---------------------------------------------------------------------------- 02 network intelligence
NET_CAP_PER_GROUP = 25_000


def _net_group(rec):
    srid = rec["provenance"]["source_record_id"] or ""
    return srid.split(":", 1)[0] if ":" in srid else (rec["body"]["orig_ip"] or rec["record_id"])


def build_network(records, cap_per_source=None, stats=None, cap_per_group=NET_CAP_PER_GROUP):
    """Flows -> classify examples. Capped per capture scenario (deterministic hash sample) so one huge
    capture (IoT-23 1-1 has ~1M flows) cannot dominate the collection; the per-scenario counts before
    and after the cap are reported in the build stats."""
    stats = stats if stats is not None else {}
    out = []
    by_src = {}
    for r in records:
        if r["kind"] == "flow" and r["labels"]["label"] in ("malicious", "benign"):
            by_src.setdefault(r["provenance"]["source_id"], {}).setdefault(_net_group(r), []).append(r)
    for sid, groups in sorted(by_src.items()):
        kept = []
        for g, recs in sorted(groups.items()):
            sel = _sample(recs, cap_per_group, f"net:{sid}:{g}")
            stats[f"net_group:{sid}:{g}"] = f"{len(sel)}/{len(recs)}"
            kept += sel
        for rec in _sample(kept, cap_per_source, "net:" + sid):
            group = _net_group(rec)
            lm = rec["labels"]["attack_mapping"]
            quality = "low" if sid.startswith("cic-") else "medium"
            gt = truth("dataset_label", False, f"{sid} label {rec['labels']['original_label']!r}", quality,
                       "ATT&CK mapping is a heuristic of the adapter, not the dataset authors'." if lm["techniques"] else None)
            tgt = target(rec["labels"]["label"], attack=mapping(lm["techniques"], lm["tactics"], lm["mapping_source"]),
                         evidence=[rec["record_id"]])
            out.append(example("network_intelligence", "classify", [rec], "Classify this connection.", tgt, gt,
                               f"{sid}:{group}"))
    return out


# ---------------------------------------------------------------------------- 03 attack intelligence
def build_attack(records, cap_per_source=None, stats=None):
    out = []
    for r in records:
        if r["kind"] != "attack_technique":
            continue
        b = r["body"]
        if b["deprecated"] or b["revoked"]:
            continue
        m = r["labels"]["attack_mapping"]
        gt = truth("knowledge_base", True, f"MITRE ATT&CK {b['attack_version'] or ''}".strip(), "high")
        tactics = ", ".join(b["tactics"]) or "none listed"
        ans = f"{b['technique_id']} {b['name']} (tactics: {tactics})."
        out.append(example("attack_intelligence", "knowledge", [r], f"What is ATT&CK technique {b['technique_id']}?",
                           target(None, attack=mapping(m["techniques"], m["tactics"], "source", b["attack_version"]),
                                  evidence=[r["record_id"]], answer=ans), gt, b["technique_id"].split(".")[0]))
    return out


# ---------------------------------------------------------------------------- 05 vulnerability intelligence
def build_vulnerability(records, cap_per_source=None, stats=None):
    out = []
    for r in records:
        if r["kind"] != "vulnerability":
            continue
        b = r["body"]
        if not b["known_exploited"]:
            continue
        parts = [f"{b['cve_id']} ({b['vendor'] or 'unknown vendor'} {b['product'] or ''}".rstrip() + ") is in the CISA Known Exploited Vulnerabilities catalogue"]
        if b["kev_date_added"]:
            parts[0] += f", added {b['kev_date_added']}"
        parts[0] += "."
        if b["ransomware_use"] == "Known":
            parts.append("It is known to be used in ransomware campaigns.")
        if b["cwe_ids"]:
            parts.append("Weakness: " + ", ".join(b["cwe_ids"]) + ".")
        if b["required_action"]:
            parts.append("Required action: " + b["required_action"])
        gt = truth("knowledge_base", True, "CISA KEV (curated by CISA)", "high")
        out.append(example("vulnerability_intelligence", "knowledge", [r],
                           f"Is {b['cve_id']} known to be exploited, and what should be done?",
                           target(None, severity=None, evidence=[r["record_id"]], action="harden", answer=" ".join(parts)),
                           gt, b["cve_id"]))
    out += build_cve_knowledge(records, cap_per_source=cap_per_source, stats=stats)
    return out


# Which record answers "what is CVE-X?" when several sources describe the same CVE: the CVE Program's own
# record first (the CNA wrote it), then a GitHub-reviewed advisory, then anything else.
CVE_SOURCE_RANK = {"cve-list-v5": 0, "github-advisory-db": 1}
CVE_TRUTH = {"cve-list-v5": ("CVE Program record (written by the assigning CNA)", "high"),
             "github-advisory-db": ("GitHub Advisory Database", "medium")}


def _cve_rank(r):
    reviewed = r["labels"]["original_label"] == "github_reviewed"
    return (CVE_SOURCE_RANK.get(r["provenance"]["source_id"], 9), 0 if reviewed else 1, r["record_id"])


def build_cve_knowledge(records, cap_per_source=None, stats=None):
    """One 'what is this CVE and how severe is it?' example per CVE that has a description and at least a
    CWE or a CVSS score. Only facts the record states: no exploitation claim (that is the KEV question),
    no invented remediation. Severity is the CVSS v3/v4 qualitative band; v2 scores keep severity null
    (v2 has no 'critical' band)."""
    from . import cvss as _cvss
    best = {}
    for r in records:
        if r["kind"] != "vulnerability" or r["provenance"]["source_id"] == "cisa-kev":
            continue
        b = r["body"]
        if not b["description"] or not (b["cwe_ids"] or b["cvss"]):
            continue
        cur = best.get(b["cve_id"])
        if cur is None or _cve_rank(r) < _cve_rank(cur):
            best[b["cve_id"]] = r
    chosen = list(best.values())
    if cap_per_source is not None:
        by_src = {}
        for r in chosen:
            by_src.setdefault(r["provenance"]["source_id"], []).append(r)
        chosen = [x for sid in sorted(by_src) for x in _sample(by_src[sid], cap_per_source, "cve-knowledge")]
    out = []
    for r in sorted(chosen, key=lambda r: r["record_id"]):
        b = r["body"]
        sid = r["provenance"]["source_id"]
        what = " ".join(x for x in (b["vendor"], b["product"]) if x)
        desc = b["description"].strip()
        if len(desc) > 6000:  # the answer field is capped at 8192; a few CNA descriptions run past it
            desc = desc[:6000].rsplit(" ", 1)[0] + " [description truncated]"
        parts = [f"{b['cve_id']}" + (f" ({what})" if what else "") + ": " + desc]
        if b["cwe_ids"]:
            parts.append("Weakness: " + ", ".join(b["cwe_ids"]) + ".")
        sev = None
        c = b["cvss"]
        if c:
            if c["version"] != "2.0":
                sev = _cvss.severity(c["base_score"])
            parts.append(f"CVSS v{c['version']} base score {c['base_score']:.1f}"
                         + (f" ({sev})" if sev else "") + f", vector {c['vector']}.")
        src, quality = CVE_TRUTH.get(sid, (sid, "medium"))
        if sid == "github-advisory-db" and r["labels"]["original_label"] == "github_reviewed":
            src, quality = "GitHub Advisory Database (GitHub-reviewed)", "high"
        out.append(example("vulnerability_intelligence", "knowledge", [r],
                           f"What is {b['cve_id']}, and how severe is it?",
                           target(None, severity=sev, evidence=[r["record_id"]], answer=" ".join(parts)),
                           truth("knowledge_base", True, src, quality), b["cve_id"]))
    if stats is not None:
        stats["cve_knowledge"] = {"cves": len(best), "examples": len(out)}
    return out


# ---------------------------------------------------------------------------- 06 SOC reasoning (synthetic)
# Each scenario: (category, rule id, technique, tactic, severity, malicious?, fp considerations, reasoning, action)
# Values use RFC 5737 / RFC 1918 / RFC 2606 ranges only. Benign twins are the documented false-positive
# shapes from os/kernel/kernel/src/corroboration.rs (backup server, monitoring host, scanner).
SOC_SCENARIOS = [
    ("port_scan", 113, "T1046", "TA0007", "medium", True, ["An authorised vulnerability scanner produces the same fan-out."],
     "One external source touched {n} ports on one host in {w} s with mostly RST answers: horizontal/vertical scan shape.", "observe"),
    ("brute_force", 124, "T1110", "TA0006", "high", True, ["A user retrying a forgotten password makes a few attempts, not {n}."],
     "{n} login attempts to port 22 from one external source within {w} s.", "investigate"),
    ("beaconing", 116, "T1071", "TA0011", "medium", True, ["Monitoring agents and update checkers also call home periodically."],
     "Connections every {p} s with a coefficient of variation of 0.01 to a destination this device never used before.", "investigate"),
    ("exfiltration", 118, "T1048", "TA0010", "high", True, ["Scheduled backups upload large volumes to a fixed destination."],
     "{gb} GB left the device to a first-seen external destination outside the device's usual hours.", "investigate"),
    ("dns_dga", 119, "T1071.004", "TA0011", "medium", True, ["CDN hostnames can contain long hexadecimal labels."],
     "{n} NXDOMAIN answers for random-looking names under one parent within {w} s.", "investigate"),
    ("lateral_movement", 117, "T1021", "TA0008", "high", True, ["Configuration-management hosts (Ansible) connect to many peers by design."],
     "An IoT device that normally talks to one cloud endpoint opened SMB/SSH sessions to {n} LAN peers.", "investigate"),
    ("exfiltration", 118, "T1048", "TA0010", "info", False, ["This IS the documented false-positive shape: a backup job."],
     "{gb} GB to the same destination at the same nightly time as the last 30 days; the destination is the configured backup target.", "none"),
    ("beaconing", 116, "T1071", "TA0011", "info", False, ["This IS the documented false-positive shape: an update checker."],
     "Periodic HTTPS every {p} s to the vendor's documented update host, matching the device type's baseline.", "none"),
    ("port_scan", 113, "T1046", "TA0007", "info", False, ["This IS the documented false-positive shape: the operator's own scanner."],
     "Fan-out from the management address the owner registered as the vulnerability scanner, inside the scheduled window.", "allowlist"),
]


def build_soc_synthetic(n_per_scenario=4, seed=7):
    rng = random.Random(seed)
    created = "2026-11-18T00:00:00.000Z"
    out = []
    for si, (cat, rule, tech, tac, sev, mal, fp, why, action) in enumerate(SOC_SCENARIOS):
        for k in range(n_per_scenario):
            params = {"n": rng.choice([24, 60, 180, 600]), "w": rng.choice([30, 60, 300]), "p": rng.choice([30, 60, 300]),
                      "gb": rng.choice([1, 4, 12])}
            src = f"203.0.113.{rng.randint(2, 250)}" if cat in ("port_scan", "brute_force") and mal else f"192.168.10.{rng.randint(2, 250)}"
            dst = f"198.51.100.{rng.randint(2, 250)}" if cat not in ("port_scan", "brute_force") or not mal else f"192.168.10.{rng.randint(2, 250)}"
            rid = canon.sha256_obj(["soc-synth", si, k, seed])[:24]
            rec = {
                "schema": "heqk.security-event/1", "record_id": f"detection:{rid}", "kind": "detection",
                "observed_at": created, "sensor": {"type": "synthetic", "name": "soc-synthetic"},
                "body": {"schema": "heqk.detection/1", "rule_id": 1_200_000 + rule, "rule_msg": cat.replace("_", " "),
                         "category": cat, "severity": "high" if sev == "high" else "medium", "mitre": tech,
                         "src_ip": src, "dst_ip": dst, "dst_port": 22 if cat == "brute_force" else (443 if cat in ("beaconing", "exfiltration") else None),
                         "action": "observed"},
                "labels": {"label": None, "family": None, "label_source": "synthetic", "original_label": None,
                           "attack_mapping": mapping([tech], [tac], "heqk_rulecat")},
                "provenance": {"source_id": "hookprobe-synthetic-soc", "source_record_id": f"{si}:{k}",
                               "acquisition_id": "synthetic:soc-templates-v1", "raw_sha256": None,
                               "license_id": "agpl-3.0-only", "transform": {"name": "soc-templates", "version": VERSION},
                               "created_at": created},
            }
            ctx = {"device_role": "iot_camera" if cat == "lateral_movement" else "workstation", "synthetic": True}
            tgt = target("malicious" if mal else "benign", severity=sev, attack=mapping([tech], [tac], "heqk_rulecat"),
                         evidence=[rec["record_id"]], reasoning="SYNTHETIC: " + why.format(**params), fp=[s.format(**params) for s in fp], action=action)
            gt = truth("synthetic", False, "soc-templates-v1", "unknown",
                       "Template-generated illustration; not real telemetry. Use for format/teaching, never as evidence.")
            out.append(example("soc_reasoning", "triage", [rec], "Assess this detection: verdict, severity, ATT&CK, next step.",
                               tgt, gt, f"soc-synth:{si}", context=ctx))
    return out


BUILDERS = {
    "dns_intelligence": build_dns,
    "network_intelligence": build_network,
    "attack_intelligence": build_attack,
    "vulnerability_intelligence": build_vulnerability,
}
