# SPDX-License-Identifier: AGPL-3.0-only
"""Per-address context tables, used directly by the windows export and the lookup build (not normalised into
records: they describe address space, not events). Agreed with the Neuro session, 2026-11-21.

iptoasn (PDDL 1.0)        IP range -> ASN, AS name, country. Only the CURRENT mapping exists (iptoasn has no
                          history), so context for old captures is "current mapping as of <fetch date>":
                          approximate context, never ground truth.
misp-warninglists (CC0)   known-benign address ranges and names (cloud, CDN, public DNS, ...). Lists that are
                          not CC0 are left out: the X4BNet-derived VPN/datacenter lists (MIT notice) and lists
                          built from third-party rankings with their own terms (Alexa, Cisco Umbrella,
                          Cloudflare Radar, Chrome CrUX, Majestic, Tranco). tor-exit-nodes is a current
                          snapshot, so it is kept for the on-device lookup but never attached to old captures.
"""
import bisect
import gzip
import io
import ipaddress
import json
import os
import re
import tempfile
import zipfile

from . import licensing, safeio

LOADERS = ("iptoasn_tsv", "misp_warninglists_zip")
X4BNET = {"datacenter-ipv4", "datacenter-ipv6", "vpn-ipv4", "vpn-ipv6"}
RANKING = re.compile(r"^(alexa|cisco_top|cloudflare-top|google-chrome-crux|majestic|tranco|umbrella-)")
NOT_FOR_CAPTURES = {"tor-exit-nodes"}  # current snapshots that must be date-matched to a capture
MAX_LIST_JSON = 256 << 20


class ASN:
    """Sorted, non-overlapping ranges per address family; lookup by bisect."""

    def __init__(self, path):
        self.v = {4: ([], []), 6: ([], [])}  # family -> (starts, rows)
        with gzip.open(path, "rb") as raw:
            f = io.TextIOWrapper(safeio._Capped(raw, 1 << 30), encoding="utf-8", errors="replace")
            for _, line in safeio.lines(f):
                p = line.split("\t")
                if len(p) < 5:
                    continue
                try:
                    a, b = ipaddress.ip_address(p[0]), ipaddress.ip_address(p[1])
                    asn = int(p[2])
                except ValueError:
                    continue
                if asn == 0:  # "Not routed"
                    continue
                starts, rows = self.v[a.version]
                starts.append(int(a))
                rows.append((int(b), asn, p[3] if p[3] not in ("", "None") else None, p[4][:128] or None))
        for fam in self.v:
            starts, rows = self.v[fam]
            order = sorted(range(len(starts)), key=starts.__getitem__)
            self.v[fam] = ([starts[i] for i in order], [rows[i] for i in order])

    def lookup(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        starts, rows = self.v[a.version]
        i = bisect.bisect_right(starts, int(a)) - 1
        if i < 0 or int(a) > rows[i][0]:
            return None
        _, asn, cc, name = rows[i]
        return {"asn": asn, "as_name": name, "country": cc}

    def rows(self):
        for fam in (4, 6):
            starts, rows = self.v[fam]
            for s, (e, asn, cc, name) in zip(starts, rows):
                yield fam, s, e, asn, cc, name


def warninglists_kept(name):
    """(kept, reason) for one list name."""
    if name in X4BNET:
        return False, "X4BNet-derived (MIT notice, not CC0)"
    if RANKING.match(name):
        return False, "third-party ranking or vendor list with its own terms"
    return True, None


class Warninglists:
    def __init__(self, path):
        self.lists, self.dropped = {}, {}
        tmp = tempfile.mkdtemp(prefix=".misp-")
        try:
            files = safeio.extract_zip(path, tmp, allow=lambda n: n.endswith("/list.json") and "/lists/" in n)
            for p in sorted(files):
                key = os.path.basename(os.path.dirname(p))
                ok, why = warninglists_kept(key)
                if not ok:
                    self.dropped[key] = why
                    continue
                d = safeio.load_json(p, MAX_LIST_JSON)
                entries = [e for e in d.get("list") or [] if isinstance(e, str)]
                self.lists[key] = {"name": d.get("name") or key, "type": d.get("type"),
                                   "category": d.get("category"), "version": d.get("version"), "entries": entries}
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)
        # address index: (family, prefixlen) -> {network int: [list keys]}
        self.nets = {}
        for key, l in self.lists.items():
            if l["type"] != "cidr":
                continue
            for e in l["entries"]:
                try:
                    n = ipaddress.ip_network(e.strip(), strict=False)
                except ValueError:
                    continue
                self.nets.setdefault((n.version, n.prefixlen), {}).setdefault(int(n.network_address), []).append(key)
        self.plens = {4: sorted(p for v, p in self.nets if v == 4), 6: sorted(p for v, p in self.nets if v == 6)}

    def lookup(self, ip, for_capture=True):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return []
        bits = 32 if a.version == 4 else 128
        x, hits = int(a), set()
        for p in self.plens[a.version]:
            net = x >> (bits - p) << (bits - p) if p else 0
            for k in self.nets[(a.version, p)].get(net, ()):
                if not (for_capture and k in NOT_FOR_CAPTURES):
                    hits.add(k)
        # the stable list id is the key (names change between MISP versions); category gives a short phrase
        return [{"id": k, "name": self.lists[k]["name"], "category": self.lists[k]["category"]} for k in sorted(hits)]


def load(store, registry, purpose, source_ids):
    """{source_id: (table, acquisition)} for the newest acquisition of each source, licence-gated."""
    out = {}
    for sid in source_ids:
        licensing.require(registry.license_of(sid), purpose)
        acqs = [a for a in store.acquisitions(sid) if not a.get("derived_from")]
        if not acqs:
            raise RuntimeError(f"{sid}: no acquisition (fetch it first)")
        a = acqs[-1]
        src = registry.source(sid)
        name = (src["acquisition"] or {}).get("adapter") or src.get("adapter")
        if name == "iptoasn_tsv":
            out[sid] = (ASN(store.raw_path(a)), a)
        elif name == "misp_warninglists_zip":
            out[sid] = (Warninglists(store.raw_path(a)), a)
        else:
            raise RuntimeError(f"{sid}: not a context source")
    return out


def remote_fields(tables, ip):
    """The per-remote context dict for one real address (computed before pseudonymisation)."""
    f = {}
    for sid, (t, a) in tables.items():
        if isinstance(t, ASN):
            r = t.lookup(ip)
            f.update(r or {"asn": None, "as_name": None, "country": None})
            f["asn_source_date"] = a["fetched_at"][:10]
        else:
            f["warninglists"] = t.lookup(ip)
    return f


def manifest_entry(tables):
    out = {}
    for sid, (t, a) in tables.items():
        e = {"acquisition_id": a["acquisition_id"], "fetched_at": a["fetched_at"], "license_id": a["license_id"]}
        if isinstance(t, ASN):
            e["note"] = f"current mapping as of {a['fetched_at'][:10]}; approximate context for older captures"
        else:
            e["lists_kept"] = len(t.lists)
            e["lists_dropped"] = t.dropped
            e["not_for_captures"] = sorted(NOT_FOR_CAPTURES & set(t.lists))
        out[sid] = e
    return out
