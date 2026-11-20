# SPDX-License-Identifier: AGPL-3.0-only
"""Host-hour windows for Neuro (tools/neuro-research): every flow of a capture, grouped per host per UTC hour,
pseudonymised, with the host's previous-24 h baseline, as JSONL that semantic_compression.rep_cards() reads.

One line per window chunk (at most chunk_events events, 50,000 by default; IoT-23 host-hours reach 34.5 M flows):
  {"window_id", "dataset", "acq_id", "source", "host", "hour_utc", "split", "chunk": [i, n],
   "labels": {label: count}, "baseline": {"pairs": [[src, dst], ...], "suffixes": [...]}, "events": [...]}
labels and baseline are on chunk 0 only; a consumer merges the chunks of one window_id. Nothing is capped:
rep_cards' counts (n, fanout_hosts, rst%) need every flow. Peak memory is about the flows of the busiest hour
as tuples (~1 GB for 3.6 M flows, the largest dev-split host-hour; the sealed 43-1 has a 34.5 M-flow hour).
Events follow tools/neuro-research/synth_events.py (Window.flow / Window.dns). Zeek extras (src_port,
service, history, pkts, duration, conn_state, label, detailed_label) are extra keys that rep_cards ignores.

Choices (agreed with the Neuro session, 2026-11-20):
- Host = a LAN (RFC 1918) address. A flow belongs to its originator's window if the originator is LAN,
  otherwise to its responder's window if the responder is LAN (an inbound scan lands on the device it hits).
  Flows stay oriented by initiator either way. Flows with no LAN end have no host and are dropped, counted in
  the manifest: dropped_unattributed (0.0.0.0 / ::, an unconfigured client such as a DHCP discover, which
  Zeek cannot attribute without a MAC) and dropped_remote_to_remote (spoofed or backscatter on the link).
  IPv6 link-local (fe80::/10) and unique-local (fc00::/7) addresses are LAN hosts.
- state is replay_iot23.to_events()'s mapping: REJ/RSTO/RSTR/RSTOS0/RSTRH/S0/SH -> "rst", else "est".
- Pseudonyms are allocated in order of first appearance per capture (time order), so they are injective
  and stable within a capture and reveal nothing about the real address. LAN -> 192.168.0.0/16; remote ->
  198.51.100.0/24 and 203.0.113.0/24 first, then 198.18.0.0/15, then 240.0.0.0/4 up to 255.255.254.254 (scan
  captures reach millions of remotes; a 508-address pool would merge them and corrupt fan-out counts). Only
  .1-.254 of each /24 are used: no pseudonym ends in .0 or .255. IPv6 ->
  2001:db8::/32. Multicast, broadcast and unspecified addresses carry no identity and are kept as they are.
- Domains -> <d>.example by registered domain (last two labels, as semantic_compression._suffix), and
  <s>.<d>.example for the labels in front of it. Note this removes character-level DGA signal.
- baseline.pairs = this window's (src, dst) pairs that the same host also had in the previous 24 h. For
  rep_cards that is the same test as the full 24 h set (`novel = pair not in baseline`), at a fraction of
  the size; a scanning host has millions of pairs a day.
- Compatibility mode (window="scenario-hour") reproduces gen_t0_iot23.py: one window per scenario per hour
  since the first flow, all hosts, the first max_rows rows in file order, relative timestamps on
  2020-01-01, no baseline. Used for the acceptance test only.
Sealed sources/scenarios (registry/sealed.json) are refused unless unsealed explicitly; every unseal is
written to the audit log.
"""
import collections
import datetime
import hashlib
import ipaddress
import json
import os
import shutil
import sqlite3
import tempfile

from . import VERSION, adapters, canon, licensing
from .adapters import Ctx, Reject

# Bump when the window content changes for the same inputs (host rule, pseudonyms, fields, drops), so a new
# export gets a new version directory instead of overwriting one a consumer may already be reading.
# 1 = #1402; 2 = IPv6 local hosts, drops counted by kind.
FORMAT = 2
RST = {"REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH", "S0", "SH"}
SPLIT_RULES = {
    # tools/neuro-research/replay_iot23.py split_of(): dev = sha256(scenario name) % 3 == 0, else test.
    "neuro-sha256-mod3": lambda name: "dev" if int(hashlib.sha256(name.encode()).hexdigest(), 16) % 3 == 0 else "test",
}


def lan(ip):
    """A site-local host: RFC 1918, or IPv6 link-local fe80::/10 and unique-local fc00::/7 (neuro-core peerkey
    is_local()). LAN pseudonyms are 192.168.x.y, so all of these render as H in semantic_compression.kind_of()."""
    if ip.startswith(("10.", "192.168.")):
        return True
    if ":" in ip:
        h = ip.lower().split(":", 1)[0].rjust(4, "0")
        return h[:2] in ("fc", "fd") or h[:3] in ("fe8", "fe9", "fea", "feb")
    if ip.startswith("172."):
        p = ip.split(".")
        return len(p) > 1 and p[1].isdigit() and 16 <= int(p[1]) <= 31
    return False


def _v4(n):
    return f"{n >> 24 & 255}.{n >> 16 & 255}.{n >> 8 & 255}.{n & 255}"


# (first /24 as int, number of /24 blocks). Each /24 gives .1-.254 only: no .0 or .255 is ever emitted (some
# code reads a .255 last octet as broadcast), and 240.0.0.0/4 stops before 255.255.255.0/24.
REMOTE_POOLS = [
    (int(ipaddress.IPv4Address("198.51.100.0")), 1),
    (int(ipaddress.IPv4Address("203.0.113.0")), 1),
    (int(ipaddress.IPv4Address("198.18.0.0")), 512),
    (int(ipaddress.IPv4Address("240.0.0.0")), (1 << 20) - 1),
]
LAN_POOL = (int(ipaddress.IPv4Address("192.168.0.0")), 256)


def _alloc(i, pools):
    for base, blocks in pools:
        if i < blocks * 254:
            return _v4(base + (i // 254) * 256 + i % 254 + 1)
        i -= blocks * 254
    raise RuntimeError("pseudonym pool exhausted")


class Pseudonyms:
    """Per-capture, first-appearance allocation. Injective; deterministic for a given time-ordered stream."""

    def __init__(self):
        self.ip = {}
        self.n_lan = self.n_remote = self.n_v6 = 0
        self.dom = {}
        self.sub = {}

    def addr(self, ip):
        if not ip:
            return ip
        got = self.ip.get(ip)
        if got is not None:
            return got
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return ip
        if a.is_multicast or a.is_unspecified or ip == "255.255.255.255" or (a.version == 4 and ip.endswith(".255") and lan(ip)):
            out = ip  # no identity in these
        elif a.version == 6 and not lan(ip):
            self.n_v6 += 1
            out = str(ipaddress.IPv6Address(int(ipaddress.IPv6Address("2001:db8::")) + self.n_v6))
        elif lan(ip):
            out = _alloc(self.n_lan, [LAN_POOL])
            self.n_lan += 1
        else:
            out = _alloc(self.n_remote, REMOTE_POOLS)
            self.n_remote += 1
        self.ip[ip] = out
        return out

    def domain(self, q):
        parts = q.rstrip(".").lower().split(".")
        reg = ".".join(parts[-2:])
        d = self.dom.setdefault(reg, f"d{len(self.dom) + 1}.example")
        if len(parts) <= 2:
            return d
        pre = ".".join(parts[:-2])
        s = self.sub.setdefault((reg, pre), f"s{sum(1 for k in self.sub if k[0] == reg) + 1}")
        return f"{s}.{d}"

    def stats(self):
        return {"lan": self.n_lan, "remote": self.n_remote, "ipv6": self.n_v6, "domains": len(self.dom)}


def _iso(t):
    dt = datetime.datetime.fromtimestamp(t, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (dt.microsecond // 1000)


def _epoch(iso):
    return datetime.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def _flow_tuple(rec):
    """normalised flow record -> compact tuple (ts first, so tuples sort by time)."""
    b, lab = rec["body"], rec["labels"]
    orig = (lab["original_label"] or "-").split("/", 1)
    return (_epoch(b["ts_start"]), b["orig_ip"] or "", b["orig_port"], b["resp_ip"] or "", b["resp_port"],
            b["proto"], b["service"], b["orig_bytes"], b["resp_bytes"], b["orig_pkts"], b["resp_pkts"],
            b["conn_state"], b["history"], b["duration_s"], orig[0], orig[1] if len(orig) > 1 else "-")


def _event(t, ts, P):
    _, o, op, r, rp, proto, svc, ob, rb, opk, rpk, cs, hist, dur, label, det = t
    return {"type": "flow", "ts": ts, "src_ip": P.addr(o), "dst_ip": P.addr(r), "dst_port": rp or 0, "proto": proto,
            "bytes_out": ob or 0, "bytes_in": rb or 0, "state": "rst" if cs in RST else "est",
            "src_port": op, "service": svc, "history": hist, "orig_pkts": opk, "resp_pkts": rpk, "duration": dur,
            "conn_state": cs, "label": label, "detailed_label": det}


def _label_key(t):
    return t[14] if t[15] in ("-", "", None) else f"{t[14]}/{t[15]}"


def sealed(registry_dir):
    p = os.path.join(registry_dir, "sealed.json")
    if not os.path.exists(p):
        return []
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)["sealed"]


def is_sealed(entries, source_id, scenario, split=None, split_rule=None):
    """scope: "*" (whole source), a list of scenario names, or "split:<name>@<rule>" (every scenario that
    the named split rule puts in that split, whichever rule the export itself uses)."""
    for e in entries:
        if e["source_id"] != source_id:
            continue
        sc = e["scope"]
        if sc == "*" or (isinstance(sc, list) and scenario in sc):
            return e
        if isinstance(sc, str) and sc.startswith("split:"):
            name, rule = sc[6:].split("@", 1)
            if SPLIT_RULES[rule](scenario) == name:
                return e
    return None


def _flows(store, registry, acq):
    source = registry.source(acq["source_id"])
    name = source.get("adapter") or (source["acquisition"] or {}).get("adapter")
    mod = adapters.get(name)
    ctx = Ctx(source, acq, name, mod.VERSION, store.pseudonym_key())
    rejects = 0
    for item in mod.parse(store.raw_path(acq), ctx):
        if isinstance(item, Reject):
            rejects += 1
            continue
        if item["kind"] != "flow" or not item["body"]["ts_start"]:
            rejects += 1
            continue
        yield item
    _flows.rejects = rejects


class _Spill:
    """Hour-bucketed spill files, so a capture of any size is regrouped by hour with bounded memory."""

    def __init__(self, d, max_open=64):
        self.d, self.max_open, self.open = d, max_open, collections.OrderedDict()
        self.hours = set()

    def add(self, hour, t):
        f = self.open.get(hour)
        if f is None:
            if len(self.open) >= self.max_open:
                self.open.popitem(last=False)[1].close()
            f = open(os.path.join(self.d, f"{hour}.jsonl"), "a", encoding="utf-8")
            self.open[hour] = f
            self.hours.add(hour)
        else:
            self.open.move_to_end(hour)
        f.write(json.dumps(t) + "\n")

    def close(self):
        for f in self.open.values():
            f.close()
        self.open.clear()

    def read(self, hour):
        with open(os.path.join(self.d, f"{hour}.jsonl"), "r", encoding="utf-8") as f:
            return [tuple(json.loads(ln)) for ln in f]


class _PairHistory:
    """(host, src, dst) -> last hour seen, on disk: a scanning host has tens of millions of pairs a day."""

    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.executescript("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;"
                              "CREATE TABLE seen (host TEXT, pair INTEGER, hour INTEGER, PRIMARY KEY (host, pair)) WITHOUT ROWID;")

    @staticmethod
    def _key(k):
        return int.from_bytes(hashlib.blake2b(f"{k[0]}|{k[1]}".encode(), digest_size=8).digest(), "big", signed=True)

    def seen_since(self, host, pairs, lo, hi):
        keys = {self._key(k): k for k in pairs}
        ks, out = list(keys), []
        for i in range(0, len(ks), 900):
            part = ks[i:i + 900]
            q = "SELECT pair FROM seen WHERE host = ? AND hour >= ? AND hour < ? AND pair IN (%s)" % ",".join("?" * len(part))
            out += [keys[p] for (p,) in self.db.execute(q, [host, lo, hi] + part)]
        return out

    def mark(self, host, pairs, hour):
        self.db.executemany("INSERT OR REPLACE INTO seen VALUES (?, ?, ?)", ((host, self._key(k), hour) for k in pairs))

    def prune(self, before):
        self.db.execute("DELETE FROM seen WHERE hour < ?", (before,))

    def close(self):
        self.db.close()


def _write_window(out, head, n_events, make_events, chunk_events):
    """Chunk i of n carries events [i*size, (i+1)*size); labels and baseline are on chunk 0 only. Event dicts
    are made one chunk at a time (make_events(lo, hi)), so a window of millions of flows is never all in memory
    as dicts."""
    size = chunk_events or max(1, n_events)
    n = max(1, -(-n_events // size))
    for i in range(n):
        line = dict(head, chunk=[i, n], events=make_events(i * size, (i + 1) * size))
        if i:
            line["labels"], line["baseline"] = {}, {"pairs": [], "suffixes": []}
        out.write(json.dumps(line, separators=(",", ":")) + "\n")
    return n


def host_windows(store, registry, acq, out, split, chunk_events=0, workdir=None):
    """Write every host-hour window of one acquisition to `out`. Returns counts."""
    scenario = acq["filename"].split("__", 1)[0]
    P = Pseudonyms()
    tmp = tempfile.mkdtemp(prefix=".windows-", dir=workdir or store.root)
    counts = collections.Counter()
    try:
        sp = _Spill(tmp)
        for rec in _flows(store, registry, acq):
            t = _flow_tuple(rec)
            o, r = t[1], t[3]
            host = o if lan(o) else r if lan(r) else None
            counts["flows"] += 1
            if host is None:
                counts["flows_without_lan_host"] += 1
                unspec = o in ("0.0.0.0", "::") or r in ("0.0.0.0", "::")
                counts["dropped_unattributed" if unspec else "dropped_remote_to_remote"] += 1
                continue
            sp.add(int(t[0] // 3600), (host,) + t)
        sp.close()
        counts["rejects"] = getattr(_flows, "rejects", 0)
        hist = _PairHistory(os.path.join(tmp, "pairs.sqlite"))
        last_prune = None
        for hour in sorted(sp.hours):
            if last_prune is None or hour - last_prune >= 24:
                hist.prune(hour - 24)
                last_prune = hour
            rows = sp.read(hour)
            rows.sort(key=lambda x: (x[1], x[0]))  # time order, so first-appearance pseudonyms are deterministic
            by_host = collections.OrderedDict()
            for x in rows:
                by_host.setdefault(x[0], []).append(x[1:])
            for host, flows in by_host.items():
                pairs, labels = {}, collections.Counter()
                for t in flows:  # allocates pseudonyms in time order before any event is written
                    labels[_label_key(t)] += 1
                    k = (t[1], t[3])
                    if k not in pairs:
                        pairs[k] = (P.addr(t[1]), P.addr(t[3]))
                known = hist.seen_since(host, pairs, hour - 24, hour)
                base = {pairs[k] for k in known}
                hist.mark(host, pairs, hour)
                hour_utc = _iso(hour * 3600)[:13] + ":00Z"
                head = {"window_id": f"{scenario}|{P.addr(host)}|{hour_utc}", "dataset": acq["source_id"],
                        "acq_id": acq["acquisition_id"], "source": scenario, "host": P.addr(host), "hour_utc": hour_utc,
                        "split": split, "labels": dict(sorted(labels.items())),
                        "baseline": {"pairs": sorted([list(p) for p in base]), "suffixes": []}}
                counts["lines"] += _write_window(out, head, len(flows),
                                                 lambda lo, hi, f=flows: [_event(t, _iso(t[0]), P) for t in f[lo:hi]],
                                                 chunk_events)
                counts["windows"] += 1
                counts["events"] += len(flows)
                counts["max_window_events"] = max(counts["max_window_events"], len(flows))
        counts.update({f"pseudonyms_{k}": v for k, v in P.stats().items()})
        hist.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return counts


def scenario_hour_windows(store, registry, acq, out, split, max_rows=1_500_000):
    """gen_t0_iot23.py compatibility: scenario x hour since first flow, first max_rows rows in file order."""
    scenario = acq["filename"].split("__", 1)[0]
    rows = []
    for rec in _flows(store, registry, acq):
        rows.append(_flow_tuple(rec))
        if len(rows) >= max_rows:
            break
    counts = collections.Counter(flows=len(rows))
    if not rows:
        return counts
    rows.sort(key=lambda x: x[0])
    t0 = rows[0][0]
    buckets = collections.defaultdict(list)
    for x in rows:
        buckets[int((x[0] - t0) // 3600)].append(x)
    P = Pseudonyms()
    for k in sorted(buckets):
        start = t0 + k * 3600
        events, labels = [], collections.Counter()
        for t in buckets[k]:
            rel = t[0] - start
            ts = "2020-01-01T%02d:%02d:%06.3fZ" % (int(rel // 3600) % 24, int(rel // 60) % 60, rel % 60)
            events.append(_event(t, ts, P))
            labels[_label_key(t)] += 1
        head = {"window_id": f"{scenario}|{k}", "dataset": acq["source_id"], "acq_id": acq["acquisition_id"],
                "source": scenario, "host": None,
                "hour_utc": None, "window_index": k, "split": split, "labels": dict(sorted(labels.items())),
                "baseline": {"pairs": [], "suffixes": []}}
        counts["lines"] += _write_window(out, head, len(events), lambda lo, hi, e=events: e[lo:hi], 0)
        counts["windows"] += 1
        counts["events"] += len(events)
    return counts


def export(store, registry, source_id, purpose, split_rule, out_root=None, window="host-hour", splits=None,
           unseal=(), chunk_events=50_000, max_rows=1_500_000, registry_dir=None):
    """Windows for every FULL (unsampled) acquisition of `source_id`. Refuses sampled acquisitions (timelines
    need every flow), sealed scenarios unless unsealed, and anything the licence gate denies for `purpose`."""
    lic = registry.license_of(source_id)
    licensing.require(lic, purpose)
    rule = SPLIT_RULES[split_rule]
    seal = sealed(registry_dir or registry.root)
    acqs = {}
    for a in store.acquisitions(source_id):
        if a.get("derived_from"):
            continue
        acqs[a["filename"]] = a  # ordered by fetched_at: the newest full copy of a file wins
    version = "windows-" + canon.sha256_obj([FORMAT, sorted(a["acquisition_id"] for a in acqs.values()), VERSION, purpose,
                                             split_rule, window, sorted(splits or []), sorted(unseal), chunk_events,
                                             max_rows if window == "scenario-hour" else None])[:12]
    out_dir = os.path.join(out_root or os.path.join(store.root, "builds"), version)
    if os.path.exists(os.path.join(out_dir, "manifest.json")):
        # build directories are immutable: a finished export is never rewritten (consumers pin its manifest)
        raise RuntimeError(f"{out_dir} is a finished export and is never rewritten; delete it explicitly to redo it")
    os.makedirs(out_dir, exist_ok=True)
    manifest = {"schema": "heqk.windows-manifest/1", "version": version, "tool_version": VERSION, "format": FORMAT, "purpose": purpose,
                "source_id": source_id, "license": {k: lic.get(k) for k in ("id", "name", "spdx", "url", "attribution_required", "verified_on")},
                "attribution": registry.source(source_id).get("attribution"),
                "window": window, "split_rule": {"name": split_rule, "params": {"modulus": 3, "dev_if": 0}},
                "splits": sorted(splits) if splits else None, "chunk_events": chunk_events,
                "max_rows": max_rows if window == "scenario-hour" else None, "files": [], "skipped": {}, "unsealed": []}
    for fn in sorted(acqs):
        a = acqs[fn]
        scenario = fn.split("__", 1)[0]
        s = rule(scenario)
        if splits and s not in splits:
            manifest["skipped"][scenario] = f"split {s} not requested"
            continue
        e = is_sealed(seal, source_id, scenario)
        if e:
            if source_id not in unseal:
                manifest["skipped"][scenario] = "sealed: " + e["reason"]
                continue
            store.audit("unseal", source_id=source_id, scenario=scenario, purpose=purpose, reason=e["reason"])
            manifest["unsealed"].append(scenario)
        path = os.path.join(out_dir, f"{scenario}.jsonl")
        with open(path + ".partial", "w", encoding="utf-8") as out:
            if window == "host-hour":
                c = host_windows(store, registry, a, out, s, chunk_events)
            else:
                c = scenario_hour_windows(store, registry, a, out, s, max_rows)
        os.chmod(path + ".partial", 0o444)
        os.replace(path + ".partial", path)
        manifest["files"].append({"file": os.path.basename(path), "scenario": scenario, "split": s,
                                  "acquisition_id": a["acquisition_id"], "sha256": _sha(path), **dict(c)})
    with open(os.path.join(out_dir, "manifest.json.partial"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1, sort_keys=True)
    os.chmod(os.path.join(out_dir, "manifest.json.partial"), 0o444)
    os.replace(os.path.join(out_dir, "manifest.json.partial"), os.path.join(out_dir, "manifest.json"))
    store.audit("windows", source_id=source_id, version=version, purpose=purpose, files=len(manifest["files"]))
    return out_dir, manifest


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()
