# `security/threat-intel/` — HYDRA's bundled IOC feed (ADR 0027)

> `security/exploitability/` already answers "which component on THIS device is known-exploitable
> and reachable right now" (the CVE lens, ADR 0024). This directory is the **IOC/threat-intel
> lens**: "has anything on THIS device's real traffic ever touched a known-bad indicator."

## The feed format — `hookprobe-ioc-v1`

A flat, normalized JSON document — not a full STIX 2.1 bundle, not a MISP export:

```json
{
  "format": "hookprobe-ioc-v1",
  "generated": "YYYY-MM-DD",
  "source_summary": "...",
  "indicators": [
    {
      "value": "1.2.3.4",
      "ioc_type": "ip | domain | sha256 | ja3 | ja4 | ja4s",
      "family": "Emotet",
      "source": "abuse.ch Feodo Tracker",
      "confidence": 0.9,
      "first_seen": "2022-06-04",
      "active": true,
      "mitre": "T1071.001",
      "tlp": "clear",
      "note": "optional, human-readable provenance"
    }
  ]
}
```

**Why this shape, not STIX/MISP verbatim:** it carries the same core fields a STIX 2.1
`indicator` object or a MISP `attribute` carries (value/type/confidence/source/first-seen) without
either format's bundle/pattern-language overhead — tractable to hand-write, parse with `serde_json`
with zero new dependencies, and round-trip to/from either upstream shape later (the additive
live-fetch path, not built in this first version, would simply need a MISP-attribute → this shape
translator, not a rewrite of the matcher). JSON, not CSV: indicator types are heterogeneous
(IP/domain/hash/JA3), so a typed record beats fixed CSV columns, and it matches every other
producer in this workspace (`ingest_detection`/`ingest_flow`/…, all `serde_json`-based).

## Files

| File | Role |
|---|---|
| `snapshots/ioc-feed-YYYY-MM-DD.json` | dated, air-gap-usable **seed** feed — a handful of real, currently-public indicators (abuse.ch Feodo Tracker C2 IPs) + HookProbe-owned canary values (RFC 5737/2606 reserved IP/domain, the public EICAR hash, a synthetic JA3) that exercise every indicator type without shipping a live real-malware sample. |

Installed on-device to `/usr/share/hookprobe/threat-intel/ioc-feed.json` (the dated snapshot
symlinked/copied at image build — mirrors `security/exploitability/`'s own convention).

## Honest limits (see ADR 0027 §Limits)

- **Not full MISP/TAXII/STIX** — a first-version bundled seed + matcher, not a live threat-intel
  platform integration. A live MISP/TAXII fetch is an **additive** enrolled feature, never required
  (standalone/air-gapped works on the bundle alone) — not built in this pass.
- **Exact-match only** — no CIDR-range expansion for IP indicators, no wildcard/suffix matching for
  domains beyond the exact SNI/HTTP-Host string observed. A stated v1 scope limit.
- **Hash matching is type-complete but not live-wired** — the `sha256` indicator type parses and
  matches in the matcher's own tests, but no current host-telemetry event carries a file hash
  (`hookprobe-evidence`'s `files` table is `path`/`action` only) — so it never fires against real
  on-device data yet. Stated, not silently accepted.
- **Feed freshness** is exactly what `generated` says — surfaced via `/api/intel`, never hidden.

## Relationship to `modules/hydra/hydra-feed-fetch.sh` (the OTHER "HYDRA threat feed")

This is a **separate, non-overlapping** mechanism from the existing live CIDR-blocklist fetch
(`modules/hydra/hydra-feed-fetch.sh` + `hydra-feedsync` → a pinned eBPF blocklist map, an
**enforcement** primitive). This feed is **detection/enrichment only** — it never drops a packet;
it produces alert-shaped evidence-graph detections (`crates/hookprobe-hydra`). See ADR 0027 for why
both live under the "HYDRA" name without merging.

## Trust

Matches this crate's own honest posture, same as `security/exploitability/`: the bundled snapshot
file itself is plain, versioned, checked-into-git data (not individually cosign-signed — the whole
OS image's existing SBOM/CBOM/cosign signing already covers on-disk integrity of bundled files, the
same posture `security/exploitability/`'s OSV/EPSS snapshots hold). Matches HYDRA produces flow
through the ordinary, unsigned `detections`/`iocs` evidence-graph path — same as every other
detector in this workspace (NAPSE/host-EDR/dnsxai/AEGIS); only the CVE-lens's OpenVEX document is
itself a signed compliance artifact (ADR 0024), a different class of output.
