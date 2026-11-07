# ADR 0027 — HYDRA's IOC/threat-intel lens: a bundled feed × the evidence graph's own data

**Status:** 🟢 Accepted (2026-07-08). Implemented as a working, tested, gate-green first version:
the `hookprobe-hydra` crate (`crates/hookprobe-hydra/`), the `iocs` evidence-graph table +
`enriched_by`/`ioc_seen_on` edges, `GET /api/intel`, the `hookprobe-hydra.{service,timer}` units,
and the bundled IOC feed (`security/threat-intel/`). Ships as a real, signed, staged module —
`modules/hydra/module.yaml` (`status: stub` removed; `runtime: host`, `signature: required`, a
reference-entry `staging:`/`artifacts:` block, real per-arch executable digests).

**Update 2026-07-11 (Finding-1 — the corroboration/enforcement-safety gate, product-steward
recording code-developer's landing).** The 2026-07-10 CM5 metal pentest reproduced a real safety
defect: a HYDRA IOC match fed the trust/quarantine plane **unconditionally**, so a SINGLE injected
flow to ONE bundled C2 IOC IP — historical (`active:false`), shared/CGNAT, or a mislabelled
customer IP — quarantined the host within one trust cycle (a legit customer briefly cut off). This
violates the ADR 0023 invariant "a legitimate customer connection must ALWAYS pass; drop/quarantine
only CONFIRMED attacks." Two layers now bound it: **Layer-1** `crates/hookprobe-hydra/src/verdict.rs`
— a bounded, corroboration-gated trust contribution (active-only for enforcement + confidence/
severity weighting + N-signal corroboration before a `malicious` verdict; a lone hit can never by
itself quarantine); **Layer-2** `crates/hookprobe-manifest/src/trust.rs` (`PostureSignal::IntelOnly`
— a HYDRA-sourced posture signal must be independently CORROBORATED before it may quarantine, else
it can at most observe). **Task #19 RESOLVED (2026-07-16, metal-validated Pi4 + CM5):** the intel
bridge is now WIRED end-to-end. Layer-1 `verdict.rs` is **linked + fed** — `pub mod verdict`
(`crates/hookprobe-hydra/src/lib.rs:20`) and the `hookprobe-hydra --verdicts-out` binary writes
per-device verdicts to `/var/lib/hookprobe/hydra-verdicts`; the supervisor reads them via
`--hydra-verdicts` (`supervisor/src/main.rs:215,1336`) and `trust::intel_signals_from_hydra`
(`crates/hookprobe-manifest/src/trust.rs:413`) folds them as `IntelOnly` (main.rs:1343 — **no longer
`&[]`**). A **security-audit-caught corroboration bug was fixed** in the same pass: treating the
global QSECBIT score as a distinct corroborating signal would have let a lone IOC hit quarantine a
legit customer, so HYDRA-derived signals are now **score-only** and require ≥N *independent*
corroboration before they may quarantine, with the **mgmt-floor backstop** (`trust.rs:371`) that
never enforces on a management source. On-metal (2026-07-16, clean net) the quarantine set stayed
empty and separation held. **Honest residual:** the corroboration-source diversity is only as strong
as the live detection plane feeding it (still a small bundled IOC set — 7 IOCs); real feed breadth
is future work. Relates-to [ADR 0023](0023-enforcement-separation.md).

**Deciders:** code-developer (author), os-architect (the `runtime: host` tier decision — same
reasoning as `hookprobe-exploit`/ADR 0024), security-auditor ("trust nothing unsigned" — this
module must never ship auto-enabled + unsigned), verification-engineer (the fixture-indicator ×
fixture-flow test discipline this ADR requires), release-engineer (the reference-entry module.yaml
pattern this reuses from `modules/exploit`/`modules/api`/`modules/evidence`).

**Relates to:** [ADR 0024](0024-exploitability-vex-pipeline.md) (`hookprobe-exploit` — HYDRA's CVE
lens; this ADR is HYDRA's OTHER half, explicitly anticipated by ADR 0024 D5: "when HYDRA's broader
threat-intel enrichment is built, this crate is the CVE-lens it subsumes or calls"),
[ADR 0009](0009-soc-brain-edge-cloud.md) (the ONE evidence graph both lenses fold into),
[ADR 0015](0015-registry-driven-module-inclusion.md) (the C3 reference-entry pattern this module
uses — a crate living outside `modules/` gets a `staging:` override block, not a relocation),
[ADR 0016](0016-artifact-hash-signing.md)/[ADR 0021](0021-multiarch-native-artifact-digests.md)
(per-arch executable digest binding), [ADR 0026](0026-sigma-yara-detection.md) (the reserved
`rule_id` band idiom this ADR's own band follows), [ADR 0023](0023-enforcement-separation.md)
(gate 0.7 — this module is alert/enrich ONLY, never enforcement).

## Context

`modules/hydra/module.yaml` was `status: stub` — the Intelligence workspace's IOC/threat-intel
surface was 100% mock (`os/mission-control/src/store/itlMock.ts`'s hard-coded CVE list; no IOC concept existed at
all). ADR 0024 already built HYDRA's CVE lens (`hookprobe-exploit`: SBOM→CVE→EPSS→VEX→SSVC) and
explicitly flagged the OTHER half as future work: matching IOC indicators (IPs/domains/hashes/JA3)
against the SOC's own real traffic. This ADR builds that first version — not full MISP/TAXII/STIX
compatibility, a working, tested, honestly-scoped bundled feed + matcher that fires real enriched
detections from real flow data.

The invariants that shape the design: standalone/air-gapped by default (a bundled feed is the
baseline; live fetch is additive, not built here); detect-once/act-on-it (reuse the SAME
`ingest_detection` path every other engine uses); trust-nothing-unsigned (this module ships
signed, never auto-enabled unsigned); honest (feed freshness disclosed, hash-matching's dormant
status stated plainly, not fabricated).

## Decision

### D1 — A bundled, dated, normalized feed: `hookprobe-ioc-v1`

A flat JSON document (`security/threat-intel/snapshots/ioc-feed-YYYY-MM-DD.json`) carrying the same
core fields a STIX 2.1 `indicator` or a MISP `attribute` carries — `value`/`ioc_type`/`family`/
`source`/`confidence`/`first_seen`/`active`/`mitre`/`tlp` — without either upstream format's
bundle/pattern-language overhead. JSON, not CSV: indicator types are heterogeneous (IP/domain/
hash/JA3/JA4/JA4S), so a typed record beats fixed CSV columns; this also matches every other
producer in this workspace (all `serde_json`-based). v1 shipped four indicator types (`ip`,
`domain`, `sha256`, `ja3`); `ja4`/`ja4s` were added 2026-07-09 (detection-surface expansion —
see "Honest limits" below). An unrecognized `ioc_type` in the feed is skipped at load time with a
printed warning — the SAME skip-with-a-reason contract `modules/sigma`/`modules/yara-scan` hold to
for unsupported constructs, never silently misinterpreted.

The FIRST bundled snapshot mixes **3 real, currently-public** botnet C2 IPs (fetched live from
abuse.ch Feodo Tracker — a redistribution-friendly public feed this repo already references in
`modules/hydra/hydra-feed-fetch.sh`) with **4 HookProbe-owned canary indicators** (RFC 5737/2606
reserved IP/domain values, the public EICAR test-file's own sha256, a synthetic JA3 in the correct
shape) — proving every indicator type parses and matches end-to-end without needing, or shipping, a
live real-malware sample (the same bar `modules/yara-scan`'s bundled EICAR rule already set).
`active: false` entries stay in the feed (counted, disclosed) but never fire — an honest way to
retire a stale indicator without deleting the historical record.

### D2 — The matcher: flow/application-pivot data, not a second telemetry source

`crates/hookprobe-hydra`'s matcher (`src/matcher.rs`) reads `flows` + the SAME `applications` pivot
`ingest_flow` already builds (TLS SNI / HTTP Host / JA3 — `hookprobe_evidence::EvidenceGraph::
ioc_flow_candidates`, a new watermarked read method, the SAME "read since last run, then advance"
idiom `correlate_all`'s own watermark uses) — no new capture/telemetry path, no duplicated flow
ingestion. Matching is exact-value only in this v1 (no CIDR-range expansion for IPs, no wildcard/
suffix matching for domains) — a stated scope limit, not silently accepted.

**Attribution convention (mirrors existing shapes, never invented):** an outbound IP match
(`dst_ip` is the indicator) attributes `src_ip` = the LAN device, `dst_ip` = the indicator — the
SAME shape rule `1_000_040` (C2 beaconing) uses. An inbound IP match (`src_ip` is the indicator)
attributes `src_ip` = the attacker, `dst_ip` = the LAN device targeted — the SAME shape
`1_000_003`/`1_000_001` (port-scan/brute-force) use. A domain match rides the matched value in
`dst_ip` — the SAME convention `ingest_dns_verdict` already uses for a DNS-layer detection. A JA3
match keeps the flow's real destination; the fingerprint rides in `indicator`/`rule_msg` only.

### D3 — `rule_id` band: `4,000,000,000 +`, one band above YARA's

Every other engine in this workspace uses a small, hand-enumerated `rule_id` per fixed detection
(NAPSE `1,000,001`–`1,000,025` + `napse-capture`'s extras; `host_edr` `1,000,100`–`1,000,118`; the
resource-shed `1,000,050`; the supply-chain bands `9,1xx,xxx`/`9,2xx,xxx`; Sigma `2,000,000,000+`;
YARA `3,000,000,000+` — checked against the tree, 2026-07-08). IOC indicators are open-ended and
pluggable — a bundled feed can carry any number of arbitrary values — exactly the same shape
Sigma/YARA rules are, so HYDRA reserves its OWN numeric space, one band above YARA's, using the
SAME FNV-1a-then-mask idiom: **`4,000,000,000 + (fnv1a(indicator_value) & 0x0FFFFFFF)`**
(`crates/hookprobe-hydra/src/rule.rs::hydra_rule_id`). Deterministic per indicator value — a
repeat sighting of the same indicator always gets the same `rule_id`, so `hookprobe-evidence
--stats`'s per-rule_id breakdown groups them together, like Sigma/YARA's own rule ids do.

### D4 — Enrichment, not just a fourth alert source

A confirmed match does three things through
`hookprobe_evidence::EvidenceGraph::ingest_ioc_match` (a new method, reusing
[`ingest_detection`](../../legacy/linux-tier/crates/hookprobe-evidence/src/lib.rs) verbatim for the detection row
itself — zero duplicated device-upsert/flow-linkage/user-attribution logic):

1. Upserts the pre-existing `iocs` table row (`id`/`ts`/`indicator`/`ioc_type`/`family`/`hits` —
   `hits` accumulates across sightings, never re-created per match).
2. `enriched_by`: the NEW detection → the ioc node.
3. `ioc_seen_on`: the ioc node → whichever side of the match is a REAL local device (never the
   indicator's own value — a domain match writes the domain into `dst_ip`, which must not be
   mistaken for "a device the ioc was seen on").
4. `enriched_by` again onto every OTHER pre-existing `detections` row that already names this exact
   indicator value (as either `src_ip` or `dst_ip`) — e.g. a NAPSE port-scan whose attacker IP is
   ALSO a known-bad indicator now carries that intel context too — and onto every pre-existing
   `incidents` row for a device this match touched (checked WITHOUT excluding the indicator's own
   value here, deliberately: `correlate_incident` keys an incident by its triggering detections'
   `src_ip`, which for an inbound attack IS the attacker's IP — exactly the value an inbound IOC
   match names, so excluding it would silently miss the one incident most relevant to the match).

This is what makes HYDRA an ENRICHER, not merely a fifth alert source alongside NAPSE/host-EDR/
dnsxai/AEGIS/Sigma/YARA.

### D5 — `GET /api/intel`: real IOC data, names the CVE lens rather than duplicating it

`crates/hookprobe-api`'s new `intel` handler calls a new `EvidenceGraph::list_intel` (iocs ordered
highest-hit-first + a type-breakdown summary + the most recent `category='threat_intel'`
detections). Deliberately does NOT re-serve the CVE/VEX data `/api/exploitability` already owns —
the response carries `"cve_lens": "/api/exploitability"` so the Intelligence workspace calls both
endpoints to render the full picture, never duplicating one lens's data inside the other's payload.

### D6 — Shipping: `runtime: host`, reusing the `hydra` registry id (not a new one)

`crates/hookprobe-hydra` is architecturally identical to `hookprobe-exploit`: it needs direct,
transactional evidence-DB read+write (candidate flows in, enriched detections out), which a WASI
sandbox cannot give it — so it ships as a native binary + systemd timer, the SAME `runtime: host`
tier `hookprobe-evidence`/`hookprobe-api`/`hookprobe-exploit`/`modules/sigma` already use.

Unlike `hookprobe-exploit` (which minted a brand-new `modules/exploit` registry id, because no
dedicated "exploit" id existed before it), this crate ships through the ALREADY-EXISTING
`modules/hydra/module.yaml` — `hydra` was already the canonical registry id/title/workspace for
this exact capability domain, just with nothing buildable behind it (`status: stub`). Reusing it
rather than minting a `modules/hydra-intel` duplicate is the more coherent "one system" choice: one
HYDRA id, one place an operator or auditor looks for "what does HYDRA actually ship." `status: stub`
is removed; the module now carries a real `staging:` reference-entry block (crate + bundled feed +
units) and a real per-arch (amd64 + arm64) `role: executable` digest, `signature: required` — never
shipped auto-enabled and unsigned (the concrete failure mode this ADR's own review flagged and
this pass closes, matching the `modules/sigma`/`modules/yara-scan` precedent of never leaving a
staged, auto-enabled module without a computed digest).

### D7 — Relationship to `hydra-feedsync` (a pre-existing, unrelated mechanism, same name)

A THIRD, pre-existing "HYDRA threat feed" already lives under the `hydra` module id:
`hydra-feed-fetch.sh` + `units/hydra-feedsync.{service,timer}` (source:
`modules/napse-capture/loader/src/bin/hydra-feedsync.rs`) — a LIVE fetch of public CIDR blocklists
(Spamhaus DROP/eDROP, Firehol level1, Emerging Threats, Feodo Tracker, SSLBL) that feeds a pinned
eBPF blocklist map. That is an **enforcement** primitive (it drops traffic); `crates/hookprobe-hydra`
is **detection/enrichment only** (gate 0.7 — no `CAP_NET_ADMIN`/`CAP_BPF`, no nft/tc/BPF-map
access, ever). The two are deliberately NOT merged: same "HYDRA" name, two genuinely
non-overlapping capabilities. This module.yaml's `staging:` block stages ONLY
`crates/hookprobe-hydra`; `hydra-feed-fetch.sh`/`hydra-feedsync` remain an unchanged, pre-existing,
still-not-staged gap — tracked, not silently fixed or silently ignored, and out of this ADR's scope.

## Honest limits (state plainly — do not let "HYDRA threat-intel" overclaim)

- **Not full MISP/TAXII/STIX.** A first-version bundled seed + matcher, not a live threat-intel
  platform integration. A live MISP/TAXII/OSV-style fetch is an **additive** enrolled feature —
  standalone/air-gapped devices assess against exactly the bundled snapshot, never required to
  reach out. Not built in this pass.
- **Exact-match only.** No CIDR-range expansion for IP indicators, no wildcard/suffix domain
  matching beyond the literal SNI/HTTP-Host string a flow actually presented.
- **Hash matching is live-wired (2026-07-09, detection-surface expansion — roadmap item B).**
  `matcher::match_hash`/`scan_file_candidates` now run from `main.rs`'s live pass, fed by
  `hookprobe_evidence::EvidenceGraph::ioc_file_candidates` (its own `hydra_file_watermark`,
  independent of the flow scan's `hydra_watermark`) against `files.sha256` — a real column now,
  populated by `hookprobe-fanotify` hashing a `FAN_CLOSE_WRITE` event's content (capped at 64 MiB;
  an oversized file's hash is left empty rather than a fabricated partial-content hash — see that
  binary's `hash_fd_content` doc). This closes the gap this ADR originally stated plainly.
- **JA4/JA4S matching (2026-07-09, same expansion).** `IocType::Ja4`/`Ja4s` extend the original
  four types; `napse_loader::dpi` now computes the modern FoxIO JA4+ TLS-fingerprint suite
  (JA4 = TLS client, JA4S = TLS server) alongside the legacy JA3, carried through
  `applications.ja4`/`ja4s` and matched by `scan_flow_candidates` exactly like JA3. `Ja4h` (the
  HTTP-client fingerprint) is deliberately NOT added as a feed-matchable type — see
  `hookprobe_hydra::feed::IocType`'s own doc comment for why an HTTP fingerprint is a much higher
  false-positive surface for a threat-intel feed specifically than a TLS fingerprint is; `ja4h`
  still rides the HTTP flow record for the operator's own drill-down/correlation use, just not fed
  through this matcher.
- **Feed freshness** is exactly what the bundled snapshot's `generated` field says, disclosed via
  the feed's own metadata — never hidden or implied to be live.
- **`hydra-feedsync` (the CIDR-blocklist enforcement mechanism) is untouched** — see D7. Its own
  "does it even stage/run" gap is pre-existing and NOT addressed by this ADR.

## Consequences

**Positive:** the Intelligence workspace's IOC claim stops being pure fiction — real indicators,
real matches against this device's own traffic, real evidence-graph enrichment linking new AND
pre-existing detections/incidents to the intel that explains them, for an engine class that
previously produced zero output ever. `modules/hydra/module.yaml` finally ships something real
under the id CLAUDE.md's own component table has always named. The `rule_id`/enrichment-edge
pattern this ADR establishes (D3/D4) is a template a future live-feed integration can extend
without another evidence-graph schema change.

## Alternatives considered

- **A full MISP/TAXII client as the primary path** — rejected: violates standalone/air-gapped-by-
  default; a working bundled feed beats a live-fetch subsystem that doesn't ship. Fetch is additive.
- **A new `modules/hydra-intel` registry id** (mirroring `hookprobe-exploit`'s own `modules/exploit`
  precedent exactly) — considered, rejected: `hydra` already IS the canonical id for this domain: a
  second id would fragment "what HYDRA ships" across two registry entries for no benefit (D6).
- **Folding IOC matching into `hookprobe-exploit`** — rejected: different data (indicators vs
  CVEs), different inputs (flows/applications vs SBOM/manifest), different rule_id band; keeping
  them separate crates keeps each one's blast radius and test surface small, while `/api/intel`
  names `/api/exploitability` as the sibling lens rather than merging the two payloads.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: NEUTRAL.** HYDRA reads flows/applications from the evidence graph and enriches — detection/enrich only, no kernel coupling. It ports directly (running in the Zone-4 guest for the heavy 11-service stack); the enforcement it feeds is the same re-hosted quarantine plane. → **Phases M5/M6**.
