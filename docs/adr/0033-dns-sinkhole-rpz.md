# ADR 0033 — DNS sinkhole / RPZ enforcement (roadmap A1): refuse a NAME, never a customer's PACKET

**Status:** 🟢 Accepted (implemented, metal-validated 2026-07-16). Implemented as a working, tested
version: `crates/hookprobe-dns-sinkhole/` (a library + `hookprobe-dns-sinkhole` binary + timer, 24 unit
tests, 0 clippy warnings), `modules/dns-sinkhole/module.yaml` (`runtime: host`, reference-entry
staging block, `signature: required`), `modules/dns-sinkhole/dns-sinkhole-allowlist.default.yaml`
(the shipped, operator-owned FP-safety file), `base/scripts/dns-sinkhole-apply.sh` (the tool-gated
resolver apply hook). **Accepted (2026-07-16):** the arm64 native digest + the `verify-staging` arm64
gate landed this session and the module is staged into the metal-validated Pi4/CM5 image;
dnsxai live scoring corroborated on-metal (2026-07-10). **Honest limits that REMAIN (do not claim
these done):** a full cosign/OCI-registry release-signing pass has not run, and the stock-device
resolver this RPZ actually loads into does not exist yet (see D5) — so NAME-level enforcement is
staged-and-validatable but not yet the default on-device path. code-developer built this on direct
instruction (roadmap item A1); os-architect/security-auditor review of the module-registry wiring
is complete for the arm64 staging leg.

**Update 2026-07-11 (metal note, product-steward).** The 2026-07-10 CM5/Pi4 pentest validated
`dnsxai` live *scoring* (805 verdicts, iCloud DNS scored benign) but the DNS-sinkhole *block* of a
specific bad name (`hookprobe-ioc-test.invalid`) was **inconclusive on metal** — a host-originated
`nslookup` was not captured as a forwardable flow record, so the enforcement path was never
exercised (needs a real LAN-client query or a domain-record injection). Mechanism confirmed;
end-to-end enforcement remains unproven → Status stays 🟡 Proposed. This is consistent with the
"refuse a NAME, never a customer's PACKET" thesis (no packet-drop primitive was involved).

**Deciders:** code-developer (author). Not yet reviewed by os-architect (module registry/staging
conventions) or security-auditor (FP-safety design, signing posture).

**Relates to:** [ADR 0023](0023-enforcement-separation.md) (the "legitimate customer connection
must ALWAYS pass" invariant this ADR is explicitly designed to satisfy *more safely* than any
packet-drop primitive), [ADR 0027](0027-hydra-ioc-threat-intel-enrichment.md) (the HYDRA bundled
IOC feed this module's second signal source reuses directly), [ADR 0018](0018-inline-quarantine-safety.md)
(the reversible/TTL-able quarantine reflex this module's evidence-graph response recording
mirrors), [ADR 0016](0016-artifact-hash-signing.md)/[ADR 0021](0021-multiarch-native-artifact-digests.md)
(the artifact-signing discipline this module's `module.yaml` follows), [ADR 0015](0015-registry-driven-module-inclusion.md)
(the C3 reference-entry pattern this module uses — a crate living outside `modules/`).

## Context

`modules/dnsxai`'s DGA/tunnel/lookalike classifier already computes a `Verdict::Malicious`
verdict (V1's `BLOCK_INSTANT` band, score ≥ 0.60) for domains that look like DGA, dictionary-DGA,
or brand-lookalike/phishing infrastructure. Today that verdict is a **dead end**: it's written to
`/var/lib/hookprobe/dns-verdicts`, `hookprobe-evidence --dns-verdicts` turns it into a
`detections` node for investigation, and that's it — the domain resolves exactly as if dnsxai had
never run. Separately, `crates/hookprobe-hydra` (ADR 0027) matches a bundled threat-intel feed's
`domain`-typed indicators against live flow SNI/HTTP-Host, but that too is detection-only —
matched domains are never refused.

Every enforcement primitive this workspace HAS built (`decide()`, `hookprobe-manifest::scan_responder`'s
nft quarantine, `napse-quarantine`'s TC-bpf drop) operates on the **packet** path — and ADR 0023
draws a hard line around that path: *"a legitimate customer connection must ALWAYS pass."* Every
inline drop is keyed on a narrow, confirmed, suspicion-free fact (a confirmed port scan, a
malformed frame, an L1/L2 flood, resource-exhaustion reality) specifically because a wrong verdict
on the packet path costs a real customer a real connection.

A DNS refusal is a fundamentally different, and fundamentally SAFER, class of action:

- **Per-query, not per-connection.** Refusing to resolve `evil-c2.example` has zero effect on any
  OTHER domain, and zero effect on a connection that already resolved and is mid-handshake.
- **Instantly reversible.** An allowlist edit or a feed indicator's retirement removes the
  refusal on the very next lookup — no TTL-expiry race, no "still blocked for 300 more seconds."
- **Never touches `decide()`, nft, or napse-quarantine.** A DNS sinkhole cannot become a
  packet-drop bug by construction — it lives in a completely separate code path with a completely
  separate (and much smaller) blast radius.

This ADR builds the first version: merge dnsxai's `BLOCK_INSTANT` verdicts + HYDRA's bundled
domain IOCs into an allowlist-guarded RPZ zone / dnsmasq blocklist, and record each action as a
reversible, TTL-able evidence-graph response — closing roadmap item A1.

## Decision

### D1 — A pure, dependency-light merge library, not a new detector

`crates/hookprobe-dns-sinkhole` is a library + thin CLI, reusing existing signal sources rather
than inventing a third:

1. `parse_dnsxai_block_instant` reads `/var/lib/hookprobe/dns-verdicts` (JSON lines) and keeps
   only `verdict:"malicious"` lines — dnsxai's OWN highest-confidence tier. `"suspicious"` is
   deliberately excluded: it belongs in investigation (`ANALYZE_BACKGROUND`), never a DNS refusal.
2. `hydra_domain_indicators` reuses `hookprobe_hydra::feed::IocFeed` **unmodified** — no
   reimplemented feed parser — filtered to `ioc_type: domain && active: true`.

No new `rule_id` band is minted: a sinkhole is a RESPONSE to an existing detection, not a new
detection type, so evidence-graph linking reuses the ORIGINATING detection's own natural key (see
D3).

### D2 — The allowlist wins, unconditionally, checked LAST

`Allowlist` layers a small, hardcoded, always-active floor (`BUILTIN_NEVER_SINKHOLE` — this OS's
own control-plane domains, base-OS package mirrors, NTP, a handful of maximally-implausible-to-be-
malicious root infra) under an operator-owned file
(`/etc/hookprobe/dns-sinkhole-allowlist.yaml`, never generated or overwritten by this binary — the
same "operator declares intent in a `/etc/hookprobe/*.yaml` file the reconciler only reads"
convention `LanIntent`/`WifiIntent`/`NacIntent` already use, applied here to content policy
instead of network topology). `build_sinkhole_set` applies the allowlist as the LAST step, after
merging BOTH signal sources — so an allowlisted domain can never be sinkholed no matter how many
sources agree on it or how confident they are. An allowlist entry protects every subdomain of
itself (`hookprobe.com` also protects `mssp.hookprobe.com`) so an operator doesn't enumerate every
subdomain by hand.

### D3 — Evidence-graph linking reuses `ingest_response`'s EXISTING natural-key match, no new code

`render_response_json` emits the SAME JSON shape `hookprobe-evidence --responses` already ingests
(`ts/rule_id/src_ip/dst_ip/dst_port/action/mechanism/target/detail/ttl_secs/status` — identical to
`scan_responder::render_response_json`'s contract). `rule_id`/`src_ip`/`dst_ip`/`dst_port` are
chosen to match the natural key of the ORIGINATING detection:

- dnsxai-sourced: `rule_id: 0` (matching `ingest_dns_verdict`'s own hardcoded `rule_id` for every
  dnsxai detection), `dst_ip: <domain>` (matching that ingest path's own `dst_ip = domain`
  convention).
- HYDRA-only (never yet seen on a live flow): `rule_id: hydra_rule_id(domain)` (matching
  `matcher::Hit`'s own domain-match convention).

`ingest_response`'s pre-existing `rule_id`/`src_ip`/`dst_ip`/`dst_port`/±600s linking then wires
the `responded_with` edge automatically — **zero new evidence-graph code**. `action: "sinkhole"` /
`mechanism: "dns_rpz"` are new, distinct values (never reuse `"quarantine"`/`"nft"`) so a DNS-layer
name refusal can never be confused with a packet drop in the operator's Investigate view.

### D4 — Reversible/TTL-able via a state diff, mirroring the quarantine reflex's revert shape

`diff_state` compares each pass's sinkhole set against the previous pass's persisted
`domain -> first_sinkholed_ts` map (`/var/lib/hookprobe/dns-sinkhole/state.json`): a genuinely NEW
domain gets ONE fresh `action: "sinkhole"` response record; a domain that drops out (allowlisted,
HYDRA indicator retired, the triggering dnsxai verdict aged out of the tail window) gets an
explicit `action: "sinkhole_revert"` / `status: "reverted"` record — mirroring
`scan_responder::render_shed_revert_json`'s exact shape (a DISTINCT action value, never a reused
one, so an operator sees "this stopped" as a first-class event, never a silent disappearance). A
domain still active across repeated 5-minute timer passes produces **zero** duplicate records —
proven live (see "Verification" below): a re-run with no changes emits nothing.

### D5 — Ship the artifact + apply hook now; the resolver gap is real and stated, not hidden

**This device's actually-wired LAN resolver is `systemd-resolved`**
(`crates/hookprobe-manifest/src/lan.rs`: DHCP hands the gateway out as the resolver, a
`resolved.conf.d` drop-in makes `systemd-resolved` listen there) — confirmed by reading that file,
not assumed. `systemd-resolved` has **no RPZ / domain-blocklist mechanism at all**, unlike
BIND/Unbound/Knot Resolver (RPZ: `response-policy`/`rpz:`/`policy.rpz`) or dnsmasq
(`address=/domain/`). Rather than block on a resolver decision this ADR isn't the right place to
make, this module:

1. Generates BOTH a standard RPZ zone (`render::render_rpz` — `CNAME .`, the RPZ "NXDOMAIN"
   action, deliberately chosen over sinkholing to a walled-garden IP so a blocked client's malware
   can never probe/fingerprint the sinkhole address; a `*.domain` wildcard is emitted alongside
   the exact domain so subdomains are also refused) and a dnsmasq blocklist
   (`render::render_dnsmasq_conf` — bare `address=/domain/`, NXDOMAIN on dnsmasq ≥ 2.86, natively
   covers subdomains) at a stable path
   (`/var/lib/hookprobe/dns-sinkhole/hookprobe-sinkhole.{rpz,dnsmasq.conf}`).
2. Ships `base/scripts/dns-sinkhole-apply.sh` — tool-gated (checks for `dnsmasq`/`unbound-control`/
   `rndc`), non-fatal, logs a NAMED reason and changes nothing when no capable resolver is found —
   the exact discipline `network-apply.sh`'s own OVS/nft steps already use ("if the tool isn't
   installed, skip with a named reason, never hard-fail"). Verified live on this dev box: dnsmasq
   is installed but `/etc/dnsmasq.d` isn't writable without root → the script logs the specific
   reason and exits 0, unchanged.

Deliberately **NOT** wired into an automatically-running privileged unit in this pass: the
generator's own unit (`hookprobe-dns-sinkhole.service`) intentionally keeps a minimal grant
(`ReadWritePaths=/var/lib/hookprobe` only — no `/etc/dnsmasq.d`, `/etc/bind`, or
`/var/lib/unbound`), matching its documented "DNS-layer artifact generation ONLY, never touches
enforcement" posture. Wiring a broader-privileged apply unit is a small, clearly-scoped follow-up
once a target resolver is actually chosen for a device class — not fabricated here.

## Verification

`cargo test -p hookprobe-dns-sinkhole`: **24/24 passed**, 0 clippy warnings
(`cargo clippy -p hookprobe-dns-sinkhole --all-targets -- -D warnings`). Covers: verdict→RPZ
generation (both formats, single and multiple entries), allowlist winning over BOTH sources even
when they agree, malformed/empty dnsxai stream + empty HYDRA feed degrading to an empty set
(never a panic), retired HYDRA indicators never firing, evidence-response linking fields, and the
state-diff new/revert/idempotent-repeat behavior.

End-to-end smoke test against the real release binary (`cargo build --release`), synthetic inputs
mirroring live dnsxai/HYDRA output shapes: correctly sinkholed 2 dnsxai `BLOCK_INSTANT` domains +
1 HYDRA domain IOC, correctly REFUSED to sinkhole `hookprobe.com` despite a synthetic
`BLOCK_INSTANT` verdict naming it (builtin allowlist floor), correctly skipped a malformed input
line and a retired/inactive HYDRA indicator, produced valid RPZ + dnsmasq artifacts, and produced
correctly-linked evidence-graph response records (`rule_id: 0` + real `src_ip` for the dnsxai-
sourced hits, `rule_id: hydra_rule_id(domain)` + empty `src_ip` for the HYDRA-only hit). A second
run with one domain allowlisted and one HYDRA indicator retired produced exactly 2
`sinkhole_revert` records and left the still-active domain's state untouched; a third, unchanged
re-run produced zero new records (idempotent).

## Honest limits (state plainly — do not let this overclaim)

- **No resolver on a stock device can load this artifact today.** See D5. This is real
  enforcement infrastructure with no enforcement effect until an operator installs a capable
  resolver, OR a future ADR picks one as this OS's default (a genuinely separate, bigger decision
  — replacing/augmenting `systemd-resolved` fleet-wide — explicitly out of THIS ADR's scope).
- **`module.yaml` carries a real amd64 executable digest (computed from this pass's actual release
  build) but NO arm64 digest** — this dev box has no aarch64-gnu cross-toolchain configured in
  this pass. Marked as a documented `TODO`, never fabricated. The module is therefore NOT yet
  loadable on a Pi/RK3588 image (the supervisor's trust-nothing-unsigned load path refuses to run
  an arch with no matching digest). Also not yet cosign-signed (no `module.sig`/`module.mldsa.sig`
  — the real release-signing pass, `builder/sign-release.sh`, has not run against this module).
- **Not wired into the module registry's staged/enabled set.** `modules/dns-sinkhole/module.yaml`
  exists as a reference entry (ADR 0015 C3 shape) but has not been added to any platform's staging
  manifest or exercised through `builder/gen-staging.sh`/`verify-staging.sh`/`gate-ladder.sh`.
- **Exact-match domain merge only** (same stated limit ADR 0027 D2 gives HYDRA's own matcher) — no
  wildcard/regex domain rules beyond the RPZ/dnsmasq artifacts' own subdomain-inclusive semantics.
- **`ttl_secs` on the evidence record is informational**, not an enforced expiry — the real
  enforcement window is "until the domain drops out of the merged signal set on the next 5-minute
  pass," documented as such in the field's own doc comment, never implied to be a hard timer.

## Consequences

**Positive:** dnsxai's `BLOCK_INSTANT` verdict — computed today, discarded today — gets a real,
safe consumer for the first time. HYDRA's domain IOCs get a genuinely reversible enforcement
surface distinct from (and safer than) anything on the packet path. The evidence graph gains
first-class, TTL-able sinkhole/revert records an operator can trace exactly like a quarantine
reflex. The FP-safety design (allowlist-always-wins, checked last, built-in floor + operator
override) sets a template roadmap item A2+ (any future name-refusal mechanism) can reuse directly.

**Negative / follow-up required:** zero live enforcement effect until a resolver decision is made
and the release-signing pass runs — this ADR proposes the mechanism and proves it correct in
isolation; it does not itself change what a device does today.

## Alternatives considered

- **Sinkhole to a walled-garden IP instead of NXDOMAIN** — rejected as the default: an active IP
  response CAN itself be probed/fingerprinted by the blocked client's malware (a live TCP RST or a
  landing page reveals the sinkhole exists); RPZ's own `CNAME .` NXDOMAIN action is the safer
  default and is what this ADR ships. Not precluded for a future policy-driven variant.
- **Wire directly into `decide()`/the packet-drop path** — rejected outright: this is exactly the
  invariant ADR 0023 exists to protect. A DNS refusal must stay architecturally incapable of
  becoming a packet-drop bug.
- **Pick and hard-code a target resolver (e.g., ship dnsmasq by default) in this ADR** — rejected:
  that is a bigger, separate decision (replacing/augmenting this OS's default LAN resolver
  fleet-wide) that deserves its own review, not a side effect of wiring up one detector's output.
  This ADR ships the artifact + a resolver-agnostic apply hook and states the gap plainly instead.
- **A new evidence-graph ingest method for sinkhole responses** — rejected: `ingest_response`'s
  existing natural-key linking already does the right thing once this module renders the right
  `rule_id`/`src_ip`/`dst_ip`/`dst_port` fields (D3) — no new evidence-graph code needed.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: SOFT.** The `hookprobe-dns-sinkhole` merge library (dnsxai + HYDRA → RPZ, allowlist-always-wins, "refuse a NAME never a PACKET") is portable Rust; the resolver integration (dnsmasq/systemd-resolved) retargets to whatever DNS resolver heqk runs over its M4 network stack. → **Phase M4**.
