# ADR 0026 — Sigma + YARA rule ingestion: two new, honest detection engines

**Status:** 🟢 Accepted (2026-07-08). Implemented as a working, tested, gate-green first version:
`modules/sigma` (`hookprobe-sigma` — a practical Sigma rule subset, native binary) and
`modules/yara-scan` (`hookprobe-yara-scan` — `yara-x`-backed file scanning, native binary), both
firing into the SAME `detections`/`ingest_detection` path every other engine already uses (zero
`hookprobe-evidence` schema changes needed), plus `GET /api/engines`
(`crates/hookprobe-api/src/engine_status.rs`) replacing part of the Detect workspace's mock
`ENGINES` panel with real loaded-rule-count / last-run data. Not yet folded into an image build or
enabled by default (deliberately — this ADR ships the engines + tests, not a flash; see each
module's `module.yaml` "HONEST STATUS" note).

**Deciders:** code-developer (author), os-architect (the `runtime: host` tier decision — why NOT
Wasm, reusing the same tier `modules/senzorium-flow`/`modules/evidence` already established),
security-auditor (a new YAML/rule-file parser is new untrusted-input surface — the "skip with a
warning, never mis-fire" contract below is the mitigation), verification-engineer (the fixture-
rule/fixture-event test discipline this ADR requires), release-engineer (the arm64 build-status
gap this ADR flags, not fabricates).

**Relates to:** [ADR 0005](0005-unified-ebpf-detection.md) (the detection layer this adds ALONGSIDE
— NAPSE's signatures/HMM/Bayesian engine is untouched), [ADR 0009](0009-soc-brain-edge-cloud.md)
(the ONE evidence graph both engines' detections fold into, via the EXISTING `ingest_detection`
path), [ADR 0014](0014-continuous-improvement-detection-lifecycle.md) (the detection-lifecycle
discipline — bundled rules are the seed, not the ceiling), [ADR 0015](0015-registry-driven-module-
inclusion.md) (both modules register via a normal `module.yaml`, `runtime: host`'s explicit
`staging:` override block), [ADR 0016](0016-artifact-hash-signing.md) (both modules ship
`signature: optional` today — flipping to `required` needs real computed digests, a follow-up, not
this pass), [ADR 0011](0011-product-cortex.md) (contract C9 — both engines are pure deterministic
pattern-matching, no ML in the enforcement path; see honest limits below).

## Context

The Detect workspace (`docs/architecture/MissionControl.md` §4) advertises five engines: "Suricata/Sigma/YARA/
AI/Behavioral". Before this ADR, Sigma and YARA were **entirely mock** —
`os/mission-control/src/store/detectMock.ts`'s hard-coded `ENGINES` array (`{name:'Sigma', rules:'3,910', hits:512,
status:'active'}`, literally invented numbers) and matching hard-coded rows in the demo feed. No
rule ever parsed, no file ever scanned, nothing ever really fired. This ADR builds the FIRST real
version of both — not full Sigma/YARA-ecosystem compatibility, a working, tested, honestly-scoped
subset that fires real detections from real rules.

## Decision

### D1 — Two new modules, one new detection-engine class each (not a NAPSE change)

`modules/sigma` (Sigma rule ingestion + evaluation) and `modules/yara-scan` (YARA file scanning)
are NEW modules, added ALONGSIDE the existing NAPSE signature/HMM/Bayesian engine
(`modules/napse`) — nothing in NAPSE's detection logic, rule catalogue, or rule_id band is
touched. Both fire into the exact JSON detection schema
`hookprobe_evidence::EvidenceGraph::ingest_detection` already consumes
(`rule_id`/`rule_msg`/`category`/`severity`/`mitre`/`src_ip`/`dst_ip`/`dst_port`/`confidence`) —
appended to the SAME `/var/lib/hookprobe/events` stream, so **zero evidence-graph code changed**
for this ADR. A Sigma/YARA hit shows up in Detect/Investigate/the incident correlator exactly like
a NAPSE alert or a host-EDR finding, for free.

### D2 — `runtime: host`, not `wasm` (a deliberate deviation from the workspace default, documented)

CLAUDE.md's own bias is "default to `runtime: wasm` for detection/policy/enrichment". Both engines
deviate, for reasons stated plainly (also in each module's own doc comments, not just here):

- **Sigma** needs a real YAML parser (`detection:` selections, modifiers, `condition:` strings,
  `logsource:`, `tags:` — genuinely nested structure). Hand-rolling one — the zero-external-
  dependency convention `modules/napse`/`modules/dnsxai`'s Wasm binaries hold to, which exists
  specifically to keep the SANDBOXED hot path minimal — would be materially MORE risk than using
  `serde_yaml`, a dependency this workspace already vets and uses elsewhere
  (`hookprobe-manifest`, `supervisor`).
- **YARA** uses `yara-x` (VirusTotal's maintained, pure-Rust YARA re-implementation — chosen
  specifically because it has NO `libyara`/C dependency, unlike the historical `yara` crate,
  fitting this workspace's Rust/Wasm supply-chain posture). `yara-x` internally compiles a rule's
  `condition:` to Wasm bytecode and JITs it via its OWN embedded `wasmtime`/`cranelift` — a
  dependency tree far heavier than the zero-dep floor, and one that needs real file-tree access
  (a configured scan set), not a single stdin pipe.

Both therefore ship as native `runtime: host` binaries — the SAME tier `modules/senzorium-flow`/
`modules/evidence` already established (ordinary file I/O, no eBPF/special capabilities, systemd
hardening instead of a WASI sandbox). `modules/sigma/module.yaml`'s doc header states this is a
scoped, revisitable decision: a future pass could port the pure-EVALUATION half (matching, not
YAML parsing) to Wasm once rules are pre-compiled to a compact representation outside the sandbox.

### D3 — Sigma: a practical, stated subset — never silent mis-fire on the unsupported rest

Supported: `detection:` selections as field-equality / `contains`/`startswith`/`endswith`
modifiers (also list-valued, OR semantics), multiple fields in one selection (AND), a selection as
a list-of-maps (OR of maps), `condition:` as a plain string with `and`/`or`/`not`/parentheses (a
small recursive-descent parser, `hookprobe_sigma::parse_condition`), `logsource.category`-based
event routing, `level`→severity+confidence, first `attack.tNNNN` tag→MITRE technique.

NOT supported — a rule using any of these is **skipped at load time with a printed warning, never
silently mis-evaluated**: aggregation/count conditions (`count() by`, `N of them`, `all of`, `1 of
selection*`, any wildcard identifier), `detection.timeframe`, field modifiers other than
`contains`/`startswith`/`endswith` (`|re`, `|base64`, `|cidr`, `|all`), `condition:` as anything but
one plain string. `modules/sigma/src/lib.rs`'s module doc states this plainly; `compile_rule`
returns a human-readable reason for every skip, and a dedicated bundled fixture
(`sigma_unsupported_aggregation.yml`) + unit test prove the skip contract holds end to end.

**Field-name mapping is HookProbe's OWN schema, not generic Sysmon/Windows fields.** Public Sigma
rules (SigmaHQ) overwhelmingly target Windows field names (`Image`, `CommandLine`, `ParentImage`,
`DestinationPort`, …). `hookprobe_sigma::normalize_field_name` is a small, explicit alias table
from those handful of names onto HookProbe's own Linux event schema (`name`, `cmdline`,
`parent_name`, `dst_port`, …) — a rule copied verbatim from an external repo will very likely
reference a field this table doesn't know; it simply never matches (a missing field is "no match",
never a crash or a false positive), not silently misfire. This is a stated v1 scope limit: a
practical Linux/network Sigma subset for HookProbe's own telemetry, not drop-in SigmaHQ-pack
compatibility.

Five bundled starter rules (`modules/sigma/rules/*.yml`) exercise every supported construct
(reverse-shell exec, download-and-exec AND-of-selections, suspicious-TLD DNS endswith-list,
cleartext-Telnet equality, root-shell-not-cron filter/NOT) plus the one deliberately-unsupported
aggregation fixture. 27 unit tests cover the parser, every modifier, category routing, the
skip-with-a-reason contract, and two end-to-end fires against the bundled rules.

### D4 — YARA: `yara-x`, a small bundled test rule set, amd64/gnu proven / arm64 unverified

Scans a small, tractable v1 scan set (`/tmp`, `/var/tmp`, `/dev/shm` — the SAME "world-writable/
staging" paths `hookprobe_evidence::host_edr`'s `EXEC_FROM_WRITABLE_PATH` check already watches),
bounded by file count/size/depth caps, run periodically (`hookprobe-yara-scan.timer`, every 15
min) rather than continuously — file scanning is I/O/CPU-heavy (ADR 0003 edge budgets), and a
bounded sweep is the honest, edge-appropriate tradeoff. A full host-filesystem sweep is explicitly
OUT of scope for this v1 (stated, not silently accepted).

Bundled: the industry-standard EICAR test string (harmless, publicly documented — every AV engine
recognizes it on purpose) and a second, HookProbe-own benign marker string — both prove the scan
path fires without needing (or shipping) any real malware sample. 8 unit tests cover rule loading
(incl. a deliberately-malformed fixture proving one bad `.yar` file never blocks the others),
EICAR + the HookProbe marker firing on real bytes/a real file, benign content never firing, and the
detection-JSON shape.

**Arch honesty:** proven green on amd64/`x86_64-unknown-linux-gnu` (this crate's own test suite).
arm64 (`aarch64-unknown-linux-gnu`) build status is explicitly **NOT proven in this pass** —
`yara-x`'s dependency graph is pure Rust (no C-toolchain cross-compile step the way
`libbpf-sys`/`rusqlite bundled` need), so it SHOULD cross-compile via the same aarch64-gnu target
every other native loader in this repo already uses, but this was time-boxed out of this v1's
scope and is NOT claimed. `module.yaml`'s own doc header states this as the honest, open gap for a
release-engineer follow-up to close before any arm64 image stages this module.

### D5 — rule_id numbering: two new, non-colliding reserved bands

Every other engine in this workspace uses a small, hand-enumerated `rule_id` per FIXED detection
(`modules/napse` 1,000,001–1,000,025; `napse-capture` 1,000,003/012/013/014/030–033/040/041;
`hookprobe_evidence::host_edr` 1,000,100–1,000,118; the resource-shed 1,000,050; the supply-chain
bands 9,1xx,xxx/9,2xx,xxx — all checked against the tree, 2026-07-08). Sigma/YARA rules are
open-ended and pluggable, identified by their own `id`/name, not a fixed enum — so each engine
reserves its OWN numeric space, far above every other band: **Sigma: `2,000,000,000 +
(fnv1a(rule_id) & 0x0FFFFFFF)`**; **YARA: `3,000,000,000 + (fnv1a(rule_name) & 0x0FFFFFFF)`** (same
FNV-1a-then-mask idiom `hookprobe_evidence::sid()` already uses for stable node ids). Deterministic
per rule, collision-free in practice for the handful of rules a device loads — a genuinely large
rule pack would need a wider reservation or a real UUID-keyed side table, a stated, not silently
accepted, v1 limit.

### D6 — `GET /api/engines`: real Sigma/YARA status, honest labels for the rest

`hookprobe-sigma`/`hookprobe-yara-scan` each write a small JSON status file
(`sigma-status.json`/`yara-status.json`: loaded/skipped rule counts, events/files processed, hits,
last-run timestamp) that `crates/hookprobe-api/src/engine_status.rs`'s new `GET /api/engines`
reads and normalizes. `os/mission-control/src/store/detectLive.ts`/`DetectApp.tsx` merge this with the existing
static `ENGINES` mock: a Sigma/YARA row with real data REPLACES the mock numbers; Suricata/AI
Detection/Behavioral (no backing engine exists) stay mock — every row is now individually badged
"live"/"mock" rather than one blanket "· mock" on the whole panel, so the UI never overclaims
which numbers are real.

## Honest limits (state plainly — do not let "Sigma/YARA support" overclaim)

- Sigma: no aggregation/count/timeframe rules, no regex/base64/cidr modifiers, HookProbe's own
  field schema (not SigmaHQ's Windows-oriented one) — see D3.
- YARA: a small, fixed scan-path set (not a full filesystem sweep), periodic not continuous, arm64
  build unverified — see D4.
- Neither engine is wired into an image build, staged preset, or signed artifact yet
  (`signature: optional`, no `preset:` entry in either `module.yaml`) — this ADR ships the engines
  + tests; a follow-up release-engineer pass proves the cross-build, computes real digests, and
  flips both to `signature: required` before either ships on a real image.
- No ML anywhere in either engine (contract C9) — both are pure deterministic pattern-matching,
  same posture as every other detector in this workspace.

## Consequences

**Positive:** the Detect workspace's "Sigma/YARA" claim stops being pure fiction — real rules,
real matches, real evidence-graph correlation, for two engine classes that previously produced
zero output ever. The rule_id/status-file/`ingest_detection`-reuse pattern this ADR establishes is
a template any FUTURE pluggable rule-based engine (a future Suricata integration, say) can follow
without another evidence-graph schema change.

**Negative / cost:** two new native (non-Wasm) dependency trees in the workspace — `serde_yaml`
(already vetted, low incremental cost) and `yara-x`'s heavier one (its own `wasmtime`/`cranelift`,
a genuinely large addition, worth the pure-Rust supply-chain-posture tradeoff it buys). Neither
engine is auto-enabled today — realizing the value requires the release-engineer follow-up work
named in D3/D4/the honest limits above.

## Alternatives considered

- **Full pySigma-equivalent Sigma compatibility (all backends, all modifiers, aggregation):**
  rejected for v1 — far outside a tractable first version; the stated subset is honestly scoped and
  extensible later (ADR 0014's continuous-improvement lifecycle is the natural home for widening
  it).
- **The C-wrapping `yara` crate (libyara bindings) instead of `yara-x`:** rejected — a new C
  dependency to audit/cross-compile/patch is exactly what this workspace's Rust/Wasm supply-chain
  posture (ADR 0002, the Wasm-first bias) exists to avoid; `yara-x` is pure Rust and equally
  maintained (VirusTotal production use).
- **Force both engines into `runtime: wasm` regardless:** rejected — `serde_yaml`'s dependency
  weight and `yara-x`'s embedded `wasmtime`/file-tree-access needs are a poor fit for the
  capability-sandboxed hot path the Wasm-default convention protects; `runtime: host` (an
  established tier, not a new one) is the honest fit.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: NEUTRAL.** Sigma + yara-x are pure-Rust detection engines (yara-x embeds its own wasmtime) that port; only the file-scan paths and the `runtime: host` launch model retarget to heqk's module runtime. → **Phase M5**.
