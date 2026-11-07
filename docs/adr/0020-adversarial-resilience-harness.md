# ADR 0020 — Adversarial resilience harness: the autonomous, ROE-gated inward pentester

**Status:** 🟢 Accepted with conditions (2026-07-05). The `security-auditor` threat-model this ADR
mandated (§"Safety & abuse analysis") returned **GO-WITH-CONDITIONS for Phase-1** (L2/L3/L4 probes +
Aegis mitigations) and **NO-GO for the blocklist/threat-intel write loop**. The six binding conditions
are folded into the enforced ROE (D3) and phasing (D8); see §"Threat-model sign-off (2026-07-05)". The
DEFENSIVE half (Aegis/napse IDS/IPS drop-filters, the `attack_run`/`finding` evidence plumbing, the
QSECBIT input, the Gate R skeleton) is cleared to build **now**; the OFFENSIVE probes under
`security/redteam/probes/` are cleared **only after conditions 1–6 land in the enforced ROE** — until
then `security/redteam/` stays non-existent.
**Deciders:** os-architect (author), security-auditor (threat-model **signed off with conditions
2026-07-05** — see §"Threat-model sign-off"), verification-engineer (owns the AI-interpretation remit +
Gate R),
release-engineer (release-pass integration), code-developer, product-steward (Cortex traceability).
**Relates to:** [ADR 0018](0018-inline-quarantine-safety.md) (the anti-spoof / confirmation-gate
hardening this session; the harness is the *automation* of the manual Kali-container-attacks-the-Pi
campaign that drove 0018, and its regression fixtures become live Gate R probes), [ADR
0005](0005-unified-ebpf-detection.md) (the XDP/TC-bpf detection core + `tc-mirred` mirror the L2–L4
probes exercise and whose defenses they verify fired), [ADR 0011](0011-product-cortex.md) (the
evidence graph is the harness's output sink; **contract C9** governs it; **no new Cortex agent** —
ADR 0013's 11-agent cap holds, the AI-interpretation duty lands on the existing
`verification-engineer`), [ADR 0012](0012-release-definition-cortex-pass.md) (the release bundle +
`release-pass.sh` fail-closed gate this ADR adds a Gate R verdict to), [ADR
0016](0016-artifact-hash-signing.md)/[ADR 0017](0017-authenticated-aot-cache.md) (the supply-chain /
signing-downgrade surface the L6 probes attack), [ADR 0002](0002-crypto-agility-pqc.md) +
QSECBIT (the L5/L6 crypto boundary and the composite resilience score the harness feeds), [ADR
0004](0004-secure-edge-transport.md) (HTP/NEURO/DSM — **largely design-only in this repo**, so HTP
transport testing is explicitly ROADMAP, not phase-1). Upholds a new sibling of *"trust nothing
unsigned"* / *"trust nothing unconfirmed"*: **prove your own defenses fire before you ship them** —
a defense that has never been attacked in CI is an untested claim.

---

## Context — we hardened by hand; the hardening must be re-attacked automatically, forever

ADR 0018 exists because a real port scan from a real iPhone, and then a Kali container on the lab
LAN, out-ran and then *defeated* the reactive detect→quarantine loop — twice (the initial cut, then
the same-day Q2/Q5/Q6 re-audit that found the confirmation gate was keyed on IP alone). Both were
found by a human running offensive tooling against the device under test (DUT) by hand. That is the
right instinct and the wrong cadence: a hand-run campaign catches a regression once; a *release* must
catch it every time. The fixes landed as unit-test fixtures (`confirm::tests`,
`scan_responder::tests`) — but a unit test proves the decision function's logic, not that the
end-to-end kernel dataplane (`napse-dpi` on the mirror → `scan_responder::decide` →
`napse-quarantine` Ring-0 TC-bpf) actually drops/holds/releases the right packets under a live burst
on a real interface. There is a gap between "the reconciler unit-tests pass" and "an attacker on the
wire cannot take the box down."

This ADR closes that gap by making the manual campaign a **deterministic, ROE-scoped, PLM-gated
harness** — an "autonomous pentester" that continuously re-attacks HookProbe's OWN components and
records, into the same evidence graph an operator's incidents live in, whether each defense withstood
or was breached. It is a **new Gate R (adversarial resilience) tier** on the existing gate ladder,
pre-release, fail-closed on a critical breach.

**This is a security tool aimed inward. That framing is load-bearing and is enforced, not merely
documented — see D3 and §"Safety & abuse analysis".** The harness targets ONLY declared DUTs on an
isolated lab/CI segment or network namespace. It is NOT a general-purpose attack toolkit and MUST be
structurally incapable of targeting WAN / third-party / arbitrary hosts.

---

## Decision

### D1 · Scope of validation: L1→L7 mapped to real components, honest about testable-today vs roadmap

The harness validates the resilience of HookProbe's own dataplane and control surfaces. Each layer
maps to a concrete component and a concrete defense whose firing the harness verifies by reading that
component's OWN telemetry (the loop-closing principle: an attack is only "withstood" if we can observe
the defense fired, not merely that the attacker failed).

| OSI-ish layer | Probe class | DUT component / defense | Verify-fired signal | Status |
|---|---|---|---|---|
| **L1 physical** | link-down/flap, radio jam | N/A on a netns; real-radio only | — | **Not in scope** (no software defense to test; a lab-radio harness is out of this ADR) |
| **L2 link** | ARP spoof/poison, MAC flood, 802.11 frame-source forgery | `napse-capture` mirror observation; ADR 0018 D2 observed-MAC keying; ADR 0018 residual #1 (MFP/802.1X-less Wi-Fi) | quarantine keyed on the *observed* MAC, victim NOT enforced | **ARP/MAC-flood: phase-1** (veth/netns). **802.11 frame forgery: roadmap** (needs real radio; it is a *documented* residual, the harness asserts the layer-appropriate boundary, not a fix) |
| **L3 network** | IP spoofing, martian/bogon source, WAN-ingress-spoof of gateway/resolver, fragmentation | `scan_responder::is_wan_ingress_martian`, live-upstream auto-protect, `classify_source` | martian → `Observed`, never enforced; spoofed victim never quarantined | **Phase-1** (this is exactly ADR 0018's attack surface) |
| **L4 transport** | SYN-only fan-out (portscan), SYN flood, TCP state-exhaustion, confirmation-gate bypass, TTL/hold abuse | `napse-dpi` `PortScanTracker` + `HandshakeTracker` (confirmation gate), `napse-quarantine` Ring-0 drop, `reconcile_quarantine` bounded set (`DEFAULT_MAX_QUARANTINE_ENTRIES`) | confirmed source dropped at line rate; unconfirmed never enforced; the enforced set stays bounded (no OOM) | **Phase-1** |
| **L5 session** | handshake replay/forgery, TLS downgrade, HTP session forgery/no-FS | local dashboard TLS (ADR 0001); **HTP evolved handshake (ADR 0004)** | session refused / FS proven | **Dashboard TLS: phase-2.** **HTP: ROADMAP** — the evolved X25519+ML-KEM/PUF handshake is design-only in this repo (ADR 0004 evolves `~/hookprobe` V1); there is nothing here to attack yet. Do NOT fabricate HTP probe results. |
| **L6 presentation** | module-signing downgrade, artifact/`.cwasm` swap, hash-alg downgrade, cert-validation bypass | ADR 0016 `verify_artifact_digests` / `verify_executable_binding`, ADR 0017 AOT binding, ADR 0002 crypto posture | tampered/unsigned payload REFUSED (fail-closed), `ArtifactTamper` evidence emitted | **Phase-2** (the mechanisms exist and are unit-tested; the harness adds a live "attacker swaps the payload on a running/staged image" campaign) |
| **L7 application** | Mission Control read-API fuzzing, authz/RBAC bypass, intent-bar/plan-diff injection, SSRF/path-traversal on the local read/write API | the read-API (`hookprobe-evidence` read-only surface, ADR 0013 D4a), RBAC (ADR 0008), `aegis-guard` Deny path | unauthorized request refused; no mutation reaches an un-authz'd endpoint | **API fuzzing: phase-2/3** (read-API exists; write/plan surface is partly unbuilt — gate only what ships) |

**Rule of honesty (verification-engineer canon):** a probe class for a component that does not exist
yet is **declared, marked ROADMAP, and never emits a synthetic PASS**. A green Gate R must mean
"every phase-active probe ran against a real DUT and every fail-closed threshold held," not "the
probes we haven't built didn't fail."

### D2 · Directory structure — `security/redteam/` (sibling of the existing `security/` posture dirs)

The harness lives under the existing `security/` tree (alongside `cbom/`, `cosign/`, `slsa/`,
`formal/`), NOT under `modules/` — it is a build/verification tool, never a shipped runtime module,
never staged into an image, never in the manifest.

```
security/redteam/
  rules-of-engagement.yaml        # THE enforced scope contract (D3). Hard-scopes target
                                  #   CIDRs/interfaces/netns to the declared DUT; kill-switch;
                                  #   default-deny. Parsed + enforced in code before any probe fires.
  engine/                         # Rust+tokio campaign runner (D4): loads ROE, resolves targets,
                                  #   FAIL-CLOSED target_guard, schedules probes, collects findings,
                                  #   reads DUT telemetry to verify-fired, emits findings JSON.
  probes/
    l2_link/                      # arp-spoof, mac-flood, (roadmap) 80211-frame-forge
    l34_net/                      # ip-spoof, martian-src, wan-ingress-spoof, frag-overlap
    l56_session/                  # (phase-2) tls-downgrade; (roadmap) htp-session-*
    l7_app/                       # (phase-2/3) read-api-fuzz, rbac-bypass, plan-diff-inject
  targets/                        # per-DUT-component descriptor: which interfaces/paths/ports are
    napse.yaml                    #   the DUT surface, which telemetry proves a defense fired, and
    hydra.yaml                    #   which thresholds are RED. A target file NAMES the component; it
    qsecbit.yaml                  #   NEVER names an out-of-scope host (that is ROE's job to reject).
    htp.yaml                      #   (roadmap placeholder — declares probes but marks them inactive)
  schema/
    finding.schema.json           # the node/edge shape into hookprobe-evidence (D6). Outline here;
                                  #   the full JSON Schema is a follow-up impl step.
```

### D3 · Rules-of-engagement are ENFORCED IN CODE, fail-closed, before any probe fires (CRITICAL)

The single most important control in this ADR. `rules-of-engagement.yaml` is **default-deny** and is
enforced by a `target_guard` in `engine/` that runs **before the first byte of any probe leaves the
process** (before raw-socket creation, before any `pnet`/AF_PACKET/AF_XDP send, before any TCP
connect):

```yaml
# security/redteam/rules-of-engagement.yaml (shape)
version: 1
mode: dut-self-test                 # the ONLY supported mode; any other value → refuse to start
allowed_targets:
  - cidr: 10.99.0.0/24              # the isolated lab DUT segment. IP/CIDR LITERALS ONLY — a
    interface: veth-dut             #   hostname here is a hard parse error (condition 3, no DNS).
  - netns: hookprobe-dut            # probes run INSIDE this netns; its only route is to the DUT
allowed_target_files: [targets/*.yaml]
limits:                             # condition 1 — MANDATORY; a missing/zero field → refuse to start
  max_pps_per_probe: 50000          # hard packets-per-second ceiling per probe (fail-closed on breach)
  max_frames_per_campaign: 5000000  # total frame budget across the campaign
  max_bytes_per_campaign: 4294967296 # total byte budget across the campaign
  max_wall_clock_seconds: 300       # campaign hard deadline; engine aborts fail-closed at the edge
  max_concurrency: 4                # max simultaneously-firing probes
kill_switch:
  file: /run/redteam/STOP           # presence aborts every in-flight campaign, fail-closed
  signal: SIGTERM                   # trapped → drain + halt, never "finish the burst"
hard_deny:
  - any_public_ip: true             # RFC1918/CGNAT/loopback/link-local ONLY; a routable dst → refuse
  - wan_interface: true             # binding/targeting any interface classified WAN → refuse
  - dns_resolution: true            # condition 3 — resolving ANY target name is forbidden, always
require_isolation:
  network_namespace: true           # engine refuses to send a raw frame outside a dedicated netns
  l2_egress_must_be_veth: true      # condition 2 — L2/broadcast/line-rate egress MUST be a veth
                                     #   (netlink kind==virtual) whose peer is in the DUT netns; that
                                     #   netns has NO default route and no route to any RFC1918/real
                                     #   prefix except the DUT veth. Asserted via netlink, never trusted
                                     #   from this string.
```

Enforcement contract (in code, not prose):

1. **Resolve-then-assert, fail-closed.** For every probe, `target_guard::validate(target)` resolves
   the concrete destination IP(s)/interface and asserts membership in `allowed_targets` AND
   non-membership in `hard_deny`. **If a target resolves outside the allowed segment, or resolution
   fails, or the ROE file is missing/malformed/`mode != dut-self-test` — the engine refuses to fire
   the probe and exits non-zero.** There is no `--force`, no override flag, no env bypass (the exact
   discipline ADR 0016 D2 established for digest mismatches: absence-of-permission is a hard stop, not
   a warning).
2. **No raw socket without an in-scope, resolved target.** Raw-socket / AF_PACKET / AF_XDP capability
   is acquired lazily, *per validated target*, never process-wide up front. A probe that has not
   passed `target_guard` cannot obtain a send path.
3. **Namespace isolation is required, not advised.** The engine refuses to transmit L2/L3 frames
   unless it is running inside the declared `network_namespace` whose only route is the DUT veth — so
   even a hypothetical `target_guard` bug cannot reach the operator's real LAN/WAN, because there is
   no route to it from inside the netns. Defense in depth: the code check AND the topology both must
   fail before a packet can escape.
4. **Kill-switch.** A `/run/redteam/STOP` sentinel or a trapped signal drains and halts all campaigns
   fail-closed; a partially-run campaign records what it did (D6) and stops.
5. **Every campaign is audited into the evidence graph BEFORE probes fire** (D6): an `attack_run`
   node with the ROE hash, target ids, and operator/CI identity is written first, so there is no
   un-audited campaign, ever.

**The six threat-model conditions (2026-07-05) — binding in `rules-of-engagement.yaml` AND enforced in
code before ANY offensive probe is written.** These are not advisory; the `security-auditor` sign-off
is conditional on all six being present and enforced (fail-closed) as a precondition of Phase-1:

1. **Enforced `limits:` block.** Max pps per probe, max total frames/bytes per campaign, max
   wall-clock, max concurrency. The engine aborts **fail-closed** the instant any ceiling is breached
   (a missing or zero `limits:` field is itself a refuse-to-start). The AF_XDP line-rate TX path (D4)
   is gated behind **BOTH** `require_isolation` **AND** the hard `max_pps_per_probe` ceiling — never
   line-rate without both.
2. **L2 topology assertion — assert, never trust the config string.** L2 / broadcast / line-rate
   probes are **REFUSED** unless the egress is a veth (`kind==virtual`, verified via netlink) whose
   peer lives in the declared DUT netns, and that netns has **no default route** and no route to any
   RFC1918 / real prefix except the DUT veth. This is the **only** real containment for L2: the
   IP-layer `target_guard` (contract #1) is structurally **inert for broadcast/multicast frames that
   carry no unicast IP destination**, so L2 safety cannot rest on it — it must rest on the asserted
   veth/netns topology.
3. **IP/CIDR literals only — DNS resolution FORBIDDEN.** No target may be a name; `hard_deny.dns_resolution`
   is always true. This kills the resolve→send TOCTOU and DNS-rebind-to-RFC1918 class outright: the
   target bytes are captured **once** and the raw send uses **exactly those bytes** — no re-lookup ever
   happens between `validate()` and `send()`.
4. **No blocklist / feed write path in Phase-1, at all.** The harness emits `finding` / `attack_run`
   nodes **only**. The QSECBIT resilience input (D7) and the Gate R verdict (D5) are the **sole**
   downstream consumers. A `finding` MUST NEVER reach an enforcement action (quarantine / blocklist /
   release-block) without passing the deterministic gate (**C9**). See §"Threat-model sign-off" for the
   blocklist NO-GO.
5. **Every campaign audited pre-fire and the kill-switch honored** — contract #5 above, unchanged: the
   `attack_run` node (ROE hash + identity) is written before the first probe; `/run/redteam/STOP` and
   the trapped signal drain-and-halt fail-closed.
6. **Hardware-in-the-loop off the mgmt path — hard rule.** Destructive L1/L2 floods run against a
   netns/QEMU DUT **by default**. Hardware-in-the-loop against the real Pi, *if done at all*, runs
   **only over a dedicated link/VLAN off the management path — NEVER the shared mgmt /28**. A MAC-flood
   or broadcast-amplification on the shared segment would DoS the operator's own SSH to both the Pi and
   the dev box. This is documented in the README topology diagram (D2 / §"Files that will change") and
   is **the single largest residual risk in the design** — hence a hard rule, not a recommendation.

### D4 · Tooling — native Rust+tokio; no Metasploit/heavy external framework in the enforced path

**Decision: a custom Rust+tokio engine, reusing this repo's own AF_PACKET/XDP crating seam.** No
Metasploit, no Cobalt Strike, no external C2/exploit framework in the gate path. Rationale:

- **Stack-nativeness and auditability.** The L2–L4 probes craft/replay frames using the same
  `pnet`-class packet crating and the AF_PACKET path `napse-capture`'s `napse-dpi` already links
  (`modules/napse-capture/loader/src/{dpi.rs,portscan.rs,confirm.rs}`). The harness and the DUT share
  a packet-parsing vocabulary, so a probe that says "50 SYN-only to distinct ports, spoofed src=V,
  attacker MAC" maps 1:1 to what `PortScanTracker`/`HandshakeTracker` observe — and the harness can
  read the DUT's own emitted alert to verify. A general framework would bring an un-auditable
  dependency into a security-gate that must itself be trustworthy (a red-team tool with a supply-chain
  risk is a liability, not an asset — see §"Safety & abuse analysis").
- **`target_guard` must be in the same trust boundary as the send path.** A native engine keeps ROE
  enforcement (D3) in-process, ahead of the socket — impossible to guarantee if the actual packets are
  emitted by an opaque third-party binary.
- **L7 fuzzing — Rust for the enforced gate, Python allowed for exploratory probes.** The
  release-blocking L7 probes (read-API authz/fuzz) are Rust (reqwest/hyper client, in the same engine,
  same ROE guard, deterministic seed → reproducible finding). Python (e.g. an `atheris`/`schemathesis`
  exploratory fuzzer) is **permitted for developer-time exploration under the same ROE loader**, but a
  Python-only finding is *advisory* (informs a new Rust probe) and never by itself a RED gate — because
  the gate must be reproducible and dependency-light in CI. Speed-to-write buys exploration; the
  enforced path stays stack-native. This split is the honest trade: we do not pretend Rust is the
  fastest way to write a fuzzer, we scope where each belongs.
- **eBPF/XDP seam (ADR 0005).** Where a probe needs line-rate generation (SYN-flood/state-exhaustion),
  it reuses the ADR 0005 AF_XDP TX path rather than a userspace loop, so the load actually exercises
  the Ring-0 defense at a rate that matters. This is gated behind `require_isolation` (D3) — line-rate
  generation only ever happens inside the DUT netns.

### D5 · PLM event model — Gate R tier, two cadences, and the fail-closed thresholds that block a release

Two campaign cadences map onto the existing ladder (ADR 0011 D4 "the gate ladder IS the sandbox"):

- **Post-build smoke campaign (fast, per-image):** a bounded set of phase-active probes against a
  freshly-built image booted in QEMU/netns (Gate 2's boot artifact). Minutes. Runs on the nightly Gate
  2 job and on-demand. Catches gross regressions (a defense that stopped firing at all).
- **Pre-release full campaign (Gate R):** the complete phase-active probe matrix against the
  release-candidate image, run before `release-pass.sh` assembles the bundle. This produces the Gate R
  verdict that gates the release.

**Gate R fail-closed thresholds (a breach at any of these blocks the release via `release-pass.sh`):**

| Threshold (RED — blocks release) | Probe | Maps to |
|---|---|---|
| A spoofed single-packet/SYN burst causes a **victim host to be quarantined** (reflected-DoS) | `l34_net/wan-ingress-spoof`, `l2_link/arp-spoof` | ADR 0018 Q2 — the exact regression, now a live gate |
| An **unconfirmed** source (no completed handshake) reaches the **enforced** quarantine map | `l34_net/ip-spoof` + read DUT quarantine state | ADR 0018 D1 |
| **L4 state-exhaustion:** the confirmation tracker or quarantine set grows **unbounded** (OOM / budget breach) under flood | `l34_net/state-exhaust` + read `reconcile_quarantine` size | ADR 0018 D6 bounded set; resource-honesty invariant |
| A LAN attacker scanning the **gateway/resolver** evades detection (marked martian) | `l34_net/wan-ingress-spoof` | ADR 0018 Q5 |
| **L6:** a tampered/unsigned/downgraded payload or `.cwasm` **loads and executes** | `l56_session/`+`l6` signing probes | ADR 0016/0017 — fail-closed refuse must hold |
| **L7:** an **unauthenticated/unauthorized** request reaches a mutating or privileged endpoint | `l7_app/rbac-bypass` | ADR 0008 RBAC; C9 Deny-final |

Below RED is **AMBER** (a low-priority detection shed, a latency-budget regression, a non-critical
withstand-ratio drop): recorded as a finding, surfaced to the operator, does NOT auto-block — the
operator decides (ADR 0011 D3 verdict model, unchanged). **C9 holds throughout:** the harness and the
AI *propose* the Gate R verdict as evidence; `release-pass.sh` (the deterministic gate) *enforces* it.
The AI (`verification-engineer`'s remit) interprets and prioritizes findings and may draft the
narrative — it is **never in the enforcement path and never autonomously attacks a production device**
(the harness only ever runs against a lab/CI DUT in the declared netns/segment, per D3).

`release-pass.sh` integration: Gate R contributes a `--gate resilience:pass|fail:<summary>` entry to
the release bundle, and a Gate R **FAIL is a hard non-zero exit** from the ADR-0016-style post-sign
block (same mechanism, new check) — no `--attest` can override a RED resilience breach, exactly as no
attestation overrides an INVALID signature today.

### D6 · Finding schema — new evidence-graph node/edge types (outline; full JSON Schema is a follow-up)

The harness is a **lens on the same evidence graph** (ADR 0011 "one system") — it adds node/edge types
to `crates/hookprobe-evidence`, it does NOT create a second store. This also **generalizes the ADR
0011 D1 audit finding** that `test_run`/`benchmark`/`platform_target` were promised-but-absent: the
same "delivery/verification signal is a first-class node" shape, applied to adversarial verification.

New node types (SQLite tables, FNV-1a stable ids, JSONEachRow offload to cloud ClickHouse like every
other node type):

- `attack_run` — one campaign: `{id, ts, roe_hash, cadence(smoke|full), image_version, dut_targets[], operator, verdict(pass|amber|red)}`. Written **before** probes fire (D3.5).
- `finding` — one probe outcome: `{id, ts, attack_run, layer(l2..l7), probe, target_component, outcome(withstood|breached|inconclusive), severity(red|amber|info), verified_fired(bool), evidence_ref, mitre_attck?, repro_seed}`.

New edge types (added to the `EDGE_*` constants in `hookprobe-evidence/src/lib.rs`):

- `breached` — `finding → detections`/`responses`/component node: "this probe defeated that defense."
- `validates` — `finding → adr`/`gate_results` node: "this probe confirms ADR 0018 D1 still holds"
  (the traceability leg — a green `validates` edge to ADR 0018 is the living proof its fix survives).
- `informed_by` — reuses the EXISTING field-feedback edge (ADR 0011 D1): a `breached` finding →
  `requirement`, closing red-team → roadmap the same way field telemetry closes it.

Finding JSON (the on-disk artifact `hookprobe-evidence` ingests, mirroring the existing line-oriented
JSON ingest paths):

```jsonc
// security/redteam/schema/finding.schema.json (outline)
{
  "attack_run": "ar:<hash>",
  "ts": "2026-07-05T18:00:00Z",
  "layer": "l4",
  "probe": "wan-ingress-spoof",
  "target_component": "napse-quarantine",
  "outcome": "withstood",          // withstood | breached | inconclusive
  "verified_fired": true,          // did we OBSERVE the defense act? (loop-closing; false → inconclusive, never "withstood")
  "severity": "red",               // the threshold class if breached
  "evidence_ref": "det:<id>|resp:<id>",   // the DUT's own alert/response that proves it
  "repro_seed": 42,                // deterministic replay
  "mitre_attck": "T1595.001"
}
```

`inconclusive` (probe ran but the verify-fired signal could not be read) is **never** silently a
withstand — it is surfaced, and for a RED-class probe it fails Gate R closed (we do not ship a defense
we could not confirm fired). This mirrors ADR 0018's honesty about the un-runnable verifier-load smoke
test: a check we could not run is not a check that passed.

### D7 · QSECBIT integration — breach/withstand ratios feed the composite resilience score

QSECBIT already computes a composite score with inputs `{drift, qdrift, p_attack, decay, maha_dist,
entropy_nats}` (see `qsecbit_scores` in `hookprobe-evidence` + `modules/qsecbit`). The harness adds a
**resilience-evidence input**: a per-layer withstand ratio `withstood / (withstood + breached)` over
the most-recent full campaign, folded in as a bounded factor (a low withstand ratio *depresses* the
score; a clean sweep does not inflate it above baseline — resilience is expected, not a bonus). The
mechanism is a new optional field on the QSECBIT reading, populated from the latest `attack_run`
verdict; QSECBIT stays the sole owner of the weighting math (the harness supplies evidence, not a
score — same C9 separation as everywhere). This makes the Organism Status orb reflect *proven* current
resilience, not just anomaly statistics. **Honesty note:** until the harness runs against a device
class, that class's resilience input is absent (not assumed 1.0) — QSECBIT must treat "never attacked"
as unknown, never as "perfectly resilient."

### D8 · Phasing — build the proven attack patterns first; HTP/L7 fuzzing later

- **Phase 1a — DEFENSIVE, buildable NOW (no offensive send path, ungated):** the `finding` /
  `attack_run` node/edge types in `hookprobe-evidence` (D6), the QSECBIT resilience input (D7), and the
  Gate R skeleton wired into `gate-ladder.sh --gate-r` and `release-pass.sh` (D5). Plus the Aegis /
  `napse` IDS/IPS drop-filters these will exercise. This is ordinary detection/verification plumbing
  and is cleared by the sign-off immediately.
- **Phase 1b — OFFENSIVE, gated on conditions 1–6 landing in the enforced ROE first:** the ROE loader +
  `target_guard` **with the enforced `limits:` block (condition 1), the netlink veth/netns topology
  assertion (condition 2), and IP/CIDR-literals-only / no-DNS (condition 3)**, the Rust+tokio engine
  skeleton, and only then the **L3/L4 probes that replay THIS session's proven ADR 0018 attacks** —
  IP-spoof, WAN-ingress-spoof-of-gateway/resolver, SYN-only portscan fan-out, SYN-flood
  state-exhaustion — against `napse-dpi` + `scan_responder` + `napse-quarantine`, reading the DUT's own
  alert/quarantine state to verify-fired. Plus `l2_link/arp-spoof` + `mac-flood`. These probes have
  known-good and known-bad oracles already (the ADR 0018 fixtures), so they can be written test-first —
  but not one probe byte is written until conditions 1–6 are present and enforced fail-closed.
  **Destructive L1/L2 floods run against a netns/QEMU DUT by default (condition 6); hardware-in-the-loop
  against the real Pi, if at all, only over a dedicated link/VLAN off the mgmt path — never the shared
  mgmt /28.** `security/redteam/` (engine + probes) does not exist until Phase 1b begins.
- **Phase 2:** L6 signing-downgrade / payload-swap probes (ADR 0016/0017 mechanisms exist), dashboard
  TLS-downgrade (L5), and the L7 read-API authz/RBAC probes against the endpoints that actually ship.
- **Phase 3 / roadmap:** L7 API fuzzing at scale (Python exploratory → Rust enforced), and **HTP/NEURO/
  DSM transport probes once HTP's evolved handshake is actually built** (ADR 0004 is design-only in this
  repo today — an HTP probe now would test nothing and MUST NOT emit a synthetic result). 802.11
  frame-forgery (ADR 0018 residual #1) needs a real-radio lab rig and stays roadmap.

---

## Safety & abuse analysis — how this could be misused, and the controls that prevent it

This tool exists to attack; the risk is that it attacks the wrong thing. Enumerated honestly:

| Abuse / failure | Control |
|---|---|
| Pointed at the operator's real LAN/WAN or a third-party host | **D3 fail-closed `target_guard`**: default-deny ROE, resolve-then-assert before any send, `hard_deny` on any public/routable/WAN target, no override flag. |
| `target_guard` bug lets a frame escape | **Netns topology isolation (D3.3):** probes run in a dedicated netns whose only route is the DUT veth — no route to the real network exists, so a code bug still cannot reach it. Two independent failures required. |
| Left running / no stop | **Kill-switch (D3.4)** file + trapped signal; campaigns are bounded (finite probe matrix), not daemons. |
| A campaign runs unlogged / for cover | **Pre-fire audit (D3.5 / D6):** the `attack_run` node (with ROE hash + identity) is written to the evidence graph *before* the first probe; there is no un-audited campaign. |
| Harness itself becomes an attack asset (supply chain) | **D4 native/dependency-light**, no external exploit framework; the harness is signed/reviewed like any other repo code; it is **never staged into a shipped image** (D2 — lives in `security/`, not `modules/`), so it cannot reach a customer device at all. |
| AI drives it to attack production autonomously | **C9 (D5):** the AI interprets findings and proposes the verdict; it never fires probes at production and is never in the enforcement path. The harness only runs against a lab/CI DUT in the declared segment. Red (commits/releases/flashing/live-attack) is never autonomous. |
| Raw-socket capability abused for other ends | **D3.2:** raw-socket acquired lazily per validated target, never process-wide; a probe that failed `target_guard` has no send path. |
| L2 broadcast/multicast frame escapes the IP-layer guard (no unicast IP dest to check) | **D3 condition 2:** the IP `target_guard` is structurally inert here; L2/broadcast/line-rate egress is REFUSED unless it is a netlink-verified veth whose peer is in a routeless DUT netns. L2 safety rests on the asserted topology, not the IP guard. |
| A line-rate flood exceeds intended load / becomes the OOM it tests for | **D3 condition 1:** mandatory `limits:` block (pps/frames/bytes/wall-clock/concurrency); engine aborts fail-closed on breach; AF_XDP line-rate TX gated behind BOTH `require_isolation` AND the hard pps ceiling. |
| Resolve→send TOCTOU / DNS-rebind flips a name to an RFC1918 or real host between validate and send | **D3 condition 3:** DNS resolution FORBIDDEN; IP/CIDR literals only; target bytes captured once, raw send uses exactly those bytes, no re-lookup. |
| HIL flood on the shared mgmt segment DoSes the operator's own SSH to the Pi and dev box | **D3 condition 6 (hard rule, largest residual risk):** destructive L1/L2 floods run against a netns/QEMU DUT by default; real-Pi HIL only over a dedicated link/VLAN off the mgmt path, never the shared mgmt /28; documented in the README topology diagram. |
| A finding auto-writes an enforcement action (blocklist/quarantine) bypassing the gate | **D3 condition 4 + §"Threat-model sign-off":** Phase-1 has NO blocklist/feed write path; findings feed only QSECBIT + Gate R; a finding never reaches enforcement without C9. The `bitwire-it/ipblocklist` auto-write is NO-GO and needs its own ADR. |

**Explicit gate on implementation:** `security-auditor` MUST perform a dedicated threat-model of the
*harness-turned-outward* risk (the "what if this tool, or its ROE enforcement, is subverted to attack
something it shouldn't" analysis) and sign off **before any offensive probe code is written**. This
ADR pins the governance and rules-of-engagement precisely so that review has a fixed target; it does
not authorize writing probes. The Phase-1 build starts only after that sign-off — **now recorded
below**.

---

## Threat-model sign-off (2026-07-05)

The `security-auditor` threat-model mandated above (§"Safety & abuse analysis") was performed and
returned:

- **GO-WITH-CONDITIONS for Phase-1** — L2/L3/L4 probes + the Aegis mitigations they verify — **subject
  to the six binding conditions now folded into D3** (and enumerated there as "The six threat-model
  conditions"). All six MUST be present in `rules-of-engagement.yaml` **and** enforced fail-closed in
  code **before ANY offensive probe is written**. They are conditions of the sign-off, not follow-ups.
- **NO-GO for the blocklist / threat-intel write loop** — see the dedicated ruling below.

### The clean split the sign-off drew

| Half | What | Clearance |
|---|---|---|
| **(a) DEFENSIVE** | Aegis / `napse` IDS/IPS drop-filters; the evidence-graph `attack_run` / `finding` plumbing (D6); the QSECBIT resilience input (D7); the Gate R skeleton (D5) wired into `gate-ladder.sh` / `release-pass.sh` | **Safe to build NOW.** No offensive send path; C9-clean. |
| **(b) OFFENSIVE** | the probes under `security/redteam/probes/` (D8 Phase-1: L2/L3/L4) | **Only after conditions 1–6 land in the enforced ROE.** Until then `security/redteam/` — including `engine/` and `probes/` — **stays non-existent.** |

The defensive half needs no offensive send path, so it is not gated on the ROE `target_guard`; it is
ordinary detection/verification plumbing and proceeds immediately. The offensive half is gated,
strictly, on the six conditions.

### Blocklist / threat-intel write loop — NO-GO (separate future ADR required)

ADR 0020 **as written contains no blocklist-write path** — that is correct and MUST stay that way. The
proposed `bitwire-it/ipblocklist` → `inbound.txt` / `outbound.txt` auto-write is a **net-new capability**
that is NO-GO now because it is:

1. **Spoof-poisonable.** It exports the ADR-0018 reflected-DoS to a *shared feed* — strictly worse than
   the local case, because the TTL-revert and mgmt-allowlist protections do **not** travel with an
   exported line. A poisoned entry propagates without its safety context.
2. **C9-violating as an auto-write.** A `finding` reaching an enforcement action (a blocklist write is
   one) without the deterministic gate is exactly the C9 violation condition 4 forbids.
3. **Dependent on an external repo not in this workspace.** `bitwire-it/ipblocklist` is not present here;
   its ownership, consumer set, and blast radius are unknown.

**Explicit ruling:** the blocklist loop MUST NOT be designed or implemented under this ADR. It requires
its **own ADR** carrying, at minimum:

- the `(IP, MAC)`-confirmed + multi-signal + human-review gating from **ADR 0018** (no single-signal
  auto-write);
- the external repo present, **ownership confirmed**, and its consumer / blast-radius understood before
  any write path is drawn; and
- the invariant that **a single L1/L2 observation is NEVER blocklist-eligible** — there is no
  non-spoofable proof-of-liveness at L1/L2, so an L1/L2 sighting alone can never justify an exported
  block.

Until that separate ADR exists and is accepted, the harness's only outputs remain `finding` /
`attack_run` nodes (condition 4).

---

## Files that will change

**New (the harness — none shipped in an image):**
- `security/redteam/rules-of-engagement.yaml` — the enforced scope contract (D3).
- `security/redteam/engine/` — Rust+tokio campaign runner + `target_guard` (new workspace member,
  dev/CI-only; NOT in the module registry, NOT staged).
- `security/redteam/probes/{l2_link,l34_net,l56_session,l7_app}/` — probe implementations, phased (D8).
- `security/redteam/targets/{napse,hydra,qsecbit,htp}.yaml` — per-DUT descriptors (htp = roadmap stub).
- `security/redteam/schema/finding.schema.json` — the finding schema (D6; full schema follow-up).
- `security/redteam/README.md` — ROE, isolation topology, how to run a lab campaign, the abuse analysis.

**Evidence graph (D6):**
- `crates/hookprobe-evidence/src/lib.rs` — `attack_run` + `finding` tables; `ingest_finding`/
  `ingest_attack_run`; `EDGE_BREACHED`/`EDGE_VALIDATES` constants (+ reuse `EDGE_INFORMED_BY`); add both
  tables to `graph_stats`' `NODE_TABLES`; read-API list endpoints for the Detect/Investigate workspaces.

**Gate ladder / release (D5):**
- `builder/gate-ladder.sh` — a new **Gate R** tier (`--gate-r`), run against the Gate 2 boot artifact /
  a netns DUT; SKIP-with-reason where no isolated DUT is available (honesty rule), never a silent green.
- `.github/workflows/gate-ladder.yml` — wire Gate R into the nightly/Gate-2 job (needs a privileged,
  netns-capable runner; documented, not faked on the free tier).
- `builder/release-pass.sh` — accept a Gate R verdict; a RED resilience breach is a hard non-zero exit
  in the post-sign block (same mechanism as the ADR 0016 gate), non-overridable by `--attest`.

**QSECBIT (D7):**
- `modules/qsecbit/src/lib.rs` — optional resilience-evidence input (withstand ratio) folded into the
  composite score; "never attacked" = unknown, never 1.0.

**Docs:**
- `docs/architecture/Readme.md` — add the adversarial-resilience harness to the supply-chain/verification section
  (Gate R; "prove your defenses fire before you ship").
- `docs/roadmap/BuildPlan.md` — a phased work item (D8) under verification-engineer, blocked on the
  security-auditor threat-model sign-off.
- `.claude/agents/verification-engineer.md` — note the new AI-interpretation remit (C9-bound; no new
  agent — ADR 0013 11-cap holds).

---

## Alternatives considered

- **A general pentest framework (Metasploit/Caldera/Atomic-Red-Team) driven by a script.** Rejected for
  the enforced gate: opaque dependency inside a security-critical gate, cannot keep `target_guard` in
  the send path's trust boundary, and brings a supply-chain surface into the tool that certifies our
  supply chain. Atomic-Red-Team *techniques* may inform probe design; their runners do not enter the
  gate. (Exploratory Python fuzzers are allowed developer-side, advisory-only — D4.)
- **A new Cortex agent ("red-team-agent").** Rejected: ADR 0013 caps the roster at 11; the
  AI-interpretation duty is verification-engineer's existing remit. A 12th agent needs its own ADR and
  is not justified — the harness is a *tool*, not a persona.
- **Run it against production devices for "real" coverage.** Rejected outright: violates D3 and the
  edge-box-never-takes-the-network-down invariant; the whole point is DUT-only, isolated. Fleet
  resilience is inferred from the release the fleet runs, not from attacking live customer devices.
- **Make Gate R advisory (amber-only), never release-blocking.** Rejected for the RED thresholds: the
  ADR 0018 reflected-DoS was a critical, shippable regression that unit tests alone did not catch
  end-to-end; a defense that can be shown broken on the wire must block the release, or the harness is
  theatre.

## Consequences

**Positive.** The manual campaign that hardened ADR 0018 becomes a permanent, fail-closed gate; every
release proves its own dataplane defenses still fire, on the wire, not just in unit tests. Red-team →
roadmap closes as a first-class graph edge (`breached`/`informed_by`). QSECBIT reflects *proven*
resilience. The tool is structurally incapable of hitting a non-DUT target (D3 + netns), audited every
run, and never shipped to a device.

**Residual risks / costs.** (1) Gate R needs a privileged, netns/QEMU-capable CI runner — not available
on the free tier; until then it runs on the operator's box / a self-hosted runner and SKIPs honestly in
public CI. (2) The harness is offensive code in the repo; its own trustworthiness matters — hence the
mandatory security-auditor threat-model *before* code, dependency-light native design, and
never-staged placement. (3) L5-HTP and L7-fuzz coverage is roadmap; Gate R is only as strong as its
phase-active probes, and this ADR is explicit that a green Gate R covers phase-active probes only,
never the unbuilt ones. (4) A live line-rate SYN-flood probe consumes real DUT resources — bounded by
the netns, the finite probe matrix, and now the mandatory `limits:` block (D3 condition 1), but the
resource-honesty invariant applies to the harness too (it must not itself become the OOM it is testing
for). (5) **The single largest residual risk (per the 2026-07-05 sign-off): a destructive L1/L2 flood
on the shared mgmt segment would DoS the operator's own SSH.** Mitigated by the hard rule (D3 condition
6): netns/QEMU DUT by default, real-Pi HIL only over a dedicated link/VLAN off the mgmt path, never the
shared mgmt /28. (6) The blocklist / threat-intel write loop is deliberately **out of scope and NO-GO**
under this ADR; it must not be built until its own ADR carries the ADR-0018 `(IP,MAC)`-confirmed +
multi-signal + human-review gating and the external repo's ownership/blast-radius is understood
(§"Threat-model sign-off").

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: SOFT.** The "prove your defenses actually fire" Gate-R concept is substrate-neutral; the netns/veth isolation topology + AF_PACKET/AF_XDP probe send-path are re-hosted on heqk. **Gate R must pass on heqk metal before any promotion** (a RED breach stays a hard, non-overridable release block). → **Phase M2**.
