# ADR 0023 — Enforcement separation: observe by default, drop only a genuine attack or resource-exhaustion event

**Status:** 🟢 Accepted (2026-07-07). The posture is the operator's hard rule, made structural in the
shipped code this session and regression-locked by a dedicated gate (`0.7-separation-matrix`,
`builder/gate-ladder.sh:285`). Proven on real hardware: the runt-floor false-drop that severed a
legitimate iPhone (a well-formed 42-byte ARP frame classified as a "runt") was reproduced on a live
Pi 4 and fixed protocol-aware (`modules/napse-capture/loader/src/dpi.rs:154`). This ADR documents a
posture the code already enforces but that had **no ADR and no spec line** — the top traceability gap
a PLM audit flagged (contract C9 requires an Amber-class change to carry an ADR). It does not
introduce new mechanism; it names, justifies, and makes reviewable the separation the D12–D19 audit
fixes and the resource-shed already shipped.
**Deciders:** os-architect (author), security-auditor (reuses the ADR-0018/0020 anti-spoof
sign-off — every drop path here inherits it), verification-engineer (the `0.7-separation-matrix`
gate + the on-metal iPhone-ARP reproduction/fix), product-steward (Cortex traceability — this closes
the flagged gap), release-engineer (the gate wired release-blocking).
**Relates to:** [ADR 0018](0018-inline-quarantine-safety.md) (the anti-spoof confirmation gate every
identity-keyed drop here depends on), [ADR 0022](0022-behavioral-quarantine-vs-static-allowlists.md)
(behavioural quarantine is *one* of the SAFE-TO-DROP classes governed here; this ADR is the umbrella
posture it sits under), [ADR 0005](0005-unified-ebpf-detection.md) (the detectors that *emit alerts*
this ADR keeps decoupled from enforcement), [ADR 0020](0020-adversarial-resilience-harness.md) (the
harness that pentests attacker × legit, both directions), [ADR 0011](0011-product-cortex.md)
(contract C9 — AI proposes, the deterministic reconciler enforces; this ADR is enforced by a gate,
never a model).

## Context

### The operator's hard rule
> *Observe by default. Drop ONLY a genuine, high-confidence attack or a resource-exhaustion/DDoS
> event. A legitimate customer connection must ALWAYS pass. The SOC's job is to distinguish an
> attacker from a non-attacker — not to break connectivity when in doubt.*

This is a **product-posture** decision, not a detail: a security appliance that false-drops a paying
customer's iPhone is worse than one that misses a slow scan, because the first failure is visible,
immediate, and erodes the trust the whole product depends on ("an edge box must never be able to take
the network down with it" — `docs/Readme.md:307`). The rule inverts the naive IPS default ("when
suspicious, block"): here, suspicion alone is never sufficient to touch the wire.

### Why this needed an ADR
The posture was, before this session, enforced **only by a test gate** and a scatter of D-labelled
inline fixes. It contradicted the older, blunter invariant wording in `CLAUDE.md`/`docs/Readme.md`
("data plane out-of-band by default, inline opt-in; per-interface fail-open/fail-closed") which does
not describe the *new* inline, self-reverting, resource-keyed drop the resource-shed introduced. A
load-bearing change with no ADR and a stale spec is exactly the C9 Amber violation the Cortex audit
exists to catch.

### The research basis — context beats context-free static checks
The dominant false-drop failure mode is a **context-free static check** firing on a benign edge case:
a 42-byte frame is "too short" only if you ignore that it is a structurally complete ARP packet; 40
distinct MACs on a port is a "MAC flood" only if you ignore that the port is an AP uplink radio
serving the whole LAN. The fix is consistently **contextual, multi-dimensional classification**: a
frame/flow is judged by *what it structurally is and where it arrived*, and enforcement fires only
when that context is unambiguously an attack. A single static length floor, a single flat threshold,
or a single spoofable source claim is never enough. This is the same discipline ADR 0022 applied to
reachability (behaviour, not a CIDR list) and ADR 0018 applied to quarantine (a confirmed handshake,
not a claimed source), generalised into the OS's default posture.

## Decision

### D1 — The tri-state verdict model: detectors emit alerts, `decide()` enforces, graduated by confidence
Enforcement is expressed as a **tri-state verdict graduated by confidence**, with a fourth
management-safety floor. The parser/detectors are decoupled from enforcement by construction: a
detector's only job is to emit an alert; a single `decide()` function is the only place a verdict is
chosen. At the L3/flow layer this is `scan_responder::ReflexVerdict`
(`crates/hookprobe-manifest/src/scan_responder.rs:632`); at L1/L2 it is the isomorphic
`l2_responder::L2Verdict` (`crates/hookprobe-manifest/src/l2_responder.rs`, `decide_l2`):

| Verdict (L3 / L2) | Confidence | Wire effect | Anti-spoof property |
|---|---|---|---|
| `Observed` / `Observe` | detected, not attributable-to-enforce | **none** — log only | a spoofable/impossible/stateful-only finding can reach here but no further |
| `RateLimit` / `RateLimit` | real pattern, identity unconfirmed | bounded, **self-reverting** per-source nft `meter` | reflecting a victim's IP costs it a few pps for one window, never a durable block |
| `Quarantine` / `FrameDrop` | high-confidence, confirmed | durable identity block / structural frame drop | only ever after ADR-0018 confirmation (handshake **or** conntrack-ESTABLISHED) |
| `Allowlisted` (L3 floor) | mgmt path | **never enforced** | the operator can never self-lock-out (ADR 0022 D2) |

`decide()`'s gate order (`scan_responder.rs:705`) encodes the posture: (1) a physically-impossible
WAN-ingress martian → `Observed`, unconditionally; (2) the management-path floor → `Allowlisted`;
(3) unconfirmed → `RateLimit`, never a durable block; (4) only a *confirmed* malicious verdict →
`Quarantine`. Confidence graduates the response; it never skips a step. The detectors
(`napse_loader::portscan`, `l2guard`, `beacon`, `lateral`) never suppress emission — observation is
always complete; only *enforcement* is gated.

### D2 — What is SAFE-TO-DROP (the only four classes)
Enforcement touches the wire in exactly four cases, each either identity-confirmed under ADR 0018 or
keyed on resource reality (D3), never on suspicion:

1. **A confirmed port scan** — ≥50 distinct destination ports fanned out **and** an independently
   validated handshake or conntrack-ESTABLISHED flow (`scan_responder::is_confirmed_any`,
   `scan_responder.rs:624`; the durable path, `decide` → `trust::evaluate` → `Quarantine`,
   `scan_responder.rs:706`). TTL auto-revert, escalating hold capped at 6× (ADR 0022).
2. **A truly-malformed frame** — dropped because of *what the frame structurally is* (byte/length/
   VLAN-nesting facts, `napse_loader::dpi::frame_anomaly_reason`), never who sent it —
   `L2Verdict::FrameDrop`, enforced by the `modules/napse-l2guard` TC-bpf ingress hook.
3. **A real L1/L2 flood** — a genuine MAC-flood/broadcast-storm on a genuine access port, mitigated
   by a bounded self-reverting nft `meter` (`l2_responder::render_storm_control`), never a permanent
   MAC blocklist.
4. **Resource-shed (new this session, D3)** — a volumetric DDoS that trips no signature detector.

### D3 — Resource-shed: the one enforcement class keyed on RESOURCE REALITY, never identity
An adversarial audit found the single gap in the picture above: a genuine volumetric flood with no
port-scan shape and no L2-storm shape (just raw connection/packet volume saturating the box's own
CPU/RAM/conntrack table) was *detected* (telemetry sees the load) but never *shed*. The
`RESOURCE-REALITY ENFORCEMENT` section (`scan_responder.rs:1236`), driven by
`hookprobe-resource-shed.{service,timer}` (`base/units/`, 10s cadence), closes exactly that gap and
only that gap. Three layers, all keyed on a **measured resource fact**, never a reputation verdict:

- **Layer 1 — blanket per-source new-connection cap** (`render_conn_rate_cap`, default
  `DEFAULT_NEW_CONN_PPS = 400`, `scan_responder.rs:1529`): an always-on nft `meter` with no concept
  of source reputation at all — every source, however trusted, capped at the same generous ceiling a
  real client never approaches; only a connect-flood does.
- **Layer 2 — conntrack-saturation guard** (`DEFAULT_CONNTRACK_SATURATION_PCT = 80`,
  `scan_responder.rs:1826`): only once the conntrack table itself is ≥80% full does it temporarily
  cap the highest-*measured*-concurrent-flow source (`top_talkers`), not a reputation pick.
- **Layer 3 — PSI CPU/mem pressure** (`psi_under_sustained_pressure`, `scan_responder.rs:1401`;
  `DEFAULT_CPU_SOME_AVG60_PCT = 40`, `DEFAULT_MEM_FULL_AVG60_PCT = 15`): keyed on the kernel's own
  `/proc/pressure` stall fraction — the operator's literal "the box is maxing out RAM/CPU".

Every entry is **self-reverting as a structural property** (`scan_responder.rs:1265`): no entry is
ever written without a TTL, none is ever refreshed just for existing, none carries history across
pressure windows, and there is no offense counter or persisted "known bad" list. The moment pressure
clears, the source ages out. It lives in its own nft table (`hookprobe_resource_shed`), never
touching the identity-keyed quarantine/scan-ratelimit/l2guard tables. This is the one place the OS
drops inline by default without an identity confirmation — justified precisely because it makes **no
identity judgment at all**: a source is capped because a real resource wall is provably crossed, and
the remedy self-reverts.

### D4 — What is OBSERVE-ONLY (alert-only, no enforcement consumer, correct by construction)
Several real detectors deliberately have **no enforcement consumer at all** — they emit alerts into
the evidence graph and stop there, because their real-world confidence does not clear the bar for
touching the wire, or no honest wire-level mechanism exists:

- **Beaconing** (rule 1000040) and **lateral movement** (rule 1000041) — behavioural, multi-flow
  inferences; a false positive here is common (a legitimate polling client looks like a beacon), so
  they inform investigation, never a drop. Confirmed alert-only: no responder references them (grep
  of `scan_responder.rs`/`l2_responder.rs` for these rule IDs returns nothing).
- **UDP / slow / ICMP scan variants** and **host-EDR** (exec/persistence, rules 1000100–115) —
  detection and evidence, no auto-enforcement.
- **ARP binding flip-flop** (D15) — needs cross-packet history that neither the stateless nft meter
  nor the stateless per-packet TC-bpf classifier can express, so `decide_l2` maps it to
  `L2Verdict::Observe`, and `render_l2_response_json`'s `mechanism`/`status` never claim an
  enforcement action that does not exist (`l2_responder.rs:56`). Honesty over a fabricated verdict.

"No enforcement consumer" is the *correct* design for these, not a gap — it is the observe-by-default
rule applied at the detector granularity.

### D5 — The l2guard structural-runt fix and the five conservative guards
The iPhone false-drop was the canonical failure this posture exists to prevent, and it seeded five
audit fixes (D12–D17), each replacing a context-free static check with a contextual one:

- **Protocol-aware runt floor** (`dpi.rs:154`, `frame_anomaly_reason_local`): there is no longer a
  single hand-picked length floor. A frame in `[14, min_len)` is exempt from the runt drop iff it
  *structurally* parses as a well-formed IPv4 TCP/UDP packet, an IPv4 ICMP packet, **or** a complete
  42-byte ARP packet (`parse_arp_obs` now returns `None` for a truncated ARP, so a merely-truncated
  capture is never misread as benign). Length-AND-structure per protocol, never a flat "short is
  fine" relaxation — the exact fix for the 802.3 60-byte padding-floor assumption that dropped the
  iPhone's legitimate 42-byte ARP.
- **D12 — mac-flood topology-awareness** (`l2_responder.rs:43`): `lan_port_role` gates both the
  verdict (`RateLimit` only on a genuine `PortRole::Access` port; `Observe` on an `UplinkBridge`
  port — the device's own default topology, `wlan0` = an AP radio serving the whole LAN) and the
  static meter (`render_storm_control` installs no mac-flood drop on an uplink at all). 40 distinct
  MACs on a shared radio is ordinary churn, not a flood.
- **D13 — broadcast-storm mDNS/SSDP/LLMNR exemption** (`l2_responder.rs:51`;
  `napse_loader::l2guard::is_exempt_multicast`): well-known service-discovery multicast is `accept`ed
  before the storm meter and never even generates an alert — a chatty-but-legitimate Bonjour device
  can never reach a drop path.
- **D16 — RA-guard observe-first** (`multi_wan.rs:296`, `lan.rs:34`): a non-allowlisted Router
  Advertisement is **logged + accepted** (observed), not silently first-sight-dropped; only a source
  in `confirmed_rogue` is hard-dropped. A new HomeKit hub emitting RAs is observed, not severed.
- **D17 — NAC onboarding-grace** (`nac.rs:36`): a brand-new/unclassified device gets
  `NacPolicy::OnboardingGrace` — full LAN+WAN reach, separately *logged* (`onboarding_macs` set), and
  **never dropped** — until fingerprinting classifies it and the class preset applies. A device is
  never cut off merely for being new.
- **D15 — flip-flop honesty** (covered in D4): the verdict never claims a drop the mechanism can't
  perform.

### D6 — The `0.7-separation-matrix` gate is how this decision is enforced
The posture is regression-locked by a dedicated, release-blocking gate
(`gate_0_7_separation_matrix`, `builder/gate-ladder.sh:285`) running two test suites that call the
**real** public enforcement-decision functions (never a reimplementation) with representative legit
and attacker inputs, both directions:

- `crates/hookprobe-manifest/tests/separation_matrix.rs` (19 rows) — responder-level verdicts
  (`decide`, `decide_l2`, `nac::resolve`, `render_ra_guard_*`, `evaluate_resource_reality`).
- `modules/napse-capture/loader/tests/separation_matrix_frames.rs` (11 rows) — raw-frame predicates
  (`frame_anomaly_reason_local`, `parse_arp_obs`, `classify_scan_probe`).

Thirty rows total, split into a `legit` mod (**must** render FORWARD/OBSERVE — zero false-drops) and
an `attacker` mod (**must** reach the correct tri-state action). It is named as its own gate rather
than folded into the whole-workspace `cargo test` precisely so a "does the SOC still forward legit
traffic" regression is never lost in a several-hundred-test summary line — a FAIL here is
release-blocking by itself.

## Consequences

- **Positive:** the "SOC breaks a legit device" failure class is structurally gated, not just
  hoped-for; every drop path is either identity-confirmed (ADR 0018/0022) or resource-reality-keyed
  and self-reverting (D3), so the blast radius of any single mistake is bounded; the posture is now
  reviewable (this ADR) and testable (D6) instead of tribal knowledge; volumetric DDoS is finally
  shed (D3, previously the one enforcement gap).
- **Negative / accepted trade-offs:** observe-by-default means a slow-and-low or novel attack that
  never crosses a confirmation/resource threshold is not auto-dropped (mitigated by auth as the front
  line per ADR 0022 D4, by the detection roadmap ADR 0014, and by the pentest harness ADR 0020) —
  this is the deliberate direction of the trade: a missed slow scan over a dropped customer.
  Resource-shed picks its capped source by measured volume, so a legitimate heavy top-talker present
  *during* genuine saturation can be briefly capped — bounded (self-reverting, own generous cap) and
  surfaced in the evidence graph, never durable.
- **Honest residuals / roadmap (not built):**
  - **Flip-flop stateful drop** (D15/D4) — deferred; a real ARP binding-flip-flop enforcement needs
    cross-packet history no current mechanism expresses; remains observe-only until a stateful
    tracker ships. Roadmap.
  - **Curated OUI list** — mac-flood/host-intel vendor labelling uses a minimal built-in OUI table;
    a full curated OUI database is a documented seam, not shipped. Roadmap.
  - **NAC onboarding-grace expiry** — grace ends when fingerprinting classifies the device; there is
    no independent time-boxed expiry if classification never converges (a device that stays
    unclassified stays in grace). Acceptable (grace is full-access-observed, not a privilege
    escalation) but noted. Roadmap: a grace TTL.
  - **Resource-shed response-record coverage** — Layer 1's blanket meter emits no per-hit event (nft
    does not push one); only Layers 2/3 emit first-class response records. Documented, not fabricated
    (`scan_responder.rs:1296`).
- **Supersession:** this ADR **refines** the older `CLAUDE.md`/`docs/Readme.md` invariant wording
  ("data plane out-of-band by default, inline opt-in; per-interface fail-open/fail-closed"). That
  framing remains true for the *inline-IPS opt-in* posture, but it did not describe the
  observe-by-default enforcement-separation rule nor the new inline, self-reverting, resource-keyed
  drop (D3). Both specs are updated to state the enforcement-separation invariant crisply and
  cross-link this ADR; the fail-open/closed per-interface choice is retained, not removed.

## Validation
- **On-metal (live Pi 4, this session):** the runt-floor false-drop severing a legitimate iPhone
  (a well-formed 42-byte ARP frame) was reproduced and fixed protocol-aware (`dpi.rs:154`); the
  device regained connectivity.
- **Gate:** `0.7-separation-matrix` — 33 rows (22 verdict-level + 11 frame-level), legit-passes + attacks-caught, both directions —
  calls the real enforcement-decision functions and is release-blocking (`gate-ladder.sh:285`).
- **Adversarial:** the resource-shed (D3) was the direct output of an adversarial audit that found
  the one un-shed enforcement gap; ADR 0020's harness pentests attacker × legit both directions.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: SOFT.** The observe-by-default posture and the `decide()`/`decide_l2` tri-state verdict are portable Rust; the mechanisms they read (PSI `/proc/pressure`, `nf_conntrack`, nft, tc-bpf) are replaced by heqk's native resource-accounting + Packet-Engine primitives. **The release-blocking 0.7 enforcement-separation matrix must pass on heqk metal** — "a legit customer connection must ALWAYS pass" does not bend for the substrate. → **Phase M2**.
