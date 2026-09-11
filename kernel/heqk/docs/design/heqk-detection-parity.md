# heqk M2 Detection / Enforcement-Separation Parity — the 33-row Gate-R matrix

> **Status: reconstructed 2026-09-10 from the authoritative in-tree sources.** The
> source of truth is the CODE + the validation markers, not this prose. Where this
> doc and the code disagree, the code wins. Canonical sources: `validate.sh`
> (`[P8-*]` phase descriptions), `tools/gate-r-matrix.sh` (rule→row taxonomy),
> `tools/gate-r-run.py` (the machine-readable 33-row table + verdict logic),
> `kernel/src/verdict.rs` (`decide_core`/`PortRole`/`FindingClass`→verdict seam),
> `kernel/src/rules.rs` (the rule corpus), `kernel/src/segment.rs` (the reach
> actuator), `kernel/src/corroboration.rs` (A11). This file was referenced by
> `tools/gate-r-frames.py` and `PRODUCTION_READINESS.md` before it existed; it is
> reconstructed here so those canon references resolve.

## 0. Purpose

Gate-R is the release-blocking **enforcement-separation** matrix for the CM5 heqk
sensor/enforcer (Track C / M2). It proves the ADR 0023 invariant on real silicon:
**observe by default; a legitimate customer connection ALWAYS passes; only a
genuine attack or resource-exhaustion event is ever dropped on the wire.** Passing
it unlocks unbuild-batch U2 (retire the Linux OVS/nftables dataplane).

## 1. The decision seam (`verdict.rs::decide_core`)

Every frame resolves to a tri-state wire verdict, graduated by confidence:

```
Observed  → RateLimit (bounded, self-reverting) → Quarantine / FrameDrop (confirmed)
```

plus a management-safety `Allowlisted` floor (`MGMT_NET` = 10.200.0.0/24). The
mapping from a detection's `FindingClass` to a wire verdict is the SINGLE seam
`decide_core()`. Key design rules:

- **Behavioral** findings (beaconing, lateral, DNS-anomaly) → **unconditional
  Observe**, never a wire drop (they key on suspicion, not fact).
- **Port-role-gated** findings (mac-flood, rogue-RA) → drop **only on an Access
  interface**; on an Uplink they Observe (an uplink legitimately carries many MACs
  / a downstream RA). `PortRole` defaults fail-safe to `Uplink`.
- **Corroboration (A11)** raises alert **severity** only — it NEVER feeds a wire
  drop (security-auditor NO-GO; the axes share one forgeable trust root = src IP,
  so a wire-quarantine would be a spoofed-victim DoS).
- **Resource-shed** (conntrack saturation / PSI pressure) sheds the dominant
  top-talker, self-reverting, keyed on RESOURCE REALITY not identity.

## 2. The 33 rows

Legend for "proven by": **frame** = a real driven frame fires the named rule with
the expected verdict; **sepdiag** = an on-metal bring-up self-test through the real
datapath entry (`#[cfg(feature="sepdiag")]`, emitted once at sensor start);
**off-device** = an off-device control-plane concern (ADR 0044 D3), legit-safe by
absence. Rule ids are `kernel/src/rules.rs`.

### 2a. Legit — must PASS / Observe, never wire-drop the legit source (`mod legit`)

| Row | Assertion | Proven by |
|-----|-----------|-----------|
| L1  | mDNS/SSDP/LLMNR mcast burst → no storm alert | sepdiag STRUCT (exemption) |
| L2  | busy uplink, many MACs → Observe, never RateLimit | sepdiag A1A2 (uplink leg) |
| L3  | ARP flip-flop → Observe, never FrameDrop | frame: rule 102 PASS |
| L4  | downstream RA on an uplink → observed + accepted | sepdiag RAGUARD (uplink leg) |
| L5  | new unclassified device → OnboardingGrace | **off-device** NAC |
| L6  | stale device past grace → InternetOnly | **off-device** NAC |
| L7  | CDN fan-out 100 conns:443 → no scan alert | frame: rule 113 PASS (own ===ROW=== window) |
| L8  | NTP beacon-shape :123 → allowlisted | frame: rule 116, no drop |
| L9  | heavy legit src, table 40%, low PSI → no shed | sepdiag SHED |
| L10 | ~100 new-conn/s under the 400/s cap → allow | frame: rule 114 PASS |
| L11 | customer touches one IOC → never quarantine | frame: rule 302 PASS |

### 2b. Attacker — must reach the correct tri-state (`mod attacker`)

| Row | Assertion | Proven by |
|-----|-----------|-----------|
| A1  | Access-port mac-flood ≥20 MACs → RateLimit | sepdiag A1A2 (synthetic Access port; live=Uplink fail-safe, C-2) |
| A2  | Uplink 300+-MAC flood → Observe | sepdiag A1A2 |
| A3  | non-exempt bcast flood → RateLimit | frame: rule 112 → FloodRate DROP |
| A4  | unconfirmed SYN scan ≥50 ports → RateLimit (not Quarantine) | frame: rule 113 DROP |
| A5  | confirmed SYN scan → Quarantine (durable) | frame: rule 113 DROP (durability QEMU-only) |
| A6  | FIN/NULL/XMAS stealth scan → observe/rate | frame rule 201/202/203 + sepdiag SCAN |
| A7  | conntrack saturation → shed source | sepdiag SHED |
| A8  | sustained PSI + top-talker → shed | sepdiag SHED |
| A9  | rogue RA (type 134) on an access port → FrameDrop **(arm EMBARGOED — §5)** | sepdiag RAGUARD (synthetic Access port, C-2; posture ruled §5) |
| A10 | lateral / C2-beacon → detected, never enforced | frame: rule 117 PASS (Behavioral) |
| A11 | corroborated IOC → Observe + CRIT sev (wire-Quarantine **rejected by design**) | sepdiag CORR |

### 2c. Frame-structural (`mod frames`)

| Row | Assertion | Proven by |
|-----|-----------|-----------|
| F1  | iPhone 42B unpadded ARP → never anomalous | sepdiag STRUCT |
| F2  | bare 54B TCP ACK → never anomalous | sepdiag STRUCT |
| F3  | locally-administered unicast MAC → no mcast trip | sepdiag STRUCT |
| F4  | frame < eth header → flagged | sepdiag STRUCT (host NIC pads runts) |
| F5  | ARP truncated <42B → flagged | frame: rule 101 DROP |
| F6  | mcast/bcast **source** MAC → flagged | frame: rule 110 DROP |
| F7  | oversize >1522B → flagged | sepdiag STRUCT (host MTU blocks send) |
| F8  | double-VLAN → flagged | frame: rule 110 DROP |
| F9  | malformed ARP header → flagged | frame: rule 101 DROP |
| F10 | ARP sender-mac / eth-src mismatch → flagged (Observe) | frame: rule 102 PASS |
| F11 | FIN/NULL/XMAS shapes → recognized | frame: rule 201/202/203 |

## 3. Running the matrix

- **Metal drive:** `tools/gate-r-matrix.sh` sends each frame-drivable row at a real
  DUT link; send `A3_bcast_storm` LAST/alone (its bounded burst crosses the 10 s
  broadcast window and would otherwise be counted toward any concurrent
  broadcast-dst row). The device emits `[SEPDIAG] rule=N verdict=V` per fired rule
  each heartbeat, and the 5 bring-up self-tests `[SEPDIAG-{SHED,A1A2,STRUCT,RAGUARD,CORR}]`
  (+ SCAN) at start.
- **Report:** `tools/gate-r-run.py <serial-capture.log> …` aggregates those markers,
  maps them to the 33 rows, and prints a per-row table + one
  `GATE-R: PASS/FAIL/INCOMPLETE` line. Rows sharing a rule with an attacker DROP row
  (L7 vs A4/A5 on rule 113) are reported SHARED-indeterminate unless driven in their
  own window. Build a `FEATURES="prod,sepdiag" HOOKPROBE_DEBUG_ACCESS=1` image.

## 4. Sign-off status (§6 — product-steward ruling, 2026-09-08: CONDITIONAL-GO)

31/31 heqk-owned rows are metal-proven (frame-driven or via a sepdiag self-test
through the real datapath entry); L5/L6 are off-device. Four accepted carve-outs:

- **C-1** self-test-through-datapath is acceptable for physically-undrivable rows
  (F4/F7 runt/oversize the host NIC won't emit; A7/A8/L9 resource-shed).
- **C-2** the A1/A9 manifest port-role reader for a **real** Access interface is
  M4/P9-gated (needs the RTL8111/eth1 second datapath; today A1/A9 run on a
  synthetic port and live traffic is fail-safe Uplink = MISS-not-harm).
- **C-3** A11 wire-Quarantine is rejected by design (Observe + severity only).
- **C-4** L5/L6 NAC is off-device (ADR 0044 D3).

**Open (tracked):** a single unified adversarial metal pass emitting one
`GATE-R: PASS` artifact (`gate-r-run.py` is the parser half); the A9 arming
conditions in §5 before C-2 lands. U2 is no longer detection-blocked; retiring the
Linux dataplane is the U2a/U2b split-ADR now that the segmentation reach-actuator
(`segment.rs`) is armed on metal.

## 5. A9 verdict-posture ruling — security-auditor, 2026-09-11: CONDITIONAL-GO

The port-keyed RA-guard is accepted for M2 closure because the `FrameDrop` arm is
**unreachable on the live device** (`DEFAULT_PORT_ROLE = Uplink`, `verdict.rs:153`;
single fused port 0, `packet.rs:302`) — it cannot drop a legitimate frame on any
shipping CM5. Unlike A11 there is **no spoofed-victim path**: the decision
(`verdict.rs:331-340`) reads only the frame type and the heqk-observed ingress port,
never an attacker-asserted identity, and the drop is per-frame, not per-flow.

**The as-built posture is EMBARGOED from arming.** A first-sight, source-blind hard
drop of every RA on an Access port is the *default-deny-everyone-else* posture
**ADR 0023 D16 explicitly removed** on the Linux tier
(`crates/hookprobe-manifest/src/multi_wan.rs:355-362,421,488,537`). Legitimate RAs
on access ports are routine in HookProbe's market (Thread/HomeKit border routers — see
`DEFAULT_ROUTER_OUI_ALLOWLIST`, `multi_wan.rs:321` — downstream routers, IPv6
tethering, ICS, bridging VM hosts), and an RA false-drop costs **segment-wide IPv6
loss, silent until prefix expiry** — a worse legit-drop shape than the iPhone-ARP
incident that seeded ADR 0023.

**Before the C-2 follow-on (manifest port-role reader / RTL8111 Access interface,
P9/M4) may arm any Access-port RA drop, ALL of the following are required:**

- **A9-1** `PortRole::Access` is **manifest-declared only, never inferred** from
  traffic (an attacker who can influence the role chooses who gets dropped, and
  MAC-flooding a port to force `Uplink` would evade both A1 and A9).
- **A9-2** `set_port_role` (`verdict.rs:174`) becomes **authority-gated**, on the
  operator-signed pattern already used for `segment.rs::set_reach` (C16). A single
  authenticated writer; no unauthenticated in-kernel caller. (Shared dependency of
  A1 and A9.)
- **A9-3** Re-map `FindingClass::RaGuard` to **ADR 0023 D16 parity**: unknown source
  → `Observe` + `SEV_HIGH`; recognized OUI / `(MAC, port)` hub-allowlist → `Observe`
  log-suppressed; **RA flood from one source MAC → self-reverting `RateLimit`**
  (clean under D3 — legit routers emit ~1 per 3-600 s per RFC 4861; approved to
  build **now**, no port-role reader required); `FrameDrop` **only** for an
  operator-confirmed `(MAC, port)` rogue.
- **A9-4** `hub_allowlist` and `confirmed_rogue` are **`(MAC, port)`-scoped and
  operator/authority-confirmed, never detector-auto-promoted**. A MAC-global
  `confirmed_rogue` re-imports the A11 flaw: an attacker spoofing the real router's
  MAC gets the **legitimate router** hard-dropped via the operator. Confirmation
  evidence must display the ingress port. Non-negotiable.
- **A9-5** Rule-121 events carry **source attribution** (`ratelimit::mac_hash(&frame[6..12])`,
  already used at `rules.rs:391`) plus a per-port distinct-RA-source counter —
  without it the D16 promote/confirm loop is impossible and a guard-caused IPv6
  outage is undiagnosable. Do not silently overload `Event.src`'s IPv4 semantic
  (`events.rs:44`); add a discriminator or document the rule-keyed interpretation.
- **A9-6** An **IPv6 management floor** exists before any Access drop arms.
  *Correction of record:* the claim *"the mgmt floor still short-circuits"* at
  `verdict.rs:119-121` and `rules.rs:373-375` is **false for this class** —
  `eth_ipv4_src` is `0` for every IPv6 frame and `is_allowlisted(0) == false` by
  design (`verdict.rs:254-256`), so `RaGuard` can never reach the `Allowlisted` arm.
  Comments corrected 2026-09-11; the floor itself is required before arming.
- **A9-7** Evasion is made visible: an IPv6 frame that fails `parse_ipv6`
  (`net.rs:332-368`, `MAX_V6_EXT = 8`) is today **neither dropped nor alerted** — an
  RA behind a padded Hop-by-Hop chain silently bypasses the guard. Emit an
  observe-level finding (never a drop).
- **A9-8** Scope honesty: heqk guards **type 134 only**. ICMPv6 Redirect (137 —
  handled on the Linux tier at `multi_wan.rs:526,538`), unsolicited NA-Override
  (136), and rogue DHCPv6 (RFC 7610) are **scoped-absent**. A9 is a *rogue-RA
  guard*, not a *gateway-hijack guard*.
- **A9-9** Verification: once a real Access interface exists, the C-1 synthetic-port
  carve-out no longer covers A9. Re-drive with real frames, both directions,
  including an **end-to-end SLAAC assertion** that a legitimate Thread/tethering
  router on that port keeps its address and default route — a frame-verdict
  assertion cannot detect the delayed prefix-expiry failure mode.

**Residual risk, stated plainly:** A9 provides zero live *prevention* on shipping CM5
today (rogue RA is Observed + alerted, never dropped — a MISS correctly preferred over
a legit-drop, recorded as C-2). After the conditions, the D16 posture still lets a
single first-sight rogue RA through by design. Redirect/NA-Override/rogue-DHCPv6 are
not mitigated either way. A11's wire-Quarantine NO-GO stands unchanged.

**Cross-tier note (for product-steward):** ADR 0023 D16 is written tier-agnostically;
heqk's as-built A9 contradicts it. Either heqk adopts D16 parity (recommended) or ADR
0023 gains an explicit tier-scoped amendment. Recorded here so the contradiction is
not silent.
