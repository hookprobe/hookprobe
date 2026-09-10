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
| A9  | rogue RA on an access port → FrameDrop | sepdiag RAGUARD (synthetic Access port, C-2; posture → security-auditor) |
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

**Open (tracked):** the A9 RFC-6105 FrameDrop-on-Access **posture** still needs a
recorded security-auditor sign-off; a single unified adversarial metal pass emitting
one `GATE-R: PASS` artifact (`gate-r-run.py` is the parser half). U2 is no longer
detection-blocked; retiring the Linux dataplane is the U2a/U2b split-ADR now that the
segmentation reach-actuator (`segment.rs`) is armed on metal.
