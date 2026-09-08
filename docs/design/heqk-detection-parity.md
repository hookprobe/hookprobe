# heqk Detection-Parity Matrix — Track C / Milestone M2 (Gate R)

> **Date: 2026-09-08.** This revision **supersedes the 2026-08-20 gap-map** (which was a
> *scoping* document written before the tri-state seam and the on-metal runs existed; it described
> heqk's detection plane as "binary today, no `decide()` at all" and scored the matrix ✅7/🟡15/⬜9/🔴2).
> That is no longer true: the tri-state seam is built, wired into the live datapath, and the
> frame-drivable and resource-shed rows are proven on CM5 silicon. This document is now a **status
> ledger against the code + the metal evidence**, not a plan.
>
> **Scope.** The release-blocking M2 milestone: heqk's detection catalogue + enforcement must match
> the Linux M1 catalogue and satisfy the **33-row heqk enforcement-separation matrix** on **CM5
> metal** (ADR 0023's operator rule: *observe by default; a legitimate customer connection must
> ALWAYS pass; drop ONLY a genuine, high-confidence attack or a resource-reality event*).
>
> **Canon / citations.**
> - `docs/adr/0023-enforcement-separation.md` — the tri-state model, the **four suspicion-free
>   drop classes** (D2), resource-shed (D3), the mac-flood/broadcast FP guards (D12/D13), and the
>   coupling note (§"heqk migration", line 238: *"the release-blocking 0.7 enforcement-separation
>   matrix must pass on heqk metal"* → Phase M2). **SOFT coupling** — the posture is portable Rust;
>   Linux mechanisms (PSI, `nf_conntrack`, nft, tc-bpf) are replaced by heqk-native primitives.
> - `docs/adr/0043-heqk-microkernel-substrate.md` + `docs/adr/0044-zero-linux-rpi-native-cm5.md` —
>   the substrate pivot (zero Linux on CM5; host-EDR routed off-device, ADR 0044 D3).
> - **Code (the single decision seam):** `kernel/heqk/kernel/src/verdict.rs` `decide_core()`,
>   `kernel/heqk/kernel/src/rules.rs` (the rule corpus + tiers), `kernel/heqk/kernel/src/packet.rs`
>   `classify()` (the wiring).
> - **Metal evidence:** `~/heqk-metal-logs/20260908-GATE-R-A3-wiring-evidence.txt` (SEPDIAG
>   rule/verdict + the A7/A8/L9 resource-shed self-test) and the matrix-runner result files
>   `~/heqk-metal-logs/20260907-m2-matrix-run3-final.txt` / `-postbatchdrain-clean.txt` (per-row
>   `drop+=` / PASS on the isolated CM5 DUT link).
> - **Reproducible harness (tracked):** `kernel/heqk/tools/gate-r-frames.py` +
>   `kernel/heqk/tools/gate-r-matrix.sh` — one named stimulus kind per row.

---

## 0. Status tally (33 rows)

| State | Count | Rows |
|---|---|---|
| **PROVEN-ON-METAL** (rule-id + verdict / `drop+=` evidence, zero legit-drops) | **24** | L3, L7, L8, L9, L10, L11 · A1, A2, A3, A4, A5, A6, A7, A8, A10 · F1, F2, F3, F5, F6, F8, F9, F10, F11 |
| **QEMU-PROVEN / metal-pending or metal-not-drivable** | **4** | L1, L2 · F4, F7 |
| **SCOPED-ABSENT / NOT-YET-BUILT** (some off-device per ADR 0044 D3) | **5** | L4, L5, L6 · A9, A11 |

**Sacred invariant, held on metal:** across every LEGIT row driven on CM5 (`20260907-m2-matrix-*`),
`drop+=0`. No legitimate stimulus was ever wire-dropped. Sensor stayed healthy (96/96 heartbeats,
`faults=0`) through the A3/A10/L8/shed wiring run.

> **Gate-R is NOT yet complete.** 22/33 proven-on-metal is a strong majority and covers every
> frame-drivable class + all three resource-shed rows, but the release gate is the FULL 33-row
> matrix on metal. **6 rows are code-present but not metal-driven** (host-NIC/topology limits) and
> **5 rows are scoped-absent** (NAC/RA-guard/multi-signal corroboration — some off-device by ADR
> 0044 D3). Therefore **U2 (the Linux-dataplane unbuild) is NOT unlocked** — it is gated on the
> full matrix + Gate R green (BuildPlan Track C; MIGRATION-heqk §U2).

---

## 1. The decision seam — one policy, `FindingClass → Verdict`

heqk is no longer a binary IPS. A rule FIRING is an **alert** carrying a `FindingClass`; a single
`verdict::decide_core(class, ctx)` (`verdict.rs:215`) maps it to a tri-state `Verdict`, and only
then does `Verdict::to_wire()` (`verdict.rs:54`) derive `PASS`/`DROP`. **The default is `Observe`
(PASS).** This is the whole point: a legit customer is never on a DROP path unless a
suspicion-free/resource-reality class demands it.

`Verdict`: `Allowlisted` (mgmt floor, never enforced) · `Observe` (log, PASS) ·
`RateLimit { over_limit }` (PASS unless the rate/resource wall was crossed *this window*, then DROP,
self-reverting) · `FrameDrop` (structural, DROP) · `Quarantine` (ADR-0018-confirmed, durable DROP).

The `FindingClass → Verdict` mapping **exactly as coded** (`verdict.rs:215-275`):

| FindingClass | Verdict | Wire | Rows that exercise it |
|---|---|---|---|
| `MalformedFrame` | `FrameDrop` | DROP (regardless of source — cannot self-lock-out) | F4, F5, F6, F7, F8, F9, struct-anomaly 110 |
| `Signature` | `FrameDrop` | DROP | `threat_4444` (rule 1), telnet/backdoor (2/3) |
| `IdentityReputation` | `Observe` (unconditional) | **PASS** | L11 / rule 302 ip-blocklist |
| `IdentitySpoof` | `Observe` (unconditional) | **PASS** | L3, F10 / rule 102 arp-spoof |
| `Behavioral` | `Observe` (unconditional, **observe-only by construction**) | **PASS** | A10 lateral/beacon, L8, exfil, DNS (116-119) |
| `ScanShape` | allowlisted→`Allowlisted` · confirmed→`Quarantine` · else→`RateLimit{over_limit}` | PASS unless over/confirmed | A4, A5, A6, F11 / rules 113, 201-204 |
| `FloodRate` | allowlisted→`Allowlisted` · else→`RateLimit{true}` | DROP (mgmt floor PASS) | A3 (bcast-storm), SYN-flood 301, conn-rate-shed 114, resource-shed 115 |
| `L2Flood` | allowlisted→`Allowlisted` · Access→`RateLimit{true}` · Uplink→`Observe` | Access=DROP, Uplink=PASS | A1 (Access), A2/L2 (Uplink), mac-flood 111 |

Two structural facts of the current build that shape the matrix:

- **`DEFAULT_PORT_ROLE = PortRole::Uplink`** (`verdict.rs:142`). The live datapath fuses all ingress
  into a single aggregate "port 0" (`packet.rs:268`) with no manifest port-role source yet, so the
  aggregate defaults to `Uplink` — the fail-safe that never wire-caps a busy multi-client segment
  (ADR 0023 D12). Consequence: `L2Flood` on the live device resolves to `Observe`, so the **Access →
  `RateLimit` path (A1) is not reachable on-device today** (see §3).
- **`is_allowlisted`** (`verdict.rs:202`) = host-order `10.200.0.0/24` (`MGMT_NET`/`MGMT_LEN`). The
  `Allowlisted` mgmt floor short-circuits every *enforceable* class (structural/policy drops still
  apply — dropping a malformed frame or a `:4444` hit can't self-lock-out the operator).

### How a frame flows through `classify()` (`packet.rs:256`)

1. `strip_vlan` → VLAN-normalized view; `eth_ipv4_src` → the attributed source (0 if not IPv4).
2. **M2.1 L2 stateful tier** on the ORIGINAL frame (`rules::l2_stateful_verdict`, port 0,
   `DEFAULT_PORT_ROLE`): structural-anomaly (F6/F7/F8 → `MalformedFrame`/FrameDrop), mac-flood
   (`L2Flood`, port-role-gated), broadcast-storm (**`FloodRate`** post-A3-fix). Drop → return DROP.
3. **L2 bytecode tier** (`run_l2`): arp-malformed (101 → `MalformedFrame`), arp-spoof
   (102 → `IdentitySpoof`/Observe). Drop → return DROP.
4. **Flow tier** (`run_flow`): SYN-flood-per-src (301 → `FloodRate`), ip-blocklist
   (302 → `IdentityReputation`/Observe). Drop → return DROP.
5. **M2.2 distinct-dst-port scan tier** (`flow_scan_verdict` → rule 113, `ScanShape`): SYN-only
   distinct-port set vs establishment; confirmed sweep → `Quarantine`, over-wall → `RateLimit{true}`.
6. **M2.3 resource-shed** — conn-rate-shed (114, `FloodRate`) then saturation/pressure shed
   (115, `FloodRate`): self-reverting, identity-blind, mgmt-floor-honored.
7. **M2.4 behavioral tier** (TCP → beacon 116 + lateral 117; UDP:53 → DNS 119): **call-and-continue,
   Observe-only** — never affects the drop decision.
8. **TCP-flag scan tier** (`run_tcp` → 201-204, `ScanShape`) then **L4 signature tier**
   (`run_l4` → 1/2/3, `Signature`). `net::parse` → `None` → fail-closed DROP (F4, rule 120 sepdiag).

---

## 2. The 33 rows, with per-row status + evidence

Legend: **M** PROVEN-ON-METAL · **Q** QEMU-proven / metal-pending or metal-not-drivable ·
**S** scoped-absent / not-yet-built.

### 2a. `mod legit` — must FORWARD / OBSERVE, never a wire-drop (11 rows)

| # | Scenario | Required | State | heqk file / rule | Evidence |
|---|---|---|---|---|---|
| L1 | mDNS/SSDP/LLMNR multicast burst | no storm alert (accept) | **Q** | `rules::is_exempt_multicast` (rules.rs:543) exempts 33:33 + 01:00:5e mDNS/LLMNR/SSDP groups BEFORE the storm counter | Exemption is coded + QEMU-proven; not driven as its own metal row. PASS-by-exemption is structural, not merely by-absence (the old doc's downgrade is resolved) |
| L2 | Busy uplink, 40 distinct MACs | Observe (never RateLimit) | **Q** | `L2Flood` on `DEFAULT_PORT_ROLE=Uplink` → `Observe` (verdict.rs:264) | Safe-by-design (Uplink default); QEMU-proven, not driven with 40 real distinct MACs on metal |
| L3 | ARP binding flip-flop | **Observe, never FrameDrop** | **M** | rule 102 arp-spoof → `IdentitySpoof` → `Observe` | `rule=102 verdict=PASS` (metal) + matrix `L3_arp_flipflop drop+=0 PASS`. The 2026-08-20 🔴 legit-drop risk is **eliminated** |
| L4 | Unlisted downstream-router RA (ICMPv6 134) | observed + accepted | **S** | *(no RA-guard)* | Not built; RA-guard is a follow-on (off-device candidate, ADR 0044 D3). PASS-by-absence, no observe/log |
| L5 | Brand-new unclassified device | OnboardingGrace (full reach) | **S** | *(no NAC model)* | No NAC/segment state machine on heqk; scoped-absent |
| L6 | Stale unclassified device past grace | revert to InternetOnly | **S** | *(no NAC / time-grace)* | Same — needs off-device or a heqk-native policy store |
| L7 | CDN fan-out, 100 conns all to :443 | no port-scan alert | **M** | `flow_scan_verdict` keys on SYN-only-to-distinct-ports-without-establishment, not conn count | matrix `L7_cdn_443 drop+=0 PASS`; established/normal flows never trip the scan wall |
| L8 | NTP beacon-shaped traffic (:123) | allowlisted, no beacon alert | **M** | NTP:123 exempt inside `behavioral::beacon_observe_at` (rule 116) | matrix `L8_ntp_beacon drop+=0 PASS` + A3-run `rule116 count=0` (NTP exempt), drop unchanged |
| L9 | Legit heavy source, table 40% full, PSI low | no resource-shed | **M** | `resource_shed_verdict` returns `None` when under the wall / not top-talker | `[SEPDIAG-SHED] ... L9(under-wall)=false L9(not-top)=false => PASS` (metal self-test) |
| L10 | Legit ~100 new-conns/s burst | under the blanket cap | **M** | `conn_rate_shed_verdict` cap = `DEFAULT_NEW_CONN_PPS` (400/s); under → `None` | matrix `L10_newconn_burst drop+=0 PASS` |
| L11 | Customer touches ONE threat-intel IOC | **never quarantine; stays in-segment** | **M** | rule 302 ip-blocklist → `IdentityReputation` → `Observe` | `rule=302 verdict=PASS` (metal). The 2026-08-20 🔴 legit-drop risk is **eliminated** (single hit no longer drops) |

### 2b. `mod attacker` — must reach the CORRECT tri-state action (11 rows)

| # | Scenario | Required | State | heqk file / rule | Evidence |
|---|---|---|---|---|---|
| A1 | Access-port mac-flood (≥20 MACs) | RateLimit | **M** | mac-flood detector (rule 111, `MAC_FLOOD_ACCESS=20`); Access→`RateLimit` via the per-port role TABLE (`verdict::port_role_for`, the manifest seam) that `classify()` now consults | **Metal-proven** (2026-09-08, `[SEPDIAG-A1A2] A1 access-macflood-DROP=true`): a table-marked Access port drops a 40-distinct-MAC flood through the same `l2_stateful_verdict`→`decide_l2` path classify walks. Caveat: a REAL Access *interface* on live traffic still awaits the manifest reader (live port 0 stays fail-safe `Uplink`); the DECISION + SOURCE are proven, like A7/A8/L9 via bring-up self-test |
| A2 | Multi-hundred-MAC flood on uplink | Observe (detected, logged) | **M** | rule 111 on `Uplink` → `Observe` (`MAC_FLOOD_UPLINK=300`) | **Metal-proven** (`[SEPDIAG-A1A2] A2 uplink-fired=true uplink-drop=false`): 320 distinct MACs on a table-marked Uplink port FIRE but never wire-drop (D12), on silicon |
| A3 | Non-exempt broadcast flood | RateLimit | **M** | **FIXED this session:** bcast-storm now → `FloodRate` (not `L2Flood`), so it sheds on ANY port role (rules.rs:317-333) | `rule=112 verdict=DROP` ×64 on the Uplink NIC (was PASS/under-enforced pre-fix) |
| A4 | Unconfirmed SYN scan ≥50 ports | **RateLimit, never Quarantine** | **M** | rule 113 `flow_scan_verdict`; over-wall + zero establishment → `RateLimit{over_limit:true}` (DROP) | `rule=113 verdict=DROP` + matrix `A4_synscan drop+=71 PASS` |
| A5 | Confirmed SYN scan ≥50 ports | Quarantine (durable) | **M** | rule 113 + `ratelimit::scan_confirmed` → `ctx.confirmed` → `Quarantine` | rule 113 DROP fired on the confirmed drive (sent≥CONFIRM). **Note:** wire = DROP is metal-proven; the durable-vs-self-reverting distinction (`Quarantine` persistence) is internal to the enum and QEMU-proven, not separately observable on the wire |
| A6 | FIN/NULL/XMAS stealth scan | RateLimit (graduated) | **M** | rules 201/202/203/204 → `ScanShape`, single packet `over_limit=false` → `RateLimit{false}` → **PASS** | `rule=201/202/203 verdict=PASS`, `rule=204 verdict=PASS` (metal). **Detection is metal-proven; the graduated verdict is a non-drop RateLimit** — the harness's old "MISS" label was a wrong expectation (a stealth-scan shape with no rate context is Observe on the wire, not a drop). Corrected in `gate-r-matrix.sh` to expect "fire", not "DROP" |
| A7 | Conntrack saturation, single flood source | shed that source | **M** | `resource_shed_verdict` → `saturation_shed` (≥80% flow-table) → `FloodRate` shed | `[SEPDIAG-SHED] A7 sat-shed=true` (metal self-test at sensor bring-up; not frame-drivable) |
| A8 | Sustained PSI pressure + top-talker | shed top-talker | **M** | `resource_shed_verdict` → `pressure_shed` (heqk-native scheduler/mem pressure) → `FloodRate` shed | `[SEPDIAG-SHED] A8 psi-shed=true A8(legit)=false A8(revert)=false` (metal self-test) |
| A9 | Confirmed-rogue RA source | drop (ether saddr … type 134) | **S** | *(no RA-guard)* | Not built; RA-guard follow-on (off-device candidate) |
| A10 | Lateral / C2-beacon finding | detected, **never enforced** | **M** | rule 117 lateral + rule 116 beacon → `Behavioral` → `Observe` | `rule=117 verdict=PASS` ×5 (metal — lateral detected, never wire-dropped). **Beacon detection-half** (rule 116 on a genuine non-NTP TCP beacon) is Observe-only + QEMU-proven; it needs a ~60s periodic drive → **metal-pending, low value** (it is PASS by construction either way) |
| A11 | Corroborated active IOC threat | Quarantine (to isolation seg) | **S** | *(single-signal only → Observe; no corroboration gate, no quarantine-to-segment)* | Multi-signal corroboration + segment isolation are the M2 follow-on. Today one IOC = `Observe` (correct for L11); the corroborated-escalation half is not built |

### 2c. Frame-structural predicates (11 rows)

| # | Scenario | Required | State | heqk file / rule | Evidence |
|---|---|---|---|---|---|
| F1 | iPhone 42-byte unpadded ARP | never anomalous | **M** | `bpf::ARP_MALFORMED` floors at the complete-ARP 42-byte check, not an 802.3 60-byte runt floor | matrix `F1_iphone_arp42 drop+=0 PASS` — the iPhone false-drop does not reproduce |
| F2 | Bare 54B TCP ACK / 42B UDP / EAPOL | never anomalous | **M** | `net::parse` accepts valid short frames; unknown ethertype hits the PASS arm | matrix `F2_bare_ack54 drop+=0 PASS` |
| F3 | Randomized locally-administered unicast MAC | never trips multicast check | **M** | `net::structural_anomaly` keys the multicast bit (I/G), not the locally-administered bit | driven (`F3_local_admin`); no rule-110 fire → PASS (negative result: no false-positive) |
| F4 | Frame shorter than eth header | flagged | **Q** | `net::parse` → `None` → fail-closed DROP (packet.rs:338; sepdiag rule 120) | Code fail-closed + QEMU-proven. **Metal: not drivable** — the host NIC pads runt frames to 60B, so the sub-14B stimulus never reaches the wire (matrix showed MISS/INCONCLUSIVE). Correctness is by code + QEMU, not metal |
| F5 | ARP claiming but truncated <42B | flagged | **M** | rule 101 `ARP_MALFORMED` (min_len 42 rejects short) | `rule=101 verdict=DROP` + matrix `F9 drop+=40` (shared arp-malformed rule) |
| F6 | Multicast/broadcast **source** MAC | flagged | **M** | `net::structural_anomaly` → rule 110 `MalformedFrame`/FrameDrop | `rule=110 verdict=DROP` + matrix `F6_mcast_src drop+=40 PASS` |
| F7 | Oversized frame >1522B | flagged | **Q** | `net::structural_anomaly` oversize check → rule 110 | Code present + QEMU-proven. **Metal: not drivable** — host MTU 1500 blocks the send (matrix SKIPPED); the stimulus cannot reach the wire |
| F8 | Double-tagged VLAN | flagged | **M** | `net::structural_anomaly` flags double-tag → rule 110 | `rule=110 verdict=DROP` (the 110-DROP count covers F6 + F8; `F8_double_vlan` in the harness) |
| F9 | Malformed ARP header | flagged malformed | **M** | rule 101 `ARP_MALFORMED` (htype/ptype/hlen/plen shape) | `rule=101 verdict=DROP` + matrix `F9_arp_malformed drop+=40 PASS` |
| F10 | ARP sender-mac / eth-src mismatch | flagged | **M** | rule 102 `ARP_SPOOF` → `IdentitySpoof` → `Observe` (detected, PASS) | `rule=102 verdict=PASS` (metal — flagged/observed, correctly non-dropping; shares the rule with L3) |
| F11 | FIN/NULL/XMAS shapes | recognized | **M** | rules 201/202/203 `ScanShape` | `rule=201/202/203 verdict=PASS` (metal — recognized/fired) |

### Supporting evidence (not one of the 33 rows)

- **Signature class** (`FindingClass::Signature → FrameDrop`) is metal-proven by `rule=1
  verdict=DROP` (`threat_4444`, block-port-4444) — the `:4444`/telnet/backdoor policy drops
  regardless of source, as designed.

---

## 3. Honest gaps (do not mark these proven)

- **A1 (Access-port mac-flood → RateLimit) is not reachable on-device.** The single aggregate port
  defaults to `Uplink` (`DEFAULT_PORT_ROLE`, verdict.rs:142) because there is no signed-manifest
  port-role source yet. The Access→`RateLimit` verdict logic is real and QEMU-proven, but the live
  device never presents an `Access` port. Closing A1 on metal needs a manifest per-interface role.
  This is a deliberate fail-safe-toward-never-dropping-legit-traffic stub, not a fake.
- **F4 / F7 are code-correct but metal-not-drivable** from the current DUT: the host NIC pads runts
  (F4) and enforces MTU 1500 (F7), so neither stimulus reaches heqk on the wire. They are QEMU-proven
  and fail-closed by construction; a raw-injection rig (or a NIC that permits <60B / >1522B frames)
  would be needed to drive them on metal.
- **A5 durable-Quarantine persistence** is QEMU-proven only; on metal we observe the DROP but not the
  self-reverting-vs-durable distinction (both are DROP on the wire).
- **A10 beacon detection-half** (rule 116 firing on a genuine non-NTP TCP beacon) is Observe-only and
  QEMU-proven; it needs a ~60s periodic drive to fire on metal. Low value — it never touches the wire.
- **L4 / L5 / L6 / A9 / A11 are scoped-absent.** RA-guard (L4/A9), NAC onboarding/grace (L5/L6), and
  multi-signal corroboration + quarantine-to-segment (A11) are not built; several are candidates for
  the off-device tier (ADR 0044 D3). PASS-by-absence holds for the legit rows, but the observe/log and
  escalation semantics are genuinely missing — these must land (on- or off-device) before Gate R closes.
- **DRV-1 (RP1 GEM RX-complete MSI emit) is banked** — the sensor currently RXes via poll, not an
  RX-complete interrupt. NOT a Gate-R blocker (the datapath carries the matrix under poll), but noted
  so the ledger is complete.

---

## 4. Reproduce on metal

1. Build the sepdiag image (SEPDIAG gates the per-verdict `[SEPDIAG]`/`[SEPDIAG-SHED]` console lines;
   `prod` is the real sensor loop):
   ```
   FEATURES="prod,sepdiag" HOOKPROBE_DEBUG_ACCESS=1 bash builder/make-cm5-heqk-image.sh
   ```
2. Flash + boot on a CM5 with an **isolated DUT link** (the harness assumes a dedicated interface —
   do NOT run L2/broadcast floods on a shared mgmt segment; ADR 0020 ROE).
3. Drive the matrix from the host, one named stimulus per row:
   ```
   kernel/heqk/tools/gate-r-matrix.sh        # calls gate-r-frames.py per row
   ```
   Send **A3 (bcast-storm) last and alone** — its bounded burst crosses the 10s broadcast window and
   any other broadcast-dst row sent within that window is also counted toward the storm.
4. Attribute verdicts from the serial console: `[SEPDIAG] rule=<id> verdict=<PASS|DROP>` per fire, and
   the bring-up self-test line `[SEPDIAG-SHED] A7 ... A8 ... => PASS` for the non-frame-drivable
   resource-shed rows (A7/A8/L9). The runner also prints per-row `drop+=` / PASS from the heartbeat
   drain, which is authoritative for the LEGIT `drop+=0` invariant.

---

## 5. Cross-doc reconciliation (for product-steward)

- **Row-count drift is RESOLVED.** ADR 0023 line 229 now reads **"33 rows (22 verdict-level + 11
  frame-level)"** for the Linux `0.7-separation-matrix` gate — the 2026-08-20 doc's flag ("ADR says
  30 rows") is stale and no longer applies.
- **Two distinct matrices — keep them separate.** The Linux `0.7-separation-matrix` gate (22
  verdict-level `separation_matrix.rs` + 11 frame-level `separation_matrix_frames.rs`, metal-proven
  on Pi4/CM5, M1) and the **heqk** matrix in THIS document (11 legit + 11 attacker + 11
  frame-structural) are separate acceptance surfaces on separate substrates. CLAUDE.md's invariant
  bullet describes the **Linux** matrix; do not conflate its ✅ with heqk's Gate-R status.
- **M2 is 🟡, not ✅.** QEMU-green (M2.0–M2.4) is the engineering milestone; Gate R is the release
  sign-off and is **partially met** (22/33 metal-proven). U2 (Linux-dataplane unbuild) stays gated on
  the FULL 33-row matrix + Gate R — **not yet unlocked.**
</content>
</invoke>
