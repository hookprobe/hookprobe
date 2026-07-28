# heqk Detection-Parity Gap-Map — Track C / Milestone M2

> **Scope.** The release-blocking M2 milestone: heqk's detection catalogue + enforcement must match
> the Linux M1 catalogue rule-for-rule, and the `0.7-separation-matrix` gate must pass on heqk.
> This document is the **scoping deliverable** — a grounded gap-map from heqk's shipped detection
> plane to the Linux acceptance spec. **It changes no code and commits nothing.**
>
> Canon: `docs/adr/0023-enforcement-separation.md` (the tri-state model + the four suspicion-free
> inline drops), `crates/hookprobe-manifest/tests/separation_matrix.rs` +
> `modules/napse-capture/loader/tests/separation_matrix_frames.rs` (the acceptance matrix),
> `docs/adr/0043` / `0044` (the substrate pivot), `kernel/heqk/PRODUCTION_READINESS.md` (heqk's
> QEMU-proven surface).
>
> **⬆ M2 IMPLEMENTATION STATUS (2026-07-28 — QEMU-green).** M2.0–M2.4 are now BUILT + committed +
> validate.sh-green on heqk under QEMU (no longer scoping-only): **M2.0** tri-state `decide()` seam
> (`verdict.rs`, `P8-sep`) · **M2.1** L2 structural + mac-flood/bcast-storm w/ Access-vs-Uplink FP
> guards (`P8-l2struct`) · **M2.2** flow-state/conntrack-equiv → confirmed-scan `Quarantine` +
> saturation signal (`P8-flow`) · **M2.3** resource-shed: self-reverting L1 conn-cap + L2 saturation
> + L3 PSI-equiv, mgmt-floor-never-shed (`P8-shed`) · **M2.4** L7 observe-only beacon/lateral/exfil/
> DNS (`P8-l7b`); host-EDR EXCLUDED (off-device, ADR 0044 D3). **Metal remainder (Gate R — NOT
> QEMU-closable):** the L3 PSI *real* signal, conntrack-saturation + confirmed-scan *under real
> load*, self-revert TTL under wall-clock, and the whole-matrix end-to-end "a legit customer ALWAYS
> passes under load." **~24/33 rows QEMU-green; ~9 are metal.** QEMU-green is the M2 *engineering*
> milestone, NOT the release sign-off (ADR 0023 requires the matrix on heqk metal).

---

## Honesty header (Track-C discipline)

1. **QEMU-green ≠ metal.** Everything heqk "HAVE" below is proven only in the `validate.sh` QEMU
   harness (`PRODUCTION_READINESS.md` P6/P6b/P8: "verifier PROVEN SOUND", "L2/TCP/SYN-flood/
   blocklist/L7 rules, SOAR ring", both ✅ in the QEMU column). None of it is metal-validated on
   CM5. The Linux M1 catalogue, by contrast, is **metal-proven** (Pi4/CM5, separation matrix both
   directions). Parity means matching the Linux verdicts, not matching Linux's proof depth — Gate R
   (§4) is where heqk earns the metal claim.
2. **This is design-ahead-of-kernel where marked.** Several required verdict classes (tri-state
   graduation, Allowlisted floor, resource-shed) have **no heqk primitive to build on yet** — PSI/
   conntrack/nft/tc-bpf are Linux mechanisms ADR 0023's coupling note calls "replaced by heqk's
   native resource-accounting + Packet-Engine primitives." Those primitives are not yet written.
   Rows depending on them are `⬜ missing` with the honest note "needs a heqk primitive first."
3. **The heqk detection plane is binary today.** `packet.rs` defines exactly two verdicts —
   `PASS = 1`, `DROP = 2` — and **a rule that fires returns `DROP` inline** (`rules.rs:152`,
   `run_set`). There is **no `Observe`, no `RateLimit`, no `Quarantine`, no `Allowlisted`**. This is
   the single load-bearing gap and it inverts the observe-by-default posture; §3 is devoted to it.
4. **Row-count drift, flagged not resolved.** ADR 0023 D6 says "30 rows (19 responder + 11 frame)."
   The responder file has since grown to **22 `#[test]` rows** (11 `legit` + 11 `attacker`), so the
   live matrix is **33 rows** (22 + 11). This doc maps all 33 and flags the ADR/gate wording as
   stale — `product-steward` should reconcile ADR 0023 D6 and `gate-ladder.sh:285`'s "30 rows"
   comment to 33. The M2 acceptance target is **the live matrix**, whatever its count on the day.

---

## 1. The separation matrix, row-by-row (the acceptance gate)

Legend: ✅ have · 🟡 partial / holds-by-absence / verdict-mismatch · ⬜ missing · 🔴 **active
legit-drop risk on heqk today** (an invariant heqk would *violate*, not merely miss).

### 1a. `mod legit` — must FORWARD / OBSERVE, never a wire-drop (11 rows)

| # | Row (scenario) | Required verdict | heqk today | heqk file / rule | Wire action on heqk | Risk |
|---|---|---|---|---|---|---|
| L1 | mDNS/SSDP/LLMNR multicast burst | no storm alert (accept) | 🟡 holds-by-absence | *(no bcast-storm detector)* | PASS | Invariant holds only because heqk has no storm detector; the D13 multicast **exemption** must be built alongside the detector so it isn't a false-drop when L2-storm parity lands |
| L2 | Busy uplink, 40 distinct MACs | Observe (never RateLimit) | 🟡 holds-by-absence | *(no mac-flood detector, no PortRole)* | PASS | Same: safe today by absence; needs the D12 topology/port-role gate when mac-flood parity lands |
| L3 | ARP binding flip-flop | **Observe, never FrameDrop** | 🔴 **violates** | `bpf::ARP_SPOOF` (rules.rs:38) drops inline | **FrameDrop** | heqk's single-packet ARP_SPOOF (eth-src≠sender-mac) DROPs; a legit gratuitous/proxy-ARP or NAT rebind is severed. Flip-flop is cross-packet (heqk has no ARP state) so it isn't even the right detector, yet the wrong one drops. **Top-tier legit-drop risk** |
| L4 | Unlisted downstream-router RA (ICMPv6 134) | observed + accepted | 🟡 holds-by-absence | *(no RA-guard)* | PASS | Safe by absence; no observe/log either — RA-guard parity is missing entirely |
| L5 | Brand-new unclassified device | OnboardingGrace (full reach) | 🟡 holds-by-absence | *(no NAC model)* | PASS | heqk has no NAC/segment model; device reachability is not gated at all, so "never stranded" holds trivially but the grace/segment semantics are absent |
| L6 | Stale unclassified device past grace | revert to InternetOnly | ⬜ missing | *(no NAC / no time-grace)* | PASS | No NAC state machine; needs off-device or a heqk-native policy store |
| L7 | CDN fan-out, 100 conns all to :443 | no port-scan alert | 🟡 partial | `bpf::TCP_*_SCAN` are flag-based, not port-count | PASS | Legit passes (flag-scan rules don't match normal SYN/ACK), but heqk has **no distinct-dst-port scan detector** (Linux rule 1000003), so the FP-guard that "counts ports not destinations" has nothing to guard yet |
| L8 | NTP beacon-shaped traffic (:123) | allowlisted, no beacon alert | 🟡 holds-by-absence | *(no beacon detector)* | PASS | Safe by absence; the port-123 allowlist (FP-guard #4) must ship with the beacon detector |
| L9 | Legit heavy source, table 40% full, PSI low | no resource-shed | 🟡 holds-by-absence | *(no PSI/conntrack/shed)* | PASS | Safe by absence; needs heqk-native resource accounting to be *able* to shed at all (§2, resource-shed) |
| L10 | Legit ~100 new-conns/s burst | under the blanket cap | 🟡 partial-mismatch | `ratelimit::syn_rate_over` (ratelimit.rs:45) | PASS **if** limit generous; **DROP if not** | heqk *has* a per-key fixed-window limiter, but over-limit returns **DROP** (binary), not a bounded self-reverting `RateLimit` meter. A mis-tuned `TCP_SYN_FLOOD_SRC` limit would false-drop a legit burst. Cap value + non-drop semantics must be reconciled to `DEFAULT_NEW_CONN_PPS=400` |
| L11 | Customer touches ONE threat-intel IOC | **never quarantine; stays in-segment** | 🔴 **violates** | `blocklist::ip_blocked` (blocklist.rs:27) → DROP | **DROP** | heqk's IP-blocklist DROPs any feed hit **inline, with no corroboration gate**. A shared-hosting/CDN IP in a HYDRA feed severs a paying customer. No `min_distinct_signals`, no "one signal ≠ enforce." **Top-tier legit-drop risk** |

### 1b. `mod attacker` — must reach the CORRECT tri-state action (11 rows)

| # | Row (scenario) | Required verdict | heqk today | heqk file / rule | Wire action on heqk | Risk / note |
|---|---|---|---|---|---|---|
| A1 | Access-port mac-flood (≥20 MACs) | RateLimit | ⬜ missing | *(no mac-flood detector)* | PASS (undetected) | No L2 fan-out state; no RateLimit verdict |
| A2 | Multi-hundred-MAC flood on uplink | Observe (detected, logged) | ⬜ missing | *(no mac-flood detector)* | PASS (undetected) | The "detect but don't cap the AP radio" nuance can't exist without the detector + port-role |
| A3 | Non-exempt broadcast flood | RateLimit | ⬜ missing | *(no bcast-storm detector)* | PASS (undetected) | — |
| A4 | Unconfirmed SYN scan ≥50 ports | **RateLimit, never Quarantine** | ⬜ missing | *(no distinct-port scan counter)* | PASS (undetected) | heqk's TCP rules are flag-shape only; there is no ≥50-distinct-port tracker, no bounded RateLimit verdict |
| A5 | Confirmed SYN scan ≥50 ports | Quarantine (durable) | ⬜ missing | *(no confirmation gate, no quarantine)* | PASS (undetected) | Needs the ADR-0018 confirmation signal (handshake / conntrack-ESTABLISHED) **and** a durable identity block — both absent |
| A6 | FIN/NULL/XMAS stealth scan | RateLimit | ✅ detect / 🟡 verdict | `bpf::TCP_NULL/FIN/XMAS_SCAN` (rules.rs:44-46) | **DROP** | **Detection parity is real and strong here.** But heqk DROPs where the matrix wants a bounded RateLimit. These shapes are unambiguously hostile so a drop is defensible, yet it's not the graduated verdict and it forgoes the anti-reflection property |
| A7 | Conntrack saturation, single flood source | shed that source | 🟡 partial | `ratelimit::syn_rate_over` (rate only) | DROP-over-rate | Has a per-source rate limiter but no conntrack table and no saturation-triggered top-talker shed; not keyed on the ≥80% resource wall |
| A8 | Sustained PSI pressure + top-talker | shed top-talker | ⬜ missing | *(no PSI equivalent)* | PASS (unshed) | Needs a heqk-native scheduler/mem-pressure primitive (heqk *is* the kernel — no `/proc/pressure` to read; it must **expose** its own) |
| A9 | Confirmed-rogue RA source | drop (ether saddr … type 134) | ⬜ missing | *(no RA-guard)* | PASS (undetected) | — |
| A10 | Lateral / C2-beacon finding | detected, **never enforced** | ⬜ missing | *(no beacon/lateral detector)* | PASS | The "no enforcement consumer" half holds trivially by absence; the **detection** half is missing, so it's not parity |
| A11 | Corroborated active IOC threat | Quarantine (to isolation seg) | 🟡 partial | `blocklist::ip_blocked` → DROP | DROP | Can drop, but conflated with the legit-IOC case (L11): no corroboration gate to *distinguish* them, and no quarantine-to-segment. Same primitive currently serves both, incorrectly |

### 1c. `separation_matrix_frames.rs` — raw-frame predicates (11 rows)

| # | Row (scenario) | Required | heqk today | heqk file / rule | Note |
|---|---|---|---|---|---|
| F1 | iPhone 42-byte unpadded ARP | never anomalous | ✅ have | `bpf::ARP_MALFORMED` forces min_len **42** (bpf.rs:74) | heqk's floor is the *complete-ARP* 42-byte check, **not** an 802.3 60-byte runt floor — so it does **not** reproduce the iPhone false-drop. Best-in-class row |
| F2 | Bare 54B TCP ACK / 42B UDP / EAPOL | never anomalous | 🟡 partial | `net::parse` (net.rs:70) | Valid frames parse `Some` → PASS; EAPOL (unknown ethertype) hits the `_ => Some(meta)` PASS arm. Likely safe, but there is no explicit min-len exemption test on heqk — verify under §4 |
| F3 | Randomized locally-administered unicast MAC | never trips multicast check | 🟡 holds-by-absence | *(no source-MAC multicast check)* | Safe by absence; the check itself (attacker F6) is also missing |
| F4 | Frame shorter than eth header | flagged | ✅ have | `net::parse` → `None` → classify DROP (packet.rs:286) | Fail-closed on truncation |
| F5 | ARP claiming but truncated <42B | flagged | ✅ have | `bpf::ARP_MALFORMED` (min_len 42 rejects short) | — |
| F6 | Multicast/broadcast **source** MAC | flagged | ⬜ missing | *(no source-MAC check)* | A single-frame structural rule heqk should add cheaply |
| F7 | Oversized frame >1522B | flagged | ⬜ missing | *(FRAME_SZ=2048 clamp, no 1522 anomaly)* | heqk clamps to a buffer size but does not flag oversize as an anomaly |
| F8 | Double-tagged VLAN | flagged | 🟡 divergent | `net::parse` MAX_VLAN_TAGS=3 (net.rs:23,77) | heqk **normalizes** 1-2 tags (strips + inspects) rather than **flagging** the double-tag as anomalous. Security-equivalent-or-better, but not verdict-parity. Reconcile posture with Linux |
| F9 | Malformed ARP header | flagged malformed | ✅ have | `bpf::ARP_MALFORMED` (htype/ptype/hlen/plen shape) | Mirrors `dpi::ArpObs::is_malformed` field-for-field |
| F10 | ARP sender-mac / eth-src mismatch | flagged | ✅ have | `bpf::ARP_SPOOF` (rules.rs:38, mirrors `eth_mismatch`) | Same rule that creates the L3 legit-drop risk — see §3 |
| F11 | FIN/NULL/XMAS shapes | recognized | ✅ have | `bpf::TCP_NULL/FIN/XMAS_SCAN` | Strong detection parity |

**Matrix scoreboard (33 rows):** ✅ full-parity **7** · 🟡 partial/by-absence/mismatch **15** ·
⬜ missing **9** · 🔴 active legit-drop-risk **2**. The two 🔴 rows (L3 ARP-spoof, L11 IOC-blocklist)
are the ones that would make heqk **fail the gate by dropping legit traffic** — worse than a miss.

---

## 2. The detection catalogue, Linux → heqk

Grouped by layer. "heqk" column: ✅/🟡/⬜ as above.

### L2 (frame / ARP)
| Linux detector | rule ID | heqk equivalent | Notes |
|---|---|---|---|
| Malformed-frame (runt / oversize / structural) | 1000033 | 🟡 partial | Fail-closed on truncation ✅; oversize ⬜; protocol-aware runt floor ≈✅ (ARP min_len 42) |
| MAC-flood / table-exhaustion | 1000030 | ⬜ missing | No fan-out state, no PortRole topology gate |
| ARP-spoof | 1000031 | 🟡 have-detect / wrong-verdict | `ARP_SPOOF` detects eth-mismatch but **drops** (should Observe for flip-flop; see §3) |
| Broadcast-storm | 1000032 | ⬜ missing | No storm meter, no mDNS/SSDP/LLMNR exemption |

### L3 / L4 (scan / flood / blocklist)
| Linux detector | rule ID | heqk equivalent | Notes |
|---|---|---|---|
| Port scan, ≥50 distinct dst ports | 1000003 / 1000001 | ⬜ missing | heqk has **no distinct-port counter**; only flag-shape rules |
| FIN / NULL / XMAS stealth shapes | (dpi `classify_scan_probe`) | ✅ have | `TCP_NULL/FIN/XMAS_SCAN` + `TCP_SYNFIN` |
| UDP / slow / ICMP scan variants | (napse-dpi) | ⬜ missing | Observe-only in Linux; not detected on heqk |
| SYN-flood, per-source | (flow tier) | 🟡 partial | `TCP_SYN_FLOOD_SRC` + `syn_rate_over` — but **DROP**, not self-reverting RateLimit |
| IP blocklist / threat-feed | (ADR 0005) | 🟡 have / no-corroboration | `blocklist::ip_blocked` DROPs inline; **no corroboration gate** (drives L11 risk) |

### L7
| Linux detector | rule ID | heqk equivalent | Notes |
|---|---|---|---|
| C2 beacon (timing) | 1000040 | ✅ **M2.4** | `behavioral::beacon_observe_at` (rule 116) — per-(src,dst,port) inter-arrival periodicity via an INTEGER mad/mean proxy for CV (no_std, no float); NTP(:123) exempt (L8). OBSERVE-only (`FindingClass::Behavioral`→`Observe`). JA3-content beacon (1000004) is deferred (no TLS-fingerprint surface on heqk) |
| Lateral movement | 1000041 | ✅ **M2.4** | `behavioral::lateral_observe` (rule 117) — internal→internal distinct-peer fan-out on admin ports; OBSERVE-only |
| Bulk outbound exfil | 1000025 | ✅ **M2.4** (volume) | `behavioral::exfil_observe` (rule 118) — per-source windowed internal→external byte volume; OBSERVE-only. Upload/download RATIO deferred (needs bidirectional flow accounting heqk lacks) |
| DNS tunneling / DGA / high-entropy | 1000002 / 1000021 / 1000011 | ✅ **M2.4** (heuristic) | `behavioral::dns_qname_anomaly` (rule 119) — parses the UDP:53 QNAME in-kernel (FEASIBLE via `net::parse` l4_off+8); flags over-long name/label (tunneling) + long high-byte-diversity digit-mixed label (DGA); OBSERVE-only. DEFERRED (noted, not faked): true Shannon-entropy/n-gram/NN scoring + DNS name-compression-pointer following |
| L7 signature (payload match) | (dpi) | 🟡 partial | `l7::payload_match` helper #3 exists (MQTT seed corpus) — mechanism present, corpus tiny |

### Host-EDR (architecturally special — call out honestly)
| Linux detector | rule ID | heqk equivalent | Notes |
|---|---|---|---|
| exec / persistence host-EDR | 1000100–1000115 | ⬜ **architecturally N/A on heqk — EXCLUDED at M2.4 (implemented decision, not a miss)** | **heqk has no process/exec model** (ADR 0044: zero Linux, capability microkernel; the on-device Wasm host is a *build target*, not a POSIX process table). There is no `execsnoop`/`fanotify` equivalent because there are no processes to snoop in the Linux sense. Host-EDR parity is **not portable as-is** — it must either move **off-device** (ADR 0044 D3 hosted tier) or be re-expressed against heqk's capability/IPC events (a lifecycle telemetry stream), which is out of M2 scope. **M2.4 DECISION (2026-07-28):** these rows are deliberately **NOT implemented** on-device — no fake host-EDR was fabricated; the exclusion is recorded here and enforced by the absence of any `RULE_*` in the 1000100–115 band in `kernel/heqk/kernel/src/rules.rs`. The on-device M2.4 behavioral tier ships beacon/lateral/exfil/DNS only (`RULE_BEACON`/`LATERAL`/`EXFIL`/`DNS` = 116–119). Host-EDR is routed **off-device (ADR 0044 D3)**. **These rows are correctly *excluded* from the heqk separation matrix**; documented so it is not mistaken for a miss |

### Flow-state (conntrack-equivalent)
| Linux primitive | heqk equivalent | Notes |
|---|---|---|
| `nf_conntrack` table (count, per-src, ESTABLISHED) | ⬜ missing | heqk has `ratelimit.rs` fixed-window per-key counters (SLOTS=256) — a *rate* primitive, **not** a flow table. No connection state, no ESTABLISHED signal (so ADR-0018 confirmation can't be sourced), no saturation percentage. This is a **prerequisite** for A5 (confirmed scan → Quarantine), A7 (conntrack saturation), and the L11/A11 corroboration split |

### Tri-state decide() / decide_l2 — see §3.

### Resource-shed (per-source cap + conntrack-saturation + PSI)
| Linux layer | heqk equivalent | Notes |
|---|---|---|
| L1 blanket per-source new-conn cap (400/s) | 🟡 partial | `syn_rate_over` is per-key rate, but drops (not a self-reverting meter) and isn't a blanket always-on cap |
| L2 conntrack-saturation guard (≥80%) | ⬜ missing | No conntrack table to measure |
| L3 PSI CPU/mem pressure | ⬜ **needs heqk primitive** | No `/proc/pressure`; heqk must **expose** a native scheduler/allocator pressure signal (it is the kernel). Designable, not present |

---

## 3. Tri-state enforcement parity — **the keystone gap**

**Question:** does heqk's decide path graduate `Observe → RateLimit → Quarantine/FrameDrop` with an
`Allowlisted` floor, exactly like ADR 0023 D1?

**Answer: No. heqk has no `decide()` at all. It is a binary IPS.**

- `packet.rs:19-20` defines the entire verdict universe: `PASS = 1`, `DROP = 2`.
- `rules.rs:152` — the moment any rule's bytecode returns `bpf::DROP`, `run_set` **returns
  `packet::DROP`** and the frame is dropped inline. Detection and enforcement are the **same event**.
- The netq gates (`netq.rs:120 rx_publish`, `netq.rs:161 tx_drain`) consume that binary verdict: a
  `DROP` frame "never enters the ring" / "never reaches the wire." There is no third state to carry.

This is the **exact inversion** of ADR 0023's operator rule ("observe by default; suspicion alone is
never sufficient to touch the wire"). On heqk, **every detector that fires touches the wire.** That
is why the two 🔴 rows exist and why most 🟡 legit rows are "safe only by absence of the detector":
the moment a detector is ported naïvely, it will drop legit traffic, because there is no `decide()`
to demote a low-confidence or spoofable finding to `Observe`.

Missing pieces, in dependency order:

1. **A verdict enum with more than two states** — the heqk analogue of `ReflexVerdict` /`L2Verdict`:
   `Observe` (log, PASS on the wire) · `RateLimit` (bounded, self-reverting) · `Quarantine` /
   `FrameDrop` (durable / structural) · `Allowlisted` (management floor, never enforced).
2. **A `decide()` seam between rule-fire and wire action** — rules must emit an *alert + confidence*
   (they already push a SOAR event header in `events.rs`), and a single `decide()` chooses the wire
   action. Today rule-fire *is* the wire action; the seam does not exist.
3. **The `Allowlisted` management-safety floor** — heqk has **no** operator/mgmt-path exemption, so
   an operator can self-lock-out. ADR 0022 D2's "the operator can never self-lock-out" invariant is
   currently unmet on heqk.
4. **The ADR-0018 confirmation signal** — `Quarantine` may only follow a confirmed handshake /
   conntrack-ESTABLISHED. heqk has neither a flow table nor a handshake tracker, so it *cannot
   honestly* reach a durable `Quarantine` — which is actually a **safety feature to preserve**: until
   confirmation exists, the highest heqk verdict for identity-keyed findings should be `RateLimit`,
   never a durable drop.

**This is the highest-value gap. Until the tri-state `decide()` exists, no `legit`-row can be
brought up honestly, because heqk's only tools are "ignore" or "drop the customer."**

---

## 4. Proposed M2 port sequence (ranked by matrix criticality)

The ordering is chosen so the 33-row matrix comes up **without ever introducing a regression that
drops legit traffic** — i.e. remove the 🔴 risks *before* adding detectors that would trip them.

**Phase M2.0 — Stop the bleeding (the two 🔴 rows). Highest priority.**
- **Port target #1 (recommended first): build the tri-state `decide()` / `decide_l2` seam** (§3).
  Introduce the 4-state verdict enum + the `Allowlisted` floor, and re-route `run_set` so a rule
  *fire* produces an alert that flows through `decide()`, whose **default is `Observe` (PASS on the
  wire)**. Only the four ADR-0023-D2 suspicion-free classes may escalate to a wire drop. This single
  change converts the whole plane from "fire = drop" to "fire = observe unless confirmed," which is
  what every `legit` row needs. Provable in QEMU (pure verdict logic over synthetic frames).
- **Port target #2: gate the IP-blocklist (L11/A11) behind corroboration.** `ip_blocked` must feed
  `decide()` as an `IntelOnly` signal, not an inline DROP; one uncorroborated hit → `Observe`, a
  corroborated/active hit → `RateLimit`/`Quarantine`. Removes the L11 🔴.
- **Port target #3: demote single-packet ARP_SPOOF (L3) to `Observe` by default.** Keep the
  structural malformed-ARP FrameDrop (F5/F9 — that's a *structural* fact), but the eth-src≠sender-mac
  *identity* finding must route to `Observe` (heqk has no cross-packet state to confirm a real
  spoof). Removes the L3 🔴.

**Phase M2.1 — L2 structural parity (mostly QEMU-provable, cheap single-frame rules).**
- Source-MAC multicast/broadcast check (F6), oversize-frame flag (F7), reconcile double-tag posture
  (F8). These are stateless structural rules that slot straight into the existing L2 corpus.
- mac-flood (A1/A2/L2) + broadcast-storm (A3/L1) **with their FP guards** (PortRole topology gate,
  mDNS/SSDP/LLMNR exemption) — requires per-source fan-out state (extend `ratelimit.rs`'s keyed
  table) and a port-role notion from the manifest. Verdicts: `RateLimit` on Access, `Observe` on
  Uplink.

**Phase M2.2 — Flow state (the conntrack-equivalent prerequisite).**
- Build heqk's flow table (extend `ratelimit.rs` into real per-flow state: count, per-src, an
  ESTABLISHED bit). This unlocks A4/A5 (distinct-port scan + confirmation → RateLimit/Quarantine),
  A7 (saturation %), and sources the ADR-0018 confirmation signal `decide()` needs. Distinct-dst-port
  scan counter (1000003) rides on this.

**Phase M2.3 — Resource-shed (needs a heqk-native pressure primitive; part QEMU, part metal).**
- L1 blanket conn-rate cap as a *self-reverting* meter (fix `syn_rate_over` semantics, cap =
  `DEFAULT_NEW_CONN_PPS`), L2 conntrack-saturation shed (rides M2.2's table), L3 **a heqk-native PSI
  equivalent** (expose scheduler/allocator pressure). A8/A7 top-talker shed.

**Phase M2.4 — L7 / observe-only detectors (detection parity, no enforcement).**
- Beacon (A10/L8), lateral (A10), exfil, DNS analytics — all `Observe`-only, so they carry **no
  legit-drop risk** and can land last. NTP-port allowlist ships with the beacon detector (L8).
- Host-EDR (1000100–115): **explicitly out of M2 scope** — architecturally N/A on heqk (§2); route
  to the off-device tier (ADR 0044 D3) and record the exclusion in the matrix, don't fake it.

### QEMU-provable vs needs heqk metal (Gate R)

| Provable in QEMU (synthetic frames through `packet::verdict` / `netq`) | Needs heqk **metal** (Gate R) |
|---|---|
| All frame-level rows F1–F11 (pure structural verdicts) | Resource-shed L3 (PSI) — needs real CPU/mem pressure under load |
| The tri-state `decide()`/`decide_l2` graduation logic (pure functions) | Conntrack-saturation A7 — needs a real flow table filling under real traffic |
| TCP flag-scan A6, ARP rules L3/F9/F10, blocklist L11/A11 verdicts | Self-revert TTL behaviour under wall-clock; sustained-flood timing A8 |
| mac-flood/bcast-storm detection + FP-guard verdicts (A1–A3, L1–L2) | **The end-to-end invariant: "a legit customer ALWAYS passes under real load"** — ADR 0023 line 238 requires the matrix pass on **heqk metal**, not just QEMU |
| Distinct-port scan counter A4/A5 verdict logic | CM5 NIC/EL0-driver datapath carrying it all at line rate |

Roughly **~24 of 33 rows** can be brought green in QEMU (all verdict logic + structural frames);
the remaining ~9 (resource-shed, confirmed-scan-under-load, and the whole-matrix under-load
end-to-end) are **Gate R metal** rows and must be labelled as such — QEMU-green is a necessary
milestone, not the M2 sign-off.

---

## 5. Cross-doc reconciliation flags (for product-steward)

- **Row count:** ADR 0023 D6 + `gate-ladder.sh:285` say "30 rows / 19 responder"; the live file has
  **22 responder rows → 33 total.** Update the ADR and the gate comment.
- **`LIFECYCLE.md` P7 vs `buildPlan.md` §5a drift** (Track-C standing flag): unchanged by this doc,
  but M2's "detection parity is release-blocking" claim should be reflected consistently in both.
- **ADR 0023 coupling note (line 236-238)** already scopes this correctly ("SOFT coupling; the
  tri-state verdict is portable Rust; mechanisms are replaced by heqk primitives; the matrix must
  pass on heqk metal → Phase M2"). This doc is the concretization of that one-liner.
</content>
</invoke>
