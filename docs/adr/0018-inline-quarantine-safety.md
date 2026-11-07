# ADR 0018 — Inline quarantine safety: confirm before you drop

**Status:** ✅ Accepted (2026-07-05) — was 🟡 Proposed the same day; **corrected same day by a
VERIFY-pass re-audit** (Q2/Q5/Q6 below) then accepted: fully implemented + twice-audited (441+
workspace tests green) — implemented (`crates/hookprobe-manifest/src/scan_responder.rs`,
`modules/napse-capture/loader/src/{portscan.rs,dpi.rs,confirm.rs}`, `supervisor/src/main.rs`,
`modules/napse-quarantine/{bpf/quarantine.{h,bpf.c},loader/src/{state.rs,bpf.rs,main.rs}}`); 441
workspace tests green (debug + release, `--features hookprobe-supervisor/wasm`), up from the
393-test baseline (429 after the initial cut, 441 after the Q2/Q5/Q6 correction below); `cargo
clippy --workspace --all-targets --features hookprobe-supervisor/wasm` at 36 warnings (== recorded
baseline, 0 new), 0 errors; `builder/gate-ladder.sh --fast` green. The `quarantine.bpf.o` rebuild
was verified by clean `clang -target bpf` compilation on this dev box (x86_64); a verifier-load
smoke test (this device's own kernel BTF) could not run in this sandboxed session (no root/CAP_BPF)
— flagged as an open verification item, not a design gap. The Q2/Q5/Q6 correction below touched
NO `.bpf.c`/`.h` source (the loader-side `state.rs` fix is sufficient — see that section), so
`quarantine.bpf.o` was NOT rebuilt for this pass; its digest in `module.yaml` is unchanged.

## 2026-07-05 VERIFY-pass re-audit — Q2/Q5/Q6 correction

A same-day re-audit found the initial cut above **incomplete**: two of its own closure claims
(§"Default-safety decision", §"Residual, documented limitation") were **overstated**. This section
is the honest record; the two subsections below are corrected in place, not deleted, so the
history of what was claimed and what was actually true is visible.

- **Q2 (CRITICAL, reflected-DoS) — confirmation was keyed on IP alone, not `(IP, MAC)`.**
  `confirm::HandshakeTracker` kept its confirmed set as `HashSet<Ipv4Addr>` — a LAN victim `V`
  earned confirmation from **its own legitimate traffic** (V is the connection initiator on the
  mirror; V's own final ACKs marked `is_confirmed(V) = true`). An attacker on DIFFERENT hardware
  could then send ≥50 spoofed SYNs with `src = V` to distinct ports; `portscan.rs` fired
  `alert{src_ip=V}`; `napse-dpi.rs` stamped `confirmed = is_confirmed(V) = true` (the IP-only
  lookup could not tell the two apart); `scan_responder::decide` returned `Quarantine{V}`; the
  victim was dropped by IP. **No handshake forgery, no MAC forgery** — this defeated the
  confirmation gate entirely for any host with normal outbound traffic, on both wired and Wi-Fi
  LANs. Fixed by keying the confirmed set (and `is_confirmed`) on `(Ipv4Addr, [u8; 6])` — see the
  corrected D2/D5 discussion and `confirm.rs`'s module doc.
- **Q2 half 2 (CRITICAL) — LAN enforcement still populated the spoofable IP.** Even with (IP, MAC)
  confirmation, TWO enforcement writers still bound a LAN entry's bare `ip` into an enforced map:
  `scan_responder::render_element_ops` added the claimed ip to `quarantine_lan_ips` (nft) in
  addition to the mac to `quarantine_lan_macs`, and `napse-quarantine`'s `state::desired_keys`
  unconditionally inserted EVERY entry's ip into the Ring-0 BPF `quarantine_ips` map regardless of
  LAN/WAN classification. Either path meant that if a LAN entry for a borrowed/spoofed IP ever DID
  reach the quarantine state (e.g. via any future code path, or an operator-driven manual entry),
  it would still drop by IP. Fixed: LAN-plane enforcement (both nft and the Ring-0 BPF map) is now
  MAC-ONLY — `quarantine_lan_ips` is never populated by `render_element_ops`, and
  `state::desired_keys` never emits an IP key for a LAN-classified entry.
- **Q5 (evasion) — the WAN-ingress-martian check used the wrong "self" list.**
  `scan_responder::decide` called `is_wan_ingress_martian(ip, dst_ip, &policy.ips)` — passing the
  ENTIRE management/gateway/resolver ALLOWLIST as if it were "this device's own WAN address(es)".
  Since `policy.ips` legitimately contains the LAN gateway and DNS resolvers, a LAN attacker
  scanning THOSE addresses (`dst_ip ∈ policy.ips`, `src` classified LAN) satisfied
  `is_wan_ingress_martian` and was routed to `Observed` — never enforced. This let a LAN attacker
  evade detection for free by aiming at exactly the addresses this reflex most needs to protect.
  Fixed: `decide` now takes a DEDICATED `wan_self_ips: &[String]` parameter, built by the caller
  from the live WAN interface's own address(es) only (`scan_responder::parse_wan_self_ips`,
  `supervisor`'s `--wan-self-ip`/auto-detected via `ip -4 -o addr show dev <wan-iface>`) — never
  derived from or equal to `policy.ips`.
- **Q6 (MEDIUM) — the confirmed set had no TTL.** A `(ip, mac)` pair, once confirmed, stayed
  confirmed forever. Fixed: `HandshakeConfig::confirmed_ttl_secs` (default 600s/10 min,
  `NAPSE_CONFIRM_TTL_SECS`); `is_confirmed` takes the query time and treats a confirmation older
  than the TTL as absent.

See the corrected "Default-safety decision" and "Residual, documented limitation" sections below
for the honest closure statement, and this ADR's `## Files changed`/`## Verify` sections for the
Q2/Q5/Q6-specific diffs and tests.

**Deciders:** security-auditor (finding + re-audit), code-developer (author), os-architect, verification-engineer.
**Relates to:** [ADR 0005](0005-unified-ebpf-detection.md) (the tc-mirred mirror sink this fix's
confirmation gate reads; the WAN role-based fast-path SYN-rate limiter, a separate, already-correct
defense this ADR does not touch), [ADR 0009](0009-soc-brain-edge-cloud.md) (Ring-0 LPM/hash
enforcement precedent; the live 2026-07-03 finding `napse-quarantine` was built to fix), [ADR
0016](0016-artifact-hash-signing.md) (artifact-hash signing Fix C — `napse-quarantine`'s own
loader/`.bpf.o` self-verification, unchanged by this ADR and still gates before `bpf(2)`). Upholds
**"trust nothing unsigned"**'s sibling invariant this audit exposed as unenforced: *trust nothing
unconfirmed* — a single, spoofable packet must never be sufficient evidence to enforce against a
network address.

---

## Context — the reflex trusted a claim, not evidence

A 2026-07-03 live finding (documented in `modules/napse-quarantine`'s own module doc) drove the
Ring-0 `napse-quarantine` BPF fast-path: a real port scan from an iPhone outran the reactive
detect→nft-drop loop. Fixing *that* (line-rate enforcement) surfaced a second, more serious problem
a follow-on threat-model review found: the reactive loop's OWN trigger condition was unsafe by
construction.

The pipeline, as it shipped:

1. `napse_loader::portscan::PortScanTracker::observe` (the mirror-sink packet-layer detector, ADR
   0005) counts distinct destination ports reached by SYN-only packets **from a CLAIMED source IP**
   — no confirmation that the source exists, only that *something claiming to be it* sent 50 SYNs
   in 10 seconds.
2. `hookprobe_manifest::scan_responder::decide` quarantined **any** such claimed source not on the
   management allowlist — unconditionally, on that single, spoofable observation.
3. `supervisor/src/main.rs`'s LAN branch resolved the claimed IP's MAC via `ip neigh`/
   `/proc/net/arp` — i.e. asked the ARP table "who is this claimed IP", and bound the ANSWER (a
   real, possibly load-bearing device's real MAC) into the enforced quarantine set.

**The attack.** A WAN attacker sends ~50 spoofed SYNs with `src_ip` = this device's own gateway or
DNS resolver. Step 1 fires (fan-out threshold crossed on the claimed IP — the attacker never needs
a real socket). Step 2 quarantines that IP outright. On the LAN side, an on-link attacker spoofing
an innocent neighbor's IP gets that neighbor's REAL MAC resolved and L2-banned by step 3 — the
attacker never touches the victim's hardware at all. Both are single-packet-burst DoS primitives
against a device with no requirement to ever see a real connection.

## Decision

### D1 — Confirmation gating: no enforcement on unconfirmed evidence (CRITICAL)

A claimed source may only enter the **enforced** quarantine map after `napse_loader::confirm::
HandshakeTracker` observes it complete a REAL, validated TCP three-way handshake on the mirror:
SYN (seq=`isn_a`) → SYN-ACK (ack=`isn_a+1`, seq=`isn_b`) → final ACK (ack=`isn_b+1`, from the
claimed source). Handshake completion, not "any reply seen", is the signal, for a reason specific
to this architecture: the mirror sees **both directions** of every NIC (ADR 0005's `render_mirror`
tc-mirreds ingress AND egress to the same sink), so this device's own auto-generated SYN-ACK/RST
reply to an inbound spoofed SYN is ALSO on the mirror — "any bidirectional traffic" would confirm
literally every spoofed SYN this device answers, reproducing the bug one layer later. The one
packet an off-path spoofer can never produce is the validly-acknowledging final ACK: it never
receives the SYN-ACK (routed to the real owner of the spoofed address, not to the attacker), so it
cannot learn the ISN it must echo. This is the same principle SYN cookies rely on, applied
passively at the mirror.

`napse_loader::portscan::PortScanAlert` now carries a `confirmed` bit, stamped **at emission time**
from the independent `HandshakeTracker` (never a field the alert self-reports and the responder
trusts) and rendered at `SEVERITY_UNCONFIRMED` (LOW, 4) instead of `SEVERITY` (MEDIUM, 3) when
unconfirmed — **detection is never suppressed**, only enforcement weight is withheld.
`scan_responder::decide`'s FIRST gate: `!confirmed → ReflexVerdict::Observed` (logged, never
enforced). `supervisor/src/main.rs`'s per-alert loop only calls `reconcile_quarantine` (the ONLY
path that writes the persisted quarantine state / nft ops) for `Quarantine`/`Allowlisted` verdicts
— an `Observed` verdict never touches enforcement state at all: no add, no TTL refresh, no nft op.

**Honest limitation, not a bug:** a genuine SYN-only "stealth" scanner (`nmap -sS`) also never
completes a handshake (it RSTs after the SYN-ACK) and will never satisfy this gate either — it is
still detected/logged at LOW severity, just not auto-blocked. Auto-blocking a source on unconfirmed
evidence is exactly the unsafe behavior this ADR removes; a stronger network-layer signal (e.g. the
existing WAN-role SYN-rate limiter in `napse_detect.bpf.c`, ADR 0005, untouched by this fix) is the
right tool for stealth-scan containment, not this packet-mirror confirmation layer.

### D2 — Observed MAC, never resolved MAC (CRITICAL)

LAN quarantine is now keyed on the **Ethernet source MAC observed on the frame at detection time**
(`dpi::parse_tcp_obs`'s `src_mac`, threaded through `PortScanTracker`/`PortScanAlert::src_mac` into
`ScanAlert::src_mac`). `supervisor/src/main.rs` no longer calls `ip neigh`/reads `/proc/net/arp` for
this at all — the LAN branch's MAC is simply `alert.src_mac.clone()`. `scan_responder::resolve_mac`
(the ARP/neighbor-table lookup keyed on the CLAIMED IP) is kept as a pure helper — it has legitimate
non-enforcement uses (host-intel display) — but its doc comment now states plainly that it must
never key enforcement: resolving a spoofed claimed IP's MAC faithfully returns whatever the REAL
owner of that IP has, which is precisely the poisoned-lookup this ADR removes from the enforcement
path. WAN sources still have no MAC to bind (routed, `src_mac: None`) — unchanged, correct.

> **2026-07-05 correction note:** as originally written, D1+D2 together were read (including by
> this ADR's own now-corrected "Default-safety decision" section) as already closing the LAN
> reflected-DoS. They did not: D1's confirmation gate was keyed on IP ALONE (not `(IP, MAC)`), and
> LAN enforcement still bound BOTH the observed mac AND the claimed ip (`quarantine_lan_ips`), not
> mac-only. See "2026-07-05 VERIFY-pass re-audit — Q2/Q5/Q6 correction" near the top of this ADR
> for the actual fix (confirmation re-keyed on `(IP, MAC)`; LAN enforcement made MAC-only).

### D3 — Ifindex-scoped Ring-0 enforcement (HIGH)

`quarantine.bpf.c`'s two hash maps now hold `struct quarantine_val { ifindex; hits }` values
instead of a bare hit counter (`quarantine.h`). A match only drops the packet if
`skb->ingress_ifindex == entry.ifindex` — the plane the loader resolved for that entry via
`hookprobe_manifest::scan_responder::classify_source` (the SAME classification the nft rendering's
`iifname`-scoped rules already use — `state::desired_keys` now takes `PlaneIfindexes{lan, wan}` and
routes every entry, so the fast Ring-0 path can never enforce more broadly than the deterministic
nft path). `napse-quarantine`'s CLI moved from a generic `--iface` list to named `--lan-iface`/
`--wan-iface` (defaults `wlan0`/`end0`, matching `scan_responder::IfaceConfig`) so the loader knows
which resolved ifindex is which plane. A WAN-classified entry still never contributes a MAC key
(mirrors the nft convention — a routed WAN source's observed MAC is always the upstream router's,
never meaningful to bind).

### D4 — WAN martian/anti-spoof + live-upstream protection (HIGH)

Two complementary checks close "spoof the device's own gateway/resolver":

- **`scan_responder::is_wan_ingress_martian(src_ip, dst_ip, wan_self_ips)`** — if the alert's
  TARGET (`dst_ip`) is one of this device's own WAN-side addresses, the packet necessarily arrived
  via the WAN interface; if the claimed SOURCE is simultaneously private/reserved/loopback/CGNAT
  (`classify_source(src_ip) == Lan || is_bogon_v4(src_ip)`), that is definitive proof of spoofing or
  gross misrouting — no real internet host can have that address. `decide`'s SECOND gate (after
  confirmation) routes this to `Observed`, unconditionally. This is deliberately an ingress-FACT
  check (`dst_ip` is what makes it "WAN"), not a pure `classify_source(src_ip)` check — that
  function correctly calls an RFC1918 address "Lan" wherever it appears (LAN clients ARE RFC1918)
  and is the wrong tool for "is this specific pairing physically possible".
- **Live-upstream auto-protect** — `supervisor`'s scan-respond startup resolves the WAN default
  gateway (`ip route show default`, parsed by `scan_responder::parse_default_gateway`) and
  configured DNS resolvers (`/etc/resolv.conf`, `parse_resolv_conf_nameservers`) ONCE and folds them
  into `ProtectPolicy::ips` — the concrete fix for "spoof exactly the gateway/resolver address and
  trigger self-quarantine of this device's own upstream". `--no-auto-protect-upstream` opts out
  (documented escape hatch); `--gateway-route-file`/`--resolv-conf` let a test/dev box supply
  fixtures instead of shelling out.

### D5 — Allowlist bound to (MAC + interface), not the spoofable IP alone (HIGH)

`ProtectPolicy` gained `lan_macs: Vec<String>` (`--protect-mac`, repeatable). Once configured
non-empty, `protect_reason` requires a LAN-classified protected IP's OBSERVED mac (D2) to be in
`lan_macs` — an on-link impostor spoofing the gateway's IP from a different hardware address is NOT
exempted (falls through to normal quarantine evaluation instead of inheriting the gateway's
allowlist entry). Left empty by default: **backward compatible** (today's IP-only matching,
unchanged) until an operator configures the real binding; a WAN source is never MAC-bound (no L2
address to bind regardless of `lan_macs`).

### D6 — TTL/hold semantics (MEDIUM)

- **Unconfirmed re-observation cannot refresh TTL** — structurally guaranteed by D1: an `Observed`
  verdict never reaches `reconcile_quarantine`, the only function that reads/writes `last_seen`.
- **Escalating hold for confirmed repeat offenders** — `QuarantineEntry` gained `offenses: u32`
  (default 1), incremented on every confirmed re-observation of an already-quarantined source.
  `effective_ttl_secs(base, offenses) = base × clamp(offenses, 1, 6)` — capped growth (max 6× base),
  applied both to the TTL sweep's expiry check and the nft element's rendered `timeout`. An attacker
  cannot reset this by pausing (offenses persist across TTL windows); it cannot grow unbounded
  either.
- **Bounded enforced set** — `reconcile_quarantine` now takes `max_entries`
  (`DEFAULT_MAX_QUARANTINE_ENTRIES = 4096`); over capacity, the oldest-`last_seen` entries are
  evicted first. Every entry reaching this function is already CONFIRMED by construction (D1), so
  "prefer confirmed over unconfirmed" is moot — eviction simply prefers the most recently active
  offender.
- The per-alert `ip neigh`/`/proc/net/arp` fork D2 removed is not replaced with a cached read —
  there is no more per-alert MAC-resolution I/O at all (the observed MAC arrives with the alert).

## Default-safety decision — WAN attach stays on, LAN-plane confirmation is the load-bearing fix

**CORRECTED 2026-07-05 (VERIFY-pass re-audit)** — the original text of this section (below,
preserved for the record with the false claim struck through) said: ~~"With D1 landed, a spoofed
burst — WAN or LAN — cannot populate the enforced map regardless of which plane it targets"~~. That
was **not true as shipped**: D1 keyed confirmation on IP alone (Q2), so a victim's own innocent
traffic could vouch for an attacker spoofing its IP, and even a correctly-confirmed LAN entry's
bare IP was still written into the enforced map by two separate writers (Q2 half 2). The honest
statement:

- **The LAN reflected-DoS is closed by `(IP, MAC)` confirmation + LAN-MAC-only enforcement** (the
  Q2 fix above): a claimed source is only confirmed together with the OBSERVED L2 address that
  earned it, and LAN-plane enforcement (both nft and the Ring-0 BPF map) drops ONLY that observed
  MAC — never the claimed IP. An attacker must transmit frames bearing (or forging, on
  MFP/802.1X-less Wi-Fi — see the residual section below) its own hardware address to ever be
  enforced; it can no longer borrow a victim's IP-only confirmation or have its entry rendered
  IP-keyed.
- **The WAN residual is real and NOT closed by this ADR** — see the new residual bullet below: an
  external client of a port-forwarded/exposed service legitimately completes an inbound handshake
  from the WAN, becomes `confirmed`, and (having no L2 address to bind — routed traffic) is
  enforced by IP on the WAN plane. That IP is spoofable by a third party once it's known
  (e.g. observed scanning, or simply the exposed service's regular client), producing a WAN-side
  IP-quarantine of an address that isn't actually attacking. This is a genuine, documented
  limitation of IP-only WAN enforcement, not a closed gap.
- **DHCP-supplied-resolver trust** — `supervisor`'s auto-protect reads `/etc/resolv.conf`, which
  on a DHCP-configured uplink is itself attacker-influenceable by anyone who can act as (or spoof)
  the DHCP server on that segment; an attacker controlling DHCP could add an address of their
  choosing to the protect/allowlist. Documented here as a known, narrow trust dependency (DHCP
  itself is unauthenticated by design on most networks), not something this ADR's scope claims to
  fix.

Given the above, **WAN attach for `napse-quarantine` remains the default** (unchanged from before
this ADR) — the Q2 fix removes the risk that would have justified defaulting it to opt-in for the
LAN plane; the WAN plane's residual (above) is a narrower, IP-only-enforcement limitation shared
with any router-level quarantine, not a reflected-DoS primitive against an arbitrary third party.
`napse-quarantine`'s existing capability gate (`ddos_mitigation`, manifest-driven, unchanged)
remains the mechanism for a platform to disable Ring-0 enforcement entirely if desired.

## Residual, documented limitation

On-link 802.11 offers no L2 source authenticity without Management Frame Protection (802.11w) or
802.1X port-based authentication. The Q2 fix (observed-`(IP,MAC)`-keyed confirmation +
LAN-MAC-only enforcement) makes on-link victim-quarantine-by-borrowed-IP **structurally
impossible**, not merely "reducible" — an attacker's spoofed-IP SYNs are evaluated against
`is_confirmed(claimed_ip, attacker's_own_observed_mac)`, which can only be true if THAT pair
completed a real handshake; borrowing a victim's IP alone never satisfies it, and even a validly
CONFIRMED LAN entry now enforces by mac only (never populating the ip set/map). What remains
open, honestly:

1. **L2 frame-address forgery (not IP spoofing) on MFP/802.1X-less Wi-Fi.** An attacker who can
   transmit raw 802.11 frames can still forge an arbitrary SOURCE MAC at L2 and complete a real
   TCP handshake using that forged MAC — i.e. they can make `(some_ip, forged_mac)` legitimately
   confirmed and then be enforced (correctly) against `forged_mac`, but if `forged_mac` happens to
   collide with a real neighbor's hardware address, that neighbor is still implicated. This is a
   known, layer-appropriate limitation of `napse-quarantine`'s TC-bpf-at-clsact-ingress placement —
   closing it fully needs 802.11 link-layer authentication (MFP/802.1X), out of scope for a
   network-layer quarantine responder.
2. **WAN-side IP-only enforcement (see the Default-safety section above).** A confirmed WAN
   source is enforced by IP alone (no L2 address on a routed path) — a legitimate client of an
   exposed/port-forwarded service, once confirmed, is enforceable by IP, and that IP is exactly as
   spoofable to a third party as any internet-routable address. This is a real, undeferred
   residual: it is not closed by this ADR, and no compensating control beyond the existing
   martian/allowlist checks is implemented yet. A future fix (e.g. binding WAN quarantine to a
   flow 5-tuple + a short corroboration window instead of the bare IP) is a documented follow-up,
   not something this ADR claims to have already done.
3. **DHCP-supplied-resolver trust** — see the Default-safety section above.

## Files changed

- `modules/napse-capture/loader/src/dpi.rs` — `parse_l4`/`L4` gained `src_mac`, `seq`, `ack_num`;
  new `TcpObs`/`parse_tcp_obs` (kept `TcpSyn`/`parse_tcp_syn` for compatibility). +8 tests.
- `modules/napse-capture/loader/src/confirm.rs` — **new**: `HandshakeTracker`/`HandshakeConfig`,
  bounded (FIFO-evicted half-open flows + confirmed set). 8 tests.
- `modules/napse-capture/loader/src/portscan.rs` — `observe` gains `src_mac`; `PortScanAlert` gains
  `src_mac`, `SEVERITY_UNCONFIRMED`; `to_json(confirmed: bool)`. Net +5 tests.
- `modules/napse-capture/loader/src/bin/napse-dpi.rs` — feeds `HandshakeTracker` every TCP packet
  (both directions) alongside `PortScanTracker`; stamps `confirmed` at emission.
- `modules/napse-capture/loader/src/lib.rs` — registers `confirm`.
- `crates/hookprobe-manifest/src/scan_responder.rs` — `ScanAlert` gains `confirmed`/`src_mac`
  (`#[serde(default)]`, fail-closed); `ProtectPolicy` gains `lan_macs`; `protect_reason` MAC-bound
  for LAN; new `is_wan_ingress_martian`, `parse_default_gateway`, `parse_resolv_conf_nameservers`;
  `ReflexVerdict::Observed`; `decide` re-gated (martian → unconfirmed → allowlist → quarantine);
  `QuarantineEntry.offenses` + `effective_ttl_secs`; `reconcile_quarantine` gains `max_entries`
  (`DEFAULT_MAX_QUARANTINE_ENTRIES`) + escalated TTL sweep; `resolve_mac` doc-warned. 27 new/changed
  tests (54 total in this module, up from 27).
- `supervisor/src/main.rs` — removed `--neigh-file`/`--arp-table`; LAN MAC now `alert.src_mac`;
  auto-protects the resolved WAN gateway + DNS resolvers at startup (`--no-auto-protect-upstream`,
  `--gateway-route-file`, `--resolv-conf`); `--protect-mac`; `Observed` verdicts skip
  `reconcile_quarantine`/nft entirely.
- `modules/napse-quarantine/bpf/quarantine.h` — `struct quarantine_val { ifindex; hits }`.
- `modules/napse-quarantine/bpf/quarantine.bpf.c` — map value type change; `skb->ingress_ifindex`
  check before `TC_ACT_SHOT`.
- `modules/napse-quarantine/loader/src/state.rs` — `desired_keys` takes `PlaneIfindexes`, keys map
  to `(key, ifindex)`; `diff` over `BTreeMap`. 6 new/changed tests.
- `modules/napse-quarantine/loader/src/bpf.rs` — `encode_value`/`decode_value`; `run`/
  `reconcile_once`/`status` thread ifindexes; named `lan_iface`/`wan_iface`.
- `modules/napse-quarantine/loader/src/main.rs` — `Args` gains `lan_iface`/`wan_iface` (replaces
  the generic `--iface` list); non-bpf fallback path updated.

### 2026-07-05 VERIFY-pass re-audit correction — additional files changed (Q2/Q5/Q6)

No `.bpf.c`/`.h` source changed in this pass — the fix is entirely in the loader/reconciler layer;
`quarantine.bpf.o` was NOT rebuilt and its `module.yaml` digest is unchanged.

- `modules/napse-capture/loader/src/confirm.rs` — confirmed set re-keyed `HashSet<Ipv4Addr>` →
  `HashMap<(Ipv4Addr, [u8; 6]), f64>` (last-confirmed timestamp); `is_confirmed(ip, mac, now)` and
  `observe(..., src_mac)` both gained the mac parameter (Q2); `HandshakeConfig` gained
  `confirmed_ttl_secs` (default 600s, `DEFAULT_CONFIRMED_TTL_SECS`) and `is_confirmed` checks
  recency (Q6). Net +3 tests (11 total, up from 8).
- `modules/napse-capture/loader/src/bin/napse-dpi.rs` — threads `obs.src_mac` into
  `handshakes.observe`; stamps `confirmed` from `alert.src_mac.map(|m| handshakes.is_confirmed(ip,
  m, now)).unwrap_or(false)` (fails closed on a missing mac); `handshake_config_from_env` reads
  `NAPSE_CONFIRM_TTL_SECS`.
- `crates/hookprobe-manifest/src/scan_responder.rs` — `decide` gains a `wan_self_ips: &[String]`
  parameter, used for `is_wan_ingress_martian` INSTEAD OF `policy.ips` (Q5); new
  `parse_wan_self_ips` (parses `ip -4 -o addr show dev <iface>` output); `render_element_ops`'s LAN
  branch no longer emits any `quarantine_lan_ips` element (add OR delete) — LAN enforcement is
  MAC-only, a mac-less LAN entry is simply not enforced (Q2 half 2); `render_bootstrap`'s doc
  comment corrected to say so. Net +12 tests (66 total in this module, up from 54).
- `supervisor/src/main.rs` — new `--wan-self-ip` (repeatable exact override) / `--wan-addr-file`
  (fixture) CLI args; resolves `wan_self_ips` once at startup (auto via `ip -4 -o addr show dev
  <wan-iface>` unless overridden) and threads it into the `sr::decide` call, separate from
  `protect.ips`.
- `modules/napse-quarantine/loader/src/state.rs` — `desired_keys` no longer inserts an IP key for
  a LAN-classified entry AT ALL (only its mac, if resolved) — the fix for the Ring-0 BPF map's
  half of Q2 half 2 (`d.ips.insert` used to run unconditionally for every entry regardless of
  plane). Net +1 test (12 total in this file, up from 11 — one test replaced by a strengthened
  version, one new test added).

## Verify

- (a) spoofed-victim single-SYN-burst does NOT quarantine the victim —
  `confirm::tests::a_bare_syn_burst_never_confirms`,
  `scan_responder::tests::decide_never_quarantines_an_unconfirmed_scanner`.
- (b) a completed-handshake source IS quarantined —
  `confirm::tests::a_completed_handshake_confirms_the_source`,
  `scan_responder::tests::decide_quarantines_once_confirmed`.
- (c) mgmt-src spoof does not evade AND a WAN-side RFC1918-src drops as martian —
  `scan_responder::tests::decide_mgmt_spoof_from_wrong_mac_does_not_evade_enforcement_once_confirmed`,
  `decide_drops_a_wan_side_rfc1918_source_as_martian`,
  `wan_ingress_martian_flags_a_private_source_reaching_this_devices_own_wan_ip`.
- (d) quarantine keys on observed MAC, never the ARP-resolved claimed-IP MAC —
  `portscan::tests::observe_captures_the_last_observed_src_mac`,
  `dpi::tests::parse_tcp_obs_extracts_the_observed_src_mac_never_a_resolved_one`, plus
  `resolve_mac`'s doc comment + its removal from `supervisor/src/main.rs`'s enforcement path.
- (e) a LAN-plane entry does NOT fire on the WAN ifindex —
  `state::tests::desired_keys_routes_lan_and_wan_entries_to_their_own_ifindex`,
  `desired_keys_never_emits_a_mac_key_for_a_wan_entry`, plus `quarantine.bpf.c`'s
  `mhit->ifindex == skb->ingress_ifindex` check.
- (f) unconfirmed re-observation does NOT refresh TTL —
  `scan_responder::tests::reconcile_quarantine_is_never_invoked_for_an_unconfirmed_verdict`
  (structural: `main.rs` only calls `reconcile_quarantine` for `Quarantine`/`Allowlisted`).

`cargo test --workspace --features hookprobe-supervisor/wasm` — **429 passed, 0 failed** (debug
and `--release`), up from the 393-test baseline. `cargo clippy --workspace --all-targets --features
hookprobe-supervisor/wasm` — **36 warnings (== recorded baseline), 0 errors**. `quarantine.bpf.o`
recompiled cleanly (`clang -O2 -target bpf -D__TARGET_ARCH_x86`, host arch); `cargo build/test -p
napse-quarantine --features bpf` also green (libbpf-rs vendored build succeeds in this environment).
A verifier-load smoke test against this box's live kernel BTF could not run (no root/CAP_BPF in this
sandboxed session) — the aarch64 per-device build+load this module's README documents for the
original cut is the pattern to re-run on real hardware before the next release. `builder/gate-ladder.sh
--fast` — all requested gates PASS (0.1 fmt SKIPped — rustfmt not installed; 0.5 ui-build SKIPped —
no npm in this box; both pre-existing environment limits, not new).

### 2026-07-05 VERIFY-pass re-audit correction — additional verify (Q2/Q5/Q6)

- (a) a spoofed `src=V` fan-out from a DIFFERENT mac than V's does NOT quarantine V (becomes
  `Observed`) —
  `confirm::tests::confirming_via_one_mac_does_not_confirm_the_same_ip_from_a_different_mac`
  (the core Q2 unit proof: `V`'s real `(V, V_mac)` handshake does not confirm `(V, attacker_mac)`).
- (b) a real host that completes a handshake AND scans from its own `(IP, MAC)` IS still
  quarantined — `confirm::tests::a_completed_handshake_confirms_the_source`,
  `confirm::tests::confirming_one_flow_confirms_the_whole_source`,
  `scan_responder::tests::decide_quarantines_once_confirmed`.
- (c) LAN enforcement inserts only the attacker's mac, never the spoofed victim IP —
  `scan_responder::tests::element_ops_routes_lan_entry_to_mac_only_never_the_spoofable_ip`,
  `scan_responder::tests::element_ops_lan_entry_without_a_mac_is_not_enforced_on_either_set`,
  `scan_responder::tests::element_ops_lan_removal_deletes_the_mac_element_only`,
  `state::tests::desired_keys_never_emits_an_ip_key_for_a_lan_entry_mac_only`,
  `state::tests::desired_keys_skips_a_lan_entry_with_no_resolved_mac_entirely`.
- (d) a LAN attacker scanning the gateway/resolver IS now enforced (Q5) —
  `scan_responder::tests::decide_lan_attacker_scanning_the_gateway_is_no_longer_evasively_marked_martian`,
  `scan_responder::tests::decide_lan_attacker_scanning_a_protected_resolver_is_also_no_longer_evasively_martian`.
- (e) confirmation expires after its TTL (Q6) —
  `confirm::tests::confirmation_expires_after_its_ttl`,
  `confirm::tests::confirmation_refreshes_on_repeat_handshake_before_expiry`.

`cargo test --workspace --features hookprobe-supervisor/wasm` — **441 passed, 0 failed** (both
debug and `--release`), up from the 429-test post-initial-cut baseline. Per-file test counts as
measured after this correction: `napse-loader`'s `confirm` module 11 (was 8), `hookprobe-manifest`'s
`scan_responder` module 66 (was 54), `napse-quarantine`'s `state` module 12 (was 11) — some of the
delta is new tests, some is an existing test strengthened/renamed in place rather than added (see
"Files changed" above for what changed in each). `cargo clippy --workspace --all-targets --features
hookprobe-supervisor/wasm` (JSON message-format count) — **36 warnings (== recorded baseline, 0
new), 0 errors**. `cargo test -p napse-quarantine --features bpf` — 15 passed, 0 failed (unchanged
count; no `.bpf.c`/`.h` touched this pass, so `quarantine.bpf.o` was NOT rebuilt and its
`module.yaml` digest is unchanged). `builder/gate-ladder.sh --fast` — result recorded below.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: SOFT (with HARD enforcement).** The `(IP,MAC)`-confirmed `scan_responder` "confirm before drop" logic is portable Rust; the ifindex-scoped TC-bpf drop + nft + conntrack enforcement is re-implemented on heqk's verdict path. "Trust nothing unconfirmed" survives. → **Phase M2**.
