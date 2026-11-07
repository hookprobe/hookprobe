# ADR 0049 — WAN policy authority, IPv6 source identity, and scan-establishment evidence

**Status:** ✅ **Accepted by the operator 2026-11-07, with the amendments below** (drafted 2026-11-07 from the
open design items of the 2026-11-06 peer reviews, `docs/design/heqk-peer-review-2026-11-06.md`). Clauses are tagged **[realized]**, **[partial]** or **[vision]** (the ADR 0043/0044 discipline).
(0048 is reserved for the BOI / Behavioural Genome ADR.)

## Context

Task #26 gave the heqk WAN an operator policy (`POLICY.TXT`: interface-attached prefix lists + ACLs, metric
routes) and IPv6 (PPPoE IPV6CP, DHCPv6 PD, a stateful LAN firewall). Two independent reviews closed every
finding that could be patched in place. Three cannot be patched without a design decision:

1. **`POLICY.TXT` is unsigned.** It sits on the FAT boot partition; anyone with the SD/eMMC (or a write
   primitive to p1) can rewrite the operator's ACLs. Today a malformed file fails safe (management locked,
   never half-applied) but a *well-formed* forged file is obeyed. CLAUDE.md: "Trust nothing unsigned".
2. **IPv6 sources have no identity in the source-keyed tiers.** Scan, connection-rate and resource-shed key
   on an IPv4 `u32` (`ratelimit.rs`, `verdict::DecideCtx::for_src`); IPv6 traffic is never counted. Hashing a
   v6 address into the `u32` space could land inside the management floor and silently allowlist an attacker.
3. **The scan-establishment hold is gameable.** Escalation is held off while `established × 8 >= distinct SYN
   ports`, where "established" counts ACK-bearing segments from the source. A scanner pads ~1 stray ACK per
   8 SYNs. A sound signal needs evidence that the *server* answered (a SYN-ACK), i.e. bidirectional flow state —
   and on the AP's NAT path the IDS sees outbound traffic pre-NAT and inbound pre-un-NAT, so the two
   directions do not share an address.

## Decision (proposed)

### D1 — `POLICY.TXT` is authorized by the OPERATOR key, not the boot key **[vision]**

- The authority is the **operator's own Ed25519 key** — the pattern already built for the segmentation
  reach-policy (independent operator signature distinct from the Noise static key, TOFU-pinned on first
  enrollment; `[P19-seg-policy]`, `enroll.rs`) — **not** the image boot key (the device vendor must not be
  able to rewrite a customer's firewall). **[partial]** (the mechanism exists for reach-policy).
- Artifact: `POLICY.SIG` beside `POLICY.TXT` = `sig(op_key, "HQPOL1" || generation u64 || sha256(POLICY.TXT))`;
  the device keeps a persisted **generation floor** (anti-rollback, the A/B keystore) and refuses an older
  generation. **[vision]**
- Device behaviour: no operator key pinned (standalone, never enrolled) → `POLICY.TXT` is accepted as today
  (standalone is a first-class mode; the owner holds physical custody). Operator key pinned → an unsigned,
  badly-signed or rolled-back file is **rejected** with the existing fail-safe (management locked,
  forwarding unchanged). **[vision]**
- Producer: the AEGIS reconciler emits and signs `POLICY.TXT` from intent (config is a generated artifact,
  CLAUDE.md decision #3); the operator never hand-edits it on a fleet device. **[vision]**

### D2 — IPv6 sources get their own identity space **[vision]**

- A source key becomes a tagged enum: `Src::V4(u32)` | `Src::V6Prefix64([u8; 8])` (the /64 — one SLAAC host
  rotates temporary IIDs inside it; keying on the full /128 lets it evade by rotating). The management floor
  is per-family (`mgmt_floor6=` alongside `mgmt_floor=`), so a v6 key can **never** fall inside the v4 floor.
- The slot tables in `ratelimit.rs` hash the tagged key; IPv4 behaviour is byte-identical.
- The ADR 0023 separation matrix gains v6 rows (legit busy v6 host never fires; v6 sweep confirmed) before
  any v6 enforcement is armed.

### D3 — Scan establishment requires server evidence **[vision]**

- "Established" for scan purposes = the source's port saw a **SYN-ACK from the destination** before the
  source's ACK, counted per distinct port (not per segment).
- Observation point: the decision is made where both directions share addresses — on the AP **inside** the
  NAT (outbound pre-SNAT + inbound post-un-NAT, i.e. the delivery-side verdict), and natively on the
  passive `prod-mc` sensor. A per-source 256-bit "answered" bitmap (port % 256) next to the SYN-port set.
- Until D3 lands, the current proportional hold stays (it raised evasion cost from 1 packet to ~1 per 8
  probes) **[realized]**, and the gap is listed in the peer-review doc.

## Operator amendments (2026-11-07) — these override the clauses above where they differ

- **D1:** the signature is verified **before** POLICY.TXT is parsed (the parser never sees unauthenticated
  bytes), and the generation counter is a persisted **anti-rollback** floor: an older signed policy is refused.
- **D2:** IPv6 source identity is keyed on the **device** (link-layer MAC, or the DHCPv6 DUID), not on the
  address, because privacy addresses rotate. *Engineering note (not in the operator's table):* a device key
  only exists for sources on our own links (Wi-Fi / eth1 clients). An attacker on the **internet** side of the
  WAN has no MAC or DUID we can see, so WAN-side IPv6 sources keep the `/64` key from D2 — the two key kinds are
  separate variants of the tagged source enum. **Design now, build later** (with the IPv6 work, gap 13).
- **D3:** a scan is counted **only** when the server's response was observed (SYN-ACK / RST from the target);
  one-sided or spoofed traffic never counts.

## D2 — detailed design (2026-11-07; build later, gap 13)

**Key type.** `ratelimit` and `verdict::DecideCtx` key on a tagged `SrcKey` instead of `u32`:

```rust
enum SrcKey { V4(u32), Dev(u64) /* LAN device: hash(MAC) or hash(DHCPv6 DUID) */, V6Net(u64) /* WAN: the /64 */ }
```
The slot index hashes the whole enum (tag included), so a v6 key can never alias a v4 address — and the
management floor (`verdict::is_allowlisted`) matches **only** `V4` (its own `mgmt_floor6=` list matches only
`V6Net`/`Dev` once IPv6 management exists, #10).

**Which key a frame gets** (decided where the frame enters, never from the packet alone):

| Ingress | IPv4 | IPv6 |
|---|---|---|
| Wi-Fi / eth1 (our LAN) | `V4(src)` | `Dev(hash(src MAC))` — the AP holds the station's MAC (and the SAVI binding table already ties each IPv6 to it); a station with a DHCPv6 DUID uses `hash(DUID)` |
| WAN | `V4(src)` | `V6Net(src >> 64)` — no MAC/DUID from the internet; the /64 is what one site controls |
| Passive sensor (prod-mc) | `V4(src)` | `Dev(hash(src MAC))` on the local segment; `V6Net` for routed sources (src MAC = the router) |

**Why not the /128.** Privacy addresses rotate per connection (RFC 8981); a /128 key would let one host
present a fresh identity per probe. `Dev` survives rotation on the LAN; `V6Net` bounds a WAN host to its /64.

**Enforcement.** Only after the ADR 0023 separation matrix gains IPv6 rows (legit busy host with rotating
temporaries never fires; v6 sweep with answers confirmed; one-sided v6 SYNs never counted — the D3 rule is
family-independent). Until then IPv6 sources are observe-only (today's behaviour).

## Consequences

- D1 closes "trust nothing unsigned" for the one operator-written artifact on the boot partition without
  coupling customer policy to the vendor key; standalone devices keep working with no account.
- D2 is a type change across the source-keyed tiers; it must ship with the v6 separation rows or not at all.
- D3 moves part of the scan logic to the delivery-side verdict on the AP; the QEMU separation tier needs a
  connect-scan-with-padding row and a legit P2P row before it is armed.
- None of D1–D3 changes the ADR 0023 rule: legitimate customer traffic always passes; policy drops stay
  distinct from threat verdicts.

## References

`docs/design/heqk-peer-review-2026-11-06.md` (SEC-M1, re-review M2/P1/P2), `hal/src/policy.rs`,
`kernel/src/ratelimit.rs`, `kernel/src/verdict.rs`, `kernel/src/enroll.rs` (`[P19-seg-policy]`), ADR 0023.
