# heqk M4 — the control plane (network config, PQ-hybrid secure channel, enrollment, secure edge, segmentation authority)

> **Status: reconstructed 2026-09-11 from the authoritative in-tree sources.** The
> source of truth is the CODE + the `validate.sh` phase markers, not this prose;
> where they disagree the code wins. Canonical sources: `validate.sh` (the
> `[P18-*]`/`[P19-*]`/`[P20-*]`/`[P-m6-*]` phase descriptions), `kernel/src/`
> `{netcfg,securechannel,entropy,enroll,edge,segment,dnssink,export}.rs`,
> `boot-abi/src/verify.rs`, and `PRODUCTION_READINESS.md`. This file was cited by
> `securechannel.rs` (§2.3), `enroll.rs` (§M4.3), `entropy.rs` (§"M4.2b … tracked
> conditions"), `edge.rs` (§M4.4 / §7) and `PRODUCTION_READINESS.md` before it
> existed; it is reconstructed so those canon references resolve.

## 0. Principle — ADDITIVE, never a precondition (the air-gap invariant)

Every M4 layer is **additive**. An UNENROLLED / standalone / air-gapped device is a
VALID steady state: full local SOC, LAN up, WAN per local policy, **no account, no
boot-block, never bricked** (CLAUDE.md: "Standalone by default"). Enrollment, the
secure channel, export and segmentation authority only ever *add* behavior; their
absence removes nothing. `[P18-netcfg]`(d), `[P19-enroll]`(d), `[P19-edge]`(3),
`[P-m6-export]`(b) each prove this invariant explicitly.

## M4.1 — network CONFIG clients over smoltcp (`[P18-netcfg]`, `netcfg.rs`)

The first time heqk drives smoltcp UDP (not just ARP): (a) a smoltcp dhcpv4 socket
emits a well-formed DISCOVER through the **egress verdict gate**; (b) DNS query
builder/parser + SNTP request/parser round-trip **fail-closed** (truncated / wrong-id
/ wrong-mode → `None`); (c) the config **ingress gate** admits benign DHCP/DNS/NTP and
refuses a threat (UDP:4444); (d) no server ⇒ `resolve_or_fallback` returns a
static/last-known config and a **bounded** DHCP attempt terminates. Real RP1
GEM/RTL8111 datapath + real servers = metal (Gate R).

## §2.3 / M4.2a — PQC secure-channel PRIMITIVES + KATs (`[P19-pqc-kat]`, `securechannel.rs`)

**Framing-agnostic on purpose**: the ADR-0002 rustls-hybrid path and the ADR-0004
Noise path need the *identical* KEX + AEAD, brought in ONCE. No handshake here.
`no_std`, behind the `securechannel` feature (OFF by default — the base kernel TCB
pulls in none of it). (1) **ML-KEM-768** (FIPS 203, RustCrypto `ml-kem`) encaps/decaps
+ pinned KAT; (2) **X25519** (RFC 7748 §5.2 vector, `x25519-dalek`, serial backend on
aarch64 softfloat); (3) **ChaCha20-Poly1305** (RFC 8439 §2.8.2 vector, forged-tag
REJECT — no AES-NI dependence, right for a softfloat edge); (4) **hybrid KEX combiner**
= HKDF-combine (the existing `boot_abi::kdf`) of the ML-KEM ss with the X25519 ss into
ONE hybrid secret. All deterministic (fixed seeds) so QEMU-reproducible; the TRNG-fed
keygen entropy is M4.3 #6.

## M4.2b — the PQ-hybrid Noise HANDSHAKE (`[P19-noise]`)

**Noise, not rustls** (ADR 0004 HTP-v2 — the device↔control-plane channel is between
two of OUR endpoints). Pattern: an IK-analog
`Noise_HTP2hybrid_25519+MLKEM768_ChaChaPoly_SHA256`; **initiator = DEVICE**,
responder = control-plane whose static keys the device knows from enrollment. Each
es/ee is a HYBRID {X25519 DH + ML-KEM-768 encapsulation} folded via M4.2a
`hybrid_combine` before a single Noise `MixKey`. Noise rev-34
SymmetricState/CipherState/Split to spec (nonce = 4 zero bytes ‖ LE64(counter)),
KEM-in-Noise per PQNoise (ePrint 2022/539). **Device auth = an Ed25519 transcript
signature over `h`** (the PUF-anchored `attest_svc` key model — see
`heqk-signing-identity.md`). Proven in deterministic loopback: full handshake →
matching crossed transport keys; a rogue responder is rejected.

### M4.2b — security-auditor review: tracked conditions

The review's ranked conditions and where each closed (item numbers as cited in code):

| # | Condition | Status / where |
|---|-----------|----------------|
| 1 / **#6** | **Entropy** — the single most dangerous wiring surface: KATs pass identically for a seed or a TRNG, so a seeded path reaching metal = fleet-wide reused ephemerals. | CLOSED (`entropy.rs`, `[P19-enroll]`(a)): production `MetalEntropy<HwTrng>` FAILS CLOSED (boot-health-assert; absent TRNG → fill Err; stuck TRNG → rejected); NO seeded path can reach metal (`compile_error` refuses `securechannel-selftest`+`cm5`; ephemeral fields private, `from_entropy` the only production constructor). |
| **#7** | Fixed buffers — no per-handshake heap. | CLOSED (`[P19-enroll]`(b)): repeated handshakes + records grow the bump heap by 0 B. |
| **#8** | `CipherState::key_for_test` out of the metal profile. | CLOSED — gated behind `securechannel-selftest`. |
| **#3** | `ResponderStatic::from_seeds` metal-reachable; dalek zeroize. | from_seeds now selftest-only (`[P19-edge]`); dalek-zeroize **partial, tracked**. |
| **#9** | Anti-replay on the transport receiver. | CLOSED (`[P19-edge]`(1)): RFC 6479 sliding bitmap window (the WireGuard construction); replay/below-window rejected; a forged record fails AEAD and never advances the window (RFC 4303 §3.4.3 order). |
| **N1** | msg1-replay DoS (asymmetric crypto forced by a flood). | CLOSED (`[P19-edge]`(2)): load-triggered stateless cookie + token bucket BEFORE ML-KEM/Ed25519 work (WireGuard / DTLS-1.3 RFC 9147 §5.1); 256-deep flood rejected pre-crypto. **Gate-R metal item:** the cookie lacks epoch/source-address binding (`PRODUCTION_READINESS.md`). |
| **#4** | CBOM entry for `kem-0.3.0-pre`. | open, tracked. |
| **#10** | ML-DSA-65 co-signature on the channel. | open, tracked. |

## M4.3 — MSSP ENROLLMENT + authenticated update fetch (`[P19-enroll]`, `enroll.rs`)

Reuses, never reinvents: the M4.2b Noise channel as **TRANSPORT + mutual
authenticator** (device software-PUF Ed25519 ⟷ enrolled MSSP static; a rogue MSSP is
rejected); the M3.4 OTA state machine + **`boot_abi::verify` as the TRUST ROOT** for
any fetched image — *the channel authenticates the pipe, never the payload* (a
tampered or below-SVN-floor candidate delivered faithfully by the channel is still
REJECTED by `ota::verify`; a compromised MSSP cannot ship an image HBoot would
reject); the M3.2/M3.3 sealed record store to PERSIST the enrollment binding (proven
across two boots on one virtio-blk backing). Deterministic loopback + in-process fake
MSSP in QEMU; real mssp.hookprobe.com PKI + HW-TRNG + network = metal (Gate R).

## M4.4 — the SECURE-EDGE ENVELOPE (`[P19-edge]`, `edge.rs`) — ADR 0004's crown jewel

Closes the last two Noise-transport conditions (#9 anti-replay, N1 msg1-DoS — above)
and lands the **WAN-egress kill-switch** riding the M2 netq egress gate
(`packet::verdict`), fail-closed: an ENROLLED device whose tunnel is DOWN/COMPROMISED
has WAN-bound egress CUT (no plaintext leak) while LAN + local SOC + the PoP-reconnect
carve-out stay UP; a NEVER-ENROLLED / air-gapped device NEVER arms it. Armed only when
`Enrolled && tunnel != Up`; disarmed by default = zero datapath change.

## §7 — SCOPED, NOT BUILT: the SASE dataplane

`[P19-edge]` proves the kill-switch DECISION + the msg1 guard (QEMU). The rest of
ADR 0004 — **PBR (policy routing), NAT, and the encrypted TUN tunnel to the real
super-PoP at line rate** — is a larger follow-on the size of M2/M3 and needs metal
(Gate R). Honest scope: designed here, not implemented. The first concrete step in
flight (2026-09-11) is **M-AP-NAT** — routing/NAT of heqk's own WiFi-AP clients to an
uplink (see `heqk-p11-wifi-ap` in memory), the on-device half of "route LAN→WAN".

## M4.5 — SEGMENTATION AUTHORITY + the control-plane initiator

- **`[P19-seg-policy]`** — an operator-SIGNED reach-policy delivered over the enrolled
  Noise channel ARMS `segment.rs`'s per-device reach plane. **Trust separation
  (security-auditor C9): the channel authenticates the PIPE; the policy carries its
  OWN Ed25519 signature by a DEDICATED operator key (distinct from the Noise static),
  verified on-device before ANY table mutation** — a compromised always-online MSSP
  can only relay/withhold/replay operator-signed policies, never forge a
  customer-traffic-dropping one. Fail-closed serde; tampered sig / wrong key / stale
  generation (≤ floor) / tenant mismatch all reject with nothing armed.
- **`[P19-seg-policy-persist]`** — the TOFU-pinned operator key (C10) + the
  monotonic anti-rollback generation floor (C11) SURVIVE reboot in the M3 sealed
  store; a replayed lower-gen policy and a DIFFERENT operator key are refused
  across reboot (no silent key swap).
- **`[P20-reconcile]`** — the arming orchestrator `reconcile_reach_policy`: read
  persisted floor (C12 no-floor ⇒ no-arm) → TOFU-pin/read operator key → fetch over
  the Session → apply (verify sig + tenant + gen) → arm → persist floor. The QEMU half
  of the U2b gate; metal arming on the wire (armed 2026-09-09, `[SEGMETAL]`).
- **`[P19-controlplane]` + `[P19-noise-over-udp]`** — the on-device INITIATOR state
  machine over a smoltcp-FREE hand-framed UDP transport that rides the sensor's
  single GEM drain (RX tee) + single `gem::tx_frame` (the Linux-macb
  single-ring-owner discipline; no persistent smoltcp socket, no `no_std` lifetime
  hazard). msg1 (~2480 B: ML-KEM-768 ek 1184 + ct 1088) exceeds one 1514-MTU
  datagram → chunked into ≤1024-B datagrams `[total_len][offset]`, reassembled
  byte-identical; the reassembler is FAIL-CLOSED against 8 malformed-datagram
  classes (a reassembly-DoS surface closed). Noise AEAD still authenticates the
  reassembled bytes. The host MSSP-sim replying on the real wire = metal.

## M4 DNS sinkhole / RPZ (`[P20-dns-sink]`, `dnssink.rs`)

"Refuse a NAME, never a PACKET" — ADR 0023 applied to DNS. A query for a
policy-blocked domain (label-boundary subdomain match) gets a SINKHOLE A answer
(walled-garden IP); a benign name is never blocked (the packet path is never
dropped); a qname carrying a compression pointer (0xC0, illegal in a query) is
rejected fail-closed. Bounds-safe `no_std` parse; inline interception = metal.

## M6 — on-device evidence/telemetry EXPORT (`[P-m6-export]`, ADR 0044 D3 B2)

The CM5 is a PURE sensor/enforcer; Mission Control + HYDRA + tokio services are
OFF-DEVICE. A real M2 verdict is persisted as an RT_EVIDENCE record (M3 store) and
EXPORTED with the QSecBit score over the M4 enrolled channel to a consumer that
DECRYPTS + AUTHENTICATES it against the device fingerprint + tenant (the device is
the source of truth). UNENROLLED ⇒ `should_export=false`, evidence still persists
locally, local SOC unaffected. Enrolled-only: a rogue consumer fails the AEAD.

## Gate-R metal items (from `PRODUCTION_READINESS.md`)

- Endpoint objects are not reclaimed at runtime; the msg1 DoS cookie lacks
  epoch/source-address binding — both need a live network intake (Gate R).
- Everything above marked "metal" (real PKI, HW-TRNG on the wire, super-PoP tunnel,
  PBR/NAT/TUN dataplane) is scoped, not faked.
