# heqk control-plane connectivity — Track C / Milestone M4 scoping

> **Honesty header (read first).**
> - **PQC-TLS is a MAJOR NEW BUILD, not an integration.** ADR 0002 §3 records the plain truth
>   this doc confirms in the tree: *"no TLS/rustls stack exists in this tree yet"* and `tls_kex`
>   / `tls_auth` are **Roadmap**. M4.2 is the single largest new piece of Track C to date.
> - **There is NO key-exchange primitive anywhere in heqk.** The `no_std` crypto present is
>   **signatures + symmetric only** (Ed25519, SLH-DSA, SHA-256, HMAC, HKDF, a SHA-256-CTR
>   keystream). **No ML-KEM (FIPS 203), no Kyber, no X25519, no ECDH, no P-256** — and **no
>   standard AEAD** (no AES-GCM, no ChaCha20-Poly1305). A hybrid PQC KEX has to be brought in
>   as **new `no_std` crates**; it cannot be assembled from what is here.
> - **The standalone / air-gapped invariant is SACRED (CLAUDE.md core invariant).** Everything in
>   M4 is **ADDITIVE**. A device with zero network runs a full local SOC — detect, enforce,
>   self-heal, persist, roll back — with **no account, no DHCP lease, no control plane, no TLS**.
>   M4 must never introduce a code path where connectivity is a precondition for local function.
> - **Real network = metal.** Stack logic, client state machines, the TLS/handshake crypto, and
>   the enrollment protocol are QEMU/host-provable. The real NIC datapath at line rate, a real
>   DHCP/DNS server, a real MSSP endpoint, EL0-isolation of the net service, and real-network
>   timing are **Gate R (CM5 silicon + a real network)**.
> - **Docs-ahead-of-kernel (Track-C standing caveat):** this is a SCOPING doc. M4 is `⬜ (no
>   TCP/TLS today)` in `docs/BuildPlan.md` Track C. Nothing below is built yet except the smoltcp
>   ARP selftest (`PH6-net`, behind the `netsvc` feature, OFF by default).

**Milestone:** Track C / **M4 — Control-plane connectivity.**
**Predecessors (done, QEMU-green):** M1 (substrate + hybrid boot signing), M2 (detection,
`packet::verdict` rule plane), M3 (persistence + on-device A/B OTA — the **`pull` transport is
explicitly M4's job**, `kernel/src/ota.rs` §"The pull source").
**Canon:** ADR 0002 (crypto/PQC posture), ADR 0004 (secure-edge envelope — HTP-evolved,
kill-switch/PBR/NAT/TUN), ADR 0009 (edge/cloud split), ADR 0043/0044 (heqk substrate),
`docs/design/heqk-persistence.md` (M3.4 OTA), `docs/BuildPlan.md` Track C M4 row.
**Author:** os-architect. **Deciders (build-time):** os-architect / security-auditor.

---

## 1. What heqk's net stack has TODAY (and what it does not)

heqk already has a real, verified TCP/IP-capable path — **PH6net** — with a genuinely
strong security property. It does **not** yet have a single network client (DHCP/DNS/NTP),
any TLS, or any enrollment.

### 1.1 The layers that exist

| Layer | File | Trust domain | Status |
|---|---|---|---|
| **Frame parser** (Ethernet→VLAN→IPv4/IPv6→TCP/UDP, bounds-safe, no `unsafe`) | `kernel/src/net.rs` | **EL1 / TCB** | ✅ built, host-unit-tested. Feeds the rule plane. |
| **Signed rule plane** (`packet::verdict` → PASS/DROP, port + verdict) | `kernel/src/packet.rs` (+ `rules.rs`, `verdict.rs`) | **EL1 / TCB** | ✅ M2 — the IDS/IPS enforcement point. |
| **P17 net-class queue** (`rx_publish` / `tx_drain`, per-slot ownership, dual-gate) | `kernel/src/netq.rs` | **EL1↔EL0 boundary** | ✅ ABI built. The kernel-side gate is done; the EL0 consumer that rides it on metal is the follow-up. |
| **PH6 smoltcp integration** (`RuleGatedDev` `phy::Device`, ARP selftest) | `kernel/src/netsvc.rs` (`#[cfg(feature = "netsvc")]`) | *designed EL0*, runs in-image today | 🟡 QEMU/host selftest only (`smoltcp` 0.13, `no_std`). Feature OFF by default. |
| **virtio-net** (QEMU transport) | `arch-aarch64/src/virtio.rs` | EL1 | ✅ QEMU datapath. |
| **RP1 GEM (`end0`) real NIC** | `RP1_GEM_BRINGUP.md` | EL1 (isolate to EL0 later) | 📋 designed (polled RX), **not implemented**. |
| **RTL8111 (`eth1`) 2nd NIC** | `RP1_ETH2_RTL8111.md` | EL1 | 📋 designed; gated behind BCM2712 **PCIe RC1 training** (the real cost). |
| **Device-class transport (sDDF-borrow, untrusted-driver hardening)** | `DEVICE_CLASS_TRANSPORT.md` | EL1↔EL0 | 📋 designed, not implemented. |

### 1.2 The security property (why this shape, and why it must survive M4)

**PH6net puts smoltcp ABOVE the rule plane, never beside it** (`netsvc.rs` header,
`OVERLAY_CONVERGENCE.md` §A3.3). A frame is admitted to the userspace stack **only if
`packet::verdict` PASSes it** (`RuleGatedDev::ingress` / `netq::rx_publish`), and any frame
the stack emits is put on the wire **only if it PASSes again** (`TxTok::consume` /
`netq::tx_drain`). Consequences that M4 inherits as hard constraints:
- A smoltcp parser bug is **unreachable** by traffic the rules reject — a DROP frame never
  enters the ring.
- A **fully compromised IP stack still cannot emit** a frame the signed rules reject: no C2
  beacon, no spoofed ARP, no scan pattern, no covert exfil. The stack is a *client* of the
  IPS, never a bypass. **This is the whole reason the stack can be EL0-isolated and untrusted.**
- The netq ABI is deliberately **per-slot ownership, not head/tail** — there is no EL0-writable
  index the kernel would trust (`netq.rs` header, audit M-7). `len` is clamped, never used to
  index. **Any M4 socket/TLS code that grows the EL0 surface must keep this discipline.**

### 1.3 What it does NOT have (the M4 gap)

- **No exercised TCP.** The only thing PH6net does today is answer **one ARP** for its own IP
  (`netsvc_selftest`), plus a negative case proving the gate DROPs a UDP:4444 threat. **No TCP
  connection has ever been opened** — smoltcp *can* do TCP; heqk has never driven it.
- **No DHCP client** — the IP is hardcoded (`192.0.2.1/24`) in the selftest.
- **No DNS client / resolver** — `docs/BuildPlan.md` marks the sinkhole/RPZ line `⬜ no resolver`.
- **No NTP / time-sync client** — the kernel has `CNTPCT_EL0` monotonic ticks only; no wall clock.
- **No TLS of any kind** (see §2).
- **No enrollment / control-plane / MSSP client, no HTTP(S) fetch** — the M3.4 OTA `pull` is a
  stub source (`ota.rs`: *"real network fetch from the registry / control plane is M4"*).
- **No real NIC on metal** — QEMU virtio-net works; RP1 GEM is designed-not-built; the EL0-isolated
  netq service + TRNG seed + PCR3 measurement is the deferred metal half (`netsvc.rs` header).

---

## 2. The PQC crypto reality — the load-bearing scoping question

**This section decides how much of PQC-TLS is assemblable vs must be built.** The answer is:
**auth is half-present; the KEX and the AEAD are entirely absent.**

### 2.1 What the `no_std` crypto actually provides

| Primitive | Where | Class | TLS-usable as… |
|---|---|---|---|
| **Ed25519** (`ed25519-compact` 2, `no_std`) | `boot-abi/src/verify.rs` | classical **signature** | a classical **auth** leg |
| **SLH-DSA-SHA2-128s/f** (`fips205` 0.4, FIPS 205, `no_std`) | `boot-abi/src/verify.rs`, `seal.rs` refs | **PQ signature** (stateless hash-based) | a PQ **auth** leg |
| **SHA-256** (incremental `Hasher` + `digest`) | `boot-abi/src/sha256.rs` | hash | TLS transcript hash / HKDF core ✅ |
| **HMAC-SHA256** | `boot-abi/src/kdf.rs` | MAC | HKDF PRF / Finished MAC ✅ |
| **HKDF-Extract / Expand** | `boot-abi/src/kdf.rs` | KDF | TLS 1.3 key schedule ✅ |
| **SHA-256-CTR keystream** (`ctr_xor_nonce`: block = `SHA256(key‖nonce‖ctr)`) | `boot-abi/src/kdf.rs` | stream cipher | confidentiality, but **NOT a standard AEAD** |
| **Encrypt-then-MAC AEAD** (CTR + HMAC, `HQKSEAL1`) | `kernel/src/seal.rs` | AEAD-equivalent | works for a *custom* channel, **not** a TLS 1.3 cipher suite |
| **Constant-time compare** (`ct_eq`) | `boot-abi/src/kdf.rs` | util | ✅ |

### 2.2 What PQC-TLS needs — and what is missing

A TLS 1.3-class hybrid-PQC handshake (the ADR 0002 `tls_kex = ml-kem-768+x25519`,
`tls_auth = ml-dsa-65+ecdsa-p256` target) needs four things. Present vs missing:

| Handshake element | Needed | Present in heqk? | Gap |
|---|---|---|---|
| **KEX / key agreement** | hybrid **ML-KEM-768 (FIPS 203)** + **X25519** | ❌ **NEITHER** | **The load-bearing gap.** No KEM crate, no ECDH, no curve arithmetic anywhere. **Two new `no_std` crates** (e.g. RustCrypto `ml-kem` + `x25519-dalek`), shared-secret combine via the **existing HKDF**. |
| **AEAD (record protection)** | AES-128-GCM **or** ChaCha20-Poly1305 (TLS 1.3 mandatory) | ❌ none (only SHA-256-CTR+HMAC EtM) | **New crate** for a standards-compliant suite (`chacha20poly1305` is `no_std`, matches ADR 0004's chosen AEAD), **or** a deliberate non-standard channel over the present EtM (see §2.3). |
| **Handshake state machine** | TLS 1.3 (or a Noise-style authenticated channel) | ❌ none; **no rustls** (rustls is `std`-heavy — not a drop-in) | **New code**, `no_std`. Fork below. |
| **Auth (peer identity proof)** | hybrid **ML-DSA-65 + ECDSA-P256** (ADR 0002 target) | 🟡 **partial** — heqk has **Ed25519 + SLH-DSA**, *not* ML-DSA-65 / ECDSA-P256 | Present sigs can carry a hybrid auth leg *if* the suite is `ed25519+slh-dsa`; matching the ADR 0002 target verbatim needs **ML-DSA-65** (`ml-dsa`, exists in the Linux tree, not in heqk kernel) **+ ECDSA-P256** (absent). |

**Bottom line:** roughly **one of four** handshake elements (auth) is half-present; **the KEX is
0% present and is unbuildable from existing primitives** (a KEM is not derivable from signatures
or hashes). This is why M4.2 is a major new build, not an integration.

### 2.3 Fork to decide early (M4.2 sub-plan): standards-TLS vs Noise-over-present-crypto

There are two coherent ways to get a hybrid-PQC secure channel, and ADR 0002 and ADR 0004
already point in *different* directions:

- **(A) rustls-class TLS 1.3** — needed if the control plane / MSSP endpoint speaks standard
  HTTPS (the likely reality). Requires ML-KEM + X25519 + a standard AEAD + a `no_std` TLS 1.3
  handshake. Biggest surface; best interop; **ADR 0002's stated `tls_kex`/`tls_auth` target.**
- **(B) HTP-v2 Noise-style channel** — **ADR 0004's actual decision** for edge↔edge / mesh /
  fleet: a Noise-pattern authenticated hybrid **X25519+ML-KEM-768** DH, mutual **Ed25519/ML-DSA**
  auth, **ChaCha20-Poly1305** AEAD, PUF-anchored identity. This is *not* rustls; ADR 0004 §36
  says explicitly *"do not hand-roll… use audited crates composed into HTP's framing."*

**Both need the identical missing primitives** (ML-KEM-768, X25519, a real AEAD). The KEX/AEAD
crate work is shared; only the handshake *framing* differs. **Recommendation:** bring in the
KEX+AEAD crates once (M4.2a), then build the framing the endpoint actually requires — likely
**(A) rustls-class for the MSSP HTTPS link** (interop with a cloud control plane) and **(B) HTP-v2
for edge mesh** (ADR 0004, M4.4). Do **not** hand-roll the KEX; do **not** ship the SHA-256-CTR
EtM as the transport cipher (it is fine for at-rest sealing, not vetted as a wire AEAD).
Crypto-agility (ADR 0002 §1): whichever lands, the suite is **manifest policy**, and the CBOM
must report `tls_kex`/`tls_auth` honestly — a roadmap leg counts **quantum-vulnerable** until
the ML-KEM code actually runs.

---

## 3. Phased M4 plan (each phase = a testable gate)

The stack is built **bottom-up over the existing smoltcp/netq**, so every phase has a QEMU gate
before any silicon. The standalone-no-account invariant is a **precondition on every phase**.

### M4.1 — Net configuration: DHCP + DNS + NTP over smoltcp (**recommended first target**)
Drive smoltcp's TCP/UDP for real for the first time; add three client state machines.
- **DHCPv4/v6 client** — obtain address/route/DNS over UDP (smoltcp has a DHCP socket). Must
  degrade to **static / link-local / last-known** when no server answers (standalone path).
- **DNS stub resolver** — A/AAAA/PTR over UDP:53; feeds the "refuse a NAME, never a PACKET"
  sinkhole line (`docs/BuildPlan.md`). No lease/resolver ⇒ device still fully local.
- **SNTP client** — set a wall clock from NTP (UDP:123); until then, `CNTPCT_EL0` monotonic
  only. A trustworthy clock matters for TLS cert validity in M4.2 (chicken/egg: bootstrap with
  a signed roughtime-style or build-stamped floor, then refine — surface in the M4.2 sub-plan).
- **Gate `P17-netcfg` (QEMU):** against QEMU user-net / a synthetic server, the device acquires
  a lease, resolves a name, and steps its clock — **and every DHCP/DNS/NTP frame passes through
  `packet::verdict` both directions** (the PH6net property holds for real UDP, not just ARP).
  **Negative:** no server ⇒ device boots to a full local SOC on static/last-known config.
- **Why first:** smallest new surface, no new crypto, entirely QEMU-provable, and it is the
  substrate M4.2/M4.3 stand on. **This is the tractable beachhead.**

### M4.2 — PQC-TLS (**the big central piece — its own sub-plan**)
Bring up a hybrid-PQC secure channel over the M4.1 stack. Sequence:
- **M4.2a — KEX + AEAD crates:** integrate `no_std` **ML-KEM-768** + **X25519** and a standard
  **AEAD** (ChaCha20-Poly1305); combine shared secrets through the **existing HKDF**; wire into
  the manifest `crypto` suite (agility). **Gate:** KAT vectors pass in QEMU/host; CBOM flips
  `tls_kex` from roadmap→implemented **only when the code actually runs**.
- **M4.2b — handshake:** build the chosen framing (§2.3 fork) — TLS 1.3-class and/or HTP-v2
  Noise — with hybrid auth (present **Ed25519+SLH-DSA**, or the ADR target **ML-DSA-65+ECDSA**
  if adopted). **Gate `P18-tls` (QEMU/loopback):** a full handshake completes over a
  **loopback / synthetic transport**, negotiates the hybrid suite, and **fails closed** on a
  bad KEM share, a bad signature, and a downgrade attempt — no plaintext on any failure path
  (mirror `seal.rs`'s EtM discipline).
- **Honesty:** this is the largest new build in Track C; ADR 0002 must not be read as "TLS is
  coming for free." Budget it as a security-auditor-gated sub-milestone with an independent
  crypto review (ADR 0004 §51 — a ProVerif/formal pass on the handshake).

### M4.3 — MSSP enrollment + authenticated update fetch
The additive control-plane layer. **Reuses M3.4 OTA + device identity; adds only transport.**
- **Enrollment:** device presents its **software-PUF / TPM-bound identity** (ADR 0002 §3 device
  identity — Ed25519 software-PUF today, re-derived each boot, never stored) over the M4.2
  channel; receives a tenant binding. **Standalone invariant, explicit:** enrollment is a
  **state transition on an already-fully-functional device** (mirrors the Linux `claim.rs`
  Unclaimed→Claimed→Enrolled), **never** a boot precondition. Un-enroll returns to standalone.
- **Authenticated update fetch:** provide the M3.4 `pull` transport — fetch a signed candidate
  from the registry/control plane over M4.2, hand the bytes to the **existing** `ota.rs`
  state machine + `boot-abi/verify.rs` (hybrid Ed25519+SLH-DSA + SVN floor). **No second trust
  root** — the transport authenticates the *channel*; the image is verified by the *same boot
  keys* regardless of how it arrived (a compromised control plane still cannot ship an image
  hboot would reject).
- **Gate `P19-enroll` (QEMU):** against a fake control plane — enroll over M4.2, pull a signed
  candidate, feed `ota.rs` stage→verify→flip; a below-floor/bad-sig candidate is refused;
  **un-enrolled and air-gapped runs identical local SOC.**

### M4.4 — ADR 0004 secure-edge envelope over the native stack
Re-implement the "crown jewel" operational envelope on heqk's stack (ADR 0004 heqk footer:
*"the operational envelope must be re-implemented on heqk's native network stack"*).
- **Kill-switch** (no plaintext leaks if the tunnel drops), **PBR/fwmark** routing, **NAT**,
  **TUN**-equivalent — as native heqk constructs gating egress through `packet::verdict`
  (the envelope is *policy on top of* the rule plane, not a bypass of it).
- **Gate `P20-envelope` (QEMU):** tunnel-down ⇒ egress fail-closed (kill-switch); policy routes
  select the tunnel path; a non-tunneled packet that would leak is DROPPED by the rule plane.
- **Fork note:** this is where HTP-v2 (ADR 0004 path B, §2.3) lands if adopted for edge mesh.

---

## 4. QEMU-provable vs metal (Gate R) split

**The crypto, the client state machines, the handshake, and the enrollment protocol are
QEMU/host-provable. The real NIC datapath, EL0-isolation of the net service, real servers, and
real-network timing are metal.**

| M4 piece | QEMU-green | Needs CM5 silicon + real network (Gate R) |
|---|---|---|
| DHCP/DNS/NTP client **state machines** (M4.1) | ✅ over QEMU user-net / synthetic server | real DHCP/DNS/NTP **server** + real lease/RA timing |
| PH6net verdict-gating on real UDP/TCP (M4.1) | ✅ (extends the ARP `PH6-net` gate) | line-rate frames on RP1 GEM |
| **ML-KEM-768 / X25519 / AEAD** primitives (M4.2a) | ✅ pure logic — **KAT vectors, fully QEMU/host** | — (crypto is arch-agnostic; TRNG seed quality is metal) |
| **PQC-TLS handshake** (M4.2b) | ✅ over **loopback / synthetic transport** | handshake against a **real MSSP TLS endpoint** + real RTT/MTU |
| Enrollment protocol + un-enroll (M4.3) | ✅ against a **fake control plane** | real `mssp.hookprobe.com` tenant, real tokens |
| OTA `pull` transport feeding `ota.rs` (M4.3) | ✅ fetch→stage→verify→flip logic | real registry + the M3 metal slot-flip/watchdog (already Gate R in M3) |
| Kill-switch / PBR / NAT / TUN **decisions** (M4.4) | ✅ fail-closed logic, route selection | real TUN datapath + real WAN failover/roaming on silicon |
| **Real NIC datapath** (RP1 GEM `end0`) | ❌ QEMU can't model `rp1-gem` | ✅ polled RX/TX, PHY reset, RGMII clocks |
| **2nd NIC** (RTL8111 `eth1`) | ❌ | ✅ **+ BCM2712 PCIe RC1 training** (the real cost) |
| **EL0-isolated net service** over netq + TRNG seed + PCR3 measurement | 🟡 netq ABI + gate logic QEMU-testable | ✅ the actual EL0 isolation + hardware TRNG seed + measurement on metal |

**Rough split:** **~70–75 % of M4 is QEMU-green** — the entire crypto build (KEX/AEAD/handshake
are pure logic with KATs), the three client state machines, the enrollment protocol, and the
envelope *decisions* all prove over QEMU user-net + loopback + a synthetic control plane.
**~25–30 % needs silicon + a real network** — the RP1 GEM (and, more expensively, RTL8111/PCIe
RC1) datapath, the EL0-isolation + TRNG + PCR3 half of PH6net, real DHCP/MSSP servers, and
real-network timing (RTT, MTU, lease/RA, WAN failover). This mirrors M2/M3's ~70/30 shape.
**Caveat:** the QEMU-green % is *volume*, not *risk* — M4.2's handshake correctness carries the
most residual security risk and needs an independent crypto review regardless of gate colour.

---

## 5. Recommended first target

**Start with M4.1 (DHCP + DNS + NTP over the existing smoltcp).** It is the tractable beachhead:
smallest new surface, **no new crypto**, entirely QEMU-provable against QEMU user-net, it forces
heqk to drive smoltcp's TCP/UDP for the first time (today only ARP is exercised), it extends the
proven `PH6-net` verdict-gating property to real UDP both directions, and it is the substrate
M4.2/M4.3 stand on. Its negative gate directly re-proves the sacred invariant: **no server ⇒ full
local SOC on static/last-known config.**

**Flag M4.2 (PQC-TLS) for its own careful sub-plan** — it is the central load-bearing piece and
the largest new build. Sequence it KEX+AEAD crates first (M4.2a, KAT-gated, QEMU) → handshake
(M4.2b, loopback-gated, security-auditor + independent crypto review) → only then M4.3 enrollment
rides on top. Do not let the doc-level ambition ("hybrid-PQC TLS") obscure that **the KEX does
not exist in the tree and must be brought in as new `no_std` crates.**

---

## 6. Residual risks & open decisions

- **No KEX = new crate dependency.** ML-KEM-768 (RustCrypto `ml-kem`) + X25519 (`x25519-dalek`)
  must vet clean as `no_std` on bare-metal aarch64. Their TRNG seed on metal is a real assurance
  question (today PH6net's smoltcp PRNG is seeded from a constant in QEMU; production wants the
  hardware TRNG + PCR3 measurement — the deferred metal half).
- **AEAD choice.** ChaCha20-Poly1305 (ADR 0004's AEAD, `no_std`) is recommended over hand-rolling;
  the present SHA-256-CTR+HMAC EtM is fine for at-rest sealing but is **not** a vetted wire AEAD.
- **Auth-leg mismatch.** ADR 0002 names `ml-dsa-65+ecdsa-p256` for TLS auth; heqk has
  `ed25519+slh-dsa`. Decide whether M4 uses the **present sig pair** (cheaper, already vetted for
  boot) or adopts the ADR target (needs ML-DSA-65 + ECDSA-P256, both new to the kernel). Record
  in an ADR + the manifest suite; keep the CBOM honest either way.
- **Standards-TLS vs HTP-v2 fork (§2.3)** — resolve which framing the MSSP endpoint requires
  before M4.2b; the KEX/AEAD work is shared, the framing is not.
- **Clock bootstrap for TLS.** Cert validity needs a wall clock before NTP is trusted — bootstrap
  from a build-stamped floor / signed time, refine via SNTP. Own item in the M4.2 sub-plan.
- **Standalone invariant is testable, not aspirational** — every M4 gate carries an air-gapped
  negative case. A regression here is release-blocking.

---

## M4.2b security-auditor review — verdict: GO (loopback), with tracked metal/M4.3 conditions

The PQ-hybrid Noise handshake (`kernel/src/securechannel.rs`) passed an adversarial
security-auditor review (2026-07-29). The Noise rev-34 state machine, the AEAD
nonce-never-reuse invariant, the transcript/Ed25519-signature binding (no UKS /
misbinding), the ML-KEM implicit-reject handling (KEM ss never trusted before the AEAD
gate), the hybrid_combine (HKDF over two fixed-length secrets, "secure if either leg
holds"), and the fixed suite (no downgrade surface) were all **verified correct**; the
loopback selftest does **not** false-pass. **No must-fix correctness bug.** Verdict: **GO**
to commit as a loopback-proven phase.

**Tracked conditions — these do NOT block the loopback commit; every one BLOCKS the
metal / M4.3 network promotion (Gate R):**
1. **⚠️ Entropy (highest consequence).** Real ephemerals/keygen MUST be HW-TRNG-sourced on
   metal, with NO seeded fallback and a boot-time entropy-health assertion. The KATs pass
   identically for a seed or a TRNG — a wiring slip that lets a seeded path reach metal
   gives the whole fleet reused ephemerals behind a green gate (total confidentiality break).
2. **Fixed buffers.** Replace the transport/handshake `alloc::Vec` (leaks per-record on the
   never-freeing bump allocator) with fixed in-place buffers (the AEAD is already detached).
3. **Zeroize.** Enable `zeroize` on the dalek crates + scrub the raw `ss_*`/`dh_*` arrays.
4. **`key_for_test()`** — feature-gate behind `securechannel-selftest`, out of the metal profile.
5. **Anti-replay window** (IPsec/DTLS-style sliding window) + **msg1-replay DoS** mitigation
   (cookie/retry or rate-limit — asymmetric ML-KEM/keygen/verify work on the responder).
6. **CBOM/SBOM** entry for the pre-release `kem =0.3.0-pre.0` crate (SHA + "pre-release"),
   upgrade when RustCrypto tags `kem 0.3`.
7. **ML-DSA-65 co-signature** at the auth site (ADR 0002/0004 target — roadmap; KEX is
   hybrid-PQ today, auth is classical Ed25519, which is acceptable now since auth signatures
   are not subject to harvest-now-decrypt-later).
