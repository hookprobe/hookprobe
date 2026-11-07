# ADR 0004 — Secure edge-to-edge transport: evolve HTP / NEURO / DSM

**Status:** ✅ **Accepted (revised 2026-06-28).** V2's edge-to-edge / node-to-node / mesh / fleet secure transport is **HookProbe's own HTP, evolved**, with **NEURO** (PUF identity + attestation) and **DSM** (Byzantine consensus). **WireGuard / Rosenpass / QUIC-as-VPN are explicitly NOT used.** (The earlier WireGuard draft is withdrawn.) **⚠️ In-repo implementation: DESIGN-ONLY (~0%).** V1 HTP lives *outside* this repo (`~/hookprobe`, Python); the V2 hardened handshake (X25519+ML-KEM, mutual ML-DSA/Ed25519 auth, no-PSK-fallback removal), the DSM aggregate, and NEURO-attestation→QSECBIT are **not started in-tree** — no `secure_tunnel`/`fleet_mesh` code exists. The *decision* is accepted; the *build* is not. All cross-device / mesh / fleet transport depends on this and is therefore unbuilt.
**Date:** 2026-06-28 · **Deciders:** operator (decision), os-architect, security
**Grounded in:** [`htp-dsm-neuro-investigation.md`](../research/htp-dsm-neuro-investigation.md). **Relates to:** [ADR 0002](0002-crypto-agility-pqc.md) (crypto-agility/PQC), [ADR 0003](0003-platform-manifest-schema.md) (`secure_tunnel`/`fleet_mesh` tokens), [`runtime-engine-map.md`](../architecture/runtime-engine-map.md), [`Readme.md`](../architecture/Readme.md) (standalone-first).

> **Scope:** this ADR is the **edge VPN / mesh / fleet** transport (device↔device, device↔fleet). The *local operator dashboard* transport (browser↔on-device backend) stays local TLS per ADR 0001 — that is not the edge VPN and is unaffected.

## Context

HookProbe already has a proprietary end-to-end secure transport — **HTP** — with **NEURO** (PUF-based identity, neural-synaptic attestation) and **DSM** (Byzantine consensus mesh). It is real, deployed work with a strong operational envelope. The decision is to **keep and harden it**, not replace it.

The investigation found **"HTP" is two things**: (1) the **deployed VPN** (`products/*/lib/htp_vpn_client.py`, `shared/mesh/htp_gateway.py`) — a working UDP/TUN tunnel wrapped in genuinely strong ops (nftables kill switch, PBR table 300/fwmark, NAT, WAN-failover, roaming); and (2) an **experimental "keyless" HTP + NSE** that is research-only and not in the data path. The one concrete weakness in the deployed VPN's crypto core: its handshake is **PSK + HKDF with no Diffie-Hellman → no forward secrecy, no mutual crypto-auth**, plus a **no-PSK gateway fallback**. We fix that **within HTP's own handshake**.

## Decision — keep HTP; evolve its crypto core

| Element | Verdict | What we do |
|---|---|---|
| **HTP transport** (the VPN data plane) | **KEEP** | HTP remains *the* edge-to-edge tunnel. UDP/TUN, per-packet **ChaCha20-Poly1305** AEAD retained. |
| **Operational envelope** (kill switch, PBR/fwmark, NAT, WAN-failover, roaming, `atexit` fail-safe) | **KEEP as-is** | The crown jewel — carry forward unchanged; an off-the-shelf tunnel would lose it. |
| **HTP handshake crypto** (PSK+HKDF, Ed25519 *server-only*, no DH, no-PSK fallback) | **EVOLVE** | Add an **authenticated ephemeral key agreement**: hybrid **X25519 + ML-KEM-768** per session → **forward secrecy**; **mutual authentication** (both peers prove identity) via **PUF-anchored Ed25519 + ML-DSA-65** (hybrid), replacing server-only TOFU. **Remove the no-PSK fallback.** REKEY now ratchets over fresh ephemeral secrets → post-compromise security. (An optional PSK may remain as an *additional* factor, never the only one.) |
| **NEURO / PUF identity** (fuzzy extractor, never-stored Ed25519 regenerated at boot) | **KEEP + adopt** | The HW root of trust for TPM-less Pi 5 / RK3588; HTP mutual auth binds to it (802.1AR LDevID-style). |
| **NSE as *encryption*** + the keyless HTP | **DROP** | Unsound (key derived from wire-exchanged values) and not in the data path. HTP confidentiality comes from the AEAD over the new ephemeral-DH/KEM session key. |
| **NSE as *attestation*** (deterministic weight-replay tamper detection) | **EVOLVE + KEEP** | Salvage as continuous attestation feeding **QSECBIT** — innovative *as attestation*. |
| **DSM** Byzantine consensus (2/3 quorum + proof-of-possession) | **KEEP architecture, EVOLVE crypto** | Replace RSA-fallback "BLS" + software identity with real **BLS / ML-DSA** aggregate signatures over **PUF/HW identity**. |
| **mesh / federation** | **EVOLVE + contain** | Lives behind the `fleet_mesh` capability — additive, off by default (standalone-first). |
| **PQC** | **EVOLVE** | **Kyber512 (draft) → ML-KEM-768**; **ML-DSA-65** for signatures. All primitives are **manifest policy** (ADR 0002), so the suite is swappable without re-architecture. |
| **mirage / steganography** | **KEEP** | The `deception` capability. |

**Capabilities (already in the contract):** `secure_tunnel` = the evolved HTP data plane; `fleet_mesh` = the DSM/mesh coordination layer (additive).

## Why HTP, not WireGuard

A product/architecture decision: HTP carries HookProbe's **operational envelope, PUF identity, DSM consensus, and deception integration** that a generic tunnel does not — and the only real gap (forward secrecy + mutual auth) is **fixable inside HTP's own handshake** with standard, vetted PQC primitives. Crypto-agility is preserved because the primitives are manifest policy, not hardcoded. So we keep what's differentiated and harden the one weak spot.

## Implementation guidance (build the hardened handshake on vetted primitives)

Do **not** hand-roll the new handshake. Use audited Rust crates, composed into HTP's existing framing:
- KEX: `x25519-dalek` + RustCrypto **`ml-kem`** (hybrid; combine both shared secrets via HKDF).
- Auth: `ed25519-dalek` + **`ml-dsa`** (hybrid mutual signatures), keyed to the PUF-derived identity.
- AEAD: keep **ChaCha20-Poly1305** (`chacha20poly1305`).
- Model the handshake on a reviewed pattern (Noise-style authenticated DH, e.g. an IK/XX-equivalent) so the security argument is standard, then have it independently reviewed.

## Migration

V1 HTP → **HTP v2** with the hardened handshake. Dual-stack per rollout ring (canary → ring → fleet); cut over when healthy; then remove keyless-HTP, NSE-as-encryption, and the no-PSK fallback. Because crypto is manifest policy, future suite swaps are config, not a rewrite.

## Consequences / risks & open questions

- ⚠️ **Live V1 concern (independent of V2):** the *current* deployed VPN lacks forward secrecy/mutual auth and has a no-PSK fallback — worth hardening in V1 too.
- Implementing an authenticated hybrid handshake correctly is the main risk → vetted crates + independent cryptographic review (ideally a ProVerif/formal pass like Rosenpass had).
- DSM crypto upgrade (real BLS/ML-DSA + HW identity) and the "v5.1 planned" hardware root of trust need to actually land.
- PUF assurance tiers differ by board (Pi/RK3588 software-PUF vs TPM where present) — record in the manifest `identity`.
- **Open Qs to lock:** (1) handshake pattern (Noise IK vs XX-equivalent) + who reviews it; (2) is `secure_tunnel` (HTP data plane) one module or two with `fleet_mesh` (DSM mesh); (3) DSM signature scheme (BLS aggregate vs ML-DSA); (4) keep an optional PSK as a second factor or drop entirely.

## Sources

`htp-dsm-neuro-investigation.md` (file/function citations); V1 docs `HTP_QUANTUM_CRYPTOGRAPHY.md`, `HTP_KEYLESS_PROTOCOL_ANALYSIS.md`, `NEURAL-SYNAPTIC-ENCRYPTION.md`, `networking/VPN.md`; FIPS 203 ML-KEM / FIPS 204 ML-DSA; RustCrypto `ml-kem`/`ml-dsa`, `x25519-dalek`, `ed25519-dalek`; Noise Protocol Framework; IEEE 802.1AR.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: SOFT (with a HARD envelope).** The hybrid X25519+ML-KEM handshake crates port; but the operational envelope — nftables kill-switch, PBR table 300/fwmark, NAT, TUN — must be re-implemented on heqk's native network stack. → **Phase M4**.
