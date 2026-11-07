# HTP / DSM / NEURO / NSE / PUF — Faithful Investigation & V2 Reconciliation

**Date:** 2026-06-28
**Author:** os-architect
**Scope (read-only):** `~/hookprobe` — `core/htp/`, `core/neuro/`, `core/aegis/neurokernel/`, `shared/dsm/`, `shared/mesh/`, `shared/mirage/`, `products/{fortress,guardian}/lib/`, the design docs, and the security test-suite.
**Purpose:** A previous pass (ADR 0004, now "under revision") proposed swapping the whole stack for WireGuard *without reading it*. This document reads it first, describes it accurately, judges it fairly, and gives an evolve-vs-replace verdict per component.

> **Headline finding up front (so nothing is conflated):** "HTP" is **two different things** in this repo. (1) the **deployed VPN** — a conventional UDP/ChaCha20 tunnel with excellent routing/ops code but a *cryptographically weak handshake (no Diffie-Hellman, no forward secrecy)*; and (2) the **experimental "keyless" HTP** (`core/htp/transport/htp.py`) plus **NSE** — a research crypto narrative that is **not in the VPN data path** and whose "nobody knows the key" claim is, as implemented, **backwards**. The two must be judged separately. The honest verdict is **evolve the operational VPN onto a standards handshake; keep PUF and DSM; re-cast NSE as attestation, not encryption.**

---

## 0. What is actually live vs. what is a paper/lab artifact

The single most important map, established by `docs/architecture/MESH-TRANSPORT-REFACTOR.md` (a prior four-agent investigation) and confirmed here by the import graph:

| Surface | File(s) | Live? | Depends on `core/htp`? |
|---|---|---|---|
| **Deployed VPN data plane** | `products/fortress/lib/htp_vpn_client.py`, `products/guardian/lib/htp_vpn_client.py`, `shared/mesh/htp_gateway.py` (1712 LOC) | **Yes** (`fts-htp-vpn.service`, `guardian-htp-vpn.service`, `hookprobe-mesh`) | **No** — protocol inlined, stdlib + `cryptography` only |
| **"Keyless" HTP** (qsecbit/RDV/PoSF/NeuroStateEvolver) | `core/htp/transport/htp.py` (1273 LOC) | **No** running service | importers are tests + `htp_vpn.py` (non-deployed) + a Cortex demo bridge |
| **NSE synaptic encryption** | `core/neuro/synaptic_encryption.py` | **No** as a transport; used by `core/neuro/integration.py`, adversarial mitigator, one test | — |
| **Hybrid KEM (X25519+Kyber512)** | `core/htp/crypto/hybrid_kem.py` | **No** in VPN; only `core/htp/crypto/transport_v2.py` | — |
| **DSM consensus/ledger** | `shared/dsm/*` | **Yes** on MSSP/Guardian | — |
| **Mesh overlay** | `shared/mesh/{unified_transport,neuro_encoder,consciousness,...}` | **Yes** on Guardian(offline)+MSSP | divergent-by-design (WON'T-MERGE) |

`MESH-TRANSPORT-REFACTOR.md` §1 states it plainly: *"The live VPN does not depend on `core/htp` at all."* This is decisive for the WireGuard debate — the quantum/keyless/NSE marketing does **not** describe the bytes that actually protect user traffic today.

---

## 1. What each component actually is and does

### 1.1 HTP — the deployed VPN transport (the real one)

**Files:** `products/fortress/lib/htp_vpn_client.py`, `products/guardian/lib/htp_vpn_client.py`, `shared/mesh/htp_gateway.py`.

**Framing.** UDP tunnel (gateway `mesh.hookprobe.com:8144`), TUN device (`htp0`), gateway TUN `10.250.0.1`, client pool `10.250.0.2–254`.

**Handshake (HELLO → CHALLENGE → ATTEST → ACCEPT):**
- **HELLO** (`>HB32s32sQ`, 75 B): version, type, `node_id`, `client_nonce(32)`, `flow_token(64)`.
- **CHALLENGE** (35 or 131 B): `gateway_challenge(32)` and, when present, `server_pubkey(32) + Ed25519_sig(64)`. The server **signs `gateway_challenge ‖ client_nonce`** with a persistent Ed25519 identity key (`_load_or_create_identity`, `htp_gateway.py:271`). Client verifies and **TOFU-pins** (`_tofu_verify`, client:1000); a known host that later sends an *unsigned* challenge is rejected as a downgrade.
- **Session key** (`_perform_handshake`, client:925; gateway `_handle_attest`:754):
  `session_key = HKDF-SHA256(ikm = client_nonce ‖ gateway_challenge ‖ PSK, salt="htp-vpn-session-salt-v2", info="htp-vpn-session-key-v2")`.
- **ATTEST** (43 B): `HMAC-SHA256(session_key, client_nonce ‖ gateway_challenge)` — proves the client derived the same key (i.e., knows the PSK).
- **ACCEPT** (7 B): assigned tunnel IP (client validates it is inside `10.250.0.0/24`).

**Data plane.** Per-packet `ChaCha20-Poly1305` with a **random 12-byte nonce** (`_encrypt_packet`, client:1038); frame `struct.pack('>QIB', flow_token, seq, type)`. **REKEY** every 300 s: gateway sends a fresh `rekey_nonce` encrypted under the *current* key; both derive `HKDF(old_key ‖ rekey_nonce, "htp-vpn-rekey-*")`; old key kept 10 s for in-flight packets (`_handle_rekey`, client:1073).

**The "keyless" name is misleading here:** this transport is **PSK-keyed**. The PSK is the device token / MSSP `API_KEY` (`VPNConfig.load`). Ed25519 authenticates only the *server*; the *client* is authenticated by PSK knowledge.

**Operational envelope (genuinely strong, see §2).** PBR via routing table 300 + `fwmark 0x300/0xf00` at rule priority 45; three kill-switch modes (`off`/`host`/`full`) implemented in `nftables` with prerouting marking for forwarded LAN traffic (the same technique WireGuard/OpenVPN use on Linux routers, explicitly noted in `_nft_create_vpn_table`); WAN-failover coexistence (tables 100/200); `SO_BINDTODEVICE` re-detection on every connect; `atexit` emergency teardown so a crash never leaves a kill switch black-holing the box.

### 1.2 HTP — the "keyless" research protocol (not in the data path)

**File:** `core/htp/transport/htp.py`. Packet = `HTPHeader(32 B)` + `ResonanceLayer(64 B)` + `NeuroLayer(224 B)`. The identity/auth primitives:
- **qsecbit** = `SHA256(white_noise(32) ‖ sensor_vec ‖ clock_jitter)` — per-tick device entropy.
- **RDV (Resonance Drift Vector)** = `BLAKE3(qsecbit_history[t-50:t] ‖ TER ‖ timestamp)`.
- **PoSF (Proof of Sensor Fusion)** = `BLAKE3(sensor_matrix ‖ RDV ‖ delta_W)`.
- **anti-replay nonce** = `HKDF-SHA256(salt=qsecbit_prev, ikm=qsecbit_now, info="htp-anti-replay-v2")` (htp.py:237 — note: the *implementation* is better than the keyless-analysis doc's "returns True" snippet; it was fixed).
- **NeuroStateEvolver** (htp.py:360): `W(t+1) = W(t) − η·grad(TER) + ξ·qsecbit` in fixed-point int16; the gradient is just 4×SHA256(TER‖i). The "evolution" is a **hash chain**, not learning.

**Status, per the project's own docs:** `docs/HTP_KEYLESS_PROTOCOL_ANALYSIS.md` is an *internal critique* that flags the state machine as incomplete (*"INIT → RESONATE → ??? (never reaches SYNC or STREAMING)"*), rates **Authentication "WEAK"**, **Forward Secrecy "NONE"**, and concludes **"NOT READY for production use … Suitable for research/experimentation only."** That document is to the project's credit — it is an honest self-assessment. The unit tests (`tests/test_htp_keyless.py`) verify serialization sizes and that qsecbit/RDV/PoSF are *deterministic*, not that the protocol is *secure*.

### 1.3 "Quantum cryptography" approach

Two distinct claims live under this banner:

1. **The narrative** (`docs/HTP_QUANTUM_CRYPTOGRAPHY.md`): *"Instead of static cryptographic keys, HTP uses living neural networks as cryptographic primitives,"* quantum-resistant because qsecbit/RDV/PoSF *"have no algebraic structure"* (only SHA256/BLAKE3, so Shor's algorithm is irrelevant; Grover only halves symmetric strength). The "Theorems 1–3" prove **unpredictability of an entropy source** and **tamper-divergence** — which are real properties — but **none of them establishes a secure key-agreement or confidentiality argument.** The doc conflates "I only use hashes" with "this is a secure protocol." It is a strong *attestation/anti-tamper* argument dressed as a *cryptosystem* argument.
2. **The real PQC code** (`core/htp/crypto/hybrid_kem.py`): a correct **hybrid KEM = X25519 ⊕ Kyber512**, `combined = HKDF(x25519_shared ‖ kyber_shared)` — the standard "if either primitive holds, the KEM holds" construction. This is sound, but (a) uses **Kyber512 draft params, not ML-KEM (FIPS 203)** and is **not wire-compatible** with the standard, and (b) is **only referenced by `transport_v2.py`, not the deployed VPN.** So the production tunnel has **no PQC at all** today; the PQC is in a lab file.

### 1.4 NSE — Neural Synaptic Encryption (the "nobody knows the key" mechanism)

**File:** `core/neuro/synaptic_encryption.py`. The actual mechanism (read precisely):

```
ephemeral_secret = SHA256-iterated(
    my.weight_fingerprint ‖ peer.weight_fingerprint
  ‖ my.ter_entropy       ‖ peer.ter_entropy
  ‖ my.collective_entropy ‖ struct(timestamp, ter_chain_hash, ter_sequence))   # 10 000 rounds
key   = HKDF-SHA256(ephemeral_secret, salt=ter_entropy[:16], info="synaptic-encryption-v1")
nonce = SHA256(timestamp ‖ ter_entropy)[:12]
ct    = ChaCha20Poly1305(key).encrypt(nonce, plaintext)
```

It is **not** key-agreement. There is **no asymmetric trapdoor, no Diffie-Hellman, no per-party secret.** Both peers must hold each other's `SynapticState`, and `SynapticState` (weight fingerprint, TER entropy, collective entropy, timestamp) is **exchanged over the wire** (`MeshSynapseNetwork.register_peer` comment: *"would receive state via HTP"*). The design doc itself says the key derives from values that are transmitted. Therefore:

> **The key is a deterministic function of values both peers send to each other. A passive eavesdropper who observes the two `SynapticState` exchanges computes the identical key.** "The key is not a secret you know — it's a state you ARE" — but that state is broadcast, so *everyone who hears the handshake knows the key.* The "nobody can extract the key" claim is inverted by construction.

The two intended mitigations are both currently inert:
- **`hardware_attestation`** is meant to be TPM/PUF; the implemented `_derive_hardware_binding()` is `SHA256(hostname ‖ machine ‖ MAC)` — **fully predictable, not secret.**
- **`collective_entropy`** "no single node can decrypt" only engages with ≥3 mesh nodes *and* assumes those contributions are confidential — but they are exchanged the same way, so the same eavesdropper argument applies.

What NSE **does** legitimately provide is **continuous mutual attestation**: two nodes can only "resonate" if their independently-evolving weight trajectories stay within a 5 % drift window (`is_aligned_with`, `WEIGHT_ALIGNMENT_THRESHOLD = 0.05`) and within 100 ms — and a remote validator can **replay the TER log and recompute the weights bit-for-bit** to detect offline tampering (`docs/...NEURAL-SYNAPTIC-ENCRYPTION.md` threat table; the cloud-replay in `HTP_QUANTUM_CRYPTOGRAPHY.md` Theorem 3). **That** is the valuable idea — it is remote attestation / tamper-evidence, not encryption.

### 1.5 PUF identity (the quiet crown jewel)

**Files:** `core/neuro/puf/{sram_puf,clock_drift_puf,cache_timing_puf,composite_identity,puf_ter_binding}.py`.

This is textbook-correct and genuinely good:
- **SRAM PUF** with a real **fuzzy extractor**: `gen() → (key, helper_data)`, `rep()` reproduces the key from a noisy reading with BCH-style error correction; stable-bit map at 95 % threshold over 10 enrollment readings; public **helper data reveals no key bits** (`sram_puf.py`).
- **Composite identity** XOR-combines SRAM (weight 0.5) + clock-drift (0.35) + cache-timing (0.15), then **derives an Ed25519 keypair via HKDF** from the composite, and **the private key is never stored — it is regenerated from PUF readings at each boot** (`composite_identity.py`).

This is a credible **hardware-rooted device identity for boards without a TPM** (Pi 5, RK3588) — exactly the gap ADR 0004 flags. It is materially better than ADR 0004's offhand "reuse *concepts*."

### 1.6 DSM — Distributed Security Mesh (Byzantine consensus + node verification)

**Files:** `shared/dsm/{consensus,validator,node,gossip,merkle,microblock,ledger,bloom_ioc,identity}.py`, `shared/dsm/crypto/{bls,tpm,attestation}.py`.

- **Consensus** (`consensus.py`): BLS-aggregated checkpoints, **2/3 BFT quorum** with the *correct* formula `quorum = n − ⌊(n−1)/3⌋` (`bft_quorum_required`), tolerating `f = ⌊(n−1)/3⌋` faulty validators. **Proof-of-Possession** verification is enforced to stop **rogue-key attacks** (and it *warns loudly* when the registry is absent — good hygiene). Optional NSE TER-checkpoint proofs gate a validator's vote.
- **Guarantees:** safety/finality under <1/3 Byzantine validators, with hardware/PoP-bound identities — a recognizable, sound BFT design.
- **Caveat:** `bls.py` and `tpm.py` headers say *"v5.0 uses RSA fallback. Native BLS / hardware TPM planned for v5.1."* So today the "BLS aggregate" is an **RSA multi-signature bundle** and identities are **software self-signed** (`identity.provision_node` → `SHA256(hardware_id)`), with `verify_certificate_chain` accepting self-signed when no CA is present. The *architecture* is right; the *primitives and root-of-trust are stubbed*.

### 1.7 NEURO / neurokernel (fingerprinting / identity / AI-SOC)

- `core/neuro/neural/engine.py`: Q16.16 fixed-point `WeightState`, **SHA512 fingerprint**, deterministic Xavier/He init (optionally PUF-seeded). **But the weight update is a placeholder** (`# TODO: Implement full fixed-point backpropagation`). So the "living key evolves via learning" story is, in the deterministic engine, **not actually learning** — the only live "evolution" is the hash-chain `NeuroStateEvolver` in `htp.py`.
- `core/neuro/core/ter.py`: the 64-byte TER (`H_Entropy(32) ‖ H_Integrity(20, RIPEMD160) ‖ ts(8) ‖ seq(2) ‖ CRC16(2)`).
- `core/aegis/neurokernel/*` (7.8k LOC) is a **separate AI-SOC subsystem** (eBPF compiler/templates, embedding engine, vector store, streaming RAG, shadow pentester, kernel-twin, hybrid inference) — detection/AI, *not* transport crypto. It is out of scope for the VPN question and maps to Detect/Investigate.

### 1.8 mesh transport

`shared/mesh/` is the **live federation overlay** (Guardian-offline + MSSP). `unified_transport.py` (`MeshPacket`, 48 B header with `rdv_prefix`), `neuro_encoder.py` (3-way RESONATE_INIT/ACK/CONFIRM resonance handshake, big-endian TER, hash-chain weights), `consciousness.py` (threat-intel tier state machine, neural-resonance HMAC), `nat_traversal.py`, `resilient_channel.py`, `channel_selector.py`, `port_manager.py`, `mesh_server.py`, `htp_gateway.py`. `MESH-TRANSPORT-REFACTOR.md` §3 establishes (with byte-level evidence) that these are **divergent reimplementations by design**, not duplicates of `core/htp`/`core/neuro`, and records **WON'T-MERGE**.

### 1.9 mirage (deception) + steganography

- `shared/mirage/`: an **active-deception controller** — subscribes to the NAPSE EventBus, auto-deploys honeypots on scan detection, runs a per-attacker escalation state machine (`DORMANT→DETECTING→ENGAGING→PROFILING→LEARNING`), and feeds intelligence back. This is legitimate SOC deception, not crypto.
- `core/htp/steganography/` (`traffic_shaper`, `domain_fronting`, `decoy_generator`, `profile_library`) + the security-enhancements doc's BURST/BALANCED/STEALTH/GHOST padding+jitter modes: **censorship-resistant / DPI-evading transport shaping.** Useful in hostile-network deployments.

### 1.10 How they compose into the end-to-end VPN

Per `docs/networking/VPN.md`, the e2e path is **two-segment**:

```
Phone/Laptop --[IKEv2/IPsec, EAP-TLS, AES-256-GCM]--> MSSP Mesh Gateway --[HTP, ChaCha20-Poly1305, PSK]--> Guardian/Fortress edge (behind NAT/CGNAT)
```

Mobile uses native IKEv2 (no app); HTP carries the NAT-traversing edge segment (the edge dials *out*, so no port-forwarding). DSM/mesh sit *beside* this as the federation/herd-immunity overlay (threat-intel + consensus), and PUF/NSE are meant to provide identity/attestation for mesh membership. In the **deployed** system, the confidentiality of the edge segment rests entirely on the §1.1 PSK/ChaCha20 tunnel — **not** on keyless HTP, NSE, or the hybrid KEM.

---

## 2. Honest assessment — strengths (what to be proud of and keep)

1. **The VPN's operational engineering is excellent and hard-won.** The PBR + `fwmark` + nftables kill-switch design (with prerouting marking for forwarded LAN traffic, WAN-failover coexistence, conntrack flush on mode change, `SO_BINDTODEVICE` re-detection, `atexit` fail-safe teardown, REKEY grace window, roaming reconnect on WAN change) is the part of a VPN that is *actually* hard and that off-the-shelf WireGuard does **not** give you. This is genuine IP and must survive any crypto change.
2. **PUF-based identity is real, correct, and strategically valuable.** A fuzzy-extractor SRAM/clock/cache composite that regenerates a never-stored Ed25519 key at boot is a credible hardware root of trust for TPM-less boards — directly solving an ADR 0004 open question ("Pi/RK3588 have no onboard TPM").
3. **DSM is a sound, recognizable BFT system.** Correct 2/3 quorum math, PoP against rogue-key attacks, Merkle/microblock/ledger machinery, gossip — a legitimate basis for a federated trust/intel mesh.
4. **The continuous-attestation idea behind NSE/qsecbit is genuinely innovative** *when framed as attestation*: deterministic replay of a sensor-driven state chain to detect offline tampering / device cloning is a real, useful, edge-friendly property that classical PKI does not give you.
5. **Deception (mirage) and traffic-shaping/stego** are differentiated SOC capabilities that map cleanly onto V2 workspaces.
6. **The project critiques itself honestly.** `HTP_KEYLESS_PROTOCOL_ANALYSIS.md` and `MESH-TRANSPORT-REFACTOR.md` already document the weaknesses and the live/dead reality — this is a mature engineering culture, not hype-only.

## 3. Honest assessment — risks (stated plainly, with where the repo already addresses them)

1. **The deployed VPN has no forward secrecy and no mutual cryptographic auth.** The session key is `HKDF(client_nonce ‖ gateway_challenge ‖ PSK)` with **no Diffie-Hellman**. Consequences: (a) anyone who ever learns the PSK can **passively decrypt all recorded past and future traffic** (the "harvest now, decrypt later" target ADR 0002 worries about); (b) the client is authenticated only by PSK possession; (c) REKEY is a *symmetric* ratchet seeded from the current key, so it gives key-separation but **not** post-compromise security — an attacker with one session key derives all subsequent ones. This is **weaker than WireGuard**, which does an ephemeral ECDH per handshake. *Not yet addressed in the deployed code.*
2. **A no-PSK fallback exists on the gateway.** `_handle_attest` retries key derivation *without* the PSK "for backwards compatibility" (`htp_gateway.py:771`). Any client that authenticates on the no-PSK path is, in effect, **unauthenticated** (only nonce exchange) — a downgrade/foothold risk. *Should be removed or gated.*
3. **NSE as encryption is not sound** (§1.4): the key is derived from transmitted state, so it provides **no confidentiality against a passive network adversary**, and its claimed hardware/collective mitigations are currently inert (`hardware_attestation = SHA256(hostname+MAC)`). The "nobody knows the key" framing is the opposite of what the code does. *The keyless-analysis doc already rates auth WEAK / FS NONE and says research-only; runtime-engine-map already marks NSE for drop.*
4. **Bespoke crypto, no external review, custom wire formats.** The keyless HTP, NSE, neuro_encoder resonance, and mesh `MeshPacket` are all bespoke protocols with hand-rolled framing and no formal/peer-reviewed analysis. This collides with **ADR 0002** (standards-based, crypto-agile) and is a procurement/credibility liability for a security product. *Partially acknowledged in runtime-engine-map.*
5. **PQC is claimed but not deployed, and is the wrong primitive.** The only real KEM (`hybrid_kem.py`) is **Kyber512 (draft), not ML-KEM-768 (FIPS 203)**, and is not wired into the VPN. So today's tunnel is **not** post-quantum, despite the doc title. *runtime-engine-map already flags Kyber512 → ML-KEM-768.*
6. **The hardware root of trust is stubbed across the board.** TPM (`tpm.py`), DSM identity (`identity.py`), BLS (`bls.py` → RSA fallback), and NSE hardware binding are all software fallbacks marked "planned v5.1." Every "tamper-evident / unclonable / harvest-resistant" claim depends on hardware that is not yet integrated. *Explicitly labeled in the file headers — honest, but the marketing docs do not carry the caveat.*
7. **Maintainability / determinism debt.** The neural "evolution" the quantum narrative rests on is a `TODO` placeholder in `engine.py`; "evolution" is really a hash chain. Determinism across architectures (int16 fixed-point, endianness — the mesh refactor doc notes big-vs-little-endian TER divergence between `neuro_encoder` and `core/neuro`) is fragile and untested across arches.
8. **FIPS / regulatory.** None of the bespoke constructions are FIPS-validatable; ChaCha20-Poly1305 + HKDF-SHA256 + Ed25519 are fine primitives but the *protocol* (no DH, no KCI resistance, no formal model) would not pass a serious crypto review or CNSA-2.0 posture (ADR 0002).
9. **Side channels / DoS.** Per-packet `ChaCha20Poly1305` and HKDF are constant-time via `cryptography`; the iterated-SHA256 NSE KDF is fine timing-wise. DoS protection (rate-limit, PoW) is documented as "future" and only partially present (HELLO rate-limit on the gateway).

---

## 4. Reconciliation with V2 — evolve-vs-replace per component

Default posture = **understand and EVOLVE**; replace only with concrete cause. Tokens/ADRs referenced: `secure_tunnel`, `fleet_mesh` (runtime-engine-map §86–101), ADR 0002 (crypto-agility/PQC), ADR 0003 (manifest identity), ADR 0004 (under revision).

| Component | Verdict | What specifically, and V2 mapping |
|---|---|---|
| **Deployed VPN — operational envelope** (PBR, kill switch, NAT, roaming, two-segment IKEv2 mobile) | **KEEP** | This is the crown jewel of the VPN. It becomes the `secure_tunnel` capability's host-integration layer regardless of which wire protocol sits underneath. Keep the kill-switch state machine, WAN-failover coexistence, `atexit` fail-safe, mobile IKEv2 segment. |
| **Deployed VPN — wire crypto / handshake** | **REPLACE (concrete reason)** | It lacks forward secrecy and mutual auth and has a no-PSK fallback. Replace the handshake+AEAD core with a **DH-based, FS-providing** protocol: **WireGuard + Rosenpass** (PQ-hybrid PSK) per ADR 0004, *or* a Noise-IK handshake if we want to keep our own dataplane. The reason to replace is **not** "bespoke is scary" — it is the specific, demonstrable absence of forward secrecy. Crypto stays manifest policy (ADR 0002). |
| **Keyless HTP** (`core/htp/transport/htp.py`) | **REPLACE / RETIRE as transport** | Not in the data path, state machine incomplete, no FS, no real key agreement (the project's own doc says research-only). Do not promote it to production. *Salvage* qsecbit/RDV/PoSF → feed the attestation module below and QSECBIT scoring. |
| **NSE — as encryption** | **REPLACE / DROP** | The eavesdropper-derives-the-key flaw is concrete. Confidentiality must come from the standards `secure_tunnel`. Aligns with ADR 0004 / runtime-engine-map "NSE dropped, not migrated." |
| **NSE / qsecbit / weight-replay — as *attestation*** | **EVOLVE & KEEP (re-cast)** | This is the salvageable innovation. Re-cast as a **continuous device-attestation / anti-tamper signal**: a Wasm detection module that emits a tamper/divergence score into QSECBIT and gates `fleet_mesh` membership. It is *not* in the enforcement/confidentiality path. This is a **correction to "drop NSE entirely"** — drop the crypto claim, keep the attestation idea. |
| **PUF identity** (`core/neuro/puf/*`) | **KEEP & EVOLVE** | Promote to the **device-identity provider** for TPM-less boards. Conform to **ADR 0002 `device_identity` = hybrid ML-DSA-65 + Ed25519** (derive both legs from the PUF composite) and **ADR 0003** manifest `identity.idevid.type` (`puf`/`dice`/`tpm`/`software`). This is stronger than ADR 0004's "reuse concepts" — the code is already correct. |
| **DSM** (consensus/ledger/validator/gossip) | **KEEP architecture, EVOLVE crypto** | Sound BFT. Move RSA-fallback "BLS" → **real BLS or ML-DSA-65 hybrid** (ADR 0002), wire **real TPM/PUF identity** in place of self-signed software certs, keep PoP enforcement. Gate the whole thing behind **`fleet_mesh` (off by default)** so standalone-first holds (runtime-engine-map §92). |
| **mesh transport** (`shared/mesh/*`) | **EVOLVE, contain** | Keep as the **additive federation overlay** under `fleet_mesh`; its wire crypto rides the same standards uplift; honor the WON'T-MERGE contract. Decide (open Q) whether the P2P herd-immunity overlay ships *on top of* pull-GitOps or is dropped — either way never a precondition. |
| **Hybrid KEM** (`hybrid_kem.py`) | **EVOLVE** | Swap **Kyber512 → ML-KEM-768 + X25519** per ADR 0002 `tls_kex`; route through the crypto-provider abstraction (no algorithm names at call sites). |
| **mirage (deception)** | **KEEP, repackage** | Maps to **HYDRA / Automate + Protect**. Keep the EventBus-driven honeypot orchestrator. |
| **steganography / traffic shaping** | **KEEP as option** | Optional DPI-evasion/censorship-resistance mode under `secure_tunnel` for hostile-network deployments; capability-gated, off by default. |
| **neurokernel (AI-SOC)** | **OUT OF SCOPE here; KEEP** | Detection/Investigate subsystem; not transport. Repackage per runtime-engine-map (Wasm for portable detection, container for heavy stateful). |

### 4.1 Revisiting ADR 0004 (the prior WireGuard+Rosenpass proposal)

**Verdict: AMEND, mostly STANDS — but fix the rationale and the scope.**

- **What stands:** For the **data-plane wire protocol**, moving to **WireGuard + Rosenpass** (or an equivalent DH/Noise + PQ-hybrid handshake) is **justified by concrete evidence**, not by reflex — the deployed tunnel genuinely has **no forward secrecy, no mutual crypto-auth, and a no-PSK fallback**. WireGuard's per-handshake ECDH + Rosenpass's PQ PSK directly fix exactly these gaps, on the same ARM hardware, with crypto-agility (ADR 0002). The QUIC control/roaming plane and GitOps/Nebula-style offline peer certs are good calls.
- **What must be amended:**
  1. ADR 0004's framing ("bespoke HTP … NSE 'nobody knows the key'") **conflated the experimental keyless/NSE narrative with the deployed PSK tunnel.** The real, evidenced reason to change the data plane is **forward secrecy + mutual auth**, not "it's bespoke." State that.
  2. **Do not throw away the operational envelope.** ADR 0004 reads as "replace HTP"; it should say "**keep the HookProbe VPN system (PBR/kill-switch/NAT/roaming/mobile-IKEv2) and swap only its cryptographic core.**" WireGuard gives you a wire protocol, not a kill switch or WAN-failover logic — that is V1 IP worth ~thousands of lines.
  3. **Upgrade the identity line from "reuse concepts" to "adopt the PUF identity code"** as the TPM-less IDevID path (it already exists and is correct).
  4. **Add an explicit "NSE → attestation" salvage line** so the genuinely innovative part is not lost in the deletion of the crypto claim.
- **What to discard from ADR 0004:** nothing major — but the **Classic McEliece 261 KB** note is a premium option, not a default; lead with ML-KEM-768.

**So: keep the HookProbe VPN, adopt WireGuard-class crypto inside it.** The answer to "keep proprietary VPN vs adopt WireGuard" is **both, at different layers** — proprietary *operations*, standards *cryptography*.

---

## 5. Open questions for the user to lock

1. **Data plane:** WireGuard+Rosenpass underneath the existing kill-switch/PBR envelope, **or** keep a HookProbe-owned dataplane but replace its handshake with **Noise-IK + ML-KEM-768 hybrid** (keeps full control of framing/roaming/stego, costs us a peer-reviewed handshake we'd have to commission)? Both fix forward secrecy; the trade is control vs. credibility.
2. **No-PSK fallback** (`htp_gateway.py:771`): confirm we remove it now even before the larger migration — it is a live downgrade-to-unauthenticated path.
3. **NSE salvage:** approve re-casting qsecbit/RDV/weight-replay as a **continuous-attestation Wasm module feeding QSECBIT + gating `fleet_mesh`**, and formally retire the "encryption / nobody-knows-the-key" claim from all docs.
4. **PUF as IDevID:** adopt `core/neuro/puf` as the device-identity provider for Pi 5 / RK3588, deriving the ADR 0002 hybrid (ML-DSA-65 + Ed25519) from the PUF composite — and decide the manifest `identity.idevid.type` taxonomy (`puf`/`tpm`/`dice`/`software`).
5. **DSM future:** ship the BFT mesh as an **optional intel overlay on top of pull-GitOps**, or drop P2P consensus for V2 and keep only DSM's IOC/bloom intel? (This is the standing fleet-model decision; until locked, all of it stays behind `fleet_mesh`, additive.)
6. **Crypto migration gate:** confirm ADR 0002 is a **hard precondition** for *any* mesh/VPN engine shipping — i.e. NSE-drop + Kyber512→ML-KEM-768 + RSA-fallback→real-BLS/ML-DSA must land before `secure_tunnel`/`fleet_mesh` are granted on any platform.
7. **TPM stance for Pi/RK3588:** PUF-only software-rooted identity as the default tier, external SPI TPM (SLB9670) as an upsell, or RK3588 OP-TEE fTPM — and record the assurance tier in the manifest.
