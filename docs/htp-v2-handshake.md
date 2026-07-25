# HTP v2 — Hardened Handshake Specification

**Status:** Reviewed twice — fixes applied (2026-06-28; see §7 + §8 changelogs). Implementable, **gated on the §6.2 formal (ProVerif/Tamarin) model** before final build. · **Date:** 2026-06-28 · **Author:** os-architect · **Reviews:** Director (expert) + independent adversarial cryptanalysis
**Implements:** [ADR 0004](adr/0004-secure-edge-transport.md) (evolve HTP, no WireGuard) · **Grounded in:** [ADR 0002](adr/0002-crypto-agility-pqc.md) (crypto = manifest policy), [ADR 0003](adr/0003-platform-manifest-schema.md) (manifest `crypto`/`identity` blocks).
**Scope:** the **edge VPN / mesh / fleet** key-agreement handshake (device↔gateway, device↔device). This is a **handshake / key-agreement change only** — the UDP/TUN data path and the operational envelope are unchanged (§3).

> One-line thesis: replace HTP v1's PSK-only, no-DH, server-only-TOFU handshake with a **signature-authenticated hybrid (PQC) Diffie-Hellman** handshake (SIGMA-I pattern), keeping the HTP framing and names (`HELLO/CHALLENGE/ATTEST/ACCEPT`), giving **forward secrecy + mutual PUF-anchored authentication + post-compromise security + downgrade resistance** with no change to the data plane.

---

## 1. V1 baseline — what the deployed handshake actually does, and its four gaps

Cited against the live code: client `products/fortress/lib/htp_vpn_client.py`, gateway `shared/mesh/htp_gateway.py`.

### 1.1 The V1 flow (HELLO → CHALLENGE → ATTEST → ACCEPT)

| Msg | Direction | Wire format (V1) | Code |
|---|---|---|---|
| `HELLO` (0x01) | client → gw | `version(2) | type(1) | node_id(32) | client_nonce(32) | flow_token(8)` = 75 B | client L866–874 |
| `CHALLENGE` (0x02) | gw → client | `version(2) | type(1) | challenge(32) [ | gw_pubkey(32) | sig(64)]` = 35 or **131** B | gw L710–723 |
| `ATTEST` (0x03) | client → gw | `version(2) | type(1) | hmac(32) | flow_token(8)` = 43 B | client L939–947 |
| `ACCEPT` (0x04) | gw → client | `version(2) | type(1) | assigned_ip(4)` = 7 B | client L966–987 |

- **Server identity (one-way):** the gateway signs `gateway_challenge + client_nonce` with a long-lived **Ed25519** key and ships `pubkey + sig` in `CHALLENGE` (gw L714–716). The client verifies it (client L900–905) and **TOFU-pins** the key in `vpn_known_hosts.json` (client L907, `_tofu_verify` L1000–1032). Server-only; the client presents **no asymmetric identity**.
- **Session key (no DH):** `IKM = client_nonce + gateway_challenge [+ PSK]`, then `session_key = HKDF-SHA256(IKM, salt="htp-vpn-session-salt-v2", info="htp-vpn-session-key-v2")` (client L925–930; gw L754–761; helper `_hkdf_derive` client L240–242, salts client L65–68). **There is no Diffie-Hellman or KEM** — the key is a deterministic function of two public nonces plus the PSK.
- **Client "auth" = key proof:** `ATTEST` carries `HMAC-SHA256(session_key, client_nonce + gateway_challenge)` (client L933–937); the gateway recomputes and compares (gw L764–770). Possession of the PSK (which feeds `session_key`) is the *only* thing the client proves.
- **AEAD (data path):** `ChaCha20-Poly1305`, random 12-byte nonce prepended (client `_encrypt_packet` L1038–1045 / `_decrypt_packet` L1047–1071). Data frame header `flow_token(8) | seq(4) | type(1)` (client L48).
- **REKEY:** gateway sends `enc(rekey_nonce)` under the **current** key (gw `_initiate_rekey` L979–985); client derives `new_key = HKDF(session_key + rekey_nonce, salt="htp-vpn-rekey-salt-v2", info="htp-vpn-rekey-v2")` (client `_handle_rekey` L1096–1100), ACKs by encrypting the nonce under the new key (L1102–1106), and keeps the old key for a 10 s grace window (`OLD_KEY_TTL`, L1116–1117).

### 1.2 The four gaps (exactly what HTP v2 fixes)

1. **No Diffie-Hellman → no forward secrecy.** `session_key` derives only from `client_nonce`, `gateway_challenge` (both sent in cleartext) and a long-lived PSK (client L927–930). An attacker who records traffic and *ever* learns the PSK can recompute **every past and future** session key from the on-wire nonces. There is no per-session secret that is destroyed after use.
2. **REKEY ratchets from the old key → no post-compromise security.** `new_key = HKDF(old_key + rekey_nonce)` (client L1096–1100) is a pure hash chain seeded by the compromised material; the `rekey_nonce` arrives **encrypted under the old key** (gw L984–985). Compromise of one `session_key` yields the entire forward chain. Rekeying adds no fresh entropy from a new key exchange.
3. **Client authenticated only by the PSK → no mutual asymmetric auth (and KCI-exposed).** The server proves an Ed25519 identity (gw L714–716) but the client proves only PSK knowledge via `ATTEST` (client L933). There is no client public-key identity, so: (a) any holder of the (often shared/fleet-wide) PSK is indistinguishable from the legitimate device; (b) the construction is open to key-compromise-impersonation — leaking the gateway's key lets an attacker impersonate the gateway *to* the client, and the symmetric PSK design gives no per-device cryptographic identity to bind against.
4. **The no-PSK gateway fallback (and localhost PSK-skip) → silent downgrade to unauthenticated.** On HMAC mismatch the gateway **retries without the PSK** and, on match, establishes a no-PSK session (gw L771–792, "matched WITHOUT PSK — using no-PSK session"). Localhost connections skip the PSK entirely (gw L757–761). Either path lets a peer that does not hold the PSK complete the handshake — the authenticator can be negotiated away.

> Net: V1 has **confidentiality** (a good AEAD) but its **authenticated key exchange is weak** — no FS, no PCS, no mutual asymmetric auth, and a downgrade-to-unauthenticated path.

---

## 2. HTP v2 handshake design

### 2.1 Chosen pattern — SIGMA-I (signature-authenticated DH), Noise-IK-equivalent flow

We model HTP v2 on **SIGMA-I** ("SIGn-and-MAc", the construction underneath IKEv2 and conceptually TLS 1.3), composed onto HTP's existing 2-RTT `HELLO/CHALLENGE/ATTEST/ACCEPT` framing.

**Why SIGMA and not raw Noise IK/XX:** Noise authenticates peers *implicitly*, via static **DH** keys mixed into the handshake hash. But HookProbe's device identity is a **PUF-anchored signing key** — `CompositeIdentity` derives an **Ed25519** keypair from the PUF composite secret (`core/neuro/puf/composite_identity.py`; see `tests/test_puf_identity.py` L274–284, 292–307), and ADR 0002/0003 specify the device identity as **hybrid `ml-dsa-65 + ed25519` signatures**, not an X25519 static key. Signature keys do not slot into Noise's DH-based auth. SIGMA is the standard, formally-analysed way to authenticate an **ephemeral** DH/KEM exchange with **signature** identity keys, and it composes cleanly with **hybrid** signatures (sign the transcript with both legs). It also gives us, by construction, the two properties V1 lacks at the auth layer: **KCI resistance** (signatures, not shared secrets, authenticate) and **identity-misbinding resistance** (the SIGMA MAC binds each identity to the session key).

**IK-equivalent vs XX-equivalent (deployment-dependent):**
- **Device ↔ gateway VPN (`secure_tunnel`):** **IK-equivalent.** The initiator (device) already knows the responder's (gateway's) static identity — today via TOFU pinning (client L1000–1032), in v2 via the manifest/LDevID trust anchor. The gateway authenticates the device by its enrolled **LDevID**. 1.5-RTT to first authenticated data.
- **Mesh / fleet peer ↔ peer (`fleet_mesh`):** **XX-equivalent.** Peers may not know each other a priori; both transmit and sign their static identity in-band, with responder identity protection. Same key schedule, one extra identity-carrying flight.

Both variants share the key schedule (§2.4) and identity binding (§4); they differ only in *when* each side's static identity pubkey appears on the wire. The rest of this section specifies the **IK-equivalent VPN variant**; the XX delta is called out in §2.7.

### 2.2 Cryptographic building blocks (all resolved from the manifest `crypto` block — never hardcoded)

| Purpose | Active primitive (suite `hookprobe-pqc-hybrid-2026`) | Manifest key (ADR 0002/0003) |
|---|---|---|
| Ephemeral KEX — classical | **X25519** | `crypto.tls_kex` (the `x25519` leg of `ml-kem-768+x25519`) |
| Ephemeral KEX — PQC | **ML-KEM-768** (FIPS 203) | `crypto.tls_kex` (the `ml-kem-768` leg) |
| Identity signatures (mutual) | **Ed25519 + ML-DSA-65** (hybrid composite, both must verify) | `crypto.device_identity` = `["ml-dsa-65","ed25519"]` |
| KDF | **HKDF-SHA-384** (extract+expand) | `crypto.hash` |
| Transcript hash | **SHA-384** | `crypto.hash` |
| AEAD (data + handshake records) | **ChaCha20-Poly1305** | unchanged from V1 |

The offered/selected suite is identified by `crypto.suite_id` and **bound into the transcript** (§2.6), so a future swap (e.g. `ml-kem-768` → `ml-kem-1024`, or dropping a classical leg) is a manifest edit, not a protocol change.

### 2.3 Messages (IK-equivalent VPN variant)

Frame prefix is unchanged: `version(2) | type(1) | …`. **`HTP_VERSION = 0x0002`** (was `0x0001`). All public-key/ciphertext fields are length-prefixed (`u16`) so suite changes that alter sizes need no format change. Because ML-KEM/ML-DSA fields are large (§2.8), handshake messages use the fragmentation header in §2.8.

Notation: `e` = ephemeral, `s` = static (identity). `epk`/`esk` = ephemeral X25519 pub/priv; `ek_pq`/`dk_pq` = ML-KEM encapsulation (public)/decapsulation (private) key; `ct_pq` = ML-KEM ciphertext. `||` = concatenation. `Sign_hybrid(sk, m)` = `Ed25519.Sign(sk_ed, m) || ML-DSA-65.Sign(sk_mldsa, m)`; verification requires **both** valid.

**Message 1 — `HELLO` (client → gateway), `PKT_HELLO` 0x01**
```
version(2)=0x0002 | type(1)=0x01
offered_suites      : u8 count, then count × suite_id (u16)   # negotiation, transcript-bound
node_id(32)                                                   # kept from V1
flow_token(8)                                                 # kept from V1
client_nonce(32)
client_epk          : X25519 ephemeral public key (32)
client_ek_pq        : ML-KEM-768 ephemeral encapsulation key (~1184 B)
gw_keyid_hint(32)   : fingerprint of the gateway static identity the client expects (IK)
```
No identity, no signature yet (initiator identity is deferred to `ATTEST` for identity protection, and to avoid signing before the responder is liveness-checked). The client keeps `esk`, `dk_pq` in memory only.

**Message 2 — `CHALLENGE` (gateway → client), `PKT_CHALLENGE` 0x02**
```
version(2) | type(1)=0x02
selected_suite(u16)                                          # chosen from offered_suites
gw_nonce(32)                                                 # was "challenge"
gw_epk              : X25519 ephemeral public key (32)
ct_pq               : ML-KEM-768 ciphertext = Encap(client_ek_pq) (~1088 B)  # → ss_pq
gw_static_pub       : hybrid identity bundle { ed25519_pub(32), ml_dsa_pub(~1952 B) }
gw_sig              : Sign_hybrid(gw_static_sk, "HTP-v2 server-auth" || th_auth_gw)
gw_mac              : MAC(k_mac, "HTP-v2 server-id" || gw_static_pub)
```
- The gateway runs `ss_pq = ML-KEM-768.Encap(client_ek_pq)` (producing `ct_pq` + `ss_pq`) and `ss_dh = X25519(gw_esk, client_epk)`, then derives the schedule (§2.4) from **`th_ks`** (key-share fields only) → it holds `k_mac`, `k_hs_g2c`/`k_hs_c2g`, and the data keys **before** any identity is processed.
- The gateway signs **`th_auth_gw = SHA-384(HELLO || CHALLENGE_ks || gw_static_pub)`** (§2.4), binding its identity to both ephemeral keys, the KEM pubkey+ciphertext, and `selected_suite`/`version`. (`CHALLENGE_ks` = the key-share fields, excluding `gw_static_pub`/`gw_sig`/`gw_mac`.)
- `gw_mac` (SIGMA's MAC leg) binds the gateway identity to the *derived session key* → defeats identity-misbinding/UKS.
- This **replaces** V1's TOFU-only server auth: the client verifies `gw_sig` against its pinned/LDevID trust anchor for `gw_keyid_hint`, **and** verifies `gw_mac` under `k_mac`. **The client MUST abort the handshake if either check fails — before deriving or sending any `ATTEST` material** (so the device identity is never revealed to an unauthenticated peer).
- *(Responder-identity hiding — optional for IK, MANDATORY for XX/mesh):* because `k_hs_g2c` derives from **`th_ks`** (which excludes `gw_static_pub`), the client derives it from the key-share fields alone, then **decrypts** `gw_static_pub`/`gw_sig`/`gw_mac` (sent as a ChaCha20-Poly1305 record under `k_hs_g2c`) and **then** verifies. The two-transcript split (§2.4) is exactly what makes this non-circular (Finding 1). Off by default for a public gateway; on for sensitive mesh responders.

**Message 3 — `ATTEST` (client → gateway), `PKT_ATTEST` 0x03**
```
version(2) | type(1)=0x03
flow_token(8)
client_static_pub   : hybrid identity bundle { ed25519_pub(32), ml_dsa_pub(~1952 B) }   # encrypted*
client_sig          : Sign_hybrid(client_static_sk, "HTP-v2 client-auth" || th_auth_client)  # encrypted*
client_mac          : MAC(k_mac, "HTP-v2 client-id" || client_static_pub)                # encrypted*
```
- `*encrypted` = this flight is sent as a **ChaCha20-Poly1305 record** under the **directional** handshake key `k_hs_c2g` (§2.4), with **AAD = the frame header** `version|type|flow_token` (binds the record to this handshake), giving the *initiator* identity protection against passive eavesdroppers. The gateway's successful decryption of this record is **key confirmation from the client**.
- `th_auth_client = SHA-384( HELLO || CHALLENGE || client_static_pub )` (CHALLENGE = the full message, incl. `gw_sig`/`gw_mac`). The client signature over `th_auth_client` is the **mutual-auth** step V1 never had: it transitively commits to the gateway's signed CHALLENGE and binds the device's PUF-anchored hybrid identity to the ephemeral keys, the gateway identity, and the negotiated suite/version.
- This **replaces** V1's `HMAC(session_key, …)` ATTEST. There is **no PSK-only path and no fallback** — a peer with no valid hybrid signature cannot complete the handshake.

**Message 4 — `ACCEPT` (gateway → client), `PKT_ACCEPT` 0x04**
```
version(2) | type(1)=0x04
record              : ChaCha20-Poly1305{ k_hs_g2c }( assigned_ip(4) | accept_flags )   # AAD = frame header
```
- The gateway verifies `client_sig` and `client_mac` (**aborting on failure**), then sends `ACCEPT` as an **AEAD record under the directional `k_hs_g2c`**. A valid tag is **key confirmation** for the client (proves the gateway reached the same keys) and authenticates `assigned_ip`. `REJECT` (0x05) stays a cleartext code.
- After `ACCEPT`, both sides switch to the directional data keys (§2.4) and the **unchanged** data path begins.

### 2.4 Key schedule

All key material derives from the **two ephemeral shared secrets** (FS), salted by the **transcript hash** (downgrade/identity binding), with optional PSK mixed in as an *additional* factor only:

```
ss_dh  = X25519(own_esk, peer_epk)            # classical ephemeral-ephemeral DH
ss_pq  = ML-KEM-768 shared secret             # client: Decap(dk_pq, ct_pq); gateway: from Encap
                                              # FS holds because dk_pq/esk are per-session, then wiped

IKM    = ss_dh || ss_pq [ || PSK ]            # hybrid concat: attacker must break BOTH KEX legs;
                                              # PSK (if configured) is extra entropy, NEVER the authenticator
# TWO-TRANSCRIPT SPLIT (TLS-1.3-style): the KEY SCHEDULE salts ONLY with the key-share
# transcript th_ks, which EXCLUDES the identity bundles — this breaks the circular dependency
# that otherwise makes responder-identity hiding (and the XX/mesh variant) UNIMPLEMENTABLE.
th_ks          = SHA-384(HELLO || CHALLENGE_ks)   # CHALLENGE_ks = version|type|selected_suite|gw_nonce|gw_epk|ct_pq
                                                  #   (NO gw_static_pub / gw_sig / gw_mac)
PRK    = HKDF-Extract(salt = th_ks, IKM)          # keys depend only on version+suite+ephemerals+KEM, NOT on identities

# AUTH transcripts — used by the SIGNATURES only (these DO include the identities):
th_auth_gw     = SHA-384(HELLO || CHALLENGE_ks || gw_static_pub)
th_auth_client = SHA-384(HELLO || CHALLENGE     || client_static_pub)   # CHALLENGE = full msg incl gw_sig/gw_mac

k_hs_c2g      = HKDF-Expand(PRK, "htp-v2 hs c2g",     32)   # AEAD: client→gw handshake records (ATTEST) + initiator identity hiding
k_hs_g2c      = HKDF-Expand(PRK, "htp-v2 hs g2c",     32)   # AEAD: gw→client handshake records (ACCEPT) + optional responder identity hiding
k_mac         = HKDF-Expand(PRK, "htp-v2 sigma-mac",  32)   # SIGMA identity-MAC key
k_c2g         = HKDF-Expand(PRK, "htp-v2 data c2g",   32)   # client→gateway data AEAD
k_g2c         = HKDF-Expand(PRK, "htp-v2 data g2c",   32)   # gateway→client data AEAD
k_rekey_seed  = HKDF-Expand(PRK, "htp-v2 rekey-seed", 32)   # chaining input for REKEY v2 (§2.5)
```

- **Forward secrecy:** `IKM` contains only **ephemeral** secrets; `esk` and `dk_pq` are zeroized after derivation. Compromise of any long-lived identity/PSK does **not** recover a past session key (contrast V1 gap #1).
- **Hybrid KEX combiner:** concatenation `ss_dh || ss_pq` fed through HKDF-Extract is the IETF-style hybrid combiner — secure as long as *either* primitive holds (defends against both a quantum break and a young-PQC-impl bug).
- **Directional keys are MANDATORY — handshake *and* data.** Both the handshake records (`k_hs_c2g`/`k_hs_g2c`) and the data path (`k_c2g`/`k_g2c`) use **per-direction** keys feeding the unchanged `ChaCha20-Poly1305` path (client L1038–1071). This eliminates the V1 same-key-both-directions risk **and** the analogous handshake-record hazard: a single shared handshake key would let `ATTEST` (c2g) and `ACCEPT` (g2c) reuse the same `(key, nonce)` → keystream **and** Poly1305 one-time-key reuse → confidentiality + forgery break. There is **no single-`session_key` mode**; never share one AEAD key across both directions. Each direction keeps its own nonce counter; every AEAD record (handshake + data) sets **AAD = the frame header**.
- **What is signed (precise):** the gateway signs `"HTP-v2 server-auth" || th_auth_gw`; the client signs `"HTP-v2 client-auth" || th_auth_client`. These **auth** transcripts include the identity bundles (unlike `th_ks`, which the key schedule uses), so the signatures bind each identity to the ephemeral keys, the KEM pubkey+ciphertext, the peer's contributions, and the negotiated suite/version — while the **keys themselves never depend on an identity** (this is what makes responder-identity hiding non-circular, Finding 1). Distinct context strings prevent reflection/cross-protocol misuse.

### 2.5 REKEY v2 — fresh ephemeral exchange (post-compromise security)

V1 rekey is a hash ratchet off the old key (gap #2). HTP v2 rekey performs a **new ephemeral KEX**, so a one-time key compromise heals after the next rekey. We keep the names `PKT_REKEY` (0x18) / `PKT_REKEY_ACK` (0x19), the grace window, and `OLD_KEY_TTL`.

```
REKEY      (gw → client, AEAD under current k_g2c):  gw_epk' (32) | gw_ek_pq'? | rekey_id
REKEY_ACK  (client → gw, AEAD under current k_c2g):  client_epk' (32) | ct_pq' | rekey_id
```
- Both sides contribute a **fresh** X25519 ephemeral (and a fresh ML-KEM exchange); identity is **not** re-sent (it is already established and the records are authenticated by the current AEAD keys, proving liveness).
- New secrets: `ss_dh' = X25519(esk', peer_epk')`, `ss_pq'` from the fresh KEM. New schedule:
  ```
  PRK'   = HKDF-Extract(salt = k_rekey_seed, IKM = ss_dh' || ss_pq')
  k_c2g' = HKDF-Expand(PRK', "htp-v2 data c2g", 32);  k_g2c' = … ;  k_rekey_seed' = …
  ```
  Using the previous `k_rekey_seed` as the **salt** preserves session continuity, but every new key requires **fresh ephemeral private keys** that an attacker holding only the old key cannot derive. Old keys held for `OLD_KEY_TTL` (10 s) then zeroized (matches V1 grace handling, client L1116–1117).
- **PCS scope (precise).** An AEAD-authenticated REKEY heals a **passive** key compromise — an attacker who merely *recorded* old key material cannot derive the post-rekey keys (the new ephemerals are independent). It does **not**, on its own, evict an **active** attacker who holds the *current* `k_c2g`/`k_g2c`: since the lightweight rekey re-sends no identity, such an attacker can ride/hijack it. Full PCS against an active adversary requires **re-authentication**.
- **Mandatory periodic re-authentication.** A session MUST perform a **re-signed REKEY** — re-running the SIGMA signature leg over a fresh transcript, re-proving both hybrid identities — at least once per `REAUTH_MAX_AGE` (default: 1 h or a byte budget, whichever first). Lightweight AEAD-authenticated rekeys run between re-auths for fresh data keys + passive PCS. This **bounds the active-attacker window to `REAUTH_MAX_AGE`**.

### 2.6 Downgrade / rollback resistance

- `offered_suites` (HELLO) and `selected_suite` (CHALLENGE) are inside `th_1`/`th_2`, which are **signed by both peers**. A MITM that strips the PQC leg, forces a weaker suite, or rolls the version back changes the transcript → **both** hybrid signatures fail. There is no unauthenticated negotiation surface.
- **Version anti-rollback (hard rule):** `version` (`0x0002`) is the first signed transcript byte. **A device with a provisioned v2 identity (IDevID/LDevID) MUST NOT initiate or accept a v1 handshake** — it never falls back, so an in-band downgrade cannot succeed against a provisioned device. Only un-provisioned/legacy peers run v1, and only during the migration window (§5); the gateway closes even that per-ring via the v2-only cutover.

### 2.7 Removal of the no-PSK fallback (and the PSK's new, demoted role)

- The gateway's "try without PSK" path (gw L771–792) and the localhost PSK-skip (gw L757–761) are **deleted**. In v2 the authenticator is the **mandatory hybrid signature** over the transcript; there is no code path that accepts a peer lacking a valid `client_sig`/`client_mac`.
- A PSK MAY still be configured, but **only** as an *additional* factor mixed into `IKM` (`ss_dh || ss_pq || PSK`). A wrong/missing PSK changes the derived keys, so `ACCEPT`'s key-confirmation tag fails — but the PSK can never, alone, authenticate a peer. Default deployments need no PSK at all (the device identity replaces it).

### 2.8 Engineering notes (sizes, fragmentation, DoS)

- **Message sizes** (ML-KEM-768 / ML-DSA-65, approx): encapsulation key ~1184 B, ciphertext ~1088 B; ML-DSA-65 pubkey ~1952 B, signature ~3309 B. So `CHALLENGE` (gw ephemerals + ct + hybrid pubkey + hybrid sig) ≈ **6–7 KB**; `ATTEST` ≈ **5–6 KB**. These exceed the path MTU.
- **Handshake fragmentation (required):** handshake frames carry a fragmentation sub-header `msg_id(u16) | frag_off(u16) | frag_len(u16) | total_len(u16)` after `version|type`; the receiver reassembles before parsing. This is a handshake-only concern — the **data path keeps `TUN_MTU=1400` and per-packet framing unchanged**. Reassembly buffers are bounded and time-limited (anti-memory-DoS).
- **Anti-DoS retry cookie (required):** because `CHALLENGE` makes the gateway do a KEM encapsulation + two signatures, an unauthenticated `HELLO` flood is amplifiable. The gateway issues a **stateless retry cookie** (HMAC over client addr + timestamp, à la DTLS/WireGuard cookie) and only performs expensive crypto after the client echoes a valid cookie. The cookie round trip is skipped when the gateway is unloaded.
- **Handshake anti-replay:** `client_nonce`/`gw_nonce` (32 B each) plus the per-handshake `flow_token` bound into the transcript prevent replay of a recorded handshake; the gateway tracks recent `(node_id, nonce)` to reject duplicates within the cookie window.

### 2.9 Binding & validation rules (second-review hardening)

MUST-level rules surfaced by the independent adversarial review; they close gaps the message layout alone does not:

- **Identity vs handle — `node_id` (Finding 2).** `node_id` is an attacker-chosen handle. The gateway MUST NOT use the wire `node_id` for any security decision (IP/ACL/PBR-scope `0x300`/tenant/attribution); it uses **only** the verified IDevID/LDevID. Either derive `node_id = fingerprint(client_static_pub)` and reject mismatches, or ignore it entirely for authz.
- **Suite floor (Finding 6).** Signed negotiation stops *tampering*, not a legitimately-offered weak suite. Each endpoint MUST reject any `offered`/`selected_suite` below its manifest policy floor, and MUST require **both** hybrid legs (`ml-kem-768+x25519` KEX, `ml-dsa-65+ed25519` sig) when policy demands them — regardless of what a suite "permits."
- **KEX input validation (Finding 4).** Reject an all-zero `ss_dh` / low-order `peer_epk` (X25519 is non-contributory, RFC 7748) — never silently collapse to PQC-only. Apply FIPS 203 encapsulation-key + ciphertext input validation before any ML-KEM op.
- **DoS-cookie binding (Finding 3).** The retry cookie MUST bind `node_id` + `H(client_ek_pq)` and be short-lived/low-count, so one cookie authorizes **one** pending handshake — not a real-IP flood of ML-KEM-Encap + dual-signing. Add per-validated-source rate limiting on the expensive path.
- **Tenant binding (Finding 8).** Include `identity.tenant` (+ LDevID issuer/serial) in the signed auth transcripts; the gateway verifies the handshake realm matches its own (defence-in-depth for recursive multi-tenancy).
- **Data nonces & epochs (Finding 7).** Data AEAD uses per-direction, **per-epoch counter** nonces, reset to 0 on each rekey (the key changes, so no reuse); add a `rekey_id`/epoch tag to the data frame (or document trial-decryption during the `OLD_KEY_TTL` grace). State the per-key record cap.
- **REKEY public-value binding (Finding 9).** Fold `rekey_id || gw_epk' || client_epk' || ct_pq'` into `PRK'` (Extract salt or Expand info), matching the initial handshake's ciphertext+pubkey binding (X-Wing-style). Compute every transcript over the **reassembled, fragment-header-stripped** logical message.
- **Software-PUF tier custody (Finding 5).** On TPM-less boards use **hedged ML-DSA** signing (deterministic keygen + fault attacks → online key recovery otherwise); document that the `software` tier offers **no clone resistance** (a single PUF + public-helper-data leak permanently clones the identity, with no key to rotate), and have QSECBIT down-weight its trust accordingly.
- **XX role assignment.** For symmetric mesh peers, fix initiator=client-role / responder=gateway-role deterministically (e.g., by node-id ordering) so the `*-auth`/`*-id` context strings cannot be confused under simultaneous open.

---

## 3. What stays unchanged (this is a key-agreement change, not a rewrite)

Explicitly **carried forward as-is** from V1:

- **The UDP/TUN data path** and its framing: `flow_token(8) | seq(4) | type(1)` (client L48), `TUN_MTU=1400`, the read/encrypt/send and recv/decrypt/write loops.
- **ChaCha20-Poly1305 AEAD** for every data packet (client L1038–1071) — only the *key source* changes (directional keys from the new schedule); the cipher, nonce handling, and tag are identical.
- **The entire operational envelope** — the crown jewel ADR 0004 insists on keeping: the three-mode **kill switch** (OFF/HOST/FULL), **PBR routing table 300 / fwmark 0x300** (client L80–83), **NAT**, **WAN failover** coexistence (tables 100/200), **roaming**/NAT-rebinding handling, keepalives, reconnect/backoff, and the `atexit` fail-safe. None of these touch key agreement.
- **Per-interface fail-open (default) / fail-closed** posture and the standalone-first stance.

HTP v2 changes only: the handshake messages' *contents*, the key schedule, REKEY's key source, and the removal of the no-PSK fallback. A reviewer can audit the change surface in isolation from the dataplane.

---

## 4. Identity binding — PUF/NEURO → signing key (802.1AR-style), and TPM tiers

### 4.1 The chain: PUF composite secret → hybrid IDevID → enrolled LDevID

HookProbe already derives an **Ed25519** identity from on-device PUFs: `CompositeIdentity` mixes PUF sources (SRAM / clock-drift / cache-timing), runs a **fuzzy extractor** for noise tolerance, and expands the composite secret into an `ed25519_seed` → Ed25519 keypair (`tests/test_puf_identity.py` L274–284, 292–324; `core/neuro/puf/composite_identity.py`). Crucially the **private key is never stored** — it is regenerated at boot from the PUF + helper data (the degraded-mode and provisioning tests, L513–518, 715–724).

HTP v2 binds to this as the device's **IDevID** (IEEE 802.1AR birth identity), extended to the **hybrid** posture ADR 0002/0003 require:

```
puf_secret  = FuzzyExtractor.rep(puf_reading, helper_data)        # 32 B, hardware-anchored, never stored
seed_ed     = HKDF-Expand(puf_secret, "htp idevid ed25519", 32)   # → Ed25519 identity keypair
seed_mldsa  = HKDF-Expand(puf_secret, "htp idevid ml-dsa-65", 32) # → ML-DSA-65 identity keypair (deterministic keygen)
IDevID_pub  = { ed25519_pub, ml_dsa_pub }                         # the hybrid bundle signed in ATTEST/CHALLENGE
```
- `manifest.identity.idevid.pubkey_fpr` = `SHA-256(IDevID_pub bundle)`; `crypto.device_identity = ["ml-dsa-65","ed25519"]` (ADR 0003 schema). This is the trust anchor a gateway/peer authenticates against.
- **Standalone mode:** the IDevID is the identity; the gateway pins it TOFU-style on first claim (same trust model as V1's `vpn_known_hosts.json`, but now mutual and hybrid).
- **Enrolled mode (MSSP / self-hosted CP):** on enrollment the device obtains an **LDevID** — a tenant-scoped credential/cert over the IDevID public bundle, signed by the tenant CA — and authenticates with the LDevID inside its tenant. `manifest.identity.claim_state` moves `unclaimed → claimed → enrolled`; `identity.tenant` is set. This is the 802.1AR IDevID→LDevID lifecycle.

### 4.2 Keystore tiers per board (recorded in `manifest.identity.idevid.type` / `sealed`)

| Tier | Boards | `idevid.type` | Where the identity private key lives |
|---|---|---|---|
| **TPM-sealed** | N100 / appliances with discrete or firmware TPM 2.0 | `tpm` | Keys generated/held in TPM; `sealed:true`, bound to PCR policy; PUF may still seed but the TPM is the keystore. Highest assurance. |
| **DICE** | SoCs exposing a DICE/CDI chain | `dice` | Identity derived along the DICE measured-boot chain; `sealed:true`. |
| **Software-PUF** | Pi 5 / CM5 / RK3588 (no TPM) | `software` | **Never stored**; regenerated each boot from PUF + helper data via fuzzy extractor; `sealed:false` but hardware-anchored. This is the common Pi path (ADR 0003 notes `type=software` is typical for Pi 5/CM5). |

The handshake is **identical** across tiers — it always authenticates the same hybrid `IDevID_pub`/LDevID bundle. The tier only changes *where the private key is custodied and how strongly it is sealed*, surfaced honestly in the manifest so the operator (and QSECBIT scoring) can weight trust accordingly. Capabilities, not branches: the handshake code reads `crypto.device_identity` + the LDevID, never "is this a Pi?".

---

## 5. Migration — backwards-incompatible, dual-stack per rollout ring

HTP v2 is **not wire-compatible** with v1 (different `CHALLENGE`/`ATTEST` contents; no PSK-only path). Migration uses the version field and the fleet rings:

1. **Version discriminator.** Every handshake's first two bytes are `version`. `v1 = 0x0001`, `v2 = 0x0002`. A v2-capable gateway **dual-stacks**: it runs the v1 state machine for a `0x0001` HELLO and the v2 state machine for `0x0002`, during the transition window only.
2. **Staged rollout (canary → ring → fleet, health-gated)** per ADR 0004 and the GitOps ring model:
   - *Ring 0 (canary):* push v2-capable client + dual-stack gateway. Devices negotiate v2; v1 still accepted fleet-wide.
   - *Ring N:* widen. A device is "migrated" once it has a provisioned hybrid IDevID/LDevID and has completed a v2 handshake.
   - *Cutover:* when a ring is fully v2 (telemetry confirms zero v1 handshakes from it), flip the **gateway policy for that ring to v2-only** — it then `REJECT`s `0x0001`. This closes the downgrade window per-ring rather than fleet-wide, so a straggler never blocks others and a bad ring can roll back.
3. **Remove the legacy surface** once the fleet is fully v2: delete the v1 state machine, the **no-PSK fallback** (gw L771–792), the **localhost PSK-skip** (gw L757–761), and the V1 `HMAC`-based `ATTEST`. Also retire keyless-HTP / NSE-as-encryption per ADR 0004.
4. **Crypto-agility preserved.** Because the suite is `crypto.suite_id` policy negotiated and transcript-bound, future swaps (e.g. ML-KEM-768→1024, or dropping the classical leg post-2030) are a manifest re-sign + ring rollout — **not** another protocol migration.

**Residual migration risk:** the dual-stack window is exactly when both versions coexist; keep it short per ring, monitor for any unexpected v1 handshakes after a ring is declared migrated (could indicate a downgrade attempt or an un-provisioned device), and alert.

---

## 6. Security properties — V1 vs V2, and open questions

### 6.1 Properties delta

| Property | HTP v1 | HTP v2 | How v2 achieves it |
|---|---|---|---|
| **Forward secrecy** | ❌ key = f(nonces, PSK) only (client L927–930) | ✅ | Ephemeral X25519 + ML-KEM-768; `esk`/`dk_pq` zeroized after use (§2.4) |
| **Mutual asymmetric auth** | ❌ server Ed25519 only; client = PSK (gw L714 / client L933) | ✅ | Both sign the transcript with PUF-anchored hybrid Ed25519+ML-DSA-65 (§2.3) |
| **Post-compromise security** | ❌ rekey = HKDF(old_key+nonce) (client L1096) | ✅ passive · active ≤ `REAUTH_MAX_AGE` | REKEY v2 = fresh ephemeral KEX heals passive compromise; mandatory re-signed re-auth bounds active recovery (§2.5) |
| **Downgrade / rollback resistance** | ❌ no-PSK fallback (gw L771–792); unsigned negotiation | ✅ | Suite+version inside signed transcript; fallback removed (§2.6–2.7) |
| **KCI resistance** | ❌ symmetric/TOFU exposure | ✅ | SIGMA signatures authenticate, not shared secrets |
| **Identity-misbinding / UKS resistance** | ❌ | ✅ | SIGMA MAC binds each identity to the session key (§2.3) |
| **Initiator identity protection** | n/a (no client identity) | ✅ | Client identity flight encrypted under `k_hs` (§2.3) |
| **PQC / quantum resistance** | ❌ classical/PSK only | ✅ | Hybrid ML-KEM-768 KEX + ML-DSA-65 signatures (§2.2) |
| **Confidentiality (data path)** | ✅ ChaCha20-Poly1305 | ✅ (unchanged) | Same AEAD, now with directional keys (§3) |
| **Crypto-agility** | ❌ algorithms hardcoded | ✅ | Suite from manifest `crypto`, negotiated + transcript-bound (§2.2) |

### 6.2 Open questions (lock before/with implementation)

1. **IK vs XX per deployment.** Confirmed split: IK-equivalent for device↔gateway, XX-equivalent for mesh/fleet (§2.1). Open: do we want a *single* unified XX-style flow everywhere to reduce code paths, accepting the extra flight on the VPN? (Ties to ADR 0004 open-Q: one module or two for `secure_tunnel` vs `fleet_mesh`.)
2. **Formal review.** SIGMA-I is analysed in the literature, but our **hybrid-signature + hybrid-KEM** composition and the rekey chaining should get an independent pass — ideally a **ProVerif/Tamarin** model (the bar ADR 0004 set by citing Rosenpass). Who owns it and on what timeline?
3. **Exact crates (Rust).** Proposed: `x25519-dalek` (KEX classical) + RustCrypto **`ml-kem`** (KEX PQC) + `ed25519-dalek` (sig classical) + **`ml-dsa`** (sig PQC) + `chacha20poly1305` (AEAD) + `hkdf`/`sha2`. All behind the ADR 0002 crypto-provider abstraction (no algorithm names at call sites). Pin versions and confirm `ml-kem`/`ml-dsa` maturity + constant-time guarantees; for FIPS deployments consider `aws-lc-rs`.
4. **PSK — keep as optional second factor or drop entirely?** Spec keeps it demoted to an extra `IKM` input (§2.7); ADR 0004 leaves this open. Decision needed: default-off vs offer-as-hardening.
5. **Directional vs single data key.** §2.4 recommends directional `k_c2g`/`k_g2c`; confirm the data path adopts both (best) or keeps one `session_key` for minimal diff.
6. **Re-auth cadence on long sessions.** Default is AEAD-only REKEY without re-signing (§2.5); decide a max session age after which a full re-signed handshake is forced.
7. **DoS cookie + fragmentation parameters.** Lock the retry-cookie threshold, reassembly buffer caps, and handshake timeout (V1 `HANDSHAKE_TIMEOUT=15` s) given the larger PQC messages (§2.8).
8. **Manifest schema touch.** Confirm whether `crypto` needs an explicit `tunnel_kex`/`tunnel_auth` pair distinct from `tls_kex`/`tls_auth`, or whether the HTP handshake reuses the existing TLS entries (proposal: reuse `tls_kex` for KEX, `device_identity` for auth — already present in ADR 0003). Coordinate with manifest owners (do not edit `manifest/**` here).

---

## 7. Review changelog (2026-06-28)

Director security review of the draft; fixes applied in-place:

1. **[fixed · high] Handshake-record nonce reuse.** The draft used a single `k_hs` for both `ATTEST` (c2g) and `ACCEPT` (g2c) → potential ChaCha20-Poly1305 `(key, nonce)` reuse. Split into directional `k_hs_c2g` / `k_hs_g2c` (§2.3, §2.4); removed the single-`session_key` drop-in; mandated per-direction nonce counters + frame-header AAD on every record.
2. **[fixed · med] Post-compromise-security claim over-stated.** REKEY-without-re-sign heals only *passive* compromise; an active attacker holding current keys can hijack it. Qualified PCS (passive vs active) and made a **re-signed** re-auth mandatory per `REAUTH_MAX_AGE` (§2.5, §6.1).
3. **[fixed · med] Version-downgrade not fully closed.** Added the hard rule: a v2-provisioned device MUST NOT initiate/accept v1 (§2.6).
4. **[fixed · low] Explicit abort-on-fail** before the client reveals its identity; **AAD** specified for handshake AEAD records; **optional responder-identity hiding** for IK (§2.3).

**Unchanged & confirmed sound:** SIGMA-I pattern, transcript-hash signing, hybrid combiner (ciphertext bound via the transcript salt), ephemeral-KEM forward secrecy, KCI / identity-misbinding (UKS) resistance, initiator identity protection, suite-downgrade resistance, DoS cookie, fragmentation, anti-replay.

**Still open (per §6.2):** an independent **ProVerif/Tamarin** model of the hybrid-sig + hybrid-KEM + rekey composition is recommended before this is the final build target — an expert review is not a proof.

## 8. Second review — independent cryptanalysis (2026-06-28)

A fresh cryptanalyst pass (web-grounded vs SIGMA / TLS 1.3 / Noise / X-Wing / FIPS 203/204) on the §7-fixed spec. Findings fixed in-place above:

1. **[fixed · HIGH] Circular key-derivation in responder-identity hiding (Finding 1).** The key schedule salted with a transcript that *included* `gw_static_pub`, so deriving `k_hs_g2c` required the very value it was meant to hide → the mandatory XX/mesh mode was unimplementable. **Fixed** with a TLS-1.3 **two-transcript split**: `th_ks` (key-share only) for the key schedule; `th_auth_gw`/`th_auth_client` (incl. identities) for the signatures (§2.3, §2.4).
2. **[fixed · MED→HIGH] `node_id` not bound to verified identity (Finding 2)** → §2.9 (use only the verified IDevID/LDevID for authz).
3. **[fixed · MED] Residual asymmetric DoS after the cookie (Finding 3)** → §2.9 (cookie bound to `node_id`+`H(ek_pq)`, single-use, rate-limit).
4. **[fixed · MED] X25519 all-zero / KEM input validation unspecified (Finding 4)** → §2.9.
5. **[fixed · MED] Suite floor implicit (Finding 6)** → §2.9 (reject below-floor, require both hybrid legs).
6. **[fixed · MED] Software-PUF clone-once + deterministic ML-DSA fault risk (Finding 5)** → §2.9 (hedged ML-DSA; honest no-clone-resistance note; QSECBIT down-weight).
7. **[fixed · LOW→MED] Data-nonce contradiction / no epoch tag (Finding 7); tenant not bound (Finding 8); REKEY public values not folded + frag-transcript (Finding 9); XX role assignment** → §2.9.

**Confirmed sound by the second review:** SIGMA sign/MAC split, role/reflection separation (distinct context strings + fresh nonces), KCI (IK responder side), hybrid-KEM combiner binding (ciphertext+pubkey via the transcript salt — more conservative than X-Wing), ephemeral-KEM forward secrecy, ML-KEM implicit-rejection (no decap oracle), key-schedule domain separation, PSK fail-closed demotion, negotiation-tamper detection.

**Verdict:** the core AKE is sound and a large improvement over V1; with Findings 1–6 closed (done) it is implementable and defensible. **A ProVerif/Tamarin model remains a gate before final build** — the composition (hybrid-sig + hybrid-KEM + SIGMA-with-rekey) is novel in three dimensions at once, and a symbolic identity-secrecy query is exactly what flagged Finding 1.

---

## Sources

Live code: `products/fortress/lib/htp_vpn_client.py` (L48, L65–68, L80–83, L240–242, L866–987, L1000–1071, L1096–1119); `shared/mesh/htp_gateway.py` (L94–108, L256–291, L313–317, L700–792, L979–1001); `tests/test_puf_identity.py` (PUF→Ed25519 identity, L274–324, L478–518, L715–724). V2 docs: ADR 0004 (evolve HTP), ADR 0002 (crypto-agility/PQC), ADR 0003 (manifest `crypto`/`identity`). External: SIGMA ("SIGn-and-MAc", Krawczyk); Noise Protocol Framework (IK/XX patterns); TLS 1.3 / IKEv2 authenticated DH; FIPS 203 ML-KEM / FIPS 204 ML-DSA; IETF hybrid KEM combiner drafts; IEEE 802.1AR (IDevID/LDevID); RustCrypto `ml-kem`/`ml-dsa`, `x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`.
