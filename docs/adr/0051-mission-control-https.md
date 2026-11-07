# ADR 0051 — Mission Control HTTPS: thin crypto provider, one suite, local name-constrained CA

**Status:** ✅ **Accepted by the operator 2026-11-07** (decisions 6 + 7 of the remaining-work table). Builds on
ADR 0050 D2 (TLS terminates in an EL0 server with its own heap). Clauses tagged **[realized]** / **[partial]**
/ **[vision]**.

## Context

Mission Control on heqk is served over plain HTTP on :80 (owner auth by an HttpOnly session cookie, ADR 0037
D3). The EL0 TLS spike (`docs/design/tls-el0-spike/`) showed `rustls` (no_std, unbuffered server) builds for
the EL0 target and interoperates (TLS 1.3, X25519, ECDSA) — using `rustls-rustcrypto`, an unaudited alpha.

## Decision

### D1 — Keep rustls' protocol layer; write only a thin provider over vendored primitives **[vision]**

- No `rustls-rustcrypto`. A minimal `CryptoProvider` in the EL0 TLS server, glue only — **no hand-written
  primitives**.
- **Server only, TLS 1.3 only, one suite:** `TLS_CHACHA20_POLY1305_SHA256`, key exchange **X25519**,
  certificate signature **ECDSA P-256 / SHA-256** (browsers do not accept Ed25519 server certificates).
- Primitive crates and their public audit status (checked 2026-11-07):

| Crate | Role | Status |
|---|---|---|
| `chacha20poly1305` 0.10 (already vendored) | record AEAD | NCC Group review (published 2020), no significant findings |
| `x25519-dalek` 2 / `curve25519-dalek` (already vendored) | key exchange | Quarkslab 2019 review of the dalek libraries, minor issues — predates the 4.x line in use |
| `p256` / `ecdsa` (new) | certificate signing | **No full independent audit** (crate docs disclaim one); a scoped zkSecurity 2025 review of field/group arithmetic + verification at one older commit. Signing path not covered → open risk, tracked |
| `sha2` / `hmac` / `hkdf` | key schedule | to verify before release |

- PQC: hybrid `X25519MLKEM768` is a follow-up (ML-KEM-768 is already vendored, `[P19-pqc-kat]`); until then the
  CBOM reports classical X25519 for Mission Control TLS.

### D2 — Browser trust = a local CA, name-constrained to the device **[vision]**

- Rejected: self-signed + pin-on-first-use (trains users to click through warnings); "owner-key-signed cert"
  (meaningless to a browser unless that key is a trusted CA — i.e. this option under another name).
- **Per-owner root CA** generated during **flasher provisioning** (task #20, browser flasher); the owner installs
  the root **once**, guided. The root carries an **X.509 Name Constraints** extension limiting it to the
  device's names (e.g. the `hookprobe.local` subtree + the device's assigned name) so a stolen root cannot mint
  certificates for other sites.
- Later option (not now): a publicly trusted certificate on a per-device hostname via the HookProbe cloud —
  smoother, with a privacy trade-off (device names become public via CT logs).

### D3 — Key custody **[vision]**

- The **TLS private key never touches the FAT boot partition** (readable by anyone holding the card). It is
  derived on the device from the SRK (`HKDF(SRK, "heqk-mc-tls-p256")`, like the device identity) and lives only
  in the EL0 TLS server's memory.
- Provisioning round-trip: on first boot the device publishes its TLS public key (serial line + `/api/health`
  field + the flasher's USB channel); the flasher signs the device certificate with the owner's CA and writes
  only the **certificate** (public) to the boot partition (`MCTLS.CRT`). The CA private key stays with the
  owner (flasher-side storage), never on the device.
- Until a certificate is provisioned the device serves HTTP only (today's behaviour) and says so.

### D4 — Serving **[vision]**

:443 alongside :80; once a certificate is installed, :80 redirects to https and the session cookie gains
`Secure`. TLS failures are counted on the heartbeat; an EL0 TLS server fault follows ADR 0050 D5 (the service
fails closed, is restarted; forwarding/IPS unaffected).

## Consequences

- No unaudited all-in-one provider in the product; a small reviewable surface (one suite, server only).
- `p256` signing is the weakest-reviewed link; it signs only the handshake transcript with a device key —
  documented as an open risk until reviewed.
- The CA flow couples to the browser flasher (task #20, another session's ownership) — the device side
  (D3 key derivation + publishing the public key + loading `MCTLS.CRT`) is built here; the flasher side is
  coordinated with that session.

## References

ADR 0002 (crypto agility / PQC), ADR 0037 D3 (owner auth), ADR 0050 (D2, D5), `docs/design/tls-el0-spike/`,
NCC Group RustCrypto AES-GCM/ChaCha20-Poly1305 review (2020), Quarkslab dalek review (2019), zkSecurity p256
review (2025).
