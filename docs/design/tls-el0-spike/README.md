# EL0 TLS feasibility spike (2026-11-07, task #21 S2, ADR 0050 D2)

Question: can Mission Control get HTTPS without a freeing allocator in the kernel TCB — i.e. as an EL0
server with its own heap (ADR 0050 D2)?

## Result

| Check | Result |
|---|---|
| `rustls` 0.23 (no_std, `UnbufferedServerConnection`) + `rustls-rustcrypto` + `talc` freeing allocator, `aarch64-unknown-none-softfloat`, build-std | **builds + links** (`el0/`) |
| Size (opt-level z, LTO) | `.text` 316 KiB, `.rodata` 21 KiB, heap arena 256 KiB (same size class as the EL0 Wasm host, ~326 KiB) |
| Interop, same provider + cert (`host/`, std build) | `curl` 200; `openssl s_client`: **TLSv1.3, TLS_AES_256_GCM_SHA384, X25519, ECDSA P-256** |
| Entropy | `getrandom` has no bare-metal backend → `register_custom_getrandom!` — on device a SYS call to the kernel's RNG200 (fail-closed), spike uses a stub |

## Findings that shape the real build

1. **Crypto provider maturity.** `rustls-rustcrypto` is `0.0.2-alpha` and unaudited. For a security product this
   is the main risk; alternatives: `ring` (needs C/asm for aarch64-none; check no_std build), or a small
   provider over the RustCrypto primitives heqk already vendors (ML-KEM, X25519, ChaCha20-Poly1305 —
   `securechannel.rs`). Decision needed before shipping.
2. **PQC.** The rustcrypto provider has no hybrid `X25519MLKEM768`. heqk already carries ML-KEM-768 (`[P19-pqc-kat]`)
   — a custom `SupportedKxGroup` would give hybrid KEX (ADR 0002 posture). Classical X25519 until then,
   reported honestly in the CBOM.
3. **Trim.** RSA is pulled in but unused (device key is ECDSA P-256): feature-gate it out.
4. **Certificate.** Per-device key derived from the SRK (like the device identity), self-signed cert minted on
   device or at the factory; the browser trust story (TOFU pin / owner-key-signed cert / local CA) is a UX
   decision for MissionControl.md.
5. **Time.** Server-side TLS needs no wall clock (no client-cert validation); SNTP time is available anyway.

## Next steps (not started)

EL0 server crate modeled on `el0-wasmhost` (detached crate, built by `kernel/build.rs`, loaded by the M5.1 ELF
loader); kernel ↔ server IPC carries TCP payload (smoltcp moves into the server per ADR 0050 D4 step 1);
`SYS_TRNG`; port 443 alongside 80 (80 → redirect); `mc-e2e` HTTPS leg.

Reproduce: `el0/` → `cargo build --release` (needs `.cargo/config.toml` + `rust-toolchain.toml` from
`kernel/heqk/el0-wasmhost`, and `cert.der`/`key.der` from `openssl req -x509 -newkey ec -pkeyopt
ec_paramgen_curve:P-256 …` — never committed). `host/` → `cargo run --release`, then `curl -k https://127.0.0.1:18443/`.
