# heqk-tlsprov — the thin rustls provider (ADR 0051 D1)

One suite (`TLS13_CHACHA20_POLY1305_SHA256`), X25519, ECDSA P-256/SHA-256 server key, injected entropy
(fail-closed). Glue only over `chacha20poly1305`, `x25519-dalek`, `sha2`, `hmac`, `p256`.

- Bare-metal build (EL0 target, via the parent `.cargo/config`): `cargo build --release`
- Host unit tests: `cargo test --release --target x86_64-unknown-linux-gnu -Z build-std=std,panic_abort`

Interop (2026-11-07, host server on this provider): `curl --cacert` 200; `openssl s_client` TLSv1.3 /
TLS_CHACHA20_POLY1305_SHA256 / X25519 / ECDSA, verify OK; AES-GCM-only client → `NoCipherSuitesInCommon`;
P-384-only client → `NoKxGroupsInCommon`.
