# Security

| Topic | Where |
|---|---|
| Reporting a vulnerability | [`SECURITY.md`](../../SECURITY.md) |
| On-device security code (index) | [`os/security/`](../../os/security/) |
| Kernel TCB audit | [`os/kernel/SECURITY_AUDIT.md`](../../os/kernel/SECURITY_AUDIT.md) |
| Boot signing identity + key custody | [heqk-signing-identity](../design/heqk-signing-identity.md), ADR 0046 |
| Crypto agility / PQC | ADR 0002 · heqk boot: Ed25519 + SLH-DSA-128s · channel: ML-KEM + X25519 |
| Enforcement separation (legit traffic always passes) | ADR 0023 |
| Adversarial reviews | [`docs/design/`](../design/) (`*adversarial*`, `*peer-review*`) |
| Secret scanning | `.gitleaks.toml`, [`tools/build/git-hooks/pre-push`](../../tools/build/git-hooks/pre-push) |
