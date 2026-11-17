# Security findings (outside the kernel)

2026-11-17, read-only. Severity is the agent's estimate; none is a confirmed exploit. No finding
is marked fixed without a reproducible validation.

## Authentication and write paths — no unauthenticated write found

Session: owner token → `/api/login` (`http.rs:367-370`), cookie `HttpOnly; SameSite=Strict`
(`:1202`), every `/api/*` requires the session (`:397`). UI writes go through `post()`
(`store/actions.ts:24-27`) with `X-HQ-CSRF` from `/api/session` and a strictly increasing `seq`.
Kernel checks Origin + CSRF + seq on every write (`actionapi.rs:96-102,147-151`;
`ownerapi.rs:162-171,509-518,583-592,665-674,741-750,808-817`; `upload.rs:221-230`), re-auth with
the owner token on sensitive writes, and an owner-signed Ed25519 HQMGMT1 envelope for config
confirm/rollback, upload activate/rollback, factory reset and anchor rotate. UI and kernel agree.

| ID | Finding | Severity | Owner |
|---|---|---|---|
| SF-01 | `/api/logout` checks only the session, no Origin/CSRF (`http.rs:372`); `?all=1` ends every session. A cross-site request is blocked by SameSite=Strict, so impact is limited to forced logout if SameSite is ever relaxed | low | homepods |
| SF-02 | `/api/login` checks Origin only when the header is present (`http.rs:367-370`) | low | homepods |
| SF-03 | `/api/actions/revoke` and upload chunk/finish/abort have no owner re-auth (they do have Origin+CSRF+seq) | info | homepods, by design? |
| SF-04 | Image signer `os/build/heqk-sign` has zero unit tests; G1 runs an empty `cargo test` (`tools/ci/gates.sh:101`) — a green step that tests nothing on the trust root's signer | medium (assurance) | operator (protected, Red) |
| SF-05 | Production trust chain open: TC-01..04 (key custody, OTP, fuses, RPMB) without signoffs; SEC-05 owner-key review not done | high for release | operator |
| SF-06 | A single downloadable image with one owner key (as getting-started describes) would give every buyer the same owner key | high if shipped as written | operator + docs |
| SF-07 | `legacy/v1` has placeholder default credentials in deploy scripts (`products/nexus/radius/clients.conf`, `deploy/cloud/config.sh`, `deploy/addons/n8n/config.sh`, `products/guardian/config/wpa_supplicant.conf`, `install.sh`, `scripts/install-edge.sh`, fortress scripts). None looked real; values not copied here | low (frozen code) | operator: allowlist or scrub |
| SF-08 | Owner-token security is ok, but there is no RBAC on heqk (single owner); ADR 0028 still reads "Implemented" (Linux tier only) | medium for MSSP | operator (ADR) |

## Clean

No committed private keys, tokens, `*.pem`, `*.key`, `.owner-key` or dev keys. PEM strings in
`os/mission-control/tests/ui/specs/*.mjs` are deliberate fixtures, allowlisted in `.gitleaks.toml`;
`secrets-scan.yml` and CodeQL are green.
