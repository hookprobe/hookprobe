# Security Policy

HookProbe OS is an AI-native security operating system. We hold ourselves to the discipline we
build for others: **coordinated, confidentiality-first vulnerability disclosure**, aligned with the
practices the broader ecosystem is standardizing on (e.g. the Linux Foundation's Akrites
initiative — CVD, TLP, CVE/CWE/CVSS/EPSS/SSVC/VEX).

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately via one of:

- **GitHub Security Advisories** — "Report a vulnerability" on the repository's *Security* tab
  (preferred once the repository is public).
- **Email** — `security@hookprobe.com` *(operator: confirm/replace this address before publishing).*
  Encrypt sensitive reports with our published PGP key when available.

Please include: affected component (the heqk image, a kernel subsystem, `os/build/`, a Wasm module, or legacy `builder/`),
version / image digest, a description, reproduction steps or a PoC, and impact. Treat all
correspondence as **TLP:RED** until we jointly agree otherwise.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement of your report | within **3 business days** |
| Initial severity assessment (CVSS + reachability) | within **10 business days** |
| Coordinated fix + disclosure window | agreed with you, typically **≤ 90 days** |

We follow a **confidentiality-first coordinated disclosure** model: we validate, deduplicate,
score (CVSS/EPSS, and — for vulnerabilities in our own code — a reachability/**VEX** assessment
against the affected image), remediate, and publish the fix and advisory in a single synchronized
window, crediting the reporter unless anonymity is requested. Fixes to third-party/upstream
components we consume are reported upstream on the maintainers' terms.

## Scope

**In scope:** the heqk kernel and image (`os/kernel/`), Mission Control as served by heqk
(`os/mission-control/`), the build & signing pipeline (`os/build/`), and the trust model. The
legacy Linux tier (`legacy/linux-tier/`: `base/`, `modules/*`, `crates/`, `builder/`) still
receives security fixes (ADR 0047). Privilege boundaries (eBPF/XDP loaders, the Wasm sandbox), the
signing/trust store, the anti-spoof enforcement path, and data-at-rest are especially in scope.

**Out of scope:** issues that require an already-compromised host with root; theoretical findings
without a reachable path on a shipped image; vulnerabilities in third-party OSS we merely consume
(report those upstream — though we welcome a heads-up so we can ship a VEX statement and, where
warranted, a mitigation ahead of the upstream fix).

## Supported versions

The current release channel and the most recent prior release receive security fixes. Standalone
devices update transactionally with rollback: heqk uses A/B `tryboot` slots verified by `hboot`
(legacy Linux tier: bootc `upgrade`/`rollback` on UEFI, A/B image-sync on Pi — ADR 0019).

## Our security posture (what we already do)

- **Trust nothing unsigned.** heqk boot images are signed **hybrid Ed25519 + SLH-DSA-SHA2-128s**
  (`os/build/heqk-sign`) and verified fail-closed by `hboot` against the trust root in
  `os/kernel/boot-abi/src/verify.rs`. The control channel is Noise IK with an ML-KEM-768 hybrid,
  and Mission Control HTTPS offers TLS `X25519MLKEM768`. (Legacy Linux tier: cosign image signing,
  hybrid ML-DSA-65 + Ed25519 module signing, ADR 0016/0017.)
- **CBOM per image**; crypto-agile / PQC posture (ADR 0002) — the CBOM reports
  implemented-vs-roadmap honestly.
- **Gates:** `os/kernel/validate.sh` (QEMU phase gates) and `os/kernel/tools/mc-e2e.sh`
  (Mission Control API + browser) on every change, then CM5 metal. (Legacy Linux tier:
  `builder/gate-ladder.sh`.)
- **Behavioral, on-device enforcement** that catches exploitation regardless of patch status —
  the layer that defends the window between a vulnerability's disclosure and its fix reaching the
  device.

## Safe harbor

We will not pursue or support legal action against researchers who act in good faith, follow this
policy, avoid privacy violations and service disruption, and give us reasonable time to remediate
before public disclosure.
