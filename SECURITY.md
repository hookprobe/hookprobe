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

Please include: affected component (OS image, a specific module, `builder/`, a Wasm module),
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

**In scope:** the HookProbe OS image (`base/`), the modules (`modules/*`), the supervisor and
reconciler (`supervisor/`, `crates/`), the build & signing pipeline (`builder/`), and the
Platform Manifest / trust model. Privilege boundaries (eBPF/XDP loaders, the Wasm sandbox), the
signing/trust store, the anti-spoof enforcement path, and data-at-rest are especially in scope.

**Out of scope:** issues that require an already-compromised host with root; theoretical findings
without a reachable path on a shipped image; vulnerabilities in third-party OSS we merely consume
(report those upstream — though we welcome a heads-up so we can ship a VEX statement and, where
warranted, a mitigation ahead of the upstream fix).

## Supported versions

The current release channel and the most recent prior release receive security fixes. Standalone
devices update transactionally with rollback (bootc `upgrade`/`rollback` on UEFI platforms; A/B
image-sync on Raspberry-Pi-native platforms — see ADR 0019).

## Our security posture (what we already do)

- **Trust nothing unsigned.** OS images, Wasm modules, and manifests are cosign-signed; module
  signing is **hybrid ML-DSA-65 + Ed25519**, fail-closed with no downgrade (ADR 0016/0017).
- **SBOM + CBOM per image**, SLSA provenance; crypto-agile / PQC-ready posture (ADR 0002) — the
  CBOM reports implemented-vs-roadmap honestly.
- **A gate ladder** (`builder/gate-ladder.sh`) enforces tests, clippy, unit-lint, artifact-digest
  signing, provenance, and a behavioral-separation matrix on every build.
- **Behavioral, on-device enforcement** that catches exploitation regardless of patch status —
  the layer that defends the window between a vulnerability's disclosure and its fix reaching the
  device.

## Safe harbor

We will not pursue or support legal action against researchers who act in good faith, follow this
policy, avoid privacy violations and service disruption, and give us reasonable time to remediate
before public disclosure.
