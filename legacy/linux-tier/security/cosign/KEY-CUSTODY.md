# Key custody — signing keys live OFF-device (ADR 0002 §5)

> **The single biggest PQC footgun is stateful hash-based signatures (LMS/XMSS): reusing
> a one-time leaf index catastrophically breaks the scheme (SP 800-208 is emphatic). We
> avoid it architecturally.** This note is the operational guard ADR 0002 says the
> release tooling MUST enforce; `security` reviews it (ADR 0002 "Validation").

## The custody split (non-negotiable)

| Key | Algorithm | Where the PRIVATE/signing key lives | Devices |
|---|---|---|---|
| **OS image signing** | composite ML-DSA-65 + Ed25519 | offline release HSM / KMS — never in repo, CI checkout, or image | **verify only** |
| **Module / sysext signing** | composite ML-DSA-65 + Ed25519 | offline release HSM / KMS | **verify only** |
| **Firmware / boot chain** | **LMS (stateful HBS)** | release HSM **with leaf-state management** (see below) | **verify only** |
| Device identity | ML-DSA-65 + Ed25519 (**stateless**) | on device, TPM-sealed | sign + verify (safe — no state) |
| TLS (fleet/control plane) | ML-KEM-768 + X25519 (ephemeral) | ephemeral on both ends | n/a |
| Data at rest | AES-256-GCM | on device, TPM-sealed | n/a |

Verification is **stateless and safe**, so it is the only crypto operation devices
perform on the off-device keys. On-device keys are deliberately **stateless schemes**, so
no device ever has to track HBS leaf state.

## The LMS/XMSS leaf-state rule (the one that cannot be violated)

For the boot-chain LMS key:

1. The signing key + its **monotonic leaf-index counter** live ONLY in the release HSM.
2. The counter is **never forked**: never copy the key to a second signer, never restore
   an older state snapshot, never run two release pipelines off the same key. A fork that
   reuses any leaf index is a catastrophic, unrecoverable break.
3. State is **backed up transactionally** (advance-then-sign is durable, or the index is
   reserved before use) so a crash cannot replay an index.
4. Capacity is **finite** (the Merkle tree has a fixed number of leaves) — track
   remaining signatures and plan key rollover before exhaustion.
5. If multi-signer throughput is ever needed, use a **hierarchical scheme (HSS/XMSS^MT)**
   with disjoint sub-tree assignment — still a single state authority, never a fork.

**CI guard (TODO — only a real release HSM/pipeline can close):**
- The CI workflows in `.github/workflows/**` **never** touch the LMS key. Boot-chain
  signing is a SEPARATE, gated release step on the HSM, not a GitHub-hosted runner.
- A release-time check MUST assert leaf-index monotonicity (current > last-recorded) and
  refuse to sign on any regression or ambiguity. This lives in the HSM-side release
  tooling, which is out of scope for this repo; flagged here so it is not forgotten.

## What never enters this repo, CI, or the image

- No private signing key, of any algorithm.
- No HBS leaf-state file.
- No KMS/HSM credential beyond a short-lived CI OIDC token (keyless) or a scoped KMS role
  that can `sign` but not `export`.
- Only PUBLIC material ships: the cosign public key / Fulcio identity, injected into
  `/etc/pki/hookprobe/` for `policy.json`. The image stays reproducible and secret-free
  (Readme "Secrets stay off the image").
