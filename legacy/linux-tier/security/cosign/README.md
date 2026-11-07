# `security/cosign/` — signing & verification policy

> **Readme "Trust nothing unsigned" / ADR 0002 §3: OS images, Wasm modules, sysexts, and
> manifests are cosign-signed; the device only VERIFIES — signing keys never ship.**

## What signs what

| Artifact | Signed in | Verified by |
|---|---|---|
| OS bootc image | `build-os.yml` (cosign sign + attest SBOM/CBOM) | `bootc`/podman at upgrade via `/etc/containers/policy.json`; auditors via `verify.sh` |
| Wasm module (OCI) | `build-modules.yml` | the **supervisor** on load (`signature: required` in every `module.yaml`) + `policy.json` |
| sysext (OCI, e.g. napse-capture) | `build-modules.yml` | the supervisor before merge-on-boot; `policy.json` |
| Platform Manifest | `hookprobe-bootstrap` on-device (signs the manifest it writes) + TPM-seal | next-boot verify; `manifest/validate.py` only checks structure (full cosign verify is release-CI/on-device) |
| disk artifacts (`.img.xz`/`.iso`/`.qcow2`/`.ami`) | `build-os.yml` (`cosign sign-blob` + checksums) | operator at flash time |

The on-device trust anchor is **`base/config/containers/policy.json`** (default-reject;
`sigstoreSigned` for `ghcr.io/hookprobe` + `registry.hookprobe.com`). CI injects only the
PUBLIC trust material into `/etc/pki/hookprobe/`. This directory holds the
release-/CI-side counterpart: how to SIGN, and `verify.sh` to verify out-of-band.

## Identity options (pick ONE; keep workflows + `verify.sh` + `policy.json` in lockstep)

**Option A — keyless (Fulcio/Rekor OIDC). Recommended for the open-core OSS image.**
- CI signs with its workload OIDC identity; signature + cert logged to the Rekor
  transparency log. No long-lived private key to steal.
- Requires `permissions: id-token: write` in the workflow and
  `policy.json` switched from `keyPath` to a `fulcio`/`sigstoreSigned` identity rule
  (the TODO already noted in `base/config/containers/policy.json`).
- **TODO:** the exact `--certificate-identity-regexp` + `--certificate-oidc-issuer` once
  the repo lives at `github.com/hookprobe/hookprobe-os` with the real workflow path.

**Option B — KMS / offline HSM key. For regulated / air-gapped release lines.**
- `cosign sign --key <kms-ref>` (e.g. `awskms://`, `azurekms://`, `hashivault://`, or a
  PKCS#11 HSM). Private key never leaves the KMS/HSM.
- `policy.json` keeps `keyPath: /etc/pki/hookprobe/cosign.pub`; publish the PUBLIC key to
  `security/cosign/keys/cosign.pub` (public material ONLY — ADR 0002 §5).
- **This is the mandatory model for the boot-chain (LMS) and is strongly preferred for
  image/module signing in a commercial release** — see `KEY-CUSTODY.md`.

## PQC / composite-signature roadmap (ADR 0002 §3, consequences)

The target is **composite ML-DSA-65 + Ed25519** for image/module signing. cosign/sigstore
native PQC signing is **still maturing**, so the **interim** is dual/composite signing:
sign with the classical key as today AND attach a PQC (ML-DSA-65) signature, verifying
*both*. The hybrid posture is itself the mitigation — the classical leg holds if a young
PQC implementation has a bug. Track the sigstore PQC roadmap; flip the suite (not the
code) when native composite support lands.

**TODO (only sigstore can close):** native cosign composite/ML-DSA signing; until then
the workflows sign classically and mark the PQC leg as a follow-on attach step.
