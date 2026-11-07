# `security/local-release/` — local, offline, secret-safe release signing

For the case `security/cosign/README.md`'s two documented options don't cover: **no GitHub,
no remote, no CI** — just a local build that has not been disclosed yet, and must not leak
its own existence via the public Sigstore Rekor transparency log the moment it's signed.

`.github/workflows/build-os.yml` is NOT the path for this — its keyless cosign step
(`cosign sign-blob --yes`, no `--tlog-upload=false`) publishes to Rekor by design (Option A
in `security/cosign/README.md`, correct for the eventual public open-core image, wrong for
a secret build today).

## Tooling on this box (fortress001) — cosign & syft are containerized

fortress001's egress **resets the sigstore/anchore binary CDNs** (`objects.githubusercontent.com`,
`get.anchore.io` — verified 2026-07-16, connection reset, 0 bytes), so the native-binary installs
the preflight suggests **cannot complete here**. Container registries *are* reachable, so both tools
are installed as thin wrappers in `~/.local/bin/` that run the **pinned official images** with
`podman run --network none`:

| tool | wrapper | pinned image |
|---|---|---|
| `cosign` | `~/.local/bin/cosign` | `ghcr.io/sigstore/cosign/cosign:v2.4.1` (`@sha256:b03690aa…`, matches `base/Containerfile`) |
| `syft`   | `~/.local/bin/syft`   | `docker.io/anchore/syft:v1.48.0` (`@sha256:a64166d9…`) |

`--network none` is deliberate and load-bearing: it makes "a secret build never phones home to
Rekor/Fulcio" a **hard guarantee** (no route at all), not merely a `--tlog-upload=false` flag. To
reinstall on a fresh box: `podman pull` the two pinned digests and re-create the wrappers (they only
`podman run … --network none <image> "$@"` with the repo + `/tmp` bind-mounted). Verified against
cosign 2.4.1 that `--tlog-upload=false` (sign) and `--insecure-ignore-tlog` (verify) are real flags.

## Use `sign-and-sbom.sh`

```bash
security/local-release/sign-and-sbom.sh builder/mkosi-arm64/hookprobe-os-pi-release.img
```

Does, in order: preflight (cosign + syft + sfdisk/debugfs present, or fails loudly with the
install command) → bootstraps a local key-pair in `keys/` (gitignored) if none exists yet →
signs via `security/cosign/sign-image.sh` with `--tlog-upload=false` (offline, no Rekor) →
extracts the rootfs read-only via `debugfs rdump` (no root/loop-mount needed) and runs
`syft` for a real CycloneDX + SPDX SBOM → prints the exact `--sbom`/`--digest` values and a
ready-to-run `builder/release-pass.sh` command line (does not run it — that needs the four
Ring-1 `--attest` sign-offs, an Amber/human step by design).

## Key custody note (read before trusting this key for anything beyond "local, secret, ours")

The key `sign-and-sbom.sh` generates in `keys/cosign.key` is a **local/dev key**, not the
production off-device HSM/KMS key `security/cosign/KEY-CUSTODY.md` describes. It exists so
this undisclosed build can be signed and verified *by the same team, on the same machines*,
without inventing a parallel unsigned artifact class. It is gitignored (`keys/`, `*.key`) so
it never lands in a commit even once this tree grows a local git remote. When the project
goes public / a real release HSM exists, re-sign the eventual public artifacts under that
key instead — do not treat this one as carrying the same custody guarantee.

## Verifying later

```bash
COSIGN_PUBLIC_KEY=security/local-release/keys/cosign.pub \
  security/cosign/verify-image.sh builder/mkosi-arm64/hookprobe-os-pi-release.img
```
