#!/usr/bin/env bash
# =============================================================================
# security/local-release/sign-and-sbom.sh — LOCAL, OFFLINE, secret-safe sign + SBOM for a
# HookProbe OS release disk image, for the "no GitHub yet, this build is not public" case.
# =============================================================================
#
# WHY THIS EXISTS, AND WHY NOT build-os.yml (2026-07-16 pivot): the operator clarified there
# is no GitHub for this project yet -- this is a LOCAL build kept secret so far (local git,
# if any, is fine; no remote, no push). That makes `.github/workflows/build-os.yml`'s
# keyless cosign path (Fulcio/Rekor OIDC) actively WRONG here: Rekor is a PUBLIC append-only
# transparency log, so a keyless `cosign sign --yes`/`sign-blob --yes` would publish this
# build's existence + artifact hash to the world the moment it ran, secret or not. A CI job
# was drafted and then explicitly reverted for this reason -- see the git history / the
# coordinator's course-correction. This script is the replacement: a wholly offline,
# local-key path, run by hand, on this box, by the operator.
#
# REUSE, NOT REINVENTION (per instruction): this composes the EXISTING scripts rather than
# duplicating their logic --
#   - security/cosign/sign-image.sh   already had a `COSIGN_KEY=...` key-mode branch; it was
#     MISSING the Rekor-upload-disable flag (`cosign sign-blob` uploads to the public Rekor
#     log by DEFAULT for key-based signing too, not just keyless -- a real, previously
#     unflagged gap for exactly this scenario). Fixed there (search
#     `--tlog-upload=false`/`COSIGN_TLOG_UPLOAD` in that file) rather than forked here.
#   - security/cosign/verify-image.sh already had the `COSIGN_PUBLIC_KEY` key-mode verify
#     branch; given the matching `--insecure-ignore-tlog` counterpart flag (search
#     `COSIGN_REQUIRE_TLOG` in that file) so a signature this script produces (no tlog entry
#     to look up) verifies cleanly offline.
# THIS script adds only what neither of those cover: (a) bootstrapping a LOCAL key-pair if
# none exists yet, gitignored, distinct from KEY-CUSTODY.md's production HSM/KMS tier; (b) a
# local `syft` SBOM (build-os.yml's SBOM step never ran here -- no CI); (c) a
# `builder/release-pass.sh --sbom <ref>` value so the release.json bundle's `"sbom":
# "CI-GATED: syft not installed"` placeholder can be replaced with a real one.
#
# OFFLINE GUARANTEE (HARD as of 2026-07-16): no Fulcio, no OIDC, no Rekor upload. cosign and
# syft are installed on this box as CONTAINERIZED wrappers (~/.local/bin/{cosign,syft}, pinned
# images cosign v2.4.1 / syft v1.48.0) that run with `podman ... --network none`. That air-gap
# is not best-effort or dependent on `--tlog-upload=false` alone: the tool literally has NO route
# to Fulcio/Rekor/TUF, so even a stray trust-root refresh cannot reach the network. Verified the
# same day that cosign 2.4.1 accepts `--tlog-upload=false` (sign) and `--insecure-ignore-tlog`
# (verify). WHY containers: fortress001's egress resets the sigstore/anchore binary CDNs, so the
# native binaries could not be downloaded here; registries are reachable, so we run the official
# images instead. `--tlog-upload=false` remains belt-and-suspenders under the --network-none belt.
#
# Usage:
#   security/local-release/sign-and-sbom.sh <image.img> [--key-dir DIR] [--work-dir DIR]
#
#   <image.img>   the release disk image to sign + SBOM (e.g.
#                 builder/mkosi-arm64/hookprobe-os-pi-release.img)
#   --key-dir     local cosign key-pair location (default: security/local-release/keys/,
#                 gitignored -- see that dir's own note once created)
#   --work-dir    scratch space for the read-only rootfs extraction the SBOM step needs
#                 (default: a mktemp -d; needs room for the image's USED rootfs content, not
#                 its full partition size -- see the SBOM step comment)
#
# Requires: cosign, syft, sfdisk + debugfs (e2fsprogs/util-linux -- already repo
# dependencies, see builder/mkosi-arm64/verify-image-payload.sh which uses the same tools
# the same way). Missing cosign/syft = FAIL LOUD with the install command; this is a
# supply-chain gate, never a silent skip.
#
# Does NOT run builder/release-pass.sh -- that assembles the release.json evidence bundle
# and requires the four Ring-1 `--attest` role sign-offs (an Amber, human-reviewed step by
# design, security/../builder/release-pass.sh's own gate). This script prints the exact
# `--sbom <ref>` value + a ready-to-run release-pass.sh command line at the end; the
# operator runs that separately, deliberately.
# =============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

IMG=""
KEY_DIR="$HERE/keys"
WORK_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --key-dir)  KEY_DIR="$2"; shift 2 ;;
    --work-dir) WORK_DIR="$2"; shift 2 ;;
    -h|--help)  sed -n '1,60p' "$0"; exit 0 ;;
    *)
      [ -z "$IMG" ] || { echo "ERROR: unexpected extra argument '$1'" >&2; exit 2; }
      IMG="$1"; shift ;;
  esac
done
[ -n "$IMG" ] || { echo "usage: sign-and-sbom.sh <image.img> [--key-dir DIR] [--work-dir DIR]" >&2; exit 2; }
[ -f "$IMG" ] || { echo "ERROR: image not found: $IMG" >&2; exit 1; }
IMG="$(cd "$(dirname "$IMG")" && pwd)/$(basename "$IMG")"   # absolute, for clean paths below

echo "=== sign-and-sbom.sh: LOCAL / OFFLINE release signing (no Rekor, no GitHub) ==="
echo "image: $IMG"
echo "sha256 (pre-sign, for the operator to eyeball against what they expect): $(sha256sum "$IMG" | cut -d' ' -f1)"
echo ""

# --- preflight: fail LOUD, never silently skip a supply-chain tool -----------------------
MISSING=0
if ! command -v cosign >/dev/null 2>&1; then
  echo "ERROR: cosign not installed. Install it (offline-signing-capable, no daemon needed):" >&2
  echo "  curl -fsSL -o /usr/local/bin/cosign \\" >&2
  echo "    https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64" >&2
  echo "  chmod +x /usr/local/bin/cosign" >&2
  echo "  (arm64 host: .../cosign-linux-arm64 instead)" >&2
  echo "  NOTE (fortress001): this box's egress RESETS the sigstore binary CDN, so the curl" >&2
  echo "  above will hang/reset here. Use the containerized wrapper instead (registries are" >&2
  echo "  reachable): ~/.local/bin/cosign runs 'podman run --network none ghcr.io/sigstore/" >&2
  echo "  cosign/cosign:v2.4.1 \"\$@\"'. See security/local-release/README.md." >&2
  MISSING=1
fi
if ! command -v syft >/dev/null 2>&1; then
  echo "ERROR: syft not installed -- the release.json bundle's SBOM field cannot be produced" >&2
  echo "  without it (and this script refuses to silently skip a supply-chain artifact)." >&2
  echo "  Install it:" >&2
  echo "    curl -fsSL https://raw.githubusercontent.com/anchore/syft/main/install.sh \\" >&2
  echo "      | sh -s -- -b \$HOME/.local/bin" >&2
  echo "  (same installer build-os.yml's build-image job used; a one-time tool fetch from" >&2
  echo "   syft's own public release CDN -- NOT a per-build phone-home about THIS artifact)." >&2
  echo "  NOTE (fortress001): the anchore CDN (get.anchore.io) is RESET by this box's egress," >&2
  echo "  so that installer fails here. Use the containerized wrapper instead: ~/.local/bin/" >&2
  echo "  syft runs 'podman run --network none anchore/syft:v1.48.0'. See that README." >&2
  MISSING=1
fi
for t in sfdisk debugfs; do
  command -v "$t" >/dev/null 2>&1 || { echo "ERROR: $t not installed (util-linux / e2fsprogs)." >&2; MISSING=1; }
done
[ "$MISSING" -eq 0 ] || { echo "" >&2; echo "ABORT: missing tool(s) above -- install then re-run." >&2; exit 3; }
echo "preflight OK: cosign $(cosign version 2>/dev/null | head -1 || echo '(version unknown)'), syft $(syft version 2>/dev/null | head -1 || echo '(version unknown)')"
echo ""

# --- 1) local key-pair bootstrap (gitignored; NOT the KEY-CUSTODY.md production HSM tier) --
if [ ! -f "$KEY_DIR/cosign.key" ]; then
  echo "=== no local key at $KEY_DIR/cosign.key -- generating one now ==="
  echo "  NOTE: this is a LOCAL/DEV signing key for this secret-so-far build lineage, NOT the"
  echo "  production off-device HSM/KMS key security/cosign/KEY-CUSTODY.md describes -- do not"
  echo "  treat artifacts signed with it as carrying the same custody guarantee. When this"
  echo "  project goes public / gets a real release HSM, re-sign under that key instead."
  mkdir -p "$KEY_DIR"
  ( cd "$KEY_DIR" && cosign generate-key-pair --output-key-prefix cosign )
  echo "  wrote $KEY_DIR/cosign.key (private, encrypted -- COSIGN_PASSWORD or interactive prompt)"
  echo "  wrote $KEY_DIR/cosign.pub (public -- fine to share once/if this build goes public)"
  echo "  $KEY_DIR is gitignored (see security/local-release/.gitignore) -- the private key"
  echo "  never gets committed even if this tree grows a local git remote later."
else
  echo "=== reusing existing local key: $KEY_DIR/cosign.key ==="
fi
echo ""

# --- 2) sign (reuses security/cosign/sign-image.sh's key-mode branch -- now fixed to pass
#         --tlog-upload=false so nothing phones home to the public Rekor log) --------------
echo "=== signing (cosign sign-blob --key, offline, no tlog upload) ==="
COSIGN_KEY="$KEY_DIR/cosign.key" "$REPO/security/cosign/sign-image.sh" "$IMG"
echo ""

# --- 3) local SBOM (syft) over the MOUNTED rootfs, not the raw partitioned blob -----------
# `syft <file>` on a raw MBR/GPT disk image does NOT understand partitions (it would just
# hash-catalog one opaque binary, not the actual package inventory) -- the same reasoning
# builder/mkosi-arm64/verify-image-payload.sh's own header documents for reading the rootfs
# payload. This uses THAT script's exact technique (sfdisk -J to enumerate partitions,
# `debugfs -R "ls /" "$IMG?offset=N"` to find the ext-formatted one) but goes one step
# further with `debugfs -R "rdump / <dir>"` to extract the real files syft needs to scan --
# deliberately NOT `sudo losetup`/`mount` (no root needed at all, matching this repo's
# existing no-root-for-read-only-inspection convention).
echo "=== SBOM (syft, over the extracted rootfs -- no root/loop-mount needed) ==="
[ -n "$WORK_DIR" ] || WORK_DIR="$(mktemp -d)"
EXTRACT="$WORK_DIR/rootfs"
mkdir -p "$EXTRACT"
echo "  extracting to $EXTRACT (this is the image's USED file content, not its full partition"
echo "  size -- e2fsprogs skips unallocated blocks; still needs real disk space, see --work-dir)"

mapfile -t OFFSETS < <(sfdisk -J "$IMG" 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)["partitiontable"]
except Exception:
    sys.exit(0)
ss = d.get("sectorsize", 512)
for p in d.get("partitions", []):
    print(p["start"] * ss)
')
[ "${#OFFSETS[@]}" -gt 0 ] || { echo "ERROR: sfdisk found no partition table in $IMG" >&2; exit 4; }

ROOT_OFFSET=""
for off in "${OFFSETS[@]}"; do
  if debugfs -R "ls /" "${IMG}?offset=${off}" >/dev/null 2>&1; then
    ROOT_OFFSET="$off"
    echo "  found ext-formatted partition at byte offset $off"
    break   # first ext partition on a p1=vfat-boot/p2=ext4-root layout (make-pi-image.sh
            # convention) IS the root; if a future layout adds more ext partitions before
            # root (e.g. split /usr), this picks the FIRST one -- TODO(REAL) below.
  fi
done
[ -n "$ROOT_OFFSET" ] || { echo "ERROR: no ext-formatted (debugfs-readable) partition found in $IMG" >&2; exit 4; }
# TODO(REAL): unverified against a real split-/usr (`hp-usr`) layout -- verify-image-payload.sh
# handles that by searching ALL ext partitions under both path forms; this script only scans
# the first ext partition it finds. Fine for the current p1=boot/p2=root layout
# hookprobe-os-pi-release.img actually uses (confirmed: dos label, p1 type c, p2 type 83,
# no third partition) -- flagged in case that changes.

debugfs -R "rdump / ${EXTRACT}" "${IMG}?offset=${ROOT_OFFSET}" >/tmp/hp-sbom-rdump.log 2>&1 \
  || { echo "ERROR: debugfs rdump failed -- see /tmp/hp-sbom-rdump.log" >&2; exit 4; }
echo "  extraction OK ($(du -sh "$EXTRACT" 2>/dev/null | cut -f1))"

SBOM_CDX="$(dirname "$IMG")/$(basename "$IMG").sbom.cdx.json"
SBOM_SPDX="$(dirname "$IMG")/$(basename "$IMG").sbom.spdx.json"
SYFT_CFG="$REPO/security/sbom/syft.yaml"
if [ -f "$SYFT_CFG" ]; then
  syft -c "$SYFT_CFG" "dir:${EXTRACT}" -o "cyclonedx-json=${SBOM_CDX}" -o "spdx-json=${SBOM_SPDX}"
else
  syft "dir:${EXTRACT}" -o "cyclonedx-json=${SBOM_CDX}" -o "spdx-json=${SBOM_SPDX}"
fi
echo "  wrote $SBOM_CDX"
echo "  wrote $SBOM_SPDX"
rm -rf "$WORK_DIR"
echo ""

# --- 4) print the release-pass.sh feed values (does NOT run it -- Amber, operator's call) --
SBOM_HASH="$(sha256sum "$SBOM_CDX" | cut -d' ' -f1)"
IMG_HASH="$(cut -d' ' -f1 "${IMG}.sha256")"
echo "=== done. Feed builder/release-pass.sh locally with: ==="
echo ""
echo "  --sbom \"${SBOM_CDX}@sha256:${SBOM_HASH}\""
echo "  --digest \"hookprobe-os-pi:arm64:sha256:${IMG_HASH}\""
echo ""
echo "Example (adjust --cbom/--version/--channel/--out to match your existing bundle, e.g."
echo "/tmp/release-2026.7.0/release.json's cbom ref -- this REPLACES that bundle's"
echo '"sbom": "CI-GATED: syft not installed" placeholder with a real one):'
echo ""
echo "  builder/release-pass.sh \\"
echo "    --version 2026.7.0 --channel stable \\"
echo "    --digest \"hookprobe-os-pi:arm64:sha256:${IMG_HASH}\" \\"
echo "    --sbom \"${SBOM_CDX}@sha256:${SBOM_HASH}\" \\"
echo "    --cbom \"/tmp/release-2026.7.0/cbom.cdx.json@sha256:<its existing sha256>\" \\"
echo "    --gate \"module-signing:pass:...\" [... repeat every --gate/--platform from the"
echo "    existing bundle ...] \\"
echo "    --attest all \\"
echo "    --out /tmp/release-2026.7.0/release.json"
echo ""
echo "NOT run automatically -- release-pass.sh requires the Ring-1 --attest sign-offs by"
echo "design (Amber gate); the operator runs it deliberately, separately from this script."
