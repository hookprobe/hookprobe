#!/usr/bin/env bash
# gen-heqk-dev-keys.sh — generate a DEV heqk boot-signing keydir + register its fingerprints.
# ADR 0046 / docs/design/heqk-signing-identity.md (M1 dev-beachhead plumbing).
#
# Produces a dev keydir (ed25519 + SLH-DSA-SHA2-128s boot keys) using the IN-TREE vendored
# signer (builder/heqk-sign — NOT the external ~/heqk-sign), installs the matching compiled-in
# boot pubkeys into kernel/heqk/hboot/src/trusted_keys.rs, and APPENDS the new keys' SHA-256
# fingerprints to builder/heqk-dev-key-fingerprints.txt so the release-blocking gate
# (base/scripts/heqk-boot-key-check.sh) always rejects them in a RELEASE build.
#
# These keys are for HOOKPROBE_DEBUG_ACCESS builds ONLY. Production boot keys are provisioned
# under HSM custody (open decision — docs/design/heqk-signing-identity.md). The keydir is
# gitignored; the AK (attest_keys.rs, which embeds PRIVATE keys) is a separate opt-in concern —
# this script does NOT regenerate it (a hardware-bound AK is the follow-on, B-1).
#
# Usage: gen-heqk-dev-keys.sh [keydir]   (default: builder/.heqk-dev-keys)
#   After running:  export HEQK_KEYDIR="<keydir>"  then build with HOOKPROBE_DEBUG_ACCESS=1.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
KEYDIR="${1:-$ROOT/builder/.heqk-dev-keys}"
SIGNER_DIR="$ROOT/builder/heqk-sign"
SIGNER="$SIGNER_DIR/target/release/heqk-sign"
TRUSTED_DST="$ROOT/kernel/heqk/hboot/src/trusted_keys.rs"
REG="$ROOT/builder/heqk-dev-key-fingerprints.txt"

# Build the in-tree signer if needed (host tool, stable toolchain).
if [ ! -x "$SIGNER" ]; then
  echo "== building in-tree heqk-sign ($SIGNER_DIR)"
  ( cd "$SIGNER_DIR" && cargo build --release )
fi
[ -x "$SIGNER" ] || { echo "FATAL: heqk-sign not built at $SIGNER" >&2; exit 1; }

mkdir -p "$KEYDIR"
echo "== generating DEV boot keys into $KEYDIR"
"$SIGNER" keygen "$KEYDIR"          # writes ed25519.{pk,sk} slhdsa.{pk,sk} trusted_keys.rs
[ -f "$KEYDIR/trusted_keys.rs" ] || { echo "FATAL: keygen did not emit trusted_keys.rs" >&2; exit 1; }

echo "== installing matching compiled-in boot pubkeys -> $TRUSTED_DST"
cp "$KEYDIR/trusted_keys.rs" "$TRUSTED_DST"

echo "== registering new dev-key fingerprints in $REG (so the release gate rejects them)"
python3 - "$TRUSTED_DST" "$REG" <<'PY'
import sys, re, hashlib, pathlib, datetime
src, reg = sys.argv[1], sys.argv[2]
txt = pathlib.Path(src).read_text()
existing = set()
if pathlib.Path(reg).exists():
    for line in pathlib.Path(reg).read_text().splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            existing.add(s.split()[0].lower())
added = []
day = "dev keygen (gen-heqk-dev-keys.sh)"
for m in re.finditer(r'pub (?:const|static mut) (\w+)\s*:\s*\[u8;\s*(\d+)\]\s*=\s*\[(.*?)\];', txt, re.S):
    name, n = m.group(1), int(m.group(2))
    b = [int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', m.group(3))]
    if len(b) != n:
        continue
    fp = hashlib.sha256(bytes(b)).hexdigest()
    kind = "SECRET" if name.endswith("_SK") else "public"
    if fp not in existing:
        added.append(f"{fp}  # {name} ({n}B, {kind}) — {day}")
        existing.add(fp)
if added:
    with open(reg, "a") as fh:
        fh.write("\n".join(added) + "\n")
print(f"  registered {len(added)} new fingerprint(s)")
for a in added:
    print("   +", a.split("#")[0].strip()[:16] + "…", a.split("#")[1].strip())
PY

echo ""
echo "== DONE. DEV keydir: $KEYDIR"
echo "   Build a debug heqk image with:"
echo "     export HEQK_KEYDIR=\"$KEYDIR\""
echo "     HOOKPROBE_DEBUG_ACCESS=1 builder/make-cm5-heqk-image.sh"
echo "   (A RELEASE build will be BLOCKED by base/scripts/heqk-boot-key-check.sh — by design.)"
