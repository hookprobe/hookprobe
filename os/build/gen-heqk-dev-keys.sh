#!/usr/bin/env bash
# gen-heqk-dev-keys.sh — generate a DEV heqk boot-signing keydir + register its fingerprints.
# ADR 0046 / docs/design/heqk-signing-identity.md (M1 dev-beachhead plumbing).
#
# Produces a dev keydir (ed25519 + SLH-DSA-SHA2-128s boot keys) using the IN-TREE vendored
# signer (os/build/heqk-sign — NOT the external ~/heqk-sign), installs the matching compiled-in
# boot pubkeys into os/kernel/hboot/src/trusted_keys.rs, and APPENDS the new keys' SHA-256
# fingerprints to os/build/heqk-dev-key-fingerprints.txt so the release-blocking gate
# (os/build/heqk-boot-key-check.sh) always rejects them in a RELEASE build.
#
# These keys are for HOOKPROBE_DEBUG_ACCESS builds ONLY. Production boot keys are provisioned
# under HSM custody (open decision — docs/design/heqk-signing-identity.md). The keydir is
# gitignored; the AK (attest_keys.rs, which embeds PRIVATE keys) is a separate opt-in concern —
# this script does NOT regenerate it (a hardware-bound AK is the follow-on, B-1).
#
# Usage: gen-heqk-dev-keys.sh [keydir]   (default: os/build/.heqk-dev-keys)
#   After running:  export HEQK_KEYDIR="<keydir>"  then build with HOOKPROBE_DEBUG_ACCESS=1.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
KEYDIR="${1:-$ROOT/os/build/.heqk-dev-keys}"
SIGNER_DIR="$ROOT/os/build/heqk-sign"
SIGNER="$SIGNER_DIR/target/release/heqk-sign"
# The boot trust root moved OUT of the now-deleted hboot/src/trusted_keys.rs into the SHARED
# boot-abi verifier (one root for boot-time verify + M3.4 OTA pre-flight). Installing to the old
# path silently orphaned the keys: hboot kept compiling the PREVIOUS pubkeys while mkimage-hboot.sh
# signed with the NEW ones, so the board would fail signature verification and park on boot.
TRUSTED_DST="$ROOT/os/kernel/boot-abi/src/verify.rs"
REG="$ROOT/os/build/heqk-dev-key-fingerprints.txt"

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
# SPLICE (never `cp`): verify.rs carries the verification LOGIC as well as the two roots, and it
# names them TRUSTED_*_PUBKEY while `heqk-sign keygen` emits *_PUBKEY. Overwriting the file would
# delete the verifier; so rewrite ONLY the two byte arrays in place, fail-closed if either the
# source key or the destination constant is not found.
python3 - "$KEYDIR/trusted_keys.rs" "$TRUSTED_DST" <<'PYSPLICE'
import re, sys, pathlib
src, dst = (pathlib.Path(a) for a in sys.argv[1:3])
stxt, dtxt = src.read_text(), dst.read_text()

def grab(txt, name):
    m = re.search(r'pub const %s\s*:\s*\[u8;\s*32\]\s*=\s*\[(.*?)\];' % name, txt, re.S)
    if not m:
        sys.exit(f"FATAL: {name} not found in {src}")
    b = [int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', m.group(1))]
    if len(b) != 32:
        sys.exit(f"FATAL: {name} is {len(b)} bytes, expected 32")
    return b

def fmt(b):
    rows = ["    " + " ".join(f"0x{x:02x}," for x in b[i:i+16]) for i in range(0, 32, 16)]
    return "\n".join(rows)

for srcname, dstname in (("ED25519_PUBKEY", "TRUSTED_ED25519_PUBKEY"),
                         ("SLHDSA_PUBKEY", "TRUSTED_SLHDSA_PUBKEY")):
    body = fmt(grab(stxt, srcname))
    pat = re.compile(r'(pub const %s\s*:\s*\[u8;\s*32\]\s*=\s*\[)(.*?)(\];)' % dstname, re.S)
    if not pat.search(dtxt):
        sys.exit(f"FATAL: {dstname} not found in {dst} — trust-root layout changed, refusing")
    dtxt = pat.sub(lambda m: m.group(1) + "\n" + body + "\n" + m.group(3), dtxt, count=1)

dst.write_text(dtxt)
print(f"  spliced 2 boot pubkeys into {dst}")
PYSPLICE

echo "== registering new dev-key fingerprints in $REG (so the release gate rejects them)"
python3 - "$KEYDIR/trusted_keys.rs" "$REG" <<'PY'
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
echo "     HOOKPROBE_DEBUG_ACCESS=1 os/build/make-cm5-heqk-image.sh"
echo "   (A RELEASE build will be BLOCKED by os/build/heqk-boot-key-check.sh — by design.)"
