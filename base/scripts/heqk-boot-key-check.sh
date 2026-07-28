#!/usr/bin/env bash
# heqk-boot-key-check.sh — RELEASE-BLOCKING gate: no DEV boot/AK signing keys in a RELEASE hboot.
# ADR 0046 / docs/design/heqk-signing-identity.md (security-auditor decision #5, raised to blocker).
#
# heqk's hboot compiles its root-of-trust pubkeys (kernel/heqk/hboot/src/trusted_keys.rs) and its
# software Attestation Key (attest_keys.rs — INCLUDING the AK PRIVATE keys, AK_*_SK) directly into
# the boot binary. If a RELEASE image ships the DEV keys, the operator's laptop key becomes a
# production boot-RoT / AK master key (the dev *_SK live unencrypted under ~/heqk-sign/keys). This
# gate fingerprints every compiled-in key and FAILS a release build if any matches the known-dev
# block-list (builder/heqk-dev-key-fingerprints.txt).
#
# Mirrors the house pattern of base/scripts/rbac-os-check.sh (known-dev-credential release gate).
#
# Usage: heqk-boot-key-check.sh [--mode release|debug]
#   MODE resolves: --mode arg  >  $HOOKPROBE_DEBUG_ACCESS (1 => debug)  >  default release.
#   release + a dev-fingerprint match => FATAL (exit 1). debug => WARN, allowed.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
REG="$ROOT/builder/heqk-dev-key-fingerprints.txt"
KEYFILES=("$ROOT/kernel/heqk/hboot/src/trusted_keys.rs" "$ROOT/kernel/heqk/hboot/src/attest_keys.rs")

MODE=""
if [ "${1:-}" = "--mode" ]; then MODE="${2:-}"; fi
if [ -z "$MODE" ]; then
  if [ "${HOOKPROBE_DEBUG_ACCESS:-0}" = "1" ]; then MODE=debug; else MODE=release; fi
fi

[ -f "$REG" ] || { echo "FATAL: dev-key registry missing: $REG" >&2; exit 1; }
command -v python3 >/dev/null || { echo "FATAL: python3 required for heqk-boot-key-check" >&2; exit 1; }

python3 - "$REG" "$MODE" "${KEYFILES[@]}" <<'PY'
import sys, re, hashlib, pathlib
reg_path, mode = sys.argv[1], sys.argv[2]
keyfiles = sys.argv[3:]

reg = {}
for line in pathlib.Path(reg_path).read_text().splitlines():
    s = line.strip()
    if not s or s.startswith("#"):
        continue
    fp = s.split()[0].lower()
    reg[fp] = s.partition("#")[2].strip() or "(no note)"

hits, ak_secrets = [], []
for f in keyfiles:
    p = pathlib.Path(f)
    if not p.exists():
        continue
    txt = p.read_text()
    for m in re.finditer(r'pub (?:const|static mut) (\w+)\s*:\s*\[u8;\s*(\d+)\]\s*=\s*\[(.*?)\];', txt, re.S):
        name, n = m.group(1), int(m.group(2))
        b = [int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', m.group(3))]
        if len(b) != n:
            continue
        fp = hashlib.sha256(bytes(b)).hexdigest()
        if fp in reg:
            hits.append((pathlib.Path(f).name, name, fp))
        if name.endswith("_SK") and any(b):
            ak_secrets.append((pathlib.Path(f).name, name))

for fn, name, fp in hits:
    print(f"  DEV-KEY MATCH: {name}  ({fn})  sha256={fp[:16]}…")
for fn, name in ak_secrets:
    print(f"  note: software-AK PRIVATE key compiled in: {name} ({fn}) "
          f"— a hardware-bound (OTP-derived) AK is the follow-on (B-1)")

if hits and mode != "debug":
    sys.stderr.write(
        f"FATAL: {len(hits)} DEV signing key(s) compiled into a RELEASE hboot — refusing.\n"
        "       Dev keys are for HOOKPROBE_DEBUG_ACCESS builds only. Provision production\n"
        "       keys under HSM custody before a release build. See\n"
        "       docs/design/heqk-signing-identity.md.\n")
    sys.exit(1)

if hits:
    print(f"OK (debug): {len(hits)} dev key(s) present — allowed only because MODE=debug.")
else:
    print("OK: no known-dev signing keys compiled into hboot.")
PY
