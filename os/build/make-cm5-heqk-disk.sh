#!/usr/bin/env bash
# make-cm5-heqk-disk.sh — the CM5 IMAGE FACTORY (BuildPlan Track C, ADR 0047): one command from a
# clean checkout to ONE signed, partitioned, flashable heqk disk image. No Linux in the image.
#
#   HEQK_KEYDIR=<keydir> os/build/make-cm5-heqk-disk.sh [--zero-linux] [--size-mib N] [--owner-token auto|TOKEN]
#
# Layout (MBR):
#   LBA 0            MBR (0x55AA)
#   LBA 2016..2047   heqk reserved keystore window — ZEROED, outside every partition (store.rs)
#   p1  LBA 8192     FAT32 boot set: config.txt, tryboot.txt, heqk8-a.img, heqk8-b.img [+ .dtb]
#   p2  after p1     type 0xDA heqk DataVolume (raw, filesystem-less log store; store.rs)
#
# A/B slots have EQUAL-LENGTH names and config.txt/tryboot.txt are emitted in a canonical form, so
# an on-device commit is a same-size in-place rewrite of one file (fat.rs locates its sectors) —
# no FAT writer, and the commit survives a cold boot because it changes what config.txt boots.
#
# --zero-linux  ship NO devicetree (config-nolinux.txt): zero Linux artifacts in the image. heqk
#               never parses a DTB; the cost is the RTL8111 (eth1) PCIe link is not firmware-
#               trained — fine for the passive-first GEM profile (ADR 0037 D4). METAL-UNPROVEN:
#               proving it on the bench is the U1 gate. Default keeps the one proven .dtb.
#
# OWNER.TXT (ADR 0037 D3 — physical possession is the only credential, no default password): a
# FIXED 128-byte file on p1 holding only a salted verifier. Default = the "HQOWN0 unclaimed"
# placeholder (the device refuses access until claimed); the browser flasher patches the verifier
# in place at the byte offset recorded in the manifest. --owner-token auto mints a token for a
# bench image (printed ONCE; the image stores only sha256(salt||token)).
#
# Self-check: boots the heqk QEMU p15-write kernel against a COPY of the produced image — the
# device's OWN fat.rs/store code must locate slot B in the real layout ([P15-otafat] PASS).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
HEQK="$ROOT/os/kernel"
OUT="${OUT:-$ROOT/os/build/generated/cm5-heqk}"
FEATURES="${FEATURES:-prod}"
SVN="${SVN:-1}"
SIZE_MIB=512
ZERO_LINUX=0
OWNER_TOKEN=""
WAN_FILE=""
POLICY_FILE=""
BLOCK_FILE=""
ALLOW_FILE=""
IOC_FILE=""
DEVICES_FILE=""
WIFI_FILE=""
MCTLS_FILE=""
POLICY_KEY=""
POLICY_GEN="1"
while [ $# -gt 0 ]; do
  case "$1" in
    --zero-linux) ZERO_LINUX=1 ;;
    --owner-token) OWNER_TOKEN="$2"; shift ;;
    --size-mib) SIZE_MIB="$2"; shift ;;
    --wan-file) WAN_FILE="$2"; shift ;;
    --policy-file) POLICY_FILE="$2"; shift ;;
    --mctls-file) MCTLS_FILE="$2"; shift ;;
    --policy-key) POLICY_KEY="$2"; shift ;;
    --policy-gen) POLICY_GEN="$2"; shift ;;
    --blocklist-file) BLOCK_FILE="$2"; shift ;;
    --allowlist-file) ALLOW_FILE="$2"; shift ;;
    --ioc-file) IOC_FILE="$2"; shift ;;
    --devices-file) DEVICES_FILE="$2"; shift ;;
    --wifi-file) WIFI_FILE="$2"; shift ;;
    *) echo "usage: $0 [--zero-linux] [--size-mib N] [--owner-token auto|TOKEN] [--wan-file WAN.TXT] [--policy-file POLICY.TXT] [--mctls-file MCTLS.CRT] [--policy-key OPERATOR.key [--policy-gen N]] [--blocklist-file BLOCK.TXT] [--allowlist-file ALLOW.TXT] [--ioc-file IOC.TXT] [--devices-file DEVICES.TXT] [--wifi-file WIFI.TXT]" >&2; exit 2 ;;
  esac
  shift
done
for t in sfdisk mkfs.vfat mcopy mdir sha256sum python3; do
  command -v "$t" >/dev/null || { echo "FATAL: $t not on PATH (host build tool)"; exit 1; }
done
[ "$SIZE_MIB" -ge 128 ] || { echo "FATAL: --size-mib must be >= 128"; exit 1; }

mkdir -p "$OUT"
echo "== [factory] 1/5 inputs: Wi-Fi firmware + UI (if the profile serves Mission Control)"
FW="$HEQK/firmware/brcm"
if [ ! -s "$FW/cyw43455-sdio.bin" ] || [ ! -s "$FW/cyw43455-sdio.clm_blob" ] || [ ! -s "$FW/cyw43455-sdio-cm5.nvram.txt" ]; then
  "$HEQK/cm5-boot/stage-wifi-firmware.sh"
fi
case ",$FEATURES," in
  *,mcserve,*|*,prod-mc,*)
    if [ ! -f "$ROOT/os/mission-control/dist/index.html" ]; then
      export PATH="$HOME/.local/node/bin:$PATH"
      command -v npm >/dev/null || { echo "FATAL: profile serves Mission Control but npm is missing"; exit 1; }
      (cd "$ROOT/os/mission-control" && npm ci --no-audit --no-fund >/dev/null && PUBLIC_API_BASE='' npm run build >/dev/null)
    fi ;;
esac

# ADR 0049 D1 — an operator policy key: its PUBLIC half is compiled into the boot-signed kernel (the device
# then refuses any POLICY.TXT not signed by it), and this image's generation becomes the anti-rollback floor.
if [ -n "$POLICY_KEY" ]; then
  HEQK_POLICY_PUBKEY="$(python3 -I "$HEQK/tools/policy-sign.py" pubkey "$POLICY_KEY")" || { echo "FATAL: --policy-key unreadable"; exit 1; }
  export HEQK_POLICY_PUBKEY HEQK_POLICY_GEN_FLOOR="$POLICY_GEN"
  echo "   operator policy key ${HEQK_POLICY_PUBKEY:0:16}… compiled in, generation floor $POLICY_GEN"
else
  unset HEQK_POLICY_PUBKEY HEQK_POLICY_GEN_FLOOR
fi
echo "== [factory] 2/5 build + hybrid-sign the boot set (make-cm5-heqk-image.sh, FEATURES=$FEATURES)"
# Job-PRIVATE image dir + cargo target dir: never write the shared cm5-boot/ or target/ that
# other builders/sessions flash from (a shared path once swapped another session's slot A).
PRIV="$OUT/.work"; mkdir -p "$PRIV/img"
IMG_DIR="$PRIV/img" CARGO_TARGET_DIR="$HEQK/target/factory" \
FEATURES="$FEATURES" SVN="$SVN" OUT="$OUT/bootset" "$HERE/make-cm5-heqk-image.sh" >"$OUT.build.log" 2>&1 || {
  tail -25 "$OUT.build.log"; echo "FATAL: boot-set build failed (full log: $OUT.build.log)"; exit 1; }
BS="$OUT/bootset"
[ -s "$BS/heqk8.img" ] || { echo "FATAL: no signed heqk8.img produced"; exit 1; }

if [ "$ZERO_LINUX" = 1 ]; then MODE_DESC="ZERO-LINUX: no devicetree"; else MODE_DESC="proven: one .dtb"; fi
echo "== [factory] 3/5 canonical A/B boot config ($MODE_DESC)"
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
cp "$BS/heqk8.img" "$STAGE/heqk8-a.img"
cp "$BS/heqk8.img" "$STAGE/heqk8-b.img"           # both slots start identical; OTA replaces B
if [ "$ZERO_LINUX" = 1 ]; then
  TEMPLATE="$HEQK/cm5-boot/config-nolinux.txt"
else
  TEMPLATE="$HEQK/cm5-boot/config.txt"
  DTB="${HEQK_DTB:-$ROOT/legacy/linux-tier/builder/kernel-build/out/bcm2712-rpi-cm5-cm5io.dtb}"
  [ -s "$DTB" ] || { echo "FATAL: proven layout needs $DTB (set HEQK_DTB, or use --zero-linux)"; exit 1; }
  cp "$DTB" "$STAGE/bcm2712-rpi-cm5-cm5io.dtb"
fi
# Canonical config: the template with every kernel= line replaced by ONE slot line. The A and B
# files differ only in that line, and the slot names have equal length, so swapping a commit is a
# same-size in-place rewrite.
python3 -I - "$TEMPLATE" "$STAGE" <<'PY'
import sys, re
tpl, stage = sys.argv[1], sys.argv[2]
lines = [l for l in open(tpl).read().splitlines() if not re.match(r'\s*kernel\s*=', l)]
def emit(path, slot, note):
    body = [f"# heqk A/B boot config — generated by make-cm5-heqk-disk.sh; {note}",
            "# The kernel= line is rewritten IN PLACE (same size) by the on-device A/B commit."]
    body += lines
    # The kernel= line must sit inside ONE 512-byte sector (the commit is a single-sector, atomic
    # rewrite — abboot.rs refuses a split line). Pad with a comment if it would straddle.
    head = ("\n".join(body) + "\n").encode()
    line = f"kernel=heqk8-{slot}.img"
    if len(head) % 512 + len(line) > 512:
        pad = 512 - len(head) % 512 - 1
        body.append("#" * max(pad, 1) if pad >= 1 else "#")
        head = ("\n".join(body) + "\n").encode()
    assert len(head) % 512 + len(line) <= 512
    body += [line, ""]
    open(path, "w").write("\n".join(body))
emit(f"{stage}/config.txt", "a", "cold boot = slot A")
emit(f"{stage}/tryboot.txt", "b", "one-shot trial = slot B")
PY
# OWNER.TXT — fixed 128 bytes (the flasher overwrites it in place; the length never changes).
python3 -I - "$STAGE/OWNER.TXT" "$OWNER_TOKEN" >"$STAGE/owner.token" <<'PY'
import sys, os, hashlib, secrets
path, tok = sys.argv[1], sys.argv[2]
if tok == "auto":
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"            # no URL-encoding needed, no 0/O/1/I
    raw = "".join(secrets.choice(alphabet) for _ in range(24))  # 24*5 = 120 bits
    tok = "-".join(raw[i:i+4] for i in range(0, 24, 4))
if tok:
    if any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in tok) or len(tok) < 16:
        sys.exit("owner token must be >= 16 chars of [A-Za-z0-9-_]")
    salt = os.urandom(16)
    line = f"HQOWN1 {salt.hex()} {hashlib.sha256(salt + tok.encode()).hexdigest()}"
    print(tok)
else:
    line = "HQOWN0 unclaimed"
open(path, "w").write(line.ljust(127) + "\n")
PY
[ "$(stat -c %s "$STAGE/OWNER.TXT")" = 128 ] || { echo "FATAL: OWNER.TXT must be exactly 128 bytes"; exit 1; }

diff <(grep -v '^kernel=\|^# heqk A/B' "$STAGE/config.txt") <(grep -v '^kernel=\|^# heqk A/B' "$STAGE/tryboot.txt") >/dev/null \
  || echo "   note: config.txt and tryboot.txt differ beyond the kernel= line (templates kept as-is)"

echo "== [factory] 4/5 assemble the partitioned disk image (${SIZE_MIB} MiB)"
VER="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo dev)"
# (not `$( [ ... ] && echo ...)`: under set -e that substitution's false status kills the script)
SUFFIX=""; if [ "$ZERO_LINUX" = 1 ]; then SUFFIX="-zerolinux"; fi
IMG="$OUT/hookprobe-heqk-cm5-$VER$SUFFIX.img"
P1_START=8192; P1_SECT=131072                      # 64 MiB FAT32 boot partition
TOTAL=$((SIZE_MIB * 2048))
P2_START=$((P1_START + P1_SECT)); P2_SECT=$((TOTAL - P2_START))
rm -f "$IMG"; truncate -s "${SIZE_MIB}M" "$IMG"
sfdisk --quiet --label dos "$IMG" <<EOF
start=$P1_START, size=$P1_SECT, type=c, bootable
start=$P2_START, size=$P2_SECT, type=da
EOF
# WAN.TXT — the WAN mode (dhcp default / static / pppoe), exactly one 512-B sector so the flasher or
# Mission Control can rewrite it in place. --wan-file supplies the operator's (bench) choice.
python3 -I - "$STAGE/WAN.TXT" "$WAN_FILE" <<'PY'
import sys
dst, src = sys.argv[1], sys.argv[2]
body = open(src, "rb").read() if src else b"HQWAN1\n# mode = dhcp | static | pppoe (see hal::parse_wan_cfg)\nmode=dhcp\n"
if not body.lstrip().startswith(b"HQWAN1") and b"\nHQWAN1" not in body:
    sys.exit("FATAL: WAN file must contain the HQWAN1 magic line")
if len(body) > 512:
    sys.exit("FATAL: WAN file larger than 512 bytes")
open(dst, "wb").write(body + b"\n" * (512 - len(body)))
PY
[ "$(stat -c %s "$STAGE/WAN.TXT")" = 512 ] || { echo "FATAL: WAN.TXT must be exactly 512 bytes"; exit 1; }
# POLICY.TXT — the WAN policy (task #26: interface-attached ACLs + prefix lists, routes; hal::policy),
# a fixed 4 KiB (8 sectors) so it can be rewritten in place. Default = an EMPTY policy (no rules: the
# forwarding behaviour is unchanged). --policy-file supplies the operator's (bench) rules.
python3 -I - "$STAGE/POLICY.TXT" "$POLICY_FILE" <<'PY'
import sys
dst, src = sys.argv[1], sys.argv[2]
body = open(src, "rb").read() if src else b"HQPOL1\n# empty policy: no ACLs, no routes (see hal::policy for the grammar)\n"
if not body.lstrip().startswith(b"HQPOL1") and b"\nHQPOL1" not in body:
    sys.exit("FATAL: policy file must contain the HQPOL1 magic line")
if len(body) > 4096:
    sys.exit("FATAL: policy file larger than 4096 bytes")
open(dst, "wb").write(body + b"\n" * (4096 - len(body)))
PY
[ "$(stat -c %s "$STAGE/POLICY.TXT")" = 4096 ] || { echo "FATAL: POLICY.TXT must be exactly 4096 bytes"; exit 1; }
if [ -n "$POLICY_KEY" ]; then
  python3 -I "$HEQK/tools/policy-sign.py" sign "$POLICY_KEY" "$STAGE/POLICY.TXT" "$POLICY_GEN" "$STAGE/POLICY.SIG" >/dev/null || { echo "FATAL: signing POLICY.TXT failed"; exit 1; }
fi
# BLOCK.TXT / ALLOW.TXT — Shield v2 lists (ADR 0052: hosts / adblock ||d^ / @@ / bare lines, <= 16 MiB), signed with the
# operator key like POLICY.TXT (BLOCK.SIG); absent = Shield counts DNS queries but blocks nothing.
if [ -n "$BLOCK_FILE" ]; then
  [ "$(stat -c %s "$BLOCK_FILE")" -le $((16 << 20)) ] || { echo "FATAL: --blocklist-file larger than 16 MiB"; exit 1; }
  cp "$BLOCK_FILE" "$STAGE/BLOCK.TXT"
  if [ -n "$POLICY_KEY" ]; then
    python3 -I "$HEQK/tools/policy-sign.py" sign-blocklist "$POLICY_KEY" "$STAGE/BLOCK.TXT" "$POLICY_GEN" "$STAGE/BLOCK.SIG" >/dev/null || { echo "FATAL: signing BLOCK.TXT failed"; exit 1; }
  fi
fi
# IOC.TXT (threat intel, detect-only) and DEVICES.TXT (per-device policy) — operator-signed the same way.
stage_signed() { # src dst-name sign-subcommand max-bytes
  [ -n "$1" ] || return 0
  [ "$(stat -c %s "$1")" -le "$4" ] || { echo "FATAL: $1 larger than $4 bytes"; exit 1; }
  cp "$1" "$STAGE/$2.TXT"
  if [ -n "$POLICY_KEY" ]; then
    python3 -I "$HEQK/tools/policy-sign.py" "$3" "$POLICY_KEY" "$STAGE/$2.TXT" "$POLICY_GEN" "$STAGE/$2.SIG" >/dev/null || { echo "FATAL: signing $2.TXT failed"; exit 1; }
  fi
}
stage_signed "$IOC_FILE" IOC sign-ioc $((16 << 20))
stage_signed "$DEVICES_FILE" DEVICES sign-devices $((16 << 10))
stage_signed "$WIFI_FILE" WIFI sign-wifi 1024   # SSID / PSK / channel (contains the PSK: never commit one)
if [ -n "$ALLOW_FILE" ]; then
  [ "$(stat -c %s "$ALLOW_FILE")" -le $((16 << 20)) ] || { echo "FATAL: --allowlist-file larger than 16 MiB"; exit 1; }
  cp "$ALLOW_FILE" "$STAGE/ALLOW.TXT"
  if [ -n "$POLICY_KEY" ]; then
    python3 -I "$HEQK/tools/policy-sign.py" sign-allowlist "$POLICY_KEY" "$STAGE/ALLOW.TXT" "$POLICY_GEN" "$STAGE/ALLOW.SIG" >/dev/null || { echo "FATAL: signing ALLOW.TXT failed"; exit 1; }
  fi
fi
# MCTLS.CRT — the Mission Control HTTPS certificate (ADR 0051): fixed 4096 B so the flasher patches it in
# place. Default = all zeros (unprovisioned: the device publishes its SRK-derived key and serves HTTP only);
# --mctls-file = a chain made by os/kernel/tools/mctls-provision.py for THIS device's key. Public data only.
if [ -n "$MCTLS_FILE" ]; then
  [ "$(stat -c %s "$MCTLS_FILE")" = 4096 ] && head -c 6 "$MCTLS_FILE" | grep -q '^HQCRT1' || { echo "FATAL: --mctls-file must be a 4096-byte HQCRT1 file (tools/mctls-provision.py)"; exit 1; }
  cp "$MCTLS_FILE" "$STAGE/MCTLS.CRT"
else
  head -c 4096 /dev/zero > "$STAGE/MCTLS.CRT"
fi
PART="$STAGE/p1.vfat"
truncate -s $((P1_SECT * 512)) "$PART"
mkfs.vfat -F 32 -n HEQKBOOT "$PART" >/dev/null
for f in "$STAGE"/config.txt "$STAGE"/tryboot.txt "$STAGE"/OWNER.TXT "$STAGE"/WAN.TXT "$STAGE"/POLICY.TXT "$STAGE"/POLICY.SIG "$STAGE"/BLOCK.TXT "$STAGE"/BLOCK.SIG "$STAGE"/ALLOW.TXT "$STAGE"/ALLOW.SIG "$STAGE"/IOC.TXT "$STAGE"/IOC.SIG "$STAGE"/DEVICES.TXT "$STAGE"/DEVICES.SIG "$STAGE"/WIFI.TXT "$STAGE"/WIFI.SIG "$STAGE"/MCTLS.CRT "$STAGE"/heqk8-a.img "$STAGE"/heqk8-b.img "$STAGE"/*.dtb; do
  [ -e "$f" ] && mcopy -i "$PART" "$f" ::"$(basename "$f")"
done
dd if="$PART" of="$IMG" bs=512 seek=$P1_START conv=notrunc status=none

echo "== [factory] 5/5 verify the image"
FAILS=0
check() { if eval "$2"; then echo "   PASS  $1"; else echo "   FAIL  $1"; FAILS=$((FAILS+1)); fi; }
check "MBR: p1 FAT32 @$P1_START, p2 type 0xDA DataVolume @$P2_START (>= LBA 2048)" \
  "sfdisk --dump '$IMG' | grep -q 'start=\s*$P1_START.*type=c' && sfdisk --dump '$IMG' | grep -q 'start=\s*$P2_START.*type=da'"
check "reserved keystore window LBA 2016..2047 is zero and outside every partition" \
  "[ \"\$(dd if='$IMG' bs=512 skip=2016 count=32 status=none | tr -d '\0' | wc -c)\" = 0 ]"
check "boot set present on p1 (both slots, both configs)" \
  "mdir -i '$IMG@@$((P1_START*512))' -b | grep -qi heqk8-a.img && mdir -i '$IMG@@$((P1_START*512))' -b | grep -qi heqk8-b.img && mdir -i '$IMG@@$((P1_START*512))' -b | grep -qi tryboot.txt"
if [ "$ZERO_LINUX" = 1 ]; then
  check "zero Linux artifacts on p1 (no .dtb, no kernel8/initramfs)" \
    "! mdir -i '$IMG@@$((P1_START*512))' -b | grep -Eqi '\.dtb|kernel8|kernel_2712|initramfs|overlays'"
fi
# The device's OWN code against the real layout: boot the QEMU p15-write kernel on a copy.
KDIR="$HEQK/target/factory-check"   # private: never the shared target/
# READ-ONLY check kernel (no p15-write): the p15-write self-tests write fixed LBAs (from 8192 up)
# onto ANY attached disk — on this layout that is p1's boot sector — so they must not run here.
# Without p15-write the same fat.rs locate code runs and nothing is written.
if (cd "$HEQK" && CARGO_TARGET_DIR="$KDIR" cargo build -p kernel --features netsvc,securechannel,securechannel-selftest >/dev/null 2>&1); then
  COPY="$STAGE/check.img"; cp "$IMG" "$COPY"
  timeout 180 qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512M -nographic -serial mon:stdio -semihosting \
    -global virtio-mmio.force-legacy=false -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
    -drive file="$COPY",format=raw,if=none,id=hd0 -device virtio-blk-device,drive=hd0 \
    -kernel "$KDIR/aarch64-unknown-none-softfloat/debug/kernel" >"$STAGE/qemu.log" 2>&1 || true
  # Expected run length = the staged slot's real size in 512-B sectors (1 sector/cluster FS).
  WANT=$(( ($(stat -c %s "$STAGE/heqk8-b.img") + 511) / 512 ))
  check "heqk's own MBR + fat.rs code locates slot B as ONE contiguous run of $WANT sectors (read-only)" \
    "grep -qaE '\\[P15-otafat\\] located HEQK8-B.IMG @ LBA [0-9]+ \\($WANT sectors\\)' '$STAGE/qemu.log'"
  grep -aF "[P15-otafat]" "$STAGE/qemu.log" | sed 's/^/        /' | head -3
else
  echo "   FAIL  could not build the QEMU check kernel"; FAILS=$((FAILS+1))
fi

# Byte offset of OWNER.TXT's data inside the image (the flasher's patch target).
OWNER_OFF="$(python3 -I - "$IMG" $P1_START <<'PY'
import struct, sys
f = open(sys.argv[1], 'rb'); P = int(sys.argv[2])
def sec(l): f.seek(l * 512); return f.read(512)
b = sec(P); rsv = struct.unpack_from('<H', b, 14)[0]; nf = b[16]; fsz = struct.unpack_from('<I', b, 36)[0]
spc = b[13]; data = P + rsv + nf * fsz; root = struct.unpack_from('<I', b, 44)[0]
d = sec(data + (root - 2) * spc)
for i in range(0, 512, 32):
    e = d[i:i+32]
    if e[:11] == b"OWNER   TXT":
        c = (struct.unpack_from('<H', e, 20)[0] << 16) | struct.unpack_from('<H', e, 26)[0]
        print((data + (c - 2) * spc) * 512); break
PY
)"
check "OWNER.TXT located at byte $OWNER_OFF (128 B, the flasher's in-place patch target)" \
  "[ -n '$OWNER_OFF' ] && dd if='$IMG' bs=1 skip=$OWNER_OFF count=6 status=none | grep -q '^HQOWN'"
WAN_OFF="$(python3 -I - "$IMG" $P1_START <<'PY'
import struct, sys
f = open(sys.argv[1], 'rb'); P = int(sys.argv[2])
def sec(l): f.seek(l * 512); return f.read(512)
b = sec(P); rsv = struct.unpack_from('<H', b, 14)[0]; nf = b[16]; fsz = struct.unpack_from('<I', b, 36)[0]
spc = b[13]; data = P + rsv + nf * fsz; root = struct.unpack_from('<I', b, 44)[0]
d = sec(data + (root - 2) * spc)
for i in range(0, 512, 32):
    e = d[i:i+32]
    if e[:11] == b"WAN     TXT":
        c = (struct.unpack_from('<H', e, 20)[0] << 16) | struct.unpack_from('<H', e, 26)[0]
        print((data + (c - 2) * spc) * 512); break
PY
)"
check "WAN.TXT located at byte $WAN_OFF (512 B, mode=$(grep -a -m1 '^mode=' "$STAGE/WAN.TXT" | cut -d= -f2))" \
  "[ -n '$WAN_OFF' ] && dd if='$IMG' bs=1 skip=$WAN_OFF count=6 status=none | grep -q '^HQWAN1'"
POL_OFF="$(python3 -I - "$IMG" $P1_START <<'PY'
import struct, sys
f = open(sys.argv[1], 'rb'); P = int(sys.argv[2])
def sec(l): f.seek(l * 512); return f.read(512)
b = sec(P); rsv = struct.unpack_from('<H', b, 14)[0]; nf = b[16]; fsz = struct.unpack_from('<I', b, 36)[0]
spc = b[13]; data = P + rsv + nf * fsz; root = struct.unpack_from('<I', b, 44)[0]
d = sec(data + (root - 2) * spc)
for i in range(0, 512, 32):
    e = d[i:i+32]
    if e[:11] == b"POLICY  TXT":
        c = (struct.unpack_from('<H', e, 20)[0] << 16) | struct.unpack_from('<H', e, 26)[0]
        print((data + (c - 2) * spc) * 512); break
PY
)"
check "POLICY.TXT located at byte $POL_OFF (4096 B, $(grep -ac '^acl ' "$STAGE/POLICY.TXT") acl lines, $(grep -ac '^route ' "$STAGE/POLICY.TXT") routes)" \
  "[ -n '$POL_OFF' ] && dd if='$IMG' bs=1 skip=$POL_OFF count=6 status=none | grep -q '^HQPOL1'"

TLS_OFF="$(python3 -I - "$IMG" $P1_START <<'PY'
import struct, sys
f = open(sys.argv[1], 'rb'); P = int(sys.argv[2])
def sec(l): f.seek(l * 512); return f.read(512)
b = sec(P); rsv = struct.unpack_from('<H', b, 14)[0]; nf = b[16]; fsz = struct.unpack_from('<I', b, 36)[0]
spc = b[13]; data = P + rsv + nf * fsz; root = struct.unpack_from('<I', b, 44)[0]
d = sec(data + (root - 2) * spc)
for i in range(0, 512, 32):
    e = d[i:i+32]
    if e[:11] == b"MCTLS   CRT":
        c = (struct.unpack_from('<H', e, 20)[0] << 16) | struct.unpack_from('<H', e, 26)[0]
        print((data + (c - 2) * spc) * 512); break
PY
)"
MCTLS_PROV=$(head -c 6 "$STAGE/MCTLS.CRT" | grep -q '^HQCRT1' && echo True || echo False)
check "MCTLS.CRT located at byte $TLS_OFF (4096 B, provisioned=$MCTLS_PROV)" \
  "[ -n '$TLS_OFF' ] && [ \"\$(dd if='$IMG' bs=1 skip=$TLS_OFF count=4096 status=none | sha256sum | cut -d' ' -f1)\" = \"\$(sha256sum '$STAGE/MCTLS.CRT' | cut -d' ' -f1)\" ]"

SHA="$(sha256sum "$IMG" | cut -d' ' -f1)"
echo "$SHA  $(basename "$IMG")" >"$IMG.sha256"
python3 -I - "$IMG.json" <<PY
import json, sys
json.dump({
  "artifact": "$(basename "$IMG")", "sha256": "$SHA", "git": "$VER", "features": "$FEATURES",
  "svn": $SVN, "zero_linux": bool($ZERO_LINUX), "size_mib": $SIZE_MIB,
  "layout": {"p1_fat32": [$P1_START, $P1_SECT], "p2_datavolume_0xda": [$P2_START, $P2_SECT],
             "reserved_zero": [2016, 2048]},
  "slot_sha256": "$(sha256sum "$STAGE/heqk8-a.img" | cut -d' ' -f1)",
  "wan_file": {"offset": int("${WAN_OFF:-0}"), "length": 512},
  "policy_file": {"offset": int("${POL_OFF:-0}"), "length": 4096},
  "mctls_file": {"offset": int("${TLS_OFF:-0}"), "length": 4096, "provisioned": $MCTLS_PROV},
  "owner_file": {"offset": int("${OWNER_OFF:-0}"), "length": 128,
                 "claimed": bool(open("$STAGE/OWNER.TXT").read().startswith("HQOWN1"))},
  "metal_unproven": ["zero-linux boot (no devicetree)"] if $ZERO_LINUX else [],
}, open(sys.argv[1], "w"), indent=2)
PY
echo
[ "$FAILS" = 0 ] && echo "FACTORY: PASS — $IMG (sha256 $SHA)" || { echo "FACTORY: FAIL ($FAILS)"; exit 1; }
if [ -s "$STAGE/owner.token" ]; then
  # The owner key goes to a PRIVATE file next to the image (mode 600), never to stdout: build logs
  # and transcripts are not a place for device credentials. The image holds only its salted hash.
  KEYF="$IMG.owner-key"
  ( umask 077; cp "$STAGE/owner.token" "$KEYF" )
  echo
  echo "OWNER KEY written to $KEYF (mode 600). It is the ONLY copy: the image stores just its salted"
  echo "hash. Keep it (password manager) — without it this device cannot be signed in to."
fi
echo "Flash (Red/operator): the browser flasher, or today: rpiboot + dd of the whole image to the eMMC."
