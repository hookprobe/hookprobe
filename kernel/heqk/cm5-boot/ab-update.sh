#!/usr/bin/env bash
# HEQK A/B updater — stage / commit / inspect the two kernel slots on a CM5 eMMC
# boot partition (exposed via rpiboot, same as flash-cm5.sh).
#
#   SLOT A = heqk8.img    (config.txt)  — the last KNOWN-GOOD HEQK, booted normally
#   SLOT B = heqk8-b.img  (tryboot.txt) — the CANDIDATE, booted once via `tryboot`
#
# The reliability model (no mutable persistent store needed in HBoot):
#   * `reboot "0 tryboot"` (issued on-device) sets the firmware's ONE-SHOT flag,
#     so the very next boot uses tryboot.txt -> SLOT B.
#   * If SLOT B HANGS or PANICS before the kernel confirms, HBoot's EL2 trial
#     watchdog full-resets the SoC; the one-shot is already consumed, so the
#     reset boots SLOT A. If SLOT B boots clean but is never committed, a plain
#     power-cycle also returns to SLOT A. Fallback is automatic either way.
#   * A healthy SLOT B is COMMITTED (promoted to A) with the `commit` subcommand.
#
# Usage (run with sudo, CM5 in rpiboot with its eMMC enumerated):
#   sudo ./ab-update.sh stage  /dev/sdX  <candidate.img>   # write candidate -> SLOT B
#   sudo ./ab-update.sh commit /dev/sdX                    # promote SLOT B -> SLOT A
#   sudo ./ab-update.sh status /dev/sdX                    # show both slot hashes
set -euo pipefail
CMD="${1:?usage: sudo ./ab-update.sh {stage|commit|status} <eMMC device> [candidate.img]}"
DEV="${2:?pass the eMMC block device, e.g. /dev/sdb}"
HERE="$(cd "$(dirname "$0")" && pwd)"
BOOTP="${DEV}1"

[ "$(id -u)" = 0 ] || { echo "ABORT: run with sudo." >&2; exit 1; }
[ -b "$BOOTP" ] || { echo "ABORT: $BOOTP is not a block device (CM5 in rpiboot? rpiboot run?)." >&2; exit 1; }
# Safety: never touch the host's own disks.
case "$(readlink -f "$DEV")" in
  *nvme*|*/dev/sda) echo "ABORT: $DEV looks like a host disk — refusing." >&2; exit 1;;
esac

MNT="$(mktemp -d)"; mount "$BOOTP" "$MNT"; trap 'umount "$MNT" 2>/dev/null; rmdir "$MNT"' EXIT
A="$MNT/heqk8.img"; B="$MNT/heqk8-b.img"
hash_of() { [ -f "$1" ] && sha256sum "$1" | cut -d' ' -f1 || echo "(absent)"; }

case "$CMD" in
  stage)
    CAND="${3:?stage needs a candidate image path}"
    [ -f "$CAND" ] || { echo "ABORT: candidate $CAND not found." >&2; exit 1; }
    # Ensure the slot-B firmware config is present (idempotent).
    cp -f "$HERE/tryboot.txt" "$MNT/tryboot.txt"
    cp -f "$CAND" "$B"; sync
    echo "== staged SLOT B (heqk8-b.img) <- $CAND"
    echo "   SLOT A heqk8.img   : $(hash_of "$A")"
    echo "   SLOT B heqk8-b.img : $(hash_of "$B")"
    echo "== next: on the running device issue  reboot \"0 tryboot\"  to trial SLOT B once."
    echo "   If it hangs/panics before confirming, HBoot's watchdog resets -> SLOT A."
    echo "   If it boots healthy, run:  sudo ./ab-update.sh commit $DEV"
    ;;
  commit)
    [ -f "$B" ] || { echo "ABORT: no SLOT B (heqk8-b.img) to commit." >&2; exit 1; }
    [ -f "$A" ] && cp -f "$A" "$MNT/heqk8.img.prev"   # keep the prior known-good
    cp -f "$B" "$A"; sync
    echo "== committed: SLOT A <- SLOT B (prior A saved as heqk8.img.prev)"
    echo "   SLOT A heqk8.img   : $(hash_of "$A")"
    ;;
  status)
    echo "== A/B slot status on $BOOTP"
    echo "   SLOT A heqk8.img   : $(hash_of "$A")"
    echo "   SLOT B heqk8-b.img : $(hash_of "$B")"
    echo "   prior     .prev    : $(hash_of "$MNT/heqk8.img.prev")"
    [ -f "$MNT/tryboot.txt" ] && echo "   tryboot.txt (slot B config): present" || echo "   tryboot.txt: MISSING (stage will create it)"
    ;;
  *) echo "ABORT: unknown subcommand '$CMD' (use stage|commit|status)." >&2; exit 1;;
esac
