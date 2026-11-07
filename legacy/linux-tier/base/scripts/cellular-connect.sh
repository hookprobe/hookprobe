#!/usr/bin/env bash
# =============================================================================
# cellular-connect.sh — connect a 5G/LTE modem (Get Online) via ModemManager.
# =============================================================================
# Runtime APN/PIN config ONLY. The modem's DRIVER/firmware must already be in the
# image (docs/architecture/driver-strategy.md) — e.g. a USB 5G modem on a CM5 may need a driver
# sysext. Idempotent (no-op if already connected). Waits for a USB modem to
# enumerate (they appear late). `--check` prints the plan without changing anything.
#
# This is the runtime half of HookProbe's "single plane of glass" for cellular:
#   prober detects the modem (or flags a missing driver via scan.unbound)  →
#   driver bundle / sysext provides the driver  →  THIS connects it  →
#   it surfaces in Get Online (Network/Gateway) like any other WAN.
# =============================================================================
set -euo pipefail
CFG="${1:-/etc/hookprobe/cellular.yaml}"
PLAN=0; [ "${2:-}" = "--check" ] && PLAN=1
log() { echo "cellular: $*"; }

# No ModemManager → cellular can't be driven on this image. NOT an error (a wired/Wi-Fi edge has
# no cellular): skip cleanly so boot stays green. Install 'modemmanager' to enable USB-modem detect.
command -v mmcli >/dev/null 2>&1 || { log "ModemManager (mmcli) not installed → no cellular uplink; skipping (install modemmanager to enable USB 5G/LTE detection)"; exit 0; }
[ -f "$CFG" ] || { log "no config at $CFG — cellular not configured"; exit 0; }

# Minimal key:value YAML reader.
val() { sed -nE "s/^$1:[[:space:]]*//p" "$CFG" 2>/dev/null | head -1 | sed -E 's/[[:space:]]*#.*$//; s/^"//; s/"$//; s/[[:space:]]*$//'; }
APN="$(val apn)"; PIN="$(val pin)"; IPT="$(val ip_type)"; ROAM="$(val allow_roaming)"
[ -n "$APN" ] || { log "apn required in $CFG"; exit 1; }

# FAST USB-modem presence check (rpi/cm5/any board). Match by VENDOR ID only: a cellular modem always
# enumerates under its chipset vendor's USB VID regardless of mode (QMI/MBIM=vendor-specific,
# CDC-ECM/NCM, or ACM-serial), and the set of cellular-modem vendors is small + stable. We deliberately
# do NOT match by CDC interface class (02/0a) — USB Ethernet adapters and serial dongles share those
# classes and would false-positive, sending us back into the 30s ModemManager poll. If no known modem
# VID is present we skip in <1s (that 30s poll was the single biggest chunk of boot time). Only when a
# modem IS present do we wait for ModemManager to enumerate it (USB modems appear a few seconds late).
#   Quectel SIMCom Sierra Huawei Telit Fibocom u-blox ZTE Dell/DW Qualcomm Cinterion/Thales Netgear
#   Novatel Meig/CMOTECH HP-rebadge
usb_modem_present() {
  for v in /sys/bus/usb/devices/*/idVendor; do
    [ -r "$v" ] || continue
    case " 2c7c 1e0e 1199 12d1 1bc7 2cb7 1546 19d2 413c 05c6 1e2d 0846 1410 16d8 03f0 " in
      *" $(cat "$v" 2>/dev/null) "*) return 0 ;;
    esac
  done
  return 1
}
if [ "$PLAN" != 1 ] && ! usb_modem_present; then
  log "no USB cellular modem present → skipping cellular uplink in <1s (hotplug a USB 5G/LTE modem to enable)"
  exit 0
fi

# A USB modem IS present (or --check) — wait up to ~30s for ModemManager to enumerate it.
MID=""
for _ in $(seq 1 15); do
  MID="$(mmcli -L 2>/dev/null | grep -oE '/Modem/[0-9]+' | head -1 | grep -oE '[0-9]+$' || true)"
  [ -n "$MID" ] && break
  [ "$PLAN" = 1 ] && break
  sleep 2
done
if [ -z "$MID" ]; then
  # USB modem hardware is present but ModemManager never enumerated it — almost always a missing
  # driver/firmware for that modem (see docs/architecture/driver-strategy.md). Skip cleanly so boot stays green.
  log "USB cellular modem present but ModemManager didn't enumerate it (driver/firmware missing?) → skipping"
  exit 0
fi

if [ "$PLAN" = 1 ]; then
  log "PLAN: modem=$MID apn=$APN ip-type=${IPT:-ipv4v6} roaming=${ROAM:-false} pin=$([ -n "$PIN" ] && echo set || echo none)"
  exit 0
fi

# Unlock the SIM if a PIN is configured.
[ -n "$PIN" ] && mmcli -m "$MID" --pin="$PIN" >/dev/null 2>&1 || true

# Already connected? (idempotent)
if mmcli -m "$MID" 2>/dev/null | grep -qiE "state:[[:space:]]*connected"; then
  log "modem $MID already connected"
  exit 0
fi

log "connecting modem $MID (apn=$APN)"
mmcli -m "$MID" --simple-connect="apn=${APN}${IPT:+,ip-type=$IPT}${ROAM:+,allow-roaming=$ROAM}"
log "connected (apn=$APN)"
