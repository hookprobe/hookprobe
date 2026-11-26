#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""m5-relay — power-cycle the NanoPi M5 (RK3576) bench board and put it into Rockchip maskrom.

Same rig as the CM5 (tools/diagnostics/cm5-relay-nano firmware on an Arduino Nano + 2-channel relay
module), a SECOND unit dedicated to the M5. The Nano protocol code is imported from cm5-relay.py
(one implementation of the read-back / retry logic), only the wiring meaning and the boot-ROM
check differ:

  relay 1 (POWER, Nano D2)  NC contact in series with +12 V of the bench DC supply that feeds the
                            M5's USB-C port through a 5.5x2.1 barrel -> USB-C cable (the M5 takes
                            plain DC 6-20 V on USB-C; sch rev 2411 p16). Idle/unplugged = powered.
  relay 2 (MASK,  Nano D3)  NO contact across the MASK tact switch (pulls SARADC_VIN0_BOOT to GND,
                            sch p19). Energised = MASK held = boot ROM goes to USB maskrom.
                            The firmware auto-releases it after 60 s.

The device MUST be given explicitly (--dev): two CH340 Nanos on one host share the same
/dev/serial/by-id name, so use a Nano with a unique serial (FT232/16U2) or the udev symlink from
tools/diagnostics/m5-netboot/99-hq-m5-bench.rules (/dev/hq-relay-m5). --dev auto is refused.

Commands:
  status            relay read-back
  off | on          board power off / on
  cycle             off, --off-secs, on
  maskrom           off, MASK on, on, hold --hold-secs, MASK off; wait for the Rockchip boot ROM
                    (USB 2207:350e, or any 2207:* that rkdeveloptool lists as Maskrom)
  mask-on|mask-off  MASK alone (bench listening tests)
  --dry-run         print the relay commands, touch nothing
"""
import argparse
import glob
import importlib.util
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("cm5relay", os.path.join(HERE, "cm5-relay.py"))
cm5relay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cm5relay)
POWER, MASK = cm5relay.POWER, cm5relay.RPIBOOT

ROCKCHIP_VID = "2207"
RK3576_MASKROM_PIDS = {"350e"}  # ROCK 4D / RK3576 maskrom ID (Radxa docs); confirm on the bench (runbook §5)
# Adapters on this host that must never be driven as a relay (by-id substrings). The CM5 rig's Nano is
# listed by the operator in M5_FORBID (comma-separated paths) once both Nanos are plugged in.
FORBIDDEN_IDS = cm5relay.FORBIDDEN_IDS + ("Sierra_Wireless",)


def forbidden(dev):
    real = os.path.realpath(dev)
    why = cm5relay.forbidden(dev)
    if why:
        return why
    for p in filter(None, os.environ.get("M5_FORBID", "").split(",")):
        if os.path.exists(p) and os.path.realpath(p) == real:
            return f"listed in M5_FORBID ({p})"
    con = os.environ.get("M5_CONSOLE", "")
    if con and os.path.exists(con) and os.path.realpath(con) == real:
        return "the M5 serial console (M5_CONSOLE)"
    return ""


def rockchip_rom():
    """(vid, pid) of a Rockchip USB device in boot-ROM/loader mode, or None."""
    for d in glob.glob("/sys/bus/usb/devices/*/idVendor"):
        base = os.path.dirname(d)
        try:
            vid = open(d).read().strip()
            pid = open(os.path.join(base, "idProduct")).read().strip()
        except OSError:
            continue
        if vid == ROCKCHIP_VID:
            return vid, pid
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dev", default=os.environ.get("M5_RELAY", ""), help="relay Nano serial device (or $M5_RELAY)")
    ap.add_argument("--off-secs", type=float, default=3.0)
    ap.add_argument("--hold-secs", type=float, default=4.0, help="maskrom: MASK held after power returns (wiki: >= 3 s)")
    ap.add_argument("--gap-secs", type=float, default=2.0, help="maskrom: MASK held with the board off before power returns")
    ap.add_argument("--rom-timeout", type=float, default=20.0)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("cmd", choices=["status", "off", "on", "cycle", "maskrom", "mask-on", "mask-off"])
    a = ap.parse_args()

    if a.dry_run:
        r = cm5relay.Paper()
    else:
        if not a.dev or a.dev == "auto":
            sys.exit("--dev (or $M5_RELAY) is required: auto-detection is refused with two relay Nanos on one host")
        why = forbidden(a.dev)
        if why:
            sys.exit(f"refusing {a.dev}: that is {why}")
        r = cm5relay.Nano(a.dev)

    def st():
        s = r.status()
        print(s.replace("rpiboot=", "mask="))
        return s

    if a.cmd == "status":
        st()
    elif a.cmd == "off":
        r.set(POWER, True)
        st()
    elif a.cmd == "on":
        r.set(POWER, False)
        st()
    elif a.cmd == "cycle":
        r.set(POWER, True)
        time.sleep(a.off_secs)
        r.set(POWER, False)
        st()
    elif a.cmd == "mask-on":
        r.set(MASK, True)
        st()
    elif a.cmd == "mask-off":
        r.set(MASK, False)
        st()
    elif a.cmd == "maskrom":
        # Never switch both relays in the same instant (same rule as the CM5 rig).
        print("-- power off")
        r.set(POWER, True)
        time.sleep(a.off_secs)
        print("-- MASK on (board still off)")
        r.set(MASK, True)
        time.sleep(a.gap_secs)
        print("-- power on, MASK held")
        r.set(POWER, False)
        time.sleep(a.hold_secs)
        print("-- MASK off")
        r.set(MASK, False)
        s = st()
        if not a.dry_run and ("power=1" not in s or "rpiboot=0" not in s):
            sys.exit(f"want power=1 mask=0 after maskrom entry, read {s or 'no reply'} — stop")
        if a.dry_run:
            return
        t0 = time.time()
        while time.time() - t0 < a.rom_timeout:
            rom = rockchip_rom()
            if rom:
                tag = "RK3576 maskrom" if rom[1] in RK3576_MASKROM_PIDS else "Rockchip device (check rkdeveloptool ld)"
                print(f"boot ROM on USB: {rom[0]}:{rom[1]} — {tag}")
                return
            time.sleep(0.5)
        sys.exit("no Rockchip device on USB: check the OTG cable (top USB-A port), the MASK wires, and the BOOT switch")


if __name__ == "__main__":
    main()
