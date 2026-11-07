#!/usr/bin/env python3
"""cm5-relay — power-cycle the CM5 bench board and put it into rpiboot from fortress001.

Wiring (2-channel USB relay module):
  relay 1 (POWER)    in series with the CM5 IO board's 5 V feed. Wire it through the NC
                     (normally-closed) contact so the board stays powered when the relay
                     is de-energised or the host is off; "power off" = energise relay 1.
  relay 2 (RPIBOOT)  across the nRPIBOOT jumper (CM5 IO board J2 "Disable eMMC Boot") to GND,
                     on the NO (normally-open) contact; "rpiboot asserted" = energise relay 2.

Backends (stdlib only, no pip):
  lcus  CH340 serial modules (LCUS-1/LCUS-2, 9600 8N1): frame A0 <ch> <0|1> <sum>.
        Device: /dev/ttyUSB* — pass --dev (use /dev/serial/by-id/... so the debug
        console on /dev/ttyUSB2 is never written to by mistake).
  hid   USBRelay2 / dcttech HID modules (16c0:05df): feature report FF/FD <ch>.
        Device: /dev/hidrawN (needs a udev rule granting the user access).

Commands:
  status           print what the tool believes (lcus modules cannot be read back)
  off | on         power the board off / on (relay 1)
  cycle            off, wait --off-secs, on
  rpiboot          assert nRPIBOOT, power-cycle, wait for the 0a5c:2712 boot ROM on USB,
                   then release nRPIBOOT (the ROM has latched the mode by then)
  boot             release nRPIBOOT, power-cycle (normal eMMC boot)

Examples:
  tools/cm5-relay.py --backend lcus --dev /dev/serial/by-id/usb-1a86_USB_Serial-if00-port0 rpiboot
  tools/cm5-relay.py --backend hid --dev /dev/hidraw3 boot
"""
import argparse
import glob
import os
import sys
import termios
import time

POWER, RPIBOOT = 1, 2
BOOTROM_IDS = {("0a5c", "2712"), ("0a5c", "2711")}  # BCM2712 (CM5) / BCM2711 (CM4)
CONSOLE_GUARD = "/dev/ttyUSB2"  # the CM5 serial console on this bench — never a relay


class Lcus:
    def __init__(self, dev):
        real = os.path.realpath(dev)
        if real == os.path.realpath(CONSOLE_GUARD):
            sys.exit(f"refusing {dev}: that is the CM5 serial console ({CONSOLE_GUARD})")
        self.fd = os.open(real, os.O_RDWR | os.O_NOCTTY)
        a = termios.tcgetattr(self.fd)
        a[0] = 0
        a[1] = 0
        a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
        a[3] = 0
        a[4] = a[5] = termios.B9600
        termios.tcsetattr(self.fd, termios.TCSANOW, a)

    def set(self, ch, on):
        frame = bytes([0xA0, ch, 1 if on else 0])
        os.write(self.fd, frame + bytes([sum(frame) & 0xFF]))
        termios.tcdrain(self.fd)
        time.sleep(0.05)


class Hid:
    def __init__(self, dev):
        self.fd = os.open(dev, os.O_RDWR)

    def set(self, ch, on):
        import fcntl
        report = bytes([0x00, 0xFF if on else 0xFD, ch]) + bytes(6)
        # HIDIOCSFEATURE(len) = _IOC(_IOC_READ|_IOC_WRITE, 'H', 0x06, len)
        req = (3 << 30) | (len(report) << 16) | (ord("H") << 8) | 0x06
        fcntl.ioctl(self.fd, req, report)
        time.sleep(0.05)


def bootrom_present():
    for d in glob.glob("/sys/bus/usb/devices/*/idVendor"):
        base = os.path.dirname(d)
        try:
            vid = open(d).read().strip()
            pid = open(os.path.join(base, "idProduct")).read().strip()
        except OSError:
            continue
        if (vid, pid) in BOOTROM_IDS:
            return True
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", choices=["lcus", "hid"], required=True)
    ap.add_argument("--dev", required=True)
    ap.add_argument("--off-secs", type=float, default=3.0, help="power-off dwell (CM5 caps drain)")
    ap.add_argument("--rom-timeout", type=float, default=15.0)
    ap.add_argument("cmd", choices=["status", "off", "on", "cycle", "rpiboot", "boot"])
    a = ap.parse_args()
    r = Lcus(a.dev) if a.backend == "lcus" else Hid(a.dev)

    def cycle():
        r.set(POWER, True)  # energise = NC opens = board unpowered
        time.sleep(a.off_secs)
        r.set(POWER, False)

    if a.cmd == "status":
        print(f"boot ROM on USB: {'yes' if bootrom_present() else 'no'}")
    elif a.cmd == "off":
        r.set(POWER, True)
    elif a.cmd == "on":
        r.set(POWER, False)
    elif a.cmd == "cycle":
        cycle()
    elif a.cmd == "boot":
        r.set(RPIBOOT, False)
        cycle()
        print("power-cycled for a normal eMMC boot")
    elif a.cmd == "rpiboot":
        r.set(RPIBOOT, True)
        cycle()
        t0 = time.time()
        while time.time() - t0 < a.rom_timeout and not bootrom_present():
            time.sleep(0.2)
        ok = bootrom_present()
        r.set(RPIBOOT, False)
        if not ok:
            sys.exit(f"boot ROM (0a5c:2712) did not enumerate within {a.rom_timeout}s — check the RPIBOOT wiring")
        print("CM5 boot ROM enumerated — run rpiboot -d mass-storage-gadget64 next")


if __name__ == "__main__":
    main()
