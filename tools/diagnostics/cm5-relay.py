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
  nano  Arduino Nano v3 running cm5-relay-nano/ (115200 8N1, line protocol with read-back,
        safe defaults, RPIBOOT auto-release 60 s, power auto-restore 120 s).
        --dev auto picks the single CH340/Arduino serial port that is neither the console
        nor the LTE modem. Pins: D2 = POWER relay, D3 = RPIBOOT relay.

Commands:
  status           print what the tool believes (lcus modules cannot be read back)
  off | on         power the board off / on (relay 1)
  cycle            off, wait --off-secs, on
  rpiboot          assert nRPIBOOT, power-cycle, wait for the 0a5c:2712 boot ROM on USB,
                   then release nRPIBOOT (the ROM has latched the mode by then)
  boot             release nRPIBOOT, power-cycle (normal eMMC boot)

Examples:
  tools/diagnostics/cm5-relay.py --backend lcus --dev /dev/serial/by-id/usb-1a86_USB_Serial-if00-port0 rpiboot
  tools/diagnostics/cm5-relay.py --backend hid --dev /dev/hidraw3 boot
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
# Never write to these either: the console (FTDI) and the LTE modem behind wwan0 (Sierra).
FORBIDDEN_IDS = ("FTDI_FT232R_USB_UART_AB0OHO28", "Sierra_Wireless")


class Lcus:
    def __init__(self, dev):
        why = forbidden(dev)
        if why:
            sys.exit(f"refusing {dev}: that is {why}")
        self.fd = os.open(os.path.realpath(dev), os.O_RDWR | os.O_NOCTTY)
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


def forbidden(dev):
    real = os.path.realpath(dev)
    if real == os.path.realpath(CONSOLE_GUARD):
        return "the CM5 serial console"
    for link in glob.glob("/dev/serial/by-id/*"):
        if os.path.realpath(link) == real and any(f in link for f in FORBIDDEN_IDS):
            return f"a protected device ({os.path.basename(link)})"
    return None


def find_nano():
    """The single serial port that looks like a Nano (CH340 / Arduino / 16U2) and is not protected."""
    cands = []
    for link in sorted(glob.glob("/dev/serial/by-id/*")):
        name = os.path.basename(link)
        if any(f in name for f in FORBIDDEN_IDS):
            continue
        if "1a86" in name or "Arduino" in name or "CH340" in name or "wch" in name.lower():
            cands.append(link)
    if len(cands) != 1:
        sys.exit(f"--dev auto: expected exactly one Nano-like serial port, found {cands or 'none'} — pass --dev")
    return cands[0]


class Nano:
    """cm5-relay-nano firmware: replies are checked, state can be read back."""

    def __init__(self, dev):
        why = forbidden(dev)
        if why:
            sys.exit(f"refusing {dev}: that is {why}")
        self.fd = os.open(os.path.realpath(dev), os.O_RDWR | os.O_NOCTTY)
        a = termios.tcgetattr(self.fd)
        a[0] = 0
        a[1] = 0
        # no HUPCL: keep DTR asserted on close so the next open does not reset the Nano
        a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
        a[3] = 0
        a[4] = a[5] = termios.B115200
        a[6][termios.VMIN] = 0
        a[6][termios.VTIME] = 1
        termios.tcsetattr(self.fd, termios.TCSANOW, a)
        # The first open after plug-in resets the Nano (DTR): wait for it to answer.
        t0 = time.time()
        while time.time() - t0 < 4.0:
            if self.cmd("?", timeout=0.6).startswith("HQRELAY1"):
                return
        sys.exit(f"{dev}: no HQRELAY1 answer — is cm5-relay-nano flashed? (make -C tools/diagnostics/cm5-relay-nano flash PORT=...)")

    def cmd(self, line, timeout=2.0):
        termios.tcflush(self.fd, termios.TCIFLUSH)
        os.write(self.fd, (line + "\n").encode())
        buf = b""
        t0 = time.time()
        while time.time() - t0 < timeout:
            buf += os.read(self.fd, 64)
            for ln in buf.split(b"\n"):
                ln = ln.strip().decode(errors="replace")
                if ln.startswith(("OK", "ERR", "HQRELAY1 power")):
                    return ln
        return ""

    def set(self, ch, on):
        line = ("P0" if on else "P1") if ch == POWER else ("B1" if on else "B0")
        reply = self.cmd(line)
        if not reply.startswith("OK"):
            sys.exit(f"relay command {line} failed: {reply or 'no reply'}")

    def status(self):
        return self.cmd("?")


class Paper:
    """--dry-run: print the relay commands in order; touch nothing (operator paper test before any real run)."""

    def __init__(self, dev=None):
        self.st = {1: "power=1", 2: "rpiboot=0"}

    def set(self, ch, on):
        name = "IN1 power relay" if ch == POWER else "IN2 nRPIBOOT relay"
        if ch == POWER:
            print(f"  {'P0' if on else 'P1'}  {name} {'ENERGISED (board OFF)' if on else 'released (board ON)'}")
        else:
            print(f"  {'B1' if on else 'B0'}  {name} {'ENERGISED (nRPIBOOT held)' if on else 'released'}")

    def status(self):
        return "HQRELAY1 power=1 rpiboot=1 (paper)"

    def cmd(self, line, timeout=2.0):
        print(f"  {line}")
        return "OK (paper)"


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
    ap.add_argument("--backend", choices=["lcus", "hid", "nano"], required=True)
    ap.add_argument("--dev", required=True, help="device path, or auto (nano only)")
    ap.add_argument("--off-secs", type=float, default=5.0, help="power-off dwell (CM5 caps drain)")
    ap.add_argument("--rom-timeout", type=float, default=15.0)
    ap.add_argument("--dry-run", action="store_true", help="paper test: print the relay commands in order, touch nothing")
    ap.add_argument("cmd", choices=["status", "off", "on", "cycle", "rpiboot", "boot"])
    a = ap.parse_args()
    if a.dev == "auto" and not a.dry_run:
        if a.backend != "nano":
            sys.exit("--dev auto is only for --backend nano")
        a.dev = find_nano()
    if a.dry_run:
        print(f"PAPER TEST ({a.cmd}) — no relay is touched; the real run sends exactly these, in this order:")
        r = Paper()
    else:
        r = {"lcus": Lcus, "hid": Hid, "nano": Nano}[a.backend](a.dev)

    def cycle():
        r.set(POWER, True)  # energise = NC opens = board unpowered
        time.sleep(a.off_secs)
        r.set(POWER, False)

    if a.cmd == "status":
        print(f"boot ROM on USB: {'yes' if bootrom_present() else 'no'}")
        if isinstance(r, Nano):
            print(f"relays: {r.status()}")
    elif a.cmd == "off":
        r.set(POWER, True)
    elif a.cmd == "on":
        r.set(POWER, False)
    elif a.cmd == "cycle":
        cycle()
    elif a.cmd == "boot":
        # operator: after flashing, reset IN1 only (IN2 is already released by rpiboot)
        if isinstance(r, Paper):
            r.set(POWER, True)
            print(f"  (wait {a.off_secs:.0f} s)")
            r.set(POWER, False)
            return
        cycle()
        print("IN1 reset — power-cycled for a normal eMMC boot")
    elif a.cmd == "rpiboot":
        # Operator procedure (2026-11-12, proven at the bench with the IN1/IN2 LEDs): energise IN1 (power OFF) and IN2
        # (nRPIBOOT) together, wait for the caps to drain, then release BOTH — IN1 first, so nRPIBOOT is still held at
        # the instant power returns and the ROM latches USB boot. Asserting nRPIBOOT first and cycling power after it
        # left IN1 unswitched (one click). Each step is read back on the Nano.
        r.set(POWER, True)
        r.set(RPIBOOT, True)
        if isinstance(r, Nano):
            st = r.status()
            if "power=0" not in st or "rpiboot=1" not in st:
                sys.exit(f"want power=0 rpiboot=1 (IN1 + IN2 on), read {st or 'no reply'} — stop")
        if isinstance(r, Paper):
            print(f"  (wait {a.off_secs:.0f} s — caps drain)")
        else:
            time.sleep(a.off_secs)
        r.set(POWER, False)
        r.set(RPIBOOT, False)
        if isinstance(r, Paper):
            print("  (wait up to --rom-timeout for the boot ROM 0a5c:2712 on USB, then: rpiboot -d mass-storage-gadget64, flash)")
            return
        if isinstance(r, Nano):
            st = r.status()
            if "power=1" not in st or "rpiboot=0" not in st:
                sys.exit(f"want power=1 rpiboot=0 (both released), read {st or 'no reply'} — stop")
            print(f"IN1 + IN2 on -> both released, IN1 first ({st})")
        t0 = time.time()
        while time.time() - t0 < a.rom_timeout and not bootrom_present():
            time.sleep(0.2)
        ok = bootrom_present()
        if not ok:
            sys.exit(f"boot ROM (0a5c:2712) did not enumerate within {a.rom_timeout}s — check the RPIBOOT wiring")
        print("CM5 boot ROM enumerated — run rpiboot -d mass-storage-gadget64 next")


if __name__ == "__main__":
    main()
