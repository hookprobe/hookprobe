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
    ap.add_argument("cmd", choices=["status", "off", "on", "cycle", "rpiboot", "boot"])
    a = ap.parse_args()
    if a.dev == "auto":
        if a.backend != "nano":
            sys.exit("--dev auto is only for --backend nano")
        a.dev = find_nano()
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
        r.set(RPIBOOT, False)
        cycle()
        print("power-cycled for a normal eMMC boot")
    elif a.cmd == "rpiboot":
        # 2026-11-12: the operator heard ONE click — the board was never power-cycled while nRPIBOOT was held, so
        # the ROM never saw the boot mode. Assert nRPIBOOT, CONFIRM it by read-back, let the contact settle, then
        # power-cycle with nRPIBOOT still held (atomic inside the Nano firmware where available) and confirm again.
        r.set(RPIBOOT, True)
        if isinstance(r, Nano):
            st = r.status()
            if "rpiboot=1" not in st:
                sys.exit(f"nRPIBOOT not asserted after B1 (read-back: {st or 'no reply'}) — stop")
            time.sleep(0.5)
            ms = max(1, min(100, int(round(a.off_secs * 10))))
            reply = r.cmd(f"C{ms}", timeout=ms / 10 + 3)
            if not reply.startswith("OK"):
                sys.exit(f"power cycle C{ms} failed: {reply or 'no reply'} — stop")
            st = r.status()
            if "power=1" not in st or "rpiboot=1" not in st:
                sys.exit(f"after the cycle the relays read {st or 'no reply'} (want power=1 rpiboot=1) — stop")
            print(f"nRPIBOOT held, power-cycled {ms * 100} ms off ({st})")
        else:
            time.sleep(0.5)
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
