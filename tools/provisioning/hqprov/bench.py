"""Bench-station I/O: serial capture, the existing flasher, the relay rig, rpiboot disk discovery.

All of this needs real hardware and is NOT exercised by the unit tests (they replay recorded logs).
Existing tools reused, not reimplemented:
  - os/kernel/cm5-boot/flash-image.sh   (guarded whole-eMMC write + sha256 read-back; needs root)
  - tools/diagnostics/cm5-relay.py      (bench relays: power cycle / assert nRPIBOOT)
"""
import glob
import os
import re
import select
import shlex
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
FLASH_IMAGE = os.path.join(REPO, "os/kernel/cm5-boot/flash-image.sh")
RELAY_PY = os.path.join(REPO, "tools/diagnostics/cm5-relay.py")
MCTLS_PROVISION = os.path.join(REPO, "os/kernel/tools/mctls-provision.py")
MC_E2E_METAL = os.path.join(REPO, "os/kernel/tools/mc-e2e-metal.sh")
USBBOOT = os.path.join(REPO, "os/kernel/tools/usbboot")


class BenchError(Exception):
    pass


def relay(relay_args, cmd, timeout=120):
    """cm5-relay.py <relay_args> <cmd>; relay_args e.g. '--backend nano --dev auto'."""
    r = subprocess.run([sys.executable, RELAY_PY, *shlex.split(relay_args), cmd],
                       capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise BenchError(f"relay {cmd} failed: {(r.stdout + r.stderr).strip()}")
    return r.stdout.strip()


def flash(image, confirm_erase=False, backup=None):
    """flash-image.sh via sudo when not root. The script's own guards (by-id USB mass storage only, sha256
    read-back, typed FLASH unless --confirm-erase) apply unchanged."""
    if not os.path.exists(FLASH_IMAGE):
        raise BenchError(f"flasher missing: {FLASH_IMAGE}")
    cmd = [FLASH_IMAGE, image]
    if backup:
        cmd += ["--backup", backup]
    if confirm_erase:
        cmd.append("--confirm-erase")
    if os.geteuid() != 0:
        cmd = ["sudo"] + cmd
    r = subprocess.run(cmd)               # interactive: the operator sees the prompts
    if r.returncode != 0:
        raise BenchError(f"flash-image.sh exited {r.returncode} (device NOT verified; reflash)")


def find_rpiboot_disk(wait=30):
    """The CM5 eMMC exposed over USB mass storage (same selection as flash-image.sh:51)."""
    for _ in range(max(1, wait)):
        c = [d for pat in ("/dev/disk/by-id/usb-*Raspberry_Pi*", "/dev/disk/by-id/usb-RPi*MSD*")
             for d in glob.glob(pat) if not re.search(r"-part\d+$", d)]
        if c:
            return sorted(c)[0]
        time.sleep(1)
    return None


def run_rpiboot():
    exe = os.path.join(USBBOOT, "rpiboot")
    if not os.access(exe, os.X_OK):
        raise BenchError("vendored rpiboot not built: " + exe)
    cmd = [exe, "-d", os.path.join(USBBOOT, "mass-storage-gadget64")]
    if os.geteuid() != 0:
        cmd = ["sudo"] + cmd
    if subprocess.run(cmd).returncode != 0:
        raise BenchError("rpiboot failed")


def open_console(dev, baud=115200):
    import termios
    fd = os.open(dev, os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
    a = termios.tcgetattr(fd)
    a[0] = a[1] = a[3] = 0                                   # raw
    a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    a[4] = a[5] = getattr(termios, f"B{baud}")
    a[6][termios.VMIN], a[6][termios.VTIME] = 0, 0
    termios.tcsetattr(fd, termios.TCSANOW, a)
    return fd


def capture(fd, until, timeout, on_start=None):
    """Read the console until every regex in `until` has matched (or timeout). Returns (text, all_seen).

    `on_start` runs AFTER the console is open (e.g. the relay power cycle), so no boot output is lost.
    The text is held in memory only: it contains the setup passphrase; callers store a redacted copy.
    """
    if on_start:
        on_start()
    buf = b""
    t0 = time.time()
    rx = [re.compile(p) for p in until]
    while time.time() - t0 < timeout:
        r, _, _ = select.select([fd], [], [], 0.5)
        if r:
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                chunk = b""
            buf += chunk
            text = buf.decode("utf-8", "replace")
            if all(x.search(text) for x in rx):
                time.sleep(1.0)                                  # let the tail of the burst land
                try:
                    buf += os.read(fd, 65536)
                except BlockingIOError:
                    pass
                return buf.decode("utf-8", "replace"), True
    text = buf.decode("utf-8", "replace")
    return text, all(x.search(text) for x in rx)


def prompt(msg, non_interactive):
    if non_interactive:
        raise BenchError(f"operator action required but --non-interactive: {msg}")
    input(f">> {msg} [Enter] ")
