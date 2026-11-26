#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""m5-qemu-rehearsal — rehearse the NanoPi M5 netboot chain on the host, before (and between) metal runs.

Same pinned U-Boot source as the M5 (tools/build/m5-firmware-build.sh), built for qemu_arm64 with the SAME
baked-in boot command (m5-netboot/bootcommand.txt), QEMU user-net DHCP+TFTP serving the SAME boot.cmd, and
the m5probe image. Passes when: U-Boot DHCPs, fetches + sources boot.scr.uimg, booti's the probe, the probe
reports EL2 + RESULT: PASS, and a PSCI SYSTEM_RESET (key `r`) ends QEMU (-no-reboot).

  tools/diagnostics/m5-qemu-rehearsal.py [--work ~/heqk-m5-bench/fw-build] [--timeout 120]
Stdlib only. Log: <work>/rehearsal/serial.log.
"""
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
UBOOT_TAG = "v2026.10"


def sh(cmd, **kw):
    print("+", " ".join(cmd) if isinstance(cmd, list) else cmd, flush=True)
    subprocess.run(cmd, check=True, **kw)


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", default=os.path.expanduser("~/heqk-m5-bench/fw-build"))
    ap.add_argument("--timeout", type=int, default=120)
    a = ap.parse_args()
    work, reh = a.work, os.path.join(a.work, "rehearsal")
    tgz = os.path.join(work, "dl", f"u-boot-{UBOOT_TAG}.tar.gz")
    lock = os.path.join(ROOT, "tools", "build", "m5-firmware.sha256")
    want = [l.split()[0] for l in open(lock) if l.strip().endswith(os.path.basename(tgz))]
    if not os.path.exists(tgz) or not want or sha256(tgz) != want[0]:
        sys.exit(f"{tgz} missing or not matching {lock}: run tools/build/m5-firmware-build.sh first")
    os.makedirs(reh, exist_ok=True)

    # 1. U-Boot for QEMU, same source + same boot command as the M5 firmware
    ub = os.path.join(reh, "u-boot-qemu")
    ubin = os.path.join(ub, "u-boot.bin")
    if not os.path.exists(ubin):
        shutil.rmtree(ub, ignore_errors=True)
        os.makedirs(ub)
        with tarfile.open(tgz) as t:
            t.extractall(ub, filter=lambda m, p: tarfile.data_filter(m.replace(name=m.name.split("/", 1)[1]), p) if "/" in m.name else None)
        env = dict(os.environ, CROSS_COMPILE="aarch64-linux-gnu-")
        sh(["make", "-C", ub, "qemu_arm64_defconfig"], env=env, stdout=subprocess.DEVNULL)
        bootcmd = open(os.path.join(HERE, "m5-netboot", "bootcommand.txt")).read().strip()
        sh([os.path.join(ub, "scripts", "config"), "--file", os.path.join(ub, ".config"),
            "-d", "TOOLS_MKEFICAPSULE", "-d", "TOOLS_MKFWUMDATA", "-e", "USE_BOOTCOMMAND",
            "-d", "BOOTSTD_BOOTCOMMAND", "--set-str", "BOOTCOMMAND", bootcmd])
        sh(["make", "-C", ub, "olddefconfig"], env=env, stdout=subprocess.DEVNULL)
        sh(["make", "-C", ub, f"-j{os.cpu_count()}"], env=env, stdout=subprocess.DEVNULL)

    # 2. TFTP root: boot.scr.uimg (same boot.cmd), the probe, a compact copy of QEMU's DTB
    tftp = os.path.join(reh, "tftp")
    d = os.path.join(tftp, "heqk-m5")
    os.makedirs(d, exist_ok=True)
    sh([os.path.join(ub, "tools", "mkimage"), "-A", "arm64", "-T", "script", "-C", "none", "-n", "heqk-m5",
        "-d", os.path.join(HERE, "m5-netboot", "boot.cmd"), os.path.join(d, "boot.scr.uimg")], stdout=subprocess.DEVNULL)
    sh([os.path.join(HERE, "m5-probe-build.sh"), "--out", reh])
    shutil.copy(os.path.join(reh, "m5probe.img"), os.path.join(d, "heqk-m5.img"))
    qemu = ["qemu-system-aarch64", "-M", "virt,virtualization=on", "-cpu", "cortex-a72", "-m", "1G",
            "-nographic", "-no-reboot", "-bios", ubin]
    raw = os.path.join(reh, "qemu-virt.dtb")
    sh([qemu[0], "-M", f"virt,virtualization=on,dumpdtb={raw}"] + qemu[3:7], stdout=subprocess.DEVNULL)
    sh(["dtc", "-q", "-I", "dtb", "-O", "dtb", "-o", os.path.join(d, "heqk-m5.dtb"), raw])

    # 3. Boot: wait for the probe's PASS, then press `r` and expect QEMU to exit on the PSCI reset.
    logp = os.path.join(reh, "serial.log")
    p = subprocess.Popen(qemu + ["-netdev", f"user,id=n0,tftp={tftp}", "-device", "virtio-net-pci,netdev=n0"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    os.set_blocking(p.stdout.fileno(), False)
    buf, sent, t0 = b"", False, time.time()
    with open(logp, "wb") as log:
        while time.time() - t0 < a.timeout:
            chunk = p.stdout.read() or b""
            if chunk:
                log.write(chunk)
                log.flush()
                buf += chunk
            if not sent and b"[m5probe] keys:" in buf:
                p.stdin.write(b"r")
                p.stdin.flush()
                sent = True
            if p.poll() is not None:
                break
            time.sleep(0.05)
        if p.poll() is None:
            p.kill()
    text = buf.decode(errors="replace").replace("\r", "")
    checks = [
        ("U-Boot DHCP", "DHCP client bound" in text),
        ("boot.scr fetched + sourced", "== heqk-m5 netboot from" in text),
        ("DTB override used", "fdt 0x" in text and "== booti" in text),
        ("probe at EL2", "[m5probe] EL2 " in text),
        ("probe RESULT: PASS", "[m5probe] RESULT: PASS" in text),
        ("PSCI reset ended QEMU", sent and p.returncode == 0 and "PSCI SYSTEM_RESET" in text),
    ]
    for name, ok in checks:
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
    for line in text.splitlines():
        if line.startswith(("[m5probe]", "== ")):
            print("   ", line)
    print(f"log: {logp}")
    sys.exit(0 if all(ok for _, ok in checks) else 1)


if __name__ == "__main__":
    main()
