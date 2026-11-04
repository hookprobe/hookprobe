# Bench runbook — production image (prod-mc) metal acceptance, 2026-11

**Goal:** prove on the CM5 what is today proven only in QEMU — the factory image boots (zero-Linux:
no devicetree), heqk serves Mission Control on the real GEM, the owner key signs in, and a real
attack is dropped, detected and shown in the browser. Also capture the `[BOOT-TIMING]` lines that
decide the late-confirm default. One flash, ~30 minutes. Operator-run (flashing is Red).

## What is ready

| Image (`builder/generated/cm5-heqk/`) | Purpose |
|---|---|
| `hookprobe-heqk-cm5-bf6bcaf-zerolinux.img` | **Primary.** No devicetree, no Linux artifact at all. Tests the U1 gate. |
| `hookprobe-heqk-cm5-bf6bcaf.img` | **Fallback** (proven layout, keeps the one `.dtb`). Use if the primary stays silent. |

Each image has a `.sha256`, a `.json` manifest, and its own `.owner-key` (mode 600): the ONLY copy of
that device's sign-in key. Both are `prod-mc` (Mission Control on GEM, passive-first, owner auth),
signed with the DEV boot keys (bench only — production keys are the K1 ceremony).

Tools: `kernel/heqk/cm5-boot/flash-image.sh` (guarded whole-eMMC write + read-back verify) and
`kernel/heqk/tools/mc-e2e-metal.sh` (the acceptance run; rehearsed against QEMU — PASS).

## Before you start

1. **Coordinate with the other session** — it owns the serial console and the CM5 for AP/NAT work.
2. **Fortress NAC:** the production image uses a NEW per-device MAC (SRK-derived, printed on serial
   as `[MC] Mission Control node UP on GEM: mac ...`). The fortress NAC quarantines unknown MACs
   (DHCP + DNS only), which would block the test. Admit that MAC after boot (operator decision).
3. The flash **erases the whole eMMC** (including any remaining Linux recovery partitions). Use
   `--backup` (below) to keep a full copy; restore = flash that backup file with the same script.

## Steps

```bash
cd ~/hookprobe-os/.claude/worktrees/heqk-premetal-gaps
IMG=builder/generated/cm5-heqk/hookprobe-heqk-cm5-bf6bcaf-zerolinux.img
LOG=~/heqk-metal-logs/$(date +%Y%m%d)-prod-mc-serial.log

# 1. Flash (nRPIBOOT jumper on, power-cycle when prompted). ~5 min + backup time.
sudo kernel/heqk/cm5-boot/flash-image.sh "$IMG" --backup ~/heqk-emmc-backup-$(date +%Y%m%d).img
#    must end with: VERIFIED: eMMC content == image

# 2. Serial capture in a second terminal (CM5 console = FTDI /dev/ttyUSB2, 115200 8N1):
sudo stty -F /dev/ttyUSB2 115200 raw -echo && sudo cat /dev/ttyUSB2 | tee "$LOG"

# 3. Remove the nRPIBOOT jumper, power-cycle the CM5. Wait for (in order):
#    [HBoot-AB] PASS ... [BOOT-TIMING] t=+N ms
#    [P8] rule plane: 11 rules verified
#    [MC] Mission Control node UP on GEM: mac xx:xx:...   <- admit this MAC in the NAC
#    [MC] owner: CLAIMED — sign-in required
#    [BOOT-TIMING] prod loop entered at t=+N ms
#    [MC] heqk Mission Control serving on http://<IP>:80 (DHCP lease)

# 4. Acceptance run (from this host, which is on the same segment via enp4s0):
kernel/heqk/tools/mc-e2e-metal.sh --ip <IP> --key-file "$IMG.owner-key" --serial-log "$LOG"
#    must end with: MC-METAL: PASS   (results file is written under ~/heqk-metal-logs/)

# 5. Optional: open http://<IP>/ in a browser, sign in with the key from "$IMG.owner-key".
```

## If something fails

| Symptom | Meaning | Do |
|---|---|---|
| Total silence on serial | zero-Linux boot (no devicetree) does not work → **U1 not met** | flash the **fallback** image, continue; report it |
| `VERIFY FAILED` from the flash script | bad write | reflash; do not boot |
| `[MC] Mission Control DISABLED — TRNG absent` | TRNG did not init on this boot | power-cycle once; report if it repeats |
| `[MC] owner: UNCLAIMED` | OWNER.TXT not read from eMMC | report (eMMC read path / layout bug) |
| `serving on http://169.254.x.y` | no DHCP lease (NAC or DHCP server) | admit the MAC / check dnsmasq; or test on a direct cable |
| Device reachable but attack not detected | detection on metal differs from QEMU | keep the results + serial log; report |
| Reset loop every ~15 s | confirm never reached (should not happen: late-confirm is off) | power off; report the serial log |

## Report back

The `~/heqk-metal-logs/*-prod-mc-metal-acceptance.txt` results file and the serial log. That
decides: U1 (zero-Linux boot) → first Linux unbuild batch; the late-confirm default (from the
`[BOOT-TIMING]` lines); and the browser flasher being built on an image proven to boot.

**Not in this session:** the on-device A/B commit on metal (the eMMC write clamp must first admit
the BootConfig sector — Gate R), and the production signing keys (K1).
