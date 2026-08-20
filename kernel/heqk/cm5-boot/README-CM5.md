# HEQK Core — CM5 (BCM2712) First-Boot Bring-up

**Goal of this first image: prove HEQK Core boots and prints on real silicon over the serial console.** Nothing more — MMU/GIC/timer/RP1-network come *after* we have a console to iterate against.

## What's here
- `heqk8.img` — the flat kernel binary (linked at `0x80000`, entry = boot stub). HEQK-specific name so it never clobbers an existing kernel; `config.txt` `kernel=` and `flash-cm5.sh` both use this exact name (a mismatch here silently boots the Linux image's leftover kernel instead).
- `config.txt` — minimal Pi 5 boot config. **`pciex4_reset=0` is load-bearing**: by default the firmware resets the RP1 PCIe controller before starting the OS, which would make every RP1 access (including the header UART) hang.
- `flash-cm5.sh` — copies both onto the eMMC's FAT boot partition (backs up the old `config.txt`).
- `flash-now.sh` — one-shot rpiboot + copy. **ADDS** heqk files and leaves every Linux file in place, so the one-rename revert (`config.txt.heqk-backup` → `config.txt`) stays available. Use this while heqk is unproven on metal.
- `flash-clean.sh` — **ZERO-LINUX flash.** Archives the whole boot partition to the host (`~/heqk-linux-reference/<UTC-stamp>/`, override with `HEQK_ARCHIVE_ROOT`), reads the archive back to verify it, and only THEN wipes the partition and writes heqk alone. Removes ~102 MB of resident Linux boot artifacts (`kernel8.img`, `kernel_2712.img`, both initramfs, cmdline, dtbs, overlays) from the board.
  - `--no-dtb` → uses `config-nolinux.txt`: no devicetree at all. heqk never parses one (HBoot prints `dtb_pa` and ignores it), but the firmware applies `dtparam=` to the DTB **before** OS entry, so with no DTB the RTL8111H (eth1) PCIe RC1 is not trained. `pciex4_reset=0` is a plain config parameter and still works, so RP1/GEM (eth0) is unaffected — correct for the M1 gate, wrong once eth1 matters.
  - default (no flag) keeps exactly ONE Linux artifact: the `.dtb` that `config.txt` names.
  - `--with-rootfs` also images part2 (the Debian rootfs) to the archive. Without it, part2 is left INTACT on the eMMC — `flash-clean.sh` only touches part1.
  - `--restore <archive-dir>` repopulates the boot partition and promotes the saved Linux `config.txt` back.
- `config-nolinux.txt` — the no-devicetree boot config (see above for what it costs).

> **Recovery.** The CM5's boot firmware is in SPI EEPROM, *not* on the FAT partition, so wiping part1 cannot brick the board — rpiboot always re-enumerates the eMMC. If heqk does not boot: nRPIBOOT jumper, power-cycle, `sudo ./flash-clean.sh --restore <archive-dir>`. Note this is an rpiboot cycle rather than a `config.txt` rename, which is the trade you accept for a genuinely zero-Linux first metal test.

## Console: which UART and why (ground truth, 2026-07-20)
The CM5 has two candidate PL011s:

| UART | Address | Bare-metal state at entry | Physically reachable |
|---|---|---|---|
| **RP1 UART0** (GPIO14/15, header pins 8/10) | `0x1F00030000` | needs `pciex4_reset=0` + our pinmux (FUNCSEL=4) + PL011 init (clk 50 MHz → IBRD 27/FBRD 8) | 40-pin header on the carrier — **the bench FTDI is already here** (validated: it carried the Linux `ttyAMA0` console + login prompt) |
| uart10 (on-SoC debug) | `0x107D001000` | always enabled + pre-programmed by firmware; raw DR writes work | **module-only**: JST-SH pads / testpoints TP35-36 on the CM5 itself — *no carrier board routes it* |

So: **RP1 UART0 is the console** (leave the FTDI wired exactly where it is, 115200 8N1); uart10 is mirrored as a firmware-guaranteed fallback for pogo-pin debugging.

## Boot markers (from the asm stub, before any Rust)
1. `HK1` → emitted on **uart10** (module pads only) using the firmware's own UART setup.
2. RP1 pinmux + PL011 init, then `HK2` → emitted on **the header UART (FTDI)**.
3. Rust `kmain` re-inits the console and prints the full banner to both.

## Expected serial output on the FTDI (success)
```
HK2
================================================
 HEQK Core on BCM2712 (Raspberry Pi CM5) — real silicon
================================================
 boot: running at EL2        (or EL1)
 cpu : MIDR_EL1=0x414fd0b1 (part 0x0d0b; 0xd0b=Cortex-A76)
 uart: RP1 UART0 @ 0x1F00030000 (GPIO14/15 header = the FTDI) + uart10 mirror
 [CM5-BOOT] PASS — HEQK boots and prints on real hardware
 halting; next: MMU high-PA map, GIC-400 @0x107FFF9000, generic timer, then RP1
```

## Flash procedure
1. Put the CM5 into **rpiboot / USB-boot** mode (carrier BOOT/nRPIBOOT switch), USB cable to this host, `sudo rpiboot` (current usbboot build — the packaged 2022 one can't flash BCM2712), eMMC appears as a block device.
2. `sudo ./flash-cm5.sh /dev/sdX`
3. Switch back to eMMC boot, power-cycle, watch the FTDI at 115200 (e.g. `~/hookprobe-bsd/rig/console.sh`).

## Failure decision table
| Symptom on FTDI | Meaning | Next move |
|---|---|---|
| `HK2` + full banner | PASS | proceed to MMU/GIC bring-up |
| `HK2` only, no banner | stub→Rust transition broke (stack/bss/kmain) | bisect in `boot_cm5.s` after the marker |
| garbled bytes at boot | RP1 `clk_uart` ≠ 50 MHz (divisor wrong) | try IBRD/FBRD for 54 MHz (29/17) or probe with a scope |
| total silence | firmware never entered the image, OR RP1 access hung (`pciex4_reset=0` missing/ignored) | pogo-probe TP35/36 on the module for `HK1`: `HK1` present = RP1 path is the problem; absent = load/format problem |
| Linux boots instead | `config.txt` not applied / wrong `kernel=` | check FAT partition contents |

## ✅ RESOLVED — 2026-07-21, tryboot 17: HEQK boots and prints on real silicon

Full banner + `RUST OK` + `[CM5-BOOT] PASS` captured over the FTDI. Root causes, in
the order they were unmasked (17 tryboots):
1. **Wrong RP1 window**: at handoff RP1 is ARM-visible at **0x1C_0000_0000** (the
   bootloader's mapping, printed in its own banner) — not Linux's 0x1F.
2. **Posted-PCIe-write races**: back-to-back clock/pinmux/PL011 writes with no
   read-backs killed the console after ~1 byte. Fix: dump-before-touch + a
   read-back/`dsb` after every programming step (the BootDebug crumb discipline).
3. Firmware facts from the crumbs: entry at **EL2 with MMU OFF** (SCTLR=0x30c50830);
   with `enable_rp1_uart=1` the UART arrives **already configured** (IBRD 27/FBRD 8
   @50 MHz, CR=0x301, clk armed) — re-programming it is what broke it.
4. **Load address 0x200000**, MZ-mimic header, `pciex4_reset=0`+`enable_rp1_uart=1`,
   tryboot one-shot loop, PM reset @0x107D200000 (bcm2835 layout) all verified live.
Console doctrine now in force: the stub owns bring-up; Rust `init()` is a no-op;
single UART owner; every future device gets the same crumb+barrier treatment.

## Bring-up log — 2026-07-21 (tryboots 1–6, all facts from live firmware console)
- `enable_rp1_uart=1` + `pciex4_reset=0` WORK: the EEPROM (May 2026) mirrors its
  full boot log to the GPIO14/15 header UART — the FTDI sees the firmware.
- The firmware loads arm64 images at **0x200000**, not 0x80000 (`kernel_address=0x80000`
  got "Kernel relocated to 0x200000"; without it, direct load to 0x200000).
  → `linker-cm5.ld` now links at 0x200000.
- With config applied, image+DTB loaded correctly, the firmware trace **ends at
  "Device tree loaded to 0x2efec100"** and the ARM never executes our first
  instruction: an unhangable raw-FIFO "HK0" marker at `_start` never appears.
- Every hang self-diagnoses now: PCIe RC link probe @0x1000120000+0x4068 with
  clean PM-reset fallback (0x107D200000, bcm2835 layout) — but none of it runs.
- **Open question**: what does the firmware do after "Device tree loaded" on a
  SUCCESSFUL Linux boot? Linux config.txt now also has enable_rp1_uart=1 — the
  next normal power-cycle boot captures the known-good handoff trace to diff.
  Leading suspect: the RPi kernel trailer (RPTL atoms) real kernels carry.

## Known hazards (from research, 2026-07-20)
- tnishinaga's Pi 5 bare-metal GPIO14/15 UART worked via SWD load but he never confirmed SD-card boot — root cause unresolved. Circle (rsta2) is the proven reference for this path: 50 MHz clock, own PCIe bring-up. If `pciex4_reset=0` turns out not to be honored, the fallback is porting Circle's minimal RP1 PCIe RC init.
- The 50 MHz `clk_uart` value comes from Circle's working driver, not an official document. First garbled output → suspect the clock, not the wiring (wiring is already validated under Linux).
