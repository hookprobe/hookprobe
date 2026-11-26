# tools/diagnostics

| Tool | What |
|---|---|
| [`cm5-metal-loop.sh`](cm5-metal-loop.sh) | One unattended round: relay rpiboot → flash + verify → relay boot → wait for serial markers → PASS/FAIL report |
| [`cm5-relay-nano/`](cm5-relay-nano/) | Arduino Nano v3 firmware for the two bench relays (safe defaults, read-back, auto-release) |
| [`cm5-relay.py`](cm5-relay.py) | Power-cycles the CM5 bench board and asserts nRPIBOOT through a 2-channel USB relay, so it can be reflashed without anyone touching it |
| [`os/kernel/tools/mc-e2e-metal.sh`](../../os/kernel/tools/mc-e2e-metal.sh) | Metal acceptance run against a live CM5 |
| [`m5-relay.py`](m5-relay.py) | NanoPi M5 bench: power-cycle and forced maskrom (MASK) through a second Nano rig (same firmware, reuses the `cm5-relay.py` protocol code) |
| [`m5-console.sh`](m5-console.sh) | NanoPi M5 serial capture at 1 500 000 8N1 into `~/heqk-metal-logs/` |
| [`m5-metal-loop.sh`](m5-metal-loop.sh) | NanoPi M5 unattended round, netboot: stage image in TFTP → relay cycle → U-Boot booti → serial markers → PASS/FAIL |
| [`m5-spi-flash.sh`](m5-spi-flash.sh) | NanoPi M5 SPI-NOR loader write via maskrom + read-back verify (recovery path) |
| [`m5-probe-build.sh`](m5-probe-build.sh) | Builds the NanoPi M5 bring-up probe (`os/kernel/m5probe`): 31 KiB PIE booti payload that reports EL/FDT/PSCI and tests reset, off, maskrom, watchdog, LED |
| [`m5-qemu-rehearsal.py`](m5-qemu-rehearsal.py) | Rehearses the M5 netboot chain on the host: same pinned U-Boot (qemu_arm64) + same boot command + same boot.cmd + probe over TFTP, 6 checks |
| [`m5-netboot/`](m5-netboot/) | dnsmasq + udev examples and the U-Boot `boot.cmd` for the M5 netboot loop |

NanoPi M5 runbook: `docs/design/heqk-nanopi-m5-bench-runbook-2026-11-26.md`.
| [`os/kernel/tools/gate-r-run.py`](../../os/kernel/tools/gate-r-run.py) | Separation-matrix (Gate R) run |

Serial console: FTDI at 115200. The CM5 prints its boot timing, device identity (`[NETCP] pk=`)
and Mission Control address on it.

## Arduino Nano relay rig

Wiring (relay module powered from the Nano's 5 V / GND):

| Nano | Relay | Contact | CM5 IO board |
|---|---|---|---|
| D2 | IN1 (POWER) | **NC** + COM in series with the board's 5 V feed | board stays powered when the relay is idle or the Nano is unplugged |
| D3 | IN2 (RPIBOOT) | **NO** + COM across the nRPIBOOT jumper (J2 "Disable eMMC Boot") | open = normal eMMC boot |
| D13 | (on-board LED) | — | lit while nRPIBOOT is asserted |

Most Arduino relay modules are active-low (the default build). For an active-high module build with
`ACTIVE_LOW=0`. Safety in the firmware: both coils idle at reset; nRPIBOOT auto-releases after 60 s;
power-off auto-restores after 120 s.

Bring-up:

```bash
ls -l /dev/serial/by-id/                         # the Nano shows up as usb-1a86_... (CH340) or ttyACM
make -C tools/diagnostics/cm5-relay-nano flash PORT=/dev/serial/by-id/usb-1a86_...
tools/diagnostics/cm5-relay.py --backend nano --dev auto status    # -> relays: HQRELAY1 power=1 rpiboot=0
tools/diagnostics/cm5-relay.py --backend nano --dev auto cycle     # board reboots
tools/diagnostics/cm5-relay.py --backend nano --dev auto rpiboot   # waits for 0a5c:2712 on USB
```

Unattended round (reuse the running console capture with `--log`; the tool refuses the console and the
LTE modem as relay ports):

```bash
tools/diagnostics/cm5-metal-loop.sh --image os/build/generated/cm5-heqk/<image>.img \
    --log ~/heqk-metal-logs/20261107-ap-serial.log
```

Default markers are the AP image's boot contract (secure boot, A/B commit, Wi-Fi firmware, AP up, MC
owner state); override with `--expect REGEX` / `--fail REGEX` for other images.
