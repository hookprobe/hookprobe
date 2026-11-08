# tools/diagnostics

| Tool | What |
|---|---|
| [`cm5-metal-loop.sh`](cm5-metal-loop.sh) | One unattended round: relay rpiboot → flash + verify → relay boot → wait for serial markers → PASS/FAIL report |
| [`cm5-relay-nano/`](cm5-relay-nano/) | Arduino Nano v3 firmware for the two bench relays (safe defaults, read-back, auto-release) |
| [`cm5-relay.py`](cm5-relay.py) | Power-cycles the CM5 bench board and asserts nRPIBOOT through a 2-channel USB relay, so it can be reflashed without anyone touching it |
| [`os/kernel/tools/mc-e2e-metal.sh`](../../os/kernel/tools/mc-e2e-metal.sh) | Metal acceptance run against a live CM5 |
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
