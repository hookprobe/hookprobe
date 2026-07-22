# P9 (RTL8111H / RC1) + WiFi investigation notes

_Live investigation. Ground truth = the working hookprobe-os image's dmesg._

## ★ RESOLVED (2026-07-22): root cause = CM5 not fully seated in the Waveshare carrier

The external PCIe (RC1) runs over the CM5↔carrier board-to-board connector. The CM5
wasn't housed deeply enough → the carrier-side PCIe never mated → `1000110000.pcie:
link down` under BOTH Linux and HEQK, while everything inside the CM5/RP1 (GEM
`end0`, WiFi `wlan0`) worked fine. **After reseating the CM5, the RTL trains:**
```
brcm-pcie 1000110000.pcie: clkreq-mode set to default
brcm-pcie 1000110000.pcie: link up, 2.5 GT/s PCIe x1
pci 0001:01:00.0: [10ec:8168]   ← RTL8111H enumerated; enP1p1s0 netdev present
```
Implications: **HEQK's `rc1_train()` was correct all along** — the only failure was
physical. With the link now good, HEQK should train + enumerate the RTL too.
Linux trains it at **Gen1 x1 (2.5 GT/s)** with **clkreq-mode "default"** (sets
L1SS, clears CLKREQ_DEBUG) — NOT "safe"/REFCLK_OVRD. Match that in HEQK.

Reference-capture TODO (optional): to read the trained RC1 controller regs
(0x4304 etc.) need `iomem=relaxed` on cmdline (STRICT_DEVMEM blocks it otherwise).

## P9 — external PCIe RC1 (RTL8111H, eth1/enP1p1s0)

### Confirmed facts
- HEQK `rtl8111::rc1_train()` runs every stage correctly (RESCAL done, SERDES up,
  8/8 refclk MDIO writes land, PERST 0x0->0x4) but `PCIE_STATUS 0x4068` stuck at
  `0x0001e08f` (DL_ACTIVE|PHYLINKUP both 0 = link down).
- Register offsets verified against real `pcie-brcmstb.c`: HARD_DEBUG=0x4304 (2712),
  STATUS=0x4068, PERST=0x4064 bit2, CLKREQ_DEBUG=0x2, L1SS=0x200000, SERDES_IDDQ=bit27.
- CM5 datasheet: `PCIe_CLK_nREQ` internally pulled UP (clock not requested) → CM5
  holds its own refclk OUTPUT off by default unless CLKREQ# asserted or REFCLK_OVRD set.
- My MDIO PLL-lock read is UNRELIABLE on 2712 (`CFG_QUIRK_NO_SSC`, MDIO map differs) —
  the authoritative status is memory-mapped 0x4068, not the MDIO SSC bit.

### Key uncertainty being resolved NOW
- Under Linux (both the pciex1-compat-pi5-overlay config AND the minimal
  hookprobe-os config) RC1 also showed `brcm-pcie 1000110000.pcie: link down`,
  bus 01 released, NO r8169. So on the CURRENT board state, Linux ALSO can't
  train RC1 → points at physical (seating/connector/power) OR a kernel-init step.
- The clean v8 CM5 config = `kernel_2712.img` + stock `bcm2712-rpi-cm5-cm5io.dtb`,
  NO `dtparam=pciex1`, NO `pciex1-compat-pi5` overlay. (Adding those broke my
  earlier observe boot — they're Pi5-Model-B fixups, wrong for the CM5-IO dtb.)
- **TEST IN PROGRESS:** flash the clean, validated v8 image and read dmesg. If it
  shows `1000110000.pcie: link up` + `r8169` → capture its trained RC1 registers
  and mirror in HEQK. If it shows `link down` too → current failure is physical.

### RESULT (clean v8 image, 2026-07-22) — DEFINITIVE
- Flashed the pristine validated **hookprobe-os-pi-debug-v8.img** (same kernel
  `6.12.94-v8-16k-hookprobe-edge` that the user validated). dmesg:
  `brcm-pcie 1000110000.pcie: link down` + `pci_bus 0001:01: [bus 01] is released`,
  NO `r8169`. So even the clean validated image CANNOT train RC1 on THIS board.
- **Therefore P9 is PHYSICAL on this unit** — not HEQK, not my config hacks, not the
  overlay. HEQK runs the correct sequence; there's just no PCIe link to train.
- **Crucial reframe:** the "2 interfaces up, validated" = **`end0` (wired GEM) +
  `wlan0` (WiFi)**, BOTH up on v8. The RTL8111H (`enP1p1s0`) is a THIRD/optional
  interface, and it is the one that's down. It is NOT part of the validated pair.
- OPEN Q for user: was the RTL (`eth1`/`enP1p1s0`) EVER up on THIS specific board,
  or only on another unit? If never here → this board's RTL/PCIe path is faulty
  (reseat/RMA). HEQK's rc1_train can't beat a dead physical link.

## WiFi (CYW43455 / brcmfmac, wlan0)

### Observed (earlier hookprobe-edge boot dmesg)
- `brcmfmac: brcmf_set_channel: set chanspec 0xd02e fail, reason -52` — channel set
  rejected. 0xd02e decodes to a specific band/channel the current regdomain forbids.
- `hostapd.service ... skipped (ConditionFileNotEmpty=/etc/hostapd/hostapd.conf)` —
  AP config empty at that boot (may be generated later / per-deployment).
- `hookprobe-wifi-optimize-reapply@wlan0` + `hookprobe 5GHz channel-optimizer
  DFS-LKG` services present — there IS a channel/DFS management layer.

### Hypothesis (matches [[heqk-wifi-regdomain-backlog]])
- The regdomain is likely world/00 or 99, which forbids the 5 GHz DFS channel the
  optimizer wants (chanspec 0xd02e) → reason -52. Fix = register a REAL country/
  regdomain (crda/cfg80211 `iw reg set <CC>`, or brcmfmac nvram `ccode`), and gate
  DFS channels on it.

### RESULT (clean v8 image dmesg, 2026-07-22) — root cause found
- `brcmfmac43455-sdio` (CYW43455) loads, FW ver 7.45.234 — WiFi works, `wlan0 Link UP`.
- **MISSING board NVRAM:** `Direct firmware load for
  brcm/brcmfmac43455-sdio.raspberrypi,5-compute-module.bin failed with error -2`
  (ENOENT). The CM5-specific NVRAM (which carries `ccode`/regrev + RF calibration)
  is absent → driver falls back to generic, no country from NVRAM.
- **regdomain = 00 (world):** `hookprobe-regdomain.service` →
  `regulatory country = 00 (source: world)`. So no real CC detected/set.
- **Effect:** `wifi-optimize[wlan0]: cc=00 allow_dfs=false allow_meteo=false` →
  DFS/upper-5GHz channels blocked → earlier `set chanspec 0xd02e fail, reason -52`.

### FIX PLAN (WiFi)
1. **Set a real regulatory country.** `hookprobe-regdomain.service` currently
   yields 00/world — give it a real CC source (deployment config / geo-IP / a
   provisioned `ccode`). Then `iw reg set <CC>` + hostapd `country_code=<CC>` +
   `ieee80211d=1`. This alone unblocks non-DFS channels for that country.
2. **Provide the CM5 brcmfmac NVRAM** so the -2 load stops and the radio gets its
   board `ccode`/regrev + calibration: install
   `brcm/brcmfmac43455-sdio.raspberrypi,5-compute-module.txt` (the RPi CM5 nvram;
   the CM4/Pi-Zero-2 43455 nvram is a close base) — sets `ccode`/`regrev` in-driver.
3. Gate DFS (`allow_dfs`) on the real CC once set; keep `allow_meteo=false` unless
   licensed. Confirm with `iw reg get` + `iw list` (channel flags) post-fix.
- Both layers matter: NVRAM ccode sets the radio's hard regulatory floor; the
  userspace `iw reg set` sets the OS regdb. They must agree (intersection wins).
