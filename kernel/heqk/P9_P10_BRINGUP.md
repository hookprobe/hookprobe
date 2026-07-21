# P9 (RTL8111H eth1) + P10 (CYW43455 WiFi) — advance bring-up plan

Prepared from two deep investigations (2026-07-22) so the metal flashes are
maximally productive (connector-wear-minimizing): each stage has ONE console
proof-point, and everything codeable **off-metal** is separated from what needs
the board. Primary oracles: the local RPi kernel tree
(`~/hookprobe-os/builder/kernel-build/linux-a923c1dcd822385aaa82a4388c6a6ad92cbf9280/`),
`~/heqk/arch-aarch64/src/gem.rs` (the proven RC2 + NC-alias + polled-OWN patterns),
and the Pico-W `cyw43-driver` (bare-metal same-family WiFi).

---

## P9 — RTL8111H second Ethernet (`eth1`) via BCM2712 external PCIe RC1

**Verdict: with Track A, the RTL is EASIER than the GEM was.** RC1 (`pcie1`) is
register-identical to RC2 (`pcie2`, the RP1's controller `gem.rs` already drives);
the inbound DMA window is byte-for-byte `gem.rs::pcie_inbound_window` with only
the base changed; the DMA offset (`+0x10_0000_0000`), the GB257 NC descriptor
alias, and the polled-OWN model all carry over. The only genuinely NEW work is
PCIe **link training** + **enumeration/BAR assignment** — and Track A hands the
link training to firmware.

### Address map (from `bcm2712.dtsi` + CM5 aliases)
| Item | Value |
|---|---|
| RC1 controller base (CPU-phys) | **`0x10_0011_0000`** (GB64, already Device-mapped) |
| Config index / data (indirect) | base+`0x9000` / base+`0x8000` |
| Outbound MMIO window (RTL BAR2) | CPU **`0x1b_00000000`** → PCIe bus `0x0` |
| Inbound DMA window | PCIe bus `phys + 0x10_0000_0000` (SAME as GEM) |
| RTL device | `0001:01:00.0`, vendor/device **`0x816810EC`**, `RTL_GIGA_MAC_VER_46` |
| Interrupts | **polled** (IMR=0); skip MSI-X/MIP + legacy INTx for bring-up |

### Track A (RECOMMENDED) — firmware trains the link
Add to `config.txt`: **`dtparam=pciex1`** (optionally `dtparam=pciex1_gen=2`).
The Pi bootloader then does RESCAL + SERDES + PERST + link training (exactly as
for NVMe boot), the same division of labor that made RC2/GEM work. This retires
the two highest bare-metal risks (RESCAL PHY calibration, 54 MHz refclk MDIO).
HEQK then does only: inbound window + enumeration + MAC init.

**Stage 0 proof-point:** read `PCIE_STATUS` (base+`0x4068`); `& 0x30 == 0x30`
(DL_ACTIVE|PHYLINKUP) ⇒ firmware already trained it → skip Track B entirely.

### Track B (fallback) — full brcmstb link-up
Only if Track A won't train it. Sequence (offsets from base, `pcie-brcmstb.c`):
```
1. RESCAL PHY calibration            (separate reset block — the RISK)
2. RGR1_SW_INIT_1(0x9210) bit1=1; 100us; =0        # bridge sw_init
3. HARD_DEBUG(0x4304) &= ~(1<<27);   100us          # clear SERDES_IDDQ (power serdes)
4. MISC_CTRL(0x4008) = SCB_ACCESS_EN|CFG_READ_UR_MODE|MAX_BURST|RCB_MPS|RCB_64B
5. inbound windows (see §inbound — identical to gem.rs)
6. confirm RC: PCIE_STATUS(0x4068) & 0x80 (PCIE_PORT)
7. outbound window 0 (see below)
8. post_setup_bcm2712: 54 MHz refclk MDIO + PM_CLK_PERIOD(0x184c)=0x12 + err-suppress   (RISK)
9. HARD_DEBUG(0x4304): clear CLKREQ mask bits
10. PERST# deassert: MISC_PCIE_CTRL(0x4064) bit2=1   # INTERNAL — no GPIO
11. msleep(100)                                      # PCIe CEM
12. poll (R32(0x4068) & 0x30)==0x30 up to 100ms      # link up
```
Outbound window 0 (CPU `0x1b_00000000` → PCIe `0x0`, 4 GiB):
`0x400c=0; 0x4010=0; 0x4070=0xfff00000; 0x4080=0x1b; 0x4084=0x1b`
(double-check the BASE_LIMIT MB field packing vs `brcm_pcie_set_outbound_win`.)

### Inbound DMA window (§inbound) — reuse `gem.rs::pcie_inbound_window`, base only changes
```
base = 0x10_0011_0000                       # (GEM uses 0x10_0012_0000)
W32(base+0x4008, R32|0x1000)                # SCB_ACCESS_EN
W32(base+0x4030, 0x00000010)                # RC_BAR1 HI = upper32(0x10_00000000)
W32(base+0x402c, 0x00000015)                # RC_BAR1 LO = size code 0x15 (64 GiB)
W32(base+0x40b0, 0x00000000)                # UBUS_BAR1 remap HI
W32(base+0x40ac, 0x00000001)                # UBUS_BAR1 remap LO | ACCESS_EN
W32(base+0x40a4, R32|(1<<13)|(1<<19))       # UBUS_CTRL err-suppress
W32(base+0x4170, 0xffffffff)                # AXI_READ_ERROR_DATA
```

### Enumerate + configure the RTL (after link up)
```
1. RC config reg 0x18 = 0x00010100          # primary=0 secondary=1 subordinate=1
2. idx = (1<<20); W32(base+0x9000, idx); R32(base+0x8000 + 0x00) == 0x816810EC   # RTL found
3. BAR2 (cfg 0x18): size it (W 0xFFFFFFFF, read back, ~0xF); assign 0x0 (window base); cfg 0x1c=0
4. Command (cfg 0x04) |= 0x0006             # Memory-Space-Enable | Bus-Master-Enable
   ⇒ RTL MMIO reachable at CPU 0x1b_00000000
```

### RTL8111H MAC init (polled) — the easy part (into BAR2 @ 0x1b_00000000)
Registers (offset:width): MAC0=`0x00`:32 MAC4=`0x04`; TNPDS=`0x20`/`0x24`;
CR=`0x37`:8 (Reset=0x10 RxEnb=0x08 TxEnb=0x04 StopReq=0x80); TxPoll=`0x38`:8 (NPQ=0x40);
IMR=`0x3C`:16; ISR=`0x3E`:16 W1C; TxConfig=`0x40`:32; RxConfig=`0x44`:32;
Cfg9346=`0x50`:8 (Unlock=0xC0 Lock=0x00); PHYstatus=`0x6C`:8 (LinkStatus=0x02);
RMS=`0xDA`:16; CPlusCmd=`0xE0`:16; IntrMitigate=`0xE2`:16; RDSAR=`0xE4`/`0xE8`.
Descriptor (16 B, 256-aligned ring, 256 desc) `{opts1,opts2,addr_lo,addr_hi}`:
`OWN=1<<31` (NIC owns; SW polls for 0, **same polarity RX+TX**), `EOR=1<<30`,
`FS=1<<29`, `LS=1<<28`, `len=opts1&0x3FFF`, `RxRES=1<<21`.
```
reset:  W8(0x37,0x80); udelay(100); W8(0x37,0x10); poll (R8(0x37)&0x10)==0
mac:    read 6 bytes at 0x00..0x05                 # eFuse-loaded on 8111H
start:  W8(0x50,0xC0)                               # unlock
        W16(0xE0,0); W16(0xE2,0)
        W16(0xDA,0x4000)                            # RxMaxSize
        W32(0x24,tx_hi); W32(0x20,tx_lo)            # TX base — HIGH then LOW (source quirk)
        W32(0xE8,rx_hi); W32(0xE4,rx_lo)            # RX base — HIGH then LOW
        W8(0x50,0x00); R8(0x37)                     # lock + commit posted writes
        W8(0x37,0x0C)                               # RxEnb|TxEnb
        W32(0x40,0x03000780)                        # TxConfig
        W32(0x44,0x0000CF00)                        # RxConfig base
        W32(0x08,0xFFFFFFFF); W32(0x0C,0xFFFFFFFF)  # MAR0 all-mcast
        W32(0x44,(R32(0x44)&~0xF)|0x0E)             # Bcast|MyPhys|Mcast (|0x01 = promisc)
        W16(0x3C,0)                                 # IMR=0 (polled)
        poll R8(0x6C)&0x02                          # LinkStatus (PHY self-negotiates, NO fw blob)
rx:  if (rx[i].opts1 & OWN)==0 { len=(opts1&0x3FFF)-4; if opts1&RxRES drop; else deliver;
                                 rx[i].opts1 = OWN|(i==255?EOR:0)|0x3FFF }   # re-arm, no doorbell
tx:  tx[e].opts1 = OWN|FS|LS|(e==255?EOR:0)|len; dsb; W8(0x38,0x40); poll (tx[e].opts1&OWN)==0
```
Buffers cacheable + `dc ivac` before read; **descriptor ring via the GB257 NC alias**
exactly like the GEM. Bus addrs (RDSAR/TNPDS + every `addr`) = CPU-phys + `0x10_0000_0000`.
PHY firmware `rtl8168h-2.fw` + ephy/OCP tuning are OPTIONAL (basic autoneg works without).

### P9 staged plan (one proof-point per flash)
| Stage | Action | Proof-point |
|---|---|---|
| 0 | `config.txt: dtparam=pciex1`; read RC1 `0x4068` | `& 0x30 == 0x30` → firmware trained it |
| 1 | (Track B only) full link-up §Track B | `link up: DL_ACTIVE\|PHYLINKUP` |
| 2 | config-space read `01:00.0` | `RTL vendor/device = 0x816810EC` |
| 3 | inbound window + BAR2 + BusMaster/MemEn + read MAC | `MAC=xx:.. BAR2@0x1b00000000` |
| 4 | RX ring (NC alias, +0x10_00000000), start MAC, poll | `RX len=NN → Packet Engine verdict` |
| 5 | TX one frame via NPQ doorbell | `TX OWN cleared` |

### P9 risk ranking (highest first)
1. RESCAL + 54 MHz refclk MDIO — **Track B only; mitigated by Track A**.
2. Outbound BASE_LIMIT field packing (`0x4070/0x4080/0x4084`) — the one novel encoding.
3. Bus-number Type1→Type0 (RC reg 0x18 secondary=1) — else `01:00.0` reads all-Fs.
4. Inbound window — LOW (proven identical to RC2).
5. PERST# — RETIRED (internal `0x4064` bit2).
6. RTL MAC init — LOW (self-negotiating PHY, no blob, simpler than the GEM).

### P9 off-metal vs on-metal
- **Prepared off-metal (this repo):** `arch-aarch64/src/rtl8111.rs` — register/descriptor
  constants, config-space index/data helpers, inbound-window (reused), and the MAC-init
  sequence, all `cfg(cm5)`, mirroring `gem.rs`. Compiles; wired + flashed at Stage 2+.
- **Needs the board:** link-up confirmation, the real vendor-ID read, BAR/MAC values,
  RX/TX first light — but each is a single console proof-point above.

---

## P10 — CYW43455 WiFi (SDIO) + real regulatory domain (the backlog item)

**The WiFi SDIO controller is a BCM2712 SDHCI (NOT the RP1):** host regs at CPU-phys
**`0x10_0110_0000`** (0x260), cfg block `0x10_0110_0400` (0x200), **GIC SPI 274**.
A standard SD Host Controller (`brcm,bcm2712-sdhci`), sibling to the mailbox. WL_ON is
a fixed-regulator GPIO (`wl_on_reg`) — assert before CMD5. `clk_emmc2` rate via the
mailbox `SET/GET_CLOCK_RATE` you already drive.

### Staged plan (proof-point each; regdomain is Stage C — no scan/data needed)
| Stage | Goal | Proof-point | Effort | Hardest unknown |
|---|---|---|---|---|
| **A** SDIO up | SDHCI init @`0x10_0110_0000`, CMD5, 4-bit/DDR50, F1 enable, backplane window | CMD53-read chip-ID at SI_ENUM_BASE = **`0x4345`** | Med | DDR50 timing + `cfg` quirk block; WL_ON order; CMD53 block mode |
| **B** FW+NVRAM upload | write `.bin`@`0x198000`, NVRAM@RAM-top, reset-vector@0, ARMCR4 out of reset | **F2 ready** (IORx bit2) = firmware alive | **Highest** | CHIPCLKCSR ALP/HT + KSO; ARMCR4 halt-clear order; verifymemory round-trip |
| **C** Country ★ | BCDC on F2; `clmload` the CM5 `.clm_blob`; set + read `country` iovar | `country` read-back = real ISO (`"GB"`,rev N), **not 00/99**; `clmver` non-empty | Med | `(ccode,rev)` present in CLM; SDPCM seq correctness |
| **D** scan+assoc | escan, `WLC_SET_SSID`, WPA2 iovars, event demux | join AP, `E_SET_SSID` success, L2 link up | High | escan parse; event channel; EAPOL 4-way |
| **E** data | BDC framing, SDPCM credits | DHCP/ping through the HEQK BPF path | High | credit flow-control; glom; RX headroom |

### The regdomain fix (Stage C — the concrete backlog target)
Why it's `00`/`99` today: firmware boots with only a built-in world locale; skipping
`clmload` or the `country` iovar leaves it there. The three-step invariant:
1. **`clmload`** the CM5 `.clm_blob` (chunked in `struct brcmf_dload_data_le { flag; dload_type=DL_TYPE_CLM(2); len; crc; data[] }`, `DL_BEGIN(1)` on first, `DL_END(2)` on last), via the `clmload` iovar. Confirm with `clmver` iovar.
2. Set the **`country` iovar** with `struct brcmf_fil_country_le { char country_abbrev[4]="GB"; __le32 rev; char ccode[4]="GB"; }` — rev from the CLM/NVRAM `ccode=` line.
3. **Read back** the `country` iovar → `country_abbrev` must be uppercase ISO, not `00`/`XX`/`99`, and `clmver` non-empty.

### Control protocol (BCDC/CDC over SDIO F2) — codeable off-metal now
```
struct brcmf_proto_bcdc_dcmd { __le32 cmd; __le32 len; __le32 flags; __le32 status; }  // 16 B
flags: SET=0x02, ERROR=0x01, IF=<<12, ID=<<16   // ++reqid pairs request/reply
iovar = "<name>\0<binary payload>" sent as the dcmd payload via WLC_SET_VAR/WLC_GET_VAR
```
Key SDIO constants: F1 enable=0x02 / F2 enable=0x04 (CCCR IOEx 0x02, poll IORx 0x03);
backplane window regs SBADDRLOW/MID/HIGH=`0x1000A/B/C`, CHIPCLKCSR=`0x1000E`,
32-bit access flag `0x08000`; firmware RAM base (43455 ARMCR4 TCM) **`0x198000`**;
chip-ID low16 **`0x4345`**.

### Firmware artifacts (already on disk — CM5 board-mangled names)
`brcmfmac43455-sdio.raspberrypi,5-compute-module.{bin,clm_blob,txt}` →
`cypress/cyfmac43455-sdio.{bin,clm_blob}` + generic NVRAM. Host forwards the CLM blob
verbatim (opaque — firmware parses it), so NO blob-format reverse-engineering.

### P10 honest scope
~3–5× the RTL8111H: an SDHCI stack + windowed backplane + firmware/NVRAM/CLM upload
with read-back verify + ARMCR4 core-reset dance + a command/event/data multiplexer,
before a single packet. But the regdomain sub-goal ends at Stage C and needs neither
scan (D) nor data (E). Best bare-metal oracle: Pico-W `cyw43-driver` (`cyw43_ll.c`
SDIO/backplane/fw-download, `cyw43_country.h`). Infineon WHD is conceptual only (does
not target the 43455).

### P10 off-metal vs on-metal
- **Prepared off-metal:** the entire control layer — BCDC header + iovar string builder,
  the `clmload` chunker, `brcmf_fil_country_le`, the NVRAM `.txt`→packed-blob parser,
  SDPCM/BDC struct layouts, chip-ID/rambase constants. Host/QEMU unit-testable against
  recorded byte streams; the country/regdomain sequence can be written + tested now.
- **Needs the board:** SDHCI DDR50 bring-up, CMD5/function-enable timing, CHIPCLKCSR
  clock handshakes, ARMCR4 reset, verifymemory round-trip, F2-ready boot handshake.

---

## Recommended flash sequence (both phases, connector-wear-minimizing)
1. **P9 Stage 0+2 in one flash** (`dtparam=pciex1` + RC1-status read + config-space vendor-ID) — proves the link + finds the RTL in a single boot.
2. **P9 Stage 3+4 in one flash** (inbound window + BAR/MAC + RX first light).
3. **P9 Stage 5** (TX) — likely folds into the same flash as Stage 3+4 if RX works.
4. **P10 Stage A** (SDIO + chip-ID `0x4345`) — the transport gate.
5. **P10 Stage B** (firmware upload + F2-ready) — the hardest; budget iteration.
6. **P10 Stage C** (regdomain) — the backlog target; rides the control channel only.

P9 is ~2–3 flashes to a working 2nd NIC (Track A). P10 is a multi-flash effort
concentrated on Stage B; everything above Stage B is codeable/testable off-metal first.
