# Linux-as-oracle: observe RC1 (external PCIe) bring-up

A reusable harness to read the **ground truth** of how Linux brings up hardware
HEQK is stuck on — the same technique that cracked the RP1 GEM (the `w1=0` /
DBW128 fix came from watching the working `macb` driver, not from docs). Here it
targets the **BCM2712 external PCIe RC1** + the Waveshare CM5-DUAL-ETH-MINI's
**RTL8111H** (`eth1`): HEQK's bare-metal `rtl8111::rc1_train()` executes every
`pcie-brcmstb` stage correctly (RESCAL done, SERDES up, all 8 refclk-MDIO writes
land, PERST released) yet the link never trains (`PCIE_STATUS` stuck at
`0x0001e08f`). Rather than keep guessing register bits, boot Linux (whose
`pcie-brcmstb` DOES train RC1 on this board) and dump the trained state.

## What it does
1. `config-linux.txt` boots the hookprobe-edge kernel (`kernel_2712.img`) with
   `dtparam=pciex1` so `pcie-brcmstb` claims + trains RC1.
2. `iomem=relaxed` (added to `cmdline.txt`) lets a userspace `/dev/mem` read reach
   the RC1 controller MMIO.
3. `rc1-observe.service` runs `rc1-dump.py` after boot, which captures — to
   `/rc1dump.txt` on the rootfs **and** to the serial/FTDI console:
   - `dmesg` pcie/brcm/rescal/r8169 lines (link speed/width, quirks),
   - `lspci` (confirms the RTL8111H `10ec:8168` at `01:00.0`),
   - the RC1 register block `@0x10_0011_0000` (the values HEQK must mirror), with
     `STATUS` decoded (PORT / DL_ACTIVE / PHYLINKUP).

## Use
CM5 in rpiboot, eMMC exposed as `/dev/sdX` (`rpiboot -d mass-storage-gadget64`):
```
sudo ./install.sh /dev/sdX     # Linux boot + dumper installed; HEQK cfg saved
# power-cycle CM5 to eMMC; watch FTDI @115200 for pcie-brcmstb link-up + the
# "===== HEQK RC1 OBSERVE =====" block. Then back in rpiboot:
sudo ./readback.sh /dev/sdX    # prints /rc1dump.txt + restores the HEQK config
```
Then diff the dumped trained-state registers against `rtl8111::rc1_train()` and
mirror any differences (clock/power enables, the real bridge-reset block, the
refclk/CLKREQ config, PERST timing). Restore HEQK with a normal `flash-now.sh`.

## Files
- `config-linux.txt` — CM5 boot config for the edge kernel.
- `rc1-dump.py` — the register/dmesg/lspci dumper (edit `OFFS`/`BASE` to retarget).
- `rc1-observe.service` — systemd oneshot that runs the dumper post-boot.
- `install.sh` / `readback.sh` — install onto / read back from the eMMC.
