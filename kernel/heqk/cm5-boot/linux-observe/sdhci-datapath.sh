#!/usr/bin/env bash
# Run ON the CM5's Linux (via ssh) with wlan0 up. Answers "PIO or DMA?" for the
# CYW43455 SDIO2 controller (BCM2712 SDHCI @0x10_0110_0000) + the SDIO func-1 block
# size — the two things HEQK's bare-metal CMD53 data phase is likely missing.
# Needs iomem=relaxed + lockdown off (the observe cmdline).  sudo ./sdhci-datapath.sh
set -u
echo "===== SDHCI DATA-PATH ORACLE (sdio2 / CYW43455) ====="
echo "--- mmc/sdhci init mode (ADMA? PIO? SDMA?) from dmesg ---"
dmesg 2>/dev/null | grep -iE "mmc[0-9].*SDHCI|ADMA|SDMA|PIO|brcmfmac.*(block|blksz|f1|f2)" | head -20

echo "--- which mmc host is the WiFi (mmc1100000 / sdio2)? ---"
for h in /sys/class/mmc_host/mmc*; do
  dev=$(cat "$h/device/uevent" 2>/dev/null | grep -m1 OF_FULLNAME)
  echo "$(basename "$h"): $dev"
done

echo "--- SDHCI regs that reveal DMA vs PIO ---"
python3 - <<'PY'
import mmap,os,struct
base=0x10_0110_0000
try:
    fd=os.open("/dev/mem",os.O_RDONLY|os.O_SYNC)
    m=mmap.mmap(fd,0x1000,mmap.MAP_SHARED,mmap.PROT_READ,offset=base)
    def r32(o): return struct.unpack('<I',m[o:o+4])[0]
    hc=r32(0x28); caps=r32(0x40); adma_lo=r32(0x58); adma_hi=r32(0x5c); tm=r32(0x0c)
    print(f"  HOST_CTRL1(0x28)={hc:#010x}  DMA_select[4:3]={(hc>>3)&3} (0=SDMA 2=ADMA2-32 3=ADMA2-64) buswidth4={(hc>>1)&1} hs={(hc>>2)&1}")
    print(f"  TRANSFER_MODE(0x0c lo)={tm&0xffff:#06x}  DMA_EN(b0)={tm&1}")
    print(f"  CAPS(0x40)={caps:#010x}  ADMA2(b19)={(caps>>19)&1} SDMA(b22)={(caps>>22)&1} HS(b21)={(caps>>21)&1}")
    print(f"  ADMA_ADDR(0x58/0x5c)={adma_hi:#010x}{adma_lo:08x}  (non-zero => controller uses ADMA/DMA, not PIO)")
    m.close(); os.close(fd)
except Exception as e:
    print(f"  /dev/mem read FAILED: {e} (need iomem=relaxed + lockdown off)")
PY

echo "--- SDIO function block sizes (brcmfmac sdio_set_block_size) ---"
for f in /sys/bus/sdio/devices/*/; do
  [ -e "$f" ] || continue
  echo "  $(basename "$f"): class=$(cat "$f/class" 2>/dev/null) vendor=$(cat "$f/vendor" 2>/dev/null) device=$(cat "$f/device" 2>/dev/null)"
done
echo "  (CCCR/FBR block sizes are in the func regs 0x110/0x210 — brcmfmac sets f1=64, f2=512 typically)"
dmesg 2>/dev/null | grep -iE "set_block_size|blksize|block size" | head

echo "--- mmc ios (bus width / clock / timing the driver actually uses) ---"
cat /sys/kernel/debug/mmc*/ios 2>/dev/null | head -40 || echo "  (no mmc debugfs)"
echo "===== END ====="
