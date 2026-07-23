#!/usr/bin/env bash
# Run ON the CM5's Linux (via ssh) with WiFi up. Dumps (a) the working SDHCI +
# cfg-block register state so HEQK's bare-metal P10 SDIO can mirror it, and (b) the
# regulatory-domain state — then optionally FIXES the regdomain to $1 (a 2-letter
# ISO country). Needs iomem=relaxed on the kernel cmdline for the /dev/mem reads.
#   sudo ./wifi-observe.sh [COUNTRY]
set -u
CC="${1:-}"
PW=DEV-CRED-SCRUBBED

echo "===== WIFI OBSERVE ====="
echo "--- brcmfmac / sdio / regulatory dmesg ---"
echo "$PW" | sudo -S dmesg 2>/dev/null | grep -iE 'brcmfmac|mmc[0-9]|sdhci|regulatory|country|clm|43455' | tail -30

echo "--- interfaces + wlan0 info ---"
ip -br link | grep -iE 'wlan|lo|end0'
echo "$PW" | sudo -S iw dev wlan0 info 2>/dev/null
echo "--- current regdomain (BEFORE) ---"
echo "$PW" | sudo -S iw reg get 2>/dev/null

echo "--- SDHCI (sdio2 WLAN) regs @0x10_0110_0000 (0x00..0x40) ---"
python3 - <<'PY'
import mmap,os,struct
for base,label,rng in [(0x10_0110_0000,"SDHCI",range(0,0x44,4)),
                        (0x10_0110_0400,"CFG",  [0x00,0x44,0x4c,0x1ac])]:
    try:
        fd=os.open("/dev/mem",os.O_RDONLY|os.O_SYNC)
        m=mmap.mmap(fd,0x1000,mmap.MAP_SHARED,mmap.PROT_READ,offset=base)
        print(f"  [{label} @ {hex(base)}]")
        for o in rng:
            print(f"    0x{o:04x}: 0x{struct.unpack('<I',m[o:o+4])[0]:08x}")
        m.close(); os.close(fd)
    except Exception as e:
        print(f"  {label} read FAILED: {e} (need iomem=relaxed)")
PY

if [ -n "$CC" ]; then
  echo "--- FIX regdomain -> $CC ---"
  echo "$PW" | sudo -S iw reg set "$CC" 2>&1
  sleep 2
  echo "--- regdomain (AFTER) ---"
  echo "$PW" | sudo -S iw reg get 2>/dev/null
  echo "--- brcmfmac country after set ---"
  echo "$PW" | sudo -S dmesg 2>/dev/null | grep -iE 'country|regulatory' | tail -5
fi
echo "===== END WIFI OBSERVE ====="
