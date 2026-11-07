#!/usr/bin/env bash
# waits for vmlinux, proves .BTF, then waits for the deb
SRC=$(ls -d /home/andrei/hookprobe-os/builder/kernel-build/linux-a923* 2>/dev/null | head -1)
OUT=/home/andrei/hookprobe-os/builder/kernel-build/out
for i in $(seq 1 240); do   # up to ~120 min
  if [ -f "$SRC/vmlinux" ]; then
    echo "=== vmlinux linked at $(date) ==="
    if readelf -S "$SRC/vmlinux" | grep -q '\.BTF'; then
      echo "PROVEN .BTF section:"; readelf -S "$SRC/vmlinux" | grep '\.BTF'
    else
      echo "NO .BTF yet (may be mid-link)"
    fi
    break
  fi
  sleep 30
done
# then wait for artifacts
for i in $(seq 1 120); do
  [ -f "$OUT/SHA256SUMS" ] && { echo "=== SHA256SUMS ==="; cat "$OUT/SHA256SUMS"; break; }
  sleep 30
done
