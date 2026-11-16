#!/usr/bin/env bash
# ADR 0065 step 4g S3d: the shipping AP+MC WPA3 kernel must contain no in-kernel Wi-Fi keying code.
# usage: tools/el0keys-symcheck.sh <kernel ELF>   (exit 0 = clean; prints every forbidden symbol found)
set -u
ELF="${1:?kernel ELF}"
NM=$(ls ~/.rustup/toolchains/*/lib/rustlib/*/bin/llvm-nm 2>/dev/null | head -1)
NM=${NM:-nm}
# the in-kernel authenticator, SAE responder, PT / PMK derivation and the kernel's PTK maths
FORBID='arch_aarch64::cyw43::KEYER$|Keyer>::on_eapol|Keyer>::start|wanparse::sae_respond|sae::derive_pt|hal::wpa::wpa_pmk|hal::wpa::wpa_ptk|cyw43::ap_sae_pmk|cyw43::DriverCrypto'
hits=$("$NM" -C "$ELF" | grep -E " [tTdDbBrR] " | grep -E "$FORBID")
if [ -n "$hits" ]; then
  echo "EL0-KEYS SYMCHECK: FAIL — in-kernel keying code present:"; echo "$hits" | sed 's/^/  /'; exit 1
fi
echo "EL0-KEYS SYMCHECK: PASS — no in-kernel authenticator / SAE responder / PT-PMK-PTK derivation in $(basename "$ELF")"
