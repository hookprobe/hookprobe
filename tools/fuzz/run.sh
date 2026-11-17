#!/usr/bin/env bash
# tools/fuzz/run.sh [seconds-per-target] — coverage-guided libFuzzer runs over the host-buildable heqk
# parsers (the `hal` crate: POLICY.TXT, WAN.TXT, frame facts / VLAN tags, SDIO glom, the A/B OTA slot derivation) and `boot-abi` (the signed-image verifier). The kernel-crate parsers
# network-facing parsers run from the SAME source files via tools/fuzz/heqk-kernel (HTTP request + form bodies, DNS
# wire, TLS ClientHello / JA4, frame classifier), and tools/fuzz/heqk-securechannel the control channel's record layer
# (W4 rekey); fixed-layout MAC-verified stores stay with the in-kernel [P-fuzz].
# Needs: nightly + `cargo install cargo-fuzz`. Exit 1 on any crash (the reproducer stays in artifacts/).
set -u
T="${1:-60}"; FUZZ="$(cd "$(dirname "$0")" && pwd)"
rc=0

# fuzz_one <crate dir> <target> <max_len>: run one target; on failure say whether it CRASHED or did not BUILD /
# start, and print the lines that show why. (The kernel / boot-abi / securechannel targets used to print only
# "crash or build error — see /tmp/...", a file CI never shows: #1264 was a build break triaged as "unknown".)
fuzz_one() {
  local dir=$1 t=$2 ml=$3 log="/tmp/heqk-fuzz-$2.log"
  mkdir -p "$FUZZ/$dir/corpus/$t"
  if (cd "$FUZZ/$dir" && cargo +nightly fuzz run --fuzz-dir . "$t" "corpus/$t" -- -max_total_time="$T" -max_len="$ml") > "$log" 2>&1; then
    echo "  ok   $t: $(grep -oE 'Done [0-9]+ runs' "$log" | tail -1)"
  elif grep -qE "panicked at|SUMMARY: libFuzzer|deadly signal" "$log"; then
    echo "  FAIL $t (crash — reproducer in tools/fuzz/$dir/artifacts/$t/)"; grep -E "panicked at|SUMMARY" "$log" | head -3; rc=1
  else
    # Not a crash: the harness did not build or libFuzzer did not start. Say so instead of crying "crash".
    echo "  FAIL $t (build/setup error, not a crash)"; grep -E "^error|^ *--> |could not|No such file" "$log" | head -8; rc=1
  fi
}

for t in policy wan_cfg frame_facts glom sdpcm_hdr el0_ring wpa_keyer abslot dhcp_wire pppoe_disc ppp_ctl eapol_wire mgmt_records wpa_auth sae_wire rsn_assoc; do
  ml=4096; [ "$t" = abslot ] && ml=32768   # abslot spans 64 sectors
  fuzz_one heqk-hal "$t" "$ml"
done
# the OS-update / boot verifier (boot_abi::verify: header gates, streamed digest, Ed25519 + SLH-DSA, SVN floor)
fuzz_one heqk-boot-abi payload_header 8192
# the firmware DTB reader HBoot uses for platform discovery (boot_abi::fdt — ADR 0061 D1, ADR 0062 T0)
fuzz_one heqk-boot-abi fdt_parse 131072
# the kernel crate's network-facing parsers (same source files, #[path]) — SEC-02; owner_journal = A9 (journal replay)
for t in http_req dns_wire tls_hello frame_meta cfg_bundle owner_journal; do
  fuzz_one heqk-kernel "$t" 4096
done
# the control channel's record layer (securechannel.rs: rekey epochs, replay windows, key retirement) — W4
fuzz_one heqk-securechannel record_rx 4096
[ $rc = 0 ] && echo "FUZZ: PASS (${T}s per target)" || echo "FUZZ: FAIL"
exit $rc
