#!/usr/bin/env bash
# tools/fuzz/run.sh [seconds-per-target] — coverage-guided libFuzzer runs over the host-buildable heqk
# parsers (the `hal` crate: POLICY.TXT, WAN.TXT, frame facts / VLAN tags, SDIO glom, the A/B OTA slot derivation) and `boot-abi` (the signed-image verifier). The kernel-crate parsers
# network-facing parsers run from the SAME source files via tools/fuzz/heqk-kernel (HTTP request + form bodies, DNS
# wire, TLS ClientHello / JA4, frame classifier); fixed-layout MAC-verified stores stay with the in-kernel [P-fuzz].
# Needs: nightly + `cargo install cargo-fuzz`. Exit 1 on any crash (the reproducer stays in artifacts/).
set -u
T="${1:-60}"; cd "$(dirname "$0")/heqk-hal" || exit 2
rc=0
for t in policy wan_cfg frame_facts glom abslot dhcp_wire; do
  mkdir -p corpus/$t
  ml=4096; [ "$t" = abslot ] && ml=32768   # (was `\&\&` inside $(...): `[` errored, abslot got 4096 = 8 sectors)
  if cargo +nightly fuzz run --fuzz-dir . "$t" corpus/$t -- -max_total_time="$T" -max_len=$ml > "/tmp/heqk-fuzz-$t.log" 2>&1; then
    echo "  ok   $t: $(grep -oE 'Done [0-9]+ runs' /tmp/heqk-fuzz-$t.log | tail -1)"
  elif grep -qE "panicked at|SUMMARY: libFuzzer|deadly signal" "/tmp/heqk-fuzz-$t.log"; then
    echo "  FAIL $t (crash — reproducer in tools/fuzz/heqk-hal/artifacts/$t/)"; grep -E "panicked at|SUMMARY" "/tmp/heqk-fuzz-$t.log" | head -3; rc=1
  else
    # Not a crash: the harness did not build or libFuzzer did not start. Say so instead of crying "crash".
    echo "  FAIL $t (build/setup error, not a crash)"; grep -E "^error|could not|No such file" "/tmp/heqk-fuzz-$t.log" | head -5; rc=1
  fi
done
# the OS-update / boot verifier (boot_abi::verify: header gates, streamed digest, Ed25519 + SLH-DSA, SVN floor)
cd ../heqk-boot-abi || exit 2
mkdir -p corpus/payload_header
if cargo +nightly fuzz run --fuzz-dir . payload_header corpus/payload_header -- -max_total_time="$T" -max_len=8192 > /tmp/heqk-fuzz-payload_header.log 2>&1; then
  echo "  ok   payload_header: $(grep -oE 'Done [0-9]+ runs' /tmp/heqk-fuzz-payload_header.log | tail -1)"
else
  echo "  FAIL payload_header (crash — reproducer in tools/fuzz/heqk-boot-abi/artifacts/payload_header/)"; rc=1
fi
# the kernel crate's network-facing parsers (same source files, #[path]) — SEC-02
cd ../heqk-kernel || exit 2
for t in http_req dns_wire tls_hello frame_meta; do
  mkdir -p corpus/$t
  if cargo +nightly fuzz run --fuzz-dir . "$t" corpus/$t -- -max_total_time="$T" -max_len=4096 > "/tmp/heqk-fuzz-$t.log" 2>&1; then
    echo "  ok   $t: $(grep -oE 'Done [0-9]+ runs' /tmp/heqk-fuzz-$t.log | tail -1)"
  else
    echo "  FAIL $t (crash or build error — see /tmp/heqk-fuzz-$t.log, reproducer in tools/fuzz/heqk-kernel/artifacts/$t/)"; rc=1
  fi
done
[ $rc = 0 ] && echo "FUZZ: PASS (${T}s per target)" || echo "FUZZ: FAIL"
exit $rc
