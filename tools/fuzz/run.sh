#!/usr/bin/env bash
# tools/fuzz/run.sh [seconds-per-target] — coverage-guided libFuzzer runs over the host-buildable heqk
# parsers (the `hal` crate: POLICY.TXT, WAN.TXT, frame facts / VLAN tags, SDIO glom). The kernel-crate parsers
# (Shield, owner journal, artifact store, HTTP, ...) are covered by the in-kernel fixed-seed [P-fuzz].
# Needs: nightly + `cargo install cargo-fuzz`. Exit 1 on any crash (the reproducer stays in artifacts/).
set -u
T="${1:-60}"; cd "$(dirname "$0")/heqk-hal" || exit 2
rc=0
for t in policy wan_cfg frame_facts glom; do
  mkdir -p corpus/$t
  if cargo +nightly fuzz run --fuzz-dir . "$t" corpus/$t -- -max_total_time="$T" -max_len=4096 > "/tmp/heqk-fuzz-$t.log" 2>&1; then
    echo "  ok   $t: $(grep -oE 'Done [0-9]+ runs' /tmp/heqk-fuzz-$t.log | tail -1)"
  else
    echo "  FAIL $t (crash — reproducer in tools/fuzz/heqk-hal/artifacts/$t/)"; grep -E "panicked at|SUMMARY" "/tmp/heqk-fuzz-$t.log" | head -3; rc=1
  fi
done
exit $rc
