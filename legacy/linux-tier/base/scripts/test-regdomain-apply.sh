#!/usr/bin/env bash
# =============================================================================
# base/scripts/test-regdomain-apply.sh — sandbox fixture for base/scripts/regdomain-apply.sh.
#
# Covers the 2026-07-15 diagnostics/tightening pass (ADR 0034 extension, "adaptive 5GHz-first AP
# band" work item 4 — the geoIP re-resolve field finding):
#   * `hp_wan_exit_ip` logs WHY it returned empty (no default route / no address yet / CGNAT-
#     private / echo-disabled) to STDERR, while STDOUT carries ONLY the IP (or nothing) — the
#     caller's `$(...)` command substitution must never capture a log line as if it were an IP.
#   * The "any global address" guess-fallback is REMOVED: an unrelated interface's public address
#     must NEVER be attributed to the WAN exit when the WAN dev itself has no address.
#   * The offline GeoIP DB lookup itself still resolves real IPs correctly (the mechanism is not
#     broken — the "regdomain unchanged (00)" field symptom was CGNAT + unmapped timezone, not a
#     lookup bug — see the embedded DB smoke tests below).
#   * `hp_resolve_cc`'s full priority ladder still degrades correctly end-to-end, and the oneshot
#     entry points (`hp_regdomain_main` / `hp_regdomain_reresolve_main`) NEVER fail (GAP-R1: always
#     exit 0, always write a valid token).
#
# Usage: base/scripts/test-regdomain-apply.sh
# Exit 0 iff every case below produced the result this fixture expects.
# =============================================================================
# shellcheck disable=SC2016,SC2034,SC2317
# (SC2016: `check()` deliberately takes its condition in SINGLE quotes and `eval`s it itself, so
#  variables inside expand at eval-time, not call-time — the same pattern test-wifi-calibrate.sh
#  already uses. SC2034: `RSRC` IS read, but only inside one of those single-quoted `check()`
#  strings, which shellcheck's static analysis can't see into. SC2317: the `ip`/`mmcli`/`iw`
#  function-shadowing test doubles below ARE called — indirectly, by the sourced script's own
#  functions — shellcheck's reachability analysis doesn't follow that either.)
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/regdomain-apply.sh"
REPO=$(cd "$HERE/../.." && pwd)

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

FAIL=0
ok()  { echo "  PASS: $*"; }
bad() { echo "  FAIL: $*"; FAIL=1; }
check() { if eval "$1"; then ok "$2"; else bad "$3"; fi; }

# Source for functions only — both `hp_regdomain_main`/`hp_regdomain_reresolve_main` are guarded by
# the `[ "${BASH_SOURCE[0]}" = "${0}" ]` idiom, so sourcing never touches the real network/systemd.
export HOOKPROBE_GEOIP_DIR="$REPO/base/data/ip-location-db"
export WIFI_INTENT_FILES="$TMP/no-such-intent.yaml"
export RUN_CC_FILE="$TMP/wifi-country"
export WIFI_LKG_FILE="$TMP/regdomain-lkg"
# shellcheck source=/dev/null
source "$SCRIPT"
set +e

# =============================================================================================
# Part 1 — hp_wan_exit_ip: diagnostics on STDERR, clean IP-or-nothing on STDOUT
# =============================================================================================

# --- (a) no default route at all -> empty stdout, a clear stderr reason, no guess -------------
ip() { if [ "$1" = route ]; then return 0; fi; return 1; }
OUT=$(hp_wan_exit_ip 2>"$TMP/err_a.log")
check '[ -z "$OUT" ]' "no default route => empty stdout (no guess)" "expected empty, got: '$OUT'"
check 'grep -q "no default route" "$TMP/err_a.log"' \
  "no default route => a clear stderr reason logged" "missing expected stderr reason: $(cat "$TMP/err_a.log")"
unset -f ip

# --- (b) default route dev exists but holds no address yet -> empty stdout, clear reason ------
ip() {
  if [ "$1" = route ]; then echo "default via 1.2.3.4 dev eth0"; return 0; fi
  return 1   # no address query succeeds
}
OUT=$(hp_wan_exit_ip 2>"$TMP/err_b.log")
check '[ -z "$OUT" ]' "WAN dev with no address yet => empty stdout" "expected empty, got: '$OUT'"
check 'grep -q "no global address yet" "$TMP/err_b.log"' \
  "WAN dev with no address yet => a clear stderr reason logged" "got: $(cat "$TMP/err_b.log")"
unset -f ip

# --- (c) WAN dev holds a PUBLIC address -> that exact IP on stdout, no log noise on stdout -----
ip() {
  if [ "$1" = route ]; then echo "default via 1.2.3.4 dev eth0"; return 0; fi
  if [ "$1" = -4 ] && [ "$2" = -o ]; then
    echo "2: eth0    inet 86.120.0.1/24 brd 86.120.0.255 scope global eth0"; return 0
  fi
  return 1
}
OUT=$(hp_wan_exit_ip 2>"$TMP/err_c.log")
check '[ "$OUT" = "86.120.0.1" ]' "public WAN address => returned verbatim on stdout: $OUT" "expected 86.120.0.1, got: '$OUT'"
unset -f ip

# --- (d) WAN dev holds a CGNAT (100.64.0.0/10) address -> empty stdout, CGNAT reason logged ----
# (the actual field finding: fibre PPPoE WANs increasingly hand out CGNAT, not just a lab NAT)
ip() {
  if [ "$1" = route ]; then echo "default via 10.0.16.191 dev ppp0"; return 0; fi
  if [ "$1" = -4 ] && [ "$2" = -o ]; then
    echo "3: ppp0    inet 100.102.141.70 peer 10.0.16.191/32 scope global ppp0"; return 0
  fi
  return 1
}
OUT=$(hp_wan_exit_ip 2>"$TMP/err_d.log")
check '[ -z "$OUT" ]' "CGNAT WAN address => empty stdout (never guessed as public)" "expected empty, got: '$OUT'"
check 'grep -qi "CGNAT" "$TMP/err_d.log"' "CGNAT WAN address => the CGNAT reason is logged clearly" "got: $(cat "$TMP/err_d.log")"
unset -f ip

# --- (e) TIGHTENED: an unrelated interface's PUBLIC address must NEVER be guessed when the WAN
# dev itself has no address (the removed "scan any global address" fallback) ---------------------
ip() {
  if [ "$1" = route ]; then echo "default via 1.2.3.4 dev eth0"; return 0; fi
  # eth0 (the actual WAN dev) has no address; a totally unrelated podman bridge DOES have a public-
  # looking one — must NOT be picked up as "the WAN exit IP".
  if [ "$1" = -4 ] && [ "$2" = -o ] && [ "${4:-}" = eth0 ]; then return 1; fi
  if [ "$1" = -4 ] && [ "$2" = -o ] && [ -z "${4:-}" ]; then
    echo "9: podman3    inet 9.9.9.9/24 scope global podman3"; return 0
  fi
  return 1
}
OUT=$(hp_wan_exit_ip 2>"$TMP/err_e.log")
check '[ "$OUT" != "9.9.9.9" ]' "an unrelated interface's address is NEVER guessed as the WAN exit IP" "REGRESSION: guessed $OUT"
unset -f ip

# =============================================================================================
# Part 2 — the offline GeoIP DB lookup mechanism itself (proves it is NOT broken)
# =============================================================================================

check '[ "$(hp_geoip_lookup4 86.120.0.1)" = "RO" ]' "offline DB: a real Romanian IPv4 range resolves to RO" \
  "expected RO, got: $(hp_geoip_lookup4 86.120.0.1)"
check '[ "$(hp_geoip_lookup4 8.8.8.8)" = "US" ]' "offline DB: 8.8.8.8 resolves to US" \
  "expected US, got: $(hp_geoip_lookup4 8.8.8.8)"
check '[ -z "$(hp_geoip_lookup4 999.999.999.999)" ]' "offline DB: a malformed IP resolves to nothing (never a crash/guess)" \
  "expected empty, got: $(hp_geoip_lookup4 999.999.999.999)"

# --- hp_ip_is_public: CGNAT/RFC1918/loopback/link-local all correctly rejected; a real public
# IPv4 and a global IPv6 are correctly accepted -------------------------------------------------
check 'hp_ip_is_public 86.120.0.1' "hp_ip_is_public: a real public IPv4 is accepted" "wrongly rejected 86.120.0.1"
check '! hp_ip_is_public 100.102.141.70' "hp_ip_is_public: CGNAT (100.64.0.0/10) is rejected" "wrongly accepted CGNAT address"
check '! hp_ip_is_public 10.200.0.1' "hp_ip_is_public: RFC1918 10.x is rejected" "wrongly accepted RFC1918"
check '! hp_ip_is_public 192.168.1.1' "hp_ip_is_public: RFC1918 192.168.x is rejected" "wrongly accepted RFC1918"
check '! hp_ip_is_public 127.0.0.1' "hp_ip_is_public: loopback is rejected" "wrongly accepted loopback"
check 'hp_ip_is_public 2a01:cb19::1' "hp_ip_is_public: a global IPv6 (2xxx::) is accepted" "wrongly rejected global IPv6"
check '! hp_ip_is_public fe80::1' "hp_ip_is_public: link-local IPv6 is rejected" "wrongly accepted link-local IPv6"

# =============================================================================================
# Part 3 — hp_resolve_cc end-to-end degrade chain + GAP-R1 (never fails, never empty)
# =============================================================================================

# No operator intent, no LKG, no modem, WAN not up (no default route) — must degrade to
# timezone (if /etc/timezone maps) or world, NEVER crash, NEVER emit "auto"/empty.
ip() { if [ "$1" = route ]; then return 0; fi; return 1; }
mmcli() { return 1; }
OUT=$(hp_resolve_cc)
read -r RCC RSRC <<<"$OUT"
check '[ -n "$RCC" ] && [ "${#RCC}" -eq 2 ]' "hp_resolve_cc with nothing live available still returns a 2-char token: '$RCC'" \
  "hp_resolve_cc returned an invalid token: '$OUT'"
check '[ "$RCC" != "AUTO" ]' "hp_resolve_cc NEVER returns 'auto'" "REGRESSION: hp_resolve_cc returned auto"
check '[ -n "$RSRC" ]' "hp_resolve_cc always names a source" "hp_resolve_cc source empty"
unset -f ip mmcli

# GAP-R1: hp_regdomain_main must exit 0 even when EVERYTHING (iw, run-file write) fails.
iw() { return 1; }
export RUN_CC_FILE="/this/path/cannot/possibly/be/written/wifi-country"
hp_regdomain_main >/tmp/hp_main.log 2>&1
RC=$?
check '[ "$RC" -eq 0 ]' "hp_regdomain_main exits 0 even with iw+run-file-write both failing (GAP-R1)" "hp_regdomain_main exited $RC"
unset -f iw
export RUN_CC_FILE="$TMP/wifi-country"

# GAP-R1 (reresolve mode): must also always return 0, and never downgrade a real CC to 00 on a
# transient WAN blip (the existing idempotency guard) — sanity-check it's intact after this change.
printf 'RO\n' > "$RUN_CC_FILE"
ip() { if [ "$1" = route ]; then return 0; fi; return 1; }  # WAN down this call -> resolves to 00/world
mmcli() { return 1; }
hp_regdomain_reresolve_main >"$TMP/reresolve.log" 2>&1
RC=$?
check '[ "$RC" -eq 0 ]' "hp_regdomain_reresolve_main always exits 0" "exited $RC"
check '[ "$(cat "$RUN_CC_FILE")" = "RO" ]' "reresolve NEVER downgrades a real CC (RO) to 00 on a transient WAN blip" \
  "run-file was downgraded: $(cat "$RUN_CC_FILE")"
check 'grep -q "latest resolve source" "$TMP/reresolve.log"' \
  "reresolve no-op log now names the resolve source (diagnosability improvement)" \
  "missing 'latest resolve source' in: $(cat "$TMP/reresolve.log")"
unset -f ip mmcli

echo
if [ "$FAIL" -eq 0 ]; then
  echo "=== test-regdomain-apply: ALL CASES PASSED ==="
  exit 0
else
  echo "=== test-regdomain-apply: FAILED -- see FAIL lines above ==="
  exit 1
fi
