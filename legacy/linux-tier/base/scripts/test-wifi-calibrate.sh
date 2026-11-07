#!/usr/bin/env bash
# =============================================================================
# base/scripts/test-wifi-calibrate.sh — sandbox fixture for the ADR 0034 D14 verify-retry loop
# (base/scripts/wifi-calibrate.sh), specifically the 2026-07-12 metal fixes:
#
#   BUG-W5 (converged-is-stable): if the AP's operating channel+width MATCH the requested rung
#           after settle, the verdict must be Stable — REGARDLESS of any chanspec-fail lines
#           logged getting there (the proven brcmfmac bounce-then-converge pattern). A rung that
#           genuinely never converges must still retry→stepdown as before.
#   BUG-W6 (per-attempt dmesg scoping): a chanspec-fail count must be scoped to the CURRENT
#           attempt's dmesg window only — a prior attempt's/rung's stale fail lines must never
#           leak into the next attempt's verdict.
#
# Two independent test seams, both inert in production (never set outside this harness):
#   1. `observe_rung`'s TEST_IW_INFO / TEST_HOSTAPD_ACTIVE env overrides — a synthetic feed that
#      drives the operating channel/width/active-state precisely, used for the verdict-PRIORITY
#      cases (converged-despite-fails vs never-converges).
#   2. A fake `dmesg` shadowing PATH (a stateful buffer file), used to prove `mark_dmesg`'s REAL
#      clear/marker scoping mechanism end-to-end across multiple simulated attempts — this is what
#      actually exercises BUG-W6's fix, not just its symptom.
#
# Usage: base/scripts/test-wifi-calibrate.sh
# Exit 0 iff every case below produced the verdict this fixture expects.
# =============================================================================
# shellcheck disable=SC2016
# (SC2016: the `check()` helper below deliberately takes its condition in SINGLE quotes — it
# `eval`s that string itself, so the variables inside must expand at eval-time, not at call-time.
# This is the intended pattern, not an escaping mistake.)
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/wifi-calibrate.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

FAIL=0
ok()  { echo "  PASS: $*"; }
bad() { echo "  FAIL: $*"; FAIL=1; }
# A tiny if/then wrapper so every assertion below is unambiguous if-then-else (avoids the
# `A && B || C` "C may run when A is true" trap — shellcheck SC2015).
check() { if eval "$1"; then ok "$2"; else bad "$3"; fi; }

# Source the script for its functions only — the `main "$@"` entry point is guarded by the
# `[ "${BASH_SOURCE[0]:-$0}" = "${0}" ]` idiom, so sourcing never touches a real radio/hostapd.
# shellcheck source=/dev/null
source "$SCRIPT"
# wifi-calibrate.sh sets `-e` for ITS OWN safety as a standalone script; this harness wants to run
# every case and report failures at the end (matching builder/test-artifact-digest-gate.sh's style),
# so drop errexit again right after sourcing (its `-u`/`pipefail` are harmless and kept).
set +e

# =============================================================================================
# Part 1 — BUG-W5: verdict PRIORITY (observe_rung), via the synthetic TEST_IW_INFO/TEST_HOSTAPD_ACTIVE feed
# =============================================================================================

# A realistic single-line `iw dev … info` fragment carries both fields our sed patterns look for.
iw_line() { echo "	channel $1 (5180 MHz), width: $2 MHz, center1: 5210 MHz"; }

# --- Case (a): converged despite transient chanspec-fails during settle => Stable/Keep ---------
DMESG_MODE="cleared"   # simulate mark_dmesg having cleared the ring for this attempt
TEST_IW_INFO=$(iw_line 36 80); export TEST_IW_INFO
export TEST_HOSTAPD_ACTIVE=1
# Real dmesg on THIS test box may be empty/inaccessible — that's fine, the point of this case is
# the verdict must be Stable EVEN IF fails are counted; force a positive count deterministically by
# stubbing dmesg itself so this case is not accidentally trivially-true on a quiet dmesg.
FAKE_BIN="$TMP/fakebin_a"; mkdir -p "$FAKE_BIN"
cat > "$FAKE_BIN/dmesg" <<'EOS'
#!/usr/bin/env bash
# Simulate the proven bounce-then-converge dmesg trace: a chanspec-fail burst DID happen this
# attempt, but the radio converged anyway (that's the whole point of BUG-W5).
if [ "${1:-}" = "-C" ]; then exit 0; fi
printf 'brcmf_set_channel: set chanspec 0xd826 fail\n'
printf 'brcmf_set_channel: set chanspec 0xd826 fail\n'
printf 'brcmf_set_channel: set chanspec 0xd826 fail\n'
EOS
chmod +x "$FAKE_BIN/dmesg"
OUT=$(PATH="$FAKE_BIN:$PATH" observe_rung 36 80); RC=$?
if [ "$RC" -eq 0 ] && echo "$OUT" | grep -qE '^36 80 [0-9]+$'; then
  ok "converged despite 3 transient chanspec-fail lines => Stable/Keep (rc=0): '$OUT'"
else
  bad "expected rc=0 (Stable) + '36 80 <fails>', got rc=$RC: '$OUT'"
fi
ACT=$(next_rung_action stable 0)
check '[ "$ACT" = keep ]' "next_rung_action(stable) => keep" "next_rung_action(stable) => $ACT, expected keep"

# --- Case (a2): BUG-W7 — THE 150-Mbps bug. Requested VHT80-ch40; the brcmfmac firmware brings the
# AP up WORKING at 80 MHz but NAMES the primary as the block's lowest channel (36). Live ground truth
# (CM5 + Pi4, 2026-07-17): `channel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz`, hostapd active,
# client associated — plus the harmless one-time bring-up churn. Pre-fix this returned rc=2
# (ChanspecFailStorm) and the loop REVERTED a healthy ~250 Mbit/s link to HT40 (~150 Mbit/s).
# 36 and 40 are the SAME physical 80 MHz channel => MUST be rc=0 (Stable).
TEST_IW_INFO=$(iw_line 36 80); export TEST_IW_INFO
export TEST_HOSTAPD_ACTIVE=1
DMESG_MODE="cleared"
cat > "$FAKE_BIN/dmesg" <<'EOS'
#!/usr/bin/env bash
if [ "${1:-}" = "-C" ]; then exit 0; fi
# the exact 7-line one-time bring-up churn observed on metal
for i in 1 2 3 4 5 6 7; do printf 'brcmf_set_channel: set chanspec 0xd022 fail, reason -52\n'; done
EOS
chmod +x "$FAKE_BIN/dmesg"
OUT=$(PATH="$FAKE_BIN:$PATH" observe_rung 40 80); RC=$?
if [ "$RC" -eq 0 ]; then
  ok "BUG-W7: VHT80-ch40 reported as block-primary ch36 => Stable (rc=0), never reverted: '$OUT'"
else
  bad "BUG-W7 REGRESSION: ch36-reported VHT80 IS the requested ch40 block — expected rc=0, got rc=$RC: '$OUT'"
fi

# --- Case (a3): BUG-W7 must NOT blind the real-drift detector. ch140 is a DIFFERENT block (center
# 138), so even at 80 MHz it is a genuine failure, not a naming quirk.
TEST_IW_INFO=$(iw_line 140 80); export TEST_IW_INFO
OUT=$(PATH="$FAKE_BIN:$PATH" observe_rung 40 80); RC=$?
if [ "$RC" -eq 2 ]; then
  ok "BUG-W7: ch140/80MHz is NOT the 36-48 block => still ChanspecFailStorm (rc=2): '$OUT'"
else
  bad "BUG-W7: ch140 drift must stay a failure — expected rc=2, got rc=$RC: '$OUT'"
fi

# --- Case (a4): block-leniency must NOT leak into 20/40 MHz (the firmware reports those faithfully).
TEST_IW_INFO=$(iw_line 40 40); export TEST_IW_INFO
cat > "$FAKE_BIN/dmesg" <<'EOS'
#!/usr/bin/env bash
if [ "${1:-}" = "-C" ]; then exit 0; fi
EOS
OUT=$(PATH="$FAKE_BIN:$PATH" observe_rung 36 40); RC=$?
if [ "$RC" -eq 1 ]; then
  ok "BUG-W7: HT40 keeps the EXACT-channel contract (ch40 != requested ch36) => WidthCollapsed (rc=1)"
else
  bad "BUG-W7: HT40 must require an exact channel match — expected rc=1, got rc=$RC: '$OUT'"
fi

# --- Case (a5): the block map itself ---------------------------------------------------------
check 'same_80mhz_block 36 40' "same_80mhz_block 36 40 (both in the 36-48 block)" "36/40 must be the same block"
check 'same_80mhz_block 48 40' "same_80mhz_block 48 40" "48/40 must be the same block"
check '! same_80mhz_block 140 40' "! same_80mhz_block 140 40 (different blocks)" "140/40 must NOT be the same block"
check '! same_80mhz_block 6 40' "! same_80mhz_block 6 40 (2.4GHz is in no 80MHz block)" "ch6 must not match any 80MHz block"

# --- Case (b): never converges (oper != requested after full settle) => retry => stepdown ------
TEST_IW_INFO=$(iw_line 140 20); export TEST_IW_INFO   # ch140/20MHz collapse, requested was 36/80
export TEST_HOSTAPD_ACTIVE=1
DMESG_MODE="cleared"
cat > "$FAKE_BIN/dmesg" <<'EOS'
#!/usr/bin/env bash
if [ "${1:-}" = "-C" ]; then exit 0; fi
# no chanspec-fail lines this attempt — the collapse can be silent
EOS
OUT=$(PATH="$FAKE_BIN:$PATH" observe_rung 36 80); RC=$?
if [ "$RC" -eq 1 ] && echo "$OUT" | grep -qE '^140 20 0$'; then
  ok "never-converges, no fail lines => WidthCollapsed (rc=1): '$OUT'"
else
  bad "expected rc=1 (WidthCollapsed), got rc=$RC: '$OUT'"
fi
A0=$(next_rung_action width_collapsed 0)
A1=$(next_rung_action width_collapsed 1)
A2=$(next_rung_action width_collapsed 2)   # MAX_RETRIES default = 2
check '[ "$A0" = retry ] && [ "$A1" = retry ] && [ "$A2" = stepdown ]' \
  "width_collapsed: retry, retry, stepdown at attempt==MAX_RETRIES ($A0/$A1/$A2)" \
  "width_collapsed retry-ladder wrong: $A0/$A1/$A2 (expected retry/retry/stepdown)"

# --- Case (b2): never converges WITH a genuine chanspec-fail storm => ChanspecFailStorm --------
cat > "$FAKE_BIN/dmesg" <<'EOS'
#!/usr/bin/env bash
if [ "${1:-}" = "-C" ]; then exit 0; fi
printf 'brcmf_set_channel: set chanspec 0xd826 fail\n'
printf 'brcmf_set_channel: set chanspec 0xd826 fail\n'
EOS
OUT=$(PATH="$FAKE_BIN:$PATH" observe_rung 36 80); RC=$?
check '[ "$RC" -eq 2 ]' "never-converges + fail storm => ChanspecFailStorm (rc=2): '$OUT'" \
  "expected rc=2 (ChanspecFailStorm), got rc=$RC: '$OUT'"

# --- Case: AP unit down => Down, regardless of fails/convergence -------------------------------
export TEST_HOSTAPD_ACTIVE=0
TEST_IW_INFO=$(iw_line 36 80); export TEST_IW_INFO   # would otherwise look converged
OUT=$(PATH="$FAKE_BIN:$PATH" observe_rung 36 80); RC=$?
check '[ "$RC" -eq 3 ]' "hostapd unit inactive => Down (rc=3) even though ch/width would match" \
  "expected rc=3 (Down), got rc=$RC"
export TEST_HOSTAPD_ACTIVE=1

# --- Case: floor rung (2.4GHz/HT20) still converges to Stable => loop always terminates stable -
TEST_IW_INFO=$(iw_line 6 20); export TEST_IW_INFO
cat > "$FAKE_BIN/dmesg" <<'EOS'
#!/usr/bin/env bash
if [ "${1:-}" = "-C" ]; then exit 0; fi
EOS
OUT=$(PATH="$FAKE_BIN:$PATH" observe_rung 6 20); RC=$?
check '[ "$RC" -eq 0 ]' "2.4GHz/HT20 floor converges => Stable (never-down guarantee): '$OUT'" \
  "floor rung expected rc=0 (Stable), got rc=$RC: '$OUT'"

unset TEST_IW_INFO TEST_HOSTAPD_ACTIVE

# =============================================================================================
# Part 2 — BUG-W6: mark_dmesg's REAL per-attempt scoping (fake `dmesg` on PATH, no TEST_* feed)
# =============================================================================================
# This proves the MECHANISM (dmesg -C / marker fallback), not just the symptom: a stateful fake
# `dmesg` backed by a buffer file, so successive mark_dmesg + observe_rung calls behave exactly
# like the real kernel ring buffer would across attempts.

FAKE_BIN2="$TMP/fakebin_b"; mkdir -p "$FAKE_BIN2"
BUF="$TMP/dmesg_buf.txt"
: > "$BUF"
cat > "$FAKE_BIN2/dmesg" <<EOF
#!/usr/bin/env bash
BUF="$BUF"
if [ "\${1:-}" = "-C" ]; then : > "\$BUF"; exit 0; fi
cat "\$BUF" 2>/dev/null
EOF
chmod +x "$FAKE_BIN2/dmesg"

export PATH="$FAKE_BIN2:$PATH"

# --- Case (c): a prior attempt's fails must NOT leak into the next attempt's count -------------
# Attempt 1: 5 stale fail lines sitting in the buffer from BEFORE this attempt started (simulating
# the prior rung's residue the field capture found — the exact 34/30/20/17-aging-out bug).
printf 'brcmf_set_channel: set chanspec 0xd826 fail\n%.0s' {1..5} > "$BUF"
mark_dmesg   # BUG-W6 fix: clears the buffer right before THIS attempt's clean_restart
check '[ "$DMESG_MODE" = "cleared" ]' \
  "mark_dmesg: DMESG_MODE=cleared (fake dmesg -C succeeds)" \
  "mark_dmesg: expected DMESG_MODE=cleared, got '$DMESG_MODE'"
TEST_IW_INFO=$(iw_line 36 80); export TEST_IW_INFO
export TEST_HOSTAPD_ACTIVE=1
OUT=$(observe_rung 36 80); RC=$?
if echo "$OUT" | grep -qE '^36 80 0$' && [ "$RC" -eq 0 ]; then
  ok "prior-attempt's 5 stale fail lines did NOT leak after mark_dmesg cleared the buffer: '$OUT'"
else
  bad "expected '36 80 0' (no leaked fails) + rc=0, got rc=$RC: '$OUT'"
fi

# Attempt 2 (same rung, clean retry): a NEW fail burst genuinely happens during THIS attempt's
# settle (simulating the real bounce) — must be counted, and (per BUG-W5) still converge to Stable.
printf 'brcmf_set_channel: set chanspec 0xd826 fail\n%.0s' {1..3} >> "$BUF"
OUT=$(observe_rung 36 80); RC=$?
if echo "$OUT" | grep -qE '^36 80 3$' && [ "$RC" -eq 0 ]; then
  ok "THIS attempt's 3 genuine fail lines ARE counted, and convergence still wins => Stable: '$OUT'"
else
  bad "expected '36 80 3' + rc=0, got rc=$RC: '$OUT'"
fi

# --- marker fallback: dmesg -C refused (no privilege) => tail only the lines added AFTER the mark
cat > "$FAKE_BIN2/dmesg" <<EOF
#!/usr/bin/env bash
BUF="$BUF"
if [ "\${1:-}" = "-C" ]; then exit 1; fi   # simulate a refused clear (no CAP_SYSLOG)
cat "\$BUF" 2>/dev/null
EOF
printf 'brcmf_set_channel: set chanspec 0xd826 fail\n%.0s' {1..7} > "$BUF"   # stale, pre-mark
mark_dmesg
check '[ "$DMESG_MODE" = "marker" ]' \
  "mark_dmesg falls back to marker mode when 'dmesg -C' is refused (DMESG_MARK=$DMESG_MARK)" \
  "mark_dmesg: expected DMESG_MODE=marker when -C is refused, got '$DMESG_MODE'"
printf 'brcmf_set_channel: set chanspec 0xd826 fail\n%.0s' {1..2} >> "$BUF"   # 2 NEW lines this attempt
OUT=$(observe_rung 36 80); RC=$?
check 'echo "$OUT" | grep -qE "^36 80 2$"' \
  "marker fallback counts only the 2 NEW lines after the mark (7 stale lines excluded): '$OUT'" \
  "expected '36 80 2' (marker-scoped), got: '$OUT'"

unset TEST_IW_INFO TEST_HOSTAPD_ACTIVE

# --- dmesg entirely unavailable => never hard-fails the loop; fails=0, convergence still decides
# Uses the TEST_NO_DMESG synthetic hook rather than stripping `dmesg` from PATH, so the REST of
# PATH (sed/grep/head, which observe_rung genuinely needs) stays intact — see mark_dmesg's doc.
export TEST_NO_DMESG=1
DMESG_MODE="unavailable"; DMESG_MARK=0
mark_dmesg
check '[ "$DMESG_MODE" = "unavailable" ]' \
  "mark_dmesg degrades to 'unavailable' with TEST_NO_DMESG set (never hard-fails)" \
  "expected DMESG_MODE=unavailable, got '$DMESG_MODE'"
TEST_IW_INFO=$(iw_line 36 80); export TEST_IW_INFO
export TEST_HOSTAPD_ACTIVE=1
OUT=$(observe_rung 36 80); RC=$?
if echo "$OUT" | grep -qE '^36 80 0$' && [ "$RC" -eq 0 ]; then
  ok "observe_rung tolerates a missing dmesg entirely (fails=0, convergence still => Stable): '$OUT'"
else
  bad "expected '36 80 0' + rc=0 with no dmesg present, got rc=$RC: '$OUT'"
fi
unset TEST_IW_INFO TEST_HOSTAPD_ACTIVE TEST_NO_DMESG

# =============================================================================================
# Part 3 (2026-07-15, ADR 0034 D15/D18/D19 — "adaptive 5GHz-first AP band" polish)
# =============================================================================================

# --- D18: default_24_channel — always {1,6,11}, deterministic, device-sensitive ----------------
CH_A=$(default_24_channel "hp-deviceA")
CH_B=$(default_24_channel "hp-deviceA")
check '[ "$CH_A" = "$CH_B" ]' "default_24_channel is deterministic for a fixed seed ($CH_A)" \
  "default_24_channel not stable across calls: $CH_A vs $CH_B"
check '[ "$CH_A" = 1 ] || [ "$CH_A" = 6 ] || [ "$CH_A" = 11 ]' \
  "default_24_channel($CH_A) is one of {1,6,11}" "default_24_channel returned out-of-range: $CH_A"
CH_C=$(default_24_channel "hp-a-totally-different-device-id-shape")
check '[ "$CH_C" = 1 ] || [ "$CH_C" = 6 ] || [ "$CH_C" = 11 ]' \
  "default_24_channel($CH_C) for a different seed is also one of {1,6,11}" \
  "default_24_channel returned out-of-range: $CH_C"

# --- D15: normalize_band_pin — every spelling collapses to exactly 5 | 2.4 | auto --------------
check '[ "$(normalize_band_pin 5)" = 5 ]'          "normalize_band_pin(5) => 5" "wrong"
check '[ "$(normalize_band_pin 5GHz)" = 5 ]'        "normalize_band_pin(5GHz) => 5" "wrong"
check '[ "$(normalize_band_pin 2.4)" = 2.4 ]'       "normalize_band_pin(2.4) => 2.4" "wrong"
check '[ "$(normalize_band_pin 2.4GHz)" = 2.4 ]'    "normalize_band_pin(2.4GHz) => 2.4" "wrong"
check '[ "$(normalize_band_pin auto)" = auto ]'     "normalize_band_pin(auto) => auto" "wrong"
check '[ "$(normalize_band_pin Auto)" = auto ]'     "normalize_band_pin(Auto) case-insensitive => auto" "wrong"
check '[ "$(normalize_band_pin junk)" = auto ]'     "normalize_band_pin(junk) degrades to auto (never a guess)" "wrong"
check '[ "$(normalize_band_pin "")" = auto ]'       "normalize_band_pin('') degrades to auto" "wrong"

# --- D15: read_band_intent — reads the FIRST real match from the intent files, in order --------
INTENT_DIR="$TMP/intent"; mkdir -p "$INTENT_DIR"
cat > "$INTENT_DIR/network.yaml" <<'EOF'
network:
  wifi:
    ap:
      band: "5"
    country: auto
EOF
WIFI_BAND_INTENT_FILES=("$INTENT_DIR/network.yaml" "$INTENT_DIR/nonexistent.yaml")
check '[ "$(read_band_intent)" = 5 ]' "read_band_intent reads a quoted band: \"5\" from network.yaml" \
  "read_band_intent got: $(read_band_intent)"

cat > "$INTENT_DIR/network.yaml" <<'EOF'
network:
  wifi:
    ap:
      band: auto
EOF
check '[ "$(read_band_intent)" = auto ]' "read_band_intent reads an unquoted band: auto" \
  "read_band_intent got: $(read_band_intent)"

# shellcheck disable=SC2034
# (SC2034: consumed by read_band_intent, sourced from wifi-calibrate.sh — shellcheck's dataflow
# doesn't see the read past this point since the variable is never read directly in THIS file.)
WIFI_BAND_INTENT_FILES=("$INTENT_DIR/nonexistent.yaml")
check '[ "$(read_band_intent)" = auto ]' "read_band_intent with no readable intent file degrades to auto" \
  "read_band_intent got: $(read_band_intent)"

# --- 2026-07-15: build_ladder — the operator's exact 3-rung shape; a hard pin DISABLES the
# auto-ladder; auto keeps the full 3-rung ladder ------------------------------------------------
build_ladder 5
check '[ "${#LADDER[@]}" -eq 2 ]' "build_ladder(pin=5) yields exactly the 2 5GHz rungs (VHT80-ch40 + HT40-ch36, no 2.4 floor)" \
  "build_ladder(pin=5) yielded ${#LADDER[@]} rungs, expected 2"
LBLS5=""; for e in "${LADDER[@]}"; do read -r l _ <<<"$e"; LBLS5="$LBLS5 $l"; done
check '[[ "$LBLS5" != *"2.4GHz"* ]]' "build_ladder(pin=5) never includes a 2.4GHz rung: [$LBLS5 ]" \
  "build_ladder(pin=5) unexpectedly included a 2.4GHz rung: [$LBLS5 ]"
# 2026-07-16 (BUG-1): LADDER entries carry ONLY the 4 single-line fields — the ht_lines block is
# NO LONGER embedded inline (that inline embedding, pulled back out via a `read` that is line-based,
# is what silently truncated a multi-line block — see `ht_lines_for_label` in wifi-calibrate.sh).
check '[ "${LADDER[0]}" = "5GHz-VHT80-ch40 5 40 80" ]' \
  "build_ladder(pin=5) rung 0 is VHT80-ch40 (4 single-line fields only)" "got: ${LADDER[0]}"
check '[ "${LADDER[1]}" = "5GHz-HT40-ch36 5 36 40" ]' \
  "build_ladder(pin=5) rung 1 is HT40-ch36 (4 single-line fields only)" "got: ${LADDER[1]}"

build_ladder 2.4
check '[ "${#LADDER[@]}" -eq 1 ]' "build_ladder(pin=2.4) yields exactly ONE rung (the floor only)" \
  "build_ladder(pin=2.4) yielded ${#LADDER[@]} rungs, expected 1"
check '[ "${LADDER[0]}" = "2.4GHz-ch6 2.4 6 20" ]' \
  "build_ladder(pin=2.4) rung is the constant ch6 floor" \
  "got: ${LADDER[0]}"

build_ladder auto
check '[ "${#LADDER[@]}" -eq 3 ]' "build_ladder(auto) yields the operator's exact 3-rung ladder" \
  "build_ladder(auto) yielded ${#LADDER[@]} rungs, expected 3"
check '[ "${LADDER[0]}" = "5GHz-VHT80-ch40 5 40 80" ]' \
  "build_ladder(auto) rung 0 is VHT80-ch40" "got: ${LADDER[0]}"
check '[ "${LADDER[1]}" = "5GHz-HT40-ch36 5 36 40" ]' \
  "build_ladder(auto) rung 1 is HT40-ch36" "got: ${LADDER[1]}"
check '[ "${LADDER[2]}" = "2.4GHz-ch6 2.4 6 20" ]' \
  "build_ladder(auto) rung 2 (last) is the constant 2.4GHz-ch6 floor" "got: ${LADDER[2]}"

# --- 2026-07-16 BUG-1 regression: `read -r label band ch mhz <<<"$entry"` on a LADDER entry must
# now recover ALL 4 fields intact for EVERY rung, and `ht_lines_for_label` (looked up separately,
# never through that `read`) must return the FULL multi-line block — proving the truncation bug
# (both the wmm_enabled-glue symptom AND VHT80 silently losing its own vht_* lines) is fixed at
# the source, not just papered over at render time. ---------------------------------------------
build_ladder auto
for i in 0 1 2; do
  read -r RL_LABEL RL_BAND RL_CH RL_MHZ <<<"${LADDER[$i]}"
  check '[ -n "$RL_LABEL" ] && [ -n "$RL_BAND" ] && [ -n "$RL_CH" ] && [ -n "$RL_MHZ" ]' \
    "LADDER[$i] read recovers all 4 fields intact: label=$RL_LABEL band=$RL_BAND ch=$RL_CH mhz=$RL_MHZ" \
    "LADDER[$i] read lost a field: label=$RL_LABEL band=$RL_BAND ch=$RL_CH mhz=$RL_MHZ"
done

# NOTE: `$(ht_lines_for_label ...)` command substitution unconditionally strips ALL trailing
# newlines from its capture (a bash property, not a bug) — so a trailing-newline assertion on the
# CAPTURED value here would be structurally unobservable (always "fails" regardless of what the
# function actually returns) and is deliberately NOT asserted this way. `render_rung`'s own
# defense-in-depth guard re-normalises exactly this case (see wifi-calibrate.sh), and the
# "rendered conf never glues wmm_enabled" checks further below are the real, end-to-end proof that
# the trailing-newline separator survives all the way to the written conf file for every rung.
HT_V=$(ht_lines_for_label "5GHz-VHT80-ch40")
check '[[ "$HT_V" == *"ieee80211ac=1"* ]] && [[ "$HT_V" == *"vht_oper_centr_freq_seg0_idx=42"* ]]' \
  "ht_lines_for_label(VHT80-ch40) returns the FULL multi-line block, not just its first line: [$HT_V]" \
  "ht_lines_for_label(VHT80-ch40) is missing VHT lines — the truncation bug is back: [$HT_V]"
check '[[ "$HT_V" == *"ht_capab=[HT40-][SHORT-GI-20][SHORT-GI-40]"* ]]' \
  "ht_lines_for_label(VHT80-ch40) still carries its ht_capab line intact" "got: [$HT_V]"
HT_4=$(ht_lines_for_label "5GHz-HT40-ch36")
check '[ "$HT_4" = "ht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40]" ]' \
  "ht_lines_for_label(HT40-ch36) returns its single ht_capab line intact (modulo \$()'s trailing-newline strip)" \
  "got: [$HT_4]"
HT_0=$(ht_lines_for_label "2.4GHz-ch6")
check '[ -z "$HT_0" ]' "ht_lines_for_label(2.4GHz-ch6 floor) is empty (plain HT20, no width block)" "got: [$HT_0]"

# --- 2026-07-16 BUG-1: the rendered conf itself must never glue wmm_enabled onto the preceding
# line, for any of the 3 shipped rungs — the actual observable symptom on metal. -----------------
COUNTRY_LINES=""
BASE_SSID="HookProbe-TEST"
BASE_SEC="wpa_passphrase=testpass1234"
CONF="$TMP/hostapd-render-test.conf"
for i in 0 1 2; do
  read -r RL_LABEL RL_BAND RL_CH RL_MHZ <<<"${LADDER[$i]}"
  RL_HW=a; [ "$RL_BAND" = "2.4" ] && RL_HW=g
  RL_HT=$(ht_lines_for_label "$RL_LABEL")
  render_rung "wlan0" "$RL_HW" "$RL_CH" "$RL_HT"
  check '! grep -q "\]wmm_enabled" "$CONF"' \
    "rendered conf for $RL_LABEL never glues wmm_enabled onto a ht_capab/vht_* line" \
    "MALFORMED conf for $RL_LABEL: $(grep wmm_enabled "$CONF")"
  check 'grep -q "^wmm_enabled=1$" "$CONF"' \
    "rendered conf for $RL_LABEL has wmm_enabled=1 on its own line" \
    "$RL_LABEL conf missing a clean wmm_enabled=1 line: $(cat "$CONF")"
done
# The 2.4GHz floor (empty ht_lines) must not gain a spurious blank line before wmm_enabled either.
read -r RL_LABEL RL_BAND RL_CH RL_MHZ <<<"${LADDER[2]}"
render_rung "wlan0" "g" "$RL_CH" ""
check '! grep -qE "^$" "$CONF"' \
  "2.4GHz floor (empty ht_lines) renders with no spurious blank line" \
  "unexpected blank line in floor conf: $(cat -A "$CONF")"

# =============================================================================================
# Part — 2026-07-16 BUG-2: the WARM-UPGRADE (warm_upgrade_candidate / attempt_warm_upgrade)
# =============================================================================================
build_ladder auto

# --- warm_upgrade_candidate: pure eligibility, no I/O -------------------------------------------
WCAND=$(warm_upgrade_candidate "5GHz-HT40-ch36"); WRC=$?
check '[ "$WRC" -eq 0 ] && [ "$WCAND" = "5GHz-VHT80-ch40 5 40 80" ]' \
  "warm_upgrade_candidate(settled=HT40-ch36) offers the wider VHT80-ch40 rung: [$WCAND]" \
  "expected '5GHz-VHT80-ch40 5 40 80' rc=0, got rc=$WRC: [$WCAND]"

WCAND=$(warm_upgrade_candidate "5GHz-VHT80-ch40"); WRC=$?
check '[ "$WRC" -ne 0 ] && [ -z "$WCAND" ]' \
  "warm_upgrade_candidate(settled=VHT80-ch40, already the top rung) offers nothing" \
  "expected no candidate (rc!=0, empty), got rc=$WRC: [$WCAND]"

WCAND=$(warm_upgrade_candidate "2.4GHz-ch6"); WRC=$?
check '[ "$WRC" -ne 0 ] && [ -z "$WCAND" ]' \
  "warm_upgrade_candidate(settled=2.4GHz floor) never jumps bands" \
  "expected no candidate, got rc=$WRC: [$WCAND]"

WCAND=$(warm_upgrade_candidate "not-a-real-rung"); WRC=$?
check '[ "$WRC" -ne 0 ] && [ -z "$WCAND" ]' \
  "warm_upgrade_candidate(unknown/foreign label) degrades safely to no candidate" \
  "expected no candidate, got rc=$WRC: [$WCAND]"

build_ladder 2.4
WCAND=$(warm_upgrade_candidate "2.4GHz-ch6"); WRC=$?
check '[ "$WRC" -ne 0 ] && [ -z "$WCAND" ]' \
  "warm_upgrade_candidate on a single-rung (hard 2.4-pin) ladder is never eligible" \
  "expected no candidate, got rc=$WRC: [$WCAND]"
build_ladder auto

# --- attempt_warm_upgrade: converges → commits the upgrade (chosen becomes VHT80-ch40) ----------
# shellcheck disable=SC2034
# (SC2034: every one of these plain — deliberately NOT exported — variables is read by
# `attempt_warm_upgrade`/`render_rung`/`ht_lines_for_label`/`log`, all defined in the sourced
# wifi-calibrate.sh; shellcheck's dataflow doesn't trace into a `source=/dev/null` target, exactly
# the same pattern already justified at the `WIFI_BAND_INTENT_FILES` disable above. Bash functions
# see the CALLER's plain variables via ordinary dynamic scoping — `export` is not required here.)
WARM_DIR="$TMP/warm"; mkdir -p "$WARM_DIR/hostapd"
(
  HOSTAPD_DIR="$WARM_DIR/hostapd"; CONF="$HOSTAPD_DIR/hostapd-wlan0.conf"
  IFACE="wlan0"; BASE_SSID="HP-WARM"; BASE_SEC="wpa_passphrase=testpass1234"; COUNTRY_LINES=""
  radio_id="aa:bb:cc:dd:ee:ff"; cc="RO"; LEARN_NOW="2026-07-16T00:00:00Z"
  MODEL='{"schema":1,"iface":"wlan0","fw_id":"x","entries":[],"updated_at":"2026-07-16T00:00:00Z"}'
  attempts_json=""; chosen="5GHz-HT40-ch36"; chosen_band="5"; chosen_ch="36"
  SETTLE=0; SETTLE_5GHZ_WARM=0
  export TEST_HOSTAPD_ACTIVE=1 TEST_NO_DMESG=1
  # D46: deterministic "already warm" — never let this test's outcome depend on the REAL box's
  # uptime (which could, on a freshly-booted CI runner, be below WARM_MIN_UPTIME_SECONDS and cause
  # an actual multi-second-to-150s sleep here).
  export TEST_UPTIME_SECONDS=999
  # the warm re-attempt at ch40/80MHz genuinely converges this time (radio is warm).
  export TEST_IW_INFO=$'channel 40 (5200 MHz), width: 80 MHz, center1: 5210 MHz'
  attempt_warm_upgrade "5GHz-VHT80-ch40" "5" "40" "80"
  RC=$?
  { echo "RC=$RC CHOSEN=$chosen CHOSEN_BAND=$chosen_band CHOSEN_CH=$chosen_ch CHOSEN_MHZ=$chosen_mhz"; echo "ATTEMPTS=$attempts_json"; } > "$WARM_DIR/result_ok.txt"
  grep -q "channel=40" "$CONF" && echo "CONF_CH=40" >> "$WARM_DIR/result_ok.txt" || echo "CONF_CH=?" >> "$WARM_DIR/result_ok.txt"
)
RESULT_OK="$(cat "$WARM_DIR/result_ok.txt" 2>/dev/null)"
check '[[ "$RESULT_OK" == *"RC=0"* ]]' \
  "attempt_warm_upgrade returns 0 (commit) when the warm re-attempt converges" "got: $RESULT_OK"
check '[[ "$RESULT_OK" == *"CHOSEN=5GHz-VHT80-ch40"* ]] && [[ "$RESULT_OK" == *"CHOSEN_BAND=5"* ]] && [[ "$RESULT_OK" == *"CHOSEN_CH=40"* ]]' \
  "attempt_warm_upgrade commits chosen/chosen_band/chosen_ch to the upgraded VHT80-ch40 rung" "got: $RESULT_OK"
check '[[ "$RESULT_OK" == *"CHOSEN_MHZ=80"* ]]' \
  "attempt_warm_upgrade also commits chosen_mhz (D46: needed so a LATER warm-upgrade knows the current width)" "got: $RESULT_OK"
check '[[ "$RESULT_OK" == *"\"warm_upgrade\":true"* ]]' \
  "attempt_warm_upgrade records the attempt in attempts_json with warm_upgrade:true" "got: $RESULT_OK"
check '[[ "$RESULT_OK" == *"\"warm_attempt\":0"* ]]' \
  "attempt_warm_upgrade converging on the FIRST attempt records warm_attempt:0" "got: $RESULT_OK"
check '[[ "$RESULT_OK" == *"CONF_CH=40"* ]]' \
  "attempt_warm_upgrade leaves hostapd rendered+running for the UPGRADED (ch40) rung" "got: $RESULT_OK"
check '(echo "$RESULT_OK" | grep -o "\"warm_upgrade\":true" | wc -l | grep -qx 1)' \
  "attempt_warm_upgrade makes exactly ONE attempt when the FIRST one converges (no wasted retries)" "got: $RESULT_OK"

# --- attempt_warm_upgrade: does NOT converge (any attempt) → reverts to the proven rung, AP never down
# shellcheck disable=SC2034
(
  HOSTAPD_DIR="$WARM_DIR/hostapd"; CONF="$HOSTAPD_DIR/hostapd-wlan0.conf"
  IFACE="wlan0"; BASE_SSID="HP-WARM"; BASE_SEC="wpa_passphrase=testpass1234"; COUNTRY_LINES=""
  radio_id="aa:bb:cc:dd:ee:ff"; cc="RO"; LEARN_NOW="2026-07-16T01:00:00Z"
  MODEL='{"schema":1,"iface":"wlan0","fw_id":"x","entries":[],"updated_at":"2026-07-16T01:00:00Z"}'
  attempts_json=""; chosen="5GHz-HT40-ch36"; chosen_band="5"; chosen_ch="36"
  SETTLE=0; SETTLE_5GHZ_WARM=0
  export TEST_HOSTAPD_ACTIVE=1 TEST_NO_DMESG=1
  export TEST_UPTIME_SECONDS=999
  # requested ch40/80MHz for the warm re-attempt, but the radio never converged — still on 36/40, on
  # EVERY attempt of the D46 bounded retry loop (the ground-truth "never holds this run" case).
  export TEST_IW_INFO=$'channel 36 (5180 MHz), width: 40 MHz, center1: 5180 MHz'
  attempt_warm_upgrade "5GHz-VHT80-ch40" "5" "40" "80"
  RC=$?
  { echo "RC=$RC CHOSEN=$chosen CHOSEN_BAND=$chosen_band CHOSEN_CH=$chosen_ch"; echo "ATTEMPTS=$attempts_json"; } > "$WARM_DIR/result_fail.txt"
  grep -q "channel=36" "$CONF" && echo "CONF_CH=36" >> "$WARM_DIR/result_fail.txt" || echo "CONF_CH=?" >> "$WARM_DIR/result_fail.txt"
)
RESULT_FAIL="$(cat "$WARM_DIR/result_fail.txt" 2>/dev/null)"
check '[[ "$RESULT_FAIL" == *"RC=1"* ]]' \
  "attempt_warm_upgrade returns non-zero (revert) when EVERY warm re-attempt fails to converge" "got: $RESULT_FAIL"
check '[[ "$RESULT_FAIL" == *"CHOSEN=5GHz-HT40-ch36"* ]] && [[ "$RESULT_FAIL" == *"CHOSEN_BAND=5"* ]] && [[ "$RESULT_FAIL" == *"CHOSEN_CH=36"* ]]' \
  "attempt_warm_upgrade leaves chosen/chosen_band/chosen_ch UNCHANGED (still HT40-ch36) on a miss" "got: $RESULT_FAIL"
check '[[ "$RESULT_FAIL" == *"CONF_CH=36"* ]]' \
  "attempt_warm_upgrade REVERTS the rendered+running conf back to the proven ch36 rung — AP never left on the failed ch40 attempt" "got: $RESULT_FAIL"
check '[[ "$RESULT_FAIL" == *"\"warm_upgrade\":true"* ]]' \
  "attempt_warm_upgrade still records the FAILED warm attempts (so the model learns VHT80 is not-yet-holding warm, without thrashing)" "got: $RESULT_FAIL"
check '(echo "$RESULT_FAIL" | grep -o "\"warm_upgrade\":true" | wc -l | grep -qx "$WARM_MAX_ATTEMPTS")' \
  "attempt_warm_upgrade spends the FULL bounded retry budget ($WARM_MAX_ATTEMPTS attempts) before reverting — not a single shot, not unbounded" \
  "got: $RESULT_FAIL (WARM_MAX_ATTEMPTS=$WARM_MAX_ATTEMPTS)"

# --- attempt_warm_upgrade: D46 bounded retry loop — first 2 attempts fail, 3rd CONVERGES ----------
# The ground-truth-proven case a single-shot design cannot handle: one settle window isn't quite
# enough, but a later retry within the SAME bounded budget succeeds.
# shellcheck disable=SC2034,SC2317
# (SC2034: IFACE/BASE_SSID/BASE_SEC/COUNTRY_LINES are read via dynamic scoping by
# attempt_warm_upgrade/render_rung, exactly like the earlier WARM_DIR blocks' own disable comment.
# SC2317: the `observe_rung` override below is NOT unreachable — shellcheck's static analysis can't
# see that `attempt_warm_upgrade` (defined in the sourced wifi-calibrate.sh) calls it dynamically;
# this override is exactly how bash lets a test replace a sourced function for one subshell.)
(
  HOSTAPD_DIR="$WARM_DIR/hostapd"; CONF="$HOSTAPD_DIR/hostapd-wlan0.conf"
  IFACE="wlan0"; BASE_SSID="HP-WARM"; BASE_SEC="wpa_passphrase=testpass1234"; COUNTRY_LINES=""
  radio_id="aa:bb:cc:dd:ee:ff"; cc="RO"; LEARN_NOW="2026-07-17T00:00:00Z"
  MODEL='{"schema":1,"iface":"wlan0","fw_id":"x","entries":[],"updated_at":"2026-07-17T00:00:00Z"}'
  attempts_json=""; chosen="5GHz-HT40-ch36"; chosen_band="5"; chosen_ch="36"
  SETTLE=0; SETTLE_5GHZ_WARM=0
  export TEST_HOSTAPD_ACTIVE=1 TEST_NO_DMESG=1
  export TEST_UPTIME_SECONDS=999
  # Override observe_rung with a stateful fake: the first 2 calls report the STILL-cold ch36/40
  # (not converged), the 3rd (and any later) call reports the requested ch40/80 (converged) — bash
  # function overrides are ordinary dynamic scoping, exactly like every other main()-local override
  # in this harness.
  RETRY_COUNTER_FILE="$WARM_DIR/retry_counter"
  echo 0 > "$RETRY_COUNTER_FILE"
  observe_rung() {
    local n; n=$(cat "$RETRY_COUNTER_FILE"); n=$((n + 1)); echo "$n" > "$RETRY_COUNTER_FILE"
    if [ "$n" -ge 3 ]; then
      echo "40 80 0"; return 0
    else
      echo "36 40 0"; return 1
    fi
  }
  attempt_warm_upgrade "5GHz-VHT80-ch40" "5" "40" "80"
  RC=$?
  { echo "RC=$RC CHOSEN=$chosen CHOSEN_CH=$chosen_ch ATTEMPTS_MADE=$(cat "$RETRY_COUNTER_FILE")"; echo "ATTEMPTS=$attempts_json"; } > "$WARM_DIR/result_retry.txt"
)
RESULT_RETRY="$(cat "$WARM_DIR/result_retry.txt" 2>/dev/null)"
check '[[ "$RESULT_RETRY" == *"RC=0"* ]]' \
  "attempt_warm_upgrade: 2 failed attempts then a 3rd that converges still COMMITS (RC=0) — the whole point of a bounded retry loop, not a single shot" \
  "got: $RESULT_RETRY"
check '[[ "$RESULT_RETRY" == *"CHOSEN=5GHz-VHT80-ch40"* ]] && [[ "$RESULT_RETRY" == *"CHOSEN_CH=40"* ]]' \
  "attempt_warm_upgrade commits after the LATE-converging attempt" "got: $RESULT_RETRY"
check '[[ "$RESULT_RETRY" == *"ATTEMPTS_MADE=3"* ]]' \
  "attempt_warm_upgrade made exactly 3 attempts (stopped as soon as it converged, did not over-retry)" "got: $RESULT_RETRY"
check '[[ "$RESULT_RETRY" == *"\"warm_attempt\":0"* ]] && [[ "$RESULT_RETRY" == *"\"warm_attempt\":1"* ]] && [[ "$RESULT_RETRY" == *"\"warm_attempt\":2"* ]]' \
  "attempt_warm_upgrade's attempts_json records EVERY attempt (0, 1, 2) with an incrementing warm_attempt index" "got: $RESULT_RETRY"

# --- D46: the min-uptime gate actually WAITS when the radio is not yet warm enough ---------------
# A tiny WARM_MIN_UPTIME_SECONDS + a real (short, bounded) sleep proves `read_uptime_seconds`/
# `warm_upgrade_ready` are wired into `attempt_warm_upgrade`'s actual control flow, not just unit
# tested in isolation — the real `sleep` call fires (kept short: 1s) rather than mocked away.
# shellcheck disable=SC2034
# (IFACE/BASE_SSID/BASE_SEC/COUNTRY_LINES/SETTLE_5GHZ_WARM/WARM_MIN_UPTIME_SECONDS are read via
# dynamic scoping by attempt_warm_upgrade/render_rung — see the earlier WARM_DIR blocks' own
# identical disable comment.)
(
  HOSTAPD_DIR="$WARM_DIR/hostapd"; CONF="$HOSTAPD_DIR/hostapd-wlan0.conf"
  IFACE="wlan0"; BASE_SSID="HP-WARM"; BASE_SEC="wpa_passphrase=testpass1234"; COUNTRY_LINES=""
  radio_id="aa:bb:cc:dd:ee:ff"; cc="RO"; LEARN_NOW="2026-07-17T01:00:00Z"
  MODEL='{"schema":1,"iface":"wlan0","fw_id":"x","entries":[],"updated_at":"2026-07-17T01:00:00Z"}'
  attempts_json=""; chosen="5GHz-HT40-ch36"; chosen_band="5"; chosen_ch="36"
  SETTLE=0; SETTLE_5GHZ_WARM=0
  WARM_MIN_UPTIME_SECONDS=1
  export TEST_HOSTAPD_ACTIVE=1 TEST_NO_DMESG=1
  export TEST_UPTIME_SECONDS=0   # "just booted" — below the (tiny, test-only) 1s threshold
  export TEST_IW_INFO=$'channel 40 (5200 MHz), width: 80 MHz, center1: 5210 MHz'
  START=$(date +%s)
  attempt_warm_upgrade "5GHz-VHT80-ch40" "5" "40" "80" >/dev/null
  END=$(date +%s)
  echo "ELAPSED=$((END - START))" > "$WARM_DIR/result_wait.txt"
)
RESULT_WAIT="$(cat "$WARM_DIR/result_wait.txt" 2>/dev/null)"
check '[[ "$RESULT_WAIT" =~ ELAPSED=[1-9] ]]' \
  "attempt_warm_upgrade actually SLEEPS the remainder when uptime is below WARM_MIN_UPTIME_SECONDS (D46 min-uptime gate is wired in, not decorative)" \
  "got: $RESULT_WAIT"

# The VHT80 rung MUST use [HT40-] (control ch40 is the block's upper secondary) — this is the
# entire fix: [HT40+] on ch40 is what does NOT hold on brcmfmac.
check '[[ "$VHT80_LINES" == *"ht_capab=[HT40-]"* ]]' \
  "VHT80_LINES uses ht_capab=[HT40-] for control ch40" "VHT80_LINES: $VHT80_LINES"
check '[[ "$VHT80_LINES" != *"[HT40+]"* ]]' \
  "VHT80_LINES must NOT use [HT40+] (that's the bug being fixed)" "VHT80_LINES: $VHT80_LINES"
check '[[ "$VHT80_LINES" == *"vht_oper_centr_freq_seg0_idx=42"* ]]' \
  "VHT80_LINES centers the 36-48 block on seg0=42" "VHT80_LINES: $VHT80_LINES"
check '[[ "$HT40_LINES" == *"ht_capab=[HT40+]"* ]]' \
  "HT40_LINES uses ht_capab=[HT40+] for control ch36 (lower primary)" "HT40_LINES: $HT40_LINES"

# --- 2026-07-15 DFS-AWARE SETTLE: channel_footprint / dfs_cac_seconds / select_settle -----------
check '[ "$(dfs_cac_seconds 40 80)" = 0 ]' "dfs_cac_seconds(ch40,80) = 0 — the shipped VHT80 rung is non-DFS" \
  "got: $(dfs_cac_seconds 40 80)"
check '[ "$(dfs_cac_seconds 36 40)" = 0 ]' "dfs_cac_seconds(ch36,40) = 0 — the shipped HT40 rung is non-DFS" \
  "got: $(dfs_cac_seconds 36 40)"
check '[ "$(dfs_cac_seconds 52 20)" = 60 ]' "dfs_cac_seconds(ch52,20) = 60 — a standard DFS channel" \
  "got: $(dfs_cac_seconds 52 20)"
check '[ "$(dfs_cac_seconds 132 80)" = 60 ]' "dfs_cac_seconds(ch132,80) = 60 — the 132-144 block has no meteo overlap" \
  "got: $(dfs_cac_seconds 132 80)"
check '[ "$(dfs_cac_seconds 120 20)" = 600 ]' "dfs_cac_seconds(ch120,20) = 600 — inside the meteo sub-band" \
  "got: $(dfs_cac_seconds 120 20)"
check '[ "$(dfs_cac_seconds 116 40)" = 600 ]' \
  "dfs_cac_seconds(ch116,40) = 600 — ch116 alone is standard-DFS, but its HT40 pair (116,120) touches the meteo sub-band" \
  "got: $(dfs_cac_seconds 116 40)"
check '[ "$(dfs_cac_seconds 116 80)" = 600 ]' \
  "dfs_cac_seconds(ch116,80) = 600 — the VHT80 block 116-128 fully overlaps the meteo sub-band" \
  "got: $(dfs_cac_seconds 116 80)"

check '[ "$(select_settle 5 40 80)" = "$SETTLE_5GHZ" ]' \
  "select_settle picks the ordinary settle for the shipped non-DFS VHT80-ch40 rung" \
  "got: $(select_settle 5 40 80), expected \$SETTLE_5GHZ=$SETTLE_5GHZ"
check '[ "$(select_settle 5 36 40)" = "$SETTLE_5GHZ" ]' \
  "select_settle picks the ordinary settle for the shipped non-DFS HT40-ch36 rung" \
  "got: $(select_settle 5 36 40)"
check '[ "$(select_settle 2.4 6 20)" = "$SETTLE" ]' \
  "select_settle picks the ordinary settle for the 2.4GHz floor (never DFS)" \
  "got: $(select_settle 2.4 6 20)"
check '[ "$(select_settle 5 52 20)" = "$SETTLE_DFS_STANDARD" ]' \
  "select_settle picks the ~75s DFS-standard settle for a standard DFS channel (ch52)" \
  "got: $(select_settle 5 52 20), expected \$SETTLE_DFS_STANDARD=$SETTLE_DFS_STANDARD"
check '[ "$(select_settle 5 120 20)" = "$SETTLE_DFS_METEO" ]' \
  "select_settle picks the ~660s DFS-meteo settle for the meteorological sub-band (ch120) — a 75s settle would wrongly fail it" \
  "got: $(select_settle 5 120 20), expected \$SETTLE_DFS_METEO=$SETTLE_DFS_METEO"

# --- DFS-CAC-in-progress must never be misclassified as a chanspec-fail storm -------------------
# During a DFS CAC the radio has not yet converged to the requested (DFS) channel/width, but the
# kernel log lines produced during that transition are NOT the brcmfmac "set chanspec … fail"
# signature this loop's fail-storm detector greps for — so observe_rung must report fails=0 (no
# false fail-storm) even while a DFS rung is still mid-CAC, exactly like an ordinary quiet dmesg.
cat > "$FAKE_BIN/dmesg" <<'EOS'
#!/usr/bin/env bash
if [ "${1:-}" = "-C" ]; then exit 0; fi
printf 'IEEE 802.11: AP mode driver-based DFS enabled\n'
printf 'brcmfmac: CAC in progress for channel 52\n'
EOS
mark_dmesg
TEST_IW_INFO=$(iw_line 6 20); export TEST_IW_INFO   # radio still parked on ch6 while ch52's CAC runs
export TEST_HOSTAPD_ACTIVE=1
OUT=$(PATH="$FAKE_BIN:$PATH" observe_rung 52 20); RC=$?
if echo "$OUT" | grep -qE '^6 20 0$'; then
  ok "DFS-CAC-in-progress dmesg lines do NOT match the chanspec-fail signature — fails=0: '$OUT'"
else
  bad "DFS-CAC transition lines were misclassified as chanspec-fail lines: '$OUT'"
fi
check '[ "$RC" -eq 1 ]' "not-yet-converged during a simulated DFS CAC is WidthCollapsed, NOT a fail-storm (rc=1, not rc=2): rc=$RC" \
  "expected rc=1 (WidthCollapsed, no fail-storm misclassification), got rc=$RC"
unset TEST_IW_INFO TEST_HOSTAPD_ACTIVE

# --- D19: band-LKG round trip (write → read back → valid only for the SAME cc+radio) -----------
LKG_FILE="$TMP/wifi-band-lkg-wlan0.json"
write_band_lkg "$LKG_FILE" "RO" "aa:bb:cc:dd:ee:ff" 5 "5GHz-HT40-ch36" 36
check '[ -r "$LKG_FILE" ]' "write_band_lkg created $LKG_FILE" "write_band_lkg did not create the file"

GOT=$(read_band_lkg_label "$LKG_FILE" "RO" "aa:bb:cc:dd:ee:ff")
check '[ "$GOT" = "5GHz-HT40-ch36" ]' "read_band_lkg_label returns the cached label for the SAME cc+radio: $GOT" \
  "expected 5GHz-HT40-ch36, got: $GOT"

GOT_CI=$(read_band_lkg_label "$LKG_FILE" "ro" "aa:bb:cc:dd:ee:ff")
check '[ "$GOT_CI" = "5GHz-HT40-ch36" ]' "read_band_lkg_label's cc compare is case-insensitive" "got: $GOT_CI"

GOT_WRONG_CC=$(read_band_lkg_label "$LKG_FILE" "GB" "aa:bb:cc:dd:ee:ff")
check '[ -z "$GOT_WRONG_CC" ]' "read_band_lkg_label INVALIDATES on a regdomain change (RO cached, now GB)" \
  "expected empty (invalid), got: $GOT_WRONG_CC"

GOT_WRONG_RADIO=$(read_band_lkg_label "$LKG_FILE" "RO" "11:22:33:44:55:66")
check '[ -z "$GOT_WRONG_RADIO" ]' "read_band_lkg_label INVALIDATES on a swapped radio (different MAC)" \
  "expected empty (invalid), got: $GOT_WRONG_RADIO"

GOT_MISSING=$(read_band_lkg_label "$TMP/does-not-exist.json" "RO" "aa:bb:cc:dd:ee:ff")
check '[ -z "$GOT_MISSING" ]' "read_band_lkg_label on a missing file returns empty (first-boot case)" \
  "expected empty, got: $GOT_MISSING"

# --- D19: radio_fingerprint — reads the iface MAC when present, degrades to "unknown" otherwise -
# radio_fingerprint reads /sys/class/net/<iface>/address directly, which cannot be faked without
# root/netns; prove the "no such iface" degrade path (the common CI case) and independently prove
# the real sysfs-read branch via `lo`, which is always present and readable unprivileged.
GOT_UNKNOWN=$(radio_fingerprint "hp-definitely-not-a-real-iface-xyz")
check '[ "$GOT_UNKNOWN" = unknown ]' "radio_fingerprint degrades to 'unknown' for a non-existent iface" \
  "expected 'unknown', got: $GOT_UNKNOWN"
if [ -d /sys/class/net/lo ]; then
  GOT_LO=$(radio_fingerprint lo)
  check '[ -n "$GOT_LO" ]' "radio_fingerprint(lo) reads a real sysfs address on this box: $GOT_LO" \
    "radio_fingerprint(lo) returned empty"
fi

# =============================================================================================
# Part — D45/D46 (2026-07-17): read_uptime_seconds / warm_upgrade_ready — the min-uptime gate's
# pure building blocks, mirroring `wifi_calibrate::warm_upgrade_ready` exactly.
# =============================================================================================
check '[ "$(TEST_UPTIME_SECONDS=42 read_uptime_seconds)" = 42 ]' \
  "read_uptime_seconds honours the TEST_UPTIME_SECONDS override" \
  "got: $(TEST_UPTIME_SECONDS=42 read_uptime_seconds)"
check '[ -r /proc/uptime ] && [ "$(read_uptime_seconds)" -ge 0 ]' \
  "read_uptime_seconds reads a real non-negative value from /proc/uptime on this box" \
  "got: $(read_uptime_seconds)"

check 'warm_upgrade_ready 150 150' "warm_upgrade_ready(150,150) — exactly at the threshold is ready" "not ready at exactly the threshold"
check 'warm_upgrade_ready 200 150' "warm_upgrade_ready(200,150) — past the threshold is ready" "not ready past the threshold"
check '! warm_upgrade_ready 149 150' "warm_upgrade_ready(149,150) — one second short is NOT ready" "wrongly ready one second short"
check '! warm_upgrade_ready 0 150' "warm_upgrade_ready(0,150) — freshly booted is NOT ready" "wrongly ready at uptime=0"

# rung_label_for_channel_width — the reverse lookup resolve_warm_target needs.
build_ladder auto
check '[ "$(rung_label_for_channel_width 40 80)" = "5GHz-VHT80-ch40" ]' \
  "rung_label_for_channel_width(40,80) finds the VHT80-ch40 label" "got: $(rung_label_for_channel_width 40 80)"
check '[ "$(rung_label_for_channel_width 36 40)" = "5GHz-HT40-ch36" ]' \
  "rung_label_for_channel_width(36,40) finds the HT40-ch36 label" "got: $(rung_label_for_channel_width 36 40)"
check '! rung_label_for_channel_width 149 80 >/dev/null 2>&1' \
  "rung_label_for_channel_width degrades safely (rc!=0, no output) for a channel/width not in this ladder" \
  "wrongly found a label for an out-of-ladder (channel,width)"

# =============================================================================================
# Part — ADR 0034 D35-D44: the Wi-Fi calibration LEARNING MODEL (learn_* jq-backed functions).
# Skipped gracefully (documented, not a silent pass) when `jq` is unavailable on the test box —
# every learn_* function already degrades the same way in production.
# =============================================================================================
if command -v jq >/dev/null 2>&1; then
  LEARN_TMP="$TMP/wifi-learn-wlan0.json"

  M0=$(learn_load "$TMP/does-not-exist-learn.json" wlan0 fw1 2026-07-15T00:00:00Z)
  check '[ "$(echo "$M0" | jq -r ".schema")" = 1 ] && [ "$(echo "$M0" | jq -r ".entries | length")" = 0 ]' \
    "learn_load: a missing file yields a fresh empty schema-1 store" "got: $M0"

  M1=$(learn_record "$M0" r1 RO 40 80 stable 2026-07-15T00:00:00Z)
  check '[ "$(echo "$M1" | jq -r ".entries[0].successes")" = 1 ] && [ "$(echo "$M1" | jq -r ".entries[0].failures")" = 0 ]' \
    "learn_record: a stable verdict creates a cell with successes=1,failures=0" "got: $(echo "$M1" | jq -c .entries)"

  M2=$(learn_record "$M1" r1 RO 40 80 width_collapsed 2026-07-15T01:00:00Z)
  check '[ "$(echo "$M2" | jq -r ".entries[0].successes")" = 1 ] && [ "$(echo "$M2" | jq -r ".entries[0].failures")" = 1 ] && [ "$(echo "$M2" | jq -r ".entries | length")" = 1 ]' \
    "learn_record: a SECOND verdict on the SAME key updates the SAME cell (not a new one)" "got: $(echo "$M2" | jq -c .entries)"

  M3=$(learn_record "$M2" r1 RO 36 40 stable 2026-07-15T01:00:00Z)
  check '[ "$(echo "$M3" | jq -r ".entries | length")" = 2 ]' \
    "learn_record: a DIFFERENT (channel,width) key creates a second, independent cell" "got: $(echo "$M3" | jq -c .entries)"

  # plan_boot / the boot-time consult — after 1 Stable, decide-ResumeAtRung; a known-bad key never wins.
  LEGAL='[[40,80],[36,40],[6,20]]'
  DECISION=$(learn_plan_boot "$M3" RO r1 "$LEGAL" shadow 2026-07-15T01:00:00Z)
  check '[ "$DECISION" = "resume_at_rung 5GHz-VHT80-ch40" ]' \
    "learn_plan_boot: winner with >=1 Stable observation => resume_at_rung" "got: $DECISION"

  # D44 SHIP-IN-SHADOW: 3 clean holds would clear the DirectToBest gate in Active mode, but the
  # SHIPPED $WIFI_LEARN_MODE default (shadow) must still print resume_at_rung, never direct_to_best.
  MDIRECT="$M1"
  MDIRECT=$(learn_record "$MDIRECT" r1 RO 40 80 stable 2026-07-15T02:00:00Z)
  MDIRECT=$(learn_record "$MDIRECT" r1 RO 40 80 stable 2026-07-15T03:00:00Z)
  check '[ "$(echo "$MDIRECT" | jq -r ".entries[0].successes")" = 3 ]' \
    "learn setup: 3 clean holds recorded (precondition for the D44 shadow-mode assertion)" "got: $(echo "$MDIRECT" | jq -r '.entries[0].successes')"
  DEC_SHADOW=$(learn_plan_boot "$MDIRECT" RO r1 '[[40,80]]' "$WIFI_LEARN_MODE" 2026-07-15T03:00:00Z)
  check '[ "$WIFI_LEARN_MODE" = shadow ]' "D44: the shipped WIFI_LEARN_MODE default is 'shadow'" "got: $WIFI_LEARN_MODE"
  check '[ "$DEC_SHADOW" = "resume_at_rung 5GHz-VHT80-ch40" ]' \
    "D44 shadow mode: a DirectToBest-eligible winner is printed as resume_at_rung, NEVER direct_to_best" "got: $DEC_SHADOW"
  DEC_ACTIVE=$(learn_plan_boot "$MDIRECT" RO r1 '[[40,80]]' active 2026-07-15T03:00:00Z)
  check '[ "$DEC_ACTIVE" = "direct_to_best 5GHz-VHT80-ch40" ]' \
    "learn_plan_boot: the SAME model, in active mode, DOES return direct_to_best (the flag is a single one-line flip)" "got: $DEC_ACTIVE"

  # never-repeat-known-bad: 5 straight failures on ch36/HT40 => excluded from the legal set entirely.
  MBAD=$(learn_load "$TMP/does-not-exist-learn2.json" wlan0 fw1 2026-07-15T00:00:00Z)
  for d in 1 2 3 4 5; do
    MBAD=$(learn_record "$MBAD" r1 RO 36 40 width_collapsed "2026-07-1${d}T00:00:00Z")
  done
  DEC_BAD=$(learn_plan_boot "$MBAD" RO r1 '[[36,40]]' shadow 2026-07-16T00:00:00Z)
  check '[ "$DEC_BAD" = ladder ]' \
    "learn_plan_boot: a confidently known-bad winner is EXCLUDED — degrades to ladder, never re-selected" "got: $DEC_BAD"

  # always-joinable: the model's favourite (ch40) is NOT in this boot's legal set => the model must
  # fall to the next-best LEGAL entry (ch36), never select the excluded, higher-quality ch40.
  DEC_ILLEGAL=$(learn_plan_boot "$M3" RO r1 '[[36,40]]' shadow 2026-07-15T01:00:00Z)
  check '[ "$DEC_ILLEGAL" = "resume_at_rung 5GHz-HT40-ch36" ]' \
    "learn_plan_boot: never selects a (channel,width) outside the caller-supplied legal set" "got: $DEC_ILLEGAL"
  DEC_NOTHING_LEGAL=$(learn_plan_boot "$M3" RO r1 '[[149,80]]' shadow 2026-07-15T01:00:00Z)
  check '[ "$DEC_NOTHING_LEGAL" = ladder ]' \
    "learn_plan_boot: an entirely-illegal legal-set degrades cleanly to ladder (always-joinable)" "got: $DEC_NOTHING_LEGAL"

  # age_model: aging over a half-life shrinks the counts (still non-negative) and stamps updated_at.
  AGED=$(learn_age "$M3" fw1 2026-08-05T01:00:00Z)
  check '[ "$(echo "$AGED" | jq -r ".updated_at")" = "2026-08-05T01:00:00Z" ]' \
    "learn_age: stamps updated_at to the real wall-clock now" "got: $(echo "$AGED" | jq -r '.updated_at')"
  check '(echo "$AGED" | jq -e ".entries[0].successes < 1" >/dev/null)' \
    "learn_age: a stale cell's successes decay below their pre-aging value" "got: $(echo "$AGED" | jq -c '.entries[0]')"

  # LKG export FROM the model — round-trips into the SAME shape read_band_lkg_label already parses.
  learn_export_band_lkg "$M3" RO r1 "$LEGAL" 2026-07-15T01:00:00Z "$LEARN_TMP"
  check '[ -r "$LEARN_TMP" ]' "learn_export_band_lkg: writes a band-LKG file when a proven winner exists" "no file written"
  EXPORT_LABEL=$(read_band_lkg_label "$LEARN_TMP" RO r1)
  check '[ "$EXPORT_LABEL" = "5GHz-VHT80-ch40" ]' \
    "learn_export_band_lkg: the export round-trips through the UNCHANGED read_band_lkg_label reader" "got: $EXPORT_LABEL"

  # Persist + reload round-trip.
  learn_save "$M3" "$LEARN_TMP.store"
  RELOADED=$(learn_load "$LEARN_TMP.store" wlan0 fw1 2026-07-15T02:00:00Z)
  check '[ "$(echo "$RELOADED" | jq -r ".entries | length")" = "$(echo "$M3" | jq -r ".entries | length")" ]' \
    "learn_save/learn_load: the store round-trips through disk" "saved=$(echo "$M3" | jq -c .entries) reloaded=$(echo "$RELOADED" | jq -c .entries)"

  # ===========================================================================================
  # Part — D45/D46 (2026-07-17, metal-diagnosed): warm-vs-cold learning context.
  # Ground truth: a COLD attempt at VHT80-ch40 chanspec-fail-storms; a genuinely WARM one holds
  # rock-solid. Before this fix both folded into ONE cell and the model would learn to AVOID ch40
  # forever. `warm` (learn_record's 9th arg) is the fix: cold and warm are now INDEPENDENT cells.
  # ===========================================================================================

  # learn_record with warm=true creates a SEPARATE cell from the (channel,width)-identical cold one.
  MW0=$(learn_load "$TMP/does-not-exist-learn-warm.json" wlan0 fw1 2026-07-17T00:00:00Z)
  MW1=$(learn_record "$MW0" r1 RO 40 80 chanspec_fail_storm 2026-07-17T00:00:00Z "" false)
  MW2=$(learn_record "$MW1" r1 RO 40 80 stable 2026-07-17T00:01:00Z "" true)
  check '[ "$(echo "$MW2" | jq -r ".entries | length")" = 2 ]' \
    "learn_record: warm=true and warm=false for the IDENTICAL (channel,width) create TWO independent cells" \
    "got: $(echo "$MW2" | jq -c .entries)"
  MW_COLD=$(echo "$MW2" | jq -c '.entries[] | select((.key.warm // false) == false)')
  MW_WARM=$(echo "$MW2" | jq -c '.entries[] | select(.key.warm == true)')
  check '[ "$(echo "$MW_COLD" | jq -r .failures)" = 1 ] && [ "$(echo "$MW_COLD" | jq -r .successes)" = 0 ]' \
    "learn_record: the COLD cell recorded its own chanspec_fail_storm failure" "got: $MW_COLD"
  check '[ "$(echo "$MW_WARM" | jq -r .successes)" = 1 ] && [ "$(echo "$MW_WARM" | jq -r .failures)" = 0 ]' \
    "learn_record: the WARM cell recorded its own stable success — UNPOISONED by the cold failure" "got: $MW_WARM"

  # A THIRD, later cold observation only ever updates the COLD cell — still exactly 2 entries.
  MW3=$(learn_record "$MW2" r1 RO 40 80 chanspec_fail_storm 2026-07-17T00:02:00Z "" false)
  check '[ "$(echo "$MW3" | jq -r ".entries | length")" = 2 ]' \
    "learn_record: a further cold observation updates the EXISTING cold cell, never creates a third" \
    "got: $(echo "$MW3" | jq -c .entries)"
  check '[ "$(echo "$MW3" | jq -c ".entries[] | select((.key.warm // false)==false) | .failures")" = 2 ]' \
    "learn_record: the cold cell now has 2 failures; the warm cell (checked next) is untouched" \
    "got: $(echo "$MW3" | jq -c .entries)"
  check '[ "$(echo "$MW3" | jq -c ".entries[] | select(.key.warm==true) | .successes")" = 1 ]' \
    "learn_record: the warm cell's success count is STILL 1 — the later cold failure never poisoned it" \
    "got: $(echo "$MW3" | jq -c .entries)"

  # learn_plan_boot is COLD-CONTEXT ONLY: even with 5 clean WARM holds for ch40/80 and zero cold
  # data, it must resume at the best COLD winner (ch36/40), never the warm-only ch40.
  MWCOLDWIN=$(learn_load "$TMP/does-not-exist-learn-warm2.json" wlan0 fw1 2026-07-17T00:00:00Z)
  for d in 1 2 3 4 5; do
    MWCOLDWIN=$(learn_record "$MWCOLDWIN" r1 RO 40 80 stable "2026-07-1${d}T00:00:00Z" "" true)
  done
  MWCOLDWIN=$(learn_record "$MWCOLDWIN" r1 RO 36 40 stable 2026-07-17T00:00:00Z "" false)
  DEC_WARM_ONLY=$(learn_plan_boot "$MWCOLDWIN" RO r1 "$LEGAL" shadow 2026-07-17T00:00:00Z)
  check '[ "$DEC_WARM_ONLY" = "resume_at_rung 5GHz-HT40-ch36" ]' \
    "learn_plan_boot: strong warm-only evidence for ch40/80 must NOT win — resumes at the cold-proven ch36 instead" \
    "got: $DEC_WARM_ONLY"

  # learn_export_band_lkg is likewise cold-context only — must never point at the warm-only rung.
  LKG_WARM_TMP="$TMP/wifi-band-lkg-warmtest.json"
  learn_export_band_lkg "$MWCOLDWIN" RO r1 "$LEGAL" 2026-07-17T00:00:00Z "$LKG_WARM_TMP"
  EXPORT_LABEL_COLD=$(read_band_lkg_label "$LKG_WARM_TMP" RO r1)
  check '[ "$EXPORT_LABEL_COLD" = "5GHz-HT40-ch36" ]' \
    "learn_export_band_lkg: never exports a warm-only-proven rung as the resume-here cache" "got: $EXPORT_LABEL_COLD"

  # learn_plan_warm_upgrade: the model-informed warm target — argmax over WARM-context, strictly
  # WIDER-than-cold-chosen, legal, not-known-bad winners.
  TARGET=$(learn_plan_warm_upgrade "$MWCOLDWIN" RO r1 "$LEGAL" 40 2026-07-17T00:00:00Z)
  check '[ "$TARGET" = "40 80" ]' \
    "learn_plan_warm_upgrade: selects the proven-warm ch40/80 as the target (strictly wider than the cold-chosen 40MHz)" \
    "got: $TARGET"

  # ...but returns NOTHING when no warm evidence exists at all (pure-cold model) — the caller then
  # falls back to the static warm_upgrade_candidate ladder-adjacency rule (the bootstrap path).
  TARGET_NONE=$(learn_plan_warm_upgrade "$M3" RO r1 "$LEGAL" 40 2026-07-15T01:00:00Z)
  check '[ -z "$TARGET_NONE" ]' \
    "learn_plan_warm_upgrade: an entirely-cold model yields NO target (bootstrap falls back to the static candidate)" \
    "got: '$TARGET_NONE'"

  # ...and never proposes something at (or narrower than) the cold-chosen width — an upgrade only.
  TARGET_SIDEWAYS=$(learn_plan_warm_upgrade "$MWCOLDWIN" RO r1 "$LEGAL" 80 2026-07-17T00:00:00Z)
  check '[ -z "$TARGET_SIDEWAYS" ]' \
    "learn_plan_warm_upgrade: nothing wider than an already-80MHz cold-chosen rung exists in this ladder — correctly empty" \
    "got: '$TARGET_SIDEWAYS'"

  # resolve_warm_target: prefers the model-informed pick over the static fallback when one exists.
  # shellcheck disable=SC2034
  # (MODEL/cc/radio_id/LEARN_NOW/LEGAL_JSON/chosen_mhz are read via dynamic scoping by
  # resolve_warm_target/learn_plan_warm_upgrade, exactly like every other main()-local variable this
  # harness feeds a sourced function through plain (non-exported) assignment.)
  (
    MODEL="$MWCOLDWIN"; cc=RO; radio_id=r1; LEARN_NOW=2026-07-17T00:00:00Z; LEGAL_JSON="$LEGAL"
    chosen_mhz=40
    RESOLVED=$(resolve_warm_target "5GHz-VHT80-ch40 5 40 80")
    echo "$RESOLVED" > "$TMP/resolve_warm_target_out.txt"
  )
  RESOLVED_TARGET=$(cat "$TMP/resolve_warm_target_out.txt")
  check '[ "$RESOLVED_TARGET" = "5GHz-VHT80-ch40 5 40 80" ]' \
    "resolve_warm_target: model-informed pick agrees with (and is echoed in) the static candidate's shape here" \
    "got: $RESOLVED_TARGET"

  # resolve_warm_target falls back to the STATIC candidate untouched when the model has nothing.
  # shellcheck disable=SC2034
  (
    MODEL="$M3"; cc=RO; radio_id=r1; LEARN_NOW=2026-07-15T01:00:00Z; LEGAL_JSON="$LEGAL"
    chosen_mhz=40
    RESOLVED=$(resolve_warm_target "5GHz-VHT80-ch40 5 40 80")
    echo "$RESOLVED" > "$TMP/resolve_warm_target_fallback.txt"
  )
  RESOLVED_FALLBACK=$(cat "$TMP/resolve_warm_target_fallback.txt")
  check '[ "$RESOLVED_FALLBACK" = "5GHz-VHT80-ch40 5 40 80" ]' \
    "resolve_warm_target: falls back to the static candidate byte-for-byte when the model has no warm evidence" \
    "got: $RESOLVED_FALLBACK"
else
  echo "  SKIP: learning-model (D35-D44 / D45-D46) checks — jq not available on this box"
fi

# =============================================================================================
# Part — full end-to-end: main() consults + records into the learning model (no radio needed)
# =============================================================================================
if command -v jq >/dev/null 2>&1; then
  E2E_DIR="$TMP/e2e"
  mkdir -p "$E2E_DIR/hostapd"
  (
    HOSTAPD_DIR="$E2E_DIR/hostapd"
    WIFI_STATUS="$E2E_DIR/wifi-calibration.json"
    WIFI_BAND_LKG_DIR="$E2E_DIR"
    WIFI_LEARN_DIR="$E2E_DIR"
    WIFI_COUNTRY_FILE="$E2E_DIR/wifi-country"
    export HOSTAPD_DIR WIFI_STATUS WIFI_BAND_LKG_DIR WIFI_LEARN_DIR WIFI_COUNTRY_FILE
    echo RO > "$WIFI_COUNTRY_FILE"
    export TEST_HOSTAPD_ACTIVE=1 TEST_NO_DMESG=1
    export TEST_IW_INFO=$'channel 40 (5200 MHz), width: 80 MHz, center1: 5210 MHz'
    export SETTLE=0 SETTLE_5GHZ=0 SETTLE_DFS_STANDARD=0 SETTLE_DFS_METEO=0
    main wlan0 >/dev/null 2>&1
    main wlan0 >"$E2E_DIR/boot2.log" 2>&1
  )
  check '[ -r "$E2E_DIR/wifi-learn-wlan0.json" ]' \
    "e2e: main() persists the learning-model store at wifi-learn-<iface>.json" "no store file"
  check '(jq -e ".entries | length >= 1" "$E2E_DIR/wifi-learn-wlan0.json" >/dev/null 2>&1)' \
    "e2e: the store has at least one recorded cell after two boots" "$(cat "$E2E_DIR/wifi-learn-wlan0.json" 2>/dev/null)"
  check 'grep -q "learning model: ResumeAtRung" "$E2E_DIR/boot2.log"' \
    "e2e: the SECOND boot consults the learning model and resumes directly (no cold re-fight)" \
    "$(cat "$E2E_DIR/boot2.log" 2>/dev/null)"
  check '[ -r "$E2E_DIR/wifi-band-lkg-wlan0.json" ] && grep -q "exported FROM the learning model" "$E2E_DIR/boot2.log"' \
    "e2e: the band-LKG file is a READ-ONLY EXPORT written FROM the model, not directly" \
    "$(cat "$E2E_DIR/boot2.log" 2>/dev/null)"

  # =============================================================================================
  # Part — THE ROOT-CAUSE-1 REGRESSION: main() must persist the learning model on EVERY exit path,
  # including a warm-upgrade REVERT (the exact bug: `attempt_warm_upgrade` used to be a bare command
  # under `set -e`, so its documented non-converge return-1 aborted main() BEFORE `learn_save` ran —
  # the model persisted `entries: []` EVERY boot and the box could never learn anything). This drives
  # main() end-to-end through: cold ladder settles at the NON-top rung (5GHz-HT40-ch36, since
  # TEST_IW_INFO never reports the VHT80-ch40 request as converged) -> warm-upgrade IS attempted
  # (chosen is not the top rung) -> every bounded warm-upgrade attempt ALSO fails to converge (same
  # fixed TEST_IW_INFO) -> attempt_warm_upgrade returns 1 (revert) -> main() must NOT abort here.
  # =============================================================================================
  E2E2_DIR="$TMP/e2e-revert"
  mkdir -p "$E2E2_DIR/hostapd"
  (
    HOSTAPD_DIR="$E2E2_DIR/hostapd"
    WIFI_STATUS="$E2E2_DIR/wifi-calibration.json"
    WIFI_BAND_LKG_DIR="$E2E2_DIR"
    WIFI_LEARN_DIR="$E2E2_DIR"
    WIFI_COUNTRY_FILE="$E2E2_DIR/wifi-country"
    export HOSTAPD_DIR WIFI_STATUS WIFI_BAND_LKG_DIR WIFI_LEARN_DIR WIFI_COUNTRY_FILE
    echo RO > "$WIFI_COUNTRY_FILE"
    export TEST_HOSTAPD_ACTIVE=1 TEST_NO_DMESG=1
    # ALWAYS reports 36/40 — the VHT80-ch40 rung (cold ladder AND every warm-upgrade attempt) never
    # converges; the ladder settles at 5GHz-HT40-ch36 and the warm-upgrade exhausts its retry budget.
    export TEST_IW_INFO=$'channel 36 (5180 MHz), width: 40 MHz, center1: 5180 MHz'
    export TEST_UPTIME_SECONDS=999   # already "warm" — no real sleep in this test
    export SETTLE=0 SETTLE_5GHZ=0 SETTLE_5GHZ_WARM=0 SETTLE_DFS_STANDARD=0 SETTLE_DFS_METEO=0
    main wlan0 >"$E2E2_DIR/boot1.log" 2>&1
    echo "MAIN_EXIT=$?" >> "$E2E2_DIR/boot1.log"
  )
  check '[ -r "$E2E2_DIR/wifi-learn-wlan0.json" ]' \
    "root-cause-1 regression: main() STILL persists wifi-learn-<iface>.json even when the warm-upgrade REVERTS" \
    "no store file — this is EXACTLY the bug: entries:[] forever"
  check '(jq -e ".entries | length >= 1" "$E2E2_DIR/wifi-learn-wlan0.json" >/dev/null 2>&1)' \
    "root-cause-1 regression: the persisted store has recorded cell(s) — NOT the empty entries:[] symptom" \
    "$(cat "$E2E2_DIR/wifi-learn-wlan0.json" 2>/dev/null)"
  check '(jq -e "[.entries[] | select(.key.warm == true)] | length >= 1" "$E2E2_DIR/wifi-learn-wlan0.json" >/dev/null 2>&1)' \
    "root-cause-1 regression: the store also has at least one WARM-context cell recorded (the warm-upgrade attempts were folded in, not lost)" \
    "$(cat "$E2E2_DIR/wifi-learn-wlan0.json" 2>/dev/null)"
  check 'grep -q "MAIN_EXIT=0" "$E2E2_DIR/boot1.log"' \
    "root-cause-1 regression: main() exits 0 (never aborted by set -e on the warm-upgrade's documented revert)" \
    "$(cat "$E2E2_DIR/boot1.log" 2>/dev/null)"
  check 'grep -q "reverting to the already-proven" "$E2E2_DIR/boot1.log"' \
    "root-cause-1 regression: the warm-upgrade revert path actually fired in this run (proving the test drives the real scenario, not a no-op)" \
    "$(cat "$E2E2_DIR/boot1.log" 2>/dev/null)"
  check '[ -r "$E2E2_DIR/wifi-calibration.json" ] && jq -e ".chosen == \"5GHz-HT40-ch36\"" "$E2E2_DIR/wifi-calibration.json" >/dev/null 2>&1' \
    "root-cause-1 regression: the status artifact still gets written, AP ends on the proven ch36 rung (never left down)" \
    "$(cat "$E2E2_DIR/wifi-calibration.json" 2>/dev/null)"
else
  echo "  SKIP: end-to-end learning-model boot checks — jq not available on this box"
fi

echo
if [ "$FAIL" -eq 0 ]; then
  echo "=== test-wifi-calibrate: ALL CASES PASSED ==="
  exit 0
else
  echo "=== test-wifi-calibrate: FAILED -- see FAIL lines above ==="
  exit 1
fi
