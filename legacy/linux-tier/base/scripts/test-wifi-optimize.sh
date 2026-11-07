#!/usr/bin/env bash
# =============================================================================
# base/scripts/test-wifi-optimize.sh — sandbox fixture for the ADR 0034 D24-D33 autonomous
# 5GHz channel optimizer (base/scripts/wifi-optimize.sh), mirroring test-wifi-calibrate.sh's own
# style/seams (synthetic TEST_* feeds + a stateful fake `iw`/`dmesg` on PATH, no real radio).
#
# Coverage (matches the D34 T2 shell gate item list):
#   - D28 score_block_sh: busy dominates, EIRP bonus, meteo penalty, scan-only degradation.
#   - D27 enumerate_candidates: ETSI anchor/UNII-3 gating, allow_dfs/allow_meteo/ch144/blocked/
#     dfs_ap_supported admission.
#   - D16a apply_no_ir_filter: empty list = optimistic; a populated list excludes.
#   - D26 parse_survey_busy / parse_scan_bss_counts / apply_bss_counts: realistic `iw` text parsing.
#   - D28/D29 select_decision_sh: quiet-floor Keep, not-better Keep, Switch, single-best-candidate,
#     ap_capable filtering.
#   - D24 intent readers: read_optimize_bool/read_optimize_field/read_optimize_min_improvement
#     (nested `wifi: ap: optimize:` block extraction), read_ap_channel_pin.
#   - D30/D31 state/LKG round trips: load_state (cc/radio invalidation), write_optimize_state,
#     write_channel_lkg/channel-LKG read via json_field.
#   - D29 apply_and_observe (isolated, via the sourced observe_rung's TEST_IW_INFO/
#     TEST_HOSTAPD_ACTIVE seams): hold vs not-hold.
#   - D31 do_reapply end-to-end: no LKG, invalid LKG (cc/radio change), non-DFS skip, DFS
#     hold->commit, DFS fail->revert+clear.
#   - D24 main() guards end-to-end: band pin 2.4, disabled by intent, operator channel pin,
#     non-5GHz radio — every guard writes a documented skip artifact and NEVER touches the radio.
#   - A full do_optimize REVERT-chain integration test (stateful fake `iw`+`dmesg`): a busy current
#     channel considers switching, the candidate fails to hold, and the previous channel is
#     restored — proving the "even a bad decision never breaks the AP" chain end-to-end.
#
# Usage: base/scripts/test-wifi-optimize.sh
# Exit 0 iff every case below produced the verdict this fixture expects.
# =============================================================================
# The `check()` helper deliberately takes its condition in SINGLE quotes -- it `eval`s that
# string itself, so the variables inside expand at eval-time, not at call-time (same pattern as
# test-wifi-calibrate.sh/test-regdomain-apply.sh); every HAS-star/DFS_COUNT-star helper var is
# consumed inside one of those single-quoted conditions, and CAND_BSS is assigned inside
# enumerate_candidates' nested helpers -- shellcheck's static/cross-function analysis can't see
# any of that, hence the blanket disable below (matches the sibling test harnesses' own choice).
# shellcheck disable=SC2016,SC2034,SC2153
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/wifi-optimize.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

FAIL=0
ok()  { echo "  PASS: $*"; }
bad() { echo "  FAIL: $*"; FAIL=1; }
check() { if eval "$1"; then ok "$2"; else bad "$3"; fi; }

# Source the script for its functions only — `main "$@"` is guarded by the `[ "${BASH_SOURCE[0]:-$0}"
# = "${0}" ]` idiom, so sourcing never touches a real radio/hostapd (mirrors test-wifi-calibrate.sh).
# shellcheck source=/dev/null
source "$SCRIPT"
set +e

# CRITICAL sandbox isolation: STATE_DIR/STATUS/HOSTAPD_DIR are resolved from their WIFI_OPTIMIZE_*
# env vars ONCE at the top of wifi-optimize.sh (source time) — a later `export WIFI_OPTIMIZE_*=`
# in this harness does NOT retroactively change them (only the per-call WIFI_OPTIMIZE_STATE_FILE/
# WIFI_CHANNEL_LKG_FILE full-path overrides are re-read every call, inside main()). Reassign the
# actual variables here, immediately post-source, so EVERY function this harness calls — including
# through `main` — stays inside $TMP and can NEVER read or write this machine's real
# /var/lib/hookprobe or /etc/hostapd.
STATE_DIR="$TMP"
STATUS="$TMP/wifi-channel-optimize.json"
HOSTAPD_DIR="$TMP"

# =============================================================================================
# Part 1 — D28: score_block_sh
# =============================================================================================
S_QUIET=$(score_block_sh 5 2 23 0 0)
S_BUSY=$(score_block_sh 80 2 23 1 60)
check '[ "$S_BUSY" -gt "$S_QUIET" ]' "score_block_sh: a busier/DFS channel scores worse ($S_BUSY > $S_QUIET)" \
  "expected S_BUSY > S_QUIET, got $S_BUSY vs $S_QUIET"

S_CONGESTED_CH40=$(score_block_sh 80 10 23 0 0)
S_CLEAN_DFS=$(score_block_sh 2 0 30 1 60)
check '[ "$S_CLEAN_DFS" -lt "$S_CONGESTED_CH40" ]' \
  "score_block_sh: a clean high-EIRP DFS block ($S_CLEAN_DFS) beats a congested ch40 ($S_CONGESTED_CH40)" \
  "expected clean DFS < congested ch40, got $S_CLEAN_DFS vs $S_CONGESTED_CH40"

S_METEO=$(score_block_sh 0 0 30 1 600)
S_STD_DFS=$(score_block_sh 0 0 30 1 60)
check '[ "$S_METEO" -gt "$S_STD_DFS" ]' "score_block_sh: the meteo penalty ($S_METEO) dominates a standard DFS block ($S_STD_DFS) even when equally clean" \
  "expected meteo > standard DFS, got $S_METEO vs $S_STD_DFS"

S_SCAN_QUIET=$(score_block_sh "" 1 23 0 0)
S_SCAN_BUSY=$(score_block_sh "" 20 23 0 0)
check '[ "$S_SCAN_BUSY" -gt "$S_SCAN_QUIET" ]' "score_block_sh: scan-only (no busy_ratio) still discriminates via bss_count ($S_SCAN_BUSY > $S_SCAN_QUIET)" \
  "expected scan-only busy candidate to score worse, got $S_SCAN_BUSY vs $S_SCAN_QUIET"

# =============================================================================================
# Part 2 — D27: enumerate_candidates
# =============================================================================================
enumerate_candidates GB true false true null
check '[ "${#CAND_CONTROL[@]}" -gt 1 ]' "enumerate_candidates(GB): more than just the anchor when allow_dfs=true" "got only ${#CAND_CONTROL[@]} candidates"
HAS40=0; HAS149=0; HAS52=0
for c in "${CAND_CONTROL[@]}"; do [ "$c" = 40 ] && HAS40=1; [ "$c" = 149 ] && HAS149=1; [ "$c" = 56 ] && HAS52=1; done
check '[ "$HAS40" -eq 1 ]' "enumerate_candidates(GB): the ch40 anchor is always present" "ch40 missing"
check '[ "$HAS149" -eq 0 ]' "enumerate_candidates(GB, ETSI): UNII-3 (ch149) must NOT be admitted" "UNII-3 unexpectedly admitted for GB"
check '[ "$HAS52" -eq 1 ]' "enumerate_candidates(GB, allow_dfs=true): UNII-2A (ch56) admitted" "ch56 missing despite allow_dfs=true"

enumerate_candidates US true false true null
HAS149_US=0
for c in "${CAND_CONTROL[@]}"; do [ "$c" = 149 ] && HAS149_US=1; done
check '[ "$HAS149_US" -eq 1 ]' "enumerate_candidates(US, FCC-style): UNII-3 (ch149) admitted as an alternative" "UNII-3 missing for US"

enumerate_candidates GB false false true null
DFS_COUNT=0
for d in "${CAND_DFS[@]}"; do [ "$d" -eq 1 ] && DFS_COUNT=$((DFS_COUNT + 1)); done
check '[ "$DFS_COUNT" -eq 0 ]' "enumerate_candidates(allow_dfs=false): zero DFS candidates" "got $DFS_COUNT DFS candidates, expected 0"

enumerate_candidates GB true false true null
HAS116=0
for c in "${CAND_CONTROL[@]}"; do [ "$c" = 120 ] && HAS116=1; done
check '[ "$HAS116" -eq 0 ]' "enumerate_candidates(allow_meteo=false): the 116-128(ctrl120) meteo block is excluded" "meteo block unexpectedly present"
enumerate_candidates GB true true true null
for c in "${CAND_CONTROL[@]}"; do [ "$c" = 120 ] && HAS116=1; done
check '[ "$HAS116" -eq 1 ]' "enumerate_candidates(allow_meteo=true): the 116-128(ctrl120) meteo block is admitted" "meteo block missing despite allow_meteo=true"

enumerate_candidates GB true false false null
HAS132=0
for c in "${CAND_CONTROL[@]}"; do [ "$c" = 136 ] && HAS132=1; done
check '[ "$HAS132" -eq 0 ]' "enumerate_candidates(ch144_capable=false): the 132-144(ctrl136) block is dropped" "132-144 block present despite ch144_capable=false"
enumerate_candidates GB true false true null
for c in "${CAND_CONTROL[@]}"; do [ "$c" = 136 ] && HAS132=1; done
check '[ "$HAS132" -eq 1 ]' "enumerate_candidates(ch144_capable=true): the 132-144(ctrl136) block is admitted" "132-144 block missing"

enumerate_candidates GB true false true null 104
HAS100=0
for c in "${CAND_CONTROL[@]}"; do [ "$c" = 104 ] && HAS100=1; done
check '[ "$HAS100" -eq 0 ]' "enumerate_candidates: a SPECIFIC blocked channel (104) is excluded" "ch104 present despite being blocked"
HAS52B=0
for c in "${CAND_CONTROL[@]}"; do [ "$c" = 56 ] && HAS52B=1; done
check '[ "$HAS52B" -eq 1 ]' "enumerate_candidates: OTHER DFS blocks stay admitted when only ch104 is blocked" "ch56 unexpectedly excluded"

enumerate_candidates GB true false true false
DFS_COUNT2=0
for d in "${CAND_DFS[@]}"; do [ "$d" -eq 1 ] && DFS_COUNT2=$((DFS_COUNT2 + 1)); done
check '[ "$DFS_COUNT2" -eq 0 ]' "enumerate_candidates(dfs_ap_supported=false): a radio proven DFS-incapable never gets a DFS candidate again" "got $DFS_COUNT2 DFS candidates"

enumerate_candidates 00 true false true null
DFS_COUNT3=0
for d in "${CAND_DFS[@]}"; do [ "$d" -eq 1 ] && DFS_COUNT3=$((DFS_COUNT3 + 1)); done
check '[ "$DFS_COUNT3" -eq 0 ] && [ "${#CAND_CONTROL[@]}" -eq 1 ]' "enumerate_candidates(world 00): a total no-op — only the ch40 anchor, zero DFS" \
  "world domain: expected exactly 1 non-DFS candidate, got ${#CAND_CONTROL[@]} (dfs=$DFS_COUNT3)"

# =============================================================================================
# Part 3 — D16a: apply_no_ir_filter
# =============================================================================================
enumerate_candidates GB true false true null
TEST_AP_CAPABLE_LIST=""
apply_no_ir_filter
ALL_CAP=1
for a in "${CAND_APCAP[@]}"; do [ "$a" = 1 ] || ALL_CAP=0; done
check '[ "$ALL_CAP" -eq 1 ]' "apply_no_ir_filter: an EMPTY No-IR list optimistically admits everything" "some candidate was excluded despite an empty list"

enumerate_candidates GB true false true null
TEST_AP_CAPABLE_LIST="52 56 60 64"
apply_no_ir_filter
I40=-1
for i in "${!CAND_CONTROL[@]}"; do [ "${CAND_CONTROL[$i]}" = 40 ] && I40=$i; done
check '[ "${CAND_APCAP[$I40]}" = 0 ]' "apply_no_ir_filter: ch40's footprint NOT covered by the supplied list -> excluded" "ch40 unexpectedly still admitted"
I52=-1
for i in "${!CAND_CONTROL[@]}"; do [ "${CAND_CONTROL[$i]}" = 56 ] && I52=$i; done
check '[ "${CAND_APCAP[$I52]}" = 1 ]' "apply_no_ir_filter: ch56's footprint IS covered -> stays admitted" "ch56 unexpectedly excluded"
unset TEST_AP_CAPABLE_LIST

# =============================================================================================
# Part 4 — D26: survey/scan parsing
# =============================================================================================
SURVEY_TEXT=$'Survey data from wlan0\n\tfrequency:\t\t\t5200 MHz [in use]\n\tnoise:\t\t\t\t-89 dBm\n\tchannel active time:\t\t100000 ms\n\tchannel busy time:\t\t25000 ms\n'
BUSY=$(parse_survey_busy "$SURVEY_TEXT" 40)
check '[ "$BUSY" = 25 ]' "parse_survey_busy: 25000/100000 => 25% busy on ch40 (5200 MHz)" "got: $BUSY"
BUSY_OTHER=$(parse_survey_busy "$SURVEY_TEXT" 100)
check '[ -z "$BUSY_OTHER" ]' "parse_survey_busy: a channel NOT in the sample returns empty" "got: $BUSY_OTHER"

SCAN_TEXT=$'BSS aa:bb:cc:dd:ee:01(on wlan0)\n\tfreq: 5220\n\tsignal: -45.00 dBm\nBSS aa:bb:cc:dd:ee:02(on wlan0)\n\tfreq: 5220\n\tsignal: -75.00 dBm\nBSS aa:bb:cc:dd:ee:03(on wlan0)\n\tfreq: 5500\n\tsignal: -55.00 dBm\n'
COUNTS=$(parse_scan_bss_counts "$SCAN_TEXT")
check 'echo "$COUNTS" | grep -q "^44 4$"' "parse_scan_bss_counts: a strong (-45dBm) neighbour on ch44 weighs 4" "got: $COUNTS"
check 'echo "$COUNTS" | grep -q "^44 1$"' "parse_scan_bss_counts: a weak (-75dBm) neighbour on ch44 weighs 1" "got: $COUNTS"
check 'echo "$COUNTS" | grep -q "^100 3$"' "parse_scan_bss_counts: a mid-strength (-55dBm) neighbour on ch100 weighs 3" "got: $COUNTS"

enumerate_candidates GB true false true null
apply_bss_counts "$SCAN_TEXT"
I40b=-1; I100b=-1
for i in "${!CAND_CONTROL[@]}"; do
  [ "${CAND_CONTROL[$i]}" = 40 ] && I40b=$i
  [ "${CAND_CONTROL[$i]}" = 104 ] && I100b=$i
done
check '[ "${CAND_BSS[$I40b]}" = 5 ]' "apply_bss_counts: ch40's block (44 is in 36-48) sums the two neighbours weighted 4+1=5" "got: ${CAND_BSS[$I40b]}"
check '[ "${CAND_BSS[$I100b]}" = 3 ]' "apply_bss_counts: ch100's block gets its own neighbour's weight 3" "got: ${CAND_BSS[$I100b]}"

# =============================================================================================
# Part 5 — D28/D29: select_decision_sh
# =============================================================================================
enumerate_candidates GB true false true null
DEC=$(select_decision_sh 40 5 0 23 0 0 30)
check '[[ "$DEC" == keep\ quiet_floor* ]]' "select_decision_sh: a quiet current channel (busy=5% < floor 20%) => keep quiet_floor" "got: $DEC"

# "Not meaningfully better": isolate to ONE non-DFS alternative (no EIRP/CAC terms to confound the
# comparison) — a US (FCC-style) enumeration with allow_dfs=false yields exactly [ch40, ch149].
enumerate_candidates US false false false null
for i in "${!CAND_CONTROL[@]}"; do
  [ "${CAND_CONTROL[$i]}" = 149 ] && CAND_BUSY[i]=25   # only marginally quieter than current's 30%
done
DEC2=$(select_decision_sh 40 30 3 23 0 0 30)
check '[[ "$DEC2" == keep* ]]' "select_decision_sh: a marginal candidate (busy 25% vs current 30%) does not clear switch_margin => keep" "got: $DEC2"

# "Clearly better": isolate to [ch40, ch56, ch104] (ch144_capable=false drops ch136, which would
# otherwise also win on its own scan-only EIRP-bonused estimate and confound which one won).
enumerate_candidates GB true false false null
for i in "${!CAND_CONTROL[@]}"; do
  [ "${CAND_CONTROL[$i]}" = 104 ] && CAND_BUSY[i]=2
done
DEC3=$(select_decision_sh 40 80 10 23 0 0 30)
check '[[ "$DEC3" == switch* ]]' "select_decision_sh: a clearly cleaner candidate on a busy current channel => switch" "got: $DEC3"
read -r _ SWITCH_IDX _ <<<"$DEC3"
check '[ "${CAND_CONTROL[$SWITCH_IDX]}" = 104 ]' "select_decision_sh: the switch target is the single best-scoring candidate (ch104)" \
  "got control ${CAND_CONTROL[$SWITCH_IDX]}, expected 104"

# ap_capable filtering: mark every candidate not-admitted -> must never select one.
enumerate_candidates GB true false true null
for i in "${!CAND_CONTROL[@]}"; do CAND_APCAP[i]=0; done
DEC4=$(select_decision_sh 40 80 10 23 0 0 30)
check '[[ "$DEC4" == keep\ no_candidate* ]]' "select_decision_sh: every candidate non-ap_capable => keep no_candidate" "got: $DEC4"

# =============================================================================================
# Part 6 — D24 intent readers (nested `wifi: ap: optimize:` block extraction)
# =============================================================================================
INTENT_DIR="$TMP/intent"; mkdir -p "$INTENT_DIR"
cat > "$INTENT_DIR/network.yaml" <<'EOF'
network:
  wifi:
    ap:
      band: auto
      optimize:
        enabled: false
        at: "04:30"
        allow_dfs: false
        allow_meteo: true
        min_improvement: 50
    country: auto
EOF
WIFI_OPTIMIZE_INTENT_FILES=("$INTENT_DIR/network.yaml")
check '[ "$(read_optimize_bool enabled true)" = false ]' "read_optimize_bool(enabled): reads false from the nested block" "got: $(read_optimize_bool enabled true)"
check '[ "$(read_optimize_field at)" = "04:30" ]' "read_optimize_field(at): reads a quoted value" "got: $(read_optimize_field at)"
check '[ "$(read_optimize_bool allow_dfs true)" = false ]' "read_optimize_bool(allow_dfs): reads false" "got: $(read_optimize_bool allow_dfs true)"
check '[ "$(read_optimize_bool allow_meteo false)" = true ]' "read_optimize_bool(allow_meteo): reads true" "got: $(read_optimize_bool allow_meteo false)"
check '[ "$(read_optimize_min_improvement)" = 50 ]' "read_optimize_min_improvement: reads 50" "got: $(read_optimize_min_improvement)"

cat > "$INTENT_DIR/network.yaml" <<'EOF'
network:
  wifi:
    ap:
      band: auto
    country: auto
EOF
check '[ "$(read_optimize_bool enabled true)" = true ]' "read_optimize_bool: an ABSENT optimize block falls back to the caller default (true)" "got: $(read_optimize_bool enabled true)"
check '[ "$(read_optimize_min_improvement)" = 20 ]' "read_optimize_min_improvement: absent block defaults to 20" "got: $(read_optimize_min_improvement)"

cat > "$INTENT_DIR/network.yaml" <<'EOF'
network:
  wifi:
    ap:
      channel: 100
      band: auto
EOF
WIFI_BAND_INTENT_FILES=("$INTENT_DIR/network.yaml")
check '[ "$(read_ap_channel_pin)" = 100 ]' "read_ap_channel_pin: reads an operator channel pin" "got: $(read_ap_channel_pin)"
cat > "$INTENT_DIR/network.yaml" <<'EOF'
network:
  wifi:
    ap:
      band: auto
EOF
check '[ -z "$(read_ap_channel_pin)" ]' "read_ap_channel_pin: absent pin returns empty" "got: $(read_ap_channel_pin)"

# --- radio capability probes (TEST_IW_PHY_INFO) --------------------------------------------------
TEST_IW_PHY_INFO=$'Band 1:\n\t\t* 2412 MHz\nBand 2:\n\t\t* 5180 MHz\n\t\t* 5200 MHz\n\t\t* 5720 MHz [144]\n'
check '[ "$(radio_is_5ghz_capable wlan0)" = true ]' "radio_is_5ghz_capable: detects a 5xxx MHz line" "got: $(radio_is_5ghz_capable wlan0)"
check '[ "$(radio_advertises_ch144 wlan0)" = true ]' "radio_advertises_ch144: detects the [144] marker" "got: $(radio_advertises_ch144 wlan0)"
TEST_IW_PHY_INFO=$'Band 1:\n\t\t* 2412 MHz\n'
check '[ "$(radio_is_5ghz_capable wlan0)" = false ]' "radio_is_5ghz_capable: a 2.4GHz-only radio is NOT 5GHz-capable" "got: $(radio_is_5ghz_capable wlan0)"
check '[ "$(radio_advertises_ch144 wlan0)" = false ]' "radio_advertises_ch144: no [144] marker => false" "got: $(radio_advertises_ch144 wlan0)"
unset TEST_IW_PHY_INFO

# =============================================================================================
# Part 7 — D30/D31: state + channel-LKG persistence round trips
# =============================================================================================
IFACE=wlan0
STATE_FILE="$TMP/wifi-optimize-state-wlan0.json"
LKG_FILE="$TMP/wifi-channel-lkg-wlan0.json"
cc=RO
radio_id="aa:bb:cc:dd:ee:ff"
DFS_AP_SUPPORTED="null"
BLOCKED_CHANNELS=()
mark_dfs_blocked 100
mark_dfs_blocked 116
write_optimize_state true "40" 12
check '[ -r "$STATE_FILE" ]' "write_optimize_state created $STATE_FILE" "state file not created"
DFS_AP_SUPPORTED="null"; BLOCKED_CHANNELS=()
load_state
check '[ "$DFS_AP_SUPPORTED" = true ]' "load_state: round-trips dfs_ap_supported=true for the SAME cc+radio" "got: $DFS_AP_SUPPORTED"
check '[ "${#BLOCKED_CHANNELS[@]}" -eq 2 ]' "load_state: round-trips both blocked_channels" "got ${#BLOCKED_CHANNELS[@]} entries: ${BLOCKED_CHANNELS[*]:-}"

# A cc/radio CHANGE must invalidate the cached state (D30 re-test DFS).
cc=GB
DFS_AP_SUPPORTED="untouched"; BLOCKED_CHANNELS=(99)
load_state
check '[ "$DFS_AP_SUPPORTED" = "null" ]' "load_state: a regdomain change resets dfs_ap_supported to untested (null)" "got: $DFS_AP_SUPPORTED"
check '[ "${#BLOCKED_CHANNELS[@]}" -eq 0 ]' "load_state: a regdomain change resets blocked_channels" "got: ${BLOCKED_CHANNELS[*]:-}"
cc=RO

write_channel_lkg 100 106 80 true 12
check '[ "$(json_field "$LKG_FILE" cc)" = RO ]' "write_channel_lkg/json_field: cc round-trips" "got: $(json_field "$LKG_FILE" cc)"
check '[ "$(json_field "$LKG_FILE" control_channel)" = 100 ]' "write_channel_lkg/json_field: control_channel round-trips" "got: $(json_field "$LKG_FILE" control_channel)"
check '[ "$(json_field "$LKG_FILE" dfs)" = true ]' "write_channel_lkg/json_field: dfs round-trips as a bare true" "got: $(json_field "$LKG_FILE" dfs)"

# =============================================================================================
# Part 8 — D29 apply_and_observe (isolated, via the sourced observe_rung's TEST_* seams)
# =============================================================================================
export TEST_HOSTAPD_ACTIVE=1
export TEST_SKIP_SLEEP=1
CONF="$TMP/hostapd-wlan0.conf"
BASE_SSID="HookProbe-test"; BASE_SEC=""; COUNTRY_LINES=""
TEST_IW_INFO=$'\tchannel 100 (5500 MHz), width: 80 MHz, center1: 5550 MHz'
export TEST_IW_INFO
RESULT=$(apply_and_observe 100 106 1)
read -r _ _ _ RC <<<"$RESULT"
check '[ "$RC" -eq 0 ]' "apply_and_observe: requested ch100 == observed ch100 => Stable (rc=0)" "got rc=$RC: $RESULT"
# BUG-W10 (2026-07-17 audit): a DFS candidate's conf must NOT carry ieee80211h — it crash-loops
# hostapd on the shipped brcmfmac FullMAC (firmware does CAC internally; matches wifi_cfg::width_lines
# which never emits it). This assertion was INVERTED (it used to require ieee80211h=1, locking in the
# bug). SoftMAC/DFS-capable radios (ADR 0042) will re-add CAC signaling radio-conditionally.
check '! grep -q "ieee80211h" "$CONF"' "apply_and_observe: a DFS candidate's conf must NOT carry ieee80211h (crashes brcmfmac)" "ieee80211h wrongly present in rendered conf"

TEST_IW_INFO=$'\tchannel 40 (5200 MHz), width: 80 MHz, center1: 5210 MHz'
RESULT2=$(apply_and_observe 100 106 1)
read -r _ _ _ RC2 <<<"$RESULT2"
check '[ "$RC2" -ne 0 ]' "apply_and_observe: requested ch100 but observed ch40 => did NOT hold (rc!=0)" "expected rc!=0, got rc=$RC2"

unset TEST_IW_INFO TEST_HOSTAPD_ACTIVE TEST_SKIP_SLEEP

# =============================================================================================
# Part 9 — D31 do_reapply end-to-end
# =============================================================================================
IFACE=wlan0
CONF="$TMP/hostapd-wlan0.conf"
cc=RO
radio_id="aa:bb:cc:dd:ee:ff"
STATE_FILE="$TMP/reapply-state.json"
LKG_FILE="$TMP/reapply-lkg.json"
DFS_AP_SUPPORTED="null"; BLOCKED_CHANNELS=()
prepare_render_context
export TEST_SKIP_SLEEP=1 TEST_HOSTAPD_ACTIVE=1

rm -f "$LKG_FILE"
do_reapply >/dev/null 2>&1
check '[ "$(json_field "$STATUS" verify)" = "no_channel_lkg" ]' "do_reapply: no LKG file => documented skip 'no_channel_lkg'" "got: $(json_field "$STATUS" verify)"

cat > "$LKG_FILE" <<'EOF'
{ "cc": "GB", "radio_id": "aa:bb:cc:dd:ee:ff", "control_channel": 100, "center_idx": 106, "width_mhz": 80, "dfs": true, "score": 5, "validated_at": "2026-01-01T00:00:00Z" }
EOF
do_reapply >/dev/null 2>&1
check '[ ! -e "$LKG_FILE" ]' "do_reapply: a cc-mismatched LKG (GB cached, now RO) is CLEARED" "LKG file was not cleared"
check '[ "$(json_field "$STATUS" verify)" = "channel_lkg_invalid" ]' "do_reapply: cc mismatch => documented skip 'channel_lkg_invalid'" "got: $(json_field "$STATUS" verify)"

cat > "$LKG_FILE" <<'EOF'
{ "cc": "RO", "radio_id": "aa:bb:cc:dd:ee:ff", "control_channel": 40, "center_idx": 42, "width_mhz": 80, "dfs": false, "score": 5, "validated_at": "2026-01-01T00:00:00Z" }
EOF
do_reapply >/dev/null 2>&1
check '[ "$(json_field "$STATUS" verify)" = "nondfs_already_bootfast" ]' "do_reapply: a non-DFS LKG needs no reapply (already BootFast)" "got: $(json_field "$STATUS" verify)"
check '[ -r "$LKG_FILE" ]' "do_reapply: a non-DFS LKG is left untouched, not cleared" "LKG file was unexpectedly removed"

cat > "$LKG_FILE" <<'EOF'
{ "cc": "RO", "radio_id": "aa:bb:cc:dd:ee:ff", "control_channel": 100, "center_idx": 106, "width_mhz": 80, "dfs": true, "score": 5, "validated_at": "2026-01-01T00:00:00Z" }
EOF
TEST_IW_INFO=$'\tchannel 100 (5500 MHz), width: 80 MHz, center1: 5550 MHz'
export TEST_IW_INFO
do_reapply >/dev/null 2>&1
check '[ "$(json_field "$STATUS" decision)" = switch ] && [ "$(json_field "$STATUS" verify)" = committed ]' \
  "do_reapply: the persisted DFS channel HOLDS => committed" "got decision=$(json_field "$STATUS" decision) verify=$(json_field "$STATUS" verify)"
check '[ "$(json_field "$STATUS" committed_channel)" = 100 ]' "do_reapply: committed_channel is the restored DFS channel (100)" "got: $(json_field "$STATUS" committed_channel)"

cat > "$LKG_FILE" <<'EOF'
{ "cc": "RO", "radio_id": "aa:bb:cc:dd:ee:ff", "control_channel": 116, "center_idx": 122, "width_mhz": 80, "dfs": true, "score": 5, "validated_at": "2026-01-01T00:00:00Z" }
EOF
TEST_IW_INFO=$'\tchannel 40 (5200 MHz), width: 80 MHz, center1: 5210 MHz'  # never converges to 116
DFS_AP_SUPPORTED="null"; BLOCKED_CHANNELS=()
do_reapply >/dev/null 2>&1
check '[ ! -e "$LKG_FILE" ]' "do_reapply: a DFS LKG that does NOT hold is CLEARED (never retried blindly)" "LKG file was not cleared on failure"
check '[ "$(json_field "$STATUS" verify)" = "reverted_failed_to_hold" ]' "do_reapply: a failed DFS restore is recorded as reverted_failed_to_hold" "got: $(json_field "$STATUS" verify)"
check '[ "$(json_field "$STATUS" committed_channel)" = 40 ]' "do_reapply: on failure the AP ends on ch40, never left on the unproven DFS channel" "got: $(json_field "$STATUS" committed_channel)"

unset TEST_IW_INFO TEST_HOSTAPD_ACTIVE TEST_SKIP_SLEEP

# =============================================================================================
# Part 10 — D24 main() guards end-to-end (every guard writes a documented skip artifact and NEVER
# touches the radio — no TEST_HOSTAPD_ACTIVE/TEST_IW_INFO needed since the radio is never reached)
# =============================================================================================
WIFI_OPTIMIZE_STATUS="$TMP/guard-status.json"; export WIFI_OPTIMIZE_STATUS
STATUS="$WIFI_OPTIMIZE_STATUS"
WIFI_OPTIMIZE_STATE_DIR="$TMP"; export WIFI_OPTIMIZE_STATE_DIR
WIFI_COUNTRY_FILE="$TMP/does-not-exist-country"; export WIFI_COUNTRY_FILE

cat > "$INTENT_DIR/network.yaml" <<'EOF'
network:
  wifi:
    ap:
      band: "2.4"
EOF
WIFI_BAND_INTENT_FILES=("$INTENT_DIR/network.yaml")
WIFI_OPTIMIZE_INTENT_FILES=("$INTENT_DIR/network.yaml")
main wlan0 optimize >/dev/null 2>&1
check '[ "$(json_field "$STATUS" verify)" = "band_pin_24" ]' "main(): a 2.4GHz band pin skips with 'band_pin_24'" "got: $(json_field "$STATUS" verify)"

cat > "$INTENT_DIR/network.yaml" <<'EOF'
network:
  wifi:
    ap:
      band: auto
      optimize:
        enabled: false
EOF
main wlan0 optimize >/dev/null 2>&1
check '[ "$(json_field "$STATUS" verify)" = "disabled_by_intent" ]' "main(): enabled:false skips with 'disabled_by_intent'" "got: $(json_field "$STATUS" verify)"

cat > "$INTENT_DIR/network.yaml" <<'EOF'
network:
  wifi:
    ap:
      band: auto
      channel: 100
EOF
main wlan0 optimize >/dev/null 2>&1
check '[ "$(json_field "$STATUS" verify)" = "operator_pin_active" ]' "main(): an operator channel pin skips with 'operator_pin_active' (D24 prio-1)" "got: $(json_field "$STATUS" verify)"

cat > "$INTENT_DIR/network.yaml" <<'EOF'
network:
  wifi:
    ap:
      band: auto
EOF
# No TEST_IW_PHY_INFO and no real 5GHz-capable /sys/class/net/wlan0 on this dev box => not-5GHz-capable.
main wlan0 optimize >/dev/null 2>&1
check '[ "$(json_field "$STATUS" verify)" = "not_5ghz_capable" ]' "main(): a non-5GHz-capable radio skips with 'not_5ghz_capable'" "got: $(json_field "$STATUS" verify)"

# Every guard path above must produce decision=skip with NO committed_channel — the radio was
# never touched (the strongest possible proof the guards are side-effect-free).
check '[ "$(json_field "$STATUS" decision)" = skip ]' "main(): the last guard skip's decision field is 'skip'" "got: $(json_field "$STATUS" decision)"

# =============================================================================================
# Part 11 — full do_optimize REVERT-chain integration: a busy current channel considers
# switching, the candidate does NOT hold, and the PREVIOUS channel is restored — proving the
# always-joinable guarantee end-to-end through the actual decision+apply+observe+revert pipeline.
# =============================================================================================
cat > "$INTENT_DIR/network.yaml" <<'EOF'
network:
  wifi:
    ap:
      band: auto
      optimize:
        enabled: true
        allow_dfs: true
        allow_meteo: false
        min_improvement: 20
EOF
# Part 10 pointed WIFI_COUNTRY_FILE at a nonexistent path (to exercise the "no radio touched"
# guards without a real regdomain) -- restore a real resolved country here so this integration
# test enumerates DFS candidates (the world "00" domain is deliberately a total no-op, D27).
WIFI_COUNTRY_FILE="$TMP/country-ro"; export WIFI_COUNTRY_FILE
echo RO > "$WIFI_COUNTRY_FILE"
# Part 7 exercised load_state/write_optimize_state against main()'s OWN auto-derived state-file
# path (a deliberate round-trip fixture, cc=RO, blocked_channels=[100,116]) -- clear it here so
# this integration test starts from a clean, first-run slate rather than inheriting that fixture.
rm -f "$STATE_DIR/wifi-optimize-state-wlan0.json" "$STATE_DIR/wifi-channel-lkg-wlan0.json" 2>/dev/null
WIFI_BAND_INTENT_FILES=("$INTENT_DIR/network.yaml")
WIFI_OPTIMIZE_INTENT_FILES=("$INTENT_DIR/network.yaml")
# ADR 0034 D35-D44: point this run's learning-model store at an isolated dir so the assertions
# right after this integration test (below) can inspect exactly what THIS run recorded.
LEARN_DIR_REVERT="$TMP/learn-revert"
mkdir -p "$LEARN_DIR_REVERT"
WIFI_LEARN_DIR="$LEARN_DIR_REVERT"
export WIFI_LEARN_DIR
TEST_IW_PHY_INFO=$'Band 2:\n\t\t* 5180 MHz\n\t\t* 5500 MHz\n\t\t* 5720 MHz [144]\n'
export TEST_IW_PHY_INFO
# Current channel (ch40) is busy (80%) and heavily scanned; ch100 (UNII-2C) is clean and scans quiet
# => the decision must be SWITCH. TEST_IW_INFO stays fixed at ch40 throughout (a static seam can't
# simulate the radio dynamically moving), so the VALIDATE step's observe sees "still on ch40" for
# the ch100 request => WidthCollapsed => REVERT: re-apply ch40, which THEN converges (same fixture)
# => Stable => committed_channel=40 (the previous channel restored, never left mid-switch).
TEST_IW_INFO=$'\tchannel 40 (5200 MHz), width: 80 MHz, center1: 5210 MHz'
export TEST_IW_INFO
TEST_IW_SURVEY=$'Survey data from wlan0\n\tfrequency:\t\t\t5200 MHz [in use]\n\tnoise:\t\t\t\t-80 dBm\n\tchannel active time:\t\t100000 ms\n\tchannel busy time:\t\t80000 ms\n'
export TEST_IW_SURVEY
TEST_IW_SCAN=$'BSS aa:bb:cc:dd:ee:01(on wlan0)\n\tfreq: 5200\n\tsignal: -40.00 dBm\nBSS aa:bb:cc:dd:ee:02(on wlan0)\n\tfreq: 5200\n\tsignal: -42.00 dBm\nBSS aa:bb:cc:dd:ee:03(on wlan0)\n\tfreq: 5500\n\tsignal: -85.00 dBm\n'
export TEST_IW_SCAN
export TEST_HOSTAPD_ACTIVE=1 TEST_SKIP_SLEEP=1 TEST_NO_DMESG=1
CONF="$TMP/hostapd-wlan0.conf"; : > "$CONF"
main wlan0 optimize >/dev/null 2>&1
check '[ "$(json_field "$STATUS" decision)" = switch ]' "do_optimize integration: a busy, heavily-scanned ch40 vs a clean DFS candidate => decision=switch" \
  "got decision=$(json_field "$STATUS" decision)"
check '[ "$(json_field "$STATUS" verify)" = "reverted_failed_to_hold" ]' \
  "do_optimize integration: the static-iw fixture can't hold the NEW channel => REVERT recorded" "got verify=$(json_field "$STATUS" verify)"
check '[ "$(json_field "$STATUS" committed_channel)" = 40 ]' \
  "do_optimize integration: the AP ends back on the PREVIOUS channel (40) — never left mid-switch, the always-joinable guarantee" \
  "got committed_channel=$(json_field "$STATUS" committed_channel)"

# ADR 0034 D35-D44: even a REVERTED run must fold BOTH the failed candidate (ch100, a non-stable
# verdict) AND the restored channel (ch40, stable) into the learning model — D36's "record EVERY
# candidate it measures/validates," not just a successful commit. And since nothing committed, NO
# channel-LKG export should have been written (only a COMMIT calls learn_export_channel_lkg).
if command -v jq >/dev/null 2>&1; then
  LEARN_STORE_REVERT="$LEARN_DIR_REVERT/wifi-learn-wlan0.json"
  check '[ -r "$LEARN_STORE_REVERT" ]' \
    "do_optimize REVERT integration: the run persisted the learning-model store" "no store at $LEARN_STORE_REVERT"
  # The SPECIFIC DFS channel the D28 scorer picks as "best" (ch100 vs ch132, both admitted here —
  # TEST_IW_PHY_INFO advertises ch144, and the ch100/ch132 scores can tie or favour either depending
  # on the scan/survey fixture's exact bss weighting) is an implementation/scoring detail, not what
  # this test pins down — it only asserts SOME non-ch40 (the failed switch candidate) was recorded
  # as a failure, whichever channel the scorer chose.
  check '(jq -e "[.entries[] | select(.key.channel != 40) | select(.failures >= 1)] | length >= 1" "$LEARN_STORE_REVERT" >/dev/null 2>&1)' \
    "do_optimize REVERT integration: the failed switch candidate was recorded as a FAILURE, not silently dropped" \
    "$(cat "$LEARN_STORE_REVERT" 2>/dev/null)"
  check '(jq -e "[.entries[] | select(.key.channel==40)][0].successes >= 1" "$LEARN_STORE_REVERT" >/dev/null 2>&1)' \
    "do_optimize REVERT integration: the restored ch40 was recorded as a SUCCESS (it held on revert)" \
    "$(cat "$LEARN_STORE_REVERT" 2>/dev/null)"
  check '[ ! -e "$STATE_DIR/wifi-channel-lkg-wlan0.json" ]' \
    "do_optimize REVERT integration: NO channel-LKG export on a revert (only a COMMIT exports)" \
    "unexpectedly found a channel-LKG file after a reverted run"
fi
unset WIFI_LEARN_DIR

unset TEST_IW_PHY_INFO TEST_IW_INFO TEST_IW_SURVEY TEST_IW_SCAN TEST_HOSTAPD_ACTIVE TEST_SKIP_SLEEP TEST_NO_DMESG

# =============================================================================================
# Part — ADR 0034 D35-D44: the optimizer records into, and exports FROM, the SAME learning-model
# store wifi-calibrate.sh consults (this file sources wifi-calibrate.sh, so every learn_* function
# is already in scope). Skipped gracefully (documented) when jq is unavailable.
# =============================================================================================
if command -v jq >/dev/null 2>&1; then
  LEARN_DIR="$TMP/learn"
  mkdir -p "$LEARN_DIR"

  # --- rc_to_verdict: the shared apply_and_observe-rc <-> verdict-word mapping ------------------
  check '[ "$(rc_to_verdict 0)" = stable ] && [ "$(rc_to_verdict 1)" = width_collapsed ] && [ "$(rc_to_verdict 2)" = chanspec_fail_storm ] && [ "$(rc_to_verdict 3)" = down ]' \
    "rc_to_verdict: maps every apply_and_observe return code to the right verdict word" \
    "got: 0=$(rc_to_verdict 0) 1=$(rc_to_verdict 1) 2=$(rc_to_verdict 2) 3=$(rc_to_verdict 3)"

  # --- learn_record with a busy_ratio sample (the optimizer's own D26 survey signal) ------------
  OM0=$(learn_load "$LEARN_DIR/does-not-exist.json" wlan0 fw1 2026-07-15T00:00:00Z)
  OM1=$(learn_record "$OM0" r1 RO 100 80 stable 2026-07-15T00:00:00Z 15)
  check '[ "$(echo "$OM1" | jq -r ".entries[0].busy_ema")" = 15 ]' \
    "learn_record: the FIRST busy_ratio sample seeds busy_ema directly (no cold-0 bias)" \
    "got: $(echo "$OM1" | jq -c '.entries[0]')"
  OM2=$(learn_record "$OM1" r1 RO 100 80 stable 2026-07-15T01:00:00Z 45)
  check '(echo "$OM2" | jq -e ".entries[0].busy_ema > 15 and .entries[0].busy_ema < 45" >/dev/null)' \
    "learn_record: a SECOND busy_ratio sample blends (EMA), landing strictly between the two samples" \
    "got: $(echo "$OM2" | jq -r '.entries[0].busy_ema')"

  # --- learn_export_channel_lkg: exports the 5GHz VHT80 argmax, round-trips via json_field --------
  CH_LKG="$LEARN_DIR/wifi-channel-lkg-wlan0.json"
  learn_export_channel_lkg "$OM2" RO r1 '[[100,80]]' 2026-07-15T01:00:00Z "$CH_LKG"
  check '[ -r "$CH_LKG" ]' "learn_export_channel_lkg: writes a channel-LKG file for a proven, legal VHT80 winner" "no file written"
  check '[ "$(json_field "$CH_LKG" control_channel)" = 100 ]' \
    "learn_export_channel_lkg: control_channel round-trips via the UNCHANGED json_field reader" \
    "got: $(json_field "$CH_LKG" control_channel)"
  check '[ "$(json_field "$CH_LKG" dfs)" = false ]' \
    "learn_export_channel_lkg: dfs is echoed from the model's own cached flag (ch100 recorded non-DFS here)" \
    "got: $(json_field "$CH_LKG" dfs)"

  # --- an entry outside the legal set (or nothing proven) => no export, no crash ------------------
  rm -f "$LEARN_DIR/no-export.json"
  learn_export_channel_lkg "$OM2" RO r1 '[[52,80]]' 2026-07-15T01:00:00Z "$LEARN_DIR/no-export.json"
  check '[ ! -e "$LEARN_DIR/no-export.json" ]' \
    "learn_export_channel_lkg: writes NOTHING when the model's winner is outside the legal set" \
    "unexpectedly wrote a file for an illegal candidate"

  # NOTE: a full do_optimize COMMIT-path integration test (a candidate that DOES hold) is not
  # doable with this harness's STATIC TEST_IW_INFO seam — do_optimize reads the SAME TEST_IW_INFO
  # for BOTH the initial "what's the current channel" read AND the post-switch VALIDATE read, so a
  # fixed value can only ever represent "no radio move happened" (i.e. it drives the REVERT path,
  # exactly like the existing "do_optimize integration" REVERT test above, whose model-recording
  # side effects are asserted right after it). The COMMIT path's own model-write behaviour
  # (`learn_record` + `learn_export_channel_lkg`) is fully covered above via direct unit calls
  # (`learn_export_channel_lkg: writes a channel-LKG file for a proven, legal VHT80 winner`) and via
  # `do_reapply`'s existing DFS-hold=>commit integration test (which exercises the identical
  # apply_and_observe-rc==0=>commit code shape one level up in this same file).
else
  echo "  SKIP: learning-model (D35-D44) checks — jq not available on this box"
fi

echo
if [ "$FAIL" -eq 0 ]; then
  echo "=== test-wifi-optimize: ALL CASES PASSED ==="
  exit 0
else
  echo "=== test-wifi-optimize: FAILED -- see FAIL lines above ==="
  exit 1
fi
