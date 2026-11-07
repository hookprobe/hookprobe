#!/usr/bin/env bash
# =============================================================================
# wifi-optimize.sh — the RUNTIME half of ADR 0034's D24-D33 extension: the AUTONOMOUS,
# survey-based 5 GHz channel optimizer ("scan at 3AM, find the least-congested channel per ETSI
# EN 301 893, self-validate, else default to ch40").
#
# LAYERING (D24): this is a STRICTLY ADDITIVE layer ABOVE the boot calibrate ladder
# (wifi-calibrate.sh), never inside it. Boot stays fast + DFS-free (VHT80-ch40 -> HT40-ch36 ->
# 2.4-floor, unchanged); this script only ever runs on its own schedule
# (hookprobe-wifi-optimize@<iface>.timer, 03:00 daily + jitter), on-demand
# (`systemctl start hookprobe-wifi-optimize@wlan0`), on a regdomain change, or as a fast post-boot
# DFS-LKG restore (`reapply` mode). It can only ever hand the AP a channel it has ITSELF
# validated; any failure degrades to the exact channel the boot ladder would have chosen (ch40) —
# never a dead AP.
#
# The DETERMINISTIC decisions (candidate enumeration, scoring, hysteresis select, precedence,
# DFS-support learning) are pure functions in `crates/hookprobe-manifest/src/wifi_calibrate.rs`
# (`optimize_candidates`/`score_block`/`select_optimized_channel`/`resolve_operating_channel`/
# `optimize_state_valid`/`channel_lkg_valid`), unit-tested there. This script is the shell MIRROR
# of that scoring/selection logic (same pattern as wifi-calibrate.sh mirrors `verify_rung`/
# `next_rung_action` — the authoritative `hookprobe-supervisor --wifi-optimize` subcommand that
# would route this through the Rust core directly is roadmap, exactly like wifi-calibrate.sh's own
# still-pending `--wifi-calibrate` subcommand) PLUS the actual radio measurement/apply/observe
# runtime loop those pure functions cannot be.
#
# REUSE, not duplication (D20's "single-source" principle, extended to this file): this script
# SOURCES wifi-calibrate.sh for its already-tested runtime primitives — `dfs_cac_seconds`,
# `channel_footprint`, `five_ghz_block_for`, `mask_supplicant_on_ap`, `clean_restart`,
# `observe_rung`, `mark_dmesg`, `render_rung`, `radio_fingerprint`, `read_band_intent`,
# `normalize_band_pin`, and the proven-on-metal `$VHT80_LINES` (ch40, [HT40-], center 42) — rather
# than re-implementing any of them. Only the OPTIMIZER-specific logic (candidate enumeration,
# scoring, survey parsing, the DFS test-and-learn state, channel-LKG) is new here.
#
# THE LOAD-BEARING INSIGHT (ADR D24 preamble): in every ETSI (RO/EU/GB) domain there is exactly
# ONE non-DFS 80 MHz block (36-48/ch40) — the single most-congested VHT80 option by construction.
# Every other legal VHT80 block is DFS. So in practice this optimizer is "safely reach a DFS block
# when THIS radio proves (D30) it can hold one and it is materially cleaner, else stay on ch40."
#
# MODES:
#   optimize (default) — the full nightly/on-demand survey -> score -> select -> validate ->
#                         commit/revert run (D29).
#   reapply             — the fast post-boot path (D31): validate a PERSISTED DFS channel-LKG
#                         within one CAC of boot, silently upgrading ch40 -> the DFS channel on
#                         success, or reverting + clearing the disproven LKG on failure. Never
#                         blocks boot (started by network-apply.sh AFTER hostapd, --no-block).
#
# SAFETY (why imperfect scoring weights can never break the AP, D28/D29/D30 residual-risk note):
# every code path below terminates on a VALIDATED, joinable channel — Keep, Commit, or the ordered
# REVERT chain (previous channel -> ch40 anchor -> hand off to the calibrate ladder). A radio that
# cannot do DFS in AP mode is disrupted AT MOST ONCE, EVER (D30's dfs_ap_supported=false
# short-circuits every future run to non-DFS-only candidates — an eternal Keep-ch40).
#
# TESTABILITY (mirrors wifi-calibrate.sh's TEST_* convention — see base/scripts/test-wifi-optimize.sh):
#   TEST_IW_INFO, TEST_HOSTAPD_ACTIVE, TEST_NO_DMESG  — inherited from the sourced observe_rung.
#   TEST_IW_SCAN            — raw `iw dev <ap> scan` text (else the real `iw` is invoked).
#   TEST_IW_SURVEY          — raw `iw dev <ap> survey dump` text for the CURRENT channel.
#   TEST_IW_PHY_INFO        — raw `iw phy <n> info` text (5GHz-capable / ch144-capable probes).
#   TEST_AP_CAPABLE_LIST    — space-separated No-IR-filtered channel list (else the real
#                             /run/hookprobe/wifi-5ghz-ap-capable is read; empty/absent = optimistic).
#   TEST_OFFCHAN_BUSY_<ch>  — inject a busy_ratio for a targeted off-channel survey of channel <ch>
#                             (bypasses the real retune-and-dwell, which is inherently untestable
#                             off metal — see the ADR's own "cannot validate without hardware" note).
#   TEST_SKIP_SLEEP=1       — skip the settle/CAC `sleep` calls (keeps the test harness fast).
# =============================================================================
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=./wifi-calibrate.sh
source "$HERE/wifi-calibrate.sh"

STATUS=${WIFI_OPTIMIZE_STATUS:-/var/lib/hookprobe/wifi-channel-optimize.json}
STATE_DIR=${WIFI_OPTIMIZE_STATE_DIR:-/var/lib/hookprobe}
HOSTAPD_DIR=${HOSTAPD_DIR:-/etc/hostapd}
read -ra WIFI_OPTIMIZE_INTENT_FILES <<<"${WIFI_INTENT_FILES:-/etc/hookprobe/network.yaml /var/lib/hookprobe/wifi-intent.yaml}"

# D28 scoring weights — MIRROR of wifi_calibrate.rs's OPT_* constants. Field-tunable defaults; kept
# in exact numeric sync with the Rust core (the architect has flagged these need one round of field
# calibration against real 03:00 surveys — the SAFETY below does not depend on perfect tuning).
W_BUSY=4                 # score per 1% channel-busy time (PRIMARY signal)
W_BSS=3                  # score per weighted neighbour BSS (scan-only fallback/corroborating)
EIRP_BONUS_PER_DB=-6     # score delta per dBm of max-EIRP above the 23 dBm UNII-1 floor
CAC_PENALTY_STD=40       # flat penalty for a standard 60s-CAC DFS block
CAC_PENALTY_METEO=400    # flat penalty for the 600s meteorological sub-band
SWITCH_MARGIN_DEFAULT=30 # hysteresis gate 2 default (at min_improvement=20, unscaled)
QUIET_FLOOR_BUSY=20      # hysteresis gate 1: below this current busy%, never switch
BSS_BUSY_ESTIMATE_PCT=5  # per-weighted-neighbour busy% estimate when no survey sample exists
MIN_IMPROVEMENT_DEFAULT=20

# D25 off-channel survey budget (D26: "<=2s total off-channel budget, never a sweep of all blocks",
# top 1-2 scan-ranked candidates only). OFFCHANNEL_DWELL_S x 2 candidates <= the budget.
OFFCHANNEL_DWELL_S=${OFFCHANNEL_DWELL_S:-1}

# D29 settle/CAC waits — non-DFS uses the ordinary settle; a DFS candidate waits its regulatory
# Channel-Availability-Check (dfs_cac_seconds, sourced) plus margin, exactly like wifi-calibrate.sh's
# own DFS-aware settle (this optimizer is the one place that robustness net actually fires).
NONDFS_SETTLE=${NONDFS_SETTLE:-15}
DFS_SETTLE_STANDARD=${DFS_SETTLE_STANDARD:-75}
DFS_SETTLE_METEO=${DFS_SETTLE_METEO:-660}

log() { echo "wifi-optimize[${IFACE:-?}]: $*" >&2; }

# --- D27 ETSI EN 301 893 candidate geometry (mirrors wifi_calibrate.rs's OPTIMIZE_DFS_BLOCKS +
# the non-DFS anchor/UNII-3 handling in `optimize_candidates`) ---------------------------------
is_fcc_style() {
  case "${1^^}" in
    US|CA|MX|BR|AR|CL|CO|AU|NZ|KR|TW|HK|SG|IN|JP) return 0 ;;
    *) return 1 ;;
  esac
}

# The control channel's containing 80 MHz block's designated CONTROL channel: 40 for the UNII-1
# 36-48 block (the proven-on-metal anchor — matches candidate_ladder's own convention), else the
# block's lowest channel (56/104/120/136/149 (2nd-of-block, HT40- — brcmfmac-proven)). Any channel outside a known block maps to itself.
block_control_for() {
  local ch="$1" block
  block=$(five_ghz_block_for "$ch")   # sourced from wifi-calibrate.sh
  # shellcheck disable=SC2086
  set -- $block
  # 2026-07-17 (brcmfmac-proven): a VHT80 block's control channel is its 2ND channel with [HT40-]
  # (40/56/104/120/136 — NOT the lowest/$1), matching OPTIMIZE_DFS_BLOCKS. UNII-3 (149-…) has no
  # such lower-secondary pattern — it uses its anchor channel 149 directly. A channel in no known
  # block maps to itself.
  if [ "$#" -eq 4 ]; then
    if [ "$1" = 149 ]; then echo 149; else echo "$2"; fi
  else
    echo "$ch"
  fi
}

# vht_oper_centr_freq_seg0_idx for a known control channel.
center_idx_for() {
  case "$1" in
    40) echo 42 ;;
    56) echo 58 ;;
    104) echo 106 ;;
    120) echo 122 ;;
    136) echo 138 ;;
    149) echo 155 ;;
    *) echo "$1" ;;
  esac
}

is_dfs_control() { case "$1" in 56|104|120|136) return 0 ;; *) return 1 ;; esac; }

# --- D28: the score_block mirror (lower = better, a cost) --------------------------------------
# args: busy_ratio(0-100 or empty) bss_count max_eirp_dbm dfs(0|1) cac_seconds
score_block_sh() {
  local busy="${1:-}" bss="${2:-0}" eirp="${3:-23}" dfs="${4:-0}" cac="${5:-0}" busy_pct
  if [ -n "$busy" ]; then
    busy_pct="$busy"
  else
    busy_pct=$(( bss * BSS_BUSY_ESTIMATE_PCT ))
    if [ "$busy_pct" -gt 100 ]; then busy_pct=100; fi
  fi
  local score=$(( W_BUSY * busy_pct + W_BSS * bss + EIRP_BONUS_PER_DB * (eirp - 23) ))
  if [ "$dfs" -eq 1 ]; then
    if [ "$cac" -ge 600 ]; then score=$(( score + CAC_PENALTY_METEO )); else score=$(( score + CAC_PENALTY_STD )); fi
  fi
  echo "$score"
}

# --- D27: enumerate candidate blocks into the CAND_* parallel arrays ----------------------------
# args: cc allow_dfs(true|false) allow_meteo(true|false) ch144_capable(true|false)
#       dfs_ap_supported(true|false|null) [blocked_channel ...]
enumerate_candidates() {
  local cc="$1" allow_dfs="$2" allow_meteo="$3" ch144_capable="$4" dfs_ap_supported="$5"
  shift 5
  local -a blocked=("$@")
  CAND_LABEL=(); CAND_CONTROL=(); CAND_CENTER=(); CAND_DFS=(); CAND_EIRP=(); CAND_CAC=(); CAND_APCAP=()
  CAND_BUSY=(); CAND_BSS=()
  _is_blocked() {
    local c="$1" b
    for b in "${blocked[@]:-}"; do
      if [ "$b" = "$c" ]; then return 0; fi
    done
    return 1
  }
  _add() {
    CAND_LABEL+=("$1"); CAND_CONTROL+=("$2"); CAND_CENTER+=("$3"); CAND_DFS+=("$4")
    CAND_EIRP+=("$5"); CAND_CAC+=("$6"); CAND_APCAP+=(1); CAND_BUSY+=(""); CAND_BSS+=(0)
  }
  # The non-DFS anchor — every candidate must beat this (mirrors candidate_ladder's ch40 default).
  _add "UNII-1" 40 42 0 23 0
  # UNII-3 as an INDEPENDENT alternative in FCC-style domains only.
  if is_fcc_style "$cc"; then _add "UNII-3" 149 155 0 23 0; fi
  if [ "$allow_dfs" = true ] && [ "$cc" != "00" ] && [ "$dfs_ap_supported" != false ]; then
    _is_blocked 56  || _add "UNII-2A"       56  58  1 23 60
    _is_blocked 104 || _add "UNII-2C-104"  104 106  1 30 60
    if [ "$allow_meteo" = true ]; then
      _is_blocked 120 || _add "UNII-2C-meteo" 120 122 1 30 600
    fi
    if [ "$ch144_capable" = true ]; then
      _is_blocked 136 || _add "UNII-2C-136" 136 138 1 30 60
    fi
  fi
}

# --- D16a-alike: filter CAND_APCAP by the No-IR run-file artifact, EMPTY = optimistic admit-all -
apply_no_ir_filter() {
  local content=""
  if [ -n "${TEST_AP_CAPABLE_LIST+x}" ]; then
    content="$TEST_AP_CAPABLE_LIST"
  else
    local list_file="${WIFI_5GHZ_AP_CAPABLE_FILE:-/run/hookprobe/wifi-5ghz-ap-capable}"
    if [ -r "$list_file" ]; then content=$(cat "$list_file" 2>/dev/null || true); fi
  fi
  [ -n "$content" ] || return 0
  local i n=${#CAND_CONTROL[@]}
  for ((i = 0; i < n; i++)); do
    local fp c found=0
    fp=$(channel_footprint "${CAND_CONTROL[$i]}" 80)
    for c in $fp; do
      case " $content " in *" $c "*) found=1 ;; esac
    done
    [ "$found" -eq 1 ] || CAND_APCAP[i]=0
  done
}

# --- D26 measurement parsing --------------------------------------------------------------------

# `iw dev <ap> survey dump` -> busy_ratio (0-100) for a specific target channel, or empty if that
# channel isn't in the sample (radio wasn't on it / dump unavailable).
parse_survey_busy() {
  local text="$1" want_ch="$2"
  local want_freq=$((5000 + 5 * want_ch))
  printf '%s\n' "$text" | awk -v wf="$want_freq" '
    /frequency:/        { freq = $2 + 0; active = ""; busy = "" }
    /channel active time:/ { active = $4 + 0 }
    /channel busy time:/   { busy = $4 + 0
      if (freq == wf && active > 0) { printf "%d\n", int((busy * 100) / active) }
    }'
}

# `iw dev <ap> scan` -> "channel weight" lines (one per BSS with a 5GHz freq), signal-weighted so a
# strong neighbour counts more (D26: "weighted so a strong neighbour counts more").
parse_scan_bss_counts() {
  printf '%s\n' "$1" | awk '
    /^BSS /  { freq = "" }
    /freq:/  { freq = $2 + 0 }
    /signal:/ {
      sig = $2 + 0
      if (freq >= 5000) {
        ch = int((freq - 5000) / 5)
        w = 1
        if (sig >= -50) w = 4
        else if (sig >= -60) w = 3
        else if (sig >= -70) w = 2
        printf "%d %d\n", ch, w
      }
    }'
}

# Sum weighted BSS counts into CAND_BSS[], bucketed by each observed channel's block control.
apply_bss_counts() {
  local scan_text="$1" i n=${#CAND_CONTROL[@]} ch w ctrl
  for ((i = 0; i < n; i++)); do CAND_BSS[i]=0; done
  while read -r ch w; do
    [ -n "${ch:-}" ] || continue
    ctrl=$(block_control_for "$ch")
    for ((i = 0; i < n; i++)); do
      if [ "${CAND_CONTROL[$i]}" = "$ctrl" ]; then CAND_BSS[i]=$((CAND_BSS[i] + w)); fi
    done
  done < <(parse_scan_bss_counts "$scan_text")
}

# D26: a targeted off-channel survey — briefly retunes the AP radio to sample `iw survey dump` for
# a channel it is NOT currently on (the AP is briefly down for the dwell). Best-effort: any failure
# (no iw, retune refused) degrades to scan-only scoring for that candidate, never fatal. Injectable
# via TEST_OFFCHAN_BUSY_<ch> so the decision logic is testable without real hardware (the retune
# itself is the one piece the ADR itself calls "cannot validate without hardware").
offchannel_survey() {
  local ch="$1"
  local var="TEST_OFFCHAN_BUSY_${ch}"
  if declare -p "$var" >/dev/null 2>&1; then echo "${!var}"; return 0; fi
  command -v iw >/dev/null 2>&1 || { echo ""; return 0; }
  local freq=$((5000 + 5 * ch))
  systemctl stop "hookprobe-hostapd@$IFACE.service" 2>/dev/null || true
  if ! iw dev "$IFACE" set freq "$freq" >/dev/null 2>&1; then
    systemctl start "hookprobe-hostapd@$IFACE.service" 2>/dev/null || true
    echo ""; return 0
  fi
  [ -n "${TEST_SKIP_SLEEP:-}" ] || sleep "$OFFCHANNEL_DWELL_S"
  local out; out=$(iw dev "$IFACE" survey dump 2>/dev/null || true)
  systemctl start "hookprobe-hostapd@$IFACE.service" 2>/dev/null || true
  parse_survey_busy "$out" "$ch"
}

# Off-channel-survey only the TOP 1-2 scan-ranked ap_capable candidates (D26's disruption budget).
offchannel_survey_top_candidates() {
  command -v iw >/dev/null 2>&1 || { log "iw unavailable — scan-only scoring for every candidate"; return 0; }
  local n=${#CAND_CONTROL[@]} i
  local -a idxs=()
  for ((i = 0; i < n; i++)); do
    if [ "${CAND_APCAP[$i]}" = 1 ]; then idxs+=("$i"); fi
  done
  [ "${#idxs[@]}" -gt 0 ] || return 0
  local sorted count=0
  sorted=$(for i in "${idxs[@]}"; do echo "${CAND_BSS[$i]:-0} $i"; done | sort -rn -k1,1 | awk '{print $2}')
  for i in $sorted; do
    if [ "$count" -ge 2 ]; then break; fi
    local busy; busy=$(offchannel_survey "${CAND_CONTROL[$i]}")
    if [ -n "$busy" ]; then CAND_BUSY[i]="$busy"; fi
    count=$((count + 1))
  done
}

# --- D28/D29: select the best candidate (mirrors select_optimized_channel) --------------------
# args: current_control current_busy(may be empty) current_bss current_eirp current_dfs
#       current_cac switch_margin
# Echoes: "keep <reason-word> <current_score>"  OR  "switch <candidate_index> <candidate_score>"
select_decision_sh() {
  local cur_ctrl="$1" cur_busy="$2" cur_bss="$3" cur_eirp="$4" cur_dfs="$5" cur_cac="$6" margin="$7"
  local cur_score; cur_score=$(score_block_sh "$cur_busy" "$cur_bss" "$cur_eirp" "$cur_dfs" "$cur_cac")
  if [ -n "$cur_busy" ] && [ "$cur_busy" -lt "$QUIET_FLOOR_BUSY" ]; then
    echo "keep quiet_floor $cur_score"; return 0
  fi
  local i n=${#CAND_CONTROL[@]} best_i=-1 best_score="" s
  for ((i = 0; i < n; i++)); do
    [ "${CAND_APCAP[$i]}" = 1 ] || continue
    [ "${CAND_CONTROL[$i]}" = "$cur_ctrl" ] && continue
    s=$(score_block_sh "${CAND_BUSY[$i]}" "${CAND_BSS[$i]}" "${CAND_EIRP[$i]}" "${CAND_DFS[$i]}" "${CAND_CAC[$i]}")
    if [ -z "$best_score" ] || [ "$s" -lt "$best_score" ]; then best_score="$s"; best_i="$i"; fi
  done
  if [ "$best_i" -lt 0 ]; then echo "keep no_candidate $cur_score"; return 0; fi
  if [ $((best_score + margin)) -le "$cur_score" ]; then
    echo "switch $best_i $best_score"
  else
    echo "keep not_better $cur_score"
  fi
}

# --- D24: intent readers ------------------------------------------------------------------------

# Extract the raw child lines of the `wifi: ap: optimize:` block (2 levels of indentation below
# `optimize:`) from an intent file — a lightweight indentation-scoped extractor, NOT a full YAML
# parser (mirrors this codebase's existing `read_band_intent`/regdomain-apply.sh sed convention).
extract_optimize_block() {
  local f="$1"
  [ -r "$f" ] || return 0
  awk '
    /^[[:space:]]*ap:[[:space:]]*$/ { in_ap = 1; next }
    in_ap && /^[[:space:]]*optimize:[[:space:]]*$/ {
      in_opt = 1; match($0, /^[[:space:]]*/); opt_indent = RLENGTH; next
    }
    in_opt {
      if ($0 ~ /^[[:space:]]*$/) next
      match($0, /^[[:space:]]*/); ind = RLENGTH
      if (ind <= opt_indent) { in_opt = 0; in_ap = 0; next }
      print
    }
  ' "$f"
}

read_optimize_field() {
  local field="$1" f val
  for f in "${WIFI_OPTIMIZE_INTENT_FILES[@]}"; do
    if [ -r "$f" ]; then
      val=$(extract_optimize_block "$f" | sed -n "s/^[[:space:]]*${field}:[[:space:]]*\"\\?\\([^\"[:space:]]*\\)\"\\?.*/\\1/p" | head -1)
      if [ -n "$val" ]; then echo "$val"; return 0; fi
    fi
  done
  echo ""
}

read_optimize_bool() {
  local field="$1" default="$2" val
  val=$(read_optimize_field "$field")
  case "$val" in
    true|True|TRUE) echo true ;;
    false|False|FALSE) echo false ;;
    *) echo "$default" ;;
  esac
}

read_optimize_min_improvement() {
  local val; val=$(read_optimize_field min_improvement)
  case "$val" in
    ''|*[!0-9]*) echo "$MIN_IMPROVEMENT_DEFAULT" ;;
    *) echo "$val" ;;
  esac
}

# The operator's `wifi.ap.channel` hard pin (D24 prio-1) — disables the optimizer's channel
# authority entirely when set (any real integer).
read_ap_channel_pin() {
  local f val
  for f in "${WIFI_BAND_INTENT_FILES[@]}"; do
    if [ -r "$f" ]; then
      val=$(sed -n 's/^[[:space:]]*channel:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$f" | head -1)
      if [ -n "$val" ]; then echo "$val"; return 0; fi
    fi
  done
  echo ""
}

# --- 5GHz / ch144 radio capability probes (`iw phy … info`) -------------------------------------
_phy_info() {
  if [ -n "${TEST_IW_PHY_INFO+x}" ]; then
    printf '%s\n' "$TEST_IW_PHY_INFO"
    return 0
  fi
  command -v iw >/dev/null 2>&1 || return 0
  local phy; phy=$(cat "/sys/class/net/$1/phy80211/name" 2>/dev/null || true)
  if [ -n "$phy" ]; then iw phy "$phy" info 2>/dev/null || true; fi
}

radio_is_5ghz_capable() {
  _phy_info "$1" | grep -qE '\* 5[0-9]{3}(\.[0-9]+)? MHz' && echo true || echo false
}

radio_advertises_ch144() {
  _phy_info "$1" | grep -q '\[144\]' && echo true || echo false
}

# --- JSON scratch-file field reader (generic; mirrors read_band_lkg_label's pattern) ------------
json_field() {
  local f="$1" k="$2"
  [ -r "$f" ] || return 0
  sed -n "s/.*\"$k\"[[:space:]]*:[[:space:]]*\"\\?\\([^\",}]*\\)\"\\?.*/\\1/p" "$f" | head -1
}

# --- D30 optimize-state persistence --------------------------------------------------------------
load_state() {
  DFS_AP_SUPPORTED="null"
  BLOCKED_CHANNELS=()
  [ -r "$STATE_FILE" ] || return 0
  local s_cc s_radio blocked_line
  s_cc=$(json_field "$STATE_FILE" cc)
  s_radio=$(json_field "$STATE_FILE" radio_id)
  if [ "${s_cc^^}" != "${cc^^}" ] || [ "$s_radio" != "$radio_id" ]; then
    log "optimize-state invalid for cc=$cc radio=$radio_id (was cc=$s_cc radio=$s_radio) — resetting (D30 re-test DFS)"
    return 0
  fi
  DFS_AP_SUPPORTED=$(json_field "$STATE_FILE" dfs_ap_supported)
  [ -n "$DFS_AP_SUPPORTED" ] || DFS_AP_SUPPORTED="null"
  blocked_line=$(sed -n 's/.*"blocked_channels"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p' "$STATE_FILE" | head -1)
  if [ -n "$blocked_line" ]; then
    IFS=',' read -ra BLOCKED_CHANNELS <<<"$(printf '%s' "$blocked_line" | tr -d '[:space:]')"
  fi
}

mark_dfs_blocked() {
  local ch="$1" c
  for c in "${BLOCKED_CHANNELS[@]:-}"; do
    if [ "$c" = "$ch" ]; then return 0; fi
  done
  BLOCKED_CHANNELS+=("$ch")
}

blocked_csv() {
  local IFS=,; echo "${BLOCKED_CHANNELS[*]:-}"
}

write_optimize_state() {
  local dfssup="$1" curch="$2" curscore="$3"
  mkdir -p "$(dirname "$STATE_FILE")" 2>/dev/null || return 0
  cat > "$STATE_FILE" <<EOF 2>/dev/null || true
{
  "cc": "$cc",
  "radio_id": "$radio_id",
  "dfs_ap_supported": $dfssup,
  "blocked_channels": [$(blocked_csv)],
  "current_channel": $curch,
  "current_score": $curscore,
  "last_run": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
}

# --- D31 channel-LKG persistence -----------------------------------------------------------------
write_channel_lkg() {
  local ctrl="$1" center="$2" width="$3" dfs_json="$4" score="$5"
  mkdir -p "$(dirname "$LKG_FILE")" 2>/dev/null || return 0
  cat > "$LKG_FILE" <<EOF 2>/dev/null || true
{
  "cc": "$cc",
  "radio_id": "$radio_id",
  "control_channel": $ctrl,
  "center_idx": $center,
  "width_mhz": $width,
  "dfs": $dfs_json,
  "score": $score,
  "validated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
}

# --- D32 evidence artifact ------------------------------------------------------------------------
build_candidates_json() {
  local i n=${#CAND_CONTROL[@]} json="" s dfs_j apcap_j busy_j
  for ((i = 0; i < n; i++)); do
    s=$(score_block_sh "${CAND_BUSY[$i]}" "${CAND_BSS[$i]}" "${CAND_EIRP[$i]}" "${CAND_DFS[$i]}" "${CAND_CAC[$i]}")
    [ "${CAND_DFS[$i]}" = 1 ] && dfs_j=true || dfs_j=false
    [ "${CAND_APCAP[$i]}" = 1 ] && apcap_j=true || apcap_j=false
    [ -n "${CAND_BUSY[$i]}" ] && busy_j="${CAND_BUSY[$i]}" || busy_j=null
    json="${json:+$json,}{\"label\":\"${CAND_LABEL[$i]}\",\"control_channel\":${CAND_CONTROL[$i]},\"center_idx\":${CAND_CENTER[$i]},\"busy_ratio\":$busy_j,\"bss_count\":${CAND_BSS[$i]},\"max_eirp_dbm\":${CAND_EIRP[$i]},\"dfs\":$dfs_j,\"cac_seconds\":${CAND_CAC[$i]},\"score\":$s,\"admitted\":$apcap_j}"
  done
  echo "$json"
}

write_outcome() {
  local trigger="$1" decision="$2" verify="$3" candidates_json="$4" committed="$5"
  mkdir -p "$(dirname "$STATUS")" 2>/dev/null || true
  cat > "$STATUS" <<EOF 2>/dev/null || true
{
  "iface": "$IFACE",
  "trigger": "$trigger",
  "cc": "$cc",
  "radio_id": "$radio_id",
  "decision": "$decision",
  "verify": "$verify",
  "candidates": [ $candidates_json ],
  "committed_channel": $committed,
  "dfs_ap_supported": ${DFS_AP_SUPPORTED:-null},
  "decided_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
  log "wrote optimize status -> $STATUS (decision=$decision verify=$verify committed_channel=$committed)"
}

write_skip_outcome() {
  local trigger="$1" reason="$2"
  mkdir -p "$(dirname "$STATUS")" 2>/dev/null || true
  cat > "$STATUS" <<EOF 2>/dev/null || true
{
  "iface": "${IFACE:-unknown}",
  "trigger": "$trigger",
  "cc": "${cc:-00}",
  "radio_id": "${radio_id:-unknown}",
  "decision": "skip",
  "verify": "$reason",
  "candidates": [],
  "committed_channel": null,
  "dfs_ap_supported": null,
  "decided_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
  log "skip: $reason"
}

# --- D20/D29 rendering + apply/observe (reuses render_rung/mark_dmesg/clean_restart/observe_rung
# from wifi-calibrate.sh — see the file header) --------------------------------------------------
prepare_render_context() {
  BASE_SSID="HookProbe"
  BASE_SEC=""
  if [ -r "$CONF" ]; then
    local ssid_from_conf
    ssid_from_conf=$(sed -n 's/^ssid=\(.*\)/\1/p' "$CONF" | head -1)
    [ -n "$ssid_from_conf" ] && BASE_SSID="$ssid_from_conf"
    BASE_SEC=$(grep -E '^(auth_algs|wpa|wpa_key_mgmt|rsn_pairwise|wpa_passphrase|ieee8021x|auth_server|dynamic_vlan|vlan_file|ignore_broadcast_ssid)=' "$CONF" || true)
  fi
  if [ "$cc" = "00" ]; then COUNTRY_LINES=""; else COUNTRY_LINES="country_code=$cc"$'\n'"ieee80211d=1"$'\n'; fi
}

# Render a DFS-AWARE hostapd conf for a candidate block (D29 step 4a): control ch40 reuses the
# proven-on-metal $VHT80_LINES ([HT40-], center 42, sourced from wifi-calibrate.sh) verbatim; every
# other block is the lowest channel of its pair (always [HT40+], mirrors wifi_cfg::vht80_params'
# UNII-3 direction convention) with its own center_idx.
#
# BUG-W10 (2026-07-17 audit): this used to append `ieee80211h=1` for DFS blocks, mirroring an
# OUTDATED theory ("a FullMAC that rejects it → the D30 DFS-support signal"). That is WRONG on two
# counts, both now proven: (1) `ieee80211h=1` CRASH-LOOPS hostapd on the shipped brcmfmac FullMAC
# firmware (the firmware runs DFS/CAC internally; 802.11h is a SoftMAC/mac80211 concept) — the exact
# reason `wifi_cfg::width_lines` NEVER emits it; and (2) brcmfmac cannot do DFS-AP at all, for a
# regdomain-handoff reason unrelated to 802.11h (ADR 0034 RC-DFS), so the "crash = capability test"
# logic was measuring a config artifact, not hardware. So we NO LONGER emit `ieee80211h` here —
# matching the boot-ladder renderer. (When a real SoftMAC/DFS-capable radio is onboarded per ADR 0042,
# CAC signaling must be re-added RADIO-CONDITIONALLY, not unconditionally — a brcmfmac must never see
# it. Moot today: `allow_dfs` defaults false on this hardware, so this DFS path is dead.)
render_candidate_conf() {
  local control="$1" center="$2" dfs="$3" ht_lines ht_dir
  # 2026-07-17 (BUG-W9): the secondary-channel direction must be DERIVED from where the control sits
  # in its own 80 MHz block, not hardcoded to ch40. A block's four channels are
  # center-6/center-2/center+2/center+6; the HT40 pairs are (c1,c2) and (c3,c4), so a control that is
  # the block's 2ND channel (center-2 — exactly what `block_control_for` returns for 40/56/104/120/
  # 136, per its own [HT40-] rule) has its secondary BELOW → `[HT40-]`, while a block-anchor control
  # (center-6, e.g. UNII-3's 149) has it ABOVE → `[HT40+]`. The old `control -eq 40` special-case got
  # ch40 right by luck and silently emitted the WRONG `[HT40+]` for 56/104/120/136 — contradicting
  # block_control_for's own documented contract. Unreachable while `allow_dfs: false` (ADR 0034
  # RC-DFS) since those are all DFS, but a live bug the moment a SoftMAC radio enables them.
  if [ "$center" -eq "$((control + 2))" ]; then ht_dir="[HT40-]"; else ht_dir="[HT40+]"; fi
  if [ "$control" -eq 40 ]; then
    ht_lines="$VHT80_LINES"
  else
    ht_lines='ht_capab='"$ht_dir"$'[SHORT-GI-20][SHORT-GI-40]\nieee80211ac=1\nvht_capab=[SHORT-GI-80]\nvht_oper_chwidth=1\nvht_oper_centr_freq_seg0_idx='"$center"$'\n'
  fi
  # BUG-W10: intentionally NO `ieee80211h` for DFS candidates — see the function header. The `$dfs`
  # arg is still consumed by the CAC-wait timing in `apply_and_observe` (dfs_cac_seconds), not here.
  : "${dfs:-0}"   # $3 is deliberately NOT rendered into the conf (silences "unused" concern)
  render_rung "$IFACE" a "$control" "$ht_lines"
}

# Apply a candidate + clean-restart + settle (DFS-aware) + observe. Echoes "oper_ch oper_mhz fails rc"
# (rc: 0=Stable 1=WidthCollapsed 2=ChanspecFailStorm 3=Down — the observe_rung/Stability contract).
apply_and_observe() {
  local control="$1" center="$2" dfs="$3" settle rc obs_out
  render_candidate_conf "$control" "$center" "$dfs"
  mark_dmesg
  clean_restart
  if [ "$dfs" = 1 ]; then
    local cac; cac=$(dfs_cac_seconds "$control" 80)
    if [ "$cac" -ge 600 ]; then settle="$DFS_SETTLE_METEO"; else settle="$DFS_SETTLE_STANDARD"; fi
  else
    settle="$NONDFS_SETTLE"
  fi
  [ -n "${TEST_SKIP_SLEEP:-}" ] || sleep "$settle"
  obs_out=$(observe_rung "$control" 80) && rc=0 || rc=$?
  echo "$obs_out $rc"
}

# --- D31: fast post-boot restore of a persisted DFS channel-LKG, within one CAC of boot ----------
do_reapply() {
  # Defensive defaults for $MODEL/$LEARN_NOW/$LEARN_FILE: `main()` always sets these before calling
  # here, but a test harness (or any other future direct caller) may invoke `do_reapply` on its own
  # — under `set -u` an entirely-unset (not just empty) $MODEL would abort the whole script. An
  # empty $MODEL degrades every `learn_*` call to its own documented no-op (see learn_record's `||`
  # fallback) — never a crash, just "this call recorded nothing."
  : "${MODEL:=}"
  : "${LEARN_NOW:=$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
  : "${LEARN_FILE:=${WIFI_LEARN_FILE:-${WIFI_LEARN_DIR:-/var/lib/hookprobe}/wifi-learn-${IFACE:-wlan0}.json}}"
  if [ ! -r "$LKG_FILE" ]; then
    log "no channel-LKG at $LKG_FILE — nothing to reapply"
    write_skip_outcome reapply "no_channel_lkg"
    return 0
  fi
  local lkg_cc lkg_radio lkg_ctrl lkg_center lkg_dfs
  lkg_cc=$(json_field "$LKG_FILE" cc)
  lkg_radio=$(json_field "$LKG_FILE" radio_id)
  lkg_ctrl=$(json_field "$LKG_FILE" control_channel)
  lkg_center=$(json_field "$LKG_FILE" center_idx)
  lkg_dfs=$(json_field "$LKG_FILE" dfs)
  if [ "${lkg_cc^^}" != "${cc^^}" ] || [ "$lkg_radio" != "$radio_id" ]; then
    log "channel-LKG invalid for cc=$cc radio=$radio_id (was cc=$lkg_cc radio=$lkg_radio) — clearing, staying on the boot ladder's own choice"
    rm -f "$LKG_FILE" 2>/dev/null || true
    write_skip_outcome reapply "channel_lkg_invalid"
    return 0
  fi
  if [ "$lkg_dfs" != "true" ]; then
    log "channel-LKG (ch$lkg_ctrl) is non-DFS — already applied BootFast by the boot ladder's own render, nothing to reapply"
    write_skip_outcome reapply "nondfs_already_bootfast"
    return 0
  fi
  log "reapply: validating persisted DFS channel-LKG ch$lkg_ctrl (center $lkg_center) within one CAC of boot"
  local result o_ch o_mhz o_fails o_rc
  result=$(apply_and_observe "$lkg_ctrl" "$lkg_center" 1)
  read -r o_ch o_mhz o_fails o_rc <<<"$result"
  MODEL=$(learn_record "$MODEL" "$radio_id" "$cc" "$lkg_ctrl" 80 "$(rc_to_verdict "$o_rc")" "$LEARN_NOW")
  if [ "$o_rc" -eq 0 ]; then
    log "reapply: ch$lkg_ctrl HELD — DFS channel silently restored (ch=$o_ch width=${o_mhz}MHz)"
    write_channel_lkg "$lkg_ctrl" "$lkg_center" 80 true "$(json_field "$LKG_FILE" score)"
    DFS_AP_SUPPORTED=true
    write_optimize_state true "$lkg_ctrl" 0
    write_outcome reapply switch committed "" "$lkg_ctrl"
    learn_export_channel_lkg "$MODEL" "$cc" "$radio_id" "[[$lkg_ctrl,80]]" "$LEARN_NOW" "$LKG_FILE"
  else
    log "reapply: ch$lkg_ctrl did NOT hold (rc=$o_rc) — reverting to ch40 + clearing the disproven LKG"
    local anchor_out anchor_rc
    anchor_out=$(apply_and_observe 40 42 0) || true
    read -r _ _ _ anchor_rc <<<"$anchor_out"
    MODEL=$(learn_record "$MODEL" "$radio_id" "$cc" 40 80 "$(rc_to_verdict "${anchor_rc:-0}")" "$LEARN_NOW")
    rm -f "$LKG_FILE" 2>/dev/null || true
    mark_dfs_blocked "$lkg_ctrl"
    if [ "$o_rc" -eq 3 ]; then DFS_AP_SUPPORTED=false; fi
    write_optimize_state "${DFS_AP_SUPPORTED:-null}" 40 0
    write_outcome reapply switch reverted_failed_to_hold "" 40
  fi
}

# --- D29: the full nightly/on-demand survey -> score -> select -> validate -> commit/revert run -
do_optimize() {
  # See do_reapply's identical comment: defensive defaults so a direct caller (test harness) never
  # hits an unbound-variable abort under `set -u`.
  : "${MODEL:=}"
  : "${LEARN_NOW:=$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
  : "${LEARN_FILE:=${WIFI_LEARN_FILE:-${WIFI_LEARN_DIR:-/var/lib/hookprobe}/wifi-learn-${IFACE:-wlan0}.json}}"
  local trigger="$1" info oper_ch oper_mhz cur_control cur_center cur_dfs
  if [ -n "${TEST_IW_INFO+x}" ]; then info="$TEST_IW_INFO"
  elif command -v iw >/dev/null 2>&1; then info=$(iw dev "$IFACE" info 2>/dev/null || true)
  else info=""; fi
  oper_ch=$(printf '%s\n' "$info" | sed -n 's/.*channel \([0-9]\+\).*/\1/p' | head -1)
  oper_mhz=$(printf '%s\n' "$info" | sed -n 's/.*width: \([0-9]\+\) MHz.*/\1/p' | head -1)
  [ -n "$oper_ch" ] || oper_ch=40
  if [ -n "$oper_mhz" ] && [ "$oper_mhz" != 80 ]; then
    log "current operating width is ${oper_mhz}MHz, not VHT80 — this optimizer only manages VHT80 blocks (the boot ladder owns width step-down); skipping this run"
    write_skip_outcome "$trigger" "not_vht80"
    return 0
  fi
  cur_control=$(block_control_for "$oper_ch")
  cur_center=$(center_idx_for "$cur_control")
  cur_dfs=0
  if is_dfs_control "$cur_control"; then cur_dfs=1; fi

  # 1. MEASURE (D26)
  local scan_text survey_text cur_busy
  if [ -n "${TEST_IW_SCAN+x}" ]; then scan_text="$TEST_IW_SCAN"
  elif command -v iw >/dev/null 2>&1; then scan_text=$(iw dev "$IFACE" scan 2>/dev/null || true)
  else scan_text=""; fi
  if [ -n "${TEST_IW_SURVEY+x}" ]; then survey_text="$TEST_IW_SURVEY"
  elif command -v iw >/dev/null 2>&1; then survey_text=$(iw dev "$IFACE" survey dump 2>/dev/null || true)
  else survey_text=""; fi
  cur_busy=$(parse_survey_busy "$survey_text" "$cur_control")

  # D36: the currently-serving channel is itself an ongoing "did it hold?" observation — it is
  # live and AP-ENABLED right now, so this run's measurement folds in as a `stable` sample (with
  # its survey busy_ratio, if any) even before any candidate is validated.
  MODEL=$(learn_record "$MODEL" "$radio_id" "$cc" "$cur_control" 80 stable "$LEARN_NOW" "$cur_busy")

  # 2. ENUMERATE (D27) + measure (D26 scan + targeted off-channel survey)
  local ch144_capable; ch144_capable=$(radio_advertises_ch144 "$IFACE")
  enumerate_candidates "$cc" "$ALLOW_DFS" "$ALLOW_METEO" "$ch144_capable" "$DFS_AP_SUPPORTED" "${BLOCKED_CHANNELS[@]:-}"
  apply_no_ir_filter
  apply_bss_counts "$scan_text"
  offchannel_survey_top_candidates

  # 3. SCORE + SELECT (D28)
  local margin cur_cac decision_out kind arg1 arg2
  margin=$(( MIN_IMPROVEMENT * SWITCH_MARGIN_DEFAULT / MIN_IMPROVEMENT_DEFAULT ))
  cur_cac=$(dfs_cac_seconds "$cur_control" 80)
  decision_out=$(select_decision_sh "$cur_control" "$cur_busy" 0 23 "$cur_dfs" "$cur_cac" "$margin")
  read -r kind arg1 arg2 <<<"$decision_out"

  if [ "$kind" = keep ]; then
    log "decision: KEEP ch$cur_control (reason=$arg1 score=$arg2)"
    write_optimize_state "${DFS_AP_SUPPORTED:-null}" "$cur_control" "$arg2"
    write_outcome "$trigger" keep "$arg1" "$(build_candidates_json)" "$cur_control"
    return 0
  fi

  local idx="$arg1" bscore="$arg2"
  local to_ctrl="${CAND_CONTROL[$idx]}" to_center="${CAND_CENTER[$idx]}" to_dfs="${CAND_DFS[$idx]}"
  log "decision: SWITCH ch$cur_control -> ch$to_ctrl (candidate score $bscore, margin $margin)"

  # 4. VALIDATE (D29 step 4)
  local result o_ch o_mhz o_fails rc
  result=$(apply_and_observe "$to_ctrl" "$to_center" "$to_dfs")
  read -r o_ch o_mhz o_fails rc <<<"$result"
  # D36: fold the VALIDATE verdict into the model — this IS the same `verify_rung`-equivalent
  # binary hold signal the boot ladder feeds, just measured by this run instead.
  MODEL=$(learn_record "$MODEL" "$radio_id" "$cc" "$to_ctrl" 80 "$(rc_to_verdict "$rc")" "$LEARN_NOW")

  if [ "$rc" -eq 0 ]; then
    log "VALIDATE: ch$to_ctrl HELD (ch=$o_ch width=${o_mhz}MHz) — COMMITTING"
    local dfs_json=false; if [ "$to_dfs" = 1 ]; then dfs_json=true; fi
    write_channel_lkg "$to_ctrl" "$to_center" 80 "$dfs_json" "$bscore"
    if [ "$to_dfs" = 1 ]; then DFS_AP_SUPPORTED=true; fi
    write_optimize_state "${DFS_AP_SUPPORTED:-null}" "$to_ctrl" "$bscore"
    write_outcome "$trigger" switch committed "$(build_candidates_json)" "$to_ctrl"
    # D35/D42: regenerate the channel-LKG export FROM the model (a superset check of the direct
    # write_channel_lkg above — when jq/the model agree, as they will here since this exact
    # observation was just recorded, this simply re-confirms the same file from the source of truth).
    learn_export_channel_lkg "$MODEL" "$cc" "$radio_id" "[[$to_ctrl,80],[$cur_control,80]]" "$LEARN_NOW" "$LKG_FILE"
    return 0
  fi

  # 5. REVERT — ordered: previous channel -> ch40 anchor -> hand off to the calibrate ladder (D29).
  log "VALIDATE: ch$to_ctrl did NOT hold (rc=$rc, fails=$o_fails) — REVERTING"
  local verify=reverted_failed_to_hold
  if [ "$to_dfs" = 1 ]; then
    mark_dfs_blocked "$to_ctrl"
    if [ "$rc" -eq 3 ]; then
      # hostapd refused ieee80211h/DFS outright => this radio proven DFS-incapable (D30).
      DFS_AP_SUPPORTED=false
      verify=reverted_cac_timeout
    fi
  fi
  local revert_out revert_rc committed="$cur_control"
  revert_out=$(apply_and_observe "$cur_control" "$cur_center" "$cur_dfs")
  read -r _ _ _ revert_rc <<<"$revert_out"
  MODEL=$(learn_record "$MODEL" "$radio_id" "$cc" "$cur_control" 80 "$(rc_to_verdict "$revert_rc")" "$LEARN_NOW")
  if [ "$revert_rc" -ne 0 ]; then
    log "REVERT: previous ch$cur_control ALSO did not hold — falling to the ch40 anchor"
    local anchor_out anchor_rc
    anchor_out=$(apply_and_observe 40 42 0)
    read -r _ _ _ anchor_rc <<<"$anchor_out"
    MODEL=$(learn_record "$MODEL" "$radio_id" "$cc" 40 80 "$(rc_to_verdict "$anchor_rc")" "$LEARN_NOW")
    committed=40
    if [ "$anchor_rc" -ne 0 ]; then
      log "REVERT: even ch40 did not hold — handing off to the calibrate ladder (never leaving the AP down)"
      systemctl start --no-block "hookprobe-wifi-calibrate@$IFACE.service" 2>/dev/null || true
    fi
  fi
  write_optimize_state "${DFS_AP_SUPPORTED:-null}" "$committed" 0
  write_outcome "$trigger" switch "$verify" "$(build_candidates_json)" "$committed"
}

# ===============================================================================================
# main — guarded so this file can be `source`d (by test-wifi-optimize.sh) to unit-exercise the
# functions above without touching a real radio/hostapd. Mirrors wifi-calibrate.sh's own guard.
# ===============================================================================================
main() {
  IFACE=${1:-wlan0}
  MODE=${2:-optimize}
  CONF="$HOSTAPD_DIR/hostapd-$IFACE.conf"
  STATE_FILE=${WIFI_OPTIMIZE_STATE_FILE:-$STATE_DIR/wifi-optimize-state-$IFACE.json}
  LKG_FILE=${WIFI_CHANNEL_LKG_FILE:-$STATE_DIR/wifi-channel-lkg-$IFACE.json}

  # Regulatory country — READ-ONLY, exactly like wifi-calibrate.sh (this script never re-resolves
  # it or calls `iw reg set`; a runtime regdomain change is the D11 oneshots' job, not this one's).
  local run_cc_file="${WIFI_COUNTRY_FILE:-/run/hookprobe/wifi-country}"
  cc="00"
  if [ -r "$run_cc_file" ]; then
    cc=$(tr -dc 'A-Za-z0-9' <"$run_cc_file" 2>/dev/null | head -c2)
    cc=${cc^^}
    [ "${#cc}" -eq 2 ] || cc="00"
  fi
  radio_id=$(radio_fingerprint "$IFACE")

  # --- D24 GUARDS (step 0) — anything below `return`s a documented skip reason and NEVER touches
  # the radio. Every guard is evaluated before any measurement/apply. ---------------------------
  local band_pin; band_pin=$(normalize_band_pin "$(read_band_intent)")
  if [ "$band_pin" = "2.4" ]; then
    log "band hard-pinned to 2.4GHz — nothing to optimize"
    write_skip_outcome "$MODE" "band_pin_24"
    return 0
  fi

  local enabled; enabled=$(read_optimize_bool enabled true)
  if [ "$enabled" != true ]; then
    log "optimizer disabled by intent (wifi.ap.optimize.enabled: false)"
    write_skip_outcome "$MODE" "disabled_by_intent"
    return 0
  fi

  local pin_ch; pin_ch=$(read_ap_channel_pin)
  if [ -n "$pin_ch" ]; then
    log "operator channel pin (wifi.ap.channel: $pin_ch) active — optimizer channel authority disabled (D24 prio-1)"
    write_skip_outcome "$MODE" "operator_pin_active"
    return 0
  fi

  local fiveg; fiveg=$(radio_is_5ghz_capable "$IFACE")
  if [ "$fiveg" != true ]; then
    log "radio not 5GHz-capable — nothing to optimize"
    write_skip_outcome "$MODE" "not_5ghz_capable"
    return 0
  fi

  # CD1 (2026-07-17 audit): default FALSE — must match the Rust core (`wifi_calibrate.rs`
  # `optimize_intent`: `allow_dfs … unwrap_or(false)`), `network.example.yaml` (ships `false`), and
  # ADR 0034 RC-DFS ("the shipped brcmfmac FullMAC cannot do DFS-AP; trying it just wastes a 3AM
  # cycle + briefly disrupts the AP"). The old `true` default silently re-enabled known-broken DFS
  # attempts for any intent file that omits the field (a hand-written minimal config, or a device
  # provisioned before this field existed).
  ALLOW_DFS=$(read_optimize_bool allow_dfs false)
  ALLOW_METEO=$(read_optimize_bool allow_meteo false)
  MIN_IMPROVEMENT=$(read_optimize_min_improvement)

  mask_supplicant_on_ap
  prepare_render_context
  load_state

  # ADR 0034 D35-D44: the SAME learning-model store wifi-calibrate.sh consults/records into
  # (`wifi-learn-<iface>.json`) — one accumulating knowledge base fed by BOTH the boot ladder and
  # this 3AM/on-demand optimizer (D36's "single write path"). Loaded/aged once per run; every
  # `apply_and_observe`/current-channel measurement below folds its verdict in via `learn_record`;
  # `learn_export_channel_lkg` regenerates the read-only `wifi-channel-lkg-<iface>.json` export FROM
  # it at the end (D35/D42) — `write_channel_lkg`'s own direct writes stay as the belt-and-suspenders
  # fallback when `jq` is unavailable, exactly like wifi-calibrate.sh's band-LKG export.
  LEARN_NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  LEARN_FILE="${WIFI_LEARN_FILE:-$WIFI_LEARN_DIR/wifi-learn-$IFACE.json}"
  MODEL=$(learn_load "$LEARN_FILE" "$IFACE" "$(fw_fingerprint "$IFACE")" "$LEARN_NOW")
  MODEL=$(learn_age "$MODEL" "$(fw_fingerprint "$IFACE")" "$LEARN_NOW")

  log "cc=$cc radio=$radio_id allow_dfs=$ALLOW_DFS allow_meteo=$ALLOW_METEO min_improvement=$MIN_IMPROVEMENT dfs_ap_supported=$DFS_AP_SUPPORTED blocked=[$(blocked_csv)] mode=$MODE"

  if [ "$MODE" = reapply ]; then
    do_reapply
  else
    do_optimize "$MODE"
  fi

  # Persist whatever this run folded into the model (best-effort; never blocks the outcome writes
  # above, which have already happened by the time we get here).
  learn_save "$MODEL" "$LEARN_FILE"
}

if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
  main "$@"
fi
