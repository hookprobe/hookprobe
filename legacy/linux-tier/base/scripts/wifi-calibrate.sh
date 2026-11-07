#!/usr/bin/env bash
# =============================================================================
# wifi-calibrate.sh — the RUNTIME half of the adaptive Wi-Fi subsystem (ADR 0034), D14 (W4):
# the DFS-bounce-safe verify-retry bring-up.
#
# The DETERMINISTIC decisions (candidate rung ladder, per-rung hostapd rendering, stability
# classification, and the D14 clean-retry-then-step-down action) are pure functions in
# `crates/hookprobe-manifest/src/wifi_calibrate.rs` (`verify_rung`/`next_rung_action`) and are
# unit-tested there. This script is ONLY the runtime feedback loop those functions cannot be: it
# applies each rung, OBSERVES the radio (`iw dev … info`, `dmesg`), and steps DOWN (after a bounded
# number of same-rung clean retries) until stable — writing a status/evidence artifact at the end.
#
# ADR 0034 D14 correction (2026-07-11b): this script does NOT re-resolve the regulatory country or
# call `iw reg set` — that is exclusively the job of the two regdomain oneshots
# (`hookprobe-regdomain.service` boot fast-path / `hookprobe-regdomain-reresolve.service` WAN-online
# re-resolve, D11). Re-setting the regdomain at RUNTIME while hostapd is (or was just) serving is
# exactly the brcmfmac DFS-bounce trigger this loop exists to avoid. This script trusts whatever
# country the regdomain oneshots already applied — it reads `/run/hookprobe/wifi-country` ONCE,
# read-only, and converges WIDTH only.
#
# METAL FIX (2026-07-12, BUG-W5 + BUG-W6 — CM5 + Pi4 onboard BCM43455): ground truth proved the
# brcmfmac radio DOES settle to 5GHz VHT80 and HOLDS it (18s+ stable) — it just needs time to get
# through an initial bounce (`set chanspec … fail` in dmesg, a moment on ch6) before landing on the
# requested chanspec. The loop as it stood observed too early (SETTLE=6s, mid-bounce) AND counted
# stale chanspec-fail lines left over from a PRIOR rung's attempt (a flat `tail -n $DMESG_WINDOW`
# over the whole dmesg ring), so it declared a fail storm and stepped down a radio that would have
# converged. Both are fixed here:
#   BUG-W6 — `mark_dmesg` scopes the chanspec-fail count to ONLY the current attempt (clears the
#            ring buffer with `dmesg -C`, or falls back to a line-count marker) before every
#            `clean_restart`, so a stale fail count from an earlier rung/attempt can never leak in.
#   BUG-W5 — `SETTLE`/`SETTLE_5GHZ` give a 5GHz rung enough time to converge past the bounce, and
#            `observe_rung`'s verdict priority now puts CONVERGENCE first: if the operating
#            channel+width match the request after the settle, the rung is Stable REGARDLESS of any
#            chanspec-fail lines logged getting there (the proven bounce-then-converge pattern).
#            Only a genuine post-settle mismatch falls through to the fail-storm/width-collapse
#            verdicts — so the MAX_RETRIES step-down ladder still fires correctly for a radio that
#            truly never converges, it just no longer fires on one that did.
# Both mirror `wifi_calibrate::verify_rung`'s priority exactly (see that file's same-dated change).
#
# STATUS (2026-07-11): the loop skeleton + the per-rung hostapd rendering here is a MINIMAL inline
# mirror of the Rust ladder for the two universally-safe blocks. Production wiring routes the rung
# rendering through the Rust core (a `hookprobe-supervisor --wifi-calibrate` subcommand that emits
# the ladder + per-rung confs + the CalibrationOutcome JSON) — that subcommand is the next step and
# is NOT built yet. Until then this script falls back to the ordinary `wifi_cfg::render` conf if
# anything is uncertain. It NEVER leaves the AP down: the 2.4/HT20 floor is always the last rung.
#
# TESTABILITY: `observe_rung`/`mark_dmesg` accept synthetic-feed overrides so a sandbox harness can
# drive every Stability verdict deterministically, with no radio/hostapd present —
#   TEST_IW_INFO       — raw `iw dev <iface> info` text (else the real `iw` is invoked)
#   TEST_HOSTAPD_ACTIVE — "1"/"0" (else the real `systemctl is-active` is invoked)
#   TEST_NO_DMESG       — set (any value) to simulate `dmesg` being entirely unavailable
# Actual dmesg CONTENT is never stubbed directly — `mark_dmesg`/`observe_rung`'s dmesg reads always
# go through the real `dmesg` on PATH, and a fixture test proves the BUG-W6 scoping fix by
# shadowing `dmesg` with a stateful fake on PATH, so the real clear/marker mechanism is exercised
# end-to-end, not just its symptom. See base/scripts/test-wifi-calibrate.sh.
# =============================================================================
#
# 2026-07-15 EXTENSION (ADR 0034 D15/D18/D19 — "adaptive 5GHz-first AP band"): three additions on
# TOP of the proven-on-metal loop above (unchanged — see BUG-W5/W6 notes); nothing below alters
# `observe_rung`/`mark_dmesg`/`next_rung_action`/`clean_restart`:
#   D15 — an operator `band:` HARD PIN ("5"/"2.4") now DISABLES the auto-ladder (honored exactly:
#         "5" tries only the 5GHz rungs — the AP MAY end down, an explicit power-user override —
#         "2.4" tries only the single 2.4GHz/HT20 floor rung, the old blunt single-band behaviour).
#         `band: "auto"` (the new shipped default) or absent keeps today's unchanged full ladder
#         (already 5GHz-first, floors at 2.4) — read via `read_band_intent` from the SAME intent
#         files `regdomain-apply.sh` reads (mirrors its `INTENT_FILES` convention).
#   D18 — the 2.4GHz floor/HT40 channel is now DEVICE-DERIVED ({1,6,11} via `default_24_channel`,
#         seeded off this device's own resolved SSID) instead of the constant `ch6` — two
#         co-located boxes flashed from the same image no longer collide on ch6 even at the floor.
#   D19 — band-outcome memory: on a `Stable`/Keep verdict the winning rung is persisted to
#         `/var/lib/hookprobe/wifi-band-lkg-<iface>.json` (DISTINCT from the country-only
#         `regdomain-lkg`); next boot, if the cached rung is still valid for the CURRENT regdomain +
#         radio (`band_lkg_valid`'s shell mirror), the loop starts THERE instead of at the top —
#         eliminating the ~45s VHT80-fail-storm churn every boot on a radio that will never hold it.
#         A regdomain change or a swapped radio (different MAC on this iface) invalidates the cache
#         and the loop re-fights the full ladder from the top, exactly as before this change.
# =============================================================================
#
# 2026-07-15 LADDER FIX (operator's exact 3-rung spec, proven on metal — Pi4 + CM5, brcmfmac
# BCM43455): the D18 4-rung ladder above (VHT80-ch36 / HT40-ch36 / HT20-ch36 / 2.4-floor) is
# REPLACED by exactly 3 rungs, best-first, always ending joinable:
#   1. 5GHz-VHT80-ch40 — control channel 40 (the UNII-1 36-48 block's UPPER secondary), 80 MHz.
#      CRITICAL: control ch40 needs `ht_capab=[HT40-]` (NOT `[HT40+]`) — `vht_oper_centr_freq_
#      seg0_idx` stays 42 (still the 36-48 block, just a different primary). This HOLDS stably on
#      brcmfmac (AP-ENABLED, 80 MHz, no flap). Control ch36 with `[HT40+]` does NOT hold — the
#      firmware drifts to a DFS channel and never settles; ch40/[HT40-] is the ONLY difference that
#      fixes it.
#   2. 5GHz-HT40-ch36 — control channel 36 (the block's LOWER primary), 40 MHz, `[HT40+]`. Proven
#      rock-stable (~150 Mbps) — the safety net if VHT80 doesn't hold.
#   3. 2.4GHz-ch6 — hw_mode=g, channel 6, 20 MHz. The always-joinable floor (terminal, unconditional
#      Keep). This is now a CONSTANT — the D18 per-device {1,6,11} `default_24_channel` derivation
#      is NOT used for this floor rung any more (operator was prescriptive: ch6, always). The
#      function itself is kept below (still exercised by its own D18 unit tests further down) for
#      any other caller that wants per-device 2.4 GHz diversity — just not this ladder's floor.
# The intermediate HT20-ch36 rung is DROPPED (the operator wants exactly 3 stages, not 4).
#
# 2026-07-15 DFS-AWARE SETTLE (coordinator directive — a ROBUSTNESS NET, not exercised by the 3
# shipped rungs above: none of VHT80-ch40 / HT40-ch36 / 2.4-ch6 is a DFS channel; ch40 sits in the
# non-DFS UNII-1 block — DFS starts at ch52). If ANY future rung (a different regdomain, a wider
# ladder) ever proposes a DFS channel (UNII-2A 52-64 / UNII-2C 100-144), the radio must complete a
# regulatory Channel-Availability-Check (a radar listen) before hostapd reaches AP-ENABLED —
# observing at the ordinary 15s settle would misread "still doing CAC" as a failure and wrongly
# step the ladder down. Per ETSI EN 301 893 (the RO/ANCOM and EU-wide numbers this edge targets)
# the CAC is ~60s for ordinary DFS channels, but a full 10 MINUTES (600s) for the METEOROLOGICAL
# radar sub-band 5600-5650 MHz (ch116/120/124/128) — `dfs_cac_seconds`/`select_settle` below mirror
# `wifi_calibrate::dfs_cac_seconds`/`select_settle_seconds` exactly (channel-FOOTPRINT-aware: a
# HT40/VHT80 rung is DFS if ANY channel in its occupied block is), and pick SETTLE_DFS_STANDARD
# (~75s) or SETTLE_DFS_METEO (~660s) instead of the ordinary settle for such a rung.
# =============================================================================
#
# 2026-07-16 METAL FIXES (BUG-1 + BUG-2, real Pi4/CM5 hardware):
#
#   BUG-1 (malformed conf — `ht_capab=[...]wmm_enabled=1` glued onto ONE line, no newline between
#   them): root cause was NOT (only) a missing trailing `\n` on the `_LINES` constants — it was
#   `read -r label band ch mhz ht_lines <<<"$entry"` itself. `read` is line-based: any embedded
#   newline inside `$entry` (both `VHT80_LINES` and `HT40_LINES` are genuinely multi-line) silently
#   TRUNCATES `ht_lines` at the FIRST such newline, dropping both the field's own trailing `\n` AND
#   — for VHT80 specifically — every line after the first (`ieee80211ac=1`/`vht_capab=…`/
#   `vht_oper_chwidth=1`/`vht_oper_centr_freq_seg0_idx=…`), silently downgrading the "VHT80" rung
#   to plain HT40 on top of the glue bug. Fixed at the source: LADDER entries now carry ONLY the 4
#   single-line fields (`label band channel width_mhz`); the actual (possibly multi-line) HT/VHT
#   block is resolved AFTER the safe `read`, by label, via `ht_lines_for_label` — so it can never be
#   clipped by `read`'s splitting again. `render_rung` additionally normalises `ht_lines` to always
#   end in exactly one `\n` (or stay empty) as a second, independent line of defense.
#
#   BUG-2 (VHT80 never reached cold — box caps at HT40): ground truth proved `5GHz-VHT80-ch40`
#   HOLDS rock-solid at 80 MHz once the radio is WARM (already serving), but a genuinely cold
#   brcmfmac radio can still be mid-bounce past the ordinary boot-time settle and get stepped down
#   to `5GHz-HT40-ch36`. Rather than inflating every cold rung's settle, `main` now does exactly
#   ONE bounded warm re-attempt of the next-wider 5GHz rung (with the longer `SETTLE_5GHZ_WARM`)
#   right after the boot ladder settles on a non-top 5GHz rung — converges → commit the upgrade
#   (band-LKG then persists VHT80-ch40 for next boot); doesn't converge → revert to the
#   already-proven rung (the AP is NEVER left down) and record the miss so the learning model
#   doesn't thrash retrying it every cycle. The PURE eligibility/outcome decision this mirrors is
#   `wifi_calibrate::warm_upgrade_candidate`/`warm_upgrade_action`. `SETTLE_5GHZ` also bumps from
#   15s to 20s (cheap, helps some cold radios converge on the first pass without needing the warm
#   re-attempt at all).
# =============================================================================
set -euo pipefail

HOSTAPD_DIR=${HOSTAPD_DIR:-/etc/hostapd}
# D19: band-outcome memory, one file per AP interface (distinct from regdomain-lkg). Path depends
# on $IFACE, which main() only knows at runtime — resolved inside main(), this is just the pattern.
WIFI_BAND_LKG_DIR=${WIFI_BAND_LKG_DIR:-/var/lib/hookprobe}
# D15: the SAME operator intent files regdomain-apply.sh reads (network.yaml nested `wifi.ap.band`,
# then a standalone wifi-intent.yaml) — first real match wins. A separate env var name from the
# `WIFI_INTENT_FILES` *value* (space-separated) avoids the read/overwrite footgun regdomain-apply.sh
# already avoids with its own `INTENT_FILES` array.
read -ra WIFI_BAND_INTENT_FILES <<<"${WIFI_INTENT_FILES:-/etc/hookprobe/network.yaml /var/lib/hookprobe/wifi-intent.yaml}"
# D14/BUG-W5: seconds to let a rung settle before observing. 15s is long enough to observe AFTER a
# 5GHz/VHT80 rung's proven bounce-then-converge, not during it (the old default of 6s sampled mid
# bounce). SETTLE_5GHZ is independent of the 2.4GHz floor's settle (which never bounces, so it
# doesn't need the longer wait) — 2026-07-16: bumped 15s → 20s (cheap; helps some cold radios
# converge on the FIRST ladder pass, reducing how often the warm-upgrade re-attempt below is needed
# at all).
SETTLE=${SETTLE:-15}
SETTLE_5GHZ=${SETTLE_5GHZ:-20}
# 2026-07-16 (BUG-2, warm-upgrade): settle for the ONE bounded warm re-attempt of the next-wider
# 5GHz rung after the boot ladder has already settled on a non-top rung and the radio is WARM
# (already serving) — proven-on-metal to need longer than a COLD rung's settle to finish its
# bounce-then-converge. Deliberately independent of `SETTLE_5GHZ` (a warm radio's residual
# bounce-vs-converge timing is not necessarily the same as a cold one's).
SETTLE_5GHZ_WARM=${SETTLE_5GHZ_WARM:-30}
# 2026-07-15 DFS-AWARE SETTLE: the settle a DFS rung needs to ride out its regulatory
# Channel-Availability-Check (CAC) before hostapd reaches AP-ENABLED — see `select_settle` below.
# Not exercised by the shipped 3-rung ladder (none of its rungs is DFS); a robustness net for any
# future DFS channel pick. ~60s CAC (standard DFS) + margin; ~600s (10 min, meteo sub-band) + margin.
SETTLE_DFS_STANDARD=${SETTLE_DFS_STANDARD:-75}
SETTLE_DFS_METEO=${SETTLE_DFS_METEO:-660}
# D14: same-rung clean-restart budget before giving up and stepping down the ladder — mirrors
# `wifi_calibrate::next_rung_action`'s `max_retries` parameter (a transient bounce racing hostapd's
# first bring-up very often clears on a clean restart of the SAME rung).
MAX_RETRIES=${MAX_RETRIES:-2}

# =============================================================================
# D45/D46 (2026-07-17, metal-diagnosed) — the WARM-UPGRADE deep fix. Mirrors
# `wifi_calibrate::WARM_MIN_UPTIME_SECONDS`/`WARM_MAX_ATTEMPTS`/`warm_upgrade_ready` exactly.
#
# Ground truth (Pi4 + CM5, 2026-07-17): the PREVIOUS single ~30s-settle warm re-attempt (right after
# the boot ladder settles, ~15-95s post-boot) still did NOT converge live —
# "warm-upgrade did NOT converge (chanspec_fail_storm, ch=36 width=80MHz fails=7) — reverting". A
# MANUAL re-apply of the exact same VHT80-ch40 block "a few minutes post boot" held INSTANTLY on
# both boards. So a merely-just-settled radio (the OLD warm-upgrade's actual timescale) is NOT
# genuinely warm — the fix is two-fold:
#   (1) WARM_MIN_UPTIME_SECONDS — never attempt the warm-upgrade before the radio has been up this
#       long (sleep the remainder first); and
#   (2) WARM_MAX_ATTEMPTS — a SHORT bounded retry loop (not a single shot, not unbounded) once ready,
#       in case one settle window still isn't quite enough on a particular unit.
# =============================================================================
WARM_MIN_UPTIME_SECONDS=${WARM_MIN_UPTIME_SECONDS:-150}
WARM_MAX_ATTEMPTS=${WARM_MAX_ATTEMPTS:-3}

# System uptime in whole seconds — the D46 min-uptime gate's input. `TEST_UPTIME_SECONDS` lets the
# sandbox harness drive this deterministically; a real (or test-less) box reads `/proc/uptime`
# (always present on Linux); an unreadable/missing source degrades to 0 — CONSERVATIVE (never
# unsafe: it just means the caller sleeps the FULL WARM_MIN_UPTIME_SECONDS before the first warm
# attempt, never that it skips the wait).
read_uptime_seconds() {
  if [ -n "${TEST_UPTIME_SECONDS+x}" ]; then echo "$TEST_UPTIME_SECONDS"; return 0; fi
  if [ -r /proc/uptime ]; then
    awk '{u=$1+0; printf "%d\n", u}' /proc/uptime 2>/dev/null || echo 0
  else
    echo 0
  fi
}

# D46 — is the radio warm enough to trust a warm-upgrade attempt? A thin, named wrapper (mirrors
# `wifi_calibrate::warm_upgrade_ready` exactly) so the threshold comparison lives in exactly one
# place and is independently testable.
warm_upgrade_ready() {
  local uptime_secs="$1" min_uptime_secs="$2"
  [ "$uptime_secs" -ge "$min_uptime_secs" ]
}

# =============================================================================
# ADR 0034 D35-D44 — the Wi-Fi calibration LEARNING MODEL (shell mirror of
# `hookprobe_manifest::wifi_calibrate`'s pure core: ConfigKey/ConfigStat/WifiKnowledge,
# `hold_prob`/`confidence`/`quality_score`/`is_known_bad`/`plan_boot`/`age_model`). ONE store,
# `/var/lib/hookprobe/wifi-learn-<iface>.json`, SUBSUMES the D19 band-LKG (that file is now written
# FROM this model — see `learn_export_band_lkg` — so `read_band_lkg_label`/`write_band_lkg`/
# `band_lkg_valid` above need ZERO change; they consume the projection). Requires `jq` (already a
# base-image dependency — see network-apply.sh/trust-reconcile.sh); every call degrades gracefully
# (empty/no-op) when `jq` is unavailable or the store is corrupt — the learning layer NEVER blocks
# boot; a miss just falls through to the pre-existing band-LKG/ladder path untouched.
#
# SHIP IN SHADOW MODE (D44): $WIFI_LEARN_MODE is the single named flag — "shadow" (shipped default)
# records + does ResumeAtRung only; "active" additionally allows DirectToBest. One line to flip
# after a field-validated round, mirroring `wifi_calibrate::LEARN_MODE` exactly.
# =============================================================================
WIFI_LEARN_MODE=${WIFI_LEARN_MODE:-shadow}
WIFI_LEARN_DIR=${WIFI_LEARN_DIR:-/var/lib/hookprobe}

# jq function library shared by every learn_* call below — mirrors the Rust constants exactly
# (ALPHA0/BETA0/CONF_K/STALE_HALF_LIFE_DAYS/BAD_HOLD/BAD_CONFIDENCE/REPROBE_WINDOW_DAYS/
# DIRECT_CONFIDENCE/DIRECT_HOLD/the QUAL_* quality weights, `wifi_calibrate.rs`).
# shellcheck disable=SC2016
LEARN_JQ_DEFS='
  def alpha0: 1.0; def beta0: 1.0; def confk: 2.0;
  def stale_half_life: 21.0; def bad_hold: 0.25; def bad_conf: 0.60; def reprobe_days: 30.0;
  def direct_conf: 0.60; def direct_hold: 0.80;
  def to_epoch(ts): (ts | strptime("%Y-%m-%dT%H:%M:%SZ") | mktime);
  def age_days(t0; nowts): (((to_epoch(nowts) - to_epoch(t0)) / 86400)) as $d | (if $d < 0 then 0 else $d end);
  def decay_factor($age): (($age / stale_half_life) * (0.5 | log)) | exp;
  def hold_prob(s): (s.successes + alpha0) / (s.successes + s.failures + alpha0 + beta0);
  def confidence(s): (s.successes + s.failures) / (s.successes + s.failures + confk);
  def is_known_bad(s; nowts): (hold_prob(s) <= bad_hold) and (confidence(s) >= bad_conf) and (age_days(s.last_seen; nowts) < reprobe_days);
  def cap_for(w): if w == 80 then 100.0 elif w == 40 then 50.0 else 25.0 end;
  def quality_score(s; eirp):
    (cap_for(s.key.width_mhz) + 2.0 * (([eirp - 23, 0] | max)) - 0.6 * s.busy_ema - (if s.dfs then 8.0 else 0 end)) as $raw
    | hold_prob(s) * (if $raw < 0 then 0 else $raw end);
  def rung_label(s): (if s.band == "5" then "5GHz" else "2.4GHz" end)
    + "-" + (if s.key.width_mhz == 80 then "VHT80" elif s.key.width_mhz == 40 then "HT40" else "HT20" end)
    + "-ch" + (s.key.channel | tostring);
'

# A kernel+driver fingerprint — the D38 firmware/driver-change rehabilitation trigger. Best-effort;
# "unknown-unknown" on any read failure is still a stable, comparable value (a real fingerprint
# change is what matters, not the exact string).
fw_fingerprint() {
  local iface="$1" krel drv
  krel=$(uname -r 2>/dev/null || echo unknown)
  drv=$(basename "$(readlink -f "/sys/class/net/$iface/device/driver" 2>/dev/null)" 2>/dev/null || true)
  [ -n "$drv" ] || drv=unknown
  echo "${krel}-${drv}"
}

# Load the store (or a fresh empty one) — never fails, never blocks boot.
learn_load() {
  local file="$1" iface="$2" fw_id="$3" now="$4"
  if command -v jq >/dev/null 2>&1 && [ -r "$file" ] && jq -e . "$file" >/dev/null 2>&1; then
    cat "$file"
    return 0
  fi
  jq -n --arg iface "$iface" --arg fw "$fw_id" --arg now "$now" \
    '{schema: 1, iface: $iface, fw_id: $fw, entries: [], updated_at: $now}' 2>/dev/null \
    || printf '{"schema":1,"iface":"%s","fw_id":"%s","entries":[],"updated_at":"%s"}' "$iface" "$fw_id" "$now"
}

# D38/D40 — fw-change rehabilitation (halve every entry's failures, preserve successes) + the
# discounted-Beta aging pass, applied once on load; stamps `updated_at` to the real wall-clock now
# (every later learn_plan_boot/learn_export_* call in this same run treats that as "now").
# D35 eviction — bound to 64 entries, dropping the lowest confidence*recency cell(s) on overflow.
learn_age() {
  local model="$1" fw_id="$2" now="$3"
  command -v jq >/dev/null 2>&1 || { printf '%s' "$model"; return 0; }
  printf '%s' "$model" | jq --arg fw "$fw_id" --arg now "$now" "$LEARN_JQ_DEFS"'
    def rehab: if (.fw_id // "") != $fw then (.entries |= map(.failures /= 2)) | .fw_id = $fw else . end;
    def decay_one(nowts):
      (age_days(.decayed_at; nowts)) as $age
      | if $age > 0 then (decay_factor($age)) as $f | .successes *= $f | .failures *= $f | .decayed_at = nowts else . end;
    rehab
    | .entries |= map(decay_one($now))
    | .updated_at = $now
    | (.entries | map(. + {__pri: (confidence(.) * decay_factor(age_days(.last_seen; $now)))})
                | sort_by(.__pri)) as $sorted
    | ( ($sorted | length) - 64 ) as $over
    | .entries = ( if $over > 0 then ($sorted[$over:] | map(del(.__pri))) else ($sorted | map(del(.__pri))) end )
  ' 2>/dev/null || printf '%s' "$model"
}

# D36 — record ONE observation (creating the cell on first sight). $6 = the shell verdict word
# (stable|width_collapsed|chanspec_fail_storm|down|client_failed) exactly as produced by
# observe_rung/next_rung_action above — a single write path shared by every caller (both this
# script's boot ladder AND wifi-optimize.sh's 3AM survey, which sources this file). $8 (optional) =
# a measured `busy_ratio` (0-100, from `iw … survey dump`) — blended into `busy_ema` via the same
# EMA_ALPHA=0.3 the Rust core uses; omitted on the boot path (no survey there), matching
# `Observation.busy_ratio: Option<u8>`.
#
# $9 (optional, D45, 2026-07-17) = "true"/"false" — mirrors `ConfigKey.warm` exactly (see
# wifi_calibrate.rs's own doc on that field for the full rationale). Defaults to "false" (cold) when
# omitted, so EVERY existing call site (the boot ladder's per-rung cold tries, and every call in
# wifi-optimize.sh) is byte-identical in behaviour to before this field existed — the warm=true path
# is exclusively used by THIS script's own `attempt_warm_upgrade` bounded retry loop below. A cold
# and a warm observation for the IDENTICAL (channel, width) are two INDEPENDENT cells (matches(e)
# also compares warm) — a cold chanspec-fail-storm can never poison a warm cell's hold_prob, or vice
# versa (the exact bug this fixes: the model used to see only the COLD fail for VHT80-ch40 and would
# learn to avoid it forever, the opposite of reality).
learn_record() {
  local model="$1" radio_id="$2" cc="$3" channel="$4" width="$5" verdict="$6" now="$7" busy="${8:-}" warm="${9:-false}"
  command -v jq >/dev/null 2>&1 || { printf '%s' "$model"; return 0; }
  local success=0
  [ "$verdict" = stable ] && success=1
  local busy_arg=null
  [ -n "$busy" ] && busy_arg="$busy"
  [ "$warm" = true ] || warm=false
  printf '%s' "$model" | jq --arg radio "$radio_id" --arg cc "$cc" --argjson channel "$channel" \
    --argjson width "$width" --arg now "$now" --arg outcome "$verdict" --argjson success "$success" \
    --argjson busy "$busy_arg" --argjson warm "$warm" '
    def matches(e): e.key.radio_id == $radio and e.key.regdomain == $cc and e.key.channel == $channel
      and e.key.width_mhz == $width and ((e.key.warm // false) == $warm);
    (.entries | map(select(matches(.)))) as $m
    | (if ($m | length) > 0 then $m[0] else
        { key: {radio_id: $radio, regdomain: $cc, channel: $channel, width_mhz: $width, warm: $warm},
          center_idx: 0, band: (if $channel > 14 then "5" else "2.4" end),
          dfs: false, cac_seconds: 0, successes: 0, failures: 0,
          busy_ema: ($busy // 0), tput_ema: 0,
          obs_count: 0, last_seen: $now, last_outcome: $outcome, decayed_at: $now }
      end) as $cell
    | ($cell | .successes += $success | .failures += (1 - $success)
             | .busy_ema = (if $busy != null then (0.7 * .busy_ema + 0.3 * $busy) else .busy_ema end)
             | .obs_count = ((.successes + .failures) | floor) | .last_seen = $now | .last_outcome = $outcome) as $upd
    | .entries |= (map(select(matches(.) | not)) + [$upd])
    | .updated_at = $now
  ' 2>/dev/null || printf '%s' "$model"
}

# Map an `observe_rung`/`apply_and_observe` return code to the shared verdict word — the single
# rc<->verdict mapping both wifi-calibrate.sh's own loop (inlined) and wifi-optimize.sh (via this
# shared function) use, so the two never drift.
rc_to_verdict() {
  case "$1" in
    0) echo stable ;;
    1) echo width_collapsed ;;
    2) echo chanspec_fail_storm ;;
    3) echo down ;;
    *) echo down ;;
  esac
}

# D37 — the boot-time exploitation plan. `legal_json` is a JSON array of `[channel, width_mhz]`
# pairs (this ladder's own rungs — the model may ONLY ever choose among these, always-joinable).
# Echoes "resume_at_rung <label>" | "direct_to_best <label>" | "ladder" — a single line, never more.
# In shadow mode (the shipped default) a DirectToBest-eligible winner is deliberately printed as
# "resume_at_rung" instead (D44) — the caller never even sees a "direct_to_best" line unless
# $WIFI_LEARN_MODE=active.
#
# D45 (2026-07-17): COLD-CONTEXT ONLY (`select((.key.warm // false) | not)`) — mirrors
# `wifi_calibrate::plan_boot`'s own filter exactly. This answers "what should the ordinary,
# short-settle boot ladder resume/skip to," which must never be a rung only proven to hold once the
# radio is WARM — such a winner, applied with the ordinary settle, would very likely fail exactly
# like a fresh cold attempt. `learn_plan_warm_upgrade` below is the separate, warm-context-only
# decision for "what should the POST-settle warm-upgrade step try."
learn_plan_boot() {
  local model="$1" cc="$2" radio_id="$3" legal_json="$4" mode="$5" now="$6"
  command -v jq >/dev/null 2>&1 || { echo ladder; return 0; }
  printf '%s' "$model" | jq -r --arg cc "$cc" --arg radio "$radio_id" --argjson legal "$legal_json" \
    --arg mode "$mode" --arg now "$now" "$LEARN_JQ_DEFS"'
    def is_legal(k): k as $k | ($legal | map(.[0] == $k.channel and .[1] == $k.width_mhz) | any);
    ([.entries[] | select(.key.radio_id == $radio and (.key.regdomain | ascii_downcase) == ($cc | ascii_downcase))
                  | select((.key.warm // false) | not)
                  | select(is_legal(.key)) | select(is_known_bad(.; $now) | not)]) as $cands
    | if ($cands | length) == 0 then "ladder"
      else
        ($cands | max_by(quality_score(.; 23))) as $w
        | (confidence($w)) as $c | (hold_prob($w)) as $h
        | if $c >= direct_conf and $h >= direct_hold then
            (if $mode == "active" then "direct_to_best " + rung_label($w) else "resume_at_rung " + rung_label($w) end)
          elif $w.successes > 0 then "resume_at_rung " + rung_label($w)
          else "ladder" end
      end
  ' 2>/dev/null || echo ladder
}

# D46 (2026-07-17) — the model-informed warm-upgrade TARGET, the shell mirror of
# `wifi_calibrate::plan_warm_upgrade`. WARM-CONTEXT ONLY, STRICTLY WIDER than `cold_mhz` (the
# cold-chosen rung's width — the model can therefore only ever propose an UPGRADE, never sideways or
# narrower). Echoes "<channel> <width_mhz>" on a proven warm winner, or nothing (empty) when none
# exists yet — the caller then falls back to the static `warm_upgrade_candidate` ladder-adjacency
# rule (the correct BOOTSTRAP behaviour on a box with no warm history).
learn_plan_warm_upgrade() {
  local model="$1" cc="$2" radio_id="$3" legal_json="$4" cold_mhz="$5" now="$6"
  command -v jq >/dev/null 2>&1 || return 0
  printf '%s' "$model" | jq -r --arg cc "$cc" --arg radio "$radio_id" --argjson legal "$legal_json" \
    --argjson cold_mhz "$cold_mhz" --arg now "$now" "$LEARN_JQ_DEFS"'
    def is_legal(k): k as $k | ($legal | map(.[0] == $k.channel and .[1] == $k.width_mhz) | any);
    ([.entries[] | select(.key.radio_id == $radio and (.key.regdomain | ascii_downcase) == ($cc | ascii_downcase))
                  | select(.key.warm == true) | select(.key.width_mhz > $cold_mhz)
                  | select(is_legal(.key)) | select(is_known_bad(.; $now) | not) | select(.successes > 0)]) as $cands
    | if ($cands | length) == 0 then empty
      else
        ($cands | max_by(quality_score(.; 23))) as $w
        | (($w.key.channel | tostring) + " " + ($w.key.width_mhz | tostring))
      end
  ' 2>/dev/null || true
}

# D35/D42 — regenerate the read-only band-LKG EXPORT from the model's current argmax over the
# legal set (never written directly from a single boot's chosen rung any more — the model is the
# source of truth). No-op (keeps the prior file untouched) when nothing legal-and-proven exists yet.
# D45: COLD-CONTEXT ONLY — this export is consumed as "resume the ORDINARY ladder here" (see
# `read_band_lkg_label`/`start_index` in `main`), so it must never point at a warm-only rung.
learn_export_band_lkg() {
  local model="$1" cc="$2" radio_id="$3" legal_json="$4" now="$5" out_file="$6"
  command -v jq >/dev/null 2>&1 || return 0
  local exported
  exported=$(printf '%s' "$model" | jq -c --arg cc "$cc" --arg radio "$radio_id" --argjson legal "$legal_json" \
    --arg now "$now" "$LEARN_JQ_DEFS"'
    def is_legal(k): k as $k | ($legal | map(.[0] == $k.channel and .[1] == $k.width_mhz) | any);
    ([.entries[] | select(.key.radio_id == $radio and (.key.regdomain | ascii_downcase) == ($cc | ascii_downcase))
                  | select((.key.warm // false) | not)
                  | select(is_legal(.key)) | select(is_known_bad(.; $now) | not) | select(.successes > 0)]) as $cands
    | if ($cands | length) == 0 then empty
      else
        ($cands | max_by(quality_score(.; 23))) as $w
        | { cc: $cc, radio_id: $radio, band: $w.band, label: rung_label($w), channel: $w.key.channel, decided_at: $now }
      end
  ' 2>/dev/null || true)
  [ -n "$exported" ] || return 0
  mkdir -p "$(dirname "$out_file")" 2>/dev/null || return 0
  printf '%s\n' "$exported" > "$out_file" 2>/dev/null || true
}

# D31/D35/D42 — mirrors [`learn_export_band_lkg`] for the `wifi-channel-lkg-<iface>.json` export
# (5 GHz VHT80 entries only — the channel-optimizer's own consulted cache). Used by
# wifi-optimize.sh, which sources this file. No-op when nothing legal-and-proven exists yet.
# D45: COLD-CONTEXT ONLY — a no-op filter for every EXISTING caller (wifi-optimize.sh's own
# observations are all cold-context by construction; the warm/cold axis is scoped exclusively to
# THIS script's boot-ladder warm-upgrade step) — it only ever excludes the new warm=true cells.
learn_export_channel_lkg() {
  local model="$1" cc="$2" radio_id="$3" legal_json="$4" now="$5" out_file="$6"
  command -v jq >/dev/null 2>&1 || return 0
  local exported
  exported=$(printf '%s' "$model" | jq -c --arg cc "$cc" --arg radio "$radio_id" --argjson legal "$legal_json" \
    --arg now "$now" "$LEARN_JQ_DEFS"'
    def is_legal(k): k as $k | ($legal | map(.[0] == $k.channel and .[1] == $k.width_mhz) | any);
    ([.entries[] | select(.key.radio_id == $radio and (.key.regdomain | ascii_downcase) == ($cc | ascii_downcase))
                  | select((.key.warm // false) | not)
                  | select(.key.width_mhz == 80) | select(is_legal(.key))
                  | select(is_known_bad(.; $now) | not) | select(.successes > 0)]) as $cands
    | if ($cands | length) == 0 then empty
      else
        ($cands | max_by(quality_score(.; 23))) as $w
        | { cc: $cc, radio_id: $radio, control_channel: $w.key.channel, center_idx: $w.center_idx,
            width_mhz: 80, dfs: $w.dfs, score: (quality_score($w; 23) | floor), validated_at: $now }
      end
  ' 2>/dev/null || true)
  [ -n "$exported" ] || return 0
  mkdir -p "$(dirname "$out_file")" 2>/dev/null || return 0
  printf '%s\n' "$exported" > "$out_file" 2>/dev/null || true
}

# Persist the store — best-effort, atomic-ish (write-then-rename), never fails the loop.
learn_save() {
  local model="$1" file="$2"
  mkdir -p "$(dirname "$file")" 2>/dev/null || return 0
  local tmp="$file.tmp.$$"
  printf '%s\n' "$model" > "$tmp" 2>/dev/null && mv -f "$tmp" "$file" 2>/dev/null || rm -f "$tmp" 2>/dev/null || true
}

# Build the `[[channel,width_mhz], ...]` legal-set JSON from the (already-built) $LADDER array —
# the model may only ever select among these, mirroring `plan_boot`'s `legal: &[(u32,u32)]` input.
# 2026-07-16 (BUG-1): LADDER entries now carry exactly 4 single-line fields (no embedded ht_lines
# — see `ht_lines_for_label`), so this plain 4-field `read` is now always complete/safe.
ladder_legal_json() {
  local entry ch mhz lbl b out="["
  local first=1
  for entry in "${LADDER[@]}"; do
    read -r lbl b ch mhz <<<"$entry"
    [ "$first" -eq 1 ] || out="$out,"
    out="${out}[$ch,$mhz]"
    first=0
  done
  echo "${out}]"
}

log() { echo "wifi-calibrate[${IFACE:-?}]: $*" >&2; }

# --- Feature 2: observe one applied rung (verify each rung actually HELD) --------------------
# Returns 0 (stable) or non-zero, and echoes "oper_ch oper_mhz fail_count".
#
# Verdict priority (BUG-W5, mirrors wifi_calibrate::verify_rung exactly):
#   Down (unit not active)
#     → CONVERGED (operating channel+width match the request, or unreadable) → Stable
#     → NOT converged: chanspec-fail storm (>=2 in THIS attempt's window) → ChanspecFailStorm
#     → NOT converged, no storm → WidthCollapsed
# Convergence is checked BEFORE the chanspec-fail count so a rung that bounced-then-landed on the
# requested chanspec is never stepped down for the fail lines it took to get there.

# --- BUG-W7 (2026-07-17): the 5 GHz 80 MHz BLOCK map — mirrors wifi_calibrate::block_center_for_
# channel. An 80 MHz channel is identified by its block (its center), NOT by which of the block's
# four 20 MHz channels the firmware happens to report as primary. Echoes the block's center index
# (42/58/106/122/138/155), or nothing for a channel in no known 80 MHz block.
block_center_for_channel() {
  case "$1" in
    36|40|44|48)      printf '42'  ;;
    52|56|60|64)      printf '58'  ;;
    100|104|108|112)  printf '106' ;;
    116|120|124|128)  printf '122' ;;
    132|136|140|144)  printf '138' ;;
    149|153|157|161)  printf '155' ;;
    *)                printf ''    ;;
  esac
}

# True when both channels sit in the SAME 80 MHz block (so they are the same physical 80 MHz
# channel — the firmware just names a different primary). Refuses when either channel is in no
# known block, so an unexpected drift (e.g. the classic ch140 bounce) can never be mistaken for
# convergence.
same_80mhz_block() {
  local a b
  a=$(block_center_for_channel "$1")
  b=$(block_center_for_channel "$2")
  [ -n "$a" ] && [ -n "$b" ] && [ "$a" = "$b" ]
}
observe_rung() {
  local want_ch="$1" want_mhz="$2"
  local oper_ch="" oper_mhz="" fails=0 info=""
  if [ -n "${TEST_IW_INFO+x}" ]; then
    info="$TEST_IW_INFO"
  elif command -v iw >/dev/null 2>&1; then
    info=$(iw dev "$IFACE" info 2>/dev/null || true)
  fi
  oper_ch=$(printf '%s\n' "$info" | sed -n 's/.*channel \([0-9]\+\).*/\1/p' | head -1)
  oper_mhz=$(printf '%s\n' "$info" | sed -n 's/.*width: \([0-9]\+\) MHz.*/\1/p' | head -1)

  # BUG-W6: read ONLY this attempt's dmesg window — `mark_dmesg` (called right before this rung's
  # clean_restart) set DMESG_MODE/DMESG_MARK to scope this. Never falls back to a flat recent-N-lines
  # scan, which is exactly what let a PRIOR rung's fail lines leak into this one's verdict.
  local dmesg_out=""
  case "${DMESG_MODE:-unavailable}" in
    cleared) dmesg_out=$(dmesg 2>/dev/null || true) ;;
    marker)  dmesg_out=$(dmesg 2>/dev/null | tail -n "+$((DMESG_MARK + 1))" 2>/dev/null || true) ;;
    *) dmesg_out="" ;;  # dmesg unavailable — no chanspec-fail signal; convergence check still works.
  esac
  fails=$(printf '%s\n' "$dmesg_out" | grep -c "set chanspec .* fail" || true)

  echo "$oper_ch $oper_mhz $fails"

  local active=1
  if [ -n "${TEST_HOSTAPD_ACTIVE+x}" ]; then
    [ "$TEST_HOSTAPD_ACTIVE" = "1" ] || active=0
  else
    systemctl is-active --quiet "hookprobe-hostapd@$IFACE.service" || active=0
  fi
  [ "$active" -eq 1 ] || return 3                                                # Down

  # BUG-W5: convergence wins. `oper_*` empty (iw unreadable) counts as "not evidence against" —
  # matches the pre-fix behaviour for an unreadable radio (never fail on the absence of a reading).
  #
  # BUG-W7 (2026-07-17, THE 150-Mbps bug — found on live CM5+Pi4 metal): the channel test must be
  # BLOCK-aware at 80 MHz, never an exact control-channel match. GROUND TRUTH: applying the proven
  # VHT80-ch40 block (`channel=40`, `ht_capab=[HT40-]`, `vht_oper_centr_freq_seg0_idx=42`) brings the
  # radio up **working** — `iw dev` reports `channel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz`,
  # hostapd active, a client associated at 80 MHz — because the brcmfmac FullMAC firmware reports an
  # 80 MHz chanspec's primary as the BLOCK'S LOWEST channel (36), NOT the configured control (40).
  # The old exact test read that as `chan_ok=0` → "not converged" → the (one-time, harmless) bring-up
  # churn `fails=7` then tripped ChanspecFailStorm → the loop REVERTED a perfectly good 80 MHz link
  # (~450 Mbit/s) down to HT40 (~150 Mbit/s), cold AND warm, on BOTH boards, every single attempt.
  # That — not thermal warmth, not retry budget — is why VHT80 "never converged". An 80 MHz channel is
  # identified by its BLOCK (center 5210 for 36-48), so any of 36/40/44/48 is the same physical
  # channel: converged. 20/40 MHz keep the exact match (the firmware reports those faithfully).
  local width_ok=1 chan_ok=1
  [ -n "$oper_mhz" ] && [ "$oper_mhz" != "$want_mhz" ] && width_ok=0
  if [ -n "$oper_ch" ] && [ "$oper_ch" != "$want_ch" ]; then
    if [ "$want_mhz" = "80" ] && same_80mhz_block "$oper_ch" "$want_ch"; then
      chan_ok=1                                                                  # same 80MHz block
    else
      chan_ok=0
    fi
  fi
  if [ "$width_ok" -eq 1 ] && [ "$chan_ok" -eq 1 ]; then
    return 0                                                                     # Stable (converged)
  fi
  [ "${fails:-0}" -ge 2 ] && return 2                                            # ChanspecFailStorm
  return 1                                                                       # WidthCollapsed
}

# --- BUG-W6: scope the chanspec-fail count to THIS attempt only ------------------------------
# Called right before every rung attempt's clean_restart. Sets DMESG_MODE (cleared|marker|
# unavailable) + DMESG_MARK, consumed by observe_rung above. Never hard-fails the loop: if dmesg is
# unavailable, or `-C` is refused, we degrade gracefully — BUG-W5's convergence check remains the
# primary verdict signal either way.
DMESG_MODE="unavailable"
DMESG_MARK=0
mark_dmesg() {
  DMESG_MODE="unavailable"
  DMESG_MARK=0
  # TEST_NO_DMESG: synthetic feed for the "dmesg entirely unavailable" case — lets a sandbox
  # harness exercise this degrade-gracefully path without having to strip `dmesg` out of PATH
  # (which would also strip every other real tool this script needs, e.g. sed/grep/head).
  [ -n "${TEST_NO_DMESG:-}" ] && return 0
  command -v dmesg >/dev/null 2>&1 || return 0
  if dmesg -C >/dev/null 2>&1; then
    DMESG_MODE="cleared"
  else
    local n=0
    n=$(dmesg 2>/dev/null | wc -l | tr -d '[:space:]') || true
    DMESG_MARK=${n:-0}
    DMESG_MODE="marker"
  fi
  return 0
}

# --- D14: the verify-retry action, a shell mirror of wifi_calibrate::next_rung_action --------
# $1 = result (stable|width_collapsed|chanspec_fail_storm|down); $2 = attempt count already spent
# on THIS rung (0 on the first try). Echoes one of: keep | retry | stepdown.
next_rung_action() {
  local result="$1" attempt="$2"
  case "$result" in
    stable) echo keep ;;
    width_collapsed|chanspec_fail_storm|down)
      if [ "$attempt" -lt "$MAX_RETRIES" ]; then echo retry; else echo stepdown; fi ;;
    *) echo stepdown ;;
  esac
}

# --- PREREQUISITE: no supplicant contention on the AP radio ---------------------------------
# ROOT CAUSE (CM5, 2026-07-10): wpa_supplicant (enabled by default) scans the AP radio and yanks
# hostapd off-channel → the ch140/20 MHz "VHT80 collapse". This radio is AP-role, so a supplicant
# must NEVER touch it. Mask the global + per-interface units before calibrating. STATION radios
# (USB-dongle uplinks) keep their own supplicant — this only masks the AP interface's.
# The authoritative role→action mapping is wifi_calibrate::supplicant_policy.
mask_supplicant_on_ap() {
  systemctl mask --now "wpa_supplicant@$IFACE.service" 2>/dev/null || true
  # The global template scans all radios; on an AP-only box it must not run. A box WITH a station
  # radio runs wpa_supplicant@<station> explicitly instead, so masking the catch-all is safe.
  if ! systemctl is-enabled --quiet "wpa_supplicant@wlan_uplink.service" 2>/dev/null; then
    systemctl mask --now wpa_supplicant.service 2>/dev/null || true
  fi
  # Kill any stray supplicant already holding the AP radio.
  pkill -f "wpa_supplicant.*-i[= ]?$IFACE" 2>/dev/null || true
}

# --- D14: a CLEAN restart — stop, ensure no competing scan, start ----------------------------
# A transient scan racing hostapd's first bring-up is what makes brcmfmac bounce a requested
# VHT80 to ch140/20 MHz; a restart with NO competing scan holds. `iw … scan abort` is
# best-effort (harmless if none is running / iw is absent).
clean_restart() {
  systemctl stop "hookprobe-hostapd@$IFACE.service" 2>/dev/null || true
  if command -v iw >/dev/null 2>&1; then
    iw dev "$IFACE" scan abort >/dev/null 2>&1 || true
  fi
  systemctl start "hookprobe-hostapd@$IFACE.service" 2>/dev/null || true
}

# --- D15: the operator's band intent (hard pin), read from the same intent files
# regdomain-apply.sh reads for `country:`. Echoes the FIRST real match's raw token, or "auto" when
# none is found — mirrors `resolve_bootstrap_band`'s intent precedence (a real pin always wins).
read_band_intent() {
  local f b
  for f in "${WIFI_BAND_INTENT_FILES[@]}"; do
    [ -r "$f" ] || continue
    b=$(sed -n 's/^[[:space:]]*band:[[:space:]]*"\?\([A-Za-z0-9.]*\)"\?.*/\1/p' "$f" | head -1)
    [ -n "$b" ] && { echo "$b"; return 0; }
  done
  echo "auto"
}

# Normalise a raw band-intent token to exactly "5" | "2.4" | "auto" (never anything else — an
# unrecognised value degrades to "auto", the safe always-joinable default, never a guess).
normalize_band_pin() {
  local t="${1,,}"
  case "$t" in
    5|5ghz|5g) echo 5 ;;
    2.4|2.4ghz|2.4g) echo 2.4 ;;
    *) echo auto ;;
  esac
}

# --- per-device 2.4 GHz channel {1,6,11} — a bash mirror of the CONCEPT in wifi_cfg::
# default_24_channel (same {1,6,11} candidate set, device-derived so two co-located boxes don't
# collide). NOT required to numerically match the Rust hash for the SAME device — this loop and the
# ordinary reconcile render two INDEPENDENT confs; each only needs to be device-sensitive on its
# own. Seeded off the device's own already-resolved SSID (itself derived from the manifest
# device_id — see wifi_cfg::default_ssid) so no extra manifest/jq read is needed in this script.
#
# 2026-07-15: NO LONGER used for the calibration ladder's 2.4 GHz FLOOR rung — the operator wants a
# CONSTANT ch6 floor (see `build_ladder` below), so this function's own well-tested output is not
# wired into the ladder any more. Kept (and still unit-tested in `test-wifi-calibrate.sh`, D18) for
# any OTHER caller that wants per-device 2.4 GHz diversity outside this specific ladder.
default_24_channel() {
  local seed="$1" hexbyte n
  hexbyte=$(printf '%s' "hookprobe-24ch-v1$seed" | sha256sum 2>/dev/null | cut -c1-2)
  [ -n "$hexbyte" ] || hexbyte="00"   # sha256sum unavailable (shouldn't happen) → deterministic ch6
  n=$((16#$hexbyte))
  case $((n % 3)) in
    0) echo 1 ;;
    1) echo 6 ;;
    *) echo 11 ;;
  esac
}

# --- D19: band-outcome memory (band-LKG) --------------------------------------------------------
# A stable fingerprint for the radio actually serving $IFACE — its own MAC address. A swapped radio
# on the same interface NAME must not inherit a rung proven on different hardware (mirrors
# wifi_calibrate::band_lkg_valid's radio_id check).
radio_fingerprint() {
  if [ -r "/sys/class/net/$1/address" ]; then
    cat "/sys/class/net/$1/address" 2>/dev/null || echo unknown
  else
    echo unknown
  fi
}

# Read the cached band-LKG's rung LABEL, but only if it is still VALID for the CURRENT regdomain +
# radio (cc matches case-insensitively, radio_id matches exactly) — a regdomain change or a
# swapped radio invalidates it and the loop re-fights the full ladder from the top, same as a
# first boot. Echoes the label, or nothing when absent/invalid.
read_band_lkg_label() {
  local f="$1" want_cc="$2" want_radio="$3" lkg_cc lkg_radio lkg_label
  [ -r "$f" ] || return 0
  lkg_cc=$(sed -n 's/.*"cc"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$f" | head -1)
  lkg_radio=$(sed -n 's/.*"radio_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$f" | head -1)
  lkg_label=$(sed -n 's/.*"label"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$f" | head -1)
  [ -n "$lkg_label" ] || return 0
  if [ "${lkg_cc^^}" = "${want_cc^^}" ] && [ -n "$lkg_radio" ] && [ "$lkg_radio" = "$want_radio" ]; then
    echo "$lkg_label"
  fi
}

# Persist the winning rung as the new band-LKG. Best-effort; a write failure never fails the loop
# (the calibration already succeeded — this is only a boot-time optimisation for NEXT time).
write_band_lkg() {
  local f="$1" cc="$2" radio_id="$3" band="$4" label="$5" channel="$6"
  mkdir -p "$(dirname "$f")" 2>/dev/null || return 0
  cat > "$f" <<EOF 2>/dev/null || true
{
  "cc": "$cc",
  "radio_id": "$radio_id",
  "band": "$band",
  "label": "$label",
  "channel": $channel,
  "decided_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
}

# The ladder (best→safe) — the operator's exact 3-rung spec (2026-07-15, proven on metal), a
# minimal mirror of wifi_calibrate::candidate_ladder. Each entry: "label band channel width_mhz"
# (2026-07-16, BUG-1: the ht_lines block is NOT embedded here any more — see `ht_lines_for_label`).
# ETSI/world: no UNII-3, no 2.4 HT40. Production reads the real ladder from the Rust core.
#
# Rung 1: VHT80 on control ch40 — the UNII-1 (36-48) block's UPPER secondary. `ht_capab=[HT40-]`
# (NOT `[HT40+]`) — this is the ONE thing that makes VHT80 hold on brcmfmac; `vht_oper_centr_freq_
# seg0_idx=42` is unchanged (still the 36-48 block's center, just a different primary channel).
VHT80_LINES=$'ht_capab=[HT40-][SHORT-GI-20][SHORT-GI-40]\nieee80211ac=1\nvht_capab=[SHORT-GI-80]\nvht_oper_chwidth=1\nvht_oper_centr_freq_seg0_idx=42\n'
# Rung 2: HT40 on control ch36 — the same block's LOWER primary. `ht_capab=[HT40+]`.
HT40_LINES=$'ht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40]\n'

# --- 2026-07-16 (BUG-1): resolve a rung's HT/VHT width-lines block BY LABEL, never by threading it
# through a LADDER entry string. `VHT80_LINES`/`HT40_LINES` are genuinely multi-line — embedding
# them inside a space-delimited entry and pulling them back out with `read -r ... <<<"$entry"` used
# to TRUNCATE at the first embedded newline (read is line-based), silently dropping the field's own
# trailing `\n` (the malformed-conf glue bug) and, for VHT80, every line after the first one too
# (silently downgrading "VHT80" to plain HT40). Looking this up AFTER the (now single-line-safe)
# `read` closes both holes at the source. Echoes the empty string for any label with no width block
# (the 2.4GHz/HT20 floor, or an unrecognised label).
ht_lines_for_label() {
  case "$1" in
    "5GHz-VHT80-ch40") printf '%s' "$VHT80_LINES" ;;
    "5GHz-HT40-ch36") printf '%s' "$HT40_LINES" ;;
    *) printf '%s' "" ;;
  esac
}

# --- D15: build the ladder honoring an explicit band HARD PIN. $1 = band pin ("5"|"2.4"|"auto").
# Populates the global LADDER array (each entry: "label band channel width_mhz" — 2026-07-16,
# BUG-1: NO LONGER carries the ht_lines block inline; see `ht_lines_for_label` above).
#
# 2026-07-15: the floor rung is now the CONSTANT ch6 (operator-prescriptive — see
# `default_24_channel`'s doc above), and the auto/5-pin ladders are exactly the operator's 3/2-rung
# shape — no intermediate HT20-ch36 rung.
build_ladder() {
  local pin="$1"
  case "$pin" in
    5)
      # Hard 5GHz pin (D15): ONLY the 5GHz rungs — no 2.4 floor. An explicit operator override of
      # the always-joinable default; the AP MAY end down if neither holds. Not recommended.
      LADDER=(
        "5GHz-VHT80-ch40 5 40 80"
        "5GHz-HT40-ch36 5 36 40"
      )
      ;;
    2.4)
      # Hard 2.4GHz pin (D15): the old blunt single-band floor, nothing else attempted.
      LADDER=(
        "2.4GHz-ch6 2.4 6 20"
      )
      ;;
    *)
      # auto (default, and what every image ships) — the operator's exact 3-rung shape: fight for
      # VHT80-ch40 first, step down to HT40-ch36, floor at the always-joinable 2.4GHz-ch6.
      LADDER=(
        "5GHz-VHT80-ch40 5 40 80"
        "5GHz-HT40-ch36 5 36 40"
        "2.4GHz-ch6 2.4 6 20"
      )
      ;;
  esac
}

# =================================================================================================
# 2026-07-16 (BUG-2) — the WARM-UPGRADE: after the boot ladder settles on a non-top rung, ONE
# bounded re-attempt of the next-wider 5GHz rung now that the radio is WARM (already serving).
#
# Metal-proven (Pi4 + CM5, BCM43455): 5GHz-VHT80-ch40 HOLDS rock-solid (4/4 polls stable,
# AP-ENABLED, 80 MHz) once the radio is WARM — but a genuinely COLD radio can still be mid-bounce
# past the ordinary boot-time settle and get stepped down to 5GHz-HT40-ch36. Rather than inflating
# every cold rung's settle to cover that worst case, try the wider rung ONCE more here with the
# longer $SETTLE_5GHZ_WARM. Split into two functions — mirrors `wifi_calibrate::
# warm_upgrade_candidate`/`warm_upgrade_action` (the pure Rust decision core) exactly:
#   `warm_upgrade_candidate` — PURE eligibility + target lookup (no I/O) — independently testable.
#   `attempt_warm_upgrade`   — the actual apply/observe/commit-or-revert side effect.
# =================================================================================================

# Is there a wider 5GHz rung immediately above `$1` (the label the ladder settled on) worth a warm
# re-attempt? Echoes "label band channel width_mhz" and returns 0 on eligibility; returns 1 (no
# output) when NOT eligible — mirrors `wifi_calibrate::warm_upgrade_candidate` exactly: eligible
# ONLY when the settled label is present in $LADDER, is NOT already the ladder's top (index 0)
# rung, and BOTH it and the rung immediately above it (by ladder order) are band "5" (a 2.4GHz
# floor settle never attempts to jump bands here). Pure — touches no radio, hostapd, or dmesg.
warm_upgrade_candidate() {
  local settled_label="$1"
  local idx=-1 i=0 e lbl settled_band
  for e in "${LADDER[@]}"; do
    read -r lbl _ <<<"$e"
    if [ "$lbl" = "$settled_label" ]; then idx=$i; break; fi
    i=$((i + 1))
  done
  [ "$idx" -gt 0 ] || return 1   # not found at all, OR already the top rung — nothing wider to try
  read -r _ settled_band _ _ <<<"${LADDER[$idx]}"
  local wider_label wider_band wider_ch wider_mhz
  read -r wider_label wider_band wider_ch wider_mhz <<<"${LADDER[$((idx - 1))]}"
  if [ "$settled_band" = "5" ] && [ "$wider_band" = "5" ]; then
    echo "$wider_label $wider_band $wider_ch $wider_mhz"
    return 0
  fi
  return 1
}

# D46 — look up the LADDER label for a (channel, width_mhz) pair (the reverse of `read -r label band
# ch mhz <<<"$entry"`), needed because `learn_plan_warm_upgrade` only echoes numbers (mirrors
# `wifi_calibrate::ConfigKey`, which carries no label — `config_key_label` derives it on demand,
# exactly what this reproduces in shell). Echoes the label and returns 0, or returns 1 (no output)
# if no LADDER rung matches (defensive — `learn_plan_warm_upgrade`'s own `is_legal` filter, built
# from THIS SAME `$LADDER` via `ladder_legal_json`, means this should never actually miss).
rung_label_for_channel_width() {
  local want_ch="$1" want_mhz="$2" e lbl b ch mhz
  for e in "${LADDER[@]}"; do
    read -r lbl b ch mhz <<<"$e"
    if [ "$ch" = "$want_ch" ] && [ "$mhz" = "$want_mhz" ]; then echo "$lbl"; return 0; fi
  done
  return 1
}

# D46 — resolve the warm-upgrade TARGET: prefer the MODEL-INFORMED pick (`learn_plan_warm_upgrade`
# — a rung the model has ACTUALLY proven to hold warm, which may in principle be wider than just
# "the next rung up") over the static ladder-adjacency fallback `$1` (`warm_upgrade_candidate`'s own
# output — the correct BOOTSTRAP rule when nothing is learned yet). Reads `$MODEL`/`$cc`/
# `$radio_id`/`$LEGAL_JSON`/`$LEARN_NOW`/`$chosen_mhz` via the same dynamic scoping every other
# main()-local helper in this script already relies on. Echoes "label band channel width_mhz",
# exactly `warm_upgrade_candidate`'s own shape, so both feed `attempt_warm_upgrade` identically.
resolve_warm_target() {
  local static_cand="$1"
  local model_pick m_ch m_mhz m_label
  model_pick=$(learn_plan_warm_upgrade "$MODEL" "$cc" "$radio_id" "$LEGAL_JSON" "${chosen_mhz:-40}" "$LEARN_NOW")
  if [ -n "$model_pick" ]; then
    read -r m_ch m_mhz <<<"$model_pick"
    if m_label=$(rung_label_for_channel_width "$m_ch" "$m_mhz"); then
      log "warm-upgrade: model-informed target '$m_label' (ch=$m_ch width=${m_mhz}MHz, proven warm) — overriding the static next-rung-up guess"
      echo "$m_label 5 $m_ch $m_mhz"
      return 0
    fi
  fi
  echo "$static_cand"
}

# Apply + observe the warm-upgrade candidate, and commit-or-revert. `$1..$4` = the candidate's
# "label band channel width_mhz" (from `resolve_warm_target`, model-informed or the static
# `warm_upgrade_candidate` fallback). Reads/writes the SAME variables as the main ladder loop
# (`chosen`/`chosen_band`/`chosen_ch`/`chosen_mhz`/`MODEL`/`attempts_json`/`radio_id`/`cc`/
# `LEARN_NOW`/`IFACE`) via bash's ordinary dynamic scoping — this function is called from within
# `main`'s scope (directly, or via a test harness that has set the same names at top level), exactly
# like every other main()-local helper in this script.
#
# D45/D46 (2026-07-17) — the DEEP fix, replacing the single ~30s-settle shot that still failed live
# ("warm-upgrade did NOT converge (chanspec_fail_storm...) — reverting", the exact ground-truth
# symptom): (1) never attempts before [`warm_upgrade_ready`] confirms [`WARM_MIN_UPTIME_SECONDS`] of
# real uptime (sleeping the remainder first — the radio was simply not warm enough before); (2) a
# SHORT BOUNDED retry loop (`WARM_MAX_ATTEMPTS`, not a single shot, not unbounded) once ready; (3)
# EVERY attempt records a `warm=true` observation (`learn_record`'s 9th arg) — a SEPARATE cell from
# the cold boot-ladder's own observations of the identical (channel, width), so a cold fail can never
# poison this rung's warm `hold_prob` (D45 — see `wifi_calibrate.rs`'s `ConfigKey` doc for the full
# rationale).
#
# On CONVERGENCE (any attempt): commits the upgrade by overwriting `chosen`/`chosen_band`/
# `chosen_ch`/`chosen_mhz` — the existing band-LKG/learning-model export further down in `main` then
# persists it for next boot with NO changes needed there (that export stays cold-context-only, D45 —
# see `learn_export_band_lkg`'s own doc; the WARM cell is what `learn_plan_warm_upgrade` consults on
# a FUTURE boot to go straight for this same target once ready, skipping the doomed cold churn). On
# exhausting the retry budget without converging: reverts to the already-proven `$chosen` rung
# (re-renders + restarts it) so the AP is NEVER left down.
attempt_warm_upgrade() {
  local wider_label="$1" wider_band="$2" wider_ch="$3" wider_mhz="$4"
  local warm_ht_lines obs_out oper_ch oper_mhz fails rc result
  local uptime_now remaining attempt=0

  uptime_now=$(read_uptime_seconds)
  if ! warm_upgrade_ready "$uptime_now" "$WARM_MIN_UPTIME_SECONDS"; then
    remaining=$((WARM_MIN_UPTIME_SECONDS - uptime_now))
    log "warm-upgrade: radio not yet genuinely warm (uptime=${uptime_now}s, need ${WARM_MIN_UPTIME_SECONDS}s) — waiting ${remaining}s more before the first attempt of '$wider_label'"
    [ -n "${TEST_SKIP_WARM_WAIT:-}" ] || sleep "$remaining"
  fi

  warm_ht_lines=$(ht_lines_for_label "$wider_label")
  while true; do
    log "warm-upgrade: settled on '$chosen' (non-top, radio now WARM) — attempting '$wider_label' (attempt $attempt/$((WARM_MAX_ATTEMPTS - 1)), settle=${SETTLE_5GHZ_WARM}s)"
    render_rung "$IFACE" "a" "$wider_ch" "$warm_ht_lines"
    mark_dmesg
    clean_restart
    sleep "$SETTLE_5GHZ_WARM"
    obs_out=$(observe_rung "$wider_ch" "$wider_mhz") && rc=0 || rc=$?
    read -r oper_ch oper_mhz fails <<<"$obs_out"
    result=$(rc_to_verdict "$rc")
    # D45: warm=true — the 9th arg — is the ENTIRE fix's load-bearing line: this observation joins a
    # cell SEPARATE from the cold boot-ladder's own (channel, width) cell.
    MODEL=$(learn_record "$MODEL" "$radio_id" "$cc" "$wider_ch" "$wider_mhz" "$result" "$LEARN_NOW" "" true)
    attempts_json="${attempts_json:+$attempts_json,}{\"label\":\"$wider_label\",\"width_mhz\":$wider_mhz,\"channel\":$wider_ch,\"result\":\"$result\",\"warm_upgrade\":true,\"warm_attempt\":$attempt}"
    if [ "$result" = stable ]; then
      log "warm-upgrade CONVERGED: '$wider_label' now holding (ch=$oper_ch width=${oper_mhz}MHz, attempt $attempt) — committing the upgrade"
      chosen="$wider_label"; chosen_band="$wider_band"; chosen_ch="$wider_ch"; chosen_mhz="$wider_mhz"
      return 0
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -lt "$WARM_MAX_ATTEMPTS" ]; then
      log "warm-upgrade: attempt $((attempt - 1)) did not converge ($result, ch=$oper_ch width=${oper_mhz}MHz fails=$fails) — retrying (budget $attempt/$WARM_MAX_ATTEMPTS spent)"
      continue
    fi
    log "warm-upgrade: exhausted $WARM_MAX_ATTEMPTS attempts ($result, ch=$oper_ch width=${oper_mhz}MHz fails=$fails) — reverting to the already-proven '$chosen' rung (never leaving the AP down)"
    local revert_ht_lines revert_hw
    revert_ht_lines=$(ht_lines_for_label "$chosen")
    revert_hw=a; [ "$chosen_band" = "2.4" ] && revert_hw=g
    render_rung "$IFACE" "$revert_hw" "$chosen_ch" "$revert_ht_lines"
    mark_dmesg
    clean_restart
    sleep "$SETTLE"
    return 1
  done
}

# --- 2026-07-15 DFS-AWARE SETTLE (coordinator directive) — a robustness net; NOT exercised by the
# shipped 3-rung ladder above (none of its rungs is DFS). Mirrors `wifi_calibrate::
# channel_footprint`/`dfs_cac_seconds`/`select_settle_seconds` exactly. -------------------------

# The 4-channel (20 MHz-spaced) 80 MHz-block groupings across the WHOLE 5 GHz band, DFS included —
# echoes the block containing $1 as a space-separated list, or just $1 itself if it's in no known
# block (e.g. the lone ch165).
five_ghz_block_for() {
  case "$1" in
    36|40|44|48) echo "36 40 44 48" ;;
    52|56|60|64) echo "52 56 60 64" ;;
    100|104|108|112) echo "100 104 108 112" ;;
    116|120|124|128) echo "116 120 124 128" ;;
    132|136|140|144) echo "132 136 140 144" ;;
    149|153|157|161) echo "149 153 157 161" ;;
    *) echo "$1" ;;
  esac
}

# The occupied 20 MHz sub-channels for a (control channel, width): HT20 occupies just itself; HT40
# occupies its pair within the containing block; VHT80 occupies the whole block.
channel_footprint() {
  local ch="$1" mhz="$2" block
  block=$(five_ghz_block_for "$ch")
  case "$mhz" in
    80) echo "$block" ;;
    40)
      # shellcheck disable=SC2086
      set -- $block
      if [ "$#" -eq 4 ]; then
        case "$ch" in
          "$1"|"$2") echo "$1 $2" ;;
          "$3"|"$4") echo "$3 $4" ;;
          *) echo "$ch" ;;
        esac
      else
        echo "$ch"
      fi
      ;;
    *) echo "$ch" ;;
  esac
}

# ETSI EN 301 893 Channel-Availability-Check duration (seconds) for a rung's OCCUPIED footprint:
#   0   — footprint touches no DFS channel (UNII-1 36-48, UNII-3 149-161) — no CAC.
#   60  — a standard DFS channel (UNII-2A 52-64, UNII-2C 100-112 / 132-144).
#   600 — footprint touches the METEOROLOGICAL sub-band 5600-5650 MHz (ch116/120/124/128) — a
#         10-MINUTE CAC; a 60s (or 75s-padded) settle would wrongly fail these.
dfs_cac_seconds() {
  local ch="$1" mhz="$2" fp c meteo=0 dfs=0
  fp=$(channel_footprint "$ch" "$mhz")
  for c in $fp; do
    case "$c" in
      116|120|124|128) meteo=1 ;;
      52|56|60|64|100|104|108|112|132|136|140|144) dfs=1 ;;
    esac
  done
  if [ "$meteo" -eq 1 ]; then echo 600
  elif [ "$dfs" -eq 1 ]; then echo 60
  else echo 0
  fi
}

# Pick the settle (seconds) for a rung: 2.4GHz and non-DFS 5GHz rungs get the ordinary settle
# ($SETTLE / $SETTLE_5GHZ, per band); a DFS rung gets the CAC-appropriate settle instead
# ($SETTLE_DFS_STANDARD / $SETTLE_DFS_METEO) so a slow regulatory CAC is never mistaken for a
# stalled bring-up. None of the shipped ladder's 3 rungs is DFS, so this always returns the
# ordinary settle for them today.
select_settle() {
  local band="$1" ch="$2" mhz="$3" settle dfs_secs
  settle="$SETTLE"; [ "$band" = "5" ] && settle="$SETTLE_5GHZ"
  if [ "$band" = "5" ]; then
    dfs_secs=$(dfs_cac_seconds "$ch" "$mhz")
    if [ "$dfs_secs" -ge 600 ]; then
      settle="$SETTLE_DFS_METEO"
    elif [ "$dfs_secs" -gt 0 ]; then
      settle="$SETTLE_DFS_STANDARD"
    fi
  fi
  echo "$settle"
}

render_rung() {
  local iface="$1" hw_mode="$2" ch="$3" ht_lines="$4"
  # 2026-07-16 (BUG-1 defense-in-depth): guarantee a NON-EMPTY ht_lines ends with exactly one
  # trailing newline before `wmm_enabled=1` follows it — a bare `printf '%s' "$ht_lines"` right
  # before `echo "wmm_enabled=1"` glues the two into ONE malformed line
  # (`ht_capab=[...]wmm_enabled=1`, proven on real Pi4/CM5 hardware) whenever `$ht_lines` doesn't
  # already end in `\n`. The real fix is at the SOURCE — `ht_lines_for_label` below is now the only
  # way this function is called with multi-line content, and LADDER entries never carry it through
  # `read` any more — but this guard stays so no FUTURE caller can reintroduce the glue bug
  # indirectly. Never introduces a blank line: an EMPTY ht_lines (the 2.4GHz/HT20 floor) is left
  # exactly as-is.
  if [ -n "$ht_lines" ] && [ "${ht_lines: -1}" != $'\n' ]; then
    ht_lines="${ht_lines}"$'\n'
  fi
  {
    echo "# GENERATED by wifi-calibrate.sh (D14 verify-retry loop) — do NOT edit; declare intent."
    echo "interface=$iface"; echo "driver=nl80211"
    printf '%s' "$COUNTRY_LINES"
    echo "ssid=$BASE_SSID"; echo "hw_mode=$hw_mode"; echo "channel=$ch"; echo "ieee80211n=1"
    printf '%s' "$ht_lines"
    echo "wmm_enabled=1"
    printf '%s\n' "$BASE_SEC"
  } > "$CONF"
}

# ===============================================================================================
# main — everything below is a side-effecting entry point. Guarded so this file can be `source`d
# (by base/scripts/test-wifi-calibrate.sh) to unit-exercise the functions above without touching a
# real radio/hostapd/dmesg.
# ===============================================================================================
main() {
  IFACE=${1:-wlan0}
  CONF="$HOSTAPD_DIR/hostapd-$IFACE.conf"

  # --- Feature 1: regulatory country — READ-ONLY from the boot/re-resolve oneshots' run-file ----
  # D14 correction: this script NEVER re-resolves the country and NEVER calls `iw reg set` — doing
  # so at runtime (while hostapd is/was serving) is the brcmfmac DFS-bounce trigger. The regdomain
  # is ENTIRELY owned by hookprobe-regdomain.service (boot) / hookprobe-regdomain-reresolve.service
  # (WAN-online re-resolve, D11); this loop only converges the channel WIDTH within whatever domain
  # is already in effect. A missing/unreadable run-file degrades to the world/unresolved token "00"
  # (never a guess), exactly like the sanitiser in `wifi_cfg::sanitize_country`.
  local run_cc_file="${WIFI_COUNTRY_FILE:-/run/hookprobe/wifi-country}"
  local cc="00"
  if [ -r "$run_cc_file" ]; then
    cc=$(tr -dc 'A-Za-z0-9' < "$run_cc_file" 2>/dev/null | head -c2)
    cc=${cc^^}
    [ "${#cc}" -eq 2 ] || cc="00"
  fi
  log "regulatory country = $cc (read-only from $run_cc_file — this loop never re-resolves or iw-reg-sets)"

  mask_supplicant_on_ap

  # Read the resolved SSID + security block from the ordinary generated conf so we never diverge on
  # the security-critical bits (they came from wifi_cfg::render for this device's identity).
  BASE_SSID="HookProbe"
  BASE_SEC=""
  if [ -r "$CONF" ]; then
    local ssid_from_conf
    ssid_from_conf=$(sed -n 's/^ssid=\(.*\)/\1/p' "$CONF" | head -1)
    [ -n "$ssid_from_conf" ] && BASE_SSID="$ssid_from_conf"
    BASE_SEC=$(grep -E '^(auth_algs|wpa|wpa_key_mgmt|rsn_pairwise|wpa_passphrase|ieee8021x|auth_server|dynamic_vlan|vlan_file|ignore_broadcast_ssid)=' "$CONF" || true)
  fi

  # W2 (D12): the country line mirrors wifi_cfg::render_ap exactly — an UNRESOLVED regdomain ("00")
  # OMITS `country_code`/`ieee80211d` entirely (hostapd REJECTS `country_code=00` at config-parse on
  # ANY band); a REAL 2-letter code emits both. Built ONCE (the regdomain is read-only here — see
  # above), reused for every rung this loop tries.
  if [ "$cc" = "00" ]; then
    COUNTRY_LINES=""
  else
    COUNTRY_LINES="country_code=$cc"$'\n'"ieee80211d=1"$'\n'
  fi

  # --- D15: the operator's band intent (hard pin). 2026-07-15: the 2.4 GHz floor is now the
  # CONSTANT ch6 (operator-prescriptive) — no per-device floor channel to resolve here any more.
  local band_pin
  band_pin=$(normalize_band_pin "$(read_band_intent)")
  build_ladder "$band_pin"
  case "$band_pin" in
    5)   log "band intent = HARD PIN 5GHz (auto-ladder DISABLED — AP may end down if no 5GHz rung holds; not recommended)" ;;
    2.4) log "band intent = HARD PIN 2.4GHz (auto-ladder DISABLED — single-band floor only, ch6)" ;;
    *)   log "band intent = auto (fight for 5GHz VHT80-ch40 → HT40-ch36, floor at the always-joinable 2.4GHz ch6)" ;;
  esac

  # --- D19: band-outcome memory — start at the cached PROVEN rung (if still valid) instead of the
  # top, eliminating the fail-storm churn a radio that will never hold VHT80 would otherwise repeat
  # every boot. Invalid/absent cache (regdomain changed, radio swapped, first boot, or a stale label
  # no longer present in THIS pin's ladder) starts at the top exactly as before this change.
  local radio_id band_lkg_file cached_label start_index=0
  radio_id=$(radio_fingerprint "$IFACE")
  band_lkg_file="${WIFI_BAND_LKG_FILE:-$WIFI_BAND_LKG_DIR/wifi-band-lkg-$IFACE.json}"

  # --- ADR 0034 D35-D44: consult the learning model FIRST (D42 precedence: pin > model > boot
  # ladder > floor — the model SUPERSEDES the band-LKG it now also writes). A "ladder" verdict
  # (cold model, nothing legal-and-proven yet, or jq unavailable) falls through to the pre-existing
  # band-LKG file read below UNCHANGED — this is the migration path for a box with history from
  # before this extension, and the ordinary cold-boot path for a brand-new box.
  LEARN_NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  LEARN_FILE="${WIFI_LEARN_FILE:-$WIFI_LEARN_DIR/wifi-learn-$IFACE.json}"
  LEGAL_JSON=$(ladder_legal_json)
  MODEL=$(learn_load "$LEARN_FILE" "$IFACE" "$(fw_fingerprint "$IFACE")" "$LEARN_NOW")
  MODEL=$(learn_age "$MODEL" "$(fw_fingerprint "$IFACE")" "$LEARN_NOW")
  local learn_decision learn_kind learn_label
  learn_decision=$(learn_plan_boot "$MODEL" "$cc" "$radio_id" "$LEGAL_JSON" "$WIFI_LEARN_MODE" "$LEARN_NOW")
  read -r learn_kind learn_label <<<"$learn_decision"

  if [ "$learn_kind" = "resume_at_rung" ] || [ "$learn_kind" = "direct_to_best" ]; then
    cached_label="$learn_label"
    if [ "$learn_kind" = "direct_to_best" ]; then
      # D44: shipped mode is "shadow" — learn_plan_boot itself already degrades this to
      # "resume_at_rung" unless $WIFI_LEARN_MODE=active, so reaching here means Active mode is
      # explicitly enabled. The shell mirror does not yet implement the O(1) single-verify
      # ladder-skip (that stays a Rust-core-only capability pending the `--wifi-calibrate`
      # subcommand) — it safely degrades to starting the retry ladder AT this rung instead, which
      # is a strict (slower but equally safe) subset of DirectToBest.
      log "learning model: DirectToBest($learn_label) requested (active mode) — shell mirror degrades to ResumeAtRung(same rung); full ladder-skip is Rust-core/subcommand-only for now"
    else
      log "learning model: ResumeAtRung('$learn_label') — quality-ranked winner for cc=$cc radio=$radio_id"
    fi
  else
    cached_label=$(read_band_lkg_label "$band_lkg_file" "$cc" "$radio_id")
    if [ -n "$cached_label" ]; then
      log "learning model: cold/no legal winner — falling back to the pre-existing band-LKG '$cached_label'"
    fi
  fi

  if [ -n "$cached_label" ]; then
    local i=0 e lbl found=0
    for e in "${LADDER[@]}"; do
      read -r lbl _ <<<"$e"
      if [ "$lbl" = "$cached_label" ]; then start_index=$i; found=1; break; fi
      i=$((i + 1))
    done
    if [ "$found" -eq 1 ]; then
      log "band-LKG: resuming at proven rung '$cached_label' (index $start_index/${#LADDER[@]}) for cc=$cc radio=$radio_id — skipping known-failing rungs above it"
    else
      start_index=0
      log "band-LKG: cached label '$cached_label' not in this ladder (pin/domain changed) — starting from the top"
    fi
  else
    log "band-LKG: no valid cached rung for cc=$cc radio=$radio_id — starting from the top"
  fi

  local attempts_json="" chosen="" chosen_band="" chosen_ch="" chosen_mhz=""
  local entry label band ch mhz ht_lines hw_mode settle attempt
  local obs_out oper_ch oper_mhz fails rc result action
  for entry in "${LADDER[@]:$start_index}"; do
    # 2026-07-16 (BUG-1): LADDER entries are now exactly 4 single-line fields — `read` can never
    # truncate them. The (possibly multi-line) HT/VHT width block is resolved separately, by label.
    read -r label band ch mhz <<<"$entry"
    ht_lines=$(ht_lines_for_label "$label")
    hw_mode=a; [ "$band" = "2.4" ] && hw_mode=g
    # BUG-W5: 5GHz/VHT rungs get the (proven-adequate) longer settle; the 2.4GHz floor never
    # bounces so it keeps a shorter one if the operator narrowed SETTLE. 2026-07-15: DFS-aware —
    # a DFS rung (none of the shipped 3 today) gets the much longer CAC settle instead.
    settle=$(select_settle "$band" "$ch" "$mhz")
    attempt=0
    while true; do
      log "trying rung $label (attempt $attempt, settle=${settle}s)"
      render_rung "$IFACE" "$hw_mode" "$ch" "$ht_lines"
      mark_dmesg   # BUG-W6: scope THIS attempt's chanspec-fail count before the restart.
      clean_restart
      sleep "$settle"
      # NOTE: `read … < <(observe_rung …)` would capture `read`'s OWN exit status via `$?`, not
      # `observe_rung`'s — process substitution runs asynchronously, so its exit code is never seen
      # by the enclosing `&&`/`||`. Command substitution `$(…)` does NOT have this problem: its exit
      # status IS the function's `return` value (the function call is the last command in the
      # subshell). This is the correct way to capture both the echoed fields AND the verdict.
      obs_out=$(observe_rung "$ch" "$mhz") && rc=0 || rc=$?
      read -r oper_ch oper_mhz fails <<<"$obs_out"
      case "$rc" in
        0) result=stable;; 1) result=width_collapsed;; 2) result=chanspec_fail_storm;; 3) result=down;; *) result=down;;
      esac
      # D36/D42: record EVERY rung verdict into the learning model — a single write path shared by
      # keep/retry/stepdown (the model learns from a same-rung retry's outcome too, not just the
      # final one). Best-effort; a record failure never affects the calibration decision itself.
      MODEL=$(learn_record "$MODEL" "$radio_id" "$cc" "$ch" "$mhz" "$result" "$LEARN_NOW")
      action=$(next_rung_action "$result" "$attempt")
      if [ "$action" = keep ]; then
        attempts_json="${attempts_json:+$attempts_json,}{\"label\":\"$label\",\"width_mhz\":$mhz,\"channel\":$ch,\"result\":\"$result\"}"
        chosen="$label"; chosen_band="$band"; chosen_ch="$ch"; chosen_mhz="$mhz"
        log "rung $label STABLE (ch=$oper_ch width=${oper_mhz}MHz, attempt $attempt, fails=$fails during settle — convergence wins) — keeping"
        break 2
      elif [ "$action" = retry ]; then
        log "rung $label $result (ch=$oper_ch width=${oper_mhz}MHz fails=$fails, attempt $attempt/$MAX_RETRIES) — clean-retrying the SAME rung"
        attempt=$((attempt + 1))
        continue
      else
        attempts_json="${attempts_json:+$attempts_json,}{\"label\":\"$label\",\"width_mhz\":$mhz,\"channel\":$ch,\"result\":\"$result\"}"
        log "rung $label $result (ch=$oper_ch width=${oper_mhz}MHz fails=$fails) — retry budget exhausted, stepping down"
        break
      fi
    done
  done

  # --- D45/D46 (2026-07-17 deep fix, was 2026-07-16 BUG-2): the WARM-UPGRADE — a genuinely-warm,
  # bounded-retry re-attempt of the model-informed (or static ladder-adjacent) wider 5GHz rung now
  # that the radio has settled AND reached real uptime. See `warm_upgrade_candidate`/
  # `resolve_warm_target`/`attempt_warm_upgrade` above for the eligibility + target-selection +
  # apply/observe/commit-or-revert logic itself — this is just the (single, unconditional) call site.
  # NOTE: the eligibility check is the CONDITION of an `if` (not a bare `cmd1 && cmd2` list) —
  # under `set -e`, a plain `A && B` standalone statement DOES abort the script if A (a perfectly
  # normal "not eligible" outcome here) fails; an `if` condition is exempt (same trap the test
  # harness's own `check()` helper avoids — see its header comment).
  if [ -n "$chosen" ] && WARM_CAND=$(warm_upgrade_candidate "$chosen"); then
    local WARM_TARGET WARM_LABEL WARM_BAND WARM_CH WARM_MHZ
    WARM_TARGET=$(resolve_warm_target "$WARM_CAND")
    read -r WARM_LABEL WARM_BAND WARM_CH WARM_MHZ <<<"$WARM_TARGET"
    # CRITICAL (2026-07-17, found on v2 metal): a NON-CONVERGED warm-upgrade returns 1 — that is the
    # NORMAL "reverted to the proven rung, AP still up" outcome, NOT an error. As a BARE command under
    # `set -e` it ABORTED main() right here, so `learn_save` (below) + the band-LKG export NEVER ran →
    # the learning model persisted with `entries: []` EVERY boot → the box could never learn that
    # VHT80-ch40 holds and repeated the same cold-boot mistake forever (the exact symptom the operator
    # hit: "we don't learn that channel 40 holds 80MHz"). `|| true` lets main() continue to persist the
    # model. Same `set -e` trap the eligibility check on the line above already guards against.
    attempt_warm_upgrade "$WARM_LABEL" "$WARM_BAND" "$WARM_CH" "$WARM_MHZ" || true
  fi

  # Persist the learning model NOW (every attempt above already folded in) — best-effort, never
  # blocks the artifact/band-LKG writes below even if this fails.
  learn_save "$MODEL" "$LEARN_FILE"

  # --- status/evidence artifact ---------------------------------------------------------------
  # 2026-07-17 (test-isolation safety fix): resolved FRESH here, at call time — exactly like
  # `LEARN_FILE`/`band_lkg_file` above — NOT as a top-level `STATUS=${WIFI_STATUS:-...}` global
  # (which this used to be). A top-level `:-` default is bound ONCE when the script is sourced;
  # setting `WIFI_STATUS` in the environment AFTER sourcing (exactly what every test harness
  # subshell here does before calling `main`) silently has NO EFFECT on an already-resolved
  # variable — `main()` would keep writing to the REAL default path regardless. This was caught
  # live: a sandboxed test run overwrote this dev box's actual `/var/lib/hookprobe/
  # wifi-calibration.json` (a real, in-use system file) because of exactly this bug. Every other
  # runtime path in this function (`LEARN_FILE`, `band_lkg_file`) already used the safe
  # resolved-at-call-time pattern; `STATUS` now matches them.
  local status="${WIFI_STATUS:-/var/lib/hookprobe/wifi-calibration.json}"
  mkdir -p "$(dirname "$status")" 2>/dev/null || true
  cat > "$status" <<EOF
{
  "iface": "$IFACE",
  "country": { "cc": "$cc", "source": "run-file (read-only; regdomain owned by the D11 oneshots)" },
  "attempts": [ $attempts_json ],
  "chosen": $( [ -n "$chosen" ] && echo "\"$chosen\"" || echo null ),
  "decided_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
  log "wrote calibration status → $status (chosen: ${chosen:-none})"
  if [ -n "$chosen" ]; then
    # D19/D35/D42: the band-LKG is now a READ-ONLY EXPORT written FROM the learning model (its
    # current quality-ranked argmax over this ladder's legal set) — NOT directly from this single
    # boot's chosen rung any more. `read_band_lkg_label`/`band_lkg_valid` above are UNCHANGED; they
    # consume the same file shape either way.
    learn_export_band_lkg "$MODEL" "$cc" "$radio_id" "$LEGAL_JSON" "$LEARN_NOW" "$band_lkg_file"
    if [ -r "$band_lkg_file" ]; then
      log "band-LKG: exported FROM the learning model → $band_lkg_file (cc=$cc radio=$radio_id)"
    else
      # jq unavailable, or (should not happen — this rung was just recorded above) nothing
      # legal-and-proven yet: a direct write keeps behaviour identical to before this extension.
      write_band_lkg "$band_lkg_file" "$cc" "$radio_id" "$chosen_band" "$chosen" "$chosen_ch"
      log "band-LKG: wrote $band_lkg_file directly (learning model export unavailable)"
    fi
  else
    log "WARNING: no stable rung — AP may be down; check radio/regdomain"
    [ "$band_pin" = 5 ] && log "NOTE: band intent is a HARD 5GHz pin (D15) — the always-joinable 2.4GHz floor was intentionally never tried; unpin (band: auto) to restore it"
  fi
}

if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
  main "$@"
fi
