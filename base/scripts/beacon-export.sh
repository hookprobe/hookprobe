#!/usr/bin/env bash
# =============================================================================
# beacon-export.sh — the opt-in, OFF-BY-DEFAULT product-health beacon (ADR 0012 D5).
# =============================================================================
# Ships ONLY product-lifecycle signals (release version, platform class, boot/health
# verdicts, aggregate QSecBit) so a release can be judged by evidence beyond the
# cloud-linked/canary population — NEVER security telemetry, flows, detections, MACs,
# IPs, serials, hostnames, or any other customer data (docs/Readme.md standalone
# invariant: "never gate the device on an account"; ADR 0012 D5).
#
# CONSENT GATE (sacred): with no consent marker present this script does not collect,
# does not construct, and does not write ANYTHING — it logs one line and exits 0. There
# is no default-on path. `enable`/`disable`/`status` manage the marker; this is how
# Administration/the CLI will toggle the beacon (its own consent screen, ADR 0012 D5 —
# "not bundled into any other setting").
#
# TRANSPORT (honest): this script NEVER sends anything over the network — there is no
# cloud transport for standalone devices yet (that is a separate, cloud-linked-only
# step). `beacon-export.sh export` is the manual path: it (re)generates the local file
# and prints its path + contents so an air-gapped operator can attach it to a GitHub
# issue by hand. Cloud-linked/MSSP tenants get the full ADR 0009 evidence offload
# instead (a different, already-designed mechanism) — this script does not do that.
#
# Subcommands:
#   enable    create the consent marker (+ a one-time random salt) — turns the beacon ON
#   disable   remove the consent marker (and any local beacon.json) — turns it OFF
#   status    report whether the beacon is on/off and the last export, if any
#   export    generate beacon.json (gated by consent) and print its path + contents
#   run       generate beacon.json only (gated by consent); no stdout dump — this is
#             what the systemd timer/service calls; also the default with no args
#
# Env overrides (for off-device testing — mirrors the *_DIR override style used
# elsewhere in base/scripts, e.g. HOOKPROBE_DATA_DIR in retention-cap.sh):
#   HOOKPROBE_STATE_DIR   state root, default /var/lib/hookprobe
# =============================================================================
set -uo pipefail

STATE="${HOOKPROBE_STATE_DIR:-/var/lib/hookprobe}"
MANIFEST="$STATE/manifest.json"
CONSENT_DIR="$STATE/consent"
CONSENT_MARKER="$CONSENT_DIR/beacon-v1"
SALT_FILE="$CONSENT_DIR/beacon-v1.salt"
OUT_DIR="$STATE/beacon"
OUT="$OUT_DIR/beacon.json"
QSECBIT_SCORES="$STATE/qsecbit-scores"

log() { echo "beacon-export: $*" >&2; }

usage() {
  echo "usage: beacon-export.sh {enable|disable|status|export|run}" >&2
  echo "  (no consent marker => run/export are a no-op skip; see script header)" >&2
}

# ── consent management ───────────────────────────────────────────────────────
enable_beacon() {
  mkdir -p "$CONSENT_DIR" 2>/dev/null || { log "cannot create $CONSENT_DIR"; return 1; }
  chmod 0700 "$CONSENT_DIR" 2>/dev/null || true
  # One-time random salt, generated locally, never leaves the device except folded
  # one-way into beacon_id (sha256(device_id + salt)). Kept across disable/re-enable
  # so beacon_id stays stable for the device's own continuity; delete the salt file
  # yourself for a fresh identity.
  if [ ! -s "$SALT_FILE" ]; then
    ( umask 077; head -c 32 /dev/urandom 2>/dev/null | sha256sum 2>/dev/null | cut -d' ' -f1 > "$SALT_FILE" )
    [ -s "$SALT_FILE" ] || { log "failed to generate the beacon salt — refusing to enable"; rm -f "$SALT_FILE"; return 1; }
  fi
  date -u +%Y-%m-%dT%H:%M:%SZ > "$CONSENT_MARKER" 2>/dev/null || : > "$CONSENT_MARKER"
  chmod 0600 "$CONSENT_MARKER" "$SALT_FILE" 2>/dev/null || true
  log "beacon-v1 ENABLED — opt-in product-health signals only (no flows/detections/customer data), no network transport (manual export only). Disable any time: beacon-export.sh disable"
}

disable_beacon() {
  rm -f "$CONSENT_MARKER"
  rm -f "$OUT"   # withdrawing consent removes any locally-held beacon output too
  log "beacon-v1 DISABLED — consent withdrawn; local beacon.json removed (device salt kept for continuity if re-enabled)."
}

status_beacon() {
  if [ -f "$CONSENT_MARKER" ]; then
    echo "beacon: ENABLED (beacon-v1) since $(cat "$CONSENT_MARKER" 2>/dev/null || echo unknown)"
    if [ -f "$OUT" ]; then
      echo "  last export: $OUT"
    else
      echo "  last export: none yet"
    fi
  else
    echo "beacon: DISABLED (default — off until explicitly enabled)"
  fi
}

# ── forbidden-fields self-check (defense in depth) ──────────────────────────
# The schema only ever carries product-lifecycle counters/strings we assemble
# ourselves (never a raw manifest passthrough), so this should never fire in
# practice — it exists to catch a future bug that leaks a MAC/IP into a field.
forbidden_fields_present() {
  local f="$1"
  local mac_re='([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}'
  local ip_re='\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
  grep -qE "$mac_re" "$f" 2>/dev/null && return 0
  grep -qE "$ip_re" "$f" 2>/dev/null && return 0
  return 1
}

# ── manifest field reads (RO; tolerate a missing/partial manifest) ─────────
mfield() { [ -f "$MANIFEST" ] && jq -r "$1 // empty" "$MANIFEST" 2>/dev/null; }

# ── collection + write (gated by consent; called by run/export) ───────────
collect_and_write() {
  [ -f "$CONSENT_MARKER" ] || { log "beacon-v1 consent not granted (off by default) — skipping, nothing collected or written. Opt in: beacon-export.sh enable"; return 0; }
  mkdir -p "$OUT_DIR" 2>/dev/null || { log "cannot create $OUT_DIR"; return 1; }

  # beacon_id: salted one-way hash. Salt is generated once by `enable` (never leaves
  # the device raw); device_id itself never appears in the output, only this digest.
  local salt device_id beacon_id
  salt="$(cat "$SALT_FILE" 2>/dev/null || true)"
  if [ -z "$salt" ]; then
    log "no salt at $SALT_FILE (consent marker exists but enable never completed?) — refusing to fabricate an identity"
    return 1
  fi
  device_id="$(mfield '.identity.device_id')"
  beacon_id="$(printf '%s' "${device_id}${salt}" | sha256sum 2>/dev/null | cut -d' ' -f1)"
  [ -n "$beacon_id" ] || { log "failed to compute beacon_id"; return 1; }

  # image_version: provenance.image_ref's tag, with the '-<profile>-<arch>' suffix
  # stripped per ADR 0012 D1's tag shape (<version>-<profile>-<arch>) so the field
  # is the calendar version alone (profile/arch already ship as their own fields
  # below). A tag that doesn't match the shape (e.g. a ':dev' image) is used as-is.
  local device_class profile arch image_ref tag suffix image_version
  device_class="$(mfield '.platform.class')";  [ -n "$device_class" ] || device_class="unknown"
  profile="$(mfield '.platform.profile')";     [ -n "$profile" ]      || profile="unknown"
  arch="$(mfield '.hardware.arch')";           [ -n "$arch" ]         || arch="unknown"
  image_ref="$(mfield '.provenance.image_ref')"
  tag="${image_ref##*:}"
  suffix="-${profile}-${arch}"
  case "$tag" in
    *"$suffix") image_version="${tag%"$suffix"}" ;;
    *)          image_version="${tag:-unknown}" ;;
  esac

  # uptime_hours: real /proc/uptime, truncated to whole hours.
  local uptime_hours
  uptime_hours="$(awk '{h=$1/3600; printf "%d", h}' /proc/uptime 2>/dev/null)"
  case "$uptime_hours" in ''|*[!0-9]*) uptime_hours=0 ;; esac

  # boot.healthy / boot.unhealthy: the greenboot health-gate prints exactly these two
  # markers (supervisor/src/main.rs "BOOT HEALTHY"/"BOOT UNHEALTHY", cited verbatim by
  # ADR 0012 D2 as a signal that already exists on-device) — best-effort grep over
  # whatever the journal currently retains (bounded by base/config/journald.conf.d,
  # MaxRetentionSec=1week today), not a true lifetime cumulative counter.
  # `--since "-7 days"` matches journald's own MaxRetentionSec=1week (journald.conf.d)
  # — no point asking for a window the journal can't have anyway. `timeout` is a hard
  # guarantee: a beacon must never be able to wedge a boot-adjacent oneshot unit, even
  # on a host with an unusually large/slow journal (a real edge device's journal is
  # capped at 200M — SystemMaxUse — so this is normally sub-second there).
  local boot_healthy=0 boot_unhealthy=0
  if command -v journalctl >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
    jc() { timeout 5s journalctl -q --no-pager -g "$1" --since "-7 days" 2>/dev/null | wc -l | tr -d ' '; }
    boot_healthy="$(jc 'BOOT HEALTHY')"
    boot_unhealthy="$(jc 'BOOT UNHEALTHY')"
    case "$boot_healthy" in ''|*[!0-9]*) boot_healthy=0 ;; esac
    case "$boot_unhealthy" in ''|*[!0-9]*) boot_unhealthy=0 ;; esac
  fi
  # boot.rollbacks: TODO(source) — no HookProbe-owned line records a rollback today.
  # Per ADR 0019 D2/D3, a real `bootc rollback` only exists on a bootc-managed UEFI
  # deployment (not built anywhere yet — Phase 1+); on today's rpi-native/mkosi tier
  # there is no rollback to log at all (single-slot, no bootc). Honest zero until
  # ADR 0012 build step 3 (ring/rollback evidence) AND ADR 0019 Phase 2/3 land a real
  # counter that means something on the tier it's read from.
  local boot_rollbacks=0

  # health.{healed,failed,shed,reverted}: TODO(source) — supervisor's per-module health
  # outcomes (HealthState::Healed/Failed/Reverted, crates/hookprobe-manifest/src/health.rs)
  # are printed to the reconcile-pass log but never persisted to a counter file, and in
  # production the probe driving them (DemoProbe, supervisor/src/main.rs:235) only ever
  # simulates a failure when explicitly passed --fail/--flaky/--cut-net (test/demo CLI
  # flags) — there is no real accumulating signal here yet. Honest zeros, not fabricated.
  local health_healed=0 health_failed=0 health_shed=0 health_reverted=0

  # qsecbit_avg: mean of the `.score` field over the real QSecBit score stream
  # (/var/lib/hookprobe/qsecbit-scores, JSON-lines written by qsecbit.service —
  # modules/qsecbit/units/qsecbit.service). NOTE: this is deliberately NOT
  # /var/lib/hookprobe/telemetry — that file holds the pre-score input vector
  # (cpu,mem,net,disk norms sampled by telemetry-export.sh), not a QSecBit score;
  # averaging it would not actually be "qsecbit_avg". Omitted entirely (not "0")
  # when no samples are available yet, per the beacon.json contract.
  local qsecbit_avg=""
  if [ -s "$QSECBIT_SCORES" ] && command -v jq >/dev/null 2>&1; then
    qsecbit_avg="$(tail -n 500 "$QSECBIT_SCORES" 2>/dev/null \
      | jq -r '.score? // empty' 2>/dev/null \
      | awk 'BEGIN{s=0;n=0}{s+=$1;n++}END{if(n>0) printf "%.4f", s/n}')"
  fi

  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # ── assemble beacon.json (schema 1) — atomic tmp+mv, self-checked before commit ──
  local tmp
  tmp="$(mktemp "$OUT_DIR/.beacon.XXXXXX" 2>/dev/null)" || { log "mktemp failed in $OUT_DIR"; return 1; }
  {
    printf '{'
    printf '"schema":1,'
    printf '"kind":"beacon",'
    printf '"beacon_id":"%s",' "$beacon_id"
    printf '"image_version":"%s",' "$image_version"
    printf '"device_class":"%s",' "$device_class"
    printf '"profile":"%s",' "$profile"
    printf '"arch":"%s",' "$arch"
    printf '"uptime_hours":%s,' "$uptime_hours"
    printf '"boot":{"healthy":%s,"unhealthy":%s,"rollbacks":%s},' "$boot_healthy" "$boot_unhealthy" "$boot_rollbacks"
    printf '"health":{"healed":%s,"failed":%s,"shed":%s,"reverted":%s},' \
      "$health_healed" "$health_failed" "$health_shed" "$health_reverted"
    [ -n "$qsecbit_avg" ] && printf '"qsecbit_avg":%s,' "$qsecbit_avg"
    printf '"consent":"beacon-v1",'
    printf '"ts":"%s"' "$ts"
    printf '}\n'
  } > "$tmp"

  if forbidden_fields_present "$tmp"; then
    log "REFUSED — the generated beacon.json matched a forbidden field pattern (MAC or IP address). NOT writing. This indicates a bug upstream of this script — please report it, do not disable the check."
    rm -f "$tmp"
    return 1
  fi

  chmod 0600 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$OUT"
  log "wrote $OUT"
}

export_beacon() {
  collect_and_write || return $?
  if [ -f "$OUT" ]; then
    echo "$OUT"
    cat "$OUT"
  fi
}

case "${1:-run}" in
  enable)  enable_beacon ;;
  disable) disable_beacon ;;
  status)  status_beacon ;;
  export)  export_beacon ;;
  run)     collect_and_write ;;
  -h|--help|help) usage ;;
  *) usage; exit 2 ;;
esac
