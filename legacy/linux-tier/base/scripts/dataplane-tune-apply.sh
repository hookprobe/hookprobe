#!/usr/bin/env bash
# =============================================================================
# dataplane-tune-apply.sh — base-tier single-queue dataplane tuning recipe
# (base-tier-build-ticket.md Phase 1, ADR 0031 amendment §C, ADR 0003 "Base-tier
# capability tokens"). Run by hookprobe-tune-bcm2712.service (oneshot, every boot).
#
# WHAT this does — all config-only, zero new kernel code, zero new BOM:
#   1. Threaded NAPI ON  (`/sys/class/net/<if>/threaded=1`) on the box's real WAN/LAN
#      NICs — RX softirq becomes a cgroup-accountable kthread (closes the
#      CPUQuota-blind-to-softirq accounting hole; a DDoS-era fix, not just perf).
#   2. NIC IRQ smp_affinity pinned to `dataplane_tuning.irq_affinity_cpus`.
#   3. GRO ON (global, if `dataplane_tuning.gro: true`).
#   4. RPS — OFF by default; opt-in ONLY when `dataplane_tuning.rps_default: true`,
#      and then ONLY to `dataplane_tuning.rps_cpu_mask` (never shares a core with the
#      detection cpuset).
#   5. Detection cpuset — `systemctl set-property --runtime hookprobe-live.slice
#      AllowedCPUs=<dataplane_tuning.detection_allowed_cpus>` (QSECBIT/NAPSE epoch
#      workers; the live slice already hosts them, see base/units/hookprobe-live.slice).
#   6. big.LITTLE (RK3588 only, when `dataplane_tuning.housekeeping_allowed_cpus` is
#      set) — pins `hookprobe-background.slice` (retention/telemetry/housekeeping) to
#      the A55 cores, leaving the A76 cores (`detection_allowed_cpus` +
#      `irq_affinity_cpus`) for NAPI + detection.
#
# WHAT this deliberately does NOT do (release-blocking non-goal, ticket Phase 1):
#   - NO `isolcpus=` / `nohz_full=` kernel command-line changes — everything here is
#     cgroup-v2 `AllowedCPUs=` (soft, reconciler-owned, reversible every boot) plus
#     plain sysfs/IRQ knobs. Touching kargs.d would need a reboot to take effect and
#     would fight the supervisor's own budget model; out of scope for this phase.
#
# SOURCE OF TRUTH: `platforms/<profile>.yaml`'s `dataplane_tuning:` block, shipped
# read-only at /usr/share/hookprobe/platforms/ (Containerfile Layer E / build-arm64.sh
# L142) — matched via the SIGNED manifest's `.profile` field, gated on the `tc_bpf`
# capability being granted. Deliberately NOT parsed with a real YAML library: same
# hand-authored/stable-subset rationale as base/Containerfile's profile-package-overlay
# parser (Layer A4) — awk/sed only, no new build dependency. A platform with no
# `dataplane_tuning:` block (n100/generic/cloud/rpi4/…) is a clean, silent no-op: this
# script is shipped and enabled on EVERY image (one preset line), the profile itself is
# what makes it live or inert — "add hardware = one platforms/*.yaml file", no code
# branch here.
#
# FAIL-OPEN, ALWAYS: every step here is a perf/accounting tuning knob, never a
# detection or enforcement path. A missing/unwritable sysfs node, an absent IRQ, or a
# malformed dataplane_tuning value logs a WARNING and moves on — this script must NEVER
# fail the boot or block the network reconcile that runs alongside it.
# =============================================================================
set -uo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

MANIFEST=${MANIFEST:-/var/lib/hookprobe/manifest.json}
PLATFORMS_DIR=${PLATFORMS_DIR:-/usr/share/hookprobe/platforms}
IFACES_ENV=${IFACES_ENV:-/var/lib/hookprobe/ifaces.env}

log() { echo "dataplane-tune: $*" >&2; }

# ---- 0. gates: manifest present, jq present, tc_bpf granted -----------------------
[ -e "$MANIFEST" ] || { log "no manifest at $MANIFEST yet — nothing to tune, exiting 0"; exit 0; }
command -v jq >/dev/null 2>&1 || { log "jq not installed — cannot read the manifest, exiting 0 (fail-open)"; exit 0; }

capability_state() { jq -r --arg t "$1" '.capabilities[$t].state // "absent"' "$MANIFEST" 2>/dev/null; }
if [ "$(capability_state tc_bpf)" != "granted" ]; then
  log "tc_bpf not granted on this device — the single-queue TC-bpf dataplane this recipe tunes for isn't live here, exiting 0"
  exit 0
fi

PROFILE=$(jq -r '.profile // empty' "$MANIFEST" 2>/dev/null)
if [ -z "$PROFILE" ]; then
  log "manifest has no .profile — cannot resolve a platforms/*.yaml, exiting 0 (fail-open)"
  exit 0
fi
PROFILE_YAML="$PLATFORMS_DIR/${PROFILE}.yaml"
if [ ! -e "$PROFILE_YAML" ]; then
  log "no $PROFILE_YAML shipped — exiting 0 (fail-open)"
  exit 0
fi

# ---- 1. extract the dataplane_tuning: block (flat 2-space `key: value` scalars) ---
# Grabs every line strictly after the `dataplane_tuning:` header that is indented
# (i.e. still inside the block), stopping at the next unindented (top-level) key.
tuning_block() {
  awk '
    /^dataplane_tuning:[[:space:]]*$/ { grab=1; next }
    grab && /^[^[:space:]#]/          { grab=0 }
    grab                               { print }
  ' "$PROFILE_YAML"
}
BLOCK=$(tuning_block)
if [ -z "$BLOCK" ]; then
  log "$PROFILE_YAML has no dataplane_tuning: block — this profile opts out, exiting 0"
  exit 0
fi

# tval <key> — the block's flat scalar for <key>, comment/whitespace-stripped, or empty.
tval() {
  printf '%s\n' "$BLOCK" \
    | grep -E "^[[:space:]]*$1:" \
    | head -1 \
    | sed -E "s/^[[:space:]]*$1:[[:space:]]*//" \
    | sed -E 's/[[:space:]]*#.*$//' \
    | sed -E 's/[[:space:]]+$//'
}

NAPI_THREADED=$(tval napi_threaded)
GRO=$(tval gro)
IRQ_AFFINITY_CPUS=$(tval irq_affinity_cpus)
DETECTION_ALLOWED_CPUS=$(tval detection_allowed_cpus)
RPS_DEFAULT=$(tval rps_default)
RPS_CPU_MASK=$(tval rps_cpu_mask)
HOUSEKEEPING_ALLOWED_CPUS=$(tval housekeeping_allowed_cpus)

log "profile=$PROFILE napi_threaded=$NAPI_THREADED gro=$GRO irq_affinity_cpus=$IRQ_AFFINITY_CPUS detection_allowed_cpus=$DETECTION_ALLOWED_CPUS rps_default=$RPS_DEFAULT housekeeping_allowed_cpus=$HOUSEKEEPING_ALLOWED_CPUS"

# ---- 2. resolve the box's real dataplane interfaces (never hardcode end0/wlan0) ---
# Same source every other AEGIS reflex reads (resource-shed-reconcile.sh,
# scan-responder.sh, napse-quarantine/l2guard) — written by
# hookprobe-network-reconcile.service's ExecStartPost (network-apply.sh) from the SAME
# reconcile pass that classified the WAN uplink + LAN bridge/routed-AP radio.
# shellcheck disable=SC1090
[ -e "$IFACES_ENV" ] && . "$IFACES_ENV" 2>/dev/null
WAN_IFACE=${WAN_IFACE:-}
LAN_IFACE=${LAN_IFACE:-}

is_wireless() {
  [ -e "/sys/class/net/$1/wireless" ] || [ -e "/sys/class/net/$1/phy80211" ]
}

# find_irqs <if> — resolve the kernel IRQ number(s) servicing this netdev. MSI-backed
# devices (PCIe NICs, e.g. an i226/dwmac carrier) list exact numbers under
# device/msi_irqs; the Cadence GEM (macb) behind Pi5/CM5's RP1 is a platform (non-MSI)
# device whose IRQ line /proc/interrupts lists by the netdev's own interface name —
# the portable way to resolve it without hardcoding the RP1 platform-device string.
find_irqs() {
  ifc="$1"
  if [ -d "/sys/class/net/$ifc/device/msi_irqs" ]; then
    ls "/sys/class/net/$ifc/device/msi_irqs" 2>/dev/null
    return 0
  fi
  awk -v ifc="$ifc" '$0 ~ ifc { gsub(":", "", $1); print $1 }' /proc/interrupts 2>/dev/null
}

tune_iface() {
  ifc="$1"
  [ -n "$ifc" ] || return 0
  [ -e "/sys/class/net/$ifc" ] || { log "iface $ifc not present — skipping"; return 0; }
  if is_wireless "$ifc"; then
    log "iface $ifc is a wireless radio — skipping dataplane tuning (brcmfmac path stays untouched)"
    return 0
  fi

  # 2a. Threaded NAPI.
  if [ "$NAPI_THREADED" = "true" ]; then
    if [ -e "/sys/class/net/$ifc/threaded" ]; then
      if echo 1 > "/sys/class/net/$ifc/threaded" 2>/dev/null; then
        log "threaded NAPI on for $ifc"
      else
        log "WARNING: could not enable threaded NAPI on $ifc (non-fatal)"
      fi
    else
      log "$ifc has no threaded NAPI sysfs knob (older kernel/driver) — skipping (non-fatal)"
    fi
  fi

  # 2b. GRO.
  if [ "$GRO" = "true" ] && command -v ethtool >/dev/null 2>&1; then
    if ethtool -K "$ifc" gro on >/dev/null 2>&1; then
      log "GRO on for $ifc"
    else
      log "WARNING: ethtool could not toggle GRO on $ifc (non-fatal)"
    fi
  fi

  # 2c. IRQ affinity.
  if [ -n "$IRQ_AFFINITY_CPUS" ]; then
    irqs=$(find_irqs "$ifc")
    if [ -z "$irqs" ]; then
      log "no IRQ resolved for $ifc — smp_affinity not pinned (non-fatal)"
    else
      for irq in $irqs; do
        f="/proc/irq/$irq/smp_affinity_list"
        if [ -w "$f" ]; then
          if echo "$IRQ_AFFINITY_CPUS" > "$f" 2>/dev/null; then
            log "IRQ $irq ($ifc) smp_affinity_list=$IRQ_AFFINITY_CPUS"
          else
            log "WARNING: could not pin IRQ $irq ($ifc) to $IRQ_AFFINITY_CPUS (non-fatal)"
          fi
        fi
      done
    fi
  fi

  # 2d. RPS — default OFF; explicit opt-in only. Always writes SOMETHING (even the
  #     "off" 0 mask) so a stale mask from a prior manual test/older boot never lingers.
  for q in /sys/class/net/"$ifc"/queues/rx-*/rps_cpus; do
    [ -e "$q" ] || continue
    if [ "$RPS_DEFAULT" = "true" ] && [ -n "$RPS_CPU_MASK" ]; then
      mask=0
      for core in $(printf '%s' "$RPS_CPU_MASK" | tr ',' ' '); do
        case "$core" in ''|*[!0-9]*) continue ;; esac
        mask=$(( mask | (1 << core) ))
      done
      hexmask=$(printf '%x' "$mask")
      if echo "$hexmask" > "$q" 2>/dev/null; then
        log "RPS opt-in: $ifc $(basename "$(dirname "$q")") rps_cpus=$hexmask (cores $RPS_CPU_MASK)"
      else
        log "WARNING: could not set RPS mask on $ifc $q (non-fatal)"
      fi
    else
      echo 0 > "$q" 2>/dev/null || true
    fi
  done
}

# Dedup WAN/LAN (single-NIC boxes have WAN_IFACE == LAN_IFACE).
IFACES=$(printf '%s\n%s\n' "$WAN_IFACE" "$LAN_IFACE" | awk 'NF' | sort -u)
if [ -z "$IFACES" ]; then
  log "no WAN_IFACE/LAN_IFACE resolved from $IFACES_ENV yet — skipping NIC-level tuning this boot"
else
  for ifc in $IFACES; do
    tune_iface "$ifc"
  done
fi

# ---- 3. detection cpuset (QSECBIT/NAPSE epoch workers, hookprobe-live.slice) -------
# `--runtime`: this is a re-derived-every-boot value from the SIGNED manifest, not a
# persistent operator override — matches every other reconciler-owned setting in this
# repo (never hand-edit the unit; the tuning recipe re-applies it every boot).
if [ -n "$DETECTION_ALLOWED_CPUS" ]; then
  if systemctl set-property --runtime hookprobe-live.slice AllowedCPUs="$DETECTION_ALLOWED_CPUS" 2>/dev/null; then
    log "hookprobe-live.slice AllowedCPUs=$DETECTION_ALLOWED_CPUS (detection cpuset)"
  else
    log "WARNING: could not set hookprobe-live.slice AllowedCPUs=$DETECTION_ALLOWED_CPUS (non-fatal)"
  fi
fi

# ---- 4. big.LITTLE housekeeping pin (RK3588 only — empty/absent elsewhere) --------
if [ -n "$HOUSEKEEPING_ALLOWED_CPUS" ]; then
  if systemctl set-property --runtime hookprobe-background.slice AllowedCPUs="$HOUSEKEEPING_ALLOWED_CPUS" 2>/dev/null; then
    log "hookprobe-background.slice AllowedCPUs=$HOUSEKEEPING_ALLOWED_CPUS (A55 housekeeping cpuset)"
  else
    log "WARNING: could not set hookprobe-background.slice AllowedCPUs=$HOUSEKEEPING_ALLOWED_CPUS (non-fatal)"
  fi
fi

log "dataplane tuning applied for profile=$PROFILE"
exit 0
