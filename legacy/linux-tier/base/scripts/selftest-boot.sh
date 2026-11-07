#!/usr/bin/env bash
# selftest-boot.sh — on-boot self-test verdict. Runs after the self-provisioning chain
# settles and prints a single clear PASS/FAIL line (+ a per-stage breakdown) to the
# console, so a headless/VM boot reports its own health without anyone logging in. This
# is the "device self-tests on first boot" behaviour — and, on today's shipping images,
# it is the ONLY health verdict that actually runs (greenboot itself is not installed/
# wired on the rpi-native/mkosi tier this repo boots today).
#
# HONESTY (ADR 0019 D2/D3): a FAIL here does NOT automatically trigger a `bootc
# rollback` — that used to be implied and was an overclaim. Whether a rollback is even
# POSSIBLE depends on the tier: real only on a bootc-managed UEFI deployment (ADR 0019
# D2, Phase 1+); on rpi-native (no bootc, single-slot image) there is no second
# deployment to fall back to, and the verdict below says so explicitly instead of
# pretending a rollback occurred.
#
# 2026-07-05 FIX (backend-audit P0 #2 — "health verdict decoupled from unit liveness",
# the HIGHEST-priority gap: it hides every dataplane failure). Before this fix, this
# script checked provisioning plumbing (firstboot-data, the data mount, the manifest
# signature, a bare "is the supervisor unit active" info line that never set `fail=1`)
# and NOTHING about the SOC engines the supervisor is supposed to be running — a napse-
# capture-inactive class regression (the live gap this fix would have caught) left every
# alert/detection pipeline dark while SELFTEST still printed PASS. Two things changed:
#   1. Every staged SOC-engine unit is now `systemctl is-active` checked (never just
#      "informational") — derived from the SAME generated preset `builder/gen-staging.sh`
#      writes (`/usr/lib/systemd/system-preset/85-hookprobe-modules.preset`), intersected
#      with a fixed allowlist of dataplane/detection engine ids, so the required set can
#      never silently drift out of sync with what this image actually ships (D0: the
#      registry, not a second hand-maintained list, is the source of truth for WHICH
#      modules exist; this script only decides WHICH OF THOSE are load-bearing enough to
#      gate SELFTEST). `hookprobe-supervisor.service` itself is now also a hard failure,
#      not an info line — a dead supervisor means NONE of the engines it manages are
#      being health-checked at all.
#   2. The pipeline must be observed PRODUCING, not merely "the unit exists and systemd
#      thinks it's active" (a wedged/crash-looping-but-technically-"active" capture
#      engine would still pass a is-active-only check) — `/var/lib/hookprobe/flows`
#      (senzorium-flow/napse-capture's output) or `/var/lib/hookprobe/events` (napse's
#      output) must be present and either its mtime advanced across a short sampling
#      window, or it was touched recently. A dead SOC engine now makes SELFTEST FAIL.
set -uo pipefail
M=${HOOKPROBE_SELFTEST_MANIFEST:-/var/lib/hookprobe/manifest.json}
PRESET=${HOOKPROBE_SELFTEST_PRESET:-/usr/lib/systemd/system-preset/85-hookprobe-modules.preset}
fail=0
sleep 3   # let the oneshot chain finish

echo "================= HOOKPROBE SELF-TEST ================="

systemctl is-active --quiet hookprobe-firstboot-data.service \
  && echo "  firstboot-data : ok" \
  || echo "  firstboot-data : $(systemctl is-failed hookprobe-firstboot-data.service 2>/dev/null || echo n/a)"

if mountpoint -q /var/lib/hookprobe; then echo "  data partition : mounted"; else echo "  data partition : not a separate mount (on rootfs)"; fi

if [ -f "$M" ]; then
  cls=$(jq -r '.platform.class // "?"' "$M" 2>/dev/null)
  if grep -q ed25519-puf "$M"; then echo "  manifest       : signed, class=$cls"; else echo "  manifest       : UNSIGNED"; fail=1; fi
else echo "  manifest       : MISSING"; fail=1; fi

# Supervisor liveness is now a HARD gate (was info-only) — it is the process that starts
# and health-checks every SOC engine below; a dead supervisor means the checks below are
# moot (whatever they observe is a STALE snapshot from before it died).
if systemctl is-active --quiet hookprobe-supervisor.service; then
  echo "  supervisor     : ok"
else
  echo "  supervisor     : $(systemctl is-failed hookprobe-supervisor.service 2>/dev/null || echo inactive)"
  fail=1
fi

n=$(find /run/hookprobe/network -type f 2>/dev/null | wc -l)
if [ "${n:-0}" -ge 3 ]; then echo "  net reconcile  : $n artifacts"; else echo "  net reconcile  : ${n:-0} artifacts (LOW)"; fail=1; fi

# --- SOC engine liveness (P0 #2 fix) --------------------------------------------------
# The allowlist of module ids whose UNIT NAME (id.service, except napse-capture ->
# napse-dpi.service — the staged unit name gen-staging.sh actually copies) gates
# SELFTEST when the generated preset enables it. This is deliberately a small, named set
# of load-bearing DATAPLANE/DETECTION engines (not every enabled unit — e.g. the read-API,
# retention timer, and l2guard's kernel-level enforcement are out of scope here): a dead
# one of THESE means the evidence graph stops growing.
SOC_ALLOW_UNITS="napse.service qsecbit.service dnsxai.service aegis-guard.service napse-dpi.service senzorium-flow.service host-telemetry.service"

required_units=()
if [ -f "$PRESET" ]; then
  while read -r verb unit _rest; do
    [ "$verb" = "enable" ] || continue
    for a in $SOC_ALLOW_UNITS; do
      [ "$unit" = "$a" ] && required_units+=("$unit")
    done
  done < <(grep -E '^(enable|disable)[[:space:]]' "$PRESET" 2>/dev/null)
else
  echo "  soc engines    : generated preset $PRESET MISSING -- cannot derive required unit list"
  fail=1
fi

# hookprobe-scan-responder.service is a BASE unit (base/config/presets/80-hookprobe.preset,
# unconditionally enabled, out of ADR 0015's registry scope) but is exactly as load-bearing
# as the registry-driven engines above (it is the deterministic quarantine RESPONDER half of
# the scan-detect pipeline) -- always required, not derived from the generated preset.
required_units+=("hookprobe-scan-responder.service")

# napse-quarantine is self_gated + hardware-gated (ddos_mitigation) -- its unit line in the
# generated preset is an unconditional `enable` everywhere (the module's OWN loader is what
# checks the capability and exits 0 cleanly when absent, ADR 0015 D4/gen-staging.sh D4), so it
# can't be told apart from an always-required engine by grepping the preset alone. Require it
# ONLY when THIS device's manifest actually granted ddos_mitigation -- on a platform where it
# is absent/denied the module's own loader already exits 0 (clean, healthy, capability-checked
# no-op) and `systemctl is-active` would correctly show "inactive (dead)" for a oneshot that
# already exited -- which must NOT fail SELFTEST there.
if [ -f "$M" ] && [ "$(jq -r '.capabilities.ddos_mitigation.state // empty' "$M" 2>/dev/null)" = "granted" ]; then
  required_units+=("napse-quarantine.service")
fi

# senzorium-flow / host-telemetry are treated as a PAIR: at least one flow/telemetry-producing
# engine must be alive, not both individually -- some platform classes preset-disable one of
# the two (host_telemetry vs the conntrack-polling software fallback), and demanding both would
# make SELFTEST fail on a platform that only ever enables one by design.
flow_pair_present=0
flow_pair_alive=0
soc_dead=()
for u in "${required_units[@]:-}"; do
  [ -n "$u" ] || continue
  case "$u" in
    senzorium-flow.service|host-telemetry.service)
      flow_pair_present=1
      systemctl is-active --quiet "$u" && flow_pair_alive=1
      ;;
    *)
      if systemctl is-active --quiet "$u"; then
        :
      else
        soc_dead+=("$u")
      fi
      ;;
  esac
done
if [ "$flow_pair_present" = 1 ] && [ "$flow_pair_alive" = 0 ]; then
  soc_dead+=("senzorium-flow.service|host-telemetry.service (neither alive)")
fi

if [ "${#required_units[@]}" -gt 0 ]; then
  if [ "${#soc_dead[@]}" -eq 0 ]; then
    echo "  soc engines    : ok (${#required_units[@]} required unit(s) checked)"
  else
    echo "  soc engines    : DEAD: ${soc_dead[*]}"
    fail=1
  fi
fi

# --- pipeline liveness: the engines being "active" per systemd is not enough (a wedged
#     or crash-looping-but-technically-active capture would still pass the check above) --
#     the SHARED STREAM must be observed advancing. -----------------------------------
FLOWS=${HOOKPROBE_SELFTEST_FLOWS:-/var/lib/hookprobe/flows}
EVENTS=${HOOKPROBE_SELFTEST_EVENTS:-/var/lib/hookprobe/events}
producing_check() {
  local f="$1" m1 m2 now
  [ -f "$f" ] || return 1
  m1=$(stat -c %Y "$f" 2>/dev/null) || return 1
  sleep 2
  m2=$(stat -c %Y "$f" 2>/dev/null) || m2="$m1"
  now=$(date +%s)
  [ "$m2" != "$m1" ] && return 0            # advanced across the sampling window
  [ $(( now - m2 )) -le 120 ] && return 0   # or touched very recently
  return 1
}
if producing_check "$FLOWS"; then
  echo "  pipeline       : producing ($FLOWS advancing/recent)"
elif producing_check "$EVENTS"; then
  echo "  pipeline       : producing ($EVENTS advancing/recent)"
else
  echo "  pipeline       : NOT PRODUCING (neither $FLOWS nor $EVENTS advancing/recent)"
  fail=1
fi

# --- ingress-mirror liveness (2026-07-06 fix, F1 self-test — "dead ingress mirror" live-Pi
#     pentest finding). Root cause: modules/napse-quarantine/bpf/quarantine.bpf.c and
#     modules/napse-l2guard/bpf/l2guard.bpf.c used to return TC_ACT_OK on their PASS path; in tc
#     direct-action mode (how both attach) TC_ACT_OK TERMINATES clsact classification for that
#     skb, so the lower-priority matchall mirror filter (crates/hookprobe-manifest/src/inspect.rs,
#     pref 49152 mirred -> hp-mirror) never ran for INGRESS — napse-dpi only ever saw this
#     device's OWN egress traffic, never inbound attacks, which in turn meant
#     napse-dpi/confirm.rs's handshake confirmation (and therefore quarantine enforcement) was
#     structurally impossible on real hardware. Fixed by returning TC_ACT_UNSPEC on the guards'
#     pass paths instead (falls through to the mirror rather than terminating the pipeline) —
#     this check is the boot-time proof that fix stays fixed, so a future regression (a bad NIC
#     offload, a re-introduced TC_ACT_OK, a filter-priority change) is caught here rather than
#     silently reopening a "sensor sees nothing inbound" gap.
#
#     FAIL-SAFE, not a hard requirement (mirrors this script's other "quiet/early boot" checks):
#     a quiet boot with genuinely near-zero traffic yet is NOT a failure (WARN only), and a mirror
#     filter that hasn't been applied yet by the fabric reconciler is also WARN-only. The ONE
#     pattern this DOES hard-fail on is the EXACT symptom the live pentest found: egress traffic
#     climbing while ingress stays at zero on the SAME interface — that asymmetry is only
#     possible if something is once again terminating ingress classification before the mirror
#     filter runs, which is a real regression, not noise. ------------------------------------
MIRROR_SINK=${HOOKPROBE_SELFTEST_MIRROR_SINK:-hp-mirror}
mirror_targets() {
  # Mirrorable interfaces per crates/hookprobe-manifest/src/inspect.rs's `is_mirrorable`: any
  # ethernet/wifi NIC (never the dummy sink itself). Cellular (LTE) is policed but not mirrored,
  # matching that function exactly — see its doc comment.
  #
  # 2026-07-06 FIX (G2 — "SKIPs even though jq IS present"): the manifest's interface list is
  # NOT a top-level `.interfaces[]` field (that path is always null — `hookprobe_manifest::
  # types::Manifest` has no such field) — it lives at `.network.interfaces[]`
  # (`types::Network::interfaces`, see `crates/hookprobe-manifest/src/types.rs`). The old query
  # silently matched nothing on every real manifest ever produced, so `mirror_checked` stayed 0
  # and this WHOLE check permanently no-opped as "SKIP" on every device, defeating the very
  # regression guard the 2026-07-06 dead-ingress-mirror fix above was supposed to add. Confirmed
  # live: `jq '.interfaces' manifest.json` -> null; `jq '.network.interfaces' manifest.json` ->
  # the real end0/wlan0 array.
  if [ -f "$M" ] && command -v jq >/dev/null 2>&1; then
    jq -r --arg sink "$MIRROR_SINK" \
      '.network.interfaces[]? | select((.type=="ethernet" or .type=="wifi") and .name != $sink) | .name' \
      "$M" 2>/dev/null
  fi
}
mirror_pkts() {
  # $1=iface $2=ingress|egress -- packet count of the pref-49152 matchall mirred filter (the
  # SAME pref/handle crates/hookprobe-manifest/src/inspect.rs's render_mirror pins), or empty if
  # that filter (or `tc` itself) isn't present. Pref 49152 is deliberately the LOWEST priority
  # (highest pref number) in the stack, so it is always the LAST filter block `tc -s filter show`
  # prints for a given direction — sticking `f=1` once seen and reading the first "Sent" line
  # after it is therefore unambiguous, not a fragile ordering assumption.
  command -v tc >/dev/null 2>&1 || return 1
  tc -s filter show dev "$1" "$2" 2>/dev/null \
    | awk '/pref 49152/{f=1} f&&/Sent/{for(i=1;i<=NF;i++) if($i=="pkt"){print $(i-1); exit}}'
}
sink_pkts() {
  # Total (RX+TX) packet count on the mirror SINK device itself ($MIRROR_SINK, e.g. hp-mirror) --
  # proves frames actually LAND at the sensor's capture point, which `mirror_pkts` above does not:
  # that only proves the tc filter on the SOURCE nic fired, not that the mirrored copy reached the
  # sink. `render_mirror` (crates/hookprobe-manifest/src/inspect.rs) installs `mirred egress mirror
  # dev $sink` -- the "egress" here names the INJECTION side on the TARGET device, so a mirrored
  # frame is delivered as the sink's own TX (confirmed live: `ip -s link show hp-mirror` books
  # every mirrored packet under TX, RX stays 0 forever) -- napse-dpi's plain AF_PACKET `recv()`
  # still sees it (as PACKET_OUTGOING; Linux's `dev_queue_xmit_nit` delivers outgoing traffic to
  # packet-socket taps by default, no `PACKET_IGNORE_OUTGOING` set here) regardless of which
  # counter the kernel books it under -- so this check sums RX+TX rather than assuming either
  # direction, and stays correct if a future change ever switches to an ingress-redirect mirror.
  command -v ip >/dev/null 2>&1 || return 1
  ip -s link show "$MIRROR_SINK" 2>/dev/null | awk '
    /^ *RX:/{getline; rx=$2}
    /^ *TX:/{getline; tx=$2}
    END{ if (rx=="" && tx=="") { exit 1 } print (rx+0)+(tx+0) }'
}
mirror_checked=0
mirror_asymmetric=()
mirror_missing=()
while read -r ifc; do
  [ -n "$ifc" ] || continue
  mirror_checked=1
  if ! tc filter show dev "$ifc" ingress 2>/dev/null | grep -q "pref 49152 matchall"; then
    mirror_missing+=("$ifc")
    continue
  fi
  ing=$(mirror_pkts "$ifc" ingress); ing=${ing:-0}
  eg=$(mirror_pkts "$ifc" egress); eg=${eg:-0}
  case "$ing" in ''|*[!0-9]*) ing=0 ;; esac
  case "$eg" in ''|*[!0-9]*) eg=0 ;; esac
  # The exact live-Pi symptom: egress climbing while ingress stays at zero -- a real regression,
  # not "quiet boot" (a quiet boot has BOTH near zero). Threshold (5) avoids flagging on a
  # handful of link-local/ARP/DHCP frames that can legitimately be egress-only this early.
  if [ "$eg" -ge 5 ] && [ "$ing" -eq 0 ]; then
    # 2026-07-07 false-positive guard: a Wi-Fi AP with NO associated stations legitimately shows
    # ingress=0 (no client traffic on the air) while it STILL egresses beacons/RAs (egress>0). That
    # is not a dead mirror — it's an idle AP. Only a NON-AP iface (e.g. end0/WAN, which always has a
    # link partner sending frames) or an AP WITH clients showing egress-without-ingress is the real
    # F1 "ingress classification terminates before the mirror" regression. Without this, the flashed
    # Pi (AP up, zero clients yet) FALSE-FAILED SELFTEST on wlan0 while end0's mirror was healthy.
    is_idle_ap=0
    if command -v iw >/dev/null 2>&1 \
       && iw dev "$ifc" info 2>/dev/null | grep -qiE "type AP" \
       && [ "$(iw dev "$ifc" station dump 2>/dev/null | grep -c Station)" -eq 0 ]; then
      is_idle_ap=1
    fi
    [ "$is_idle_ap" -eq 1 ] || mirror_asymmetric+=("$ifc(ingress=0,egress=$eg)")
  fi
done < <(mirror_targets)

if [ "$mirror_checked" = 0 ]; then
  echo "  ingress mirror : SKIP (no manifest / jq / mirrorable interfaces -- cannot check)"
elif [ "${#mirror_asymmetric[@]}" -gt 0 ]; then
  echo "  ingress mirror : DEAD-INGRESS-MIRROR REGRESSION on: ${mirror_asymmetric[*]} -- ingress classification is terminating before the mirror filter again (see 2026-07-06 fix)"
  fail=1
elif [ "${#mirror_missing[@]}" -gt 0 ]; then
  echo "  ingress mirror : WARN -- mirror filter not (yet) installed on: ${mirror_missing[*]} (fabric reconciler may not have applied it yet)"
else
  # 2026-07-06 FIX (G2 continued): the filter-side checks above only prove the SOURCE nic's tc
  # rule fired -- they cannot prove the mirrored copy actually reached the sensor's capture
  # point. Read the SINK device's own counters too (delivery-vs-consumption: this is exactly the
  # class of gap "filter looks fine, sensor still blind" that motivated this whole check).
  sp=$(sink_pkts); sp_rc=$?
  case "$sp" in ''|*[!0-9]*) sp=0 ;; esac
  if [ "$sp_rc" -ne 0 ]; then
    echo "  ingress mirror : WARN -- filters ok, but sink '$MIRROR_SINK' counters unreadable (no 'ip' or interface absent)"
  elif [ "$sp" -eq 0 ]; then
    echo "  ingress mirror : DEAD-MIRROR-SINK -- filters fire on source NIC(s) but '$MIRROR_SINK' shows ZERO packets (RX+TX) -- mirrored frames are not reaching the capture point"
    fail=1
  else
    echo "  ingress mirror : ok (installed; no dead-ingress asymmetry; sink '$MIRROR_SINK' has $sp pkt(s))"
  fi
fi

if [ "$fail" = 0 ]; then
  echo "  >>> HOOKPROBE-SELFTEST: PASS"
else
  echo "  >>> HOOKPROBE-SELFTEST: FAIL"
  # Honest recovery-mechanism report (ADR 0019 D2/D3) — never claim a rollback
  # happened/will happen when there is nothing to roll back to. `bootc status`
  # only succeeds against a real bootc-managed root, so require BOTH the binary
  # AND a successful status query before calling this "bootc-managed".
  if command -v bootc >/dev/null 2>&1 && bootc status >/dev/null 2>&1; then
    echo "  recovery       : bootc-managed deployment detected — greenboot's health-gate"
    echo "                   (ADR 0019 D2) is the path to a REAL 'bootc rollback'."
  else
    echo "  recovery       : NO ROLLBACK SLOT AVAILABLE on this image (single-slot"
    echo "                   rpi-native/mkosi build, no bootc-managed deployment found)."
    echo "                   This boot is marked FAILED; nothing reverts it automatically."
    echo "                   A/B image-sync is ADR 0019 Phase 3, pending. Recovery today"
    echo "                   is a manual reflash from a known-good image."
  fi
fi
echo "======================================================"
exit "$fail"
