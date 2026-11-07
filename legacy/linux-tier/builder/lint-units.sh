#!/usr/bin/env bash
# lint-units.sh — static systemd unit linter for the gate ladder (0.6-unit-lint). Catches three
# classes of unit bug that systemd SILENTLY tolerates (no boot failure, just an easily-missed log
# line), each of which has bitten HookProbe OS on real hardware:
#
#   (1) directive-in-wrong-section — a [Service] directive under [Unit]/[Install] is IGNORED
#       ("Unknown key '<X>' in section [Unit]"). This disabled the bootstrap first-boot re-probe
#       gate (ExecCondition= in [Unit]) → re-probed hardware every boot. 2026-07-06.
#   (2) phantom dependency — After=/Wants=/Requires=/BindsTo= a hookprobe-namespace unit that no
#       repo unit defines. systemd resolves a Wants= to a nonexistent unit INSTANTLY with no error,
#       so the depending unit gets ZERO ordering. host-telemetry ordered against a nonexistent
#       hookprobe-provision-data.service → raced the data mount → EROFS/restart churn. 2026-07-06.
#   (3) malformed Documentation= — a bare path or space-broken value ("Invalid URL, ignoring").
#   (4) base unit relying on the systemd preset no-match fallback — VERIFIED EMPIRICALLY
#       (systemd 255, `systemctl --root=<scratch> preset <unit>` against preset files that have
#       OTHER rules but none matching this unit): a unit with no matching enable/disable/ignore
#       line in ANY preset file is ENABLED by the fallback default, not left alone. This bit
#       `hookprobe-precompile.service` (ADR 0017 D4 said "DELIBERATELY NOT enabled here" — it
#       was, in fact, enabled on every image, running an untrusted-cache AOT precompile pass on
#       every boot). 2026-07-07 backend-audit. Scoped to base/units/ (the hand-maintained set);
#       modules/*/units are already governed by the ADR 0015 registry gate
#       (builder/verify-staging.sh), which recognizes its own `# managed: <unit>` convention.
#   (5) long-running (Restart= set) service with no Slice= — runs unaccounted in the default
#       system.slice, outside the two-wall resource model (Architecture.md §4.3's outer host
#       wall / hookprobe.slice's aggregate MemoryHigh=80% guard never covers it). Found 6 real
#       instances 2026-07-07 (aegis-guard/dnsxai/qsecbit/hookprobe-telemetry/host-telemetry/
#       hookprobe-hostapd@) — all fixed in the same pass this check was added.
#
# Purely static (no systemd needed); runs in CI + the gate ladder.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"

unit_files() { find "$REPO/base" "$REPO/modules" "$REPO/crates" "$REPO/builder" \
  \( -name "*.service" -o -name "*.timer" -o -name "*.socket" -o -name "*.mount" -o -name "*.slice" \) 2>/dev/null; }

# Canonical SOURCE unit files only — excludes builder/mkosi*/mkosi.extra, which are
# build-time-generated mirrors (`cp` of base/units + modules/*/units, refreshed on every real
# mkosi build — see build-arm64.sh/build-vm.sh) rather than hand-maintained originals. Checks
# (4)/(5) judge intent/ownership against the source of truth, not a possibly-stale snapshot.
unit_files_source() { find "$REPO/base" "$REPO/modules" "$REPO/crates" \
  \( -name "*.service" -o -name "*.timer" \) 2>/dev/null; }

fail=0

# ---- (1) directive in wrong section --------------------------------------------------------
svc_re='^(ExecStart|ExecStartPre|ExecStartPost|ExecStop|ExecStopPost|ExecCondition|ExecReload|Type|Restart|RestartSec|WatchdogSec|ReadOnlyPaths|ReadWritePaths|InaccessiblePaths|ProtectSystem|ProtectHome|Environment|EnvironmentFile|User|Group|RemainAfterExit|TimeoutStartSec|TimeoutStopSec|WorkingDirectory|StandardOutput|StandardError|Slice|CapabilityBoundingSet|NoNewPrivileges|DynamicUser|StateDirectory)='
while IFS= read -r f; do
  bad=$(awk -v re="$svc_re" 'BEGIN{sec=""} /^\[/{sec=$0}
    $0 ~ re && (sec=="[Unit]"||sec=="[Install]"){
      print FILENAME":"NR": " $0 "   (in " sec " — SILENTLY IGNORED by systemd; belongs in [Service])"
    }' "$f")
  [ -n "$bad" ] && { echo "$bad"; fail=1; }
done < <(unit_files)

# ---- (2) phantom hookprobe-namespace dependency --------------------------------------------
# All unit names this repo defines (basename of every unit file).
defined="$(unit_files | xargs -r -n1 basename | sort -u)"
# systemd/OS units we legitimately depend on but don't define — never flag these.
ns_re='^(hookprobe|napse|qsecbit|dnsxai|aegis|senzorium|hydra|host-telemetry)'
while IFS= read -r f; do
  # extract After=/Wants=/Requires=/BindsTo= targets (space-separated, may repeat)
  grep -hoE '^(After|Wants|Requires|BindsTo|Requisite|PartOf)=.*' "$f" 2>/dev/null \
    | sed -E 's/^[A-Za-z]+=//' | tr ' ' '\n' | grep -E '\.(service|timer|socket|mount|target)$' \
    | while IFS= read -r dep; do
        # only police OUR namespace .service/.timer/.socket — .mount/.target are OS/derived.
        case "$dep" in
          *.service|*.timer|*.socket)
            if echo "$dep" | grep -qE "$ns_re" && ! echo "$defined" | grep -qxF "$dep"; then
              echo "$f: depends on '$dep' which NO repo unit defines (phantom — systemd resolves it to nothing, giving zero ordering)"
            fi ;;
        esac
      done
done < <(unit_files) > "$REPO/.lint-phantom.$$" || true
if [ -s "$REPO/.lint-phantom.$$" ]; then cat "$REPO/.lint-phantom.$$"; fail=1; fi
rm -f "$REPO/.lint-phantom.$$"

# ---- (3) malformed Documentation= ----------------------------------------------------------
while IFS= read -r f; do
  bad=$(awk 'BEGIN{FS="="} /^Documentation=/{
      v=$0; sub(/^Documentation=/,"",v)
      n=split(v,parts," ")
      for(i=1;i<=n;i++){ t=parts[i]
        if(t !~ /^(https?|file|man|info):/){
          print FILENAME": Documentation token \"" t "\" is not a valid URI (http(s)/file/man/info) — systemd logs \"Invalid URL, ignoring\""
        }
      }
    }' "$f")
  [ -n "$bad" ] && { echo "$bad"; fail=1; }
done < <(unit_files)

# ---- (4) base unit relying on the preset no-match fallback --------------------------------
PRESETS="$(find "$REPO/base/config/presets" -name '*.preset' 2>/dev/null)"
while IFS= read -r f; do
  grep -q '^\[Install\]' "$f" 2>/dev/null || continue
  grep -q '^WantedBy=' "$f" 2>/dev/null || continue
  unit=$(basename "$f")
  matched=0
  for p in $PRESETS; do
    grep -qE "^(enable|disable|ignore)[[:space:]]+${unit}([[:space:]]|\$)" "$p" 2>/dev/null && matched=1
  done
  if [ "$matched" -eq 0 ]; then
    echo "$f: '$unit' has [Install] WantedBy= but no explicit enable/disable/ignore line in base/config/presets/*.preset — systemd's PROVEN no-match fallback is to ENABLE it, which may silently contradict this unit's documented intent (see the hookprobe-precompile.service incident, 2026-07-07)"
    fail=1
  fi
done < <(find "$REPO/base/units" -name '*.service' -o -name '*.timer' 2>/dev/null)

# ---- (5) long-running service missing Slice= (escapes the two-wall resource model) ---------
while IFS= read -r f; do
  grep -q '^Restart=' "$f" 2>/dev/null || continue
  grep -q '^Slice=' "$f" 2>/dev/null && continue
  echo "$f: has Restart= (long-running/auto-restarted) but no Slice= — runs unaccounted in the default system.slice, outside the two-wall resource model (Architecture.md §4.3)"
  fail=1
done < <(unit_files_source)

if [ "$fail" -ne 0 ]; then
  echo "unit-lint: FAIL — see findings above"
  exit 1
fi
echo "unit-lint: OK — no misplaced directives, phantom deps, malformed Documentation URIs, preset-fallback surprises, or unaccounted long-running services"
