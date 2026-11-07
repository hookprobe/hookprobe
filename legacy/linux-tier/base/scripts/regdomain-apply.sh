#!/usr/bin/env bash
# =============================================================================
# regdomain-apply.sh — BOOT-PHASE regulatory-domain detection + apply (ADR 0034 Feature 1).
#
# WHY a dedicated BOOT oneshot (not the runtime wifi-calibrate loop): setting the regdomain at
# RUNTIME (`iw reg set <CC>` while hostapd is already serving) triggers the brcmfmac FullMAC DFS
# bounce — the AP collapses ch40/80MHz → ch140/20MHz (proven live, CM5 2026-07-10). So the
# regdomain MUST be set at BOOT, BEFORE hostapd starts. This script:
#   1. resolves the country (offline-first priority ladder — mirrors wifi_calibrate::decide_country)
#   2. `iw reg set <CC>`  (kernel regdomain — the compliance backstop)
#   3. writes /run/hookprobe/wifi-country  ← the reconciler reads this to set hostapd country_code
# and is ORDERED `Before=` the network reconcile + hostapd (see hookprobe-regdomain.service), so
# both the kernel regdomain AND hostapd's country_code are in place before the radio comes up.
#
# Air-gap-safe & privacy-respecting (ADR 0034 D3/D10, research
# docs/research/2026-07-11-wan-geoip-regdomain-research.json):
#   * The OFFLINE GeoIP rung is a PURELY LOCAL lookup — the box's own PUBLIC WAN exit IP is fed to an
#     embedded ODC-PDDL database (sapics/ip-location-db `user-country`, /usr/share/hookprobe/geoip/).
#     NO packet leaves the box, so it is ON by default and works air-gapped.
#   * When the WAN iface holds only a PRIVATE address (behind an upstream NAT/CGNAT) the exit IP is
#     unknown offline → the GeoIP rung SKIPS, UNLESS the operator opts in (HOOKPROBE_WIFI_GEOIP=1) to
#     a single external IP-ECHO (returns our public IP; we then still look it up OFFLINE). Default
#     off → no outbound identity leak.
#   * The AUTHORITY is always the operator-declared country (intent); GeoIP is only a HINT (Meraki
#     model). Every rung ends at a VALID token (a real 2-letter code or world "00"), NEVER `auto`.
#
# The detection function `hp_resolve_cc` is also SOURCED by wifi-calibrate.sh so the runtime
# WAN-change re-eval uses the exact same logic (single source, no drift between boot and runtime).
# =============================================================================
set -euo pipefail

RUN_CC_FILE=${WIFI_COUNTRY_FILE:-/run/hookprobe/wifi-country}
# Last-known-good cache: the last REAL country any rung resolved. Consulted early (fail-safe against
# a transiently-down WAN at boot) and refreshed whenever a real country resolves. Never holds "00".
LKG_FILE=${WIFI_LKG_FILE:-/var/lib/hookprobe/regdomain-lkg}
# Embedded offline country DB (ODC-PDDL user-country, gzipped CSV `start,end,CC`, sorted).
GEOIP_DIR=${HOOKPROBE_GEOIP_DIR:-/usr/share/hookprobe/geoip}
# Operator intent files, in order: the network.yaml (nested network.wifi.country) then a
# standalone wifi-intent.yaml (top-level country).
read -ra INTENT_FILES <<<"${WIFI_INTENT_FILES:-/etc/hookprobe/network.yaml /var/lib/hookprobe/wifi-intent.yaml}"
# HOOKPROBE_WIFI_GEOIP now gates ONLY the behind-NAT external IP-echo (the offline DB lookup on a
# public WAN IP is always allowed — it is local). 0 = offline-only (default, no leak).
GEOIP_ENABLE=${HOOKPROBE_WIFI_GEOIP:-0}
# Opt-in IP-ECHO endpoint (returns our PUBLIC IP as plain text) — used only when behind NAT AND
# GEOIP_ENABLE=1. We still resolve the country OFFLINE from the returned IP.
GEOIP_ECHO_URL=${HOOKPROBE_WIFI_GEOIP_ECHO_URL:-https://api.ipify.org}
# WAN-change re-eval (wifi-calibrate) sets this to 1 to SKIP the LKG rung and force fresh live
# detection (mobility: a box that physically moved must re-detect, not stick to the cached country).
SKIP_LKG=${HP_REGDOMAIN_SKIP_LKG:-0}
# ADR 0034 D11 (W1) — two-phase regdomain. "boot" (default): the existing fast-path, run BEFORE the
# WAN is up (see hookprobe-regdomain.service). "reresolve": phase (b), run AFTER
# network-online.target (hookprobe-regdomain-reresolve.service) — the WAN now holds a public exit
# IP, so the offline GeoIP rung can resolve the ISP's real country; if it differs from the current
# run-file value, apply it with a CLEAN hostapd stop → iw reg set → reconcile-restart sequence.
MODE=${HP_REGDOMAIN_MODE:-boot}
# Where the reconciler's resolved AP-role interfaces live (aegis::reconcile_network's
# `ifaces.env` artifact) — read by hp_ap_ifaces() below for the reresolve-mode clean switch.
IFACES_ENV_FILE=${HP_IFACES_ENV:-/var/lib/hookprobe/ifaces.env}
# Named distinctly from wifi-calibrate.sh's own $HOSTAPD_DIR (this file is `.`-sourced by that
# script) so sourcing here can never clobber a caller's already-computed hostapd conf path.
AP_HOSTAPD_DIR=${HOSTAPD_CONF_DIR:-/etc/hostapd}

hp_log() { echo "regdomain: $*" >&2; }

# --- last-known-good cache -------------------------------------------------------------------
# Read the cached country (a validated 2-letter code, never 00/blank). Echoes "" if absent/invalid.
hp_read_lkg() {
  local l
  [ -r "$LKG_FILE" ] || { echo ""; return 0; }
  l=$(tr -dc 'A-Za-z' < "$LKG_FILE" 2>/dev/null | head -c2)
  if [ "${#l}" -eq 2 ]; then echo "${l^^}"; else echo ""; fi
}
# Persist a REAL country (never 00) as the last-known-good. Best-effort; failure is non-fatal.
hp_write_lkg() {
  local cc="$1"
  case "$cc" in [A-Za-z][A-Za-z]) : ;; *) return 0 ;; esac
  mkdir -p "$(dirname "$LKG_FILE")" 2>/dev/null || return 0
  printf '%s\n' "${cc^^}" > "$LKG_FILE" 2>/dev/null || true
}

# --- offline GeoIP: public WAN exit IP → ISO country ----------------------------------------
# Is an IP a PUBLIC (globally-routable) address? Rejects RFC1918/CGNAT/link-local/ULA/loopback/
# multicast so we never feed a private address (behind NAT) to the offline DB.
hp_ip_is_public() {
  local ip="$1" a b lo
  case "$ip" in
    *:*)  # IPv6 — only 2000::/3 (2xxx/3xxx) is global unicast; fe80/fc/fd/::1 etc are not.
      lo=${ip,,}
      case "$lo" in 2*|3*) return 0 ;; *) return 1 ;; esac ;;
    *.*)  # IPv4
      IFS=. read -r a b _ _ <<<"$ip"
      [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ ]] || return 1
      case "$a" in
        0|10|127) return 1 ;;
        169) [ "$b" = 254 ] && return 1 || return 0 ;;
        172) { [ "$b" -ge 16 ] && [ "$b" -le 31 ]; } && return 1 || return 0 ;;
        192) [ "$b" = 168 ] && return 1 || return 0 ;;
        100) { [ "$b" -ge 64 ] && [ "$b" -le 127 ]; } && return 1 || return 0 ;;
        22[4-9]|23[0-9]|24[0-9]|25[0-5]) return 1 ;;  # 224-255 multicast/reserved
        *) return 0 ;;
      esac ;;
    *) return 1 ;;
  esac
}

# Determine the box's PUBLIC WAN exit IP for the offline lookup. Prefers the default-route (WAN
# egress) interface's global address. Returns "" when only a private address exists (behind NAT),
# UNLESS the operator opted into the external IP-echo. NO network unless GEOIP_ENABLE=1.
#
# 2026-07-15 (ADR 0034 D-geoip-reresolve field finding): this is DIAGNOSED, not silently a no-op —
# every skip path now logs WHY (to stderr, never mixed into the "IP" stdout the caller captures),
# so an operator staring at "regdomain unchanged (00)" can actually tell whether the WAN wasn't up
# yet, the WAN address is CGNAT/private (increasingly common even on "public-facing" fibre/DOCSIS
# links — an ISP-side NAT444, not just a lab double-NAT), or the echo opt-in is simply off. Also
# TIGHTENED: the previous "no dev-specific address found → scan ANY global address on the box"
# fallback is REMOVED — it could attribute an unrelated interface's address (a container bridge, a
# management VRF, a dummy mirror) to the WAN exit, which is worse than skipping (a wrong country
# over-permits TX power/channels — the same conservative-over-guess principle `decide_country`
# already applies). If the WAN dev itself has no address yet, we simply don't know the exit IP —
# say so and skip; the LKG/timezone/world fallbacks in `hp_resolve_cc` remain the safety net.
hp_wan_exit_ip() {
  local dev ip
  dev=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
  if [ -z "$dev" ]; then
    hp_log "geoip: no default route yet — WAN exit IP unknown (expected at BOOT-phase; the WAN-online re-resolve runs after network-online.target)"
    ip=""
  else
    ip=$(ip -4 -o addr show dev "$dev" scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
    # CD2 (2026-07-17 audit): fall back to a global IPv6 not only when the v4 is ABSENT but also when
    # it is present-but-PRIVATE/CGNAT. A dual-stack ISP with a CGNAT'd v4 + native public v6 is a
    # common real topology (the exact shape this box's own WAN uses) — the old `[ -z "$ip" ]`-only
    # fallback skipped a routable, privacy-safe (local-only) v6 GeoIP lookup whenever a CGNAT v4 was
    # present, silently degrading the regdomain to timezone/world.
    if [ -z "$ip" ] || ! hp_ip_is_public "$ip"; then
      ip6=$(ip -6 -o addr show dev "$dev" scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -v '^fe80' | head -1)
      if [ -n "$ip6" ] && hp_ip_is_public "$ip6"; then ip="$ip6"; fi
    fi
    if [ -z "$ip" ]; then
      hp_log "geoip: WAN dev '$dev' has a default route but no global address yet — exit IP unknown"
    elif hp_ip_is_public "$ip"; then
      echo "$ip"; return 0
    else
      hp_log "geoip: WAN dev '$dev' address $ip is PRIVATE/CGNAT (behind an upstream NAT — increasingly common even on a 'public' fibre/DOCSIS WAN, e.g. ISP-side NAT444/100.64.0.0-10) — offline lookup cannot see the real public IP without consent"
    fi
  fi
  # Behind NAT / no address yet: OFFLINE cannot know the exit IP. Opt-in external echo only —
  # default off (D10b: no outbound identity leak without explicit operator consent).
  if [ "$GEOIP_ENABLE" = 1 ] && command -v curl >/dev/null 2>&1; then
    ip=$(curl -fsS --max-time 4 "$GEOIP_ECHO_URL" 2>/dev/null | tr -dc '0-9a-fA-F.:' | head -c45)
    if [ -n "$ip" ] && hp_ip_is_public "$ip"; then
      hp_log "geoip: resolved the public exit IP via the opt-in echo ($GEOIP_ECHO_URL) — looking it up OFFLINE"
      echo "$ip"; return 0
    fi
    hp_log "geoip: HOOKPROBE_WIFI_GEOIP=1 but the echo did not yield a usable public IP"
  elif [ -z "$ip" ]; then
    hp_log "geoip: skipping (HOOKPROBE_WIFI_GEOIP=0, the default — no outbound identity leak); set =1 to opt into a single external IP-echo when genuinely behind NAT, or declare wifi.country explicitly"
  fi
  echo ""
}

# Look up an IP in the embedded offline DB → ISO country (or ""). Pure awk over the sorted gzipped
# CSV; early-exits once a row's start_ip passes the target (no runtime deps, sub-second at boot).
hp_geoip_lookup() {
  local ip="$1"
  case "$ip" in
    *:*) hp_geoip_lookup6 "$ip" ;;
    *.*) hp_geoip_lookup4 "$ip" ;;
    *)   echo "" ;;
  esac
}
hp_geoip_lookup4() {
  local ip="$1" db="$GEOIP_DIR/user-country-ipv4.csv.gz"
  [ -r "$db" ] || { echo ""; return 0; }
  zcat -- "$db" 2>/dev/null | awk -F, -v ip="$ip" '
    function toint(a,  p){ if(split(a,p,".")!=4) return -1; return ((p[1]*256+p[2])*256+p[3])*256+p[4] }
    BEGIN{ t=toint(ip); if(t<0) exit }
    { s=toint($1); if(s>t) exit; e=toint($2); if(t<=e){ print $3; exit } }
  ' || echo ""
}
hp_geoip_lookup6() {
  local ip="$1" db="$GEOIP_DIR/user-country-ipv6.csv.gz"
  [ -r "$db" ] || { echo ""; return 0; }
  # Expand each address to 32 lowercase hex nibbles → fixed-width lexicographic compare == numeric.
  # Cheap first-hextet prefilter (the CSV is sorted): full expand6 only runs on rows whose leading
  # group matches the target's — bounds the worst case to a first-group scan, not 273k expansions.
  zcat -- "$db" 2>/dev/null | awk -F, -v ip="$ip" '
    function pad4(g){ while(length(g)<4) g="0" g; return g }
    function fgrp(s,   c){ s=tolower(s); c=index(s,":"); if(c) s=substr(s,1,c-1); return pad4(s) }
    function expand6(s,   n,pre,post,a,b,i,nl,nr,fill,out){
      s=tolower(s); out=""
      n=index(s,"::")
      if(n){
        pre=substr(s,1,n-1); post=substr(s,n+2)
        nl=(pre==""?0:split(pre,a,":")); nr=(post==""?0:split(post,b,":"))
        fill=8-nl-nr; if(fill<0) fill=0
        for(i=1;i<=nl;i++) out=out pad4(a[i])
        for(i=0;i<fill;i++) out=out "0000"
        for(i=1;i<=nr;i++) out=out pad4(b[i])
      } else {
        nl=split(s,a,":"); for(i=1;i<=nl;i++) out=out pad4(a[i])
      }
      while(length(out)<32) out=out "0"
      return substr(out,1,32)
    }
    BEGIN{ t=expand6(ip); th=substr(t,1,4) }
    { fg=fgrp($1); if(fg<th) next; if(fg>th) exit;
      s=expand6($1); if(s>t) exit; e=expand6($2); if(t<=e){ print $3; exit } }
  ' || echo ""
}

# Resolve the regulatory country. Echoes "CC SOURCE". NEVER echoes "auto" — a real 2-letter code
# or the world "00". Priority ladder (ADR 0034 D3, fail-SAFE — every rung ends at a VALID token):
#   operator-intent → last-known-good → cellular MCC → offline-GeoIP(public WAN IP) → timezone → 00.
hp_resolve_cc() {
  local cc="" src="" op mcc g exit_ip lkg

  # (a) operator intent override — the AUTHORITY, always wins. Capture the WHOLE token so "auto"
  # (4 chars) is recognised and rejected; only a real 2-char code is taken.
  # CD4 (2026-07-17 audit): the capture's first char is `[A-Za-z0-9]` (not `[A-Za-z]`) so an explicit
  # world-domain pin `country: "00"` is honored — matching the Rust core's `normalize_cc`, which
  # "accepts `00`/`ZZ` (world) verbatim". The old letter-first class silently dropped `00`, so the
  # shell boot path could not honor a world pin the Rust contract accepts.
  for f in "${INTENT_FILES[@]}"; do
    [ -r "$f" ] || continue
    op=$(sed -n 's/^[[:space:]]*country:[[:space:]]*"\?\([A-Za-z0-9][A-Za-z0-9]*\)"\?.*/\1/p' "$f" | head -1)
    if [ -n "$op" ] && [ "${op,,}" != "auto" ] && [ "${#op}" -eq 2 ]; then
      cc="${op^^}"; src="operator"; break
    fi
  done

  # (b) last-known-good cache — fail-safe stability at boot (WAN/modem may not be up yet). Skipped
  # on a WAN-change re-eval (SKIP_LKG=1) so a physically-moved box re-detects live.
  if [ -z "$cc" ] && [ "$SKIP_LKG" != 1 ]; then
    lkg=$(hp_read_lkg); [ -n "$lkg" ] && { cc="$lkg"; src="lkg"; }
  fi

  # (c) cellular modem MCC (ModemManager) → ISO. Best live source for a moving box (it IS the
  # location) — offline (the SIM's serving network), no packet leaves.
  if [ -z "$cc" ] && command -v mmcli >/dev/null 2>&1; then
    mcc=$(mmcli -m any 2>/dev/null | sed -n 's/.*operator id: \([0-9]\{3\}\).*/\1/p' | head -1)
    if [ -n "$mcc" ]; then
      cc=$(hp_mcc_to_iso "$mcc"); [ -n "$cc" ] && src="modem-mcc"
    fi
  fi

  # (d) OFFLINE GeoIP of the PUBLIC WAN exit IP (local DB lookup, no leak). `hp_wan_exit_ip` logs
  # WHY it returned empty (WAN not up / private-CGNAT / echo disabled — see its own comment); the
  # DB-lookup half is diagnosed here too, so "resolved an exit IP but still got no country" (a
  # missing/unreadable DB, or a genuine gap in the embedded ranges) is distinguishable from "never
  # had an exit IP to look up" in the logs.
  if [ -z "$cc" ]; then
    exit_ip=$(hp_wan_exit_ip)
    if [ -n "$exit_ip" ]; then
      g=$(hp_geoip_lookup "$exit_ip" | tr -dc 'A-Za-z' | head -c2)
      if [ "${#g}" -eq 2 ]; then
        cc="${g^^}"; src="geoip"
      else
        hp_log "geoip: resolved exit IP $exit_ip but the offline DB lookup returned no country (missing/unreadable DB at $GEOIP_DIR, or a genuine gap in the embedded ranges) — falling through"
      fi
    fi
  fi

  # (e) system timezone → country (offline, approximate).
  if [ -z "$cc" ] && [ -r /etc/timezone ]; then
    cc=$(hp_tz_to_iso "$(cat /etc/timezone)"); [ -n "$cc" ] && src="timezone"
  fi

  # (f) world fallback — never "auto", never empty (GAP-R1 fix: always a VALID token).
  [ -z "$cc" ] && { cc="00"; src="world"; }
  echo "$cc $src"
}

# Minimal MCC→ISO (mirrors the representative subset of wifi_calibrate::mcc_to_iso). Unlisted → "".
hp_mcc_to_iso() {
  case "$1" in
    234|235) echo GB;; 272) echo IE;; 208) echo FR;; 262) echo DE;; 214) echo ES;;
    222) echo IT;; 204) echo NL;; 206) echo BE;; 232) echo AT;; 228) echo CH;;
    268) echo PT;; 260) echo PL;; 230) echo CZ;; 231) echo SK;; 216) echo HU;;
    226) echo RO;; 284) echo BG;; 202) echo GR;; 240) echo SE;; 242) echo NO;;
    238) echo DK;; 244) echo FI;; 293) echo SI;; 219) echo HR;; 250) echo RU;;
    255) echo UA;; 310|311|312|313|314|315|316) echo US;; 302|303) echo CA;;
    334) echo MX;; 724|725) echo BR;; 440|441) echo JP;; 450) echo KR;; 460|461) echo CN;;
    404|405|406) echo IN;; 505) echo AU;; 530) echo NZ;; 525) echo SG;; 424) echo AE;; *) echo "";;
  esac
}

# Minimal timezone→ISO (mirrors the representative subset of wifi_calibrate::timezone_to_iso).
hp_tz_to_iso() {
  case "$1" in
    Europe/London|Europe/Belfast) echo GB;; Europe/Dublin) echo IE;; Europe/Paris) echo FR;;
    Europe/Berlin) echo DE;; Europe/Madrid) echo ES;; Europe/Rome) echo IT;;
    Europe/Amsterdam) echo NL;; Europe/Bucharest) echo RO;; Europe/Warsaw) echo PL;;
    Europe/Lisbon) echo PT;; Europe/Athens) echo GR;; Europe/Stockholm) echo SE;;
    Europe/Zurich) echo CH;; Europe/Vienna) echo AT;;
    America/New_York|America/Chicago|America/Denver|America/Los_Angeles|America/Phoenix) echo US;;
    America/Toronto|America/Vancouver) echo CA;; America/Mexico_City) echo MX;;
    America/Sao_Paulo) echo BR;; Asia/Tokyo) echo JP;; Asia/Seoul) echo KR;;
    Asia/Shanghai) echo CN;; Asia/Kolkata|Asia/Calcutta) echo IN;; Asia/Singapore) echo SG;;
    Asia/Dubai) echo AE;; Australia/Sydney|Australia/Melbourne) echo AU;; Pacific/Auckland) echo NZ;;
    *) echo "";;
  esac
}

# --- AP-role interface enumeration (reresolve mode's clean-switch target list) --------------
# Enumerate the interface(s) this device actually serves hostapd on, one per line. Prefers the
# reconciler's own resolved fact (`AP_IFACES=` in ifaces.env, if a future reconciler version
# writes one) so this never re-derives topology; falls back to discovering the STAGED hostapd
# configs themselves (`hostapd-<iface>.conf`) — always correct, since network-apply.sh is what
# put them there. Best-effort: an unreadable/absent source yields no lines, never an error.
hp_ap_ifaces() {
  local iface
  unset AP_IFACES 2>/dev/null || true
  if [ -r "$IFACES_ENV_FILE" ]; then
    # SA-F1 (2026-07-17 security audit): DO NOT `source` this file. It lives under
    # /var/lib/hookprobe, whose parent dir is `hookprobe:hookprobe`-owned — a compromised
    # `hookprobe`-uid process (or an escaped Wasm module) could unlink+recreate it with arbitrary
    # shell that THIS ROOT service would then execute (a `hookprobe`→root local privesc, made worse
    # by BUG-N2's CAP_DAC_OVERRIDE). Parse the ONE field we need WITHOUT executing anything, then
    # accept only well-formed interface tokens.
    AP_IFACES=$(sed -n 's/^[[:space:]]*AP_IFACES=//p' "$IFACES_ENV_FILE" 2>/dev/null | head -1)
    AP_IFACES=${AP_IFACES%\"}; AP_IFACES=${AP_IFACES#\"}
    AP_IFACES=${AP_IFACES%\'}; AP_IFACES=${AP_IFACES#\'}
    if [ -n "${AP_IFACES:-}" ]; then
      for iface in $AP_IFACES; do
        case "$iface" in ''|*[!a-zA-Z0-9._-]*) continue ;; esac   # reject anything not an iface name
        echo "$iface"
      done
      return 0
    fi
  fi
  local f base
  for f in "$AP_HOSTAPD_DIR"/hostapd-*.conf; do
    [ -e "$f" ] || continue
    base=$(basename "$f")
    iface=${base#hostapd-}; iface=${iface%.conf}
    [ -n "$iface" ] && echo "$iface"
  done
}

# --- WAN-online re-resolve (D11 phase b) -----------------------------------------------------
# Run AFTER network-online.target: the WAN now (usually) holds a public exit IP, so the offline
# GeoIP rung can resolve the ISP's real country — a rung the BOOT phase can never reach (no WAN
# yet). Idempotency guards (D11): (1) no restart/downgrade unless the CC actually CHANGED to a
# real code; (2) a re-resolve that yields "00"/unresolved is a NO-OP when the run-file already
# holds a real CC (never downgrade a working domain on a transient WAN blip). Only a genuine
# real→real CHANGE triggers the clean switch: stop hostapd (radio idle) → iw reg set (now safe,
# no AP transmitting) → restart the reconcile (re-renders country_code=<cc> and cleanly restarts
# hostapd + the verify loop). Always exits 0 (same fail-safe contract as the boot path).
hp_regdomain_reresolve_main() {
  local cur="" cc="" src="" iface
  if [ -r "$RUN_CC_FILE" ]; then
    cur=$(tr -dc 'A-Za-z0-9' < "$RUN_CC_FILE" 2>/dev/null | head -c2)
  fi
  cur="${cur^^}"
  read -r cc src < <(hp_resolve_cc) || { cc="00"; src="world"; }
  [ -n "$cc" ] || { cc="00"; src="world"; }
  cc="${cc^^}"

  if [ "$cc" = "$cur" ]; then
    # 2026-07-15: name the SOURCE too — "unchanged (00), latest resolve source: world" tells an
    # operator this genuinely found nothing live (see hp_wan_exit_ip's own diagnostics above for
    # WHY geoip specifically didn't fire), vs "unchanged (RO), source: lkg/timezone/modem-mcc"
    # which means a real signal DID resolve, it just matches what was already applied.
    hp_log "reresolve: regdomain unchanged ($cc) — no-op (latest resolve source: $src)"
    return 0
  fi
  if [ "$cc" = "00" ] && [ -n "$cur" ] && [ "$cur" != "00" ]; then
    hp_log "reresolve: resolved unresolved/00 (source: $src) but run-file already holds real $cur — NOT downgrading (transient WAN?)"
    return 0
  fi

  hp_log "reresolve: regdomain CHANGED $cur -> $cc (source: $src) — applying (clean switch)"
  mkdir -p "$(dirname "$RUN_CC_FILE")" 2>/dev/null || true
  if printf '%s\n' "$cc" > "$RUN_CC_FILE" 2>/dev/null; then
    hp_log "wrote $RUN_CC_FILE = $cc"
  else
    hp_log "WARNING: could not write $RUN_CC_FILE"
  fi
  hp_write_lkg "$cc"

  # Clean-switch order (ADR 0034 D11): stop every AP's hostapd first (radio idle, no DFS-bounce
  # risk) → iw reg set (safe now) → reconcile restart (re-renders country_code=<cc> + cleanly
  # restarts hostapd + the verify-retry loop).
  while IFS= read -r iface; do
    [ -n "$iface" ] || continue
    hp_log "reresolve: stopping hookprobe-hostapd@$iface before regdomain switch"
    systemctl stop "hookprobe-hostapd@${iface}.service" 2>/dev/null || true
  done < <(hp_ap_ifaces)

  if command -v iw >/dev/null 2>&1; then
    iw reg set "$cc" 2>/dev/null || hp_log "iw reg set $cc failed (kernel keeps prior domain)"
  fi

  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart hookprobe-network-reconcile.service 2>/dev/null \
      || hp_log "WARNING: could not restart hookprobe-network-reconcile.service"
  fi
  return 0
}

# When EXECUTED (not sourced), detect + apply + record. MUST always exit 0 (GAP-R1 fix): the unit
# must never enter `failed`, and the run-file must never be left empty — on no-resolution we write
# the VALID world token "00", never nothing.
hp_regdomain_main() {
  local cc src
  read -r cc src < <(hp_resolve_cc) || { cc="00"; src="world"; }
  [ -n "$cc" ] || { cc="00"; src="world"; }
  hp_log "regulatory country = $cc (source: $src) — applying BEFORE hostapd"
  if command -v iw >/dev/null 2>&1; then
    iw reg set "$cc" 2>/dev/null || hp_log "iw reg set $cc failed (kernel keeps prior domain)"
  else
    hp_log "iw not installed — cannot set kernel regdomain (hostapd country_code still applied)"
  fi
  mkdir -p "$(dirname "$RUN_CC_FILE")" 2>/dev/null || true
  if printf '%s\n' "$cc" > "$RUN_CC_FILE" 2>/dev/null; then
    hp_log "wrote $RUN_CC_FILE = $cc (reconciler → hostapd country_code)"
  else
    hp_log "WARNING: could not write $RUN_CC_FILE (reconciler falls to 00)"
  fi
  # Refresh the last-known-good cache whenever a REAL country resolved (never cache world 00).
  hp_write_lkg "$cc"
  return 0
}

# Bash "am I sourced?" guard: run only when executed directly. The `|| hp_log` + explicit `exit 0`
# guarantee the oneshot never fails (GAP-R1): a fail-safe world-00 (boot) / no-op (reresolve) is
# always the worst case, never a `failed` unit.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  if [ "$MODE" = reresolve ]; then
    hp_regdomain_reresolve_main "$@" || hp_log "unexpected error in reresolve — no changes applied (fail-safe)"
  else
    hp_regdomain_main "$@" || hp_log "unexpected error in main — kernel keeps prior domain (fail-safe)"
  fi
  exit 0
fi
