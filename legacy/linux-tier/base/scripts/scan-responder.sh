#!/bin/sh
# =============================================================================
# scan-responder.sh — AEGIS reflex for NAPSE port-scan detections (LAN AND WAN scanners).
# =============================================================================
# Long-running: tails EVENTS (napse-dpi's rule-1000003 SYN-scan alerts land here, alongside
# every other NAPSE alert — the supervisor filters for port_scan lines itself; anything else is
# read and ignored) and feeds each line to `hookprobe-supervisor --scan-respond`, which BRANCHES
# ON SOURCE (RFC1918/link-local/CGNAT/loopback = LAN; else WAN):
#   1. ENRICHes the scanner — LAN: the OBSERVED frame MAC the alert already carries (napse-dpi
#      captured it at detection time — 2026-07-05 threat-model fix: NEVER an `ip neigh`/
#      `/proc/net/arp` lookup keyed on the claimed IP, which is exactly as spoofable as that IP;
#      see docs/adr/0018), then the fingerprint crate's MAC-independent identity (hostname/
#      vendor-class/opt55/mDNS/OUI). WAN: PTR (`getent hosts`), coarse /24 grouping, bogon flag,
#      and reputation against HYDRA's already-fetched threat feeds (FEEDS_DIR). Both →
#      host-intel/<key>.json.
#   2. DROPs it — but ONLY if the alert is `confirmed` (a validated TCP handshake was observed,
#      never a single spoofable SYN burst) AND not a WAN-ingress martian (docs/adr/0018 D1/D4);
#      otherwise it is logged/enriched but never enforced. Enforcement is a deterministic nft
#      quarantine, scoped to the RIGHT interface (LAN_IFACE: ip+mac; WAN_IFACE: ip-only,
#      input+forward) — TTL auto-revert (with escalating hold for repeat confirmed offenders),
#      mgmt-path allowlisted (MAC-bound on LAN once PROTECT_MACS is configured), idempotent.
#   3. DOCUMENTs it — one response JSON line per alert, appended to RESPONSES for
#      `hookprobe-evidence --responses` to link to the detection it responded to.
#
# stdout (response JSON lines only) is appended to RESPONSES; the nft bootstrap/plan and any
# diagnostics go to stderr (the unit's journal) — never mixed into the stream hookprobe-evidence
# parses. SAFETY: nft commands are only EXECUTED when SCAN_RESPOND_APPLY=1 (default: print-only
# to stderr) — mirrors trust-reconcile.sh's never-`eval`, plan-first discipline.
# =============================================================================
set -eu
SUP=${SUPERVISOR:-/usr/lib/hookprobe/hookprobe-supervisor}
MANIFEST=${MANIFEST:-/var/lib/hookprobe/manifest.json}
EVENTS=${EVENTS:-/var/lib/hookprobe/events}
RESPONSES=${RESPONSES:-/var/lib/hookprobe/responses}
STATE=${QUARANTINE_STATE_FILE:-/var/lib/hookprobe/scan-quarantine.json}
HOST_INTEL_DIR=${HOST_INTEL_DIR:-/var/lib/hookprobe/host-intel}
TTL=${QUARANTINE_TTL_SECS:-300}
LEASES=${DNSMASQ_LEASES:-}
MDNS=${MDNS_FILE:-}
DHCP_LOG=${DHCP_LOG_FILE:-}
LAN_IFACE=${LAN_IFACE:-wlan0}            # this Pi 4's routed AP (hp-br0 is down)
WAN_IFACE=${WAN_IFACE:-end0}
FEEDS_DIR=${FEEDS_DIR:-/var/lib/hookprobe/feeds}   # HYDRA's already-fetched CIDR feeds (WAN reputation)
APPLY=${SCAN_RESPOND_APPLY:-0}          # 1 = actually run nft; 0 = plan-only (safe default)
ALLOW_UNSIGNED=${ALLOW_UNSIGNED:-0}     # DEV ONLY — the shipping manifest is cosign-signed
NO_AUTO_PROTECT_UPSTREAM=${NO_AUTO_PROTECT_UPSTREAM:-0}  # 1 = skip auto-protecting the live gateway/resolvers (docs/adr/0018 D4)

args="$MANIFEST --scan-respond --quarantine-ttl-secs $TTL --quarantine-state-file $STATE --host-intel-dir $HOST_INTEL_DIR --lan-iface $LAN_IFACE --wan-iface $WAN_IFACE --feeds-dir $FEEDS_DIR"
[ -n "$LEASES" ] && args="$args --dnsmasq-leases $LEASES"
[ -n "$MDNS" ] && args="$args --mdns $MDNS"
[ -n "$DHCP_LOG" ] && args="$args --dhcp-log $DHCP_LOG"
[ "$APPLY" = "1" ] && args="$args --apply"
[ "$ALLOW_UNSIGNED" = "1" ] && args="$args --allow-unsigned"
[ "$NO_AUTO_PROTECT_UPSTREAM" = "1" ] && args="$args --no-auto-protect-upstream"
# Operator-declared protect additions (space-separated env lists), ON TOP OF the built-in
# defaults (10.200.0.0/28 mgmt subnet, 10.66.0.1 gateway) baked into the supervisor, AND the
# auto-resolved live WAN default gateway + DNS resolver(s) (docs/adr/0018 D4 — the concrete fix
# for "spoof this device's own upstream to trigger self-quarantine"; disable via
# NO_AUTO_PROTECT_UPSTREAM=1 above). PROTECT_IPS/PROTECT_CIDRS remain available for anything the
# auto-resolve doesn't cover (e.g. a secondary WAN uplink's address).
for c in ${PROTECT_CIDRS:-}; do args="$args --protect-cidr $c"; done
for i in ${PROTECT_IPS:-}; do args="$args --protect-ip $i"; done
# Known-good MAC(s) for the protected LAN addresses (typically the real gateway's MAC) — once
# set, an on-link impostor spoofing a protected IP from a DIFFERENT mac is NOT exempted from
# quarantine (docs/adr/0018 D5). Space-separated, lowercase colon-hex.
for m in ${PROTECT_MACS:-}; do args="$args --protect-mac $m"; done

# shellcheck disable=SC2086 # $args is intentionally word-split — no argument value has spaces
exec tail -n0 -F "$EVENTS" | "$SUP" $args >> "$RESPONSES"
