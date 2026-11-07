#!/usr/bin/env bash
# =============================================================================
# dns-sinkhole-apply.sh — install the GENERATED RPZ zone / dnsmasq blocklist
# (`hookprobe-dns-sinkhole.{service,timer}`, roadmap A1) into whichever RPZ/blocklist-capable
# resolver this device actually runs.
#
# HONEST GAP (docs/adr/0033-dns-sinkhole-rpz.md): this device's DEFAULT LAN resolver is
# systemd-resolved (`crates/hookprobe-manifest/src/lan.rs`: DHCP hands the gateway out as the
# resolver, a `resolved.conf.d` drop-in makes resolved listen there) — and systemd-resolved has
# NO RPZ / domain-blocklist mechanism at all, unlike BIND/Unbound/Knot (RPZ) or dnsmasq
# (`address=/domain/`). On a stock device this script therefore finds nothing to apply and says
# so plainly (exit 0, unchanged system) — it activates automatically, with zero code changes, the
# day an operator installs dnsmasq or an RPZ-capable resolver. This mirrors the EXACT tool-gated,
# non-fatal, named-reason-on-skip discipline `network-apply.sh`'s own OVS/nft steps already use.
#
# Deliberately kept SEPARATE from `hookprobe-dns-sinkhole.service` (which only ever writes under
# /var/lib/hookprobe — its whole point is a narrow, minimal-grant generator, ADR 0033) — same
# two-stage "narrow generator, separate applier" split `hookprobe-network-reconcile.service` /
# `network-apply.sh` already use for network config. Run this manually, or wire it into a future,
# explicitly broader-privileged unit once a target resolver is actually chosen for a device
# (deliberately NOT auto-wired here — this script needs write access to /etc/dnsmasq.d,
# /etc/bind, or /var/lib/unbound depending on what's installed, none of which a stock image ships
# or grants by default).
# =============================================================================
set -euo pipefail
SRC_DIR=${SRC_DIR:-/var/lib/hookprobe/dns-sinkhole}
RPZ_SRC="$SRC_DIR/hookprobe-sinkhole.rpz"
DNSMASQ_SRC="$SRC_DIR/hookprobe-sinkhole.dnsmasq.conf"
log() { echo "dns-sinkhole-apply: $*" >&2; }

applied=0

# dnsmasq — the common lightweight-edge resolver alternative.
if command -v dnsmasq >/dev/null 2>&1 && [ -d /etc/dnsmasq.d ] && [ -e "$DNSMASQ_SRC" ]; then
  if install -m 0644 "$DNSMASQ_SRC" /etc/dnsmasq.d/hookprobe-sinkhole.conf 2>/dev/null; then
    systemctl reload-or-restart dnsmasq 2>/dev/null || true
    log "installed -> /etc/dnsmasq.d/hookprobe-sinkhole.conf (dnsmasq reloaded)"
    applied=1
  else
    log "dnsmasq present but /etc/dnsmasq.d not writable — skipping"
  fi
fi

# Unbound — RPZ via an operator-declared auth-zone; we only ever refresh the ZONE FILE, never
# touch unbound.conf itself (the operator's own config decides whether/how it's referenced).
if command -v unbound-control >/dev/null 2>&1 && [ -d /var/lib/unbound ] && [ -e "$RPZ_SRC" ]; then
  if install -m 0644 "$RPZ_SRC" /var/lib/unbound/hookprobe-sinkhole.rpz 2>/dev/null; then
    unbound-control reload 2>/dev/null || true
    log "installed -> /var/lib/unbound/hookprobe-sinkhole.rpz (unbound reload signaled)"
    applied=1
  else
    log "unbound-control present but /var/lib/unbound not writable — skipping"
  fi
fi

# BIND — RPZ via `response-policy`; same "zone file only, never touch named.conf" discipline.
if command -v rndc >/dev/null 2>&1 && [ -d /etc/bind ] && [ -e "$RPZ_SRC" ]; then
  if install -m 0644 "$RPZ_SRC" /etc/bind/hookprobe-sinkhole.rpz 2>/dev/null; then
    rndc reload 2>/dev/null || true
    log "installed -> /etc/bind/hookprobe-sinkhole.rpz (rndc reload signaled)"
    applied=1
  else
    log "rndc present but /etc/bind not writable — skipping"
  fi
fi

if [ "$applied" = 0 ]; then
  log "no RPZ/blocklist-capable resolver found on this device (systemd-resolved has no such support" \
      "— ADR 0033). Artifact staged at $SRC_DIR, not applied. Install dnsmasq or an RPZ-capable" \
      "resolver (BIND/Unbound/Knot) to activate DNS-layer enforcement — no code change required."
fi
exit 0
