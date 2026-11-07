#!/usr/bin/env bash
# =============================================================================
# network-apply.sh — INSTALL the AEGIS-generated network artifacts to their live
# locations. This is the consumer that closes the gap between
# `hookprobe-supervisor --reconcile-network --network-write /run/hookprobe/network`
# (which only STAGES files) and the running system.
#
# By artifact type (all under $STAGE):
#   50-hookprobe-wan-*.network   → /etc/systemd/network/  + `networkctl reload`
#   hostapd-*.conf               → /etc/hostapd/          (hostapd@ units start them)
#   fabric/*.ovs.plan            → run (ovs-vsctl … bridge/ports/segments; idempotent)
#   fabric/*.flows.of            → ovs-ofctl add-flows <bridge-from-filename> -
#   fabric/63-microseg.*.of      → ovs-ofctl add-flows $BRIDGE -
#   fabric/60-vrf.plan           → run (ip vrf + nft; idempotent)
#   fabric/*.linux-bridge.plan   → run (ip link bridge; idempotent)
#
# Idempotent + capability-gated (OVS steps need `openvswitch` granted). `--check` prints
# the plan, changes nothing.
# =============================================================================
set -euo pipefail
# Pin a known-good PATH. This runs as an early-boot ExecStartPost of the (ProtectSystem=strict)
# reconcile service, where the inherited PATH proved flaky: `command -v hostapd` (hostapd lives
# in /usr/sbin) intermittently returned false at boot, silently skipping the hostapd-restart +
# wifi-calibrate start block below (AP stuck on the initial band, never stepped up to 5GHz). The
# gate below now also checks the absolute path, so this is belt-and-suspenders.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
MANIFEST=${MANIFEST:-/var/lib/hookprobe/manifest.json}
STAGE=${STAGE:-/run/hookprobe/network}
NETDIR=${NETDIR:-/etc/systemd/network}
HOSTAPD_DIR=${HOSTAPD_DIR:-/etc/hostapd}
BRIDGE=${BRIDGE:-hp-br0}
PLAN=0; [ "${1:-}" = "--check" ] && PLAN=1
log() { echo "network-apply: $*" >&2; }
run() { if [ "$PLAN" = 1 ]; then log "PLAN: $*"; else log "+ $*"; "$@"; fi; }
runsh() { if [ "$PLAN" = 1 ]; then log "PLAN: sh $1"; else log "+ sh $1"; sh "$1" || log "  WARNING: $1 had failures (continuing)"; fi; }

granted() { [ "$(jq -r --arg t "$1" '.capabilities[$t].state // "absent"' "$MANIFEST" 2>/dev/null)" = "granted" ]; }
[ -d "$STAGE" ] || { log "no staged artifacts at $STAGE — run the reconcile first"; exit 0; }
# Target dirs may not exist on a minimal image (e.g. no hostapd package → no /etc/hostapd).
[ "$PLAN" = 1 ] || mkdir -p "$NETDIR" "$HOSTAPD_DIR" /etc/systemd/resolved.conf.d 2>/dev/null || true

# 0. Ring-0 enforcement interface bindings (LAN_IFACE/WAN_IFACE/MIRROR_IFACE + each BPF loader's
#    namespaced names — `aegis::reconcile_network`'s `ifaces.env` artifact). THE cross-platform
#    fix: napse-quarantine/napse-l2guard (TC-bpf) and scan-responder.sh's nft quarantine load this
#    via `EnvironmentFile=-/var/lib/hookprobe/ifaces.env`, so they bind to THIS device's
#    manifest-classified interfaces instead of a hardcoded Pi default (confirmed live on an amd64
#    VM: `read ifindex for wlan0: No such file or directory` — enforcement was a silent no-op).
#    Installed FIRST and unconditionally (independent of tc/nft/OVS tooling below) so a minimal
#    image still gets it.
if [ -e "$STAGE"/ifaces.env ]; then
  run install -m 0644 "$STAGE"/ifaces.env /var/lib/hookprobe/ifaces.env
fi

# 1. systemd-networkd units — WAN uplinks (50-hookprobe-wan-*), the LAN gateway (50-hookprobe-lan-*
#    = bridge IP + DHCP server), and LAN IPv6 (55-hookprobe-lan6-* = PD claim + RA/SLAAC). All are
#    plain networkd .network units; install them all, then one reload.
net_changed=0
for f in "$STAGE"/50-hookprobe-wan-*.network "$STAGE"/50-hookprobe-lan-*.network "$STAGE"/55-hookprobe-lan6-*.network; do
  [ -e "$f" ] || continue
  # Non-fatal: under set -e a single bad artifact would otherwise abort the whole apply (skipping
  # hostapd/NAT/mirror downstream). Log + continue so one malformed unit can't take everything down.
  if run install -m 0644 "$f" "$NETDIR/$(basename "$f")"; then net_changed=1
  else log "  WARNING: install $(basename "$f") failed (continuing)"; fi
done
[ "$net_changed" = 1 ] && run networkctl reload || true

# 1b. Edge DNS drop-in — the routed/bridged LAN gateway hands out itself as the DHCP DNS server, so
#     systemd-resolved must listen on the gateway IP (not just 127.0.0.53). Install the drop-in +
#     restart resolved. NON-FATAL: this is a convenience (clients can still use an upstream DNS), and
#     the reconcile runs sandboxed (ProtectSystem=strict) — if resolved.conf.d isn't a ReadWritePath
#     the install fails, and it must NOT abort the critical hostapd/NAT/NAC steps that follow.
dns_changed=0
for f in "$STAGE"/resolved/*.conf; do
  [ -e "$f" ] || continue
  if [ "$PLAN" = 1 ]; then log "PLAN: install $(basename "$f") → /etc/systemd/resolved.conf.d/"; continue; fi
  if install -m 0644 "$f" "/etc/systemd/resolved.conf.d/$(basename "$f")" 2>/dev/null; then
    dns_changed=1
  else
    log "  (edge DNS drop-in skipped: /etc/systemd/resolved.conf.d not writable — add it to the unit ReadWritePaths)"
  fi
done
[ "$dns_changed" = 1 ] && systemctl restart --no-block systemd-resolved 2>/dev/null || true

# 2. hostapd configs + start the AP. wifi_cfg emits hostapd-<iface>.conf; install it and bring
#    up hookprobe-hostapd@<iface> so the onboard radio actually serves the AP. restart (not just
#    start) so a regenerated config (SSID/passphrase change) takes effect. Only if hostapd exists.
for f in "$STAGE"/hostapd-*.conf; do
  [ -e "$f" ] || continue
  base=$(basename "$f")
  run install -m 0600 "$f" "$HOSTAPD_DIR/$base"
  # Deterministic hostapd presence check: `command -v hostapd` is PATH-dependent and flaked at
  # boot (see the PATH note up top); the absolute-path test can't. Either succeeding is enough.
  if [ "$PLAN" = 0 ] && { [ -x /usr/sbin/hostapd ] || command -v hostapd >/dev/null 2>&1; }; then
    iface=${base#hostapd-}; iface=${iface%.conf}          # hostapd-wlan0.conf → wlan0
    run systemctl enable "hookprobe-hostapd@${iface}.service" 2>/dev/null || true
    # --no-block: this runs inside network-reconcile's ExecStartPost; a blocking restart would
    # deadlock (the job waits for the unit, the unit's start waits for this reconcile to finish).
    run systemctl restart --no-block "hookprobe-hostapd@${iface}.service" 2>/dev/null || log "  (hostapd@${iface} start deferred)"
    # ADR 0034 D14 (W4): launch the verify-retry calibration loop for this AP iface right after
    # hostapd — it starts at the cached-good rung, clean-restarts to converge width, and steps
    # DOWN only after exhausting the same-rung retry budget (never leaves the AP down). --no-block
    # for the same deadlock-avoidance reason as the hostapd restart above; the template unit's own
    # ConditionPathExists (hostapd-<iface>.conf + /usr/sbin/hostapd) makes this a safe no-op on a
    # radioless/hostapd-less image.
    # Belt-and-suspenders: ENABLE the instance too (persists a WantedBy symlink in the writable
    # /etc), so on EVERY subsequent boot systemd auto-starts the calibrate for this AP iface even
    # if this ExecStartPost is ever skipped again — the unit's own ConditionPathExists keeps that
    # a safe no-op on any boot where this iface is not an AP.
    run systemctl enable "hookprobe-wifi-calibrate@${iface}.service" 2>/dev/null || true
    run systemctl start --no-block "hookprobe-wifi-calibrate@${iface}.service" 2>/dev/null || true
    # ADR 0034 D24-D33: the autonomous 5GHz channel optimizer. (a) enable + start the nightly
    # timer for this AP iface (the script's own D24 guards no-op it when disabled/2.4-pinned/
    # operator-channel-pinned/not-5GHz-capable — never a hardware branch here); (b) run it ONCE in
    # `reapply` mode right after hostapd (D31) — a fast, boot-non-blocking (--no-block) check that
    # silently restores a previously-VALIDATED DFS channel-LKG within one CAC of boot, or is a
    # near-instant no-op when there is none. Both are safe no-ops on a radioless/hostapd-less image
    # via the same ConditionPathExists gate the calibrate template already relies on.
    run systemctl enable "hookprobe-wifi-optimize@${iface}.timer" 2>/dev/null || true
    run systemctl start --no-block "hookprobe-wifi-optimize@${iface}.timer" 2>/dev/null || true
    # (b) the D31 fast post-boot DFS-LKG restore, via the sibling `reapply`-mode template unit
    # (same ConditionPathExists/capability/sandbox posture, --no-block for the same
    # deadlock-avoidance reason as every other unit started from this ExecStartPost).
    run systemctl start --no-block "hookprobe-wifi-optimize-reapply@${iface}.service" 2>/dev/null || true
  fi
done

# 3a-mirror. Traffic mirror (tc-mirred → sink) — pure `ip`/`tc`, INDEPENDENT of nft. It is the DPI
#     feed (napse-dpi reads the sink), so it must apply even on a minimal image without nftables —
#     otherwise the entire deep-inspection layer silently gets zero packets.
if command -v tc >/dev/null 2>&1; then
  for f in "$STAGE"/fabric/70-mirror.plan; do
    [ -e "$f" ] || continue
    runsh "$f"
  done
elif [ -e "$STAGE"/fabric/70-mirror.plan ]; then
  log "tc (iproute2) not installed → cannot set up the traffic mirror; DPI sensor will see nothing"
fi

# 3a. NON-OVS dataplane (L3 VRF, Linux-bridge, nft microseg) — `ip`+`nft`, NOT OpenVSwitch.
#     This MUST apply independently of OVS: a VRF-segmented box (single LAN) has no OVS bridge
#     yet still needs its VRFs + nft cross-segment/microseg rules. Each plan is a shell script of
#     `ip`/`nft` commands; runsh tolerates a missing tool (logs a warning, keeps going).
if command -v nft >/dev/null 2>&1; then
  # VRF/bridge/microseg + the LAN router plane: NAT (masquerade + forwarding), RA-Guard (nft),
  # and per-device NAC (nft sets). All are shell scripts of ip/nft/sysctl commands.
  # 63-vrf-north-south.plan (2026-07-10 CM5 metal fix): the routed AP/LAN north-south egress grant
  # into the `hookprobe_vrf` policy-drop forward chain. The reconciler GENERATES it (fabric.rs
  # render_vrf_north_south) but it was missing from THIS apply list, so on a VRF-segmented box with
  # a routed Wi-Fi AP the wlanN→WAN egress was black-holed (phone associates, gets a lease, but no
  # internet). MUST run AFTER 60-vrf.plan (that creates the chain) — ordering preserved by position.
  for f in "$STAGE"/fabric/60-vrf.plan "$STAGE"/fabric/63-vrf-north-south.plan "$STAGE"/fabric/*.linux-bridge.plan "$STAGE"/fabric/63-microseg.nft \
           "$STAGE"/fabric/65-nat.plan "$STAGE"/fabric/64-ra-guard.nft "$STAGE"/fabric/66-nac.nft; do
    [ -e "$f" ] || continue
    runsh "$f"
  done
else
  for f in "$STAGE"/fabric/60-vrf.plan "$STAGE"/fabric/63-microseg.nft; do
    [ -e "$f" ] && { log "nft not installed → cannot enforce VRF/microseg from $(basename "$f"); install nftables"; break; }
  done
fi

# 3b. OVS dataplane (L2 bridge + OpenFlow microseg) — needs openvswitch GRANTED *and* installed.
#     The manifest can grant openvswitch on an image that doesn't ship openvswitch-switch yet, so
#     gate on the binaries too (else `ovs-ofctl: command not found` hard-fails the unit). With the
#     fabric fix, OVS-flow artifacts are only emitted in OVS-bridge mode, so these have a bridge.
if granted openvswitch && command -v ovs-vsctl >/dev/null 2>&1 && command -v ovs-ofctl >/dev/null 2>&1; then
  for f in "$STAGE"/fabric/*.ovs.plan; do
    [ -e "$f" ] || continue
    runsh "$f"
  done
  for f in "$STAGE"/fabric/*.flows.of; do
    [ -e "$f" ] || continue
    br=$(basename "$f"); br=${br#6?-}; br=${br%.flows.of}     # 61-hp-br0.flows.of → hp-br0
    run ovs-ofctl add-flows "$br" "$f"
  done
  for f in "$STAGE"/fabric/63-microseg.conntrack.of; do
    [ -e "$f" ] || continue
    run ovs-ofctl add-flows "$BRIDGE" "$f"
  done
  # RA-Guard + per-device NAC on the OVS plane (line-rate). These are shell scripts of
  # `ovs-ofctl add-flow <bridge> …` commands (the bridge is baked in), so runsh them.
  for f in "$STAGE"/fabric/64-ra-guard.*.of "$STAGE"/fabric/66-nac.*.of; do
    [ -e "$f" ] || continue
    runsh "$f"
  done
elif granted openvswitch && ls "$STAGE"/fabric/*.ovs.plan "$STAGE"/fabric/*.flows.of "$STAGE"/fabric/63-microseg.conntrack.of >/dev/null 2>&1; then
  log "openvswitch GRANTED but tools not installed (no ovs-vsctl/ovs-ofctl) → skipping OVS L2/flow apply; install openvswitch-switch to realize it"
fi
log "apply complete"
