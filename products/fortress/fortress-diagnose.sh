#!/bin/bash
# Fortress System Diagnostic Script
# Run as root: sudo ./fortress-diagnose.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ok() { echo -e "${GREEN}✓${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }
fail() { echo -e "${RED}✗${NC} $1"; }
info() { echo -e "${BLUE}ℹ${NC} $1"; }
header() { echo -e "\n${BLUE}=== $1 ===${NC}"; }

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          FORTRESS SYSTEM DIAGNOSTIC v5.7                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# 1. Systemd Services
header "SYSTEMD SERVICES"
for svc in fortress fortress-vlan fts-hostapd-24ghz fts-hostapd-5ghz dnsmasq; do
    if systemctl is-active "$svc" &>/dev/null; then
        ok "$svc: running"
    elif systemctl is-enabled "$svc" &>/dev/null; then
        warn "$svc: enabled but not running"
    else
        info "$svc: not configured"
    fi
done

# 2. Containers
header "CONTAINERS"
if command -v podman &>/dev/null; then
    echo "Running containers:"
    podman ps --format "  {{.Names}}: {{.Status}}" 2>/dev/null || warn "No containers running"
    echo ""
    echo "All containers (including stopped):"
    podman ps -a --format "  {{.Names}}: {{.Status}}" 2>/dev/null
else
    fail "Podman not installed"
fi

# 3. OVS Bridge
header "OVS NETWORK"
if command -v ovs-vsctl &>/dev/null; then
    if ovs-vsctl br-exists FTS 2>/dev/null; then
        ok "FTS bridge exists"
        ovs-vsctl show 2>/dev/null | grep -A5 "Bridge FTS" | head -10
    else
        warn "FTS bridge not found"
    fi
else
    fail "Open vSwitch not installed"
fi

# 4. VLAN Interfaces
header "VLAN INTERFACES"
if ip link show vlan100 &>/dev/null; then
    ok "vlan100 (LAN): $(ip -br addr show vlan100 2>/dev/null | awk '{print $3}')"
else
    warn "vlan100 not configured"
fi
if ip link show vlan200 &>/dev/null; then
    ok "vlan200 (MGMT): $(ip -br addr show vlan200 2>/dev/null | awk '{print $3}')"
else
    info "vlan200 not configured (optional)"
fi

# 5. DHCP
header "DHCP (dnsmasq)"
if [ -f /etc/dnsmasq.d/fts-vlan.conf ]; then
    ok "DHCP config exists"
    grep -E "^dhcp-range|^interface" /etc/dnsmasq.d/fts-vlan.conf 2>/dev/null
else
    warn "DHCP config not found"
fi

# 6. WiFi
header "WIFI (hostapd)"
for band in 24ghz 5ghz; do
    conf="/etc/hostapd/fts-${band}.conf"
    if [ -f "$conf" ]; then
        ssid=$(grep "^ssid=" "$conf" 2>/dev/null | cut -d= -f2)
        channel=$(grep "^channel=" "$conf" 2>/dev/null | cut -d= -f2)
        ok "$band: SSID=$ssid, Channel=$channel"
    else
        info "$band: not configured"
    fi
done

# 7. Databases
header "DATABASES"
for db in fingerprint ecosystem_bubbles presence; do
    dbfile="/var/lib/hookprobe/${db}.db"
    if [ -f "$dbfile" ]; then
        size=$(du -h "$dbfile" 2>/dev/null | cut -f1)
        ok "$db.db: $size"
    else
        warn "$db.db: not found"
    fi
done

# 8. Configuration
header "CONFIGURATION"
if [ -f /etc/hookprobe/fortress.conf ]; then
    ok "fortress.conf exists"
    grep -E "^(LAN_SUBNET|WEB_PORT|WIFI_SSID|INSTALL_AIOCHI)=" /etc/hookprobe/fortress.conf 2>/dev/null | while read line; do
        info "  $line"
    done
else
    fail "fortress.conf not found"
fi

# 9. AIOCHI (if enabled)
header "AIOCHI (AI Eyes)"
if grep -q "INSTALL_AIOCHI=true" /etc/hookprobe/fortress.conf 2>/dev/null; then
    ok "AIOCHI enabled"
    echo "AIOCHI containers:"
    podman ps --filter "name=aiochi-" --format "  {{.Names}}: {{.Status}}" 2>/dev/null || warn "No AIOCHI containers running"

    # Check Ollama LLM
    if podman exec aiochi-ollama ollama list 2>/dev/null | grep -q llama; then
        ok "LLM model loaded"
    else
        warn "LLM model not yet loaded (may be downloading)"
    fi
else
    info "AIOCHI not enabled"
fi

# 10. Web UI
header "WEB UI"
WEB_PORT=$(grep "^WEB_PORT=" /etc/hookprobe/fortress.conf 2>/dev/null | cut -d= -f2 || echo "8443")
if curl -sk "https://localhost:${WEB_PORT}/health" &>/dev/null; then
    ok "Web UI responding on port $WEB_PORT"
else
    if podman ps --filter "name=fts-web" --format "{{.Status}}" 2>/dev/null | grep -q "Up"; then
        warn "fts-web container running but health check failed"
    else
        fail "Web UI not responding (fts-web not running?)"
    fi
fi
info "Access: https://<your-ip>:${WEB_PORT}"

# 11. NAT/Firewall
header "NAT/FIREWALL"
if iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q MASQUERADE; then
    ok "NAT masquerade configured"
else
    warn "NAT masquerade not found"
fi

# 12. Container Logs (recent errors)
header "RECENT ERRORS (last 5 lines per container)"
for container in fts-web fts-qsecbit fts-dnsxai fts-postgres; do
    if podman ps -a --format "{{.Names}}" 2>/dev/null | grep -q "^${container}$"; then
        errors=$(podman logs "$container" 2>&1 | grep -iE "error|exception|failed" | tail -3)
        if [ -n "$errors" ]; then
            warn "$container errors:"
            echo "$errors" | sed 's/^/    /'
        fi
    fi
done

# Summary
header "SUMMARY"
echo ""
echo "Key endpoints:"
info "  Web UI:    https://localhost:${WEB_PORT}"
info "  Grafana:   http://localhost:3000 (if monitoring enabled)"
info "  n8n:       http://localhost:5678 (if automation enabled)"
echo ""
echo "Useful commands:"
info "  podman logs fts-web          # Web UI logs"
info "  podman logs fts-qsecbit      # Threat detection logs"
info "  systemctl status fortress    # Main service status"
info "  ./fortress-ctl.sh status     # Quick status"
echo ""
