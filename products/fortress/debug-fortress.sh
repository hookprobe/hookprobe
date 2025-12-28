#!/bin/bash
#
# debug-fortress.sh - Concise Fortress Diagnostic Script
# Outputs structured data for Claude to analyze and fix issues
#
# Usage: sudo ./debug-fortress.sh | pbcopy   # Copy to clipboard for Claude
#        sudo ./debug-fortress.sh > debug.txt
#

set -o pipefail

# ============================================================
# CONFIGURATION
# ============================================================
CONFIG_DIR="/etc/hookprobe"
INSTALL_DIR="/opt/hookprobe/fortress"
STATE_DIR="/var/lib/fortress"

# Load config if exists
[ -f "$CONFIG_DIR/fortress.conf" ] && source "$CONFIG_DIR/fortress.conf"

# Defaults
OVS_BRIDGE="${OVS_BRIDGE:-FTS}"
NETWORK_MODE="${NETWORK_MODE:-vlan}"

# ============================================================
# OUTPUT HELPERS
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok() { echo -e "${GREEN}[OK]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ISSUES+=("$1"); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; WARNINGS+=("$1"); }
section() { echo -e "\n### $1"; }

ISSUES=()
WARNINGS=()

# ============================================================
# CHECKS
# ============================================================

section "SYSTEM"
echo "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || uname -s)"
echo "Kernel: $(uname -r)"
echo "Fortress: $(cat $INSTALL_DIR/VERSION 2>/dev/null || echo 'not installed')"

section "DEPENDENCIES"
for cmd in podman podman-compose ovs-vsctl netplan hostapd dnsmasq; do
    if command -v $cmd &>/dev/null; then
        ok "$cmd"
    else
        fail "$cmd missing"
    fi
done

section "SYSTEMD SERVICES"
for svc in fortress fortress-vlan fts-hostapd-24ghz fts-hostapd-5ghz dnsmasq openvswitch-switch; do
    status=$(systemctl is-active $svc 2>/dev/null || echo "not-found")
    enabled=$(systemctl is-enabled $svc 2>/dev/null || echo "not-found")
    case "$status" in
        active) ok "$svc (enabled=$enabled)" ;;
        inactive) warn "$svc inactive (enabled=$enabled)" ;;
        failed) fail "$svc FAILED"; echo "  $(journalctl -u $svc -n 3 --no-pager 2>/dev/null | tail -2 | head -1)" ;;
        *) [ "$svc" = "fts-hostapd-24ghz" ] || [ "$svc" = "fts-hostapd-5ghz" ] || warn "$svc $status" ;;
    esac
done

section "CONTAINERS"
if command -v podman &>/dev/null; then
    running=$(podman ps --format "{{.Names}}" 2>/dev/null | grep "^fts-" | sort)
    expected="fts-dfs fts-dnsxai fts-postgres fts-qsecbit fts-redis fts-web"
    for c in $expected; do
        if echo "$running" | grep -q "^${c}$"; then
            ok "$c"
        else
            # Check if exists but stopped
            if podman ps -a --format "{{.Names}}" 2>/dev/null | grep -q "^${c}$"; then
                status=$(podman inspect $c --format "{{.State.Status}}" 2>/dev/null)
                fail "$c ($status)"
                echo "  $(podman logs $c 2>&1 | tail -2 | head -1)"
            else
                fail "$c not created"
            fi
        fi
    done
else
    fail "podman not available"
fi

section "NETWORK - OVS"
if command -v ovs-vsctl &>/dev/null; then
    if ovs-vsctl br-exists $OVS_BRIDGE 2>/dev/null; then
        ok "Bridge $OVS_BRIDGE exists"
        # Show ports (brief)
        ports=$(ovs-vsctl list-ports $OVS_BRIDGE 2>/dev/null | tr '\n' ' ')
        echo "  Ports: ${ports:-none}"
    else
        fail "Bridge $OVS_BRIDGE missing"
    fi
else
    fail "OVS not installed"
fi

section "NETWORK - VLANS"
for vlan in vlan100 vlan200; do
    if ip link show $vlan &>/dev/null; then
        ip_addr=$(ip -4 addr show $vlan 2>/dev/null | grep inet | awk '{print $2}' | head -1)
        state=$(ip link show $vlan 2>/dev/null | grep -oE "state [A-Z]+" | awk '{print $2}')
        if [ -n "$ip_addr" ] && [ "$state" = "UP" ]; then
            ok "$vlan: $ip_addr ($state)"
        elif [ -n "$ip_addr" ]; then
            warn "$vlan: $ip_addr (state=$state)"
        else
            fail "$vlan: no IP assigned"
        fi
    else
        fail "$vlan interface missing"
    fi
done

section "NETWORK - NAT"
if iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q MASQUERADE; then
    ok "NAT configured (iptables)"
elif nft list table inet nat 2>/dev/null | grep -q masquerade; then
    ok "NAT configured (nftables)"
else
    warn "NAT may not be configured"
fi

section "NETWORK - IP FORWARD"
fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
[ "$fwd" = "1" ] && ok "IP forwarding enabled" || fail "IP forwarding disabled"

section "DHCP"
if systemctl is-active dnsmasq &>/dev/null; then
    # Check which interface dnsmasq is listening on
    listen_if=$(grep -h "^interface=" /etc/dnsmasq.d/fts-*.conf 2>/dev/null | cut -d= -f2 | head -1)
    ok "dnsmasq running on ${listen_if:-unknown}"
else
    fail "dnsmasq not running"
fi

section "WIFI"
# Check for WiFi interfaces
wifi_24=$(cat $CONFIG_DIR/wifi-interfaces.conf 2>/dev/null | grep WIFI_24GHZ_STABLE | cut -d= -f2)
wifi_5=$(cat $CONFIG_DIR/wifi-interfaces.conf 2>/dev/null | grep WIFI_5GHZ_STABLE | cut -d= -f2)

if [ -n "$wifi_24" ] && ip link show "$wifi_24" &>/dev/null; then
    ok "2.4GHz: $wifi_24"
elif ls /sys/class/net/wlan* &>/dev/null 2>&1; then
    warn "WiFi detected but not configured: $(ls /sys/class/net/ | grep wlan | tr '\n' ' ')"
else
    echo "No WiFi adapters detected"
fi

if [ -n "$wifi_5" ] && ip link show "$wifi_5" &>/dev/null; then
    ok "5GHz: $wifi_5"
fi

# Check udev rules
[ -f /etc/udev/rules.d/70-fts-wifi.rules ] && ok "udev rules present" || warn "udev rules missing"

section "CONFIG FILES"
for f in "$CONFIG_DIR/fortress.conf" "$CONFIG_DIR/users.json" "$STATE_DIR/netplan-config.conf" "/etc/netplan/60-fortress-ovs.yaml"; do
    [ -f "$f" ] && ok "$(basename $f)" || warn "$(basename $f) missing"
done

section "PERMISSIONS"
# Check fortress group GID (should be 1000 to match container)
fortress_gid=$(getent group fortress 2>/dev/null | cut -d: -f3)
if [ "$fortress_gid" = "1000" ]; then
    ok "fortress group GID=1000 (matches container)"
elif [ -n "$fortress_gid" ]; then
    warn "fortress group GID=$fortress_gid (expected 1000 for container access)"
    echo "  Fix: groupdel fortress && groupadd --gid 1000 fortress"
else
    warn "fortress group does not exist"
fi

# Check users.json permissions
if [ -f "$CONFIG_DIR/users.json" ]; then
    perms=$(stat -c '%a %U:%G' "$CONFIG_DIR/users.json" 2>/dev/null)
    echo "  users.json: $perms"
    if [ "$fortress_gid" = "1000" ]; then
        # Should be 640 root:fortress
        if stat -c '%a' "$CONFIG_DIR/users.json" 2>/dev/null | grep -q "640" && \
           stat -c '%G' "$CONFIG_DIR/users.json" 2>/dev/null | grep -q "fortress"; then
            ok "users.json permissions correct"
        else
            warn "users.json may not be readable by container"
        fi
    else
        # Should be 644 for fallback mode
        if stat -c '%a' "$CONFIG_DIR/users.json" 2>/dev/null | grep -qE "644|664"; then
            ok "users.json world-readable (fallback mode)"
        else
            warn "users.json may not be readable by container"
        fi
    fi
fi

section "WEB ACCESS"
port="${WEB_PORT:-8443}"
if command -v curl &>/dev/null; then
    if curl -sk --connect-timeout 3 "https://127.0.0.1:$port/login" &>/dev/null; then
        ok "Web UI accessible on port $port"
    else
        fail "Web UI not responding on port $port"
    fi
else
    warn "curl not available for web check"
fi

# ============================================================
# SUMMARY
# ============================================================
section "SUMMARY"
echo "Issues: ${#ISSUES[@]}, Warnings: ${#WARNINGS[@]}"

if [ ${#ISSUES[@]} -gt 0 ]; then
    echo ""
    echo "ISSUES TO FIX:"
    for issue in "${ISSUES[@]}"; do
        echo "  - $issue"
    done
fi

if [ ${#WARNINGS[@]} -gt 0 ]; then
    echo ""
    echo "WARNINGS:"
    for w in "${WARNINGS[@]}"; do
        echo "  - $w"
    done
fi

# Quick diagnosis hints
if [ ${#ISSUES[@]} -gt 0 ]; then
    section "QUICK FIXES"

    # Container issues
    if printf '%s\n' "${ISSUES[@]}" | grep -q "fts-"; then
        echo "Containers: systemctl restart fortress"
    fi

    # VLAN issues
    if printf '%s\n' "${ISSUES[@]}" | grep -q "vlan"; then
        echo "VLANs: systemctl restart fortress-vlan"
    fi

    # OVS issues
    if printf '%s\n' "${ISSUES[@]}" | grep -q "Bridge"; then
        echo "OVS: systemctl restart openvswitch-switch && systemctl restart fortress-vlan"
    fi

    # DHCP issues
    if printf '%s\n' "${ISSUES[@]}" | grep -q "dnsmasq"; then
        echo "DHCP: systemctl restart dnsmasq"
    fi
fi

echo ""
echo "# Paste this output to Claude for analysis"
