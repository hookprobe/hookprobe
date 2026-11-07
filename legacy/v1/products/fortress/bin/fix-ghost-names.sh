#!/bin/bash
#═══════════════════════════════════════════════════════════════════════════════
# fix-ghost-names.sh - Comprehensive Ghost Name Collision Fix
#
# Part of HookProbe Fortress - Small Business Security Gateway
#
# Fixes the classic mDNS hostname incrementing bug where devices show:
#   "hookprobe Pro" → "hookprobe Pro (2)" → "hookprobe Pro (3)" etc.
#
# Root Cause:
#   1. dnsmasq responds to .local queries (should be mDNS only)
#   2. Avahi sees its own hostname "in use" via dnsmasq response
#   3. Avahi increments hostname to avoid "collision"
#
# This script:
#   - Fixes Fortress server (dnsmasq + Avahi configuration)
#   - Generates client-side fix script for macOS devices
#   - Validates the fix is working
#
# Usage:
#   ./fix-ghost-names.sh              # Run full diagnosis and fix
#   ./fix-ghost-names.sh --diagnose   # Diagnosis only (no changes)
#   ./fix-ghost-names.sh --fix        # Apply fixes
#   ./fix-ghost-names.sh --client     # Generate macOS client script
#
# Version: 1.0.0
# License: AGPL-3.0
#═══════════════════════════════════════════════════════════════════════════════

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORTRESS_ROOT="${SCRIPT_DIR}/.."

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Counters
ISSUES_FOUND=0
ISSUES_FIXED=0

log_header() { echo -e "\n${CYAN}${BOLD}═══════════════════════════════════════════════════════════════${NC}"; echo -e "${CYAN}${BOLD}  $1${NC}"; echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════════${NC}"; }
log_section() { echo -e "\n${YELLOW}[$1]${NC} $2"; }
log_pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ((ISSUES_FOUND++)); }
log_warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
log_info() { echo -e "  ${CYAN}[INFO]${NC} $1"; }
log_fix() { echo -e "  ${GREEN}[FIXED]${NC} $1"; ((ISSUES_FIXED++)); }

#───────────────────────────────────────────────────────────────────────────────
# DIAGNOSIS
#───────────────────────────────────────────────────────────────────────────────

diagnose() {
    log_header "Ghost Name Collision Diagnosis"

    #───────────────────────────────────────────────────────────────────────────
    log_section "1" "Hostname Check"
    #───────────────────────────────────────────────────────────────────────────

    local hostname
    hostname=$(hostname)

    # Check for ghost name increment suffix
    if echo "$hostname" | grep -qE ' ?\([0-9]+\)$'; then
        log_fail "GHOST NAME DETECTED: '$hostname'"
        log_info "Hostname has collision suffix - this is the bug!"
    else
        log_pass "Hostname clean: $hostname"
    fi

    #───────────────────────────────────────────────────────────────────────────
    log_section "2" "dnsmasq Configuration"
    #───────────────────────────────────────────────────────────────────────────

    # Check for server=/local/# fix
    local dnsmasq_fixed=false
    local dnsmasq_conf=""

    for conf in /etc/dnsmasq.d/fortress.conf /etc/dnsmasq.d/fts-vlan.conf /etc/dnsmasq.conf; do
        if [ -f "$conf" ]; then
            if grep -q "^server=/local/#" "$conf" 2>/dev/null; then
                log_pass "server=/local/# found in $conf"
                dnsmasq_fixed=true
                dnsmasq_conf="$conf"
                break
            fi
        fi
    done

    if [ "$dnsmasq_fixed" = false ]; then
        log_fail "server=/local/# NOT FOUND in any dnsmasq config"
        log_info "This is the PRIMARY cause of ghost name collisions"

        # Find which config to fix
        for conf in /etc/dnsmasq.d/fortress.conf /etc/dnsmasq.d/fts-vlan.conf; do
            if [ -f "$conf" ]; then
                dnsmasq_conf="$conf"
                break
            fi
        done
    fi

    # Check for conflicting local=/hookprobe.local/
    for conf in /etc/dnsmasq.d/*.conf /etc/dnsmasq.conf; do
        if [ -f "$conf" ] && grep -q "^local=/.*\.local/" "$conf" 2>/dev/null; then
            log_warn "Found local=/*.local/ in $conf - may conflict with mDNS"
        fi
    done

    # Test if dnsmasq responds to .local queries
    log_info "Testing dnsmasq .local response..."
    local dns_response
    dns_response=$(dig +short "${hostname}.local" @127.0.0.1 2>/dev/null || echo "")

    if [ -z "$dns_response" ]; then
        log_pass "dnsmasq correctly ignoring .local queries"
    else
        log_fail "dnsmasq responding to .local: $dns_response"
        log_info "This causes Avahi to detect false collisions!"
    fi

    #───────────────────────────────────────────────────────────────────────────
    log_section "3" "Avahi Configuration"
    #───────────────────────────────────────────────────────────────────────────

    if [ -f /etc/avahi/avahi-daemon.conf ]; then
        log_pass "Avahi config exists"

        # Check disallow-other-stacks
        if grep -q "^disallow-other-stacks=yes" /etc/avahi/avahi-daemon.conf; then
            log_pass "disallow-other-stacks=yes"
        else
            log_warn "disallow-other-stacks not set to yes"
        fi

        # Check enable-reflector
        if grep -q "^enable-reflector=no" /etc/avahi/avahi-daemon.conf; then
            log_pass "enable-reflector=no (good)"
        else
            log_fail "enable-reflector may be enabled - causes self-collision"
        fi

        # Check allow-interfaces
        local avahi_iface
        avahi_iface=$(grep "^allow-interfaces=" /etc/avahi/avahi-daemon.conf 2>/dev/null | cut -d= -f2)
        if [ -n "$avahi_iface" ]; then
            log_pass "allow-interfaces=$avahi_iface"
        else
            log_warn "allow-interfaces not set - Avahi listens on ALL interfaces"
        fi
    else
        log_warn "Avahi config not found"
    fi

    # Check Avahi service
    if systemctl is-active avahi-daemon &>/dev/null; then
        log_pass "avahi-daemon running"
    else
        log_info "avahi-daemon not running"
    fi

    #───────────────────────────────────────────────────────────────────────────
    log_section "4" "Network Interfaces"
    #───────────────────────────────────────────────────────────────────────────

    # Count active interfaces
    local iface_count=0
    local ifaces=""
    while read -r line; do
        iface=$(echo "$line" | cut -d: -f1)
        if [ -n "$iface" ] && [ "$iface" != "lo" ]; then
            status=$(ip link show "$iface" 2>/dev/null | grep -oP 'state \K\S+' || echo "unknown")
            if [ "$status" = "UP" ] || [ "$status" = "UNKNOWN" ]; then
                ((iface_count++))
                ifaces="$ifaces $iface"
            fi
        fi
    done < <(ip link show | grep -E "^[0-9]+:")

    log_info "Active interfaces:$ifaces"

    if [ "$iface_count" -gt 2 ]; then
        log_warn "Multiple interfaces active - may cause mDNS reflection"
    fi

    #───────────────────────────────────────────────────────────────────────────
    log_section "5" "Summary"
    #───────────────────────────────────────────────────────────────────────────

    echo ""
    if [ "$ISSUES_FOUND" -eq 0 ]; then
        echo -e "${GREEN}No ghost name issues detected!${NC}"
    else
        echo -e "${RED}Found $ISSUES_FOUND issue(s) that may cause ghost names${NC}"
        echo -e "${YELLOW}Run: $0 --fix${NC}"
    fi

    return "$ISSUES_FOUND"
}

#───────────────────────────────────────────────────────────────────────────────
# FIX
#───────────────────────────────────────────────────────────────────────────────

apply_fix() {
    log_header "Applying Ghost Name Fixes"

    # Check root
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        exit 1
    fi

    #───────────────────────────────────────────────────────────────────────────
    log_section "1" "Stopping Services"
    #───────────────────────────────────────────────────────────────────────────

    systemctl stop avahi-daemon 2>/dev/null || true
    systemctl stop dnsmasq 2>/dev/null || true
    log_info "Services stopped"

    #───────────────────────────────────────────────────────────────────────────
    log_section "2" "Clearing Caches"
    #───────────────────────────────────────────────────────────────────────────

    # Clear Avahi cache
    rm -rf /var/cache/avahi-daemon/* 2>/dev/null || true
    rm -f /var/run/avahi-daemon/*.cache 2>/dev/null || true
    log_fix "Avahi cache cleared"

    # Clear DNS resolver cache
    resolvectl flush-caches 2>/dev/null || true
    log_fix "DNS resolver cache flushed"

    #───────────────────────────────────────────────────────────────────────────
    log_section "3" "Fixing Hostname"
    #───────────────────────────────────────────────────────────────────────────

    local hostname
    hostname=$(hostname)

    if echo "$hostname" | grep -qE ' ?\([0-9]+\)$'; then
        local clean_host
        clean_host=$(echo "$hostname" | sed 's/ *([0-9]*)$//')
        hostnamectl set-hostname "$clean_host" --static
        hostnamectl set-hostname "$clean_host" --pretty
        log_fix "Hostname cleaned: '$hostname' → '$clean_host'"
    else
        log_info "Hostname already clean: $hostname"
    fi

    #───────────────────────────────────────────────────────────────────────────
    log_section "4" "Fixing dnsmasq Configuration"
    #───────────────────────────────────────────────────────────────────────────

    # Find dnsmasq config
    local dnsmasq_conf=""
    for conf in /etc/dnsmasq.d/fortress.conf /etc/dnsmasq.d/fts-vlan.conf; do
        if [ -f "$conf" ]; then
            dnsmasq_conf="$conf"
            break
        fi
    done

    if [ -z "$dnsmasq_conf" ]; then
        dnsmasq_conf="/etc/dnsmasq.d/fortress.conf"
        touch "$dnsmasq_conf"
    fi

    # Add server=/local/# if not present
    if ! grep -q "^server=/local/#" "$dnsmasq_conf" 2>/dev/null; then
        # Backup
        cp "$dnsmasq_conf" "${dnsmasq_conf}.bak.$(date +%s)"

        # Add fix at top
        local tmp_file
        tmp_file=$(mktemp)
        cat > "$tmp_file" << 'EOF'
# ============================================================================
# GHOST NAME COLLISION FIX
# ============================================================================
# .local is RESERVED for mDNS (Avahi/Bonjour)
# dnsmasq MUST NOT respond to .local queries
# Without this, devices get renamed: device → device (2) → device (3)
server=/local/#

EOF
        cat "$dnsmasq_conf" >> "$tmp_file"
        mv "$tmp_file" "$dnsmasq_conf"
        chmod 644 "$dnsmasq_conf"
        log_fix "Added server=/local/# to $dnsmasq_conf"
    else
        log_info "server=/local/# already present"
    fi

    # Replace .local domain with .lan
    if grep -q "^local=/hookprobe.local/" "$dnsmasq_conf" 2>/dev/null; then
        sed -i 's|^local=/hookprobe.local/|local=/hookprobe.lan/|' "$dnsmasq_conf"
        sed -i 's|^domain=hookprobe.local|domain=hookprobe.lan|' "$dnsmasq_conf"
        log_fix "Changed domain from .local to .lan"
    fi

    #───────────────────────────────────────────────────────────────────────────
    log_section "5" "Configuring Avahi"
    #───────────────────────────────────────────────────────────────────────────

    # Run setup-avahi.sh if available
    local avahi_script="${FORTRESS_ROOT}/devices/common/setup-avahi.sh"
    if [ -f "$avahi_script" ]; then
        chmod +x "$avahi_script"
        LAN_INTERFACE="FTS" "$avahi_script" configure
        log_fix "Avahi configured via setup-avahi.sh"
    else
        log_warn "setup-avahi.sh not found - manual Avahi config may be needed"
    fi

    #───────────────────────────────────────────────────────────────────────────
    log_section "6" "Restarting Services"
    #───────────────────────────────────────────────────────────────────────────

    # Test dnsmasq config
    if dnsmasq --test 2>/dev/null; then
        log_info "dnsmasq config valid"
    else
        log_warn "dnsmasq config has warnings"
    fi

    # Start dnsmasq FIRST
    systemctl start dnsmasq
    sleep 1
    log_info "dnsmasq started"

    # Start Avahi SECOND
    systemctl start avahi-daemon 2>/dev/null || true
    sleep 1
    log_info "avahi-daemon started"

    #───────────────────────────────────────────────────────────────────────────
    log_section "7" "Verification"
    #───────────────────────────────────────────────────────────────────────────

    # Test .local query
    local dns_response
    dns_response=$(dig +short "$(hostname).local" @127.0.0.1 2>/dev/null || echo "")
    if [ -z "$dns_response" ]; then
        log_pass "dnsmasq now ignoring .local queries"
    else
        log_fail "dnsmasq still responding to .local"
    fi

    #───────────────────────────────────────────────────────────────────────────
    log_header "Fix Complete"
    #───────────────────────────────────────────────────────────────────────────

    echo -e "\n${GREEN}Fixed $ISSUES_FIXED issue(s)${NC}"
    echo ""
    echo -e "${YELLOW}Next Steps:${NC}"
    echo "  1. Run client fix on macOS devices:"
    echo "     $0 --client > client-lock.sh && chmod +x client-lock.sh"
    echo "     Then copy to Mac and run: sudo ./client-lock.sh"
    echo ""
    echo "  2. Verify fix is working:"
    echo "     $0 --diagnose"
    echo ""
}

#───────────────────────────────────────────────────────────────────────────────
# GENERATE CLIENT SCRIPT (macOS)
#───────────────────────────────────────────────────────────────────────────────

generate_client_script() {
    cat << 'MACOS_SCRIPT'
#!/bin/bash
#═══════════════════════════════════════════════════════════════════════════════
# HookProbe Client Lock - macOS Hostname Protection
# Prevents ghost name collision incrementing (device (2), (3), etc.)
#═══════════════════════════════════════════════════════════════════════════════

set -e

HOSTNAME="${1:-$(hostname | sed 's/ *([0-9]*)$//' | tr ' ' '-')}"

echo "═══════════════════════════════════════════════════════════════"
echo "  HookProbe Client Lock - macOS"
echo "═══════════════════════════════════════════════════════════════"
echo "  Target hostname: $HOSTNAME"

if [ "$EUID" -ne 0 ]; then
    echo "Error: Run with sudo"
    exit 1
fi

echo ""
echo "[1] Flushing caches..."
dscacheutil -flushcache 2>/dev/null || true
killall -HUP mDNSResponder 2>/dev/null || true
sleep 1
echo "  Done"

echo ""
echo "[2] Setting static hostnames..."
LOCAL_HOST=$(echo "$HOSTNAME" | tr '[:upper:]' '[:lower:]' | sed "s/[^a-z0-9-]/-/g")
scutil --set ComputerName "$HOSTNAME"
scutil --set LocalHostName "$LOCAL_HOST"
scutil --set HostName "${LOCAL_HOST}.local"
echo "  ComputerName:  $HOSTNAME"
echo "  LocalHostName: $LOCAL_HOST"
echo "  HostName:      ${LOCAL_HOST}.local"

echo ""
echo "[3] Disabling wake triggers..."
pmset -a womp 0 2>/dev/null || true
pmset -a proximitywake 0 2>/dev/null || true
pmset -a tcpkeepalive 0 2>/dev/null || true
echo "  Done"

echo ""
echo "[4] Installing persistence daemon..."
PLIST="/Library/LaunchDaemons/com.hookprobe.hostname-lock.plist"
SCRIPT="/usr/local/bin/hookprobe-hostname-lock.sh"

mkdir -p /usr/local/bin
cat > "$SCRIPT" << LOCKSCRIPT
#!/bin/bash
scutil --set ComputerName "$HOSTNAME"
scutil --set LocalHostName "$LOCAL_HOST"
scutil --set HostName "${LOCAL_HOST}.local"
logger -t hookprobe-hostname "Hostname re-enforced: $HOSTNAME"
LOCKSCRIPT
chmod +x "$SCRIPT"

cat > "$PLIST" << PLISTCONTENT
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.hookprobe.hostname-lock</string>
    <key>ProgramArguments</key>
    <array><string>/usr/local/bin/hookprobe-hostname-lock.sh</string></array>
    <key>WatchPaths</key>
    <array><string>/Library/Preferences/SystemConfiguration</string></array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
PLISTCONTENT

chown root:wheel "$PLIST"
chmod 644 "$PLIST"
launchctl unload "$PLIST" 2>/dev/null || true
launchctl load "$PLIST"
echo "  Done"

echo ""
echo "[5] Restarting mDNSResponder..."
killall -9 mDNSResponder 2>/dev/null || true
sleep 2
echo "  Done"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Client hostname locked successfully!"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Verification:"
echo "  ComputerName:  $(scutil --get ComputerName)"
echo "  LocalHostName: $(scutil --get LocalHostName)"
echo "  HostName:      $(scutil --get HostName)"
echo ""
MACOS_SCRIPT
}

#───────────────────────────────────────────────────────────────────────────────
# USAGE
#───────────────────────────────────────────────────────────────────────────────

usage() {
    echo "Usage: $0 [option]"
    echo ""
    echo "Options:"
    echo "  (no option)   Run diagnosis and prompt for fix"
    echo "  --diagnose    Diagnosis only (no changes)"
    echo "  --fix         Apply fixes to Fortress server"
    echo "  --client      Generate macOS client fix script"
    echo "  --help        Show this help"
    echo ""
    echo "Examples:"
    echo "  # Diagnose ghost name issues"
    echo "  $0 --diagnose"
    echo ""
    echo "  # Fix Fortress server"
    echo "  sudo $0 --fix"
    echo ""
    echo "  # Generate and use client script"
    echo "  $0 --client > client-lock.sh"
    echo "  scp client-lock.sh user@mac:~/"
    echo "  ssh user@mac 'sudo ~/client-lock.sh'"
    echo ""
}

#───────────────────────────────────────────────────────────────────────────────
# MAIN
#───────────────────────────────────────────────────────────────────────────────

case "${1:-}" in
    --diagnose|--diag|-d)
        diagnose
        ;;
    --fix|-f)
        apply_fix
        ;;
    --client|-c)
        generate_client_script
        ;;
    --help|-h)
        usage
        ;;
    "")
        # Interactive mode
        diagnose
        if [ "$ISSUES_FOUND" -gt 0 ]; then
            echo ""
            read -p "Apply fixes? [y/N] " -n 1 -r
            echo ""
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                if [ "$EUID" -ne 0 ]; then
                    echo "Re-running with sudo..."
                    exec sudo "$0" --fix
                else
                    apply_fix
                fi
            fi
        fi
        ;;
    *)
        usage
        exit 1
        ;;
esac
