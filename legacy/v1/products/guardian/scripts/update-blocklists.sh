#!/bin/bash
# ============================================================================
# DNS Shield - Blocklist Updater for Guardian
# ============================================================================
# Downloads and configures StevenBlack's unified hosts for network-wide
# ad blocking via dnsmasq. Zero containers, maximum efficiency.
#
# Usage:
#   ./update-blocklists.sh [--silent] [--force]
#
# Blocklist Sources (StevenBlack's Unified Hosts):
#   - Base: Adware + Malware domains
#   - Extended: + Fakenews, Gambling, Porn, Social (configurable)
#
# Repository: https://github.com/StevenBlack/hosts
# ============================================================================

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
SHIELD_DIR="/opt/hookprobe/guardian/dns-shield"
HOSTS_FILE="$SHIELD_DIR/blocked-hosts"
STATS_FILE="$SHIELD_DIR/stats.json"
CONFIG_FILE="$SHIELD_DIR/shield.conf"
LOG_FILE="/var/log/hookprobe/dns-shield.log"
DNSMASQ_CONF="/etc/dnsmasq.d/dns-shield.conf"

# StevenBlack hosts URLs
declare -A BLOCKLIST_URLS=(
    ["base"]="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    ["fakenews"]="https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts"
    ["gambling"]="https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts"
    ["porn"]="https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts"
    ["social"]="https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social/hosts"
    ["fakenews-gambling"]="https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts"
    ["fakenews-gambling-porn"]="https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts"
    ["fakenews-gambling-porn-social"]="https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts"
)

# Colors (disabled in silent mode)
SILENT=false
FORCE=false
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
log() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $1" >> "$LOG_FILE"
    if [ "$SILENT" = false ]; then
        echo -e "$1"
    fi
}

log_info() { log "${BLUE}[INFO]${NC} $1"; }
log_success() { log "${GREEN}[OK]${NC} $1"; }
log_warn() { log "${YELLOW}[WARN]${NC} $1"; }
log_error() { log "${RED}[ERROR]${NC} $1"; }

show_banner() {
    if [ "$SILENT" = true ]; then return; fi
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}        ${BOLD}DNS Shield${NC} - Network Ad Blocker for Guardian       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}           Powered by StevenBlack's Unified Hosts           ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Shield Configuration
# ─────────────────────────────────────────────────────────────────────────────
init_config() {
    mkdir -p "$SHIELD_DIR"
    mkdir -p "$(dirname "$LOG_FILE")"

    # Create default config if not exists
    if [ ! -f "$CONFIG_FILE" ]; then
        cat > "$CONFIG_FILE" << 'SHIELDCONF'
# DNS Shield Configuration
# ========================
# Shield Level determines which blocklist variant to use:
#
#   1 = Base (Adware + Malware) - ~130,000 domains
#   2 = Base + Fakenews - ~132,000 domains
#   3 = Base + Fakenews + Gambling - ~135,000 domains
#   4 = Base + Fakenews + Gambling + Porn - ~200,000 domains
#   5 = Full Protection (All categories) - ~250,000 domains
#
# Higher levels = more blocking, may affect some legitimate sites
SHIELD_LEVEL=3

# Custom whitelist (one domain per line)
# Add domains here that you want to allow even if blocked
WHITELIST_FILE="/opt/hookprobe/guardian/dns-shield/whitelist.txt"

# Auto-update schedule (handled by systemd timer)
# 0 = disabled, 1 = daily, 7 = weekly
AUTO_UPDATE_DAYS=7

# Block response (0.0.0.0 is faster, 127.0.0.1 is more compatible)
BLOCK_TARGET="0.0.0.0"
SHIELDCONF
        log_info "Created default configuration at $CONFIG_FILE"
    fi

    # Create empty whitelist if not exists
    if [ ! -f "$SHIELD_DIR/whitelist.txt" ]; then
        cat > "$SHIELD_DIR/whitelist.txt" << 'WHITELIST'
# DNS Shield Whitelist
# ====================
# Add domains here (one per line) to bypass blocking
# Example:
# example.com
# subdomain.example.com
WHITELIST
    fi

    # Initialize stats if not exists
    if [ ! -f "$STATS_FILE" ]; then
        cat > "$STATS_FILE" << 'STATS'
{
    "shield_level": 3,
    "domains_blocked": 0,
    "last_update": null,
    "update_count": 0,
    "blocklist_source": "StevenBlack Unified Hosts",
    "version": "1.0.0"
}
STATS
    fi

    # Source the config
    source "$CONFIG_FILE"
}

# ─────────────────────────────────────────────────────────────────────────────
# Blocklist Selection
# ─────────────────────────────────────────────────────────────────────────────
get_blocklist_url() {
    local level="${SHIELD_LEVEL:-3}"

    case $level in
        1) echo "${BLOCKLIST_URLS[base]}" ;;
        2) echo "${BLOCKLIST_URLS[fakenews]}" ;;
        3) echo "${BLOCKLIST_URLS[fakenews-gambling]}" ;;
        4) echo "${BLOCKLIST_URLS[fakenews-gambling-porn]}" ;;
        5) echo "${BLOCKLIST_URLS[fakenews-gambling-porn-social]}" ;;
        *) echo "${BLOCKLIST_URLS[fakenews-gambling]}" ;;
    esac
}

get_level_name() {
    local level="${SHIELD_LEVEL:-3}"

    case $level in
        1) echo "Base Protection" ;;
        2) echo "Enhanced (+ Fakenews)" ;;
        3) echo "Strong (+ Gambling)" ;;
        4) echo "Maximum (+ Adult)" ;;
        5) echo "Full Shield (All)" ;;
        *) echo "Strong Protection" ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────────
# Download & Process Blocklist
# ─────────────────────────────────────────────────────────────────────────────
download_blocklist() {
    local url=$(get_blocklist_url)
    local temp_file=$(mktemp)
    local level_name=$(get_level_name)

    log_info "Downloading blocklist: $level_name"
    log_info "Source: StevenBlack Unified Hosts"

    # Download with retry
    local retries=3
    local success=false

    for ((i=1; i<=retries; i++)); do
        if curl -sL --connect-timeout 30 --max-time 120 "$url" -o "$temp_file" 2>/dev/null; then
            # Verify download (should contain hosts entries)
            if grep -q "^0\.0\.0\.0" "$temp_file" 2>/dev/null; then
                success=true
                break
            fi
        fi
        log_warn "Download attempt $i failed, retrying..."
        sleep 2
    done

    if [ "$success" = false ]; then
        log_error "Failed to download blocklist after $retries attempts"
        rm -f "$temp_file"
        return 1
    fi

    echo "$temp_file"
}

process_blocklist() {
    local input_file="$1"
    local output_file="$2"
    local block_target="${BLOCK_TARGET:-0.0.0.0}"

    log_info "Processing blocklist..."

    # Process hosts file:
    # 1. Remove comments and empty lines
    # 2. Extract domain names (second column)
    # 3. Skip localhost entries
    # 4. Convert to dnsmasq format
    # 5. Apply whitelist

    local temp_domains=$(mktemp)

    # Extract blocked domains
    grep "^0\.0\.0\.0\|^127\.0\.0\.1" "$input_file" | \
        awk '{print $2}' | \
        grep -v "^localhost" | \
        grep -v "^local$" | \
        grep -v "^$" | \
        sort -u > "$temp_domains"

    # Apply whitelist if exists
    if [ -f "$SHIELD_DIR/whitelist.txt" ]; then
        local whitelist_domains=$(grep -v "^#" "$SHIELD_DIR/whitelist.txt" | grep -v "^$" || true)
        if [ -n "$whitelist_domains" ]; then
            local temp_filtered=$(mktemp)
            grep -vFf <(echo "$whitelist_domains") "$temp_domains" > "$temp_filtered" || true
            mv "$temp_filtered" "$temp_domains"
            log_info "Applied whitelist exceptions"
        fi
    fi

    # Convert to dnsmasq format: address=/domain/0.0.0.0
    local domain_count=$(wc -l < "$temp_domains")

    {
        echo "# DNS Shield Blocklist"
        echo "# Generated: $(date -Iseconds)"
        echo "# Domains: $domain_count"
        echo "# Source: StevenBlack Unified Hosts"
        echo "# Level: $(get_level_name)"
        echo "#"

        while IFS= read -r domain; do
            echo "address=/$domain/$block_target"
        done < "$temp_domains"
    } > "$output_file"

    rm -f "$temp_domains"

    log_success "Processed $domain_count domains"
    echo "$domain_count"
}

# ─────────────────────────────────────────────────────────────────────────────
# dnsmasq Integration
# ─────────────────────────────────────────────────────────────────────────────
configure_dnsmasq() {
    log_info "Configuring dnsmasq integration..."

    # Create dnsmasq include config
    cat > "$DNSMASQ_CONF" << DNSMASQCONF
# DNS Shield - dnsmasq configuration
# Auto-generated by update-blocklists.sh
# DO NOT EDIT - changes will be overwritten

# Include blocklist
conf-file=$HOSTS_FILE

# Log blocked queries (optional, for stats)
log-queries=extra
log-facility=/var/log/hookprobe/dnsmasq-queries.log

# Cache settings optimized for blocking
cache-size=10000
min-cache-ttl=300
DNSMASQCONF

    log_success "dnsmasq configuration updated"
}

reload_dnsmasq() {
    log_info "Reloading dnsmasq..."

    # Test configuration first
    if dnsmasq --test 2>/dev/null; then
        if systemctl is-active --quiet dnsmasq; then
            systemctl reload dnsmasq 2>/dev/null || systemctl restart dnsmasq
            log_success "dnsmasq reloaded successfully"
        else
            log_warn "dnsmasq is not running"
        fi
    else
        log_error "dnsmasq configuration test failed!"
        return 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Statistics
# ─────────────────────────────────────────────────────────────────────────────
update_stats() {
    local domain_count="$1"
    local timestamp=$(date -Iseconds)
    local update_count=$(jq -r '.update_count // 0' "$STATS_FILE" 2>/dev/null || echo "0")
    update_count=$((update_count + 1))

    cat > "$STATS_FILE" << STATS
{
    "shield_level": ${SHIELD_LEVEL:-3},
    "shield_level_name": "$(get_level_name)",
    "domains_blocked": $domain_count,
    "last_update": "$timestamp",
    "update_count": $update_count,
    "blocklist_source": "StevenBlack Unified Hosts",
    "hosts_file": "$HOSTS_FILE",
    "version": "1.0.0"
}
STATS

    log_info "Statistics updated"
}

# ─────────────────────────────────────────────────────────────────────────────
# Systemd Timer Setup
# ─────────────────────────────────────────────────────────────────────────────
setup_auto_update() {
    local update_days="${AUTO_UPDATE_DAYS:-7}"

    if [ "$update_days" -eq 0 ]; then
        log_info "Auto-update disabled"
        return
    fi

    log_info "Setting up auto-update (every $update_days days)..."

    # Create systemd service
    cat > /etc/systemd/system/dns-shield-update.service << 'SERVICE'
[Unit]
Description=DNS Shield Blocklist Update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/hookprobe/guardian/scripts/update-blocklists.sh --silent
Nice=10
IOSchedulingClass=idle

[Install]
WantedBy=multi-user.target
SERVICE

    # Create systemd timer
    cat > /etc/systemd/system/dns-shield-update.timer << TIMER
[Unit]
Description=DNS Shield Weekly Blocklist Update

[Timer]
OnCalendar=weekly
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
TIMER

    # Enable timer
    systemctl daemon-reload
    systemctl enable --now dns-shield-update.timer 2>/dev/null || true

    log_success "Auto-update timer configured"
}

# ─────────────────────────────────────────────────────────────────────────────
# Shield Status Display
# ─────────────────────────────────────────────────────────────────────────────
show_status() {
    if [ ! -f "$STATS_FILE" ]; then
        echo "DNS Shield not configured"
        return
    fi

    local stats=$(cat "$STATS_FILE")
    local level=$(echo "$stats" | jq -r '.shield_level // 3')
    local level_name=$(echo "$stats" | jq -r '.shield_level_name // "Unknown"')
    local domains=$(echo "$stats" | jq -r '.domains_blocked // 0')
    local last_update=$(echo "$stats" | jq -r '.last_update // "Never"')

    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                    ${BOLD}DNS Shield Status${NC}                       ${CYAN}║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════╣${NC}"

    # Shield strength visualization
    local shield_bar=""
    for ((i=1; i<=5; i++)); do
        if [ $i -le $level ]; then
            shield_bar+="${GREEN}█${NC}"
        else
            shield_bar+="${YELLOW}░${NC}"
        fi
    done

    echo -e "${CYAN}║${NC}  Shield Level:    $shield_bar  ${BOLD}$level_name${NC}"
    printf "${CYAN}║${NC}  %-54s${CYAN}║${NC}\n" ""
    echo -e "${CYAN}║${NC}  Domains Blocked: ${BOLD}$(printf "%'d" $domains)${NC}"
    printf "${CYAN}║${NC}  %-54s${CYAN}║${NC}\n" ""
    echo -e "${CYAN}║${NC}  Last Update:     ${last_update}"
    printf "${CYAN}║${NC}  %-54s${CYAN}║${NC}\n" ""
    echo -e "${CYAN}║${NC}  Source:          StevenBlack Unified Hosts"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --silent|-s) SILENT=true; shift ;;
            --force|-f) FORCE=true; shift ;;
            --status) init_config; show_status; exit 0 ;;
            --help|-h)
                echo "DNS Shield - Blocklist Updater"
                echo ""
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --silent, -s    Run without output (for cron/systemd)"
                echo "  --force, -f     Force update even if recently updated"
                echo "  --status        Show current shield status"
                echo "  --help, -h      Show this help"
                echo ""
                echo "Configuration: $CONFIG_FILE"
                exit 0
                ;;
            *) shift ;;
        esac
    done

    show_banner

    # Check root
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root"
        exit 1
    fi

    # Initialize
    init_config

    # Check if update needed (skip if updated in last 6 hours, unless forced)
    if [ "$FORCE" = false ] && [ -f "$HOSTS_FILE" ]; then
        local file_age=$(($(date +%s) - $(stat -c %Y "$HOSTS_FILE" 2>/dev/null || echo 0)))
        if [ $file_age -lt 21600 ]; then
            log_info "Blocklist was updated recently ($(($file_age / 3600))h ago). Use --force to override."
            show_status
            exit 0
        fi
    fi

    # Download blocklist
    local temp_file=$(download_blocklist)
    if [ -z "$temp_file" ] || [ ! -f "$temp_file" ]; then
        log_error "Failed to download blocklist"
        exit 1
    fi

    # Process blocklist
    local domain_count=$(process_blocklist "$temp_file" "$HOSTS_FILE")
    rm -f "$temp_file"

    # Configure dnsmasq
    configure_dnsmasq

    # Reload dnsmasq
    reload_dnsmasq

    # Update stats
    update_stats "$domain_count"

    # Setup auto-update
    setup_auto_update

    # Show final status
    show_status

    log_success "DNS Shield updated successfully!"
}

main "$@"
