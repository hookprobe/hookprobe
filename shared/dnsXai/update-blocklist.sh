#!/bin/bash
# =============================================================================
# HookProbe Guardian - AI Ad Blocker Blocklist Updater
#
# Updates ad/tracker blocklists from multiple sources and prepares them
# for the AI ad blocker. Designed to run as a systemd timer or cron job.
#
# Usage:
#   ./update-blocklist.sh [--force] [--verbose]
#
# Author: HookProbe Team
# Version: 5.0.0
# License: AGPL-3.0 - see LICENSE file (exception from proprietary dnsXai)
# =============================================================================

set -e

# Configuration
BLOCKLIST_DIR="/opt/hookprobe/guardian/data/adblock"
BLOCKLIST_FILE="$BLOCKLIST_DIR/blocklist.txt"
TEMP_DIR="/tmp/hookprobe-blocklist-update"
LOG_FILE="/var/log/hookprobe/blocklist-update.log"
LOCK_FILE="/var/run/hookprobe-blocklist-update.lock"

# Blocklist sources (curated for quality and update frequency)
SOURCES=(
    # OISD - Optimized comprehensive blocklist
    "https://big.oisd.nl/"

    # Steven Black hosts - Unified hosts with extensions
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

    # AdGuard CNAME trackers - Critical for CNAME uncloaking
    "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/combined_disguised_trackers.txt"

    # Hagezi DNS blocklists - Pro level
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt"

    # 1Hosts - Lite version for performance
    "https://o0.pages.dev/Lite/domains.txt"

    # Anti-ad domains
    "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt"
)

# Whitelist for false positives
WHITELIST=(
    "localhost"
    "localhost.localdomain"
    "local"
    "broadcasthost"
    "ip6-localhost"
    "ip6-loopback"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
FORCE=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --force|-f)
            FORCE=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--force] [--verbose]"
            echo ""
            echo "Options:"
            echo "  --force, -f    Force update even if recently updated"
            echo "  --verbose, -v  Show detailed output"
            echo "  --help, -h     Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Logging function
log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Log to file
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null || true

    # Console output
    if [[ "$VERBOSE" == "true" ]] || [[ "$level" != "DEBUG" ]]; then
        case "$level" in
            ERROR)
                echo -e "${RED}[!]${NC} $message"
                ;;
            WARN)
                echo -e "${YELLOW}[!]${NC} $message"
                ;;
            INFO)
                echo -e "${GREEN}[*]${NC} $message"
                ;;
            DEBUG)
                echo -e "[.] $message"
                ;;
        esac
    fi
}

# Check if update is needed (within 12 hours)
check_update_needed() {
    if [[ "$FORCE" == "true" ]]; then
        return 0
    fi

    if [[ -f "$BLOCKLIST_FILE" ]]; then
        local file_age
        file_age=$(( $(date +%s) - $(stat -c %Y "$BLOCKLIST_FILE" 2>/dev/null || echo 0) ))

        # Skip if updated within 12 hours (43200 seconds)
        if [[ $file_age -lt 43200 ]]; then
            log "INFO" "Blocklist updated recently (${file_age}s ago). Use --force to override."
            return 1
        fi
    fi

    return 0
}

# Acquire lock
acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid
        pid=$(cat "$LOCK_FILE" 2>/dev/null)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            log "WARN" "Another update is running (PID: $pid)"
            exit 1
        fi
    fi

    echo $$ > "$LOCK_FILE"
}

# Release lock
release_lock() {
    rm -f "$LOCK_FILE"
}

# Cleanup on exit
cleanup() {
    release_lock
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# Create directories
setup_dirs() {
    mkdir -p "$BLOCKLIST_DIR"
    mkdir -p "$TEMP_DIR"
    mkdir -p "$(dirname "$LOG_FILE")"
}

# Download a blocklist source
download_source() {
    local url="$1"
    local output="$2"

    log "DEBUG" "Downloading: $url"

    if command -v curl &> /dev/null; then
        curl -sL --connect-timeout 30 --max-time 120 \
            -H "User-Agent: HookProbe-Guardian/5.0" \
            -o "$output" "$url" 2>/dev/null
    elif command -v wget &> /dev/null; then
        wget -q --timeout=30 \
            --user-agent="HookProbe-Guardian/5.0" \
            -O "$output" "$url" 2>/dev/null
    else
        log "ERROR" "Neither curl nor wget available"
        return 1
    fi

    return $?
}

# Parse hosts file format (0.0.0.0 domain or 127.0.0.1 domain)
parse_hosts_format() {
    local input="$1"
    local output="$2"

    grep -E '^(0\.0\.0\.0|127\.0\.0\.1)\s+' "$input" 2>/dev/null | \
        awk '{print tolower($2)}' | \
        grep -v '^localhost' | \
        grep -v '^$' | \
        sort -u >> "$output"
}

# Parse domain list format (one domain per line)
parse_domain_format() {
    local input="$1"
    local output="$2"

    grep -v '^#' "$input" 2>/dev/null | \
        grep -v '^!' | \
        grep -v '^$' | \
        sed 's/^||//' | \
        sed 's/\^$//' | \
        awk '{print tolower($1)}' | \
        grep -E '^[a-z0-9]' | \
        sort -u >> "$output"
}

# Process downloaded blocklists
process_blocklists() {
    local combined="$TEMP_DIR/combined.txt"
    local final="$TEMP_DIR/final.txt"

    > "$combined"

    local count=0
    local total=${#SOURCES[@]}

    for url in "${SOURCES[@]}"; do
        count=$((count + 1))
        local filename
        filename=$(echo "$url" | md5sum | cut -d' ' -f1)
        local output="$TEMP_DIR/$filename.txt"

        log "INFO" "[$count/$total] Fetching: $(echo "$url" | cut -d'/' -f3)"

        if download_source "$url" "$output"; then
            local lines_before
            lines_before=$(wc -l < "$combined" 2>/dev/null || echo 0)

            # Detect format and parse
            if grep -qE '^(0\.0\.0\.0|127\.0\.0\.1)\s+' "$output" 2>/dev/null; then
                parse_hosts_format "$output" "$combined"
            else
                parse_domain_format "$output" "$combined"
            fi

            local lines_after
            lines_after=$(wc -l < "$combined")
            local added=$((lines_after - lines_before))

            log "DEBUG" "  Added $added domains"
        else
            log "WARN" "  Failed to download"
        fi
    done

    # Deduplicate and clean
    log "INFO" "Processing and deduplicating..."

    sort -u "$combined" | \
        grep -vE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
        grep -E '\.' | \
        grep -vE '^\.|\.$' > "$final"

    # Remove whitelisted domains
    for domain in "${WHITELIST[@]}"; do
        sed -i "/^${domain}$/d" "$final"
    done

    # Get final count
    local final_count
    final_count=$(wc -l < "$final")

    log "INFO" "Final blocklist: $final_count unique domains"

    # Create output file with header
    {
        echo "# HookProbe Guardian AI Ad Blocker - Domain Blocklist"
        echo "# Generated: $(date -Iseconds)"
        echo "# Sources: ${#SOURCES[@]}"
        echo "# Total domains: $final_count"
        echo "# Format: One domain per line"
        echo "#"
        cat "$final"
    } > "$BLOCKLIST_FILE.new"

    # Atomic replace
    mv "$BLOCKLIST_FILE.new" "$BLOCKLIST_FILE"

    echo "$final_count"
}

# Update dnsmasq if available
update_dnsmasq() {
    local dnsmasq_hosts="/etc/dnsmasq.d/hookprobe-adblock.conf"

    if [[ -d "/etc/dnsmasq.d" ]]; then
        log "INFO" "Updating dnsmasq configuration..."

        {
            echo "# HookProbe Guardian Ad Blocker for dnsmasq"
            echo "# Generated: $(date -Iseconds)"
            echo "# Use AI ad blocker at 127.0.0.1:5353 for DNS"
            echo ""
            echo "# Forward DNS queries to AI ad blocker"
            echo "server=127.0.0.1#5353"
        } > "$dnsmasq_hosts"

        # Reload dnsmasq if running
        if systemctl is-active --quiet dnsmasq 2>/dev/null; then
            systemctl reload dnsmasq 2>/dev/null || true
            log "INFO" "dnsmasq configuration reloaded"
        fi
    fi
}

# Notify AI ad blocker to reload
notify_reload() {
    # Send SIGHUP to ai_ad_blocker if running
    local pid_file="/var/run/hookprobe-adblock.pid"

    if [[ -f "$pid_file" ]]; then
        local pid
        pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            kill -HUP "$pid" 2>/dev/null || true
            log "INFO" "Notified AI ad blocker to reload (PID: $pid)"
        fi
    fi

    # Also try via systemd
    if systemctl is-active --quiet hookprobe-adblock 2>/dev/null; then
        systemctl reload hookprobe-adblock 2>/dev/null || true
    fi
}

# Main execution
main() {
    log "INFO" "HookProbe Guardian Blocklist Updater"
    log "INFO" "===================================="

    # Check if update needed
    if ! check_update_needed; then
        exit 0
    fi

    # Acquire lock
    acquire_lock

    # Setup directories
    setup_dirs

    # Process blocklists
    local count
    count=$(process_blocklists)

    # Update dnsmasq
    update_dnsmasq

    # Notify ad blocker
    notify_reload

    log "INFO" "===================================="
    log "INFO" "Update complete: $count domains loaded"
}

main "$@"
