#!/bin/bash
#
# dfs-channel-selector.sh - DFS-aware WiFi Channel Selection
# Part of HookProbe Fortress - Bridges shell and Python DFS intelligence
#
# Uses the ML-powered DFS intelligence module for optimal channel selection
# with radar history awareness and NOP compliance.
#
# Usage:
#   ./dfs-channel-selector.sh best [--band 5] [--prefer-dfs] [--min-bw 80]
#   ./dfs-channel-selector.sh score <channel>
#   ./dfs-channel-selector.sh rank [--include-dfs]
#   ./dfs-channel-selector.sh status
#   ./dfs-channel-selector.sh log-radar <channel>
#
# Version: 1.0.0
# License: AGPL-3.0

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DFS_MODULE="${DFS_MODULE:-/opt/hookprobe/shared/wireless/dfs_intelligence.py}"
DFS_API_URL="${DFS_API_URL:-http://localhost:8767}"
DB_PATH="${DFS_DB_PATH:-/var/lib/hookprobe/dfs_intelligence.db}"
LOG_FILE="/var/log/fortress/dfs-channel-selector.log"
STATE_DIR="/var/lib/fortress/dfs"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[DFS]${NC} $*" | tee -a "$LOG_FILE" 2>/dev/null; }
log_warn() { echo -e "${YELLOW}[DFS]${NC} $*" | tee -a "$LOG_FILE" 2>/dev/null; }
log_error() { echo -e "${RED}[DFS]${NC} $*" | tee -a "$LOG_FILE" 2>/dev/null; }

# Ensure directories exist
mkdir -p "$STATE_DIR" "$(dirname "$LOG_FILE")" 2>/dev/null || true

# ============================================================
# CHECK DFS API AVAILABILITY
# ============================================================
check_dfs_api() {
    if curl -s --connect-timeout 2 "${DFS_API_URL}/health" &>/dev/null; then
        return 0
    fi
    return 1
}

# ============================================================
# CHECK PYTHON MODULE AVAILABILITY
# ============================================================
check_python_module() {
    if [ -f "$DFS_MODULE" ] && python3 -c "import sys; sys.path.insert(0, '$(dirname $DFS_MODULE)'); from dfs_intelligence import ChannelScorer" 2>/dev/null; then
        return 0
    fi
    return 1
}

# ============================================================
# FALLBACK: SIMPLE CHANNEL SELECTION (No ML)
# ============================================================
fallback_select_channel() {
    local band="${1:-5}"
    local prefer_dfs="${2:-false}"

    log_warn "Using fallback channel selection (DFS intelligence unavailable)"

    # 5GHz non-DFS channels (safe choices)
    local safe_5ghz=(36 40 44 48 149 153 157 161 165)
    # 5GHz DFS channels (UNII-2A - shorter CAC time)
    local dfs_channels=(52 56 60 64)

    if [ "$band" = "2" ] || [ "$band" = "2.4" ]; then
        # 2.4GHz - always return 6 as safe default
        echo "6"
        return
    fi

    if [ "$prefer_dfs" = "true" ]; then
        # Return first DFS channel (requires 60s CAC)
        echo "52"
    else
        # Return safe non-DFS channel
        echo "36"
    fi
}

# ============================================================
# GET BEST CHANNEL VIA API
# ============================================================
get_best_channel_api() {
    local prefer_dfs="${1:-false}"
    local min_bandwidth="${2:-20}"

    local response
    response=$(curl -s --connect-timeout 5 -X POST "${DFS_API_URL}/best" \
        -H "Content-Type: application/json" \
        -d "{\"prefer_dfs\": $prefer_dfs, \"min_bandwidth\": $min_bandwidth}" 2>/dev/null)

    if [ -n "$response" ]; then
        local channel
        channel=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('channel', d.get('best_channel', '')))" 2>/dev/null)
        if [ -n "$channel" ] && [ "$channel" != "None" ]; then
            echo "$channel"
            return 0
        fi
    fi

    return 1
}

# ============================================================
# GET BEST CHANNEL VIA PYTHON MODULE
# ============================================================
get_best_channel_python() {
    local prefer_dfs="${1:-false}"
    local min_bandwidth="${2:-20}"

    local args="best"
    [ "$prefer_dfs" = "true" ] && args="$args --prefer-dfs"
    [ "$min_bandwidth" != "20" ] && args="$args --min-bandwidth $min_bandwidth"

    local channel
    channel=$(python3 "$DFS_MODULE" $args --db "$DB_PATH" 2>/dev/null | tail -1)

    if [ -n "$channel" ] && [[ "$channel" =~ ^[0-9]+$ ]]; then
        echo "$channel"
        return 0
    fi

    return 1
}

# ============================================================
# GET CHANNEL SCORE VIA API
# ============================================================
get_channel_score_api() {
    local channel="$1"

    local response
    response=$(curl -s --connect-timeout 5 -X POST "${DFS_API_URL}/score" \
        -H "Content-Type: application/json" \
        -d "{\"channel\": $channel}" 2>/dev/null)

    if [ -n "$response" ]; then
        echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Score: {d.get(\"score\", \"N/A\")}')" 2>/dev/null
        return 0
    fi

    return 1
}

# ============================================================
# RANK ALL CHANNELS
# ============================================================
rank_channels() {
    local include_dfs="${1:-true}"

    if check_dfs_api; then
        curl -s "${DFS_API_URL}/rank?include_dfs=$include_dfs" 2>/dev/null | \
            python3 -c "import sys,json; d=json.load(sys.stdin); [print(f'{c[\"channel\"]:3d}: {c[\"score\"]:.2f} ({c.get(\"reason\", \"\")}') for c in d.get('channels', [])]" 2>/dev/null
        return
    fi

    if check_python_module; then
        local args="rank"
        [ "$include_dfs" = "true" ] && args="$args --include-dfs"
        python3 "$DFS_MODULE" $args --db "$DB_PATH" 2>/dev/null
        return
    fi

    log_error "No DFS scoring available"
    return 1
}

# ============================================================
# GET DFS STATUS
# ============================================================
get_dfs_status() {
    echo ""
    echo "DFS Intelligence Status"
    echo "======================="
    echo ""

    # Check API
    if check_dfs_api; then
        echo -e "API Server:     ${GREEN}Running${NC} (${DFS_API_URL})"
        curl -s "${DFS_API_URL}/status" 2>/dev/null | \
            python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Total Events:   {d.get(\"total_events\", 0)}'); print(f'ML Ready:       {d.get(\"ml_ready\", False)}'); print(f'NOP Channels:   {d.get(\"nop_channels\", [])}')" 2>/dev/null
    else
        echo -e "API Server:     ${RED}Not Running${NC}"
    fi

    # Check Python module
    if check_python_module; then
        echo -e "Python Module:  ${GREEN}Available${NC}"
    else
        echo -e "Python Module:  ${RED}Not Available${NC}"
    fi

    # Check database
    if [ -f "$DB_PATH" ]; then
        local size=$(du -h "$DB_PATH" 2>/dev/null | cut -f1)
        echo -e "Database:       ${GREEN}$DB_PATH${NC} ($size)"
    else
        echo -e "Database:       ${YELLOW}Not Initialized${NC}"
    fi

    # Check hostapd integration
    if systemctl is-active --quiet fts-hostapd 2>/dev/null; then
        echo -e "Hostapd:        ${GREEN}Running${NC}"

        # Get current channel
        local current_ch=$(grep "^channel=" /etc/hostapd/fortress*.conf 2>/dev/null | head -1 | cut -d= -f2)
        [ -n "$current_ch" ] && echo "Current Channel: $current_ch"
    else
        echo -e "Hostapd:        ${YELLOW}Not Running${NC}"
    fi

    echo ""
}

# ============================================================
# LOG RADAR EVENT
# ============================================================
log_radar_event() {
    local channel="$1"
    local timestamp="${2:-$(date -Iseconds)}"

    if [ -z "$channel" ]; then
        log_error "Channel required for radar logging"
        return 1
    fi

    log_info "Recording radar event on channel $channel"

    # Try API first
    if check_dfs_api; then
        curl -s -X POST "${DFS_API_URL}/radar" \
            -H "Content-Type: application/json" \
            -d "{\"channel\": $channel, \"timestamp\": \"$timestamp\"}" &>/dev/null
        return 0
    fi

    # Try Python module
    if check_python_module; then
        python3 "$DFS_MODULE" log-radar --channel "$channel" --db "$DB_PATH" 2>/dev/null
        return 0
    fi

    # Fallback: write to state file
    local state_file="$STATE_DIR/radar_events.json"
    echo "{\"channel\": $channel, \"timestamp\": \"$timestamp\"}" >> "$state_file"

    return 0
}

# ============================================================
# MAIN: SELECT BEST CHANNEL
# ============================================================
select_best_channel() {
    local band="5"
    local prefer_dfs="false"
    local min_bandwidth="20"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --band) band="$2"; shift 2 ;;
            --prefer-dfs) prefer_dfs="true"; shift ;;
            --min-bw|--min-bandwidth) min_bandwidth="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    local channel=""

    # Try API first (fastest, has caching)
    if check_dfs_api; then
        log_info "Using DFS API for channel selection..."
        channel=$(get_best_channel_api "$prefer_dfs" "$min_bandwidth")
        if [ -n "$channel" ]; then
            log_info "Best channel (API): $channel"
            echo "$channel"
            return 0
        fi
    fi

    # Try Python module
    if check_python_module; then
        log_info "Using Python DFS module for channel selection..."
        channel=$(get_best_channel_python "$prefer_dfs" "$min_bandwidth")
        if [ -n "$channel" ]; then
            log_info "Best channel (Python): $channel"
            echo "$channel"
            return 0
        fi
    fi

    # Fallback to simple selection
    channel=$(fallback_select_channel "$band" "$prefer_dfs")
    log_info "Best channel (fallback): $channel"
    echo "$channel"
}

# ============================================================
# START DFS API CONTAINER
# ============================================================
start_dfs_container() {
    log_info "Starting DFS Intelligence container..."

    # Check if already running
    if podman ps --filter name=fts-dfs-intelligence --format "{{.Names}}" 2>/dev/null | grep -q fts-dfs-intelligence; then
        log_info "DFS container already running"
        return 0
    fi

    # Check if image exists
    if ! podman image exists hookprobe-dfs-intelligence:latest 2>/dev/null; then
        log_warn "DFS container image not found, building..."
        local container_dir="/opt/hookprobe/shared/wireless/containers/dfs-intelligence"
        if [ -d "$container_dir" ]; then
            podman build -t hookprobe-dfs-intelligence:latest "$container_dir" 2>/dev/null || {
                log_error "Failed to build DFS container"
                return 1
            }
        else
            log_error "Container build directory not found: $container_dir"
            return 1
        fi
    fi

    # Start container
    podman run -d \
        --name fts-dfs-intelligence \
        --restart unless-stopped \
        -p 8767:8767 \
        -v /var/lib/hookprobe:/var/lib/hookprobe:Z \
        -v /var/log/fortress:/var/log/fortress:Z \
        hookprobe-dfs-intelligence:latest 2>/dev/null || {
        log_error "Failed to start DFS container"
        return 1
    }

    # Wait for health
    local retries=10
    while [ $retries -gt 0 ]; do
        if check_dfs_api; then
            log_info "DFS container started successfully"
            return 0
        fi
        sleep 1
        retries=$((retries - 1))
    done

    log_warn "DFS container started but health check failed"
    return 0
}

# ============================================================
# STOP DFS API CONTAINER
# ============================================================
stop_dfs_container() {
    log_info "Stopping DFS Intelligence container..."
    podman stop fts-dfs-intelligence 2>/dev/null || true
    podman rm fts-dfs-intelligence 2>/dev/null || true
    log_info "DFS container stopped"
}

# ============================================================
# USAGE
# ============================================================
usage() {
    cat << EOF
HookProbe Fortress - DFS-Aware Channel Selection

Usage: $0 <command> [options]

Commands:
  best [options]      Get best channel recommendation
    --band <2|5>      Band to select (default: 5)
    --prefer-dfs      Prefer DFS channels for less congestion
    --min-bw <MHz>    Minimum bandwidth (20, 40, 80, 160)

  score <channel>     Get score for specific channel
  rank [--include-dfs] Rank all channels by score
  status              Show DFS intelligence status
  log-radar <channel> Log radar detection event

  container-start     Start DFS API container
  container-stop      Stop DFS API container

Examples:
  $0 best                         # Best non-DFS 5GHz channel
  $0 best --prefer-dfs            # Best channel including DFS
  $0 best --band 2                # Best 2.4GHz channel
  $0 score 52                     # Score for DFS channel 52
  $0 rank --include-dfs           # Rank all channels
  $0 log-radar 100                # Log radar on channel 100

Environment:
  DFS_API_URL         DFS API endpoint (default: http://localhost:8767)
  DFS_MODULE          Python module path
  DFS_DB_PATH         SQLite database path

EOF
}

# ============================================================
# MAIN
# ============================================================
case "${1:-}" in
    best)
        shift
        select_best_channel "$@"
        ;;
    score)
        [ -z "$2" ] && { echo "Usage: $0 score <channel>"; exit 1; }
        if check_dfs_api; then
            get_channel_score_api "$2"
        elif check_python_module; then
            python3 "$DFS_MODULE" score --channel "$2" --db "$DB_PATH" 2>/dev/null
        else
            log_error "No DFS scoring available"
            exit 1
        fi
        ;;
    rank)
        shift
        include_dfs="true"
        [ "$1" = "--include-dfs" ] && include_dfs="true"
        [ "$1" = "--no-dfs" ] && include_dfs="false"
        rank_channels "$include_dfs"
        ;;
    status)
        get_dfs_status
        ;;
    log-radar)
        [ -z "$2" ] && { echo "Usage: $0 log-radar <channel>"; exit 1; }
        log_radar_event "$2"
        ;;
    container-start|start)
        start_dfs_container
        ;;
    container-stop|stop)
        stop_dfs_container
        ;;
    help|-h|--help)
        usage
        ;;
    *)
        usage
        exit 1
        ;;
esac
