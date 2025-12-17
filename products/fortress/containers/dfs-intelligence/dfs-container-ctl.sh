#!/bin/bash
# ============================================================
# HookProbe DFS Intelligence Container Controller
# ============================================================
#
# Manages the DFS Intelligence container lifecycle.
# Provides a unified interface for starting, stopping, and
# interacting with the containerized ML service.
#
# Usage:
#   dfs-container-ctl.sh <command> [options]
#
# Commands:
#   build       Build the container image
#   start       Start the container
#   stop        Stop the container
#   restart     Restart the container
#   status      Show container status
#   logs        Show container logs
#   shell       Open shell in container
#   api         Make API request to container
#   health      Check container health
#
# Version: 1.0.0
# License: AGPL-3.0
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Container configuration
CONTAINER_NAME="${DFS_CONTAINER_NAME:-fortress-dfs-intelligence}"
IMAGE_NAME="${DFS_IMAGE_NAME:-localhost/fortress-dfs-intelligence:latest}"
API_PORT="${DFS_API_PORT:-8767}"
DATA_VOLUME="${DFS_DATA_VOLUME:-fortress-dfs-data}"
LOG_VOLUME="${DFS_LOG_VOLUME:-fortress-dfs-logs}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[DFS-CTL]${NC} $*"; }
log_success() { echo -e "${GREEN}[DFS-CTL]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[DFS-CTL]${NC} $*"; }
log_error() { echo -e "${RED}[DFS-CTL]${NC} $*"; }

# ============================================================
# Container Runtime Detection
# ============================================================

detect_container_runtime() {
    # Prefer podman, fall back to docker
    if command -v podman &>/dev/null; then
        echo "podman"
    elif command -v docker &>/dev/null; then
        echo "docker"
    else
        log_error "No container runtime found (podman or docker required)"
        exit 1
    fi
}

RUNTIME=$(detect_container_runtime)
log_info "Using container runtime: $RUNTIME"

# ============================================================
# Build Functions
# ============================================================

build_image() {
    log_info "Building DFS Intelligence container image..."

    local build_args=""
    [ -n "${HTTP_PROXY:-}" ] && build_args="$build_args --build-arg HTTP_PROXY=$HTTP_PROXY"
    [ -n "${HTTPS_PROXY:-}" ] && build_args="$build_args --build-arg HTTPS_PROXY=$HTTPS_PROXY"

    cd "$SCRIPT_DIR"

    $RUNTIME build \
        -t "$IMAGE_NAME" \
        -f Containerfile \
        $build_args \
        .

    log_success "Image built: $IMAGE_NAME"
}

# ============================================================
# Lifecycle Functions
# ============================================================

start_container() {
    log_info "Starting DFS Intelligence container..."

    # Check if already running
    if $RUNTIME ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_warn "Container already running"
        return 0
    fi

    # Check if container exists but stopped
    if $RUNTIME ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_info "Starting existing container..."
        $RUNTIME start "$CONTAINER_NAME"
        log_success "Container started"
        return 0
    fi

    # Create volumes if they don't exist
    $RUNTIME volume create "$DATA_VOLUME" 2>/dev/null || true
    $RUNTIME volume create "$LOG_VOLUME" 2>/dev/null || true

    # Run new container
    $RUNTIME run -d \
        --name "$CONTAINER_NAME" \
        --restart unless-stopped \
        -p "127.0.0.1:${API_PORT}:8767" \
        -v "${DATA_VOLUME}:/var/lib/fortress:Z" \
        -v "${LOG_VOLUME}:/var/log/fortress:Z" \
        -v "/var/run/hostapd:/var/run/hostapd:ro" \
        --health-cmd "curl -sf http://localhost:8767/health || exit 1" \
        --health-interval 30s \
        --health-timeout 10s \
        --health-retries 3 \
        "$IMAGE_NAME"

    log_success "Container started: $CONTAINER_NAME"

    # Wait for health
    log_info "Waiting for container to be healthy..."
    local retries=30
    while [ $retries -gt 0 ]; do
        if $RUNTIME inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null | grep -q "healthy"; then
            log_success "Container is healthy"
            return 0
        fi
        sleep 1
        retries=$((retries - 1))
    done

    log_warn "Container may not be fully healthy yet"
}

stop_container() {
    log_info "Stopping DFS Intelligence container..."

    if $RUNTIME ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        $RUNTIME stop "$CONTAINER_NAME"
        log_success "Container stopped"
    else
        log_warn "Container not running"
    fi
}

restart_container() {
    stop_container
    start_container
}

remove_container() {
    log_info "Removing DFS Intelligence container..."

    stop_container 2>/dev/null || true

    if $RUNTIME ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        $RUNTIME rm "$CONTAINER_NAME"
        log_success "Container removed"
    else
        log_warn "Container not found"
    fi
}

# ============================================================
# Status & Monitoring
# ============================================================

show_status() {
    log_info "DFS Intelligence Container Status"
    echo "=========================================="

    # Container status
    if $RUNTIME ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo -e "Container:  ${GREEN}Running${NC}"

        # Health status
        local health
        health=$($RUNTIME inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "unknown")
        case "$health" in
            healthy)   echo -e "Health:     ${GREEN}Healthy${NC}" ;;
            unhealthy) echo -e "Health:     ${RED}Unhealthy${NC}" ;;
            starting)  echo -e "Health:     ${YELLOW}Starting${NC}" ;;
            *)         echo -e "Health:     ${YELLOW}Unknown${NC}" ;;
        esac

        # API status
        if curl -sf "http://127.0.0.1:${API_PORT}/health" &>/dev/null; then
            echo -e "API:        ${GREEN}Responding${NC}"
        else
            echo -e "API:        ${RED}Not responding${NC}"
        fi

        # Resource usage
        echo ""
        echo "Resources:"
        $RUNTIME stats --no-stream --format "  CPU: {{.CPUPerc}}\n  Memory: {{.MemUsage}}" "$CONTAINER_NAME"

    else
        echo -e "Container:  ${RED}Stopped${NC}"
    fi

    echo ""
    echo "Configuration:"
    echo "  Image:      $IMAGE_NAME"
    echo "  API Port:   $API_PORT"
    echo "  Data Vol:   $DATA_VOLUME"
    echo "  Runtime:    $RUNTIME"
    echo "=========================================="
}

show_logs() {
    local follow="${1:-}"
    local lines="${2:-100}"

    if [ "$follow" = "-f" ] || [ "$follow" = "--follow" ]; then
        $RUNTIME logs -f "$CONTAINER_NAME"
    else
        $RUNTIME logs --tail "$lines" "$CONTAINER_NAME"
    fi
}

check_health() {
    if curl -sf "http://127.0.0.1:${API_PORT}/health" &>/dev/null; then
        local response
        response=$(curl -s "http://127.0.0.1:${API_PORT}/health")
        log_success "Container is healthy"
        echo "$response" | jq . 2>/dev/null || echo "$response"
        return 0
    else
        log_error "Container health check failed"
        return 1
    fi
}

# ============================================================
# API Interaction
# ============================================================

api_request() {
    local method="${1:-GET}"
    local endpoint="${2:-/health}"
    local data="${3:-}"

    local url="http://127.0.0.1:${API_PORT}${endpoint}"

    case "$method" in
        GET)
            curl -s "$url" | jq . 2>/dev/null || curl -s "$url"
            ;;
        POST)
            if [ -n "$data" ]; then
                curl -s -X POST -H "Content-Type: application/json" -d "$data" "$url" | jq . 2>/dev/null || \
                curl -s -X POST -H "Content-Type: application/json" -d "$data" "$url"
            else
                curl -s -X POST "$url" | jq . 2>/dev/null || curl -s -X POST "$url"
            fi
            ;;
        *)
            log_error "Unknown method: $method"
            return 1
            ;;
    esac
}

# ============================================================
# Shell Access
# ============================================================

open_shell() {
    if ! $RUNTIME ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_error "Container not running"
        return 1
    fi

    $RUNTIME exec -it "$CONTAINER_NAME" /bin/bash
}

run_cli() {
    if ! $RUNTIME ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_error "Container not running"
        return 1
    fi

    $RUNTIME exec -it "$CONTAINER_NAME" python3 /app/dfs_intelligence.py "$@"
}

# ============================================================
# Quick API Commands
# ============================================================

get_best_channel() {
    local prefer_dfs="${1:-false}"
    local min_bw="${2:-20}"

    api_request POST /best "{\"prefer_dfs\": $prefer_dfs, \"min_bandwidth\": $min_bw}"
}

score_channel() {
    local channel="$1"
    api_request POST /score "{\"channel\": $channel}"
}

rank_channels() {
    local include_dfs="${1:-true}"
    api_request GET "/rank?include_dfs=$include_dfs"
}

log_radar() {
    local channel="$1"
    local frequency="${2:-}"

    local data="{\"channel\": $channel"
    [ -n "$frequency" ] && data="$data, \"frequency\": $frequency"
    data="$data}"

    api_request POST /radar "$data"
}

train_model() {
    local min_samples="${1:-50}"
    api_request POST /train "{\"min_samples\": $min_samples}"
}

# ============================================================
# Main CLI
# ============================================================

show_help() {
    cat << EOF
DFS Intelligence Container Controller

Usage: $(basename "$0") <command> [options]

Lifecycle Commands:
  build               Build the container image
  start               Start the container
  stop                Stop the container
  restart             Restart the container
  remove              Remove the container
  status              Show container status
  logs [-f] [N]       Show container logs (follow, last N lines)
  health              Check container health
  shell               Open shell in container

API Commands:
  api <method> <endpoint> [data]
                      Make raw API request
  best [prefer_dfs] [min_bw]
                      Get best channel recommendation
  score <channel>     Score a specific channel
  rank [include_dfs]  Rank all channels
  radar <channel> [freq]
                      Log radar event
  train [min_samples] Train ML model

Environment Variables:
  DFS_CONTAINER_NAME  Container name (default: fortress-dfs-intelligence)
  DFS_IMAGE_NAME      Image name (default: localhost/fortress-dfs-intelligence:latest)
  DFS_API_PORT        API port (default: 8767)
  DFS_DATA_VOLUME     Data volume name (default: fortress-dfs-data)

Examples:
  # Build and start
  $(basename "$0") build
  $(basename "$0") start

  # Get best DFS channel
  $(basename "$0") best true 80

  # Score channel 52
  $(basename "$0") score 52

  # Log radar event on channel 100
  $(basename "$0") radar 100 5500

  # Train ML model
  $(basename "$0") train 50

EOF
}

main() {
    local cmd="${1:-}"
    shift || true

    case "$cmd" in
        build)
            build_image
            ;;
        start)
            start_container
            ;;
        stop)
            stop_container
            ;;
        restart)
            restart_container
            ;;
        remove|rm)
            remove_container
            ;;
        status)
            show_status
            ;;
        logs)
            show_logs "$@"
            ;;
        health)
            check_health
            ;;
        shell|sh)
            open_shell
            ;;
        cli)
            run_cli "$@"
            ;;
        api)
            api_request "$@"
            ;;
        best)
            get_best_channel "$@"
            ;;
        score)
            score_channel "$@"
            ;;
        rank)
            rank_channels "$@"
            ;;
        radar)
            log_radar "$@"
            ;;
        train)
            train_model "$@"
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            show_help
            exit 1
            ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
