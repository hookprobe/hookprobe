#!/bin/bash
#
# HookProbe Sentinel Lite Bootstrap
# Ultra-lightweight validator for constrained devices
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/hookprobe/hookprobe/main/releases/sentinel-lite/bootstrap.sh | sudo bash
#   # OR with options:
#   curl -sSL https://raw.githubusercontent.com/hookprobe/hookprobe/main/releases/sentinel-lite/bootstrap.sh | sudo bash -s -- --mssp-endpoint my-mssp.example.com
#
# Requirements:
#   - Linux (Debian/Ubuntu/Raspbian, RHEL/Fedora, Alpine)
#   - Python 3.7+
#   - 256MB+ RAM
#   - Root access
#
# Target devices:
#   - Raspberry Pi 3/Zero/Pico
#   - Low-power ARM/IoT gateways
#   - LTE/mobile network validators
#

set -e

VERSION="1.0.0"
GITHUB_RAW="https://raw.githubusercontent.com/hookprobe/hookprobe/main/releases/sentinel-lite"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Installation paths
INSTALL_DIR="/opt/hookprobe-sentinel"
CONFIG_DIR="/etc/hookprobe"
DATA_DIR="/var/lib/hookprobe/sentinel"
LOG_DIR="/var/log/hookprobe"

# Defaults
MSSP_ENDPOINT="${MSSP_ENDPOINT:-mssp.hookprobe.com}"
MSSP_PORT="${MSSP_PORT:-8443}"
SENTINEL_PORT="${SENTINEL_PORT:-8443}"
METRICS_PORT="${METRICS_PORT:-9090}"
SENTINEL_REGION="${SENTINEL_REGION:-auto}"
SENTINEL_TIER="${SENTINEL_TIER:-community}"

# ============================================================
# FUNCTIONS
# ============================================================

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

show_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
  ___ ___ _  _ _____ ___ _  _ ___ _      _    ___ _____ ___
 / __| __| \| |_   _|_ _| \| | __| |    | |  |_ _|_   _| __|
 \__ \ _|| .` | | |  | || .` | _|| |__  | |__ | |  | | | _|
 |___/___|_|\_| |_| |___|_|\_|___|____| |____|___| |_| |___|

EOF
    echo -e "${NC}"
    echo "  Ultra-Lightweight Validator v${VERSION}"
    echo "  For Raspberry Pi, ARM, IoT, and LTE devices"
    echo ""
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        echo "Usage: curl -sSL $GITHUB_RAW/bootstrap.sh | sudo bash"
        exit 1
    fi
}

detect_platform() {
    ARCH=$(uname -m)
    TOTAL_RAM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo "512")

    # Auto-select memory limit
    if [ "$TOTAL_RAM_MB" -le 512 ]; then
        MEMORY_LIMIT=128
    elif [ "$TOTAL_RAM_MB" -le 1024 ]; then
        MEMORY_LIMIT=192
    elif [ "$TOTAL_RAM_MB" -le 2048 ]; then
        MEMORY_LIMIT=256
    else
        MEMORY_LIMIT=384
    fi

    log_info "Platform: $ARCH, RAM: ${TOTAL_RAM_MB}MB, Memory limit: ${MEMORY_LIMIT}MB"
}

install_deps() {
    log_info "Installing minimal dependencies..."

    if command -v apt-get &>/dev/null; then
        apt-get update -qq 2>/dev/null || true
        apt-get install -y -qq --no-install-recommends python3 curl ca-certificates 2>/dev/null
    elif command -v dnf &>/dev/null; then
        dnf install -y -q python3 curl ca-certificates 2>/dev/null
    elif command -v yum &>/dev/null; then
        yum install -y -q python3 curl ca-certificates 2>/dev/null
    elif command -v apk &>/dev/null; then
        apk add --no-cache python3 curl ca-certificates 2>/dev/null
    fi
}

download_sentinel() {
    log_info "Downloading Sentinel Lite..."

    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
    chmod 750 "$CONFIG_DIR" "$DATA_DIR"

    # Download the sentinel Python script
    if ! curl -sSfL "$GITHUB_RAW/sentinel.py" -o "$INSTALL_DIR/sentinel.py"; then
        log_error "Failed to download sentinel.py"
        exit 1
    fi
    chmod +x "$INSTALL_DIR/sentinel.py"

    log_info "Downloaded sentinel.py ($(wc -c < "$INSTALL_DIR/sentinel.py") bytes)"
}

create_config() {
    log_info "Creating configuration..."

    # Generate node ID
    local NODE_ID="sentinel-lite-$(hostname -s 2>/dev/null || echo 'node')-$(date +%s | sha256sum | head -c 8)"

    # Auto-detect region
    if [ "$SENTINEL_REGION" = "auto" ]; then
        SENTINEL_REGION=$(curl -sf --connect-timeout 3 http://ip-api.com/json/ 2>/dev/null | grep -o '"countryCode":"[^"]*"' | cut -d'"' -f4 | tr '[:upper:]' '[:lower:]' || echo "unknown")
        [ -z "$SENTINEL_REGION" ] && SENTINEL_REGION="unknown"
    fi

    # Create environment file
    cat > "$CONFIG_DIR/sentinel-lite.env" << ENV
SENTINEL_NODE_ID=${NODE_ID}
SENTINEL_REGION=${SENTINEL_REGION}
SENTINEL_TIER=${SENTINEL_TIER}
MSSP_ENDPOINT=${MSSP_ENDPOINT}
MSSP_PORT=${MSSP_PORT}
SENTINEL_PORT=${SENTINEL_PORT}
METRICS_PORT=${METRICS_PORT}
MEMORY_LIMIT_MB=${MEMORY_LIMIT}
LOG_LEVEL=INFO
ENV
    chmod 640 "$CONFIG_DIR/sentinel-lite.env"

    log_info "Node ID: ${NODE_ID}"
}

create_service() {
    log_info "Creating systemd service..."

    cat > /etc/systemd/system/hookprobe-sentinel-lite.service << 'SERVICE'
[Unit]
Description=HookProbe Sentinel Lite
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/hookprobe-sentinel
EnvironmentFile=/etc/hookprobe/sentinel-lite.env
MemoryMax=${MEMORY_LIMIT_MB}M
CPUWeight=50
Nice=10
ExecStart=/usr/bin/python3 /opt/hookprobe-sentinel/sentinel.py
Restart=always
RestartSec=10
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/hookprobe /var/log/hookprobe
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SERVICE

    systemctl daemon-reload
    systemctl enable hookprobe-sentinel-lite.service 2>/dev/null
}

show_complete() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  SENTINEL LITE INSTALLED SUCCESSFULLY          ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    source "$CONFIG_DIR/sentinel-lite.env" 2>/dev/null
    echo "  Node ID:    ${SENTINEL_NODE_ID:-generated}"
    echo "  Region:     ${SENTINEL_REGION:-auto}"
    echo "  Memory:     ${MEMORY_LIMIT}MB"
    echo "  MSSP:       ${MSSP_ENDPOINT}:${MSSP_PORT}"
    echo ""
    echo -e "${YELLOW}Commands:${NC}"
    echo "  sudo systemctl start hookprobe-sentinel-lite"
    echo "  sudo systemctl status hookprobe-sentinel-lite"
    echo "  curl http://localhost:${METRICS_PORT}/health"
    echo ""
}

uninstall() {
    log_warn "Uninstalling Sentinel Lite..."
    systemctl stop hookprobe-sentinel-lite.service 2>/dev/null || true
    systemctl disable hookprobe-sentinel-lite.service 2>/dev/null || true
    rm -f /etc/systemd/system/hookprobe-sentinel-lite.service
    rm -rf "$INSTALL_DIR" "$CONFIG_DIR/sentinel-lite.env" "$DATA_DIR"
    systemctl daemon-reload
    log_info "Uninstalled successfully"
    exit 0
}

show_help() {
    echo "HookProbe Sentinel Lite Bootstrap v${VERSION}"
    echo ""
    echo "Usage:"
    echo "  curl -sSL $GITHUB_RAW/bootstrap.sh | sudo bash"
    echo "  curl -sSL $GITHUB_RAW/bootstrap.sh | sudo bash -s -- [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --mssp-endpoint URL   MSSP server (default: mssp.hookprobe.com)"
    echo "  --mssp-port PORT      MSSP port (default: 8443)"
    echo "  --port PORT           Listen port (default: 8443)"
    echo "  --region REGION       Region (default: auto-detect)"
    echo "  --tier TIER           Tier: community|professional|enterprise"
    echo "  --uninstall           Remove Sentinel Lite"
    echo "  --help                Show this help"
    echo ""
    exit 0
}

# ============================================================
# MAIN
# ============================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --mssp-endpoint) MSSP_ENDPOINT="$2"; shift 2 ;;
            --mssp-port) MSSP_PORT="$2"; shift 2 ;;
            --port) SENTINEL_PORT="$2"; shift 2 ;;
            --region) SENTINEL_REGION="$2"; shift 2 ;;
            --tier) SENTINEL_TIER="$2"; shift 2 ;;
            --uninstall) uninstall ;;
            --help|-h) show_help ;;
            *) log_error "Unknown option: $1"; show_help ;;
        esac
    done

    show_banner
    check_root
    detect_platform
    install_deps
    download_sentinel
    create_config
    create_service
    show_complete

    # Auto-start prompt
    read -p "Start Sentinel Lite now? [Y/n]: " start_now
    if [ "${start_now:-y}" != "n" ] && [ "${start_now:-Y}" != "N" ]; then
        systemctl start hookprobe-sentinel-lite.service
        sleep 2
        if systemctl is-active --quiet hookprobe-sentinel-lite.service; then
            echo -e "${GREEN}✓ Sentinel Lite is running${NC}"
        else
            echo -e "${RED}✗ Failed to start. Check: journalctl -u hookprobe-sentinel-lite${NC}"
        fi
    fi
}

main "$@"
