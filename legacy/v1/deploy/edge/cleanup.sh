#!/bin/bash
#
# cleanup.sh - HookProbe Cleanup Script
# Version: 5.0
# License: AGPL-3.0 - see LICENSE file
#
# Removes all HookProbe components:
# - Systemd units
# - XDP programs
# - Sysctl configurations
# - Network configurations
# - Podman containers and PODs
# - Files and directories
#

set -e
set -u

# ============================================================================
# CONSTANTS
# ============================================================================

readonly HOOKPROBE_BASE="/opt/hookprobe"
readonly SYSTEMD_DIR="/etc/systemd/system"
readonly LOG_FILE="/var/log/hookprobe/cleanup.log"

readonly SERVICES=(
    "hookprobe-provision.service"
    "hookprobe-agent.service"
    "hookprobe-uninstall.service"
    "hookprobe-update.service"
)

readonly TIMER="hookprobe-update.timer"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# ============================================================================
# LOGGING
# ============================================================================

log() {
    echo -e "${GREEN}[INFO]${NC} $*" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE" >&2
}

# ============================================================================
# CLEANUP FUNCTIONS
# ============================================================================

stop_services() {
    log "Stopping HookProbe services..."

    for service in "${SERVICES[@]}"; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            log "Stopping $service..."
            systemctl stop "$service" || log_warning "Failed to stop $service"
        fi
    done

    # Stop timer
    if systemctl is-active "$TIMER" >/dev/null 2>&1; then
        log "Stopping $TIMER..."
        systemctl stop "$TIMER" || log_warning "Failed to stop $TIMER"
    fi
}

disable_services() {
    log "Disabling HookProbe services..."

    for service in "${SERVICES[@]}"; do
        if systemctl is-enabled "$service" >/dev/null 2>&1; then
            log "Disabling $service..."
            systemctl disable "$service" || log_warning "Failed to disable $service"
        fi
    done

    # Disable timer
    if systemctl is-enabled "$TIMER" >/dev/null 2>&1; then
        log "Disabling $TIMER..."
        systemctl disable "$TIMER" || log_warning "Failed to disable $TIMER"
    fi
}

remove_systemd_units() {
    log "Removing systemd units..."

    for service in "${SERVICES[@]}"; do
        local service_file="$SYSTEMD_DIR/$service"
        if [ -f "$service_file" ]; then
            log "Removing $service_file..."
            rm -f "$service_file"
        fi
    done

    # Remove timer
    local timer_file="$SYSTEMD_DIR/$TIMER"
    if [ -f "$timer_file" ]; then
        log "Removing $timer_file..."
        rm -f "$timer_file"
    fi

    # Reload systemd
    systemctl daemon-reload
}

remove_xdp_programs() {
    log "Removing XDP programs..."

    # Get all network interfaces
    for iface in /sys/class/net/*; do
        iface_name=$(basename "$iface")

        # Skip loopback
        if [ "$iface_name" = "lo" ]; then
            continue
        fi

        # Try to remove XDP programs (both modes)
        log "Removing XDP from $iface_name..."
        ip link set dev "$iface_name" xdpgeneric off 2>/dev/null || true
        ip link set dev "$iface_name" xdpdrv off 2>/dev/null || true
        ip link set dev "$iface_name" xdpoffload off 2>/dev/null || true
    done

    log "XDP programs removed"
}

remove_kernel_settings() {
    log "Removing kernel settings..."

    local sysctl_file="/etc/sysctl.d/99-hookprobe.conf"

    if [ -f "$sysctl_file" ]; then
        log "Removing $sysctl_file..."
        rm -f "$sysctl_file"
    fi

    log "Kernel settings removed (reboot required for full reset)"
}

remove_podman_resources() {
    log "Removing Podman containers and PODs..."

    # Stop all hookprobe PODs
    for pod in $(podman pod ps --format "{{.Name}}" | grep "^hookprobe" || true); do
        log "Stopping POD: $pod..."
        podman pod stop "$pod" || log_warning "Failed to stop POD $pod"
        log "Removing POD: $pod..."
        podman pod rm -f "$pod" || log_warning "Failed to remove POD $pod"
    done

    # Remove any remaining hookprobe containers
    for container in $(podman ps -a --format "{{.Names}}" | grep "^hookprobe" || true); do
        log "Removing container: $container..."
        podman rm -f "$container" || log_warning "Failed to remove container $container"
    done

    # Remove volumes (ask for confirmation)
    local volumes=$(podman volume ls --format "{{.Name}}" | grep "hookprobe" || true)
    if [ -n "$volumes" ]; then
        log_warning "Found HookProbe volumes:"
        echo "$volumes"
        read -p "Remove volumes? This will DELETE ALL DATA [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            for volume in $volumes; do
                log "Removing volume: $volume..."
                podman volume rm "$volume" || log_warning "Failed to remove volume $volume"
            done
        else
            log "Volumes preserved"
        fi
    fi
}

remove_ovs_bridge() {
    log "Removing OVS bridge..."

    # Check if qsec-bridge exists
    if ovs-vsctl br-exists qsec-bridge 2>/dev/null; then
        log "Removing qsec-bridge..."
        ovs-vsctl del-br qsec-bridge || log_warning "Failed to remove qsec-bridge"
    else
        log "No qsec-bridge found"
    fi
}

remove_firewall_rules() {
    log "Removing firewall rules..."

    # Check if firewalld is active
    if systemctl is-active firewalld >/dev/null 2>&1; then
        log "Removing firewalld rules..."
        firewall-cmd --permanent --remove-port=80/tcp 2>/dev/null || true
        firewall-cmd --permanent --remove-port=443/tcp 2>/dev/null || true
        firewall-cmd --permanent --remove-port=3000/tcp 2>/dev/null || true
        firewall-cmd --permanent --remove-port=5678/tcp 2>/dev/null || true
        firewall-cmd --permanent --remove-port=8888/tcp 2>/dev/null || true
        firewall-cmd --reload || true
    fi

    # nftables rules (if any)
    if command -v nft >/dev/null 2>&1; then
        log "Checking nftables rules..."
        # Remove hookprobe-specific chains if they exist
        nft delete table inet hookprobe 2>/dev/null || true
    fi
}

remove_files() {
    log "Removing HookProbe files..."

    # Remove main directory
    if [ -d "$HOOKPROBE_BASE" ]; then
        log "Removing $HOOKPROBE_BASE..."
        rm -rf "$HOOKPROBE_BASE"
    fi

    # Remove config
    if [ -d "/etc/hookprobe" ]; then
        log "Removing /etc/hookprobe..."
        rm -rf "/etc/hookprobe"
    fi

    # Ask about logs
    if [ -d "/var/log/hookprobe" ]; then
        read -p "Remove logs in /var/log/hookprobe? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log "Removing /var/log/hookprobe..."
            rm -rf "/var/log/hookprobe"
        else
            log "Logs preserved"
        fi
    fi
}

# ============================================================================
# VERIFICATION
# ============================================================================

verify_cleanup() {
    log "Verifying cleanup..."

    local issues=0

    # Check services
    for service in "${SERVICES[@]}"; do
        if systemctl is-enabled "$service" >/dev/null 2>&1; then
            log_error "Service still enabled: $service"
            ((issues++))
        fi
    done

    # Check files
    if [ -d "$HOOKPROBE_BASE" ]; then
        log_error "Directory still exists: $HOOKPROBE_BASE"
        ((issues++))
    fi

    # Check PODs
    local pods=$(podman pod ps --format "{{.Name}}" | grep "^hookprobe" || true)
    if [ -n "$pods" ]; then
        log_error "PODs still exist: $pods"
        ((issues++))
    fi

    # Check XDP
    for iface in /sys/class/net/*; do
        iface_name=$(basename "$iface")
        if [ "$iface_name" = "lo" ]; then
            continue
        fi

        if ip link show "$iface_name" | grep -q "xdp" 2>/dev/null; then
            log_error "XDP still attached to $iface_name"
            ((issues++))
        fi
    done

    if [ $issues -eq 0 ]; then
        log "Cleanup verification passed"
        return 0
    else
        log_error "Cleanup verification failed with $issues issue(s)"
        return 1
    fi
}

# ============================================================================
# MAIN CLEANUP
# ============================================================================

main() {
    echo
    echo "======================================"
    echo "  HookProbe Cleanup"
    echo "======================================"
    echo

    # Ensure log directory exists
    mkdir -p "$(dirname "$LOG_FILE")"

    log "Starting HookProbe cleanup..."

    # Confirmation
    echo
    log_warning "This will remove ALL HookProbe components!"
    read -p "Are you sure? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Cleanup cancelled"
        exit 0
    fi

    echo

    # Cleanup steps
    stop_services
    disable_services
    remove_systemd_units
    remove_xdp_programs
    remove_podman_resources
    remove_ovs_bridge
    remove_firewall_rules
    remove_kernel_settings
    remove_files

    echo
    log "Cleanup completed"

    # Verification
    if verify_cleanup; then
        echo
        log "HookProbe successfully removed"
        echo
        log "Note: Reboot recommended to fully reset kernel settings"
        echo
    else
        echo
        log_error "Cleanup completed with errors. Manual intervention may be required."
        exit 1
    fi
}

# Run main if executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main
fi
