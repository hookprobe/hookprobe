#!/bin/bash
#
# provision.sh - HookProbe Provision Script
# Version: 5.0
# License: AGPL-3.0 - see LICENSE file
#
# Runs at install and on each boot for auto-repair.
# Responsible for:
# - Installing tools
# - Building XDP programs
# - Verifying NIC capabilities
# - Enabling qsecbit
# - Applying kernel settings
#

set -e
set -u

# ============================================================================
# CONSTANTS
# ============================================================================

readonly HOOKPROBE_BASE="${HOOKPROBE_BASE:-/opt/hookprobe}"
readonly HOOKPROBE_CONFIG="${HOOKPROBE_CONFIG:-/etc/hookprobe}"
readonly LOG_FILE="/var/log/hookprobe/provision.log"

# Source configuration if available
if [ -f "$HOOKPROBE_CONFIG/network-config.sh" ]; then
    source "$HOOKPROBE_CONFIG/network-config.sh"
fi

# ============================================================================
# LOGGING
# ============================================================================

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $*" | tee -a "$LOG_FILE" >&2
}

# ============================================================================
# OS DETECTION
# ============================================================================

detect_os() {
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        case "$ID" in
            rhel|fedora|centos|rocky|almalinux)
                OS_FAMILY="rhel"
                PKG_MGR="dnf"
                ;;
            debian|ubuntu)
                OS_FAMILY="debian"
                PKG_MGR="apt"
                ;;
            *)
                log_error "Unsupported OS: $ID"
                return 1
                ;;
        esac
        log "Detected OS: $PRETTY_NAME ($OS_FAMILY)"
    else
        log_error "Cannot detect OS"
        return 1
    fi
}

# ============================================================================
# NIC DETECTION
# ============================================================================

detect_primary_nic() {
    log "Detecting primary network interface..."

    # Get default route interface
    PRIMARY_NIC=$(ip route | grep default | awk '{print $5}' | head -n1)

    if [ -z "$PRIMARY_NIC" ]; then
        log_error "No primary NIC found"
        return 1
    fi

    log "Primary NIC: $PRIMARY_NIC"

    # Detect driver
    if [ -e "/sys/class/net/$PRIMARY_NIC/device/driver" ]; then
        DRIVER=$(basename "$(readlink "/sys/class/net/$PRIMARY_NIC/device/driver")")
        log "Driver: $DRIVER"
    else
        DRIVER="unknown"
        log "Driver: unknown (virtual interface?)"
    fi

    # Save to config
    echo "PRIMARY_NIC=$PRIMARY_NIC" > "$HOOKPROBE_BASE/config/nic.conf"
    echo "DRIVER=$DRIVER" >> "$HOOKPROBE_BASE/config/nic.conf"
}

detect_xdp_capability() {
    log "Detecting XDP capability..."

    local xdp_drv_supported=false
    local xdp_skb_supported=true  # Always available

    # Check if driver supports XDP-DRV (native mode)
    case "$DRIVER" in
        igb|igc|i40e|ice|ixgbe|mlx4_en|mlx5_core)
            xdp_drv_supported=true
            log "XDP-DRV supported (native mode)"
            ;;
        *)
            log "XDP-DRV not supported, XDP-SKB (generic mode) available"
            ;;
    esac

    # Save to config
    echo "XDP_DRV_SUPPORTED=$xdp_drv_supported" >> "$HOOKPROBE_BASE/config/nic.conf"
    echo "XDP_SKB_SUPPORTED=$xdp_skb_supported" >> "$HOOKPROBE_BASE/config/nic.conf"
}

# ============================================================================
# XDP BUILD
# ============================================================================

build_xdp_program() {
    log "Building XDP program..."

    local xdp_dir="$HOOKPROBE_BASE/xdp"

    if [ ! -d "$xdp_dir" ]; then
        log "XDP directory not found, skipping XDP build"
        return 0
    fi

    # Check if we have the qsecbit XDP program
    if [ -f "$HOOKPROBE_BASE/agent/xdp_manager.py" ]; then
        log "Using qsecbit integrated XDP manager"
        # The XDP program will be loaded by qsecbit-agent
    else
        log "XDP manager not found"
    fi
}

# ============================================================================
# KERNEL SETTINGS
# ============================================================================

apply_kernel_settings() {
    log "Applying kernel settings..."

    # Create sysctl config
    cat > /etc/sysctl.d/99-hookprobe.conf <<'EOF'
# HookProbe Network Performance Settings

# Increase network buffer sizes
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216

# Increase netdev backlog
net.core.netdev_max_backlog = 10000

# Enable TCP window scaling
net.ipv4.tcp_window_scaling = 1

# Increase TCP buffer sizes
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864

# Enable TCP timestamps
net.ipv4.tcp_timestamps = 1

# Enable selective acknowledgments
net.ipv4.tcp_sack = 1

# Increase connection tracking table size
net.netfilter.nf_conntrack_max = 262144

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 8192

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Enable IP forwarding (required for OVS bridge)
net.ipv4.ip_forward = 1
EOF

    # Apply settings
    sysctl -p /etc/sysctl.d/99-hookprobe.conf >/dev/null 2>&1 || log "Some sysctl settings failed to apply"

    log "Kernel settings applied"
}

# ============================================================================
# SERVICE VERIFICATION
# ============================================================================

verify_services() {
    log "Verifying required services..."

    local services=(
        "podman"
        "openvswitch"
    )

    for service in "${services[@]}"; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            log "$service is active"
        else
            log "Starting $service..."
            systemctl start "$service" || log_error "Failed to start $service"
        fi

        if ! systemctl is-enabled "$service" >/dev/null 2>&1; then
            log "Enabling $service..."
            systemctl enable "$service" || log_error "Failed to enable $service"
        fi
    done
}

# ============================================================================
# DIRECTORY VERIFICATION
# ============================================================================

verify_directories() {
    log "Verifying directory structure..."

    local dirs=(
        "$HOOKPROBE_BASE/scripts"
        "$HOOKPROBE_BASE/agent"
        "$HOOKPROBE_BASE/xdp"
        "$HOOKPROBE_BASE/config"
        "$HOOKPROBE_BASE/data"
        "/var/log/hookprobe"
    )

    for dir in "${dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            log "Creating directory: $dir"
            mkdir -p "$dir"
        fi
    done
}

# ============================================================================
# MAIN PROVISIONING
# ============================================================================

main() {
    log "========================================="
    log "HookProbe Provision Started"
    log "========================================="

    # Ensure log directory exists
    mkdir -p "$(dirname "$LOG_FILE")"

    detect_os
    verify_directories
    verify_services
    detect_primary_nic
    detect_xdp_capability
    build_xdp_program
    apply_kernel_settings

    log "========================================="
    log "HookProbe Provision Completed Successfully"
    log "========================================="
}

# Run main if executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main
fi
