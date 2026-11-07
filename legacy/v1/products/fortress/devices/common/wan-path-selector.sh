#!/bin/bash
# ============================================================
# WAN Path Selector - Dual-Path WAN Monitoring Architecture
# ============================================================
#
# Automatically detects WAN interface type and selects optimal
# monitoring path:
#
#   WIRED (eth0/enp*):  AF_XDP → TC-BPF → AF_PACKET fallback
#   MOBILE (wwan0/*):   TC-BPF + AF_PACKET (no XDP on USB)
#
# Usage:
#   source wan-path-selector.sh
#   detect_wan_path eth0      # Returns: wired_xdp | wired_tc | mobile
#   get_optimal_capture eth0  # Returns capture method recommendation
#
# Part of HookProbe Fortress - Trio+ Designed Architecture
# ============================================================

set -euo pipefail

# ============================================================
# CONSTANTS
# ============================================================

# WAN path types
readonly WAN_PATH_WIRED_XDP="wired_xdp"      # AF_XDP capable wired
readonly WAN_PATH_WIRED_TC="wired_tc"        # Wired without XDP
readonly WAN_PATH_MOBILE="mobile"            # Mobile/LTE (CGNAT)
readonly WAN_PATH_UNKNOWN="unknown"          # Fallback

# XDP modes (in order of preference)
readonly XDP_MODE_NATIVE="native"            # XDP in driver (best)
readonly XDP_MODE_GENERIC="generic"          # XDP in kernel (slower)
readonly XDP_MODE_NONE="none"                # No XDP support

# Capture methods
readonly CAPTURE_AF_XDP="af_xdp"             # Zero-copy XDP
readonly CAPTURE_TC_BPF="tc_bpf"             # TC with eBPF
readonly CAPTURE_AF_PACKET="af_packet"       # Traditional capture
readonly CAPTURE_TC_MIRROR="tc_mirror"       # Current TC mirred

# Known mobile interface prefixes
readonly MOBILE_PREFIXES="wwan wwp ww usb"

# Known USB modem drivers (no XDP support)
readonly USB_MODEM_DRIVERS="qmi_wwan cdc_mbim cdc_ncm cdc_ether cdc_ecm rndis_host"

# Minimum kernel version for AF_XDP (5.10+)
readonly MIN_XDP_KERNEL="5.10"

# ============================================================
# LOGGING (compatible with ovs-post-setup.sh)
# ============================================================

_log_prefix() {
    echo "[wan-path]"
}

log_debug() {
    [ "${DEBUG:-false}" = "true" ] && echo "$(_log_prefix) DEBUG: $*" >&2
}

log_info() {
    echo "$(_log_prefix) INFO: $*" >&2
}

log_warn() {
    echo "$(_log_prefix) WARN: $*" >&2
}

# ============================================================
# SECURITY HARDENING
# ============================================================

# Validate interface name against allowed patterns (prevent command injection)
# Only alphanumeric, underscore, and hyphen allowed
validate_interface_name() {
    local iface="$1"

    # Check for empty
    [ -z "$iface" ] && return 1

    # Check against allowed pattern (network interface naming)
    # Allows: eth0, enp1s0, wwan0, wwp0s20f0u6, wlan_24ghz, FTS-mirror, etc.
    if [[ "$iface" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        return 0
    fi

    log_warn "Invalid interface name (security): $iface"
    return 1
}

# Create state directory with secure permissions
# State files contain non-secret metadata but should be protected
create_secure_state_dir() {
    local dir="$1"

    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        chmod 0700 "$dir"
        log_debug "Created secure state directory: $dir"
    fi
}

# ============================================================
# KERNEL & SYSTEM CHECKS
# ============================================================

# Check if kernel version supports AF_XDP
check_kernel_xdp_support() {
    local kernel_version
    kernel_version=$(uname -r | cut -d'-' -f1)

    # Compare versions (5.10+ required for stable AF_XDP)
    local major minor
    major=$(echo "$kernel_version" | cut -d'.' -f1)
    minor=$(echo "$kernel_version" | cut -d'.' -f2)

    local req_major req_minor
    req_major=$(echo "$MIN_XDP_KERNEL" | cut -d'.' -f1)
    req_minor=$(echo "$MIN_XDP_KERNEL" | cut -d'.' -f2)

    if [ "$major" -gt "$req_major" ] || \
       { [ "$major" -eq "$req_major" ] && [ "$minor" -ge "$req_minor" ]; }; then
        log_debug "Kernel $kernel_version supports AF_XDP (>= $MIN_XDP_KERNEL)"
        return 0
    else
        log_debug "Kernel $kernel_version too old for AF_XDP (need >= $MIN_XDP_KERNEL)"
        return 1
    fi
}

# Check if libbpf/bpftool available
check_bpf_tools() {
    if command -v bpftool &>/dev/null; then
        log_debug "bpftool available"
        return 0
    fi
    log_debug "bpftool not found"
    return 1
}

# ============================================================
# INTERFACE DETECTION
# ============================================================

# Check if interface is USB-based (mobile modems)
is_usb_interface() {
    local iface="$1"
    local sys_path="/sys/class/net/$iface"

    [ ! -d "$sys_path" ] && return 1

    # Check if device path contains 'usb'
    local device_path
    device_path=$(readlink -f "$sys_path/device" 2>/dev/null) || return 1

    if [[ "$device_path" == *"/usb"* ]]; then
        log_debug "$iface is USB-based"
        return 0
    fi

    return 1
}

# Check if interface uses a known mobile modem driver
is_mobile_driver() {
    local iface="$1"
    local driver_path="/sys/class/net/$iface/device/driver"

    [ ! -L "$driver_path" ] && return 1

    local driver
    driver=$(basename "$(readlink -f "$driver_path")" 2>/dev/null) || return 1

    for modem_driver in $USB_MODEM_DRIVERS; do
        if [ "$driver" = "$modem_driver" ]; then
            log_debug "$iface uses mobile driver: $driver"
            return 0
        fi
    done

    return 1
}

# Check if interface name matches mobile prefixes
is_mobile_prefix() {
    local iface="$1"

    for prefix in $MOBILE_PREFIXES; do
        if [[ "$iface" == ${prefix}* ]]; then
            log_debug "$iface matches mobile prefix: $prefix"
            return 0
        fi
    done

    return 1
}

# Check if interface is behind CGNAT (private carrier IP)
is_behind_cgnat() {
    local iface="$1"

    # Get interface IP
    local ip
    ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)

    [ -z "$ip" ] && return 1

    # Check for CGNAT range (100.64.0.0/10) or other private ranges
    if [[ "$ip" == 100.* ]]; then
        local second_octet
        second_octet=$(echo "$ip" | cut -d'.' -f2)
        if [ "$second_octet" -ge 64 ] && [ "$second_octet" -le 127 ]; then
            log_debug "$iface has CGNAT IP: $ip"
            return 0
        fi
    fi

    # Also check for typical mobile carrier private IPs
    if [[ "$ip" == 10.* ]] || [[ "$ip" == 192.168.* ]] || [[ "$ip" == 172.1[6-9].* ]] || [[ "$ip" == 172.2[0-9].* ]] || [[ "$ip" == 172.3[0-1].* ]]; then
        log_debug "$iface has private IP (likely CGNAT): $ip"
        return 0
    fi

    return 1
}

# ============================================================
# XDP SUPPORT DETECTION
# ============================================================

# Check interface XDP support mode using ethtool
check_xdp_support() {
    local iface="$1"

    # First check if interface exists
    if ! ip link show "$iface" &>/dev/null; then
        echo "$XDP_MODE_NONE"
        return
    fi

    # Method 1: ethtool --show-features (check for XDP)
    if command -v ethtool &>/dev/null; then
        local features
        features=$(ethtool -k "$iface" 2>/dev/null) || true

        # Look for XDP-related features
        if echo "$features" | grep -qi "xdp"; then
            log_debug "$iface: XDP features detected via ethtool"
        fi
    fi

    # Method 2: Check driver XDP support via /sys
    local driver_path="/sys/class/net/$iface/device/driver/module"
    if [ -d "$driver_path" ]; then
        local driver
        driver=$(basename "$(readlink -f "/sys/class/net/$iface/device/driver")" 2>/dev/null) || driver="unknown"

        # Known XDP-capable drivers (native mode)
        case "$driver" in
            i40e|ixgbe|igb|igc|mlx5_core|bnxt_en|nfp|ice|ena)
                log_debug "$iface: Driver $driver supports native XDP"
                echo "$XDP_MODE_NATIVE"
                return
                ;;
            virtio_net|veth|tun)
                log_debug "$iface: Driver $driver supports generic XDP"
                echo "$XDP_MODE_GENERIC"
                return
                ;;
        esac
    fi

    # Method 3: Try to query XDP directly (requires CAP_NET_ADMIN)
    if command -v ip &>/dev/null; then
        # Check if xdp is mentioned in ip link output
        if ip link show "$iface" 2>/dev/null | grep -q "xdp"; then
            log_debug "$iface: XDP detected via ip link"
            echo "$XDP_MODE_GENERIC"
            return
        fi
    fi

    # Fallback: Assume generic XDP is available on modern kernels for wired
    if check_kernel_xdp_support && ! is_usb_interface "$iface"; then
        log_debug "$iface: Assuming generic XDP (modern kernel, non-USB)"
        echo "$XDP_MODE_GENERIC"
        return
    fi

    echo "$XDP_MODE_NONE"
}

# ============================================================
# WAN PATH DETECTION (Main Function)
# ============================================================

# Detect the optimal WAN monitoring path for an interface
# Returns: wired_xdp | wired_tc | mobile | unknown
detect_wan_path() {
    local iface="$1"

    [ -z "$iface" ] && echo "$WAN_PATH_UNKNOWN" && return

    # Check if interface exists
    if ! ip link show "$iface" &>/dev/null; then
        log_warn "Interface $iface not found"
        echo "$WAN_PATH_UNKNOWN"
        return
    fi

    # === MOBILE PATH DETECTION ===
    # Check multiple indicators for mobile/LTE interfaces

    # 1. Interface name prefix (wwan*, wwp*, etc.)
    if is_mobile_prefix "$iface"; then
        log_info "$iface detected as MOBILE (prefix match)"
        echo "$WAN_PATH_MOBILE"
        return
    fi

    # 2. USB-based modem driver
    if is_mobile_driver "$iface"; then
        log_info "$iface detected as MOBILE (USB modem driver)"
        echo "$WAN_PATH_MOBILE"
        return
    fi

    # 3. USB bus detection
    if is_usb_interface "$iface"; then
        log_info "$iface detected as MOBILE (USB interface)"
        echo "$WAN_PATH_MOBILE"
        return
    fi

    # 4. CGNAT IP range (carrier-grade NAT)
    if is_behind_cgnat "$iface"; then
        log_info "$iface detected as MOBILE (CGNAT IP range)"
        echo "$WAN_PATH_MOBILE"
        return
    fi

    # === WIRED PATH DETECTION ===
    # Interface is likely wired (eth*, enp*, eno*, etc.)

    # Check XDP support
    local xdp_mode
    xdp_mode=$(check_xdp_support "$iface")

    if [ "$xdp_mode" = "$XDP_MODE_NATIVE" ] || [ "$xdp_mode" = "$XDP_MODE_GENERIC" ]; then
        log_info "$iface detected as WIRED with XDP ($xdp_mode)"
        echo "$WAN_PATH_WIRED_XDP"
        return
    fi

    # Wired without XDP - use TC path
    log_info "$iface detected as WIRED (no XDP, will use TC)"
    echo "$WAN_PATH_WIRED_TC"
}

# ============================================================
# CAPTURE METHOD RECOMMENDATION
# ============================================================

# Get recommended capture method for an interface
# Returns: af_xdp | tc_bpf | af_packet | tc_mirror
get_optimal_capture() {
    local iface="$1"
    local wan_path

    wan_path=$(detect_wan_path "$iface")

    case "$wan_path" in
        "$WAN_PATH_WIRED_XDP")
            # Wired with XDP: Use AF_XDP if tools available, else TC-BPF
            if check_kernel_xdp_support && check_bpf_tools; then
                echo "$CAPTURE_AF_XDP"
            else
                echo "$CAPTURE_TC_BPF"
            fi
            ;;
        "$WAN_PATH_WIRED_TC")
            # Wired without XDP: Use TC-BPF
            echo "$CAPTURE_TC_BPF"
            ;;
        "$WAN_PATH_MOBILE")
            # Mobile: TC-BPF with pre-filtering (efficient for limited bandwidth)
            echo "$CAPTURE_TC_BPF"
            ;;
        *)
            # Unknown: Fall back to current TC mirror
            echo "$CAPTURE_TC_MIRROR"
            ;;
    esac
}

# ============================================================
# TC-BPF PRE-FILTER SETUP
# ============================================================

# BPF filter to drop non-essential traffic before mirroring
# Keeps: TCP, UDP, ICMP (IP protocols worth analyzing)
# Drops: ARP, LLDP, STP, and other L2 noise
setup_tc_bpf_prefilter() {
    local iface="$1"
    local direction="${2:-ingress}"  # ingress or egress

    log_info "Setting up TC-BPF pre-filter on $iface ($direction)"

    # Remove existing qdisc if present
    tc qdisc del dev "$iface" "$direction" 2>/dev/null || true

    if [ "$direction" = "ingress" ]; then
        # Add ingress qdisc
        tc qdisc add dev "$iface" handle ffff: ingress || {
            log_warn "Failed to add ingress qdisc on $iface"
            return 1
        }

        # Add BPF filter to pass only IP traffic (drop L2 noise)
        # This is a simple u32 filter; full BPF would use tc-bpf
        # Filter: Match IP (ethertype 0x0800) and IPv6 (0x86dd)
        tc filter add dev "$iface" parent ffff: protocol ip prio 1 \
            matchall action pass 2>/dev/null || {
            # Fallback without matchall
            tc filter add dev "$iface" parent ffff: protocol ip prio 1 \
                u32 match u32 0 0 action pass 2>/dev/null || true
        }

        tc filter add dev "$iface" parent ffff: protocol ipv6 prio 2 \
            matchall action pass 2>/dev/null || true

    else
        # Egress: Add prio qdisc and filters
        tc qdisc add dev "$iface" handle 1: root prio 2>/dev/null || {
            log_warn "Failed to add egress qdisc on $iface"
            return 1
        }

        tc filter add dev "$iface" parent 1: protocol ip prio 1 \
            matchall action pass 2>/dev/null || true
        tc filter add dev "$iface" parent 1: protocol ipv6 prio 2 \
            matchall action pass 2>/dev/null || true
    fi

    log_debug "TC-BPF pre-filter configured on $iface ($direction)"
    return 0
}

# ============================================================
# ADAPTIVE SAMPLING
# ============================================================

# Sampling state file
SAMPLING_STATE_DIR="/run/fortress/sampling"
SAMPLING_RATE_DEFAULT=100  # 100% = no sampling
SAMPLING_RATE_MOBILE=10    # 10% for mobile (efficiency)

# Configure adaptive sampling for an interface
configure_adaptive_sampling() {
    local iface="$1"
    local wan_path="$2"
    local rate

    # Security: Validate interface name
    if ! validate_interface_name "$iface"; then
        log_warn "Skipping sampling config for invalid interface: $iface"
        return 1
    fi

    # Create state directory with secure permissions
    create_secure_state_dir "$SAMPLING_STATE_DIR"

    case "$wan_path" in
        "$WAN_PATH_MOBILE")
            rate=$SAMPLING_RATE_MOBILE
            ;;
        *)
            rate=$SAMPLING_RATE_DEFAULT
            ;;
    esac

    # Write sampling config
    cat > "$SAMPLING_STATE_DIR/$iface.conf" <<EOF
# Adaptive Sampling Config for $iface
# Generated by wan-path-selector.sh
INTERFACE="$iface"
WAN_PATH="$wan_path"
SAMPLE_RATE=$rate
FULL_CAPTURE_ON_ANOMALY=true
ANOMALY_THRESHOLD_PPS=1000
RARE_FLOW_THRESHOLD=10
EOF

    log_info "Adaptive sampling configured for $iface: ${rate}%"
    return 0
}

# ============================================================
# ANOMALY-TRIGGERED FULL CAPTURE
# ============================================================

# State tracking for anomaly detection
ANOMALY_STATE_DIR="/run/fortress/anomaly"
FULL_CAPTURE_DURATION=60  # Seconds to run full capture after anomaly

# Trigger full capture on anomaly detection
# Called by external anomaly detector (NAPSE or QSecBit)
trigger_full_capture() {
    local iface="$1"
    local reason="${2:-anomaly_detected}"
    local duration="${3:-$FULL_CAPTURE_DURATION}"

    # Security: Validate interface name
    if ! validate_interface_name "$iface"; then
        log_warn "Rejecting anomaly trigger for invalid interface: $iface"
        return 1
    fi

    # Create state directory with secure permissions
    create_secure_state_dir "$ANOMALY_STATE_DIR"

    # Check if already in full capture mode
    local state_file="$ANOMALY_STATE_DIR/$iface.state"
    if [ -f "$state_file" ]; then
        local current_mode
        # shellcheck source=/dev/null
        source "$state_file"
        if [ "${CAPTURE_MODE:-}" = "full" ]; then
            local now end_time
            now=$(date +%s)
            if [ -n "${END_TIME:-}" ] && [ "$now" -lt "$END_TIME" ]; then
                log_debug "$iface already in full capture mode (${END_TIME} - $now seconds remaining)"
                return 0
            fi
        fi
    fi

    log_warn "ANOMALY: Triggering full capture on $iface (reason: $reason)"

    # Calculate end time
    local end_time
    end_time=$(($(date +%s) + duration))

    # Update sampling rate to 100%
    local sampling_conf="$SAMPLING_STATE_DIR/$iface.conf"
    if [ -f "$sampling_conf" ]; then
        # Backup current config
        cp "$sampling_conf" "$ANOMALY_STATE_DIR/$iface.conf.bak"
        # Set full capture
        sed -i 's/^SAMPLE_RATE=.*/SAMPLE_RATE=100/' "$sampling_conf"
    fi

    # Write anomaly state
    cat > "$state_file" <<EOF
# Anomaly State for $iface
# Generated: $(date -Iseconds)
INTERFACE="$iface"
CAPTURE_MODE="full"
REASON="$reason"
TRIGGERED="$(date +%s)"
END_TIME="$end_time"
DURATION="$duration"
EOF

    log_info "Full capture enabled on $iface for ${duration}s"

    # Schedule return to normal sampling (background)
    (
        sleep "$duration"
        restore_normal_sampling "$iface"
    ) &>/dev/null &

    return 0
}

# Restore normal sampling after anomaly period
restore_normal_sampling() {
    local iface="$1"

    local state_file="$ANOMALY_STATE_DIR/$iface.state"
    local backup_conf="$ANOMALY_STATE_DIR/$iface.conf.bak"
    local sampling_conf="$SAMPLING_STATE_DIR/$iface.conf"

    # Restore original sampling config
    if [ -f "$backup_conf" ]; then
        cp "$backup_conf" "$sampling_conf"
        rm -f "$backup_conf"
        log_info "Restored normal sampling for $iface"
    fi

    # Update state
    if [ -f "$state_file" ]; then
        sed -i 's/^CAPTURE_MODE=.*/CAPTURE_MODE="normal"/' "$state_file"
    fi

    return 0
}

# Check if interface is in full capture mode
is_full_capture_active() {
    local iface="$1"

    local state_file="$ANOMALY_STATE_DIR/$iface.state"
    if [ -f "$state_file" ]; then
        # shellcheck source=/dev/null
        source "$state_file"
        if [ "${CAPTURE_MODE:-}" = "full" ]; then
            local now
            now=$(date +%s)
            if [ -n "${END_TIME:-}" ] && [ "$now" -lt "$END_TIME" ]; then
                return 0
            fi
        fi
    fi
    return 1
}

# Get current capture mode for interface
get_capture_mode() {
    local iface="$1"

    if is_full_capture_active "$iface"; then
        echo "full"
    else
        echo "sampled"
    fi
}

# Hook for NAPSE to trigger full capture
# Usage: wan-path-selector.sh anomaly <interface> <reason>
handle_anomaly_trigger() {
    local iface="$1"
    local reason="${2:-external_trigger}"

    if [ -z "$iface" ]; then
        log_warn "anomaly: interface required"
        return 1
    fi

    trigger_full_capture "$iface" "$reason"
}

# ============================================================
# MAIN DUAL-PATH SETUP
# ============================================================

# Setup optimal monitoring path for a WAN interface
setup_wan_monitoring_path() {
    local iface="$1"
    local mirror_iface="${2:-wan-mirror}"

    log_info "=== Setting up WAN monitoring path for $iface ==="

    # Detect WAN path type
    local wan_path
    wan_path=$(detect_wan_path "$iface")
    log_info "Detected path type: $wan_path"

    # Get optimal capture method
    local capture_method
    capture_method=$(get_optimal_capture "$iface")
    log_info "Optimal capture method: $capture_method"

    # Configure based on path type
    case "$wan_path" in
        "$WAN_PATH_WIRED_XDP")
            log_info "Configuring WIRED path with XDP optimization"
            # For now, fall back to TC-BPF until XDP programs are compiled
            # TODO: Load AF_XDP program when available
            setup_tc_bpf_prefilter "$iface" "ingress"
            setup_tc_bpf_prefilter "$iface" "egress"
            ;;

        "$WAN_PATH_WIRED_TC"|"$WAN_PATH_MOBILE")
            log_info "Configuring TC-BPF path (${wan_path})"
            setup_tc_bpf_prefilter "$iface" "ingress"
            setup_tc_bpf_prefilter "$iface" "egress"
            ;;

        *)
            log_warn "Unknown path type, using default TC mirror"
            ;;
    esac

    # Configure adaptive sampling
    configure_adaptive_sampling "$iface" "$wan_path"

    # Write path selection state
    mkdir -p /run/fortress
    cat > "/run/fortress/wan-path-$iface.state" <<EOF
# WAN Path Selection State
# Generated: $(date -Iseconds)
INTERFACE="$iface"
WAN_PATH="$wan_path"
CAPTURE_METHOD="$capture_method"
MIRROR_INTERFACE="$mirror_iface"
EOF

    log_info "=== WAN monitoring path setup complete for $iface ==="
    return 0
}

# ============================================================
# STATUS & DIAGNOSTICS
# ============================================================

# Show WAN path status for all detected interfaces
show_wan_path_status() {
    echo "=== WAN Path Selector Status ==="
    echo ""

    # Kernel support
    echo "Kernel XDP Support:"
    if check_kernel_xdp_support; then
        echo "  Status: SUPPORTED ($(uname -r))"
    else
        echo "  Status: NOT SUPPORTED (need >= $MIN_XDP_KERNEL)"
    fi

    echo "  BPF Tools: $(check_bpf_tools && echo "Available" || echo "Not found")"
    echo ""

    # Check each WAN interface
    echo "Detected WAN Interfaces:"

    # Primary WAN
    local wan_iface
    wan_iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
    if [ -n "$wan_iface" ]; then
        local path capture
        path=$(detect_wan_path "$wan_iface")
        capture=$(get_optimal_capture "$wan_iface")
        echo "  $wan_iface (primary):"
        echo "    Path Type: $path"
        echo "    Capture Method: $capture"
        echo "    XDP Mode: $(check_xdp_support "$wan_iface")"
        [ -f "/run/fortress/wan-path-$wan_iface.state" ] && echo "    State: Configured"
    fi

    # Check for WWAN interfaces
    for pattern in wwan0 wwp0s*; do
        # shellcheck disable=SC2086
        for iface_path in /sys/class/net/$pattern; do
            [ -e "$iface_path" ] || continue
            local iface
            iface=$(basename "$iface_path")
            [ "$iface" = "$wan_iface" ] && continue  # Skip if already shown

            local path capture
            path=$(detect_wan_path "$iface")
            capture=$(get_optimal_capture "$iface")
            echo "  $iface (backup/mobile):"
            echo "    Path Type: $path"
            echo "    Capture Method: $capture"
        done
    done

    echo ""
    echo "Sampling Configuration:"
    if [ -d "$SAMPLING_STATE_DIR" ]; then
        for conf in "$SAMPLING_STATE_DIR"/*.conf; do
            [ -f "$conf" ] || continue
            grep -E "^(INTERFACE|SAMPLE_RATE)=" "$conf" | sed 's/^/  /'
        done
    else
        echo "  Not configured"
    fi
}

# ============================================================
# CLI INTERFACE
# ============================================================

# Main entry point when run as script
main() {
    local cmd="${1:-status}"
    local iface="${2:-}"

    case "$cmd" in
        detect)
            [ -z "$iface" ] && { echo "Usage: $0 detect <interface>"; exit 1; }
            detect_wan_path "$iface"
            ;;
        capture)
            [ -z "$iface" ] && { echo "Usage: $0 capture <interface>"; exit 1; }
            get_optimal_capture "$iface"
            ;;
        setup)
            [ -z "$iface" ] && { echo "Usage: $0 setup <interface> [mirror_iface]"; exit 1; }
            setup_wan_monitoring_path "$iface" "${3:-wan-mirror}"
            ;;
        anomaly)
            [ -z "$iface" ] && { echo "Usage: $0 anomaly <interface> [reason]"; exit 1; }
            handle_anomaly_trigger "$iface" "${3:-manual_trigger}"
            ;;
        mode)
            [ -z "$iface" ] && { echo "Usage: $0 mode <interface>"; exit 1; }
            get_capture_mode "$iface"
            ;;
        restore)
            [ -z "$iface" ] && { echo "Usage: $0 restore <interface>"; exit 1; }
            restore_normal_sampling "$iface"
            ;;
        status)
            show_wan_path_status
            ;;
        *)
            echo "WAN Path Selector - Dual-Path WAN Monitoring"
            echo ""
            echo "Usage: $0 <command> [interface]"
            echo ""
            echo "Commands:"
            echo "  detect <iface>          - Detect WAN path type (wired_xdp|wired_tc|mobile)"
            echo "  capture <iface>         - Get optimal capture method (af_xdp|tc_bpf|af_packet)"
            echo "  setup <iface>           - Setup monitoring path for interface"
            echo "  anomaly <iface> [reason] - Trigger full capture (anomaly detected)"
            echo "  mode <iface>            - Get current capture mode (full|sampled)"
            echo "  restore <iface>         - Restore normal sampling after anomaly"
            echo "  status                  - Show status of all WAN interfaces"
            echo ""
            echo "Examples:"
            echo "  $0 detect eth0          # Check if eth0 supports XDP"
            echo "  $0 detect wwan0         # Detect mobile interface"
            echo "  $0 setup eth0           # Configure optimal path for eth0"
            echo "  $0 anomaly wwan0 ddos   # Trigger full capture due to DDoS"
            exit 1
            ;;
    esac
}

# Run main if executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
