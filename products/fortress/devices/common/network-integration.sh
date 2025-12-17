#!/bin/bash
#
# network-integration.sh - Network Module Integration for Fortress Setup
# Part of HookProbe Fortress - Small Business Security Gateway
#
# This module integrates the new network detection and configuration
# components with the main setup.sh script.
#
# Usage:
#   source devices/common/network-integration.sh
#   network_integration_init
#
# Version: 1.0.0
# License: AGPL-3.0
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Module paths
NETWORK_DETECTOR="$SCRIPT_DIR/network-interface-detector.sh"
HOSTAPD_GENERATOR="$SCRIPT_DIR/hostapd-generator.sh"
WIFI_MANAGER="$SCRIPT_DIR/wifi-manager.sh"
LTE_MANAGER="$SCRIPT_DIR/lte-manager.sh"
BRIDGE_MANAGER="$SCRIPT_DIR/bridge-manager.sh"
VALIDATOR="$SCRIPT_DIR/validate-network.sh"

# Colors (if not already defined)
RED="${RED:-\033[0;31m}"
GREEN="${GREEN:-\033[0;32m}"
YELLOW="${YELLOW:-\033[1;33m}"
CYAN="${CYAN:-\033[0;36m}"
NC="${NC:-\033[0m}"

# Logging (use existing functions if defined, otherwise define)
if ! declare -f log_info &>/dev/null; then
    log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
    log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
    log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
    log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }
fi

# ============================================================
# INITIALIZATION
# ============================================================

network_integration_init() {
    # Initialize network integration module
    #
    # This function:
    #   1. Checks for required modules
    #   2. Sources network detector
    #   3. Runs interface detection
    #   4. Exports results for setup.sh
    #
    # Set NET_QUIET_MODE=true before calling to suppress verbose output
    # Useful for re-detection after package installation

    [ "$NET_QUIET_MODE" = "true" ] || log_step "Initializing network integration..."

    # Check for network detector
    if [ ! -x "$NETWORK_DETECTOR" ]; then
        log_warn "Network detector not found: $NETWORK_DETECTOR"
        log_warn "Falling back to legacy detection"
        return 1
    fi

    # Source and run network detector (respects NET_QUIET_MODE)
    source "$NETWORK_DETECTOR"
    detect_all_interfaces

    # Export results in format expected by setup.sh
    export_for_setup

    return 0
}

export_for_setup() {
    # Export detected interfaces in format compatible with setup.sh
    #
    # Maps new variable names to legacy setup.sh variable names

    # Ethernet interfaces
    export ETH_INTERFACES="$NET_ETH_INTERFACES"
    export ETH_COUNT="$NET_ETH_COUNT"

    # WAN/LAN assignment
    export WAN_INTERFACE="$NET_WAN_IFACE"
    export WAN_PRESERVED="$NET_WAN_PRESERVED"  # Flag: WAN should not be modified
    export LAN_INTERFACES="$NET_LAN_IFACES"

    # WiFi interfaces
    export WIFI_INTERFACES="$NET_WIFI_INTERFACES"
    export WIFI_COUNT="$NET_WIFI_COUNT"

    # WWAN/LTE
    export WWAN_INTERFACES="$NET_WWAN_INTERFACES"
    export WWAN_COUNT="$NET_WWAN_COUNT"
    export LTE_INTERFACE="$NET_WWAN_IFACE"
    export MODEM_CTRL_DEVICE="$NET_WWAN_CONTROL"

    # For device profile compatibility
    export FORTRESS_WAN_IFACE="$NET_WAN_IFACE"
    export FORTRESS_LAN_IFACES="$NET_LAN_IFACES"
    export FORTRESS_WIFI_IFACE="${NET_WIFI_24GHZ_IFACE:-$NET_WIFI_5GHZ_IFACE}"
    export FORTRESS_LTE_IFACE="$NET_WWAN_IFACE"

    # WiFi configuration mode
    export WIFI_CONFIG_MODE="$NET_WIFI_CONFIG_MODE"
    export WIFI_24GHZ_IFACE="$NET_WIFI_24GHZ_IFACE"
    export WIFI_5GHZ_IFACE="$NET_WIFI_5GHZ_IFACE"

    # Check VAP support
    if [ -n "$WIFI_INTERFACES" ]; then
        WIFI_VAP_SUPPORT=false
        for iface in $WIFI_INTERFACES; do
            local iface_upper="${iface^^}"
            local has_vap
            eval "has_vap=\$NET_WIFI_${iface_upper}_VAP"
            if [ "$has_vap" = "true" ]; then
                WIFI_VAP_SUPPORT=true
                break
            fi
        done
        export WIFI_VAP_SUPPORT
    fi

    [ "$NET_QUIET_MODE" = "true" ] || log_info "Exported interface configuration for setup.sh"
}

# ============================================================
# DUAL-BAND WIFI SETUP
# ============================================================

setup_dual_band_wifi() {
    # Set up dual-band WiFi using the new hostapd generator
    #
    # Args:
    #   $1 - SSID
    #   $2 - Password
    #   $3 - Bridge name (optional)
    #
    # This function replaces the single-band setup_wifi_ap in setup.sh

    local ssid="${1:-HookProbe-Fortress}"
    local password="$2"
    local bridge="${3:-br-lan}"

    [ -z "$password" ] && { log_error "WiFi password required"; return 1; }

    log_step "Setting up dual-band WiFi..."

    # Check for hostapd generator
    if [ ! -x "$HOSTAPD_GENERATOR" ]; then
        log_warn "Hostapd generator not found, using legacy setup"
        return 1
    fi

    # Ensure network state is loaded
    if [ -z "$NET_WIFI_CONFIG_MODE" ]; then
        if [ -f "/var/lib/fortress/network-interfaces.conf" ]; then
            source "/var/lib/fortress/network-interfaces.conf"
        else
            log_error "Network interfaces not detected. Run network_integration_init first."
            return 1
        fi
    fi

    # Prepare WiFi interfaces (stop wpa_supplicant, set to AP mode)
    prepare_wifi_interfaces

    # Generate hostapd configurations
    "$HOSTAPD_GENERATOR" configure "$ssid" "$password" "$bridge"

    # Create systemd services for WiFi
    create_wifi_services

    log_info "Dual-band WiFi configuration complete"
    log_info "  2.4GHz: ${NET_WIFI_24GHZ_IFACE:-not configured}"
    log_info "  5GHz:   ${NET_WIFI_5GHZ_IFACE:-not configured}"
    log_info "  Mode:   ${NET_WIFI_CONFIG_MODE:-unknown}"

    return 0
}

prepare_wifi_interfaces() {
    # Prepare WiFi interfaces for AP mode
    #
    # - Stop wpa_supplicant
    # - Unblock rfkill
    # - Set NetworkManager to ignore AP interfaces

    log_info "Preparing WiFi interfaces for AP mode..."

    # Unblock WiFi
    rfkill unblock wifi 2>/dev/null || true

    # Stop wpa_supplicant on AP interfaces
    for iface in $NET_WIFI_24GHZ_IFACE $NET_WIFI_5GHZ_IFACE; do
        [ -z "$iface" ] && continue

        # Kill wpa_supplicant
        wpa_cli -i "$iface" terminate 2>/dev/null || true
        pkill -f "wpa_supplicant.*$iface" 2>/dev/null || true

        # Disable wpa_supplicant service
        systemctl stop wpa_supplicant@"$iface" 2>/dev/null || true
        systemctl disable wpa_supplicant@"$iface" 2>/dev/null || true

        log_info "  Prepared: $iface"
    done

    # Configure NetworkManager to ignore AP interfaces
    if [ -d /etc/NetworkManager/conf.d ]; then
        local unmanaged_list=""
        for iface in $NET_WIFI_24GHZ_IFACE $NET_WIFI_5GHZ_IFACE; do
            [ -n "$iface" ] && unmanaged_list="${unmanaged_list}interface-name:$iface;"
        done

        if [ -n "$unmanaged_list" ]; then
            cat > /etc/NetworkManager/conf.d/fortress-wifi.conf << EOF
# HookProbe Fortress: Let hostapd manage WiFi AP
[keyfile]
unmanaged-devices=${unmanaged_list}br*;ovs-*;
EOF
            # Reload NetworkManager
            systemctl reload NetworkManager 2>/dev/null || true
        fi
    fi
}

create_wifi_services() {
    # Create systemd services for WiFi APs
    #
    # Creates separate services for 2.4GHz and 5GHz if available

    local ovs_bridge="${OVS_BRIDGE_NAME:-fortress}"

    # 2.4GHz service
    if [ -n "$NET_WIFI_24GHZ_IFACE" ] && [ -f /etc/hostapd/hostapd-24ghz.conf ]; then
        cat > /etc/systemd/system/fortress-hostapd-24ghz.service << EOF
[Unit]
Description=HookProbe Fortress - 2.4GHz WiFi Access Point
After=network.target openvswitch-switch.service
Wants=network.target
Requires=openvswitch-switch.service

[Service]
Type=forking
PIDFile=/run/hostapd-24ghz.pid
ExecStartPre=/bin/sleep 2
ExecStartPre=-/sbin/ip link set ${NET_WIFI_24GHZ_IFACE} up
ExecStart=/usr/sbin/hostapd -B -P /run/hostapd-24ghz.pid /etc/hostapd/hostapd-24ghz.conf
ExecStartPost=/bin/sleep 1
ExecStartPost=-/usr/bin/ovs-vsctl --may-exist add-port ${ovs_bridge} ${NET_WIFI_24GHZ_IFACE}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable fortress-hostapd-24ghz
        log_info "Created service: fortress-hostapd-24ghz"
    fi

    # 5GHz service
    if [ -n "$NET_WIFI_5GHZ_IFACE" ] && [ -f /etc/hostapd/hostapd-5ghz.conf ]; then
        # Only create separate service if different interface
        if [ "$NET_WIFI_5GHZ_IFACE" != "$NET_WIFI_24GHZ_IFACE" ]; then
            cat > /etc/systemd/system/fortress-hostapd-5ghz.service << EOF
[Unit]
Description=HookProbe Fortress - 5GHz WiFi Access Point
After=network.target openvswitch-switch.service
Wants=network.target
Requires=openvswitch-switch.service

[Service]
Type=forking
PIDFile=/run/hostapd-5ghz.pid
ExecStartPre=/bin/sleep 2
ExecStartPre=-/sbin/ip link set ${NET_WIFI_5GHZ_IFACE} up
ExecStart=/usr/sbin/hostapd -B -P /run/hostapd-5ghz.pid /etc/hostapd/hostapd-5ghz.conf
ExecStartPost=/bin/sleep 1
ExecStartPost=-/usr/bin/ovs-vsctl --may-exist add-port ${ovs_bridge} ${NET_WIFI_5GHZ_IFACE}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable fortress-hostapd-5ghz
            log_info "Created service: fortress-hostapd-5ghz"
        else
            log_info "Single dual-band radio - using 2.4GHz service for both bands"
        fi
    fi

    # Create combined service for backward compatibility
    cat > /etc/systemd/system/fortress-hostapd.service << EOF
[Unit]
Description=HookProbe Fortress - WiFi Access Points (All Bands)
After=network.target openvswitch-switch.service
Wants=fortress-hostapd-24ghz.service fortress-hostapd-5ghz.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable fortress-hostapd
}

# ============================================================
# LTE/WWAN SETUP
# ============================================================

setup_lte_connection() {
    # Set up LTE/WWAN connection using nmcli
    #
    # Args:
    #   $1 - APN name
    #   $2 - Auth type (none, pap, chap, mschapv2)
    #   $3 - Username (optional)
    #   $4 - Password (optional)

    local apn="$1"
    local auth="${2:-none}"
    local username="$3"
    local password="$4"

    [ -z "$apn" ] && { log_error "APN required"; return 1; }

    log_step "Setting up LTE connection..."

    if [ -z "$NET_WWAN_CONTROL" ]; then
        log_warn "No WWAN control device detected"
        log_warn "Make sure LTE modem is connected"
        return 1
    fi

    # Use network detector's configure function
    configure_wwan_nmcli "$apn" "$auth" "$username" "$password"

    return $?
}

setup_wan_failover() {
    # Configure WAN failover from Ethernet to LTE using route metrics
    #
    # This function sets up automatic failover:
    #   - Primary WAN (Ethernet): metric 100 (preferred)
    #   - LTE backup: metric 200 (fallback)
    #
    # Args:
    #   $1 - Primary WAN interface
    #   $2 - LTE interface (optional, auto-detected)

    local primary_wan="${1:-$NET_WAN_IFACE}"
    local lte_iface="${2:-$NET_WWAN_IFACE}"

    [ -z "$primary_wan" ] && { log_error "[WAN] Primary WAN interface required"; return 1; }
    [ -z "$lte_iface" ] && { log_warn "[WAN] No LTE interface for failover"; return 1; }

    log_step "[WAN] Configuring metric-based failover..."
    log_info "[WAN]   Primary: $primary_wan (metric 100)"
    log_info "[WAN]   Backup:  $lte_iface (metric 200)"

    # Method 1: Use LTE manager if available (call directly, not source)
    if [ -x "$LTE_MANAGER" ]; then
        "$LTE_MANAGER" setup-failover "$primary_wan" "$lte_iface"
        return $?
    fi

    # Method 2: Configure directly via NetworkManager (fallback)
    if command -v nmcli &>/dev/null; then
        log_info "[WAN] Using NetworkManager for failover configuration"

        # Configure primary WAN metric
        local primary_con
        primary_con=$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | grep ":${primary_wan}$" | cut -d: -f1 | head -1)
        if [ -n "$primary_con" ]; then
            nmcli con mod "$primary_con" ipv4.route-metric 100 2>/dev/null || true
            log_info "[WAN]   Set $primary_con metric to 100"
        fi

        # Configure LTE metric
        local lte_con="fortress-lte"
        if nmcli con show "$lte_con" &>/dev/null; then
            nmcli con mod "$lte_con" ipv4.route-metric 200 2>/dev/null || true
            log_info "[WAN]   Set $lte_con metric to 200"
        fi

        # Reactivate to apply
        [ -n "$primary_con" ] && nmcli con up "$primary_con" 2>/dev/null || true

        log_info "[WAN] Metric-based failover configured"
        return 0
    fi

    # Method 3: Direct route manipulation (last resort)
    log_info "[WAN] Using direct route manipulation"

    local primary_gw
    primary_gw=$(ip route show dev "$primary_wan" 2>/dev/null | grep "^default" | awk '{print $3}' | head -1)

    if [ -n "$primary_gw" ]; then
        ip route del default via "$primary_gw" dev "$primary_wan" 2>/dev/null || true
        ip route add default via "$primary_gw" dev "$primary_wan" metric 100 2>/dev/null || true
        log_info "[WAN]   Primary route: metric 100"
    fi

    local lte_gw
    lte_gw=$(ip route show dev "$lte_iface" 2>/dev/null | grep "^default" | awk '{print $3}' | head -1)

    if [ -n "$lte_gw" ]; then
        ip route del default via "$lte_gw" dev "$lte_iface" 2>/dev/null || true
        ip route add default via "$lte_gw" dev "$lte_iface" metric 200 2>/dev/null || true
        log_info "[WAN]   LTE route: metric 200"
    fi

    log_info "[WAN] Failover configured"
    return 0
}

# ============================================================
# BRIDGE SETUP
# ============================================================

setup_lan_bridge_auto() {
    # Automatically set up LAN bridge with detected interfaces
    #
    # Uses:
    #   - NET_LAN_IFACES for bridge members
    #   - Excludes NET_WAN_IFACE
    #   - Excludes WiFi interfaces (managed by hostapd)

    log_step "Setting up LAN bridge with detected interfaces..."

    if [ -z "$NET_LAN_IFACES" ]; then
        log_warn "No LAN interfaces detected for bridge"
        return 1
    fi

    log_info "WAN (excluded): ${NET_WAN_IFACE:-none}"
    log_info "LAN (bridged):  $NET_LAN_IFACES"

    # Use bridge manager if available
    if [ -x "$BRIDGE_MANAGER" ]; then
        source "$BRIDGE_MANAGER"
        setup_lan_bridge "$NET_WAN_IFACE" "$NET_WWAN_IFACE"
    else
        # Manual bridge creation
        local bridge_name="${OVS_BRIDGE_NAME:-br-lan}"

        ip link add name "$bridge_name" type bridge 2>/dev/null || true
        ip link set "$bridge_name" up

        for iface in $NET_LAN_IFACES; do
            ip link set "$iface" up
            ip link set "$iface" master "$bridge_name" 2>/dev/null || true
            log_info "  Added $iface to $bridge_name"
        done
    fi

    return 0
}

# ============================================================
# VALIDATION
# ============================================================

validate_network_config() {
    # Run network validation tests
    #
    # Args:
    #   $1 - Test type (all, quick, interfaces, wifi, wwan)

    local test_type="${1:-quick}"

    log_step "Validating network configuration..."

    if [ -x "$VALIDATOR" ]; then
        "$VALIDATOR" "--$test_type"
    else
        log_warn "Validator not found, skipping validation"
        return 1
    fi
}

# ============================================================
# USAGE HELPERS
# ============================================================

show_network_summary() {
    # Display current network configuration summary

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Network Configuration Summary${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}Ethernet:${NC}"
    echo -e "    WAN:          ${NET_WAN_IFACE:-not configured}"
    echo -e "    LAN:          ${NET_LAN_IFACES:-not configured}"
    echo ""
    echo -e "  ${GREEN}WiFi:${NC}"
    echo -e "    Config Mode:  ${NET_WIFI_CONFIG_MODE:-not detected}"
    echo -e "    2.4GHz:       ${NET_WIFI_24GHZ_IFACE:-not available}"
    echo -e "    5GHz:         ${NET_WIFI_5GHZ_IFACE:-not available}"
    echo -e "    VAP Support:  ${WIFI_VAP_SUPPORT:-unknown}"
    echo ""
    echo -e "  ${GREEN}LTE/WWAN:${NC}"
    echo -e "    Interface:    ${NET_WWAN_IFACE:-not detected}"
    echo -e "    Control:      ${NET_WWAN_CONTROL:-not detected}"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# ============================================================
# AUTO-INIT
# ============================================================

# If sourced, make functions available
# If executed directly, run full detection and show summary
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    echo "HookProbe Fortress - Network Integration Module"
    echo ""

    network_integration_init
    show_network_summary

    echo "Available functions:"
    echo "  network_integration_init   - Initialize and detect interfaces"
    echo "  setup_dual_band_wifi       - Configure dual-band WiFi AP"
    echo "  setup_lte_connection       - Configure LTE connection"
    echo "  setup_wan_failover         - Configure WAN failover"
    echo "  setup_lan_bridge_auto      - Set up LAN bridge"
    echo "  validate_network_config    - Run validation tests"
    echo "  show_network_summary       - Show configuration summary"
fi
