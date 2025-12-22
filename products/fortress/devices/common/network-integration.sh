#!/bin/bash
#
# network-integration.sh - Network Module Integration for Fortress Setup
# Part of HookProbe Fortress - Small Business Security Gateway
#
# This module integrates the new network detection and configuration
# components with the main install-container.sh script.
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
    #   4. Exports results for install-container.sh
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

    # Export results in format expected by install-container.sh
    export_for_setup

    return 0
}

export_for_setup() {
    # Export detected interfaces in format compatible with install-container.sh
    #
    # Maps new variable names to legacy variable names

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

    [ "$NET_QUIET_MODE" = "true" ] || log_info "Exported interface configuration for install-container.sh"
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
    # This function replaces single-band WiFi AP setup with dual-band support

    local ssid="${1:-HookProbe-Fortress}"
    local password="$2"
    local bridge="${3:-FTS}"

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
            cat > /etc/NetworkManager/conf.d/fts-wifi.conf << EOF
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
    # Creates:
    #   1. fts-wifi-allocator.service - Detects bands and updates configs at boot
    #   2. fts-hostapd-24ghz.service - 2.4GHz AP (depends on allocator)
    #   3. fts-hostapd-5ghz.service - 5GHz AP (depends on allocator)
    #   4. fts-hostapd.service - Combined service for backward compatibility
    #
    # IMPORTANT: Uses stable interface names (wlan_24ghz, wlan_5ghz) assigned by udev rules,
    # not the detected original names (wlan0, wlp6s0, etc.)

    local ovs_bridge="${OVS_BRIDGE_NAME:-FTS}"
    local allocator_script="/opt/hookprobe/fortress/devices/common/wifi-band-allocator.sh"

    # Use stable interface names (assigned by udev rules)
    local wifi_24ghz_iface="wlan_24ghz"
    local wifi_5ghz_iface="wlan_5ghz"

    # Find hostapd binary - check common locations
    local hostapd_bin=""
    for path in /usr/local/bin/hostapd /usr/sbin/hostapd /usr/bin/hostapd; do
        if [ -x "$path" ]; then
            hostapd_bin="$path"
            break
        fi
    done
    if [ -z "$hostapd_bin" ]; then
        hostapd_bin=$(which hostapd 2>/dev/null || echo "/usr/sbin/hostapd")
    fi
    log_info "Using hostapd: $hostapd_bin"

    # Install the allocator script
    if [ -f "$SCRIPT_DIR/wifi-band-allocator.sh" ]; then
        mkdir -p "$(dirname "$allocator_script")"
        cp "$SCRIPT_DIR/wifi-band-allocator.sh" "$allocator_script"
        chmod +x "$allocator_script"
    fi

    # Create WiFi band allocator service (runs before hostapd to detect bands)
    cat > /etc/systemd/system/fts-wifi-allocator.service << EOF
[Unit]
Description=HookProbe Fortress - WiFi Band Allocator
# Run after network but before hostapd
After=network.target
Before=fts-hostapd-24ghz.service fts-hostapd-5ghz.service fts-hostapd.service
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
# Wait for WiFi interfaces to appear, detect bands, update hostapd configs
ExecStart=$allocator_script wait
TimeoutStartSec=60

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable fts-wifi-allocator
    log_info "Created service: fts-wifi-allocator (detects bands at boot)"

    # 2.4GHz service - uses stable interface name from udev rules
    if [ -n "$NET_WIFI_24GHZ_IFACE" ] && [ -f /etc/hostapd/hostapd-24ghz.conf ]; then
        # Systemd device unit - waits for stable interface name to exist before starting
        local dev_unit_24ghz="sys-subsystem-net-devices-${wifi_24ghz_iface}.device"

        cat > /etc/systemd/system/fts-hostapd-24ghz.service << EOF
[Unit]
Description=HookProbe Fortress - 2.4GHz WiFi Access Point
After=network.target fts-wifi-allocator.service ${dev_unit_24ghz}
Wants=network.target ${dev_unit_24ghz}
Requires=fts-wifi-allocator.service

[Service]
Type=forking
PIDFile=/run/hostapd-24ghz.pid
# Small delay after interface appears to ensure it's fully initialized
ExecStartPre=/bin/sleep 1
ExecStartPre=-/sbin/ip link set ${wifi_24ghz_iface} up
ExecStart=${hostapd_bin} -B -P /run/hostapd-24ghz.pid /etc/hostapd/hostapd-24ghz.conf
ExecStartPost=/bin/sleep 1
ExecStartPost=-/usr/bin/ovs-vsctl --may-exist add-port ${ovs_bridge} ${wifi_24ghz_iface}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable fts-hostapd-24ghz
        log_info "Created service: fts-hostapd-24ghz (waits for ${wifi_24ghz_iface})"
    fi

    # 5GHz service - uses stable interface name from udev rules
    if [ -n "$NET_WIFI_5GHZ_IFACE" ] && [ -f /etc/hostapd/hostapd-5ghz.conf ]; then
        # Only create separate service if different interface
        if [ "$NET_WIFI_5GHZ_IFACE" != "$NET_WIFI_24GHZ_IFACE" ]; then
            # Systemd device unit - waits for stable interface name to exist before starting
            local dev_unit_5ghz="sys-subsystem-net-devices-${wifi_5ghz_iface}.device"

            cat > /etc/systemd/system/fts-hostapd-5ghz.service << EOF
[Unit]
Description=HookProbe Fortress - 5GHz WiFi Access Point
After=network.target fts-wifi-allocator.service ${dev_unit_5ghz}
Wants=network.target ${dev_unit_5ghz}
Requires=fts-wifi-allocator.service

[Service]
Type=forking
PIDFile=/run/hostapd-5ghz.pid
# Small delay after interface appears to ensure it's fully initialized
ExecStartPre=/bin/sleep 1
ExecStartPre=-/sbin/ip link set ${wifi_5ghz_iface} up
ExecStart=${hostapd_bin} -B -P /run/hostapd-5ghz.pid /etc/hostapd/hostapd-5ghz.conf
ExecStartPost=/bin/sleep 1
ExecStartPost=-/usr/bin/ovs-vsctl --may-exist add-port ${ovs_bridge} ${wifi_5ghz_iface}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable fts-hostapd-5ghz
            log_info "Created service: fts-hostapd-5ghz (waits for ${wifi_5ghz_iface})"
        else
            log_info "Single dual-band radio - using 2.4GHz service for both bands"
        fi
    fi

    # Create combined service for backward compatibility
    cat > /etc/systemd/system/fts-hostapd.service << EOF
[Unit]
Description=HookProbe Fortress - WiFi Access Points (All Bands)
After=network.target fts-wifi-allocator.service
Wants=fts-hostapd-24ghz.service fts-hostapd-5ghz.service
Requires=fts-wifi-allocator.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable fts-hostapd
}

# ============================================================
# LTE/WWAN SETUP
# ============================================================

initialize_lte_modem() {
    # Initialize LTE modem and bring it online
    #
    # This function:
    #   1. Ensures ModemManager is running
    #   2. Waits for modem detection
    #   3. Enables the modem if disabled
    #   4. Verifies the modem is ready for connection
    #
    # Returns: 0 on success, 1 on failure

    log_step "Initializing LTE modem..."

    # Check if ModemManager is available
    if ! command -v mmcli &>/dev/null; then
        log_warn "ModemManager (mmcli) not found"
        log_warn "Install with: apt install modemmanager"
        return 1
    fi

    # Ensure ModemManager is running
    if ! systemctl is-active ModemManager &>/dev/null; then
        log_info "Starting ModemManager..."
        systemctl start ModemManager || {
            log_error "Failed to start ModemManager"
            return 1
        }
        sleep 2
    fi

    # Wait for modem to be detected (max 30 seconds)
    log_info "Waiting for modem detection..."
    local max_wait=30
    local waited=0
    local modem_found=false

    while [ $waited -lt $max_wait ]; do
        if mmcli -L 2>/dev/null | grep -q "/Modem/"; then
            modem_found=true
            break
        fi
        sleep 2
        waited=$((waited + 2))
        [ $((waited % 10)) -eq 0 ] && log_info "  Still waiting... ($waited seconds)"
    done

    if [ "$modem_found" = "false" ]; then
        log_warn "No LTE modem detected after ${max_wait}s"
        log_warn "Check: lsusb | grep -i modem"
        return 1
    fi

    # Get modem index
    local modem_idx
    modem_idx=$(mmcli -L 2>/dev/null | grep -oP '/Modem/\K\d+' | head -1)

    if [ -z "$modem_idx" ]; then
        log_error "Could not get modem index"
        return 1
    fi

    log_info "Found modem at index $modem_idx"

    # Check modem state
    local modem_state
    modem_state=$(mmcli -m "$modem_idx" 2>/dev/null | grep -oP "state:\s+'\K[^']+")
    log_info "Modem state: $modem_state"

    # Enable modem if disabled
    if [ "$modem_state" = "disabled" ] || [ "$modem_state" = "locked" ]; then
        log_info "Enabling modem..."
        if ! mmcli -m "$modem_idx" --enable 2>/dev/null; then
            log_error "Failed to enable modem"
            return 1
        fi
        sleep 3
        modem_state=$(mmcli -m "$modem_idx" 2>/dev/null | grep -oP "state:\s+'\K[^']+")
        log_info "Modem state after enable: $modem_state"
    fi

    # Check for SIM
    local sim_path
    sim_path=$(mmcli -m "$modem_idx" 2>/dev/null | grep -oP "primary sim path:\s+'\K[^']+")

    if [ -z "$sim_path" ] || [ "$sim_path" = "--" ]; then
        log_warn "No SIM card detected"
        return 1
    fi

    log_info "SIM detected: $sim_path"

    # Get WWAN interface name
    local wwan_iface
    wwan_iface=$(mmcli -m "$modem_idx" 2>/dev/null | grep -oP "primary port:\s+'\K[^']+")

    # Also check for net interface
    local net_iface
    net_iface=$(ls /sys/class/net/ 2>/dev/null | grep -E '^wwan|^wwp' | head -1)

    if [ -n "$net_iface" ]; then
        log_info "Network interface: $net_iface"
        export NET_WWAN_IFACE="$net_iface"
        export LTE_INTERFACE="$net_iface"
    fi

    export LTE_MODEM_IDX="$modem_idx"
    export LTE_MODEM_STATE="$modem_state"

    log_success "LTE modem initialized successfully"
    return 0
}

connect_lte() {
    # Connect LTE modem to network
    #
    # Args:
    #   $1 - APN name (optional, will try auto-detect if not provided)
    #   $2 - Username (optional)
    #   $3 - Password (optional)
    #
    # Returns: 0 on success, 1 on failure

    local apn="$1"
    local username="$2"
    local password="$3"

    log_step "Connecting LTE..."

    # Ensure modem is initialized
    if [ -z "$LTE_MODEM_IDX" ]; then
        initialize_lte_modem || return 1
    fi

    local modem_idx="$LTE_MODEM_IDX"

    # Check current state
    local current_state
    current_state=$(mmcli -m "$modem_idx" 2>/dev/null | grep -oP "state:\s+'\K[^']+")

    if [ "$current_state" = "connected" ]; then
        log_info "Modem already connected"
        verify_lte_connection
        return $?
    fi

    # Build connection command
    local connect_args=""
    if [ -n "$apn" ]; then
        connect_args="apn=$apn"
    fi
    if [ -n "$username" ]; then
        connect_args="${connect_args}${connect_args:+,}user=$username"
    fi
    if [ -n "$password" ]; then
        connect_args="${connect_args}${connect_args:+,}password=$password"
    fi

    # Try to connect
    log_info "Connecting with${apn:+ APN: $apn}${apn:-auto-detect}..."

    if [ -n "$connect_args" ]; then
        mmcli -m "$modem_idx" --simple-connect="$connect_args" 2>/dev/null
    else
        # Try auto-connect without APN
        mmcli -m "$modem_idx" --simple-connect="" 2>/dev/null
    fi

    local result=$?

    if [ $result -eq 0 ]; then
        log_success "LTE connected"
        sleep 2
        verify_lte_connection
        return $?
    else
        log_error "Failed to connect LTE"
        return 1
    fi
}

verify_lte_connection() {
    # Verify LTE connection is working
    #
    # Checks:
    #   1. Interface is UP
    #   2. Has IP address
    #   3. Has default route
    #   4. Can reach internet

    log_info "Verifying LTE connection..."

    local iface="${NET_WWAN_IFACE:-wwan0}"

    # Check interface exists and is UP
    if ! ip link show "$iface" 2>/dev/null | grep -q "UP"; then
        # Try to bring it up
        ip link set "$iface" up 2>/dev/null || true
        sleep 1
    fi

    # Check for IP address
    local ip_addr
    ip_addr=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet \K[\d.]+')

    if [ -z "$ip_addr" ]; then
        log_warn "No IP address on $iface"
        # Try DHCP
        dhclient "$iface" 2>/dev/null &
        sleep 3
        ip_addr=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet \K[\d.]+')
    fi

    if [ -z "$ip_addr" ]; then
        log_error "Failed to get IP address on $iface"
        return 1
    fi

    log_info "  IP: $ip_addr"

    # Check default route
    if ip route show dev "$iface" 2>/dev/null | grep -q "^default"; then
        log_info "  Route: default route present"
    else
        log_warn "  Route: no default route (will be added by failover)"
    fi

    # Test connectivity (using a lightweight endpoint)
    if ping -c 1 -W 3 -I "$iface" 8.8.8.8 &>/dev/null; then
        log_success "  Connectivity: OK"
        export LTE_CONNECTED=true
        return 0
    else
        log_warn "  Connectivity: no response (may be blocked or slow)"
        export LTE_CONNECTED=partial
        return 0
    fi
}

setup_lte_on_boot() {
    # Create systemd service to connect LTE on boot
    #
    # Args:
    #   $1 - APN (optional)

    local apn="${1:-}"

    log_info "Creating LTE boot service..."

    cat > /etc/systemd/system/fts-lte.service << EOF
[Unit]
Description=HookProbe Fortress LTE Connection
After=ModemManager.service network-online.target
Wants=ModemManager.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sleep 5
ExecStart=/bin/bash -c 'source /opt/hookprobe/fortress/devices/common/network-integration.sh && initialize_lte_modem && connect_lte ${apn}'
ExecStop=/usr/bin/mmcli -m 0 --simple-disconnect

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable fts-lte.service 2>/dev/null || true

    log_info "LTE boot service created (fts-lte.service)"
}

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
        local lte_con="fts-lte"
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
        local bridge_name="${OVS_BRIDGE_NAME:-FTS}"

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
