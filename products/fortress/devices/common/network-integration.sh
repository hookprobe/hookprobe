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
    # Initialize LTE modem using simple nmcli approach
    #
    # SIMPLIFIED VERSION: Uses NetworkManager which handles:
    #   - ModemManager integration automatically
    #   - SIM detection
    #   - Modem power state management
    #   - Connection establishment and retry
    #
    # Returns: 0 on success, 1 on failure

    log_step "Initializing LTE modem (nmcli)..."

    # Check for NetworkManager
    if ! command -v nmcli &>/dev/null; then
        log_error "NetworkManager (nmcli) not found"
        log_warn "Install with: apt install network-manager"
        return 1
    fi

    # Ensure NetworkManager is running
    if ! systemctl is-active NetworkManager &>/dev/null; then
        log_info "Starting NetworkManager..."
        systemctl start NetworkManager || {
            log_error "Failed to start NetworkManager"
            return 1
        }
        sleep 2
    fi

    # Find modem control device (cdc-wdm* for CDC-MBIM modems)
    local modem_device=""
    local max_wait=30
    local waited=0

    log_info "Waiting for modem device..."

    while [ $waited -lt $max_wait ]; do
        # Check for CDC-WDM devices (modern USB modems: Sierra, Quectel, Fibocom)
        for dev in /dev/cdc-wdm*; do
            if [ -c "$dev" ]; then
                modem_device=$(basename "$dev")
                break 2
            fi
        done 2>/dev/null

        # Check for ttyUSB devices (legacy AT command modems)
        if [ -z "$modem_device" ]; then
            for dev in /dev/ttyUSB*; do
                if [ -c "$dev" ]; then
                    modem_device=$(basename "$dev")
                    break 2
                fi
            done 2>/dev/null
        fi

        sleep 2
        waited=$((waited + 2))
        [ $((waited % 10)) -eq 0 ] && log_info "  Still waiting for modem device... ($waited seconds)"
    done

    if [ -z "$modem_device" ]; then
        log_warn "No modem device found after ${max_wait}s"
        log_warn "Check: ls /dev/cdc-wdm* or lsusb"
        return 1
    fi

    log_info "Found modem device: $modem_device"
    export LTE_MODEM_DEVICE="$modem_device"

    # Get WWAN network interface (will be created after connection)
    local net_iface
    net_iface=$(ls /sys/class/net/ 2>/dev/null | grep -E '^wwan|^wwp' | head -1)
    if [ -n "$net_iface" ]; then
        export NET_WWAN_IFACE="$net_iface"
        export LTE_INTERFACE="$net_iface"
        log_info "Network interface: $net_iface"
    fi

    log_success "LTE modem ready: $modem_device"
    return 0
}

connect_lte() {
    # Connect LTE modem to network using simple nmcli approach
    #
    # SIMPLIFIED VERSION: Uses nmcli gsm connection type which handles:
    #   - ModemManager integration automatically
    #   - SIM PIN entry if needed
    #   - Connection establishment with retry
    #   - Auto-reconnect on failure
    #
    # Args:
    #   $1 - APN name (required)
    #   $2 - Username (optional)
    #   $3 - Password (optional)
    #
    # Returns: 0 on success, 1 on failure

    local apn="$1"
    local username="$2"
    local password="$3"
    local con_name="fts-lte"

    log_step "Connecting LTE via nmcli..."

    # Ensure modem device is detected
    if [ -z "$LTE_MODEM_DEVICE" ]; then
        initialize_lte_modem || return 1
    fi

    local modem_device="$LTE_MODEM_DEVICE"

    # Check if connection already exists and is active
    if nmcli con show --active 2>/dev/null | grep -q "$con_name"; then
        log_info "LTE connection '$con_name' already active"
        verify_lte_connection
        return $?
    fi

    # Delete existing connection to recreate with new settings
    nmcli con delete "$con_name" 2>/dev/null || true

    # Build nmcli command - this is the simple approach the user requested
    log_info "Creating LTE connection:"
    log_info "  Device: $modem_device"
    log_info "  APN: ${apn:-auto}"
    log_info "  Route metric: 200 (backup to wired WAN)"

    # IMPORTANT: Set route-metric to 200 (backup WAN)
    # Default GSM metric is 700, we want 200 so it's backup to wired WAN (metric 100)
    local nmcli_args="type gsm ifname \"$modem_device\" con-name \"$con_name\" ipv4.method auto ipv4.route-metric 200 connection.autoconnect yes"

    # Add APN if provided
    if [ -n "$apn" ]; then
        nmcli_args="$nmcli_args apn \"$apn\""
    fi

    # Add credentials if provided
    if [ -n "$username" ]; then
        nmcli_args="$nmcli_args gsm.username \"$username\""
    fi
    if [ -n "$password" ]; then
        nmcli_args="$nmcli_args gsm.password \"$password\" gsm.password-flags 0"
    fi

    # Create the connection
    if ! eval "nmcli con add $nmcli_args"; then
        log_error "Failed to create LTE connection"
        return 1
    fi

    log_success "LTE connection '$con_name' created"

    # Bring up the connection (retry up to 3 times)
    log_info "Activating LTE connection..."
    local retry=0
    local max_retries=3

    while [ $retry -lt $max_retries ]; do
        if nmcli con up "$con_name" 2>&1; then
            log_success "LTE connection activated"
            sleep 2
            verify_lte_connection
            return $?
        fi

        retry=$((retry + 1))
        if [ $retry -lt $max_retries ]; then
            log_warn "Activation attempt $retry failed, retrying in 3s..."
            sleep 3
        fi
    done

    log_warn "Failed to activate connection after $max_retries attempts"
    log_info "Connection will auto-activate when modem is ready"
    return 0  # Connection created, will auto-connect
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
    # SIMPLIFIED: Uses nmcli with autoconnect=yes, so NetworkManager handles
    # reconnection automatically. This service just ensures initial connection.
    #
    # Args:
    #   $1 - APN (optional)

    local apn="${1:-}"

    log_info "Creating LTE boot service..."

    # Use nmcli for stop as well (disconnect the fts-lte connection)
    cat > /etc/systemd/system/fts-lte.service << EOF
[Unit]
Description=HookProbe Fortress LTE Connection
After=NetworkManager.service network-online.target
Wants=NetworkManager.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sleep 3
ExecStart=/bin/bash -c 'source /opt/hookprobe/fortress/devices/common/network-integration.sh && initialize_lte_modem && connect_lte ${apn}'
ExecStop=/usr/bin/nmcli con down fts-lte

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable fts-lte.service 2>/dev/null || true

    log_info "LTE boot service created (fts-lte.service)"
    log_info "  Note: nmcli autoconnect=yes handles reconnection automatically"
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

setup_lte_complete() {
    # End-to-end LTE setup: detect, connect, validate, configure failover
    #
    # This is the simple one-call function that does everything:
    #   1. Detects modem device (cdc-wdm*)
    #   2. Creates nmcli GSM connection
    #   3. Activates connection
    #   4. Validates connectivity
    #   5. Sets up WAN failover with IP SLA
    #
    # Usage:
    #   setup_lte_complete "internet.vodafone.ro"
    #   setup_lte_complete "private.apn" "myuser" "mypass"
    #
    # Args:
    #   $1 - APN name (required)
    #   $2 - Username (optional)
    #   $3 - Password (optional)
    #   $4 - Primary WAN interface (optional, auto-detected)

    local apn="$1"
    local username="$2"
    local password="$3"
    local primary_wan="${4:-$NET_WAN_IFACE}"

    [ -z "$apn" ] && { log_error "APN required. Usage: setup_lte_complete <apn> [user] [pass]"; return 1; }

    log_step "=== Complete LTE Setup ==="
    log_info "APN: $apn"
    [ -n "$username" ] && log_info "Username: $username"

    # Step 1: Initialize modem
    if ! initialize_lte_modem; then
        log_error "Failed to detect modem"
        return 1
    fi

    # Step 2: Connect to LTE network
    if ! connect_lte "$apn" "$username" "$password"; then
        log_error "Failed to create LTE connection"
        return 1
    fi

    # Step 3: Verify connection
    verify_lte_connection

    # Step 4: Set up failover with IP SLA if we have a primary WAN
    if [ -n "$primary_wan" ] && [ -n "$LTE_INTERFACE" ]; then
        setup_wan_failover "$primary_wan" "$LTE_INTERFACE"
    else
        log_info "Skipping WAN failover (no primary WAN or LTE interface)"
    fi

    # Step 5: Create boot service
    setup_lte_on_boot "$apn"

    log_success "=== LTE Setup Complete ==="
    log_info ""
    log_info "Summary:"
    log_info "  Modem: ${LTE_MODEM_DEVICE:-unknown}"
    log_info "  Interface: ${LTE_INTERFACE:-pending}"
    log_info "  Connection: fts-lte"
    log_info "  IP SLA: $(systemctl is-active fts-wan-failover 2>/dev/null || echo 'not started')"
    log_info ""
    log_info "Commands:"
    log_info "  Status:     nmcli con show fts-lte"
    log_info "  Failover:   systemctl status fts-wan-failover"
    log_info "  Logs:       journalctl -u fts-wan-failover -f"
    return 0
}

setup_wan_failover() {
    # Configure WAN failover from Ethernet to LTE with IP SLA health monitoring
    #
    # This function sets up:
    #   1. Route metrics (Primary=100, LTE=200) for kernel-level fallback
    #   2. IP SLA service for active health monitoring (ping-based)
    #
    # IP SLA solves the problem where wired WAN has link but no traffic:
    #   - Metric-based failover only works when interface goes DOWN
    #   - IP SLA detects when primary has link but no actual connectivity
    #   - IP SLA removes/downgrades primary route when health checks fail
    #
    # Args:
    #   $1 - Primary WAN interface
    #   $2 - LTE interface (optional, auto-detected)

    local primary_wan="${1:-$NET_WAN_IFACE}"
    local lte_iface="${2:-$NET_WWAN_IFACE}"

    [ -z "$primary_wan" ] && { log_error "[WAN] Primary WAN interface required"; return 1; }
    [ -z "$lte_iface" ] && { log_warn "[WAN] No LTE interface for failover"; return 1; }

    log_step "[WAN] Configuring WAN failover with IP SLA..."
    log_info "[WAN]   Primary: $primary_wan (metric 100)"
    log_info "[WAN]   Backup:  $lte_iface (metric 200)"

    # Step 1: Configure route metrics via NetworkManager
    if command -v nmcli &>/dev/null; then
        log_info "[WAN] Setting route metrics..."

        # Configure primary WAN metric
        local primary_con
        primary_con=$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | grep ":${primary_wan}$" | cut -d: -f1 | head -1)
        if [ -n "$primary_con" ]; then
            nmcli con mod "$primary_con" ipv4.route-metric 100 2>/dev/null || true
            log_info "[WAN]   Set $primary_con metric to 100"
        fi

        # Configure LTE metric (fix default 700 to 200)
        local lte_con="fts-lte"
        if nmcli con show "$lte_con" &>/dev/null; then
            nmcli con mod "$lte_con" ipv4.route-metric 200 2>/dev/null || true
            log_info "[WAN]   Set $lte_con metric to 200"
        fi

        # Reactivate BOTH connections to apply new metrics
        log_info "[WAN] Reactivating connections to apply metrics..."
        [ -n "$primary_con" ] && nmcli con up "$primary_con" 2>/dev/null || true
        nmcli con show --active 2>/dev/null | grep -q "$lte_con" && nmcli con up "$lte_con" 2>/dev/null || true
    fi

    # Step 2: Create IP SLA configuration
    log_info "[WAN] Creating IP SLA configuration..."
    mkdir -p /etc/hookprobe
    cat > /etc/hookprobe/wan-failover.conf << EOF
# Fortress WAN Failover Configuration with IP SLA
# Generated: $(date -Iseconds)
#
# IP SLA (Service Level Agreement) monitors actual traffic, not just link state.
# This detects when primary WAN has carrier but no actual connectivity.

# Interface configuration
PRIMARY_IFACE="$primary_wan"
BACKUP_IFACE="$lte_iface"

# Route metrics (lower = preferred)
PRIMARY_METRIC=100
BACKUP_METRIC=200

# Health check targets (multiple for reliability)
# Uses ping through specific interface, not just any route
HEALTH_TARGETS="8.8.8.8 1.1.1.1 9.9.9.9"

# Timing
CHECK_INTERVAL=5        # Seconds between health checks
PING_TIMEOUT=2          # Timeout for each ping
PING_COUNT=1            # Pings per target

# Failover thresholds (hysteresis to prevent flapping)
FAIL_THRESHOLD=3        # Consecutive failures before failover
RECOVER_THRESHOLD=5     # Consecutive successes before failback
EOF

    log_success "[WAN] IP SLA configuration created at /etc/hookprobe/wan-failover.conf"

    # Step 3: Install and enable IP SLA systemd service
    install_ip_sla_service

    log_info "[WAN] Failover configured with IP SLA health monitoring"
    log_info "[WAN]   - Metric failover: automatic kernel routing"
    log_info "[WAN]   - IP SLA: detects 'link up but no traffic' scenarios"
    return 0
}

install_ip_sla_service() {
    # Install systemd service for IP SLA-based WAN health monitoring
    #
    # This service continuously monitors WAN health by pinging through
    # specific interfaces and handles failover when traffic fails.
    #
    # REQUIRES: root privileges (writes to /etc/systemd/system/)

    # Check for root
    if [ "$EUID" -ne 0 ] && [ "$(id -u)" -ne 0 ]; then
        log_error "[IP-SLA] This function requires root privileges"
        log_error "[IP-SLA] Run with: sudo install_ip_sla_service"
        return 1
    fi

    # Use installed path, not source directory
    local installed_path="/opt/hookprobe/fortress/devices/common"
    local wan_monitor="${installed_path}/wan-failover-monitor.sh"

    # Check if script exists in installed location OR source location
    if [ ! -x "$wan_monitor" ]; then
        # Try source directory as fallback (during development)
        if [ -x "$SCRIPT_DIR/wan-failover-monitor.sh" ]; then
            # Copy to installed location
            mkdir -p "$installed_path"
            cp "$SCRIPT_DIR/wan-failover-monitor.sh" "$wan_monitor"
            chmod +x "$wan_monitor"
            log_info "[IP-SLA] Copied wan-failover-monitor.sh to $installed_path"
        else
            log_warn "[IP-SLA] wan-failover-monitor.sh not found"
            log_warn "[IP-SLA] Expected at: $wan_monitor"
            return 1
        fi
    fi

    log_info "[IP-SLA] Installing WAN health monitoring service..."

    cat > /etc/systemd/system/fts-wan-failover.service << EOF
[Unit]
Description=HookProbe Fortress WAN IP SLA Health Monitor
Documentation=man:wan-failover-monitor(8)
After=network-online.target NetworkManager.service
Wants=network-online.target
ConditionPathExists=/etc/hookprobe/wan-failover.conf

[Service]
Type=simple
ExecStart=$wan_monitor start
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/fortress /var/log/hookprobe /proc/sys/net

[Install]
WantedBy=multi-user.target
EOF

    # Create required directories
    mkdir -p /var/lib/fortress
    mkdir -p /var/log/hookprobe

    # Enable and start service
    systemctl daemon-reload
    systemctl enable fts-wan-failover.service 2>/dev/null || true

    # Start service if both interfaces are available
    if [ -d "/sys/class/net/${PRIMARY_IFACE:-eth0}" ]; then
        systemctl start fts-wan-failover.service 2>/dev/null || true
        log_success "[IP-SLA] WAN health monitor service started"
    else
        log_info "[IP-SLA] WAN health monitor will start when interfaces are ready"
    fi

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
    echo "  setup_lte_complete <apn>   - End-to-end LTE setup (recommended)"
    echo "  setup_lte_connection       - Configure LTE connection only"
    echo "  setup_wan_failover         - Configure WAN failover with IP SLA"
    echo "  setup_lan_bridge_auto      - Set up LAN bridge"
    echo "  validate_network_config    - Run validation tests"
    echo "  show_network_summary       - Show configuration summary"
    echo ""
    echo "Examples:"
    echo "  source network-integration.sh && setup_lte_complete internet.vodafone.ro"
    echo "  source network-integration.sh && setup_wan_failover eth0 wwan0"
fi
