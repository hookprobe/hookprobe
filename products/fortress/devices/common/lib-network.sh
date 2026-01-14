#!/bin/bash
#
# lib-network.sh - Shared Network Functions Library for Fortress
# Part of HookProbe Fortress - Small Business Security Gateway
#
# This library provides common network utility functions used by:
#   - network-integration.sh (installation)
#   - wan-failover-pbr.sh (PBR failover daemon)
#   - wan-failover-monitor.sh (monitoring daemon)
#   - early-network-resilience.sh (early boot resilience)
#
# IMPORTANT: This file should be sourced, not executed directly.
#
# Usage:
#   source /opt/hookprobe/fortress/devices/common/lib-network.sh
#   # or during development:
#   source "$(dirname "${BASH_SOURCE[0]}")/lib-network.sh"
#
# Version: 1.0.0
# License: AGPL-3.0
#

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "ERROR: This script should be sourced, not executed directly." >&2
    echo "Usage: source ${BASH_SOURCE[0]}" >&2
    exit 1
fi

# Guard against multiple sourcing
[[ -n "${_LIB_NETWORK_LOADED:-}" ]] && return 0
_LIB_NETWORK_LOADED=1

# ============================================================
# Configuration
# ============================================================

# Logging prefix for this library
_LIB_NET_LOG_TAG="${_LIB_NET_LOG_TAG:-lib-network}"

# ============================================================
# Logging Functions
# ============================================================

_lib_net_log_info() {
    if command -v log_info &>/dev/null; then
        log_info "[lib-net] $1"
    else
        logger -t "$_LIB_NET_LOG_TAG" "$1" 2>/dev/null || echo "[INFO] $1"
    fi
}

_lib_net_log_warn() {
    if command -v log_warn &>/dev/null; then
        log_warn "[lib-net] $1"
    else
        logger -t "$_LIB_NET_LOG_TAG" -p warning "$1" 2>/dev/null || echo "[WARN] $1" >&2
    fi
}

_lib_net_log_debug() {
    if [ "${DEBUG:-0}" = "1" ]; then
        if command -v log_debug &>/dev/null; then
            log_debug "[lib-net] $1"
        else
            logger -t "$_LIB_NET_LOG_TAG" -p debug "$1" 2>/dev/null || echo "[DEBUG] $1"
        fi
    fi
}

# ============================================================
# Validation Functions
# ============================================================

# Validate IPv4 address format and octet ranges
# Prevents command injection and ensures valid IP format
# Args:
#   $1 - IP address string to validate
# Returns:
#   0 if valid IPv4, 1 otherwise
is_valid_ipv4() {
    local ip="$1"

    # Empty check
    [ -z "$ip" ] && return 1

    # Quick format check - only allow digits and dots
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1

    # Validate each octet is in range 0-255
    local IFS='.'
    read -r o1 o2 o3 o4 <<< "$ip"

    # Ensure all octets are valid numbers in range
    ((o1 >= 0 && o1 <= 255)) || return 1
    ((o2 >= 0 && o2 <= 255)) || return 1
    ((o3 >= 0 && o3 <= 255)) || return 1
    ((o4 >= 0 && o4 <= 255)) || return 1

    return 0
}

# Validate network interface name
# Prevents command injection via malformed interface names
# Args:
#   $1 - Interface name to validate
# Returns:
#   0 if valid, 1 otherwise
is_valid_interface_name() {
    local name="$1"

    # Empty check
    [ -z "$name" ] && return 1

    # Length check (Linux limit is 15 chars, but allow some margin)
    [ ${#name} -gt 20 ] && return 1

    # Must not start with hyphen (could be interpreted as option)
    [[ "$name" == -* ]] && return 1

    # Allow only: letters, digits, underscore, dot, hyphen
    # This matches Linux interface naming conventions
    [[ "$name" =~ ^[A-Za-z0-9_.-]+$ ]] || return 1

    # Reject any whitespace or control characters
    [[ "$name" =~ [[:space:]] ]] && return 1

    return 0
}

# Check if interface exists in the system
# Args:
#   $1 - Interface name
# Returns:
#   0 if exists, 1 otherwise
interface_exists() {
    local iface="$1"

    is_valid_interface_name "$iface" || return 1

    [ -d "/sys/class/net/$iface" ]
}

# Check if interface is UP and has carrier
# Args:
#   $1 - Interface name
# Returns:
#   0 if up with carrier, 1 otherwise
interface_is_up() {
    local iface="$1"

    interface_exists "$iface" || return 1

    # Check operstate is up
    local state
    state=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null)
    [ "$state" = "up" ] || return 1

    # Check carrier (link detected)
    local carrier
    carrier=$(cat "/sys/class/net/$iface/carrier" 2>/dev/null)
    [ "$carrier" = "1" ] || return 1

    return 0
}

# ============================================================
# Gateway Discovery Functions
# ============================================================

# Get the gateway for a network interface
# This is the PRIMARY function for gateway discovery.
#
# Priority order:
#   1. DHCP routers option - The actual gateway from DHCP server
#      (Most reliable when ipv4.never-default=yes is set)
#   2. IP4.GATEWAY - NetworkManager's displayed gateway
#      (Used for static IP or when DHCP option unavailable)
#
# Args:
#   $1 - Interface name
#   $2 - Validate connectivity (optional, default: "false")
#        Set to "true" to ping-verify the gateway
# Returns:
#   Prints gateway IP on success, returns 0
#   Prints nothing on failure, returns 1
#
# Example:
#   gw=$(get_interface_gateway "enp1s0")
#   gw=$(get_interface_gateway "wwan0" "true")  # with validation
#
get_interface_gateway() {
    local iface="$1"
    local validate="${2:-false}"
    local gw=""

    # Validate interface name (security: prevent command injection)
    if ! is_valid_interface_name "$iface"; then
        _lib_net_log_warn "Invalid interface name: $iface"
        return 1
    fi

    # Check if nmcli is available
    if ! command -v nmcli &>/dev/null; then
        _lib_net_log_warn "nmcli not available - cannot discover gateway"
        return 1
    fi

    # Method 1: DHCP routers option (most reliable for DHCP interfaces)
    # This gets the actual gateway from DHCP lease, even when:
    #   - ipv4.never-default=yes is set (no default route added)
    #   - ipv4.ignore-auto-routes=yes is set
    # NOTE: -t (terse mode) does NOT work with DHCP4.OPTION fields - outputs nothing!
    # Must use non-terse mode and parse with grep/awk
    # Exclude 'requested_routers' which is a different field (DHCP option request)
    local dhcp_output
    dhcp_output=$(nmcli -f DHCP4.OPTION device show "$iface" 2>/dev/null)
    gw=$(echo "$dhcp_output" | grep "routers = " | grep -v "requested" | awk '{print $NF}')

    if [ -n "$gw" ] && is_valid_ipv4 "$gw"; then
        _lib_net_log_debug "Gateway $gw from DHCP routers option for $iface"

        if [ "$validate" = "true" ]; then
            if _validate_gateway_reachable "$iface" "$gw"; then
                echo "$gw"
                return 0
            else
                _lib_net_log_warn "Gateway $gw from DHCP failed reachability - trying fallback"
            fi
        else
            echo "$gw"
            return 0
        fi
    fi

    # Method 2: IP4.GATEWAY (fallback for static IP or when DHCP option unavailable)
    gw=$(nmcli -t -f IP4.GATEWAY device show "$iface" 2>/dev/null | \
         cut -d: -f2 | grep -v '^$' | grep -v '^--$' | head -1)

    if [ -n "$gw" ] && [ "$gw" != "--" ] && is_valid_ipv4 "$gw"; then
        _lib_net_log_debug "Gateway $gw from IP4.GATEWAY for $iface"

        if [ "$validate" = "true" ]; then
            if _validate_gateway_reachable "$iface" "$gw"; then
                echo "$gw"
                return 0
            else
                _lib_net_log_warn "Gateway $gw from IP4.GATEWAY failed reachability"
            fi
        else
            echo "$gw"
            return 0
        fi
    fi

    # Method 3: Check existing default route for this interface
    gw=$(ip route show default 2>/dev/null | grep "dev $iface" | awk '{print $3}' | head -1)

    if [ -n "$gw" ] && is_valid_ipv4 "$gw"; then
        _lib_net_log_debug "Gateway $gw from routing table for $iface"

        if [ "$validate" = "true" ]; then
            if _validate_gateway_reachable "$iface" "$gw"; then
                echo "$gw"
                return 0
            fi
        else
            echo "$gw"
            return 0
        fi
    fi

    # Method 4: For LTE/WWAN - check ModemManager
    case "$iface" in
        wwan*|usb*|wwp*|cdc*|mbim*|qmi*|ww*|enp*s*u*)
            gw=$(_get_lte_gateway "$iface")
            if [ -n "$gw" ] && is_valid_ipv4 "$gw"; then
                _lib_net_log_debug "Gateway $gw from ModemManager for $iface"
                echo "$gw"
                return 0
            fi
            ;;
    esac

    _lib_net_log_debug "No gateway found for $iface"
    return 1
}

# Get gateway for LTE/WWAN interface via ModemManager
# Internal function used by get_interface_gateway
_get_lte_gateway() {
    local iface="$1"
    local gw=""

    # Try ModemManager first
    if command -v mmcli &>/dev/null; then
        local modem_idx
        modem_idx=$(mmcli -L 2>/dev/null | grep -oP 'Modem/\K\d+' | head -1)

        if [ -n "$modem_idx" ]; then
            local bearer_idx
            bearer_idx=$(mmcli -m "$modem_idx" 2>/dev/null | grep -oP 'Bearer/\K\d+' | head -1)

            if [ -n "$bearer_idx" ]; then
                gw=$(mmcli -b "$bearer_idx" 2>/dev/null | grep -oP 'gateway:\s*\K[\d.]+')
                if [ -n "$gw" ] && is_valid_ipv4 "$gw"; then
                    echo "$gw"
                    return 0
                fi
            fi
        fi
    fi

    # Fallback: Calculate from point-to-point /30 or /31 network
    local lte_info
    lte_info=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet \K[\d./]+')

    if [ -n "$lte_info" ]; then
        local lte_ip lte_mask
        lte_ip=$(echo "$lte_info" | cut -d/ -f1)
        lte_mask=$(echo "$lte_info" | cut -d/ -f2)

        # For /30 subnet: calculate the other usable IP
        if [ "$lte_mask" = "30" ]; then
            local last_octet base_ip other_ip
            last_octet=$(echo "$lte_ip" | awk -F. '{print $4}')
            base_ip=$(echo "$lte_ip" | awk -F. '{print $1"."$2"."$3"."}')
            local block_start=$((last_octet / 4 * 4))
            local offset=$((last_octet - block_start))

            if [ $offset -eq 1 ]; then
                other_ip="${base_ip}$((block_start + 2))"
            elif [ $offset -eq 2 ]; then
                other_ip="${base_ip}$((block_start + 1))"
            fi

            if [ -n "$other_ip" ] && is_valid_ipv4 "$other_ip"; then
                echo "$other_ip"
                return 0
            fi
        fi

        # For /31 point-to-point (RFC 3021): the other IP is gateway
        if [ "$lte_mask" = "31" ]; then
            local last_octet base_ip candidate
            last_octet=$(echo "$lte_ip" | awk -F. '{print $4}')
            base_ip=$(echo "$lte_ip" | awk -F. '{print $1"."$2"."$3"."}')

            if [ $((last_octet % 2)) -eq 0 ]; then
                candidate="${base_ip}$((last_octet + 1))"
            else
                candidate="${base_ip}$((last_octet - 1))"
            fi

            if is_valid_ipv4 "$candidate"; then
                echo "$candidate"
                return 0
            fi
        fi
    fi

    return 1
}

# Validate that a gateway is reachable
# Internal function for connectivity validation
_validate_gateway_reachable() {
    local iface="$1"
    local gateway="$2"

    [ -z "$iface" ] || [ -z "$gateway" ] && return 1

    # Quick ping test (2 attempts, 2 second timeout each)
    if ping -c 2 -W 2 -I "$iface" "$gateway" &>/dev/null; then
        return 0
    fi

    # Gateway might block ICMP - try ARP check instead
    if command -v arping &>/dev/null; then
        if arping -c 2 -w 2 -I "$iface" "$gateway" &>/dev/null; then
            return 0
        fi
    fi

    # Check if gateway has ARP entry (means it's reachable at L2)
    if ip neigh show dev "$iface" 2>/dev/null | grep -q "$gateway"; then
        local state
        state=$(ip neigh show dev "$iface" "$gateway" 2>/dev/null | awk '{print $NF}')
        case "$state" in
            REACHABLE|STALE|DELAY|PROBE)
                return 0
                ;;
        esac
    fi

    return 1
}

# Validate gateway provides internet connectivity
# More thorough check - tests actual internet access through gateway
# Args:
#   $1 - Interface name
#   $2 - Gateway IP
#   $3 - Test target (optional, default: 1.1.1.1)
# Returns:
#   0 if gateway provides internet, 1 otherwise
validate_gateway_connectivity() {
    local iface="$1"
    local gateway="$2"
    local test_target="${3:-1.1.1.1}"

    [ -z "$iface" ] || [ -z "$gateway" ] && return 1

    # Method 1: Check NetworkManager connectivity status
    if command -v nmcli &>/dev/null; then
        local connectivity
        connectivity=$(nmcli -t -f GENERAL.IP4-CONNECTIVITY device show "$iface" 2>/dev/null | cut -d: -f2)
        # 4 = full, 3 = limited, 2 = portal, 1 = none
        if [ "$connectivity" = "4" ]; then
            _lib_net_log_debug "Gateway $gateway validated: NM reports full connectivity"
            return 0
        fi
    fi

    # Method 2: Test internet via ping through specific interface
    local iface_ip
    iface_ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)

    if [ -n "$iface_ip" ]; then
        # Add temporary route and test
        if ip route add "$test_target/32" via "$gateway" dev "$iface" 2>/dev/null; then
            if ping -c 2 -W 3 -I "$iface" "$test_target" &>/dev/null; then
                ip route del "$test_target/32" via "$gateway" dev "$iface" 2>/dev/null
                _lib_net_log_debug "Gateway $gateway validated: can reach $test_target"
                return 0
            fi
            ip route del "$test_target/32" via "$gateway" dev "$iface" 2>/dev/null
        fi
    fi

    # Method 3: HTTP check (catches captive portals)
    if command -v curl &>/dev/null; then
        if curl -s -m 5 --interface "$iface" -o /dev/null -w "%{http_code}" \
           "http://httpbin.org/ip" 2>/dev/null | grep -q "200"; then
            _lib_net_log_debug "Gateway $gateway validated: HTTP check passed"
            return 0
        fi
    fi

    _lib_net_log_warn "Gateway $gateway on $iface FAILED connectivity validation"
    return 1
}

# ============================================================
# Interface Discovery Functions
# ============================================================

# Get the primary WAN interface (interface with internet connectivity)
# Returns:
#   Prints interface name on success, returns 0
#   Prints nothing on failure, returns 1
get_wan_interface() {
    local iface=""

    # Method 1: Interface with default route
    iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
    if [ -n "$iface" ] && interface_exists "$iface"; then
        echo "$iface"
        return 0
    fi

    # Method 2: First interface with IP address (likely DHCP)
    for iface in $(ls /sys/class/net/ 2>/dev/null | grep -E '^(eth|enp|eno)'); do
        if ip addr show "$iface" 2>/dev/null | grep -q "inet "; then
            echo "$iface"
            return 0
        fi
    done

    return 1
}

# Get the connection method for an interface (dhcp, static, or unknown)
# Args:
#   $1 - Interface name
# Returns:
#   Prints "dhcp", "static", or "unknown"
get_interface_method() {
    local iface="$1"

    if ! command -v nmcli &>/dev/null; then
        echo "unknown"
        return
    fi

    local method
    method=$(nmcli -t -f IP4.METHOD device show "$iface" 2>/dev/null | cut -d: -f2)

    case "$method" in
        auto)
            echo "dhcp"
            ;;
        manual)
            echo "static"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# ============================================================
# Utility Functions
# ============================================================

# Wait for interface to be ready (up with IP)
# Args:
#   $1 - Interface name
#   $2 - Timeout in seconds (default: 30)
# Returns:
#   0 if interface ready, 1 on timeout
wait_for_interface_ready() {
    local iface="$1"
    local timeout="${2:-30}"
    local waited=0

    while [ $waited -lt $timeout ]; do
        if interface_is_up "$iface"; then
            if ip addr show "$iface" 2>/dev/null | grep -q "inet "; then
                return 0
            fi
        fi
        sleep 1
        ((waited++))
    done

    return 1
}

# Get interface IP address
# Args:
#   $1 - Interface name
# Returns:
#   Prints IP address (without mask) or empty string
get_interface_ip() {
    local iface="$1"
    ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1
}

# Get interface subnet mask in CIDR notation
# Args:
#   $1 - Interface name
# Returns:
#   Prints CIDR mask (e.g., "24") or empty string
get_interface_mask() {
    local iface="$1"
    ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet [\d.]+/\K\d+' | head -1
}

# ============================================================
# Library loaded message (debug only)
# ============================================================
_lib_net_log_debug "lib-network.sh loaded successfully"
