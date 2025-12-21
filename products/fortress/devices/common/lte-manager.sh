#!/bin/bash
#
# lte-manager.sh - LTE Modem Management and WAN Failover for Fortress
# Part of HookProbe Fortress - Small Business Security Gateway
#
# Supports:
#   - LTE modem detection (Quectel, Sierra, Huawei, Fibocom)
#   - ModemManager integration
#   - WAN failover (Ethernet -> LTE)
#   - Connection health monitoring
#
# Usage:
#   source lte-manager.sh
#   detect_lte_modems
#   setup_wan_failover
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration
LTE_STATE_DIR="/var/lib/fortress/lte"
LTE_CONFIG_FILE="$LTE_STATE_DIR/config.conf"
FAILOVER_STATE_FILE="$LTE_STATE_DIR/failover-state"
HEALTH_CHECK_INTERVAL=30  # seconds
FAILOVER_THRESHOLD=3      # consecutive failures before failover

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# LTE-specific logging (prefixed to avoid conflicts with main setup.sh)
lte_log() { echo -e "${CYAN}[LTE]${NC} $*"; }
lte_success() { echo -e "${GREEN}[LTE]${NC} $*"; }
lte_warn() { echo -e "${YELLOW}[LTE]${NC} $*"; }
lte_error() { echo -e "${RED}[LTE]${NC} $*"; }

# ============================================================
# LTE MODEM DETECTION
# ============================================================

# Known LTE modem USB IDs
declare -A LTE_MODEM_VENDORS=(
    ["2c7c"]="Quectel"
    ["1199"]="Sierra Wireless"
    ["12d1"]="Huawei"
    ["19d2"]="ZTE"
    ["2cb7"]="Fibocom"
    ["1bc7"]="Telit"
    ["05c6"]="Qualcomm"
    ["0489"]="Foxconn"
    ["413c"]="Dell"
    ["03f0"]="HP"
)

# Known modem models
declare -A LTE_MODEM_MODELS=(
    # Quectel
    ["2c7c:0125"]="EC25"
    ["2c7c:0121"]="EC21"
    ["2c7c:0306"]="EG25-G"
    ["2c7c:0512"]="EM05"
    ["2c7c:0620"]="EM120R"
    ["2c7c:0800"]="RM500Q"
    ["2c7c:0801"]="RM502Q"
    # Sierra Wireless
    ["1199:9071"]="EM7455"
    ["1199:9079"]="EM7565"
    ["1199:68c0"]="MC7455"
    ["1199:9091"]="EM7690"
    # Fibocom
    ["2cb7:0210"]="L850-GL"
    ["2cb7:0104"]="L830-EB"
    ["2cb7:01a0"]="FM150-AE"
)

detect_usb_lte_modems() {
    # Detect USB LTE modems using lsusb and sysfs
    #
    # Exports:
    #   LTE_MODEMS_FOUND - Array of detected modems
    #   LTE_MODEM_COUNT - Number of modems found

    lte_log "Scanning for USB LTE modems..."

    declare -gA LTE_MODEMS_FOUND
    export LTE_MODEM_COUNT=0

    # Method 1: Parse lsusb
    if command -v lsusb &>/dev/null; then
        while IFS= read -r line; do
            # Extract vendor:product ID
            local usb_id=$(echo "$line" | grep -oP '\b[0-9a-f]{4}:[0-9a-f]{4}\b')
            local vendor_id=$(echo "$usb_id" | cut -d: -f1)
            local product_id=$(echo "$usb_id" | cut -d: -f2)

            # Check if it's a known LTE modem vendor
            if [ -n "${LTE_MODEM_VENDORS[$vendor_id]}" ]; then
                local vendor="${LTE_MODEM_VENDORS[$vendor_id]}"
                local model="${LTE_MODEM_MODELS[$usb_id]:-Unknown}"

                LTE_MODEMS_FOUND["$usb_id"]="$vendor $model"
                LTE_MODEM_COUNT=$((LTE_MODEM_COUNT + 1))

                lte_log "  Found: $vendor $model ($usb_id)"
            fi
        done < <(lsusb 2>/dev/null)
    fi

    # Method 2: Check ModemManager
    if command -v mmcli &>/dev/null && systemctl is-active ModemManager &>/dev/null; then
        local modem_list
        modem_list=$(mmcli -L 2>/dev/null | grep "/Modem/" || true)

        while IFS= read -r line; do
            if [ -n "$line" ]; then
                local modem_path=$(echo "$line" | grep -oP '/org/freedesktop/ModemManager1/Modem/\d+')
                if [ -n "$modem_path" ]; then
                    local modem_idx=$(basename "$modem_path")
                    local modem_info
                    modem_info=$(mmcli -m "$modem_idx" 2>/dev/null | grep -E "manufacturer|model" | head -2)

                    lte_log "  ModemManager modem $modem_idx:"
                    echo "$modem_info" | while read -r info_line; do
                        lte_log "    $info_line"
                    done
                fi
            fi
        done <<< "$modem_list"
    fi

    # Method 3: Check for WWAN interfaces
    for iface in /sys/class/net/wwan* /sys/class/net/wwp*; do
        if [ -d "$iface" ]; then
            local name=$(basename "$iface")
            lte_log "  Found WWAN interface: $name"
        fi
    done 2>/dev/null || true

    if [ "$LTE_MODEM_COUNT" -eq 0 ]; then
        lte_warn "No LTE modems detected"
    else
        lte_success "Found $LTE_MODEM_COUNT LTE modem(s)"
    fi

    export LTE_MODEMS_FOUND LTE_MODEM_COUNT
}

get_modem_control_device() {
    # Get the modem control device (for AT commands, QMI, MBIM)
    #
    # Args:
    #   $1 - Modem index (optional, defaults to first modem)
    #
    # Returns: Control device path (e.g., /dev/cdc-wdm0, /dev/ttyUSB2)
    #
    # Modem control devices:
    #   - /dev/cdc-wdm* : QMI/MBIM modems (modern USB modems)
    #   - /dev/ttyUSB*  : AT command modems (legacy serial interface)

    local modem_idx="${1:-0}"

    # Method 1: Try ModemManager to get the primary port
    if command -v mmcli &>/dev/null && systemctl is-active ModemManager &>/dev/null 2>&1; then
        local primary_port
        primary_port=$(mmcli -m "$modem_idx" 2>/dev/null | grep -E "primary port:" | awk '{print $NF}')
        if [ -n "$primary_port" ]; then
            # ModemManager returns device name like "cdc-wdm0"
            if [ -c "/dev/$primary_port" ]; then
                echo "/dev/$primary_port"
                return 0
            fi
        fi
    fi

    # Method 2: Find CDC-WDM devices (QMI/MBIM modems - preferred)
    local cdc_devices=()
    for dev in /dev/cdc-wdm*; do
        [ -c "$dev" ] && cdc_devices+=("$dev")
    done 2>/dev/null

    if [ ${#cdc_devices[@]} -gt 0 ]; then
        # Return the device at the specified index, or first one
        if [ "$modem_idx" -lt ${#cdc_devices[@]} ]; then
            echo "${cdc_devices[$modem_idx]}"
        else
            echo "${cdc_devices[0]}"
        fi
        return 0
    fi

    # Method 3: Find ttyUSB devices (AT command modems)
    # Usually ttyUSB2 is the AT command port on most modems
    local tty_devices=()
    for dev in /dev/ttyUSB*; do
        [ -c "$dev" ] && tty_devices+=("$dev")
    done 2>/dev/null

    if [ ${#tty_devices[@]} -gt 0 ]; then
        # Return ttyUSB2 if available (common AT port), otherwise last one
        if [ -c "/dev/ttyUSB2" ]; then
            echo "/dev/ttyUSB2"
        else
            echo "${tty_devices[-1]}"
        fi
        return 0
    fi

    return 1
}

get_modem_interface() {
    # Get network interface name for LTE modem (data interface)
    #
    # Args:
    #   $1 - Modem index (optional, defaults to first modem)
    #
    # Returns: Interface name (e.g., wwan0, wwp0s20f0u4)
    #
    # WWAN interfaces have double 'w' prefix:
    #   - wwan*   : Generic WWAN interface
    #   - wwp*    : PCI-path based WWAN interface (e.g., wwp0s20f0u4)

    local modem_idx="${1:-0}"

    # Method 1: Try ModemManager bearer interface
    if command -v mmcli &>/dev/null && systemctl is-active ModemManager &>/dev/null 2>&1; then
        # Get active bearer
        local bearer_num
        bearer_num=$(mmcli -m "$modem_idx" 2>/dev/null | grep -oP 'Bearer/\K\d+' | head -1)
        if [ -n "$bearer_num" ]; then
            local iface
            iface=$(mmcli -b "$bearer_num" 2>/dev/null | grep -E "interface:" | awk '{print $NF}')
            if [ -n "$iface" ] && [ -d "/sys/class/net/$iface" ]; then
                echo "$iface"
                return 0
            fi
        fi
    fi

    # Method 2: Check NetworkManager for GSM connection device
    if command -v nmcli &>/dev/null; then
        local gsm_device
        gsm_device=$(nmcli -t -f TYPE,DEVICE connection show --active 2>/dev/null | grep "^gsm:" | cut -d: -f2 | head -1)
        if [ -n "$gsm_device" ] && [ -d "/sys/class/net/$gsm_device" ]; then
            echo "$gsm_device"
            return 0
        fi
    fi

    # Method 3: Find WWAN interfaces in sysfs (wwp* or wwan*)
    # These have double 'w' prefix to distinguish from WiFi (wlan/wlp)
    local wwan_ifaces=()
    for iface in /sys/class/net/wwp* /sys/class/net/wwan*; do
        if [ -d "$iface" ]; then
            wwan_ifaces+=("$(basename "$iface")")
        fi
    done 2>/dev/null

    if [ ${#wwan_ifaces[@]} -gt 0 ]; then
        if [ "$modem_idx" -lt ${#wwan_ifaces[@]} ]; then
            echo "${wwan_ifaces[$modem_idx]}"
        else
            echo "${wwan_ifaces[0]}"
        fi
        return 0
    fi

    return 1
}

get_modem_info() {
    # Get comprehensive modem information
    #
    # Args:
    #   $1 - Modem index (optional, defaults to first modem)
    #
    # Exports:
    #   MODEM_CTRL_DEV   - Control device (/dev/cdc-wdm0, /dev/ttyUSB2)
    #   MODEM_NET_IFACE  - Network interface (wwp0s20f0u4, wwan0)
    #   MODEM_TYPE       - Modem type (qmi, mbim, at)
    #   MODEM_STATUS     - Connection status

    local modem_idx="${1:-0}"

    export MODEM_CTRL_DEV=""
    export MODEM_NET_IFACE=""
    export MODEM_TYPE="unknown"
    export MODEM_STATUS="unknown"

    # Get control device
    MODEM_CTRL_DEV=$(get_modem_control_device "$modem_idx")

    # Determine modem type from control device
    if [ -n "$MODEM_CTRL_DEV" ]; then
        case "$MODEM_CTRL_DEV" in
            /dev/cdc-wdm*)
                # Check if QMI or MBIM
                if command -v qmicli &>/dev/null && qmicli -d "$MODEM_CTRL_DEV" --dms-get-manufacturer &>/dev/null 2>&1; then
                    MODEM_TYPE="qmi"
                elif command -v mbimcli &>/dev/null && mbimcli -d "$MODEM_CTRL_DEV" --query-device-caps &>/dev/null 2>&1; then
                    MODEM_TYPE="mbim"
                else
                    MODEM_TYPE="cdc"
                fi
                ;;
            /dev/ttyUSB*)
                MODEM_TYPE="at"
                ;;
        esac
    fi

    # Get network interface
    MODEM_NET_IFACE=$(get_modem_interface "$modem_idx")

    # Get connection status from ModemManager
    if command -v mmcli &>/dev/null && systemctl is-active ModemManager &>/dev/null 2>&1; then
        local state
        state=$(mmcli -m "$modem_idx" 2>/dev/null | grep -E "state:" | awk '{print $NF}')
        [ -n "$state" ] && MODEM_STATUS="$state"
    fi

    # Log findings
    lte_log "Modem $modem_idx info:"
    [ -n "$MODEM_CTRL_DEV" ] && lte_log "  Control device: $MODEM_CTRL_DEV ($MODEM_TYPE)"
    [ -n "$MODEM_NET_IFACE" ] && lte_log "  Network interface: $MODEM_NET_IFACE"
    [ -n "$MODEM_STATUS" ] && lte_log "  Status: $MODEM_STATUS"
}

detect_lte_modem() {
    # Detect LTE modem and export variables for setup.sh
    #
    # This function is called by setup.sh to detect modems and export:
    #   LTE_VENDOR    - Modem vendor (Quectel, Sierra, etc.)
    #   LTE_MODEL     - Modem model (EM05, RM502Q, etc.)
    #   LTE_INTERFACE - Network interface (wwan0, wwp0s20f0u4)
    #   LTE_PROTOCOL  - Protocol type (qmi, mbim, at)
    #   LTE_CTRL_DEV  - Control device (/dev/cdc-wdm0)
    #
    # Returns: 0 if modem found, 1 if not

    export LTE_VENDOR=""
    export LTE_MODEL=""
    export LTE_INTERFACE=""
    export LTE_PROTOCOL=""
    export LTE_CTRL_DEV=""

    lte_log "Detecting LTE modem..."

    # Ensure ModemManager is running
    if command -v mmcli &>/dev/null; then
        if ! systemctl is-active ModemManager &>/dev/null; then
            lte_log "Starting ModemManager..."
            systemctl start ModemManager 2>/dev/null || true
            sleep 3  # Give ModemManager time to detect modems
        fi
    fi

    # Method 1: Use ModemManager (most reliable)
    if command -v mmcli &>/dev/null && systemctl is-active ModemManager &>/dev/null 2>&1; then
        local modem_count
        modem_count=$(mmcli -L 2>/dev/null | grep -c "/Modem/" || echo "0")

        if [ "$modem_count" -gt 0 ]; then
            lte_log "ModemManager detected $modem_count modem(s)"

            # Get first modem info
            local mm_info
            mm_info=$(mmcli -m 0 2>/dev/null)

            if [ -n "$mm_info" ]; then
                # Extract vendor
                LTE_VENDOR=$(echo "$mm_info" | grep -E "manufacturer:" | sed 's/.*manufacturer:\s*//' | xargs)
                # Extract model
                LTE_MODEL=$(echo "$mm_info" | grep -E "^\s*model:" | sed 's/.*model:\s*//' | xargs)
                # Extract primary port (control device)
                local primary_port
                primary_port=$(echo "$mm_info" | grep -E "primary port:" | awk '{print $NF}')
                [ -n "$primary_port" ] && LTE_CTRL_DEV="/dev/$primary_port"
                # Get state
                local state
                state=$(echo "$mm_info" | grep -E "^\s*state:" | awk '{print $NF}')

                lte_log "  Vendor: $LTE_VENDOR"
                lte_log "  Model: $LTE_MODEL"
                lte_log "  Control: ${LTE_CTRL_DEV:-not found}"
                lte_log "  State: ${state:-unknown}"
            fi
        fi
    fi

    # Method 2: Fallback to USB device detection
    if [ -z "$LTE_VENDOR" ] && command -v lsusb &>/dev/null; then
        while IFS= read -r line; do
            local usb_id=$(echo "$line" | grep -oP '\b[0-9a-f]{4}:[0-9a-f]{4}\b')
            local vendor_id=$(echo "$usb_id" | cut -d: -f1)

            if [ -n "${LTE_MODEM_VENDORS[$vendor_id]:-}" ]; then
                LTE_VENDOR="${LTE_MODEM_VENDORS[$vendor_id]}"
                LTE_MODEL="${LTE_MODEM_MODELS[$usb_id]:-Unknown}"
                lte_log "  USB detected: $LTE_VENDOR $LTE_MODEL"
                break
            fi
        done < <(lsusb 2>/dev/null)
    fi

    # Find control device if not already found
    if [ -z "$LTE_CTRL_DEV" ]; then
        LTE_CTRL_DEV=$(get_modem_control_device 2>/dev/null) || true
    fi

    # Determine protocol from control device
    if [ -n "$LTE_CTRL_DEV" ]; then
        case "$LTE_CTRL_DEV" in
            /dev/cdc-wdm*)
                if command -v qmicli &>/dev/null && qmicli -d "$LTE_CTRL_DEV" --dms-get-manufacturer &>/dev/null 2>&1; then
                    LTE_PROTOCOL="qmi"
                elif command -v mbimcli &>/dev/null; then
                    LTE_PROTOCOL="mbim"
                else
                    LTE_PROTOCOL="cdc"
                fi
                ;;
            /dev/ttyUSB*)
                LTE_PROTOCOL="at"
                ;;
        esac
    fi

    # Find network interface
    LTE_INTERFACE=$(get_modem_interface 2>/dev/null) || true

    # Check if we found a modem
    if [ -n "$LTE_VENDOR" ] || [ -n "$LTE_CTRL_DEV" ] || [ -n "$LTE_INTERFACE" ]; then
        lte_success "LTE modem detected"
        export LTE_VENDOR LTE_MODEL LTE_INTERFACE LTE_PROTOCOL LTE_CTRL_DEV
        return 0
    fi

    lte_warn "No LTE modem detected"
    return 1
}

# ============================================================
# APN CONFIGURATION WITH AUTHENTICATION
# ============================================================

# APN Authentication types
APN_AUTH_NONE="none"
APN_AUTH_PAP="pap"
APN_AUTH_CHAP="chap"
APN_AUTH_MSCHAPV2="mschapv2"

configure_modem_apn() {
    # Configure APN settings for LTE modem with authentication
    #
    # Args:
    #   $1 - APN name (e.g., "internet.vodafone.ro")
    #   $2 - Authentication type: none, pap, chap, mschapv2 (optional)
    #   $3 - Username (optional, required for pap/chap)
    #   $4 - Password (optional, required for pap/chap)
    #   $5 - Modem index (optional, default 0)

    local apn="$1"
    local auth_type="${2:-none}"
    local username="${3:-}"
    local password="${4:-}"
    local modem_idx="${5:-0}"

    [ -z "$apn" ] && { lte_error "APN name required"; return 1; }

    lte_log "Configuring APN: $apn"
    lte_log "  Authentication: $auth_type"
    [ -n "$username" ] && lte_log "  Username: $username"

    # Build connection string
    local connect_args="apn=$apn"

    if [ "$auth_type" != "none" ] && [ -n "$username" ]; then
        connect_args="${connect_args},user=$username"
        [ -n "$password" ] && connect_args="${connect_args},password=$password"
    fi

    # Save configuration for later use
    mkdir -p "$LTE_STATE_DIR"
    cat > "$LTE_CONFIG_FILE" << APNEOF
# Fortress LTE APN Configuration
# Generated: $(date -Iseconds)
LTE_APN="$apn"
LTE_AUTH_TYPE="$auth_type"
LTE_USERNAME="$username"
LTE_PASSWORD="$password"
LTE_MODEM_IDX="$modem_idx"
APNEOF
    chmod 600 "$LTE_CONFIG_FILE"

    # Try NetworkManager first (preferred method like Guardian)
    if configure_apn_nmcli "$apn" "$auth_type" "$username" "$password"; then
        return 0
    fi

    # Fallback to ModemManager
    if configure_apn_modemmanager "$apn" "$auth_type" "$username" "$password" "$modem_idx"; then
        return 0
    fi

    # Fallback to QMI
    if configure_apn_qmi "$apn" "$username" "$password"; then
        return 0
    fi

    lte_error "Failed to configure APN"
    return 1
}

configure_apn_nmcli() {
    # Configure APN using NetworkManager (nmcli) - like Guardian
    #
    # Args: apn, auth_type, username, password

    local apn="$1"
    local auth_type="$2"
    local username="$3"
    local password="$4"
    local con_name="fortress-lte"

    if ! command -v nmcli &>/dev/null; then
        lte_warn "NetworkManager not available"
        return 1
    fi

    # For GSM connections, we need the modem control device (cdc-wdm*), not the network interface
    # The network interface (wwp*) is created AFTER the connection is established
    local modem_device=""

    # Method 1: Use get_modem_control_device if available
    if modem_device=$(get_modem_control_device 2>/dev/null) && [ -n "$modem_device" ]; then
        # Extract just the device name (e.g., cdc-wdm0 from /dev/cdc-wdm0)
        modem_device=$(basename "$modem_device")
        lte_log "Found modem control device: $modem_device"
    fi

    # Method 2: Check for cdc-wdm devices directly
    if [ -z "$modem_device" ]; then
        for dev in /dev/cdc-wdm*; do
            if [ -c "$dev" ]; then
                modem_device=$(basename "$dev")
                lte_log "Found CDC-WDM device: $modem_device"
                break
            fi
        done 2>/dev/null
    fi

    # Method 3: Check ModemManager for primary port
    if [ -z "$modem_device" ] && command -v mmcli &>/dev/null; then
        local mm_device
        mm_device=$(mmcli -m 0 2>/dev/null | grep -E "primary port:" | awk '{print $NF}')
        if [ -n "$mm_device" ]; then
            modem_device="$mm_device"
            lte_log "Found ModemManager device: $modem_device"
        fi
    fi

    # Method 4: Fallback to WWAN interface (may not work for all modems)
    if [ -z "$modem_device" ]; then
        for iface in /sys/class/net/wwan* /sys/class/net/wwp*; do
            if [ -d "$iface" ]; then
                modem_device=$(basename "$iface")
                lte_warn "Using WWAN interface as fallback: $modem_device"
                break
            fi
        done 2>/dev/null
    fi

    if [ -z "$modem_device" ]; then
        lte_error "No modem device found for nmcli connection"
        lte_error "Please ensure your LTE modem is connected and detected"
        return 1
    fi

    lte_log "Configuring LTE via NetworkManager"
    lte_log "  Device: $modem_device"
    lte_log "  APN: $apn"

    # Delete existing connection if exists
    nmcli con delete "$con_name" 2>/dev/null || true

    # Build nmcli command - use the modem control device as interface
    local nmcli_cmd="nmcli con add type gsm ifname \"$modem_device\" con-name \"$con_name\" apn \"$apn\""

    case "$auth_type" in
        pap|chap|mschapv2)
            nmcli_cmd="$nmcli_cmd gsm.password-flags 0"
            [ -n "$username" ] && nmcli_cmd="$nmcli_cmd gsm.username \"$username\""
            [ -n "$password" ] && nmcli_cmd="$nmcli_cmd gsm.password \"$password\""
            ;;
    esac

    # Add IPv4 configuration and auto-connect
    nmcli_cmd="$nmcli_cmd ipv4.method auto connection.autoconnect yes"

    # Execute
    lte_log "Creating connection: $con_name"
    if eval "$nmcli_cmd" 2>&1; then
        lte_success "LTE connection '$con_name' created successfully"
        lte_log "  Interface: $modem_device"
        lte_log "  APN: $apn"

        # Export connection details
        export LTE_MODEM_DEVICE="$modem_device"
        export LTE_NM_CONNECTION="$con_name"

        # Try to bring up the connection with retry logic
        lte_log "Activating LTE connection..."
        local activation_success=false
        local retry_count=0
        local max_retries=3

        while [ "$retry_count" -lt "$max_retries" ]; do
            local activation_output
            activation_output=$(nmcli con up "$con_name" 2>&1)
            local activation_rc=$?

            if [ "$activation_rc" -eq 0 ]; then
                lte_success "LTE connection '$con_name' activated"
                activation_success=true
                break
            else
                retry_count=$((retry_count + 1))
                if [ "$retry_count" -lt "$max_retries" ]; then
                    lte_warn "Activation attempt $retry_count failed, retrying in 3s..."
                    lte_log "  Error: $activation_output"
                    sleep 3
                else
                    lte_warn "Failed to activate connection after $max_retries attempts"
                    lte_log "  Last error: $activation_output"
                    lte_log "  Connection will auto-connect when modem is ready"
                fi
            fi
        done

        # Try to get the network interface that will be used
        local net_iface
        if [ "$activation_success" = true ]; then
            # Wait a moment for interface to appear
            sleep 2
        fi
        net_iface=$(get_modem_interface 2>/dev/null)
        [ -n "$net_iface" ] && export LTE_INTERFACE="$net_iface"

        # Show connection status
        lte_log "Connection status:"
        nmcli con show "$con_name" 2>/dev/null | grep -E "^connection\.(id|type|interface-name|autoconnect)" | while read -r line; do
            lte_log "  $line"
        done

        return 0
    fi

    lte_error "Failed to create nmcli connection"
    return 1
}

configure_apn_modemmanager() {
    # Configure APN using ModemManager (mmcli)

    local apn="$1"
    local auth_type="$2"
    local username="$3"
    local password="$4"
    local modem_idx="${5:-0}"

    if ! command -v mmcli &>/dev/null; then
        lte_warn "ModemManager not available"
        return 1
    fi

    # Ensure ModemManager is running
    if ! systemctl is-active ModemManager &>/dev/null; then
        systemctl start ModemManager 2>/dev/null || true
        sleep 2
    fi

    lte_log "Configuring LTE via ModemManager (modem: $modem_idx)"

    # Build connection string
    local connect_str="apn=$apn"

    if [ "$auth_type" != "none" ] && [ -n "$username" ]; then
        connect_str="${connect_str},user=$username"
        [ -n "$password" ] && connect_str="${connect_str},password=$password"
    fi

    # Enable modem first
    mmcli -m "$modem_idx" -e 2>/dev/null || true
    sleep 1

    # Connect with APN
    if mmcli -m "$modem_idx" --simple-connect="$connect_str" 2>/dev/null; then
        lte_success "LTE connected via ModemManager"

        # Get the bearer interface
        local bearer_iface
        bearer_iface=$(mmcli -m "$modem_idx" 2>/dev/null | grep -E "primary port:|interface:" | awk '{print $NF}' | head -1)

        if [ -n "$bearer_iface" ]; then
            export LTE_INTERFACE="$bearer_iface"
        fi

        return 0
    fi

    lte_warn "Failed to connect via ModemManager"
    return 1
}

configure_apn_qmi() {
    # Configure APN using QMI directly (for Quectel, Sierra modems)

    local apn="$1"
    local username="$2"
    local password="$3"

    if ! command -v qmicli &>/dev/null; then
        lte_warn "QMI tools not available"
        return 1
    fi

    # Find QMI device
    local qmi_dev=""
    for dev in /dev/cdc-wdm*; do
        if [ -c "$dev" ]; then
            qmi_dev="$dev"
            break
        fi
    done

    if [ -z "$qmi_dev" ]; then
        lte_warn "No QMI device found"
        return 1
    fi

    lte_log "Configuring LTE via QMI ($qmi_dev)"

    # Build network string
    local network_str="apn=$apn"
    [ -n "$username" ] && network_str="${network_str},username=$username"
    [ -n "$password" ] && network_str="${network_str},password=$password"

    if qmicli -d "$qmi_dev" --wds-start-network="$network_str" --client-no-release-cid 2>/dev/null; then
        lte_success "LTE connected via QMI"

        # Get WWAN interface
        local wwan_iface
        for iface in /sys/class/net/wwan*; do
            if [ -d "$iface" ]; then
                wwan_iface=$(basename "$iface")
                export LTE_INTERFACE="$wwan_iface"
                break
            fi
        done 2>/dev/null

        return 0
    fi

    lte_warn "Failed to connect via QMI"
    return 1
}

# ============================================================
# INTERACTIVE APN CONFIGURATION
# ============================================================

configure_apn_interactive() {
    # Interactive APN configuration with prompts

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  LTE APN Configuration${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""

    # First, detect and show modem information
    echo -e "${YELLOW}Detecting LTE modem...${NC}"
    local modem_device=""
    local modem_info=""

    # Find modem control device
    for dev in /dev/cdc-wdm*; do
        if [ -c "$dev" ]; then
            modem_device=$(basename "$dev")
            break
        fi
    done 2>/dev/null

    if [ -z "$modem_device" ]; then
        # Try ttyUSB
        for dev in /dev/ttyUSB*; do
            if [ -c "$dev" ]; then
                modem_device=$(basename "$dev")
                break
            fi
        done 2>/dev/null
    fi

    if [ -z "$modem_device" ]; then
        echo -e "${RED}No LTE modem detected!${NC}"
        echo "Please ensure your LTE modem is:"
        echo "  1. Plugged in via USB"
        echo "  2. Powered on"
        echo "  3. Detected by the system (check 'lsusb')"
        return 1
    fi

    echo -e "${GREEN}✓ Found modem: $modem_device${NC}"

    # Show ModemManager info if available
    if command -v mmcli &>/dev/null && systemctl is-active ModemManager &>/dev/null 2>&1; then
        local mm_info
        mm_info=$(mmcli -m 0 2>/dev/null | grep -E "manufacturer|model|state" | head -3)
        if [ -n "$mm_info" ]; then
            echo "$mm_info" | while read -r line; do
                echo "  $line"
            done
        fi
    fi

    echo ""

    # APN Name
    local apn=""
    echo "Common APNs by carrier:"
    echo "  Vodafone:  internet.vodafone.ro, web.vodafone.de, internet"
    echo "  Orange:    internet, orange.ro, orange"
    echo "  T-Mobile:  internet.t-mobile, fast.t-mobile.com"
    echo "  AT&T:      broadband, phone"
    echo "  Verizon:   vzwinternet"
    echo ""
    read -p "Enter your APN name: " apn
    [ -z "$apn" ] && { lte_error "APN is required"; return 1; }

    # Authentication type
    echo ""
    echo "Authentication types:"
    echo "  1. none     - No authentication (most carriers)"
    echo "  2. pap      - PAP authentication"
    echo "  3. chap     - CHAP authentication"
    echo "  4. mschapv2 - MS-CHAPv2 (enterprise/private APNs)"
    echo ""

    local auth_choice=""
    read -p "Select authentication type [1-4] (default: 1): " auth_choice
    auth_choice="${auth_choice:-1}"

    local auth_type="none"
    case "$auth_choice" in
        1) auth_type="none" ;;
        2) auth_type="pap" ;;
        3) auth_type="chap" ;;
        4) auth_type="mschapv2" ;;
        *) auth_type="none" ;;
    esac

    # Username and password if needed
    local username=""
    local password=""

    if [ "$auth_type" != "none" ]; then
        echo ""
        read -p "Enter username: " username
        read -sp "Enter password: " password
        echo ""
    fi

    # Confirm
    echo ""
    echo "Configuration summary:"
    echo "  APN:            $apn"
    echo "  Authentication: $auth_type"
    [ -n "$username" ] && echo "  Username:       $username"
    echo ""

    read -p "Apply this configuration? [Y/n]: " confirm
    confirm="${confirm:-Y}"

    if [[ "${confirm,,}" =~ ^y ]]; then
        configure_modem_apn "$apn" "$auth_type" "$username" "$password"
        return $?
    else
        lte_log "Configuration cancelled"
        return 1
    fi
}

quick_setup_lte() {
    # Quick LTE setup - auto-detect modem and configure with provided APN
    #
    # Usage:
    #   quick_setup_lte <apn>
    #   quick_setup_lte internet.vodafone.ro
    #
    # This function:
    #   1. Auto-detects the modem control device (cdc-wdm*)
    #   2. Creates a NetworkManager GSM connection
    #   3. Brings up the connection

    local apn="$1"

    if [ -z "$apn" ]; then
        echo "Usage: quick_setup_lte <apn>"
        echo ""
        echo "Examples:"
        echo "  quick_setup_lte internet.vodafone.ro"
        echo "  quick_setup_lte web.vodafone.de"
        echo "  quick_setup_lte internet"
        echo ""
        echo "For interactive setup with auth options, use:"
        echo "  configure_apn_interactive"
        return 1
    fi

    lte_log "Quick LTE Setup"
    lte_log "  APN: $apn"

    # Detect modem
    local modem_device=""
    for dev in /dev/cdc-wdm*; do
        [ -c "$dev" ] && modem_device=$(basename "$dev") && break
    done 2>/dev/null

    if [ -z "$modem_device" ]; then
        lte_error "No modem device found (no /dev/cdc-wdm* devices)"
        lte_error "Make sure your LTE modem is connected"
        return 1
    fi

    lte_log "  Device: $modem_device"

    # Delete existing connection
    nmcli con delete fortress-lte 2>/dev/null || true

    # Create new connection
    if nmcli con add type gsm ifname "$modem_device" con-name fortress-lte apn "$apn" ipv4.method auto; then
        lte_success "LTE connection 'fortress-lte' created"

        # Try to bring it up
        lte_log "Activating connection..."
        if nmcli con up fortress-lte 2>&1; then
            lte_success "LTE connected!"

            # Show connection info
            echo ""
            nmcli con show fortress-lte | grep -E "GENERAL|IP4" | head -10
        else
            lte_warn "Connection created but failed to activate"
            lte_warn "Try manually: nmcli con up fortress-lte"
        fi
        return 0
    else
        lte_error "Failed to create connection"
        return 1
    fi
}

connect_lte_modem() {
    # Connect LTE modem and bring up interface
    #
    # Args:
    #   $1 - Modem index (optional)

    local modem_idx="${1:-0}"

    lte_log "Connecting LTE modem $modem_idx..."

    # Ensure ModemManager is running
    if ! systemctl is-active ModemManager &>/dev/null; then
        systemctl start ModemManager
        sleep 2
    fi

    if command -v mmcli &>/dev/null; then
        # Enable modem
        mmcli -m "$modem_idx" -e 2>/dev/null || true

        # Check if already connected
        local state
        state=$(mmcli -m "$modem_idx" 2>/dev/null | grep "state:" | awk '{print $NF}')

        if [ "$state" = "connected" ]; then
            lte_success "Modem already connected"
            return 0
        fi

        # Connect with configured APN
        local apn
        apn=$(grep "^LTE_APN=" "$LTE_CONFIG_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"')

        if [ -n "$apn" ]; then
            mmcli -m "$modem_idx" --simple-connect="apn=$apn" 2>/dev/null && {
                lte_success "LTE connected with APN: $apn"
                return 0
            }
        else
            # Try to connect without explicit APN (auto-detect)
            mmcli -m "$modem_idx" --simple-connect="" 2>/dev/null && {
                lte_success "LTE connected (auto APN)"
                return 0
            }
        fi
    fi

    lte_error "Failed to connect LTE modem"
    return 1
}

disconnect_lte_modem() {
    # Disconnect LTE modem
    local modem_idx="${1:-0}"

    lte_log "Disconnecting LTE modem $modem_idx..."

    if command -v mmcli &>/dev/null; then
        mmcli -m "$modem_idx" --simple-disconnect 2>/dev/null
        lte_success "LTE disconnected"
    fi
}

get_lte_signal_strength() {
    # Get LTE signal strength
    #
    # Returns: Signal quality percentage (0-100)

    local modem_idx="${1:-0}"

    if command -v mmcli &>/dev/null; then
        local signal
        signal=$(mmcli -m "$modem_idx" --signal-get 2>/dev/null | grep "quality" | awk '{print $NF}' | tr -d '%')

        if [ -n "$signal" ]; then
            echo "$signal"
            return 0
        fi
    fi

    echo "0"
}

# ============================================================
# WAN FAILOVER (Metric-Based)
# ============================================================
#
# Simplified failover using route metrics:
#   - Primary WAN (Ethernet): metric 100 (preferred)
#   - Backup WAN (LTE):       metric 200 (fallback)
#
# The kernel automatically uses the lowest-metric available route.
# When primary goes down, traffic automatically fails over to LTE.
# When primary recovers, traffic automatically switches back.
#
# No monitoring daemon required - NetworkManager handles this!

# Metric values (lower = higher priority)
PRIMARY_WAN_METRIC=100
LTE_WAN_METRIC=200

setup_wan_failover() {
    # Set up WAN failover using route metrics
    #
    # This approach is simpler and more reliable than script-based failover:
    #   1. Configure primary WAN with metric 100
    #   2. Configure LTE with metric 200
    #   3. Both routes exist simultaneously
    #   4. Kernel automatically handles failover based on link state
    #
    # Args:
    #   $1 - Primary WAN interface
    #   $2 - LTE interface (optional, auto-detected)

    local primary_wan="${1:-$FORTRESS_WAN_IFACE}"
    local lte_iface="${2:-$(get_modem_interface)}"

    [ -z "$primary_wan" ] && { lte_error "Primary WAN interface required"; return 1; }
    [ -z "$lte_iface" ] && { lte_error "LTE interface not found"; return 1; }

    lte_log "Setting up metric-based WAN failover:"
    lte_log "  Primary: $primary_wan (metric $PRIMARY_WAN_METRIC)"
    lte_log "  Backup:  $lte_iface (metric $LTE_WAN_METRIC)"

    # Create state directory
    mkdir -p "$LTE_STATE_DIR"

    # Save failover configuration
    cat > "$LTE_STATE_DIR/failover.conf" << EOF
# Fortress WAN Failover Configuration (Metric-Based)
# Generated: $(date -Iseconds)
#
# How it works:
#   - Primary route has metric $PRIMARY_WAN_METRIC (lower = preferred)
#   - LTE route has metric $LTE_WAN_METRIC (higher = fallback)
#   - Kernel automatically uses lowest-metric available route
#   - No monitoring daemon needed - NetworkManager handles failover
#
PRIMARY_WAN="$primary_wan"
PRIMARY_WAN_METRIC=$PRIMARY_WAN_METRIC
BACKUP_WAN="$lte_iface"
BACKUP_WAN_METRIC=$LTE_WAN_METRIC
EOF

    # Configure route metrics
    setup_metric_failover "$primary_wan" "$lte_iface"

    lte_success "Metric-based WAN failover configured"
    lte_log ""
    lte_log "Validation: Run 'ip route' to verify metrics:"
    lte_log "  - Primary should have metric $PRIMARY_WAN_METRIC"
    lte_log "  - LTE should have metric $LTE_WAN_METRIC"
}

setup_metric_failover() {
    # Configure route metrics for automatic failover
    #
    # Args:
    #   $1 - Primary WAN interface
    #   $2 - LTE interface

    local primary="$1"
    local lte="$2"

    lte_log "Configuring route metrics..."

    # Method 1: Configure via NetworkManager (preferred)
    if command -v nmcli &>/dev/null; then
        configure_nm_metrics "$primary" "$lte"
        return $?
    fi

    # Method 2: Direct route manipulation (fallback)
    configure_direct_metrics "$primary" "$lte"
}

configure_nm_metrics() {
    # Configure metrics via NetworkManager connection profiles
    #
    # This is the cleanest approach - NM handles everything automatically

    local primary="$1"
    local lte="$2"

    lte_log "Configuring NetworkManager route metrics..."

    # Find and update primary WAN connection
    local primary_con
    primary_con=$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | grep ":${primary}$" | cut -d: -f1 | head -1)

    if [ -n "$primary_con" ]; then
        lte_log "  Setting $primary_con (primary) metric to $PRIMARY_WAN_METRIC"
        nmcli con mod "$primary_con" ipv4.route-metric "$PRIMARY_WAN_METRIC" 2>/dev/null || true
        nmcli con mod "$primary_con" ipv6.route-metric "$PRIMARY_WAN_METRIC" 2>/dev/null || true
    else
        # Try to find by device type
        primary_con=$(nmcli -t -f NAME,TYPE con show 2>/dev/null | grep -E "ethernet|802-3-ethernet" | cut -d: -f1 | head -1)
        if [ -n "$primary_con" ]; then
            lte_log "  Setting $primary_con (ethernet) metric to $PRIMARY_WAN_METRIC"
            nmcli con mod "$primary_con" ipv4.route-metric "$PRIMARY_WAN_METRIC" 2>/dev/null || true
        fi
    fi

    # Find and update LTE connection
    local lte_con
    lte_con=$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | grep ":${lte}$" | cut -d: -f1 | head -1)

    if [ -z "$lte_con" ]; then
        # Try fortress-lte connection
        lte_con="fortress-lte"
    fi

    if nmcli con show "$lte_con" &>/dev/null; then
        lte_log "  Setting $lte_con (LTE) metric to $LTE_WAN_METRIC"
        nmcli con mod "$lte_con" ipv4.route-metric "$LTE_WAN_METRIC" 2>/dev/null || true
        nmcli con mod "$lte_con" ipv6.route-metric "$LTE_WAN_METRIC" 2>/dev/null || true
    fi

    # Reactivate connections to apply metrics
    [ -n "$primary_con" ] && nmcli con up "$primary_con" 2>/dev/null || true
    [ -n "$lte_con" ] && nmcli con up "$lte_con" 2>/dev/null || true

    return 0
}

configure_direct_metrics() {
    # Configure metrics via direct route manipulation
    #
    # Fallback when NetworkManager is not available

    local primary="$1"
    local lte="$2"

    lte_log "Configuring route metrics directly..."

    # Get current default routes
    local primary_gw lte_gw

    primary_gw=$(ip route show dev "$primary" 2>/dev/null | grep "^default" | awk '{print $3}' | head -1)
    lte_gw=$(ip route show dev "$lte" 2>/dev/null | grep "^default" | awk '{print $3}' | head -1)

    # Remove existing default routes and re-add with metrics
    if [ -n "$primary_gw" ]; then
        ip route del default via "$primary_gw" dev "$primary" 2>/dev/null || true
        ip route add default via "$primary_gw" dev "$primary" metric "$PRIMARY_WAN_METRIC" 2>/dev/null || true
        lte_log "  Primary route: default via $primary_gw dev $primary metric $PRIMARY_WAN_METRIC"
    fi

    if [ -n "$lte_gw" ]; then
        ip route del default via "$lte_gw" dev "$lte" 2>/dev/null || true
        ip route add default via "$lte_gw" dev "$lte" metric "$LTE_WAN_METRIC" 2>/dev/null || true
        lte_log "  LTE route: default via $lte_gw dev $lte metric $LTE_WAN_METRIC"
    fi

    return 0
}

validate_failover_metrics() {
    # Validate that failover is properly configured
    #
    # Returns: 0 if valid, 1 if issues found

    lte_log "Validating WAN failover configuration..."

    local errors=0

    # Load config
    if [ ! -f "$LTE_STATE_DIR/failover.conf" ]; then
        lte_error "Failover not configured (missing failover.conf)"
        return 1
    fi

    source "$LTE_STATE_DIR/failover.conf"

    # Check primary WAN route metric
    local primary_metric
    primary_metric=$(ip route show dev "$PRIMARY_WAN" 2>/dev/null | grep "^default" | grep -oE "metric [0-9]+" | awk '{print $2}')

    if [ -z "$primary_metric" ]; then
        lte_warn "Primary WAN ($PRIMARY_WAN) has no default route"
        errors=$((errors + 1))
    elif [ "$primary_metric" != "$PRIMARY_WAN_METRIC" ]; then
        lte_warn "Primary WAN metric is $primary_metric (expected $PRIMARY_WAN_METRIC)"
        errors=$((errors + 1))
    else
        lte_success "Primary WAN ($PRIMARY_WAN): metric $primary_metric ✓"
    fi

    # Check LTE route metric
    local lte_metric
    lte_metric=$(ip route show dev "$BACKUP_WAN" 2>/dev/null | grep "^default" | grep -oE "metric [0-9]+" | awk '{print $2}')

    if [ -z "$lte_metric" ]; then
        lte_warn "LTE ($BACKUP_WAN) has no default route (may be disconnected)"
    elif [ "$lte_metric" != "$BACKUP_WAN_METRIC" ]; then
        lte_warn "LTE metric is $lte_metric (expected $BACKUP_WAN_METRIC)"
        errors=$((errors + 1))
    else
        lte_success "LTE ($BACKUP_WAN): metric $lte_metric ✓"
    fi

    # Check metric ordering (primary should be lower than LTE)
    if [ -n "$primary_metric" ] && [ -n "$lte_metric" ]; then
        if [ "$primary_metric" -lt "$lte_metric" ]; then
            lte_success "Route priority: Primary < LTE ✓"
        else
            lte_error "Route priority wrong: Primary ($primary_metric) >= LTE ($lte_metric)"
            errors=$((errors + 1))
        fi
    fi

    # Show current routing table
    lte_log ""
    lte_log "Current default routes:"
    ip route show default 2>/dev/null | while read -r line; do
        lte_log "  $line"
    done

    if [ "$errors" -gt 0 ]; then
        lte_error "Validation found $errors issue(s)"
        return 1
    fi

    lte_success "WAN failover validation passed"
    return 0
}

# Keep old function names for backward compatibility
setup_failover_routing() {
    # Deprecated: Use setup_metric_failover instead
    lte_warn "setup_failover_routing is deprecated, using metric-based failover"
    setup_metric_failover "$@"
}

check_wan_health() {
    # Check if WAN interface has connectivity
    #
    # Args:
    #   $1 - Interface name
    #
    # Returns: 0 if healthy, 1 if not

    local iface="$1"
    local hosts="${HEALTH_CHECK_HOSTS:-1.1.1.1 8.8.8.8}"

    # Check if interface is up
    if ! ip link show "$iface" 2>/dev/null | grep -q "state UP"; then
        return 1
    fi

    # Check if interface has IP
    if ! ip addr show "$iface" 2>/dev/null | grep -q "inet "; then
        return 1
    fi

    # Ping test through specific interface
    for host in $hosts; do
        if ping -c 1 -W 3 -I "$iface" "$host" &>/dev/null; then
            return 0
        fi
    done

    return 1
}

perform_failover() {
    # Execute failover from primary to backup WAN
    #
    # Args:
    #   $1 - Direction: "to_backup" or "to_primary"

    local direction="${1:-to_backup}"

    source "$LTE_STATE_DIR/failover.conf" 2>/dev/null || return 1

    local current_state
    current_state=$(cat "$FAILOVER_STATE_FILE" 2>/dev/null || echo "primary")

    if [ "$direction" = "to_backup" ] && [ "$current_state" = "primary" ]; then
        lte_warn "FAILOVER: Switching from $PRIMARY_WAN to $BACKUP_WAN (LTE)"

        # Connect LTE if not connected
        connect_lte_modem

        # Update default route
        local backup_gw
        backup_gw=$(ip route show dev "$BACKUP_WAN" 2>/dev/null | grep default | awk '{print $3}')

        if [ -n "$backup_gw" ]; then
            # Remove primary default route
            ip route del default via "$(ip route show dev "$PRIMARY_WAN" | grep default | awk '{print $3}')" 2>/dev/null || true

            # Add backup default route
            ip route add default via "$backup_gw" dev "$BACKUP_WAN" metric 100 2>/dev/null || true
        fi

        # Update state
        echo "backup" > "$FAILOVER_STATE_FILE"
        lte_success "Failover complete - now using LTE"

    elif [ "$direction" = "to_primary" ] && [ "$current_state" = "backup" ]; then
        lte_log "FAILBACK: Switching from $BACKUP_WAN (LTE) to $PRIMARY_WAN"

        # Update default route
        local primary_gw
        primary_gw=$(ip route show dev "$PRIMARY_WAN" 2>/dev/null | grep default | awk '{print $3}')

        if [ -n "$primary_gw" ]; then
            # Remove backup default route
            ip route del default via "$(ip route show dev "$BACKUP_WAN" | grep default | awk '{print $3}')" 2>/dev/null || true

            # Add primary default route
            ip route add default via "$primary_gw" dev "$PRIMARY_WAN" metric 50 2>/dev/null || true
        fi

        # Update state
        echo "primary" > "$FAILOVER_STATE_FILE"
        lte_success "Failback complete - now using primary WAN"
    fi
}

monitor_wan_failover() {
    # Continuous WAN health monitoring loop
    # Runs in background, checks health and performs failover as needed

    source "$LTE_STATE_DIR/failover.conf" 2>/dev/null || { lte_error "Failover not configured"; return 1; }

    local primary_failures=0
    local backup_available=false

    lte_log "Starting WAN failover monitor..."
    lte_log "  Checking every ${HEALTH_CHECK_INTERVAL}s"
    lte_log "  Failover after $FAILOVER_THRESHOLD consecutive failures"

    while true; do
        local current_state
        current_state=$(cat "$FAILOVER_STATE_FILE" 2>/dev/null || echo "primary")

        # Check primary WAN
        if check_wan_health "$PRIMARY_WAN"; then
            primary_failures=0

            # If on backup, try to failback
            if [ "$current_state" = "backup" ]; then
                perform_failover "to_primary"
            fi
        else
            primary_failures=$((primary_failures + 1))
            lte_warn "Primary WAN ($PRIMARY_WAN) unhealthy (failures: $primary_failures/$FAILOVER_THRESHOLD)"

            # Check if failover threshold reached
            if [ "$primary_failures" -ge "$FAILOVER_THRESHOLD" ] && [ "$current_state" = "primary" ]; then
                # Check if backup is available
                if check_wan_health "$BACKUP_WAN" 2>/dev/null || connect_lte_modem; then
                    perform_failover "to_backup"
                else
                    lte_error "Primary WAN down, LTE backup unavailable!"
                fi
            fi
        fi

        sleep "$HEALTH_CHECK_INTERVAL"
    done
}

# ============================================================
# SYSTEMD SERVICE
# ============================================================

install_failover_service() {
    # Install systemd service for WAN failover monitoring

    lte_log "Installing WAN failover systemd service..."

    cat > /etc/systemd/system/fortress-wan-failover.service << 'EOF'
[Unit]
Description=HookProbe Fortress WAN Failover Monitor
After=network-online.target ModemManager.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/hookprobe/fortress/devices/common/lte-manager.sh monitor
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable fortress-wan-failover.service
    lte_success "WAN failover service installed"
}

# ============================================================
# MAIN
# ============================================================

show_lte_status() {
    # Display current LTE modem and failover status

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  HookProbe Fortress - LTE Status${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""

    # Detect modems
    detect_usb_lte_modems

    echo ""

    # Show signal strength
    local signal=$(get_lte_signal_strength)
    echo -e "  ${GREEN}Signal:${NC}     $signal%"

    # Show failover state
    if [ -f "$FAILOVER_STATE_FILE" ]; then
        local state=$(cat "$FAILOVER_STATE_FILE")
        echo -e "  ${GREEN}Failover:${NC}   $state"
    else
        echo -e "  ${GREEN}Failover:${NC}   Not configured"
    fi

    # Show interface
    local lte_iface=$(get_modem_interface)
    if [ -n "$lte_iface" ]; then
        echo -e "  ${GREEN}Interface:${NC}  $lte_iface"
        local lte_ip=$(ip addr show "$lte_iface" 2>/dev/null | grep "inet " | awk '{print $2}')
        echo -e "  ${GREEN}IP:${NC}         ${lte_ip:-Not assigned}"
    fi

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  detect                    - Detect LTE modems"
    echo "  status                    - Show LTE and failover status"
    echo "  configure                 - Interactive APN configuration"
    echo "  configure-apn <apn> [auth] [user] [pass]"
    echo "                            - Configure APN with authentication"
    echo "                              auth: none, pap, chap, mschapv2"
    echo "  connect                   - Connect LTE modem"
    echo "  disconnect                - Disconnect LTE modem"
    echo "  setup-failover <primary_wan> [lte_iface]"
    echo "                            - Configure WAN failover (metric-based)"
    echo "  validate-failover         - Validate failover route metrics"
    echo "  monitor                   - Start failover monitoring (foreground)"
    echo "  install                   - Install failover systemd service"
    echo ""
    echo "Examples:"
    echo "  $0 detect"
    echo "  $0 configure"
    echo "  $0 configure-apn internet.vodafone.ro"
    echo "  $0 configure-apn private.apn chap myuser mypass"
    echo "  $0 setup-failover enp1s0 wwp0s20f0u4"
    echo "  $0 validate-failover"
    echo ""
    echo "Failover uses route metrics (no monitoring daemon required):"
    echo "  - Primary WAN: metric 100 (preferred)"
    echo "  - LTE backup:  metric 200 (fallback)"
    echo ""
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-}" in
        detect)
            detect_usb_lte_modems
            ;;
        status)
            show_lte_status
            ;;
        configure)
            configure_apn_interactive
            ;;
        configure-apn)
            configure_modem_apn "$2" "${3:-none}" "${4:-}" "${5:-}"
            ;;
        connect)
            connect_lte_modem "${2:-0}"
            ;;
        disconnect)
            disconnect_lte_modem "${2:-0}"
            ;;
        setup-failover)
            setup_wan_failover "$2" "$3"
            ;;
        validate-failover)
            validate_failover_metrics
            ;;
        monitor)
            monitor_wan_failover
            ;;
        install)
            install_failover_service
            ;;
        *)
            usage
            ;;
    esac
fi
