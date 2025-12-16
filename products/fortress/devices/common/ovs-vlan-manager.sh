#!/bin/bash
#
# ovs-vlan-manager.sh - OVS-based VLAN Management for Network Segmentation
# Part of HookProbe Fortress - Small Business Security Gateway
#
# Implements SDN-based VLAN assignment using Open vSwitch:
#   - MAC-to-VLAN mapping via OVS flow rules
#   - OUI-based automatic device classification
#   - Dynamic VLAN reassignment without disconnection
#   - Home Assistant / IoT device isolation
#
# VLAN Layout:
#   10 = Management (admin devices, Fortress itself)
#   20 = POS (payment terminals, registers)
#   30 = Staff (employee devices, laptops, phones)
#   40 = Guest (customers, visitors) - DEFAULT
#   99 = IoT (cameras, sensors, smart devices, Home Assistant)
#
# Version: 1.0.0
# License: AGPL-3.0
#

set -e

# Configuration
OVS_BRIDGE="${FORTRESS_OVS_BRIDGE:-fortress-br}"
OUI_RULES_FILE="${FORTRESS_OUI_RULES:-/etc/fortress/oui_vlan_rules.conf}"
MAC_VLAN_FILE="${FORTRESS_MAC_VLAN:-/etc/fortress/mac_vlan.conf}"
STATE_DIR="/var/lib/fortress/vlan"
LOG_FILE="/var/log/fortress/vlan-manager.log"

# VLAN IDs
VLAN_MGMT=10
VLAN_POS=20
VLAN_STAFF=30
VLAN_GUEST=40
VLAN_IOT=99

# Default VLAN for unknown devices
DEFAULT_VLAN=$VLAN_GUEST

# Flow priority levels
PRIORITY_MANUAL=300      # Manually assigned MACs
PRIORITY_OUI=200         # OUI-based assignment
PRIORITY_DEFAULT=100     # Default VLAN

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[VLAN]${NC} $(date '+%H:%M:%S') $*" | tee -a "$LOG_FILE" 2>/dev/null; }
log_success() { echo -e "${GREEN}[VLAN]${NC} $(date '+%H:%M:%S') $*" | tee -a "$LOG_FILE" 2>/dev/null; }
log_warn() { echo -e "${YELLOW}[VLAN]${NC} $(date '+%H:%M:%S') $*" | tee -a "$LOG_FILE" 2>/dev/null; }
log_error() { echo -e "${RED}[VLAN]${NC} $(date '+%H:%M:%S') $*" | tee -a "$LOG_FILE" 2>/dev/null; }

# ============================================================
# OVS BRIDGE SETUP
# ============================================================

check_ovs() {
    if ! command -v ovs-vsctl &>/dev/null; then
        log_error "Open vSwitch not installed. Install with: apt install openvswitch-switch"
        return 1
    fi

    if ! systemctl is-active --quiet openvswitch-switch; then
        log_warn "OVS not running, starting..."
        systemctl start openvswitch-switch
    fi

    return 0
}

create_ovs_bridge() {
    # Create the main OVS bridge for Fortress

    check_ovs || return 1

    if ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
        log_info "OVS bridge $OVS_BRIDGE already exists"
        return 0
    fi

    log_info "Creating OVS bridge: $OVS_BRIDGE"
    ovs-vsctl add-br "$OVS_BRIDGE"

    # Enable STP
    ovs-vsctl set bridge "$OVS_BRIDGE" stp_enable=true

    # Set bridge MAC learning
    ovs-vsctl set bridge "$OVS_BRIDGE" other_config:mac-aging-time=300

    log_success "Created OVS bridge $OVS_BRIDGE"
}

add_interface_to_bridge() {
    local iface="$1"
    local vlan_mode="${2:-access}"  # access, trunk, or native-untagged
    local vlan_id="${3:-$DEFAULT_VLAN}"

    check_ovs || return 1

    # Check if interface exists
    if ! ip link show "$iface" &>/dev/null; then
        log_error "Interface $iface does not exist"
        return 1
    fi

    # Check if already in bridge
    if ovs-vsctl port-to-br "$iface" 2>/dev/null | grep -q "$OVS_BRIDGE"; then
        log_info "Interface $iface already in $OVS_BRIDGE"
        return 0
    fi

    log_info "Adding $iface to $OVS_BRIDGE (mode=$vlan_mode, vlan=$vlan_id)"

    case "$vlan_mode" in
        access)
            # Access port - all traffic tagged with single VLAN
            ovs-vsctl add-port "$OVS_BRIDGE" "$iface" tag="$vlan_id"
            ;;
        trunk)
            # Trunk port - carries multiple VLANs
            ovs-vsctl add-port "$OVS_BRIDGE" "$iface" trunks="$VLAN_MGMT,$VLAN_POS,$VLAN_STAFF,$VLAN_GUEST,$VLAN_IOT"
            ;;
        native-untagged)
            # Native untagged with trunk - for uplink
            ovs-vsctl add-port "$OVS_BRIDGE" "$iface" \
                tag="$vlan_id" \
                vlan_mode=native-untagged \
                trunks="$VLAN_MGMT,$VLAN_POS,$VLAN_STAFF,$VLAN_GUEST,$VLAN_IOT"
            ;;
        *)
            # No VLAN config - WiFi interfaces (we'll use flow rules)
            ovs-vsctl add-port "$OVS_BRIDGE" "$iface"
            ;;
    esac

    # Bring interface up
    ip link set "$iface" up

    log_success "Added $iface to bridge"
}

# ============================================================
# VLAN INTERNAL PORTS
# ============================================================

create_vlan_interfaces() {
    # Create internal OVS ports for each VLAN
    # These act as the gateway interfaces for each network segment

    local vlans="$VLAN_MGMT $VLAN_POS $VLAN_STAFF $VLAN_GUEST $VLAN_IOT"
    local vlan_names="mgmt pos staff guest iot"

    local i=1
    for vlan_id in $vlans; do
        local vlan_name
        vlan_name=$(echo "$vlan_names" | cut -d' ' -f$i)
        local port_name="vlan${vlan_id}"

        # Check if port exists
        if ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null | grep -q "^${port_name}$"; then
            log_info "VLAN port $port_name already exists"
        else
            log_info "Creating VLAN port: $port_name (VLAN $vlan_id - $vlan_name)"

            ovs-vsctl add-port "$OVS_BRIDGE" "$port_name" \
                -- set interface "$port_name" type=internal \
                -- set port "$port_name" tag="$vlan_id"
        fi

        # Configure IP address based on VLAN
        local gateway_ip="10.${vlan_id}.1.1"
        local network="10.${vlan_id}.1.0/24"

        ip link set "$port_name" up 2>/dev/null || true

        if ! ip addr show "$port_name" 2>/dev/null | grep -q "$gateway_ip"; then
            ip addr add "${gateway_ip}/24" dev "$port_name" 2>/dev/null || true
            log_info "  Gateway: $gateway_ip"
        fi

        i=$((i + 1))
    done

    log_success "VLAN interfaces created"
}

# ============================================================
# MAC-TO-VLAN FLOW RULES
# ============================================================

add_mac_vlan_flow() {
    # Add OVS flow rule to assign a MAC address to a VLAN
    #
    # Args:
    #   $1 - MAC address (xx:xx:xx:xx:xx:xx)
    #   $2 - VLAN ID
    #   $3 - Priority (optional, default OUI priority)
    #   $4 - Reason (for logging)

    local mac="${1^^}"  # Uppercase MAC
    local vlan_id="$2"
    local priority="${3:-$PRIORITY_OUI}"
    local reason="${4:-manual}"

    # Normalize MAC format
    mac=$(echo "$mac" | sed 's/-/:/g')

    # Validate MAC format
    if ! echo "$mac" | grep -qE '^([0-9A-F]{2}:){5}[0-9A-F]{2}$'; then
        log_error "Invalid MAC address: $mac"
        return 1
    fi

    # Validate VLAN
    case "$vlan_id" in
        $VLAN_MGMT|$VLAN_POS|$VLAN_STAFF|$VLAN_GUEST|$VLAN_IOT)
            ;;
        *)
            log_error "Invalid VLAN ID: $vlan_id (valid: $VLAN_MGMT, $VLAN_POS, $VLAN_STAFF, $VLAN_GUEST, $VLAN_IOT)"
            return 1
            ;;
    esac

    # Remove existing flow for this MAC (if any)
    ovs-ofctl del-flows "$OVS_BRIDGE" "dl_src=$mac" 2>/dev/null || true
    ovs-ofctl del-flows "$OVS_BRIDGE" "dl_dst=$mac" 2>/dev/null || true

    # Add ingress flow: Tag traffic FROM this MAC with VLAN
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=$priority,dl_src=$mac,actions=mod_vlan_vid:$vlan_id,normal"

    # Add egress flow: Allow traffic TO this MAC (strip VLAN tag for wireless)
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=$priority,dl_dst=$mac,dl_vlan=$vlan_id,actions=strip_vlan,normal"

    # Save to state file
    mkdir -p "$STATE_DIR"
    echo "$mac:$vlan_id:$priority:$reason:$(date -Iseconds)" >> "$STATE_DIR/assignments.log"

    # Update MAC→VLAN mapping file
    update_mac_vlan_file "$mac" "$vlan_id" "$reason"

    log_success "Assigned $mac → VLAN $vlan_id ($reason)"
}

remove_mac_vlan_flow() {
    # Remove VLAN assignment for a MAC address

    local mac="${1^^}"
    mac=$(echo "$mac" | sed 's/-/:/g')

    ovs-ofctl del-flows "$OVS_BRIDGE" "dl_src=$mac" 2>/dev/null || true
    ovs-ofctl del-flows "$OVS_BRIDGE" "dl_dst=$mac" 2>/dev/null || true

    # Remove from MAC→VLAN file
    if [ -f "$MAC_VLAN_FILE" ]; then
        sed -i "/^$mac:/Id" "$MAC_VLAN_FILE"
    fi

    log_info "Removed VLAN assignment for $mac"
}

update_mac_vlan_file() {
    # Update persistent MAC→VLAN mapping file

    local mac="$1"
    local vlan_id="$2"
    local reason="$3"

    mkdir -p "$(dirname "$MAC_VLAN_FILE")"

    # Remove existing entry for this MAC
    if [ -f "$MAC_VLAN_FILE" ]; then
        grep -v "^$mac:" "$MAC_VLAN_FILE" > "${MAC_VLAN_FILE}.tmp" 2>/dev/null || true
        mv "${MAC_VLAN_FILE}.tmp" "$MAC_VLAN_FILE"
    fi

    # Add new entry
    echo "${mac}:${vlan_id}:${reason}" >> "$MAC_VLAN_FILE"
}

# ============================================================
# OUI DATABASE MANAGEMENT
# ============================================================

lookup_oui_vlan() {
    # Look up VLAN assignment based on OUI (vendor)
    #
    # Args:
    #   $1 - MAC address
    #
    # Returns: VLAN ID or empty if not found

    local mac="${1^^}"
    local oui="${mac:0:8}"  # First 3 bytes (XX:XX:XX)

    if [ ! -f "$OUI_RULES_FILE" ]; then
        return
    fi

    # Search OUI rules file
    # Format: OUI:VLAN_ID:VENDOR_NAME
    while IFS=: read -r rule_oui vlan_id vendor_name; do
        # Skip comments and empty lines
        [[ "$rule_oui" =~ ^#.*$ ]] && continue
        [ -z "$rule_oui" ] && continue

        rule_oui="${rule_oui^^}"

        if [ "$oui" = "$rule_oui" ]; then
            echo "$vlan_id"
            return
        fi
    done < "$OUI_RULES_FILE"
}

get_vendor_name() {
    # Get vendor name from OUI
    local mac="${1^^}"
    local oui="${mac:0:8}"

    if [ ! -f "$OUI_RULES_FILE" ]; then
        echo "Unknown"
        return
    fi

    while IFS=: read -r rule_oui vlan_id vendor_name; do
        [[ "$rule_oui" =~ ^#.*$ ]] && continue
        [ -z "$rule_oui" ] && continue

        rule_oui="${rule_oui^^}"

        if [ "$oui" = "$rule_oui" ]; then
            echo "${vendor_name:-Unknown}"
            return
        fi
    done < "$OUI_RULES_FILE"

    echo "Unknown"
}

auto_assign_device() {
    # Automatically assign a device to VLAN based on OUI
    #
    # Priority:
    #   1. Manual assignment in mac_vlan.conf (highest)
    #   2. OUI-based rules
    #   3. Default to Guest VLAN

    local mac="${1^^}"
    mac=$(echo "$mac" | sed 's/-/:/g')

    # Check manual assignment first
    if [ -f "$MAC_VLAN_FILE" ]; then
        local manual_vlan
        manual_vlan=$(grep -i "^$mac:" "$MAC_VLAN_FILE" 2>/dev/null | cut -d: -f2)
        if [ -n "$manual_vlan" ]; then
            log_info "$mac: Using manual assignment → VLAN $manual_vlan"
            add_mac_vlan_flow "$mac" "$manual_vlan" "$PRIORITY_MANUAL" "manual"
            return 0
        fi
    fi

    # Check OUI rules
    local oui_vlan
    oui_vlan=$(lookup_oui_vlan "$mac")
    if [ -n "$oui_vlan" ]; then
        local vendor
        vendor=$(get_vendor_name "$mac")
        log_info "$mac: OUI match ($vendor) → VLAN $oui_vlan"
        add_mac_vlan_flow "$mac" "$oui_vlan" "$PRIORITY_OUI" "oui:$vendor"
        return 0
    fi

    # Default to Guest VLAN
    log_info "$mac: No rules matched → VLAN $DEFAULT_VLAN (Guest)"
    add_mac_vlan_flow "$mac" "$DEFAULT_VLAN" "$PRIORITY_DEFAULT" "default"
}

# ============================================================
# OUI RULES DATABASE
# ============================================================

create_oui_database() {
    # Create comprehensive OUI rules for common device types

    mkdir -p "$(dirname "$OUI_RULES_FILE")"

    cat > "$OUI_RULES_FILE" << 'EOF'
# Fortress OUI-to-VLAN Rules
# Format: OUI:VLAN_ID:VENDOR_NAME
#
# VLAN IDs:
#   10 = Management (admin devices)
#   20 = POS (payment terminals)
#   30 = Staff (employee devices)
#   40 = Guest (visitors) - DEFAULT
#   99 = IoT (smart devices, cameras, sensors)
#
# Add custom rules at the end of this file
# OUI format: XX:XX:XX (first 3 bytes of MAC address)

# ================================================
# IoT / Smart Home Devices → VLAN 99
# ================================================

# Home Assistant / Raspberry Pi
B8:27:EB:99:Raspberry Pi Foundation
DC:A6:32:99:Raspberry Pi Trading
E4:5F:01:99:Raspberry Pi Trading
28:CD:C1:99:Raspberry Pi Trading

# ESP8266/ESP32 (Espressif - common IoT)
24:0A:C4:99:Espressif
24:6F:28:99:Espressif
24:B2:DE:99:Espressif
30:AE:A4:99:Espressif
3C:61:05:99:Espressif
3C:71:BF:99:Espressif
40:F5:20:99:Espressif
4C:11:AE:99:Espressif
4C:75:25:99:Espressif
50:02:91:99:Espressif
58:BF:25:99:Espressif
5C:CF:7F:99:Espressif
60:01:94:99:Espressif
68:C6:3A:99:Espressif
7C:9E:BD:99:Espressif
7C:DF:A1:99:Espressif
80:64:6F:99:Espressif
80:7D:3A:99:Espressif
84:0D:8E:99:Espressif
84:CC:A8:99:Espressif
84:F3:EB:99:Espressif
8C:AA:B5:99:Espressif
8C:CE:4E:99:Espressif
90:38:0C:99:Espressif
94:B5:55:99:Espressif
98:CD:AC:99:Espressif
98:F4:AB:99:Espressif
A0:20:A6:99:Espressif
A4:7B:9D:99:Espressif
A4:CF:12:99:Espressif
A8:48:FA:99:Espressif
AC:0B:FB:99:Espressif
AC:67:B2:99:Espressif
B4:E6:2D:99:Espressif
B8:F0:09:99:Espressif
BC:DD:C2:99:Espressif
BC:FF:4D:99:Espressif
C4:4F:33:99:Espressif
C4:5B:BE:99:Espressif
C8:2B:96:99:Espressif
C8:C9:A3:99:Espressif
CC:50:E3:99:Espressif
CC:DB:A7:99:Espressif
D8:A0:1D:99:Espressif
D8:BF:C0:99:Espressif
D8:F1:5B:99:Espressif
DC:4F:22:99:Espressif
E0:98:06:99:Espressif
E8:68:E7:99:Espressif
E8:DB:84:99:Espressif
EC:FA:BC:99:Espressif
F0:08:D1:99:Espressif
F4:12:FA:99:Espressif
F4:CF:A2:99:Espressif
FC:F5:C4:99:Espressif

# Tuya/SmartLife devices
10:D5:61:99:Tuya
D8:1F:12:99:Tuya

# Shelly
34:94:54:99:Shelly
44:17:93:99:Shelly
98:CD:AC:99:Shelly (ESP)

# Sonoff
60:01:94:99:Sonoff (ESP)

# TP-Link Smart (Kasa, Tapo)
50:C7:BF:99:TP-Link Kasa
54:AF:97:99:TP-Link Tapo
5C:A6:E6:99:TP-Link Kasa
60:32:B1:99:TP-Link Kasa
68:FF:7B:99:TP-Link Kasa
B0:4E:26:99:TP-Link Kasa
B0:BE:76:99:TP-Link Tapo

# Philips Hue
00:17:88:99:Philips Hue
EC:B5:FA:99:Philips Hue

# IKEA Tradfri
00:0B:57:99:IKEA Tradfri
34:25:BE:99:IKEA Tradfri
90:FD:9F:99:IKEA Tradfri
94:8A:0A:99:IKEA Tradfri
CC:86:EC:99:IKEA Tradfri

# Ring doorbell/camera
9C:76:0E:99:Ring
0C:0E:76:99:Ring
04:B1:67:99:Ring

# Nest/Google Home
18:D6:C7:99:Google Nest
1C:F2:9A:99:Google Nest
20:DF:B9:99:Google Nest
30:FD:38:99:Google Nest
48:D6:D5:99:Google Nest
54:60:09:99:Google Home
98:DA:C4:99:Google Nest
A4:77:33:99:Google Nest
F4:F5:D8:99:Google Home
F4:F5:E8:99:Google Home

# Amazon Echo/Alexa
0C:47:C9:99:Amazon Echo
14:91:82:99:Amazon Echo
34:D2:70:99:Amazon Echo
3C:5C:C4:99:Amazon Echo
40:A2:DB:99:Amazon Echo
44:00:49:99:Amazon Echo
4C:EF:C0:99:Amazon Echo
50:DC:E7:99:Amazon Echo
50:F5:DA:99:Amazon Echo
68:37:E9:99:Amazon Echo
68:54:FD:99:Amazon Echo
74:C2:46:99:Amazon Echo
84:D6:D0:99:Amazon Echo
A0:02:DC:99:Amazon Echo
B4:7C:9C:99:Amazon Echo
F0:F0:A4:99:Amazon Echo
FC:65:DE:99:Amazon Echo

# Wyze cameras
2C:AA:8E:99:Wyze
7C:78:B2:99:Wyze

# Hikvision cameras
00:0C:B5:99:Hikvision
18:68:CB:99:Hikvision
28:57:BE:99:Hikvision
44:19:B6:99:Hikvision
54:C4:15:99:Hikvision
58:03:FB:99:Hikvision
64:F2:FB:99:Hikvision
BC:AD:28:99:Hikvision
C0:56:E3:99:Hikvision

# Dahua cameras
3C:EF:8C:99:Dahua
90:02:A9:99:Dahua
B0:A7:B9:99:Dahua
D4:43:0E:99:Dahua

# Reolink cameras
B4:6B:FC:99:Reolink
EC:71:DB:99:Reolink

# Eufy cameras
48:78:5E:99:Eufy
AC:6A:D9:99:Eufy

# Zigbee bridges
00:0D:6F:99:Zigbee/Ember
00:0B:57:99:Zigbee/IKEA
00:12:4B:99:Texas Instruments Zigbee

# Generic Smart Plugs/Switches
00:E0:4C:99:Realtek (generic IoT)
18:FE:34:99:Generic ESP8266
84:F3:EB:99:Generic ESP32

# ================================================
# POS/Payment Terminals → VLAN 20
# ================================================

# Verifone
00:50:10:20:Verifone
00:0D:41:20:Verifone
00:17:E8:20:Verifone

# Ingenico
00:07:81:20:Ingenico
00:18:0A:20:Ingenico
44:D5:F2:20:Ingenico

# Square
58:E6:BA:20:Square
60:03:08:20:Square

# Clover
04:CF:8C:20:Clover
A8:9C:ED:20:Clover

# PAX Technology
00:1F:71:20:PAX
C0:6C:0F:20:PAX

# SumUp
CC:F9:57:20:SumUp

# ================================================
# Staff Devices → VLAN 30
# ================================================

# Apple devices (staff typically have iPhones/MacBooks)
00:1C:B3:30:Apple
00:03:93:30:Apple
00:0A:27:30:Apple
00:0A:95:30:Apple
00:10:FA:30:Apple
00:11:24:30:Apple
00:14:51:30:Apple
00:16:CB:30:Apple
00:17:F2:30:Apple
00:19:E3:30:Apple
00:1B:63:30:Apple
00:1D:4F:30:Apple
00:1E:52:30:Apple
00:1E:C2:30:Apple
00:1F:5B:30:Apple
00:1F:F3:30:Apple
00:21:E9:30:Apple
00:22:41:30:Apple
00:23:12:30:Apple
00:23:32:30:Apple
00:23:6C:30:Apple
00:23:DF:30:Apple
00:24:36:30:Apple
00:25:00:30:Apple
00:25:4B:30:Apple
00:25:BC:30:Apple
00:26:08:30:Apple
00:26:4A:30:Apple
00:26:B0:30:Apple
00:26:BB:30:Apple
18:AF:8F:30:Apple
28:0B:5C:30:Apple
28:37:37:30:Apple
28:6A:B8:30:Apple
2C:F0:A2:30:Apple
3C:06:30:30:Apple
40:98:AD:30:Apple
44:D8:84:30:Apple
48:3B:38:30:Apple
4C:57:CA:30:Apple
50:EA:D6:30:Apple
54:26:96:30:Apple
54:4E:90:30:Apple
58:55:CA:30:Apple
5C:59:48:30:Apple
60:F8:1D:30:Apple
68:DB:CA:30:Apple
70:EC:E4:30:Apple
7C:6D:62:30:Apple
80:E6:50:30:Apple
84:38:35:30:Apple
88:66:A5:30:Apple
8C:7B:9D:30:Apple
90:84:0D:30:Apple
94:E9:79:30:Apple
98:FE:94:30:Apple
9C:8B:A0:30:Apple
A4:5E:60:30:Apple
A4:83:E7:30:Apple
A8:5C:2C:30:Apple
AC:61:EA:30:Apple
AC:BC:32:30:Apple
B0:34:95:30:Apple
B8:09:8A:30:Apple
B8:C1:11:30:Apple
BC:52:B7:30:Apple
C0:84:7A:30:Apple
C8:69:CD:30:Apple
CC:08:E0:30:Apple
D4:9A:20:30:Apple
D8:1D:72:30:Apple
DC:2B:2A:30:Apple
E0:AC:CB:30:Apple
E0:B9:BA:30:Apple
E4:8B:7F:30:Apple
E8:04:0B:30:Apple
F0:18:98:30:Apple
F0:B4:79:30:Apple
F4:5C:89:30:Apple
F8:4D:89:30:Apple
FC:E9:98:30:Apple

# ================================================
# Printers → VLAN 99 (IoT)
# ================================================

# HP Printers
00:1E:0B:99:HP
00:21:5A:99:HP Printer
00:23:7D:99:HP Printer
00:25:B3:99:HP Printer
1C:C1:DE:99:HP Printer
3C:D9:2B:99:HP Printer
48:0F:CF:99:HP Printer
64:51:06:99:HP Printer
6C:C2:17:99:HP Printer
80:CE:62:99:HP Printer
98:E7:F4:99:HP Printer
A0:D3:C1:99:HP Printer

# Canon Printers
00:1E:8F:99:Canon
18:0C:AC:99:Canon
74:E5:43:99:Canon

# Epson Printers
00:26:AB:99:Epson
3C:18:A0:99:Epson
44:D2:44:99:Epson
C8:2E:47:99:Epson

# Brother Printers
00:1B:A9:99:Brother
00:80:77:99:Brother
30:05:5C:99:Brother
C8:D9:D2:99:Brother

# ================================================
# Custom Rules (add yours here)
# ================================================

# Example: Put specific device on Management VLAN
# AA:BB:CC:10:My Admin Laptop

EOF

    log_success "Created OUI database at $OUI_RULES_FILE"
}

# ============================================================
# DEFAULT FLOW RULES
# ============================================================

setup_default_flows() {
    # Set up default OVS flow rules for VLAN handling

    log_info "Setting up default OVS flows..."

    # Clear existing flows (be careful in production!)
    # ovs-ofctl del-flows "$OVS_BRIDGE"

    # Default flow: unmatched traffic goes to Guest VLAN
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=$PRIORITY_DEFAULT,actions=mod_vlan_vid:$DEFAULT_VLAN,normal"

    # Allow ARP
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=500,arp,actions=normal"

    # Allow DHCP
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=500,udp,tp_dst=67,actions=normal"
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=500,udp,tp_dst=68,actions=normal"

    # Allow DNS
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=400,udp,tp_dst=53,actions=normal"
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=400,tcp,tp_dst=53,actions=normal"

    log_success "Default flows configured"
}

# ============================================================
# DEVICE MONITORING
# ============================================================

process_new_device() {
    # Called when a new device is detected on the network
    # Automatically assigns it to appropriate VLAN

    local mac="$1"
    local ip="${2:-}"
    local iface="${3:-}"

    log_info "New device detected: $mac (IP: ${ip:-unknown}, Interface: ${iface:-unknown})"

    auto_assign_device "$mac"
}

monitor_arp_for_devices() {
    # Monitor ARP for new device detection
    # This runs continuously and calls process_new_device for each new MAC

    log_info "Monitoring for new devices..."

    # Track seen MACs
    local seen_macs_file="$STATE_DIR/seen_macs.txt"
    mkdir -p "$STATE_DIR"
    touch "$seen_macs_file"

    while true; do
        # Get current ARP table
        ip neigh show | grep -E "lladdr" | while read -r line; do
            local ip mac
            ip=$(echo "$line" | awk '{print $1}')
            mac=$(echo "$line" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')

            [ -z "$mac" ] && continue

            mac="${mac^^}"

            # Check if we've seen this MAC before
            if ! grep -q "^$mac$" "$seen_macs_file" 2>/dev/null; then
                echo "$mac" >> "$seen_macs_file"
                process_new_device "$mac" "$ip"
            fi
        done

        sleep 5
    done
}

# ============================================================
# SHOW STATUS
# ============================================================

show_status() {
    echo ""
    echo "Fortress VLAN Manager Status"
    echo "============================"
    echo ""

    if ! ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
        echo "OVS Bridge: NOT CONFIGURED"
        echo ""
        echo "Run: $0 init"
        return
    fi

    echo "OVS Bridge: $OVS_BRIDGE"
    echo ""

    echo "Ports:"
    ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null | while read -r port; do
        local vlan
        vlan=$(ovs-vsctl get port "$port" tag 2>/dev/null | tr -d '[]')
        if [ -n "$vlan" ] && [ "$vlan" != "[]" ]; then
            echo "  $port (VLAN $vlan)"
        else
            echo "  $port (trunk/untagged)"
        fi
    done
    echo ""

    echo "VLAN Interfaces:"
    for vlan in $VLAN_MGMT $VLAN_POS $VLAN_STAFF $VLAN_GUEST $VLAN_IOT; do
        local port="vlan${vlan}"
        if ip link show "$port" &>/dev/null; then
            local ip
            ip=$(ip addr show "$port" 2>/dev/null | grep "inet " | awk '{print $2}')
            echo "  VLAN $vlan: $port (${ip:-no IP})"
        fi
    done
    echo ""

    echo "MAC→VLAN Assignments (from flows):"
    ovs-ofctl dump-flows "$OVS_BRIDGE" 2>/dev/null | grep "dl_src=" | while read -r flow; do
        local mac vlan
        mac=$(echo "$flow" | grep -oE 'dl_src=[^,]+' | cut -d= -f2)
        vlan=$(echo "$flow" | grep -oE 'mod_vlan_vid:[0-9]+' | cut -d: -f2)
        if [ -n "$mac" ] && [ -n "$vlan" ]; then
            local vendor
            vendor=$(get_vendor_name "$mac")
            echo "  $mac → VLAN $vlan ($vendor)"
        fi
    done
    echo ""

    echo "OUI Rules: $(wc -l < "$OUI_RULES_FILE" 2>/dev/null | tr -d ' ') entries"
    echo ""
}

show_flows() {
    echo "OVS Flow Table for $OVS_BRIDGE:"
    echo "================================"
    ovs-ofctl dump-flows "$OVS_BRIDGE" 2>/dev/null
}

# ============================================================
# MAIN
# ============================================================

usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  init                        - Initialize OVS bridge and VLANs"
    echo "  add-port <iface> [mode] [vlan] - Add interface to bridge"
    echo "  assign <mac> <vlan>         - Manually assign MAC to VLAN"
    echo "  auto-assign <mac>           - Auto-assign MAC based on OUI"
    echo "  remove <mac>                - Remove VLAN assignment for MAC"
    echo "  monitor                     - Monitor for new devices (daemon)"
    echo "  status                      - Show current status"
    echo "  flows                       - Show OVS flow table"
    echo "  create-oui                  - Create/reset OUI database"
    echo ""
    echo "VLANs:"
    echo "  10 = Management (admin devices)"
    echo "  20 = POS (payment terminals)"
    echo "  30 = Staff (employee devices)"
    echo "  40 = Guest (visitors) - DEFAULT"
    echo "  99 = IoT (smart devices, Home Assistant)"
    echo ""
    echo "Examples:"
    echo "  $0 init                      # Set up bridge and VLANs"
    echo "  $0 add-port wlan0            # Add WiFi interface"
    echo "  $0 add-port eth1 trunk       # Add uplink as trunk"
    echo "  $0 assign AA:BB:CC:DD:EE:FF 30  # Put device on Staff VLAN"
    echo "  $0 auto-assign AA:BB:CC:DD:EE:FF # Auto-assign by OUI"
    echo "  $0 monitor                   # Watch for new devices"
    echo ""
}

mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

case "${1:-}" in
    init)
        create_ovs_bridge
        create_vlan_interfaces
        setup_default_flows
        [ ! -f "$OUI_RULES_FILE" ] && create_oui_database
        ;;
    add-port)
        [ -z "$2" ] && { echo "Usage: $0 add-port <iface> [mode] [vlan]"; exit 1; }
        add_interface_to_bridge "$2" "${3:-}" "${4:-$DEFAULT_VLAN}"
        ;;
    assign)
        [ -z "$2" ] || [ -z "$3" ] && { echo "Usage: $0 assign <mac> <vlan>"; exit 1; }
        add_mac_vlan_flow "$2" "$3" "$PRIORITY_MANUAL" "manual"
        ;;
    auto-assign)
        [ -z "$2" ] && { echo "Usage: $0 auto-assign <mac>"; exit 1; }
        auto_assign_device "$2"
        ;;
    remove)
        [ -z "$2" ] && { echo "Usage: $0 remove <mac>"; exit 1; }
        remove_mac_vlan_flow "$2"
        ;;
    monitor)
        monitor_arp_for_devices
        ;;
    status)
        show_status
        ;;
    flows)
        show_flows
        ;;
    create-oui)
        create_oui_database
        ;;
    *)
        usage
        ;;
esac
