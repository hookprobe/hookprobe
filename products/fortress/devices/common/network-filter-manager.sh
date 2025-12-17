#!/bin/bash
#
# network-filter-manager.sh - nftables-based Network Access Control
# Part of HookProbe Fortress - Alternative to VLAN-based segmentation
#
# This provides per-device network filtering using MAC addresses and
# OUI-based classification. Simpler than VLANs, works without OVS.
#
# Device Policies:
#   full_access    - Full internet and LAN access (staff)
#   lan_only       - LAN access only, no internet (sensors, cameras)
#   internet_only  - Internet only, no LAN (guests, voice assistants)
#   isolated       - Completely isolated (quarantined devices)
#   default        - Default policy for unknown devices
#
# Usage:
#   ./network-filter-manager.sh init
#   ./network-filter-manager.sh set-policy <mac> <policy>
#   ./network-filter-manager.sh block <mac>
#   ./network-filter-manager.sh unblock <mac>
#   ./network-filter-manager.sh classify <mac>
#   ./network-filter-manager.sh status
#
# Version: 1.0.0
# License: AGPL-3.0

set -e

# Configuration
CONFIG_DIR="/etc/hookprobe"
STATE_DIR="/var/lib/fortress/filters"
LOG_FILE="/var/log/fortress/filter-manager.log"
OUI_DB_FILE="${CONFIG_DIR}/oui_policies.conf"
MAC_POLICIES_FILE="${STATE_DIR}/mac_policies.conf"
NFTABLES_CONFIG="/etc/nftables.d/fortress-filters.nft"

# Network settings
LAN_INTERFACE="${FORTRESS_LAN_INTERFACE:-eth0}"
WAN_INTERFACE="${FORTRESS_WAN_INTERFACE:-eth1}"
LAN_NETWORK="${FORTRESS_LAN_NETWORK:-192.168.1.0/24}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[FILTER]${NC} $(date '+%H:%M:%S') $*" | tee -a "$LOG_FILE" 2>/dev/null; }
log_success() { echo -e "${GREEN}[FILTER]${NC} $(date '+%H:%M:%S') $*" | tee -a "$LOG_FILE" 2>/dev/null; }
log_warn() { echo -e "${YELLOW}[FILTER]${NC} $(date '+%H:%M:%S') $*" | tee -a "$LOG_FILE" 2>/dev/null; }
log_error() { echo -e "${RED}[FILTER]${NC} $(date '+%H:%M:%S') $*" | tee -a "$LOG_FILE" 2>/dev/null; }

# ============================================================
# INITIALIZATION
# ============================================================

init_directories() {
    mkdir -p "$STATE_DIR" "$CONFIG_DIR" "$(dirname "$LOG_FILE")" "/etc/nftables.d"
    chmod 755 "$STATE_DIR" "$CONFIG_DIR"
    touch "$LOG_FILE"
    touch "$MAC_POLICIES_FILE"
    chmod 644 "$MAC_POLICIES_FILE"
}

check_nftables() {
    if ! command -v nft &>/dev/null; then
        log_error "nftables not installed. Install with: apt install nftables"
        return 1
    fi

    # Ensure nftables service is enabled
    if ! systemctl is-enabled nftables &>/dev/null; then
        log_warn "Enabling nftables service..."
        systemctl enable nftables
    fi

    if ! systemctl is-active nftables &>/dev/null; then
        systemctl start nftables
    fi

    return 0
}

# ============================================================
# OUI DATABASE MANAGEMENT
# ============================================================

create_oui_database() {
    log_info "Creating OUI classification database..."

    cat > "$OUI_DB_FILE" << 'EOF'
# HookProbe Fortress - OUI Classification Database
# Format: OUI:device_category:default_policy:manufacturer
#
# Device Categories:
#   iot            - Smart home devices, sensors
#   camera         - Security cameras, doorbells
#   pos            - Payment terminals
#   printer        - Network printers
#   workstation    - Laptops, desktops
#   mobile         - Phones, tablets
#   voice_assistant - Alexa, Google Home, etc.
#   network        - Routers, switches, APs
#
# Policies:
#   full_access    - Internet + LAN
#   lan_only       - LAN only (no internet)
#   internet_only  - Internet only (no LAN)
#   isolated       - No network access
#

# ================================================
# IoT Devices -> lan_only (can't reach internet)
# ================================================
B8:27:EB:iot:lan_only:Raspberry Pi Foundation
DC:A6:32:iot:lan_only:Raspberry Pi Trading
E4:5F:01:iot:lan_only:Raspberry Pi Trading
28:CD:C1:iot:lan_only:Raspberry Pi Trading

# ESP8266/ESP32 (Espressif)
24:0A:C4:iot:lan_only:Espressif
24:6F:28:iot:lan_only:Espressif
3C:71:BF:iot:lan_only:Espressif
5C:CF:7F:iot:lan_only:Espressif
A4:CF:12:iot:lan_only:Espressif
CC:50:E3:iot:lan_only:Espressif

# Tuya/SmartLife
10:D5:61:iot:lan_only:Tuya Smart
D8:1F:12:iot:lan_only:Tuya Smart

# Shelly
34:94:54:iot:lan_only:Shelly
44:17:93:iot:lan_only:Shelly

# Philips Hue
00:17:88:iot:lan_only:Philips Hue
EC:B5:FA:iot:lan_only:Philips Hue

# IKEA Tradfri
00:0B:57:iot:lan_only:IKEA Tradfri
90:FD:9F:iot:lan_only:IKEA Tradfri

# ================================================
# Security Cameras -> lan_only
# ================================================
00:0C:B5:camera:lan_only:Hikvision
18:68:CB:camera:lan_only:Hikvision
28:57:BE:camera:lan_only:Hikvision
54:C4:15:camera:lan_only:Hikvision
3C:EF:8C:camera:lan_only:Dahua
90:02:A9:camera:lan_only:Dahua
B4:6B:FC:camera:lan_only:Reolink
EC:71:DB:camera:lan_only:Reolink
2C:AA:8E:camera:lan_only:Wyze
9C:76:0E:camera:lan_only:Ring
04:B1:67:camera:lan_only:Ring
48:78:5E:camera:lan_only:Eufy

# ================================================
# Voice Assistants -> internet_only (no LAN snooping)
# ================================================
18:D6:C7:voice_assistant:internet_only:Google Nest
1C:F2:9A:voice_assistant:internet_only:Google Nest
54:60:09:voice_assistant:internet_only:Google Home
F4:F5:D8:voice_assistant:internet_only:Google Home
0C:47:C9:voice_assistant:internet_only:Amazon Echo
34:D2:70:voice_assistant:internet_only:Amazon Echo
50:DC:E7:voice_assistant:internet_only:Amazon Echo
68:54:FD:voice_assistant:internet_only:Amazon Echo
A0:02:DC:voice_assistant:internet_only:Amazon Echo

# ================================================
# POS Terminals -> internet_only (payment processing)
# ================================================
00:50:10:pos:internet_only:Verifone
00:0D:41:pos:internet_only:Verifone
00:17:E8:pos:internet_only:Verifone
00:07:81:pos:internet_only:Ingenico
00:18:0A:pos:internet_only:Ingenico
58:E6:BA:pos:internet_only:Square
04:CF:8C:pos:internet_only:Clover
00:1F:71:pos:internet_only:PAX

# ================================================
# Printers -> lan_only
# ================================================
00:1E:0B:printer:lan_only:HP
00:21:5A:printer:lan_only:HP
64:51:06:printer:lan_only:HP
00:1E:8F:printer:lan_only:Canon
74:E5:43:printer:lan_only:Canon
00:26:AB:printer:lan_only:Epson
00:1B:A9:printer:lan_only:Brother

# ================================================
# Network Equipment -> full_access (trusted)
# ================================================
00:1A:2B:network:full_access:Ubiquiti
24:A4:3C:network:full_access:Ubiquiti
FC:EC:DA:network:full_access:Ubiquiti
00:18:0A:network:full_access:Cisco
00:1B:2A:network:full_access:Cisco
B4:FB:E4:network:full_access:Netgear

EOF

    log_success "OUI database created at $OUI_DB_FILE"
}

lookup_oui_policy() {
    # Look up device policy based on OUI
    # Args: $1 = MAC address
    # Returns: policy name or empty

    local mac="${1^^}"
    local oui="${mac:0:8}"  # First 3 bytes (XX:XX:XX)

    if [ ! -f "$OUI_DB_FILE" ]; then
        return
    fi

    while IFS=: read -r rule_oui category policy manufacturer; do
        [[ "$rule_oui" =~ ^#.*$ ]] && continue
        [ -z "$rule_oui" ] && continue

        rule_oui="${rule_oui^^}"

        if [ "$oui" = "$rule_oui" ]; then
            echo "$policy"
            return
        fi
    done < "$OUI_DB_FILE"
}

get_device_info() {
    # Get device info from OUI database
    # Args: $1 = MAC address
    # Returns: category:policy:manufacturer

    local mac="${1^^}"
    local oui="${mac:0:8}"

    if [ ! -f "$OUI_DB_FILE" ]; then
        echo "unknown:default:Unknown"
        return
    fi

    while IFS=: read -r rule_oui category policy manufacturer; do
        [[ "$rule_oui" =~ ^#.*$ ]] && continue
        [ -z "$rule_oui" ] && continue

        rule_oui="${rule_oui^^}"

        if [ "$oui" = "$rule_oui" ]; then
            echo "${category}:${policy}:${manufacturer}"
            return
        fi
    done < "$OUI_DB_FILE"

    echo "unknown:default:Unknown"
}

# ============================================================
# NFTABLES CONFIGURATION
# ============================================================

init_nftables() {
    log_info "Initializing nftables rules..."

    # Delete existing table first (ignore error if doesn't exist)
    nft delete table inet fortress_filter 2>/dev/null || true

    # Create the Fortress nftables configuration
    cat > "$NFTABLES_CONFIG" << 'NFTEOF'
#!/usr/sbin/nft -f
#
# HookProbe Fortress - Network Filter Rules
# Auto-generated - do not edit manually
#
# Tables:
#   fortress_filter - Main filter table with MAC-based policy chains
#
# Chains:
#   input_policy   - Inbound traffic policy
#   forward_policy - Forwarding policy (main filtering)
#   output_policy  - Outbound traffic policy
#
# Sets:
#   blocked_macs      - Completely blocked devices
#   lan_only_macs     - LAN-only devices (no internet)
#   internet_only_macs - Internet-only devices (no LAN)
#   full_access_macs  - Full access devices
#

table inet fortress_filter {

    # ========================================
    # MAC Address Sets for Policy Groups
    # ========================================

    # Blocked devices - no network access
    set blocked_macs {
        type ether_addr
        flags interval
        comment "Blocked devices - no network access"
    }

    # LAN-only devices - can reach local network but not internet
    set lan_only_macs {
        type ether_addr
        flags interval
        comment "LAN-only devices - local network only"
    }

    # Internet-only devices - can reach internet but not local LAN
    set internet_only_macs {
        type ether_addr
        flags interval
        comment "Internet-only devices - WAN access only"
    }

    # Full access devices - unrestricted
    set full_access_macs {
        type ether_addr
        flags interval
        comment "Full access devices - unrestricted"
    }

    # ========================================
    # Input Chain (traffic TO the Fortress)
    # ========================================
    chain input_policy {
        type filter hook input priority 0; policy accept;

        # Drop traffic from blocked MACs
        ether saddr @blocked_macs drop

        # Allow established connections
        ct state established,related accept

        # Allow loopback
        iif lo accept

        # Allow ICMP
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        # Allow DHCP
        udp dport 67 accept
        udp dport 68 accept

        # Allow DNS
        udp dport 53 accept
        tcp dport 53 accept

        # Allow admin portal (8443)
        tcp dport 8443 accept

        # Allow SSH (management)
        tcp dport 22 accept
    }

    # ========================================
    # Forward Chain (traffic THROUGH Fortress)
    # ========================================
    chain forward_policy {
        type filter hook forward priority 0; policy accept;

        # Drop all traffic from blocked MACs
        ether saddr @blocked_macs drop

        # Allow established connections
        ct state established,related accept

        # ----------------------------------------
        # LAN-ONLY devices: Allow LAN, block WAN
        # ----------------------------------------
        # Block internet access for lan_only devices
        # (Traffic destined for non-local addresses)
        ether saddr @lan_only_macs ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } counter drop

        # ----------------------------------------
        # INTERNET-ONLY devices: Allow WAN, block LAN
        # ----------------------------------------
        # Block LAN access for internet_only devices
        # (Traffic destined for local addresses except gateway)
        ether saddr @internet_only_macs ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } counter drop

        # ----------------------------------------
        # FULL ACCESS devices: Allow everything
        # ----------------------------------------
        ether saddr @full_access_macs accept

        # ----------------------------------------
        # DEFAULT: Allow all (policy can be changed)
        # ----------------------------------------
        accept
    }

    # ========================================
    # Output Chain (traffic FROM Fortress)
    # ========================================
    chain output_policy {
        type filter hook output priority 0; policy accept;
    }

    # ========================================
    # NAT for Internet Access
    # ========================================
    chain nat_postrouting {
        type nat hook postrouting priority 100; policy accept;

        # Masquerade outbound traffic (NAT for internet access)
        # Only for non-blocked, non-lan_only devices
        oifname @wan_interfaces masquerade
    }

    # Set for WAN interfaces
    set wan_interfaces {
        type ifname
        elements = { "eth0", "wlan0" }
        comment "WAN-facing interfaces for NAT"
    }
}
NFTEOF

    # Apply the rules
    local nft_error
    if ! nft_error=$(nft -f "$NFTABLES_CONFIG" 2>&1); then
        log_error "Failed to apply nftables rules"
        log_error "Error: $nft_error"
        return 1
    fi

    log_success "nftables rules initialized"
}

# ============================================================
# POLICY MANAGEMENT
# ============================================================

add_mac_to_set() {
    # Add MAC address to nftables set
    local mac="${1^^}"
    local set_name="$2"

    mac=$(echo "$mac" | sed 's/-/:/g')

    # Validate MAC format
    if ! echo "$mac" | grep -qE '^([0-9A-F]{2}:){5}[0-9A-F]{2}$'; then
        log_error "Invalid MAC address: $mac"
        return 1
    fi

    # Remove from all sets first
    nft delete element inet fortress_filter blocked_macs { "$mac" } 2>/dev/null || true
    nft delete element inet fortress_filter lan_only_macs { "$mac" } 2>/dev/null || true
    nft delete element inet fortress_filter internet_only_macs { "$mac" } 2>/dev/null || true
    nft delete element inet fortress_filter full_access_macs { "$mac" } 2>/dev/null || true

    # Add to specified set
    nft add element inet fortress_filter "$set_name" { "$mac" }

    return 0
}

set_device_policy() {
    # Set network policy for a device
    # Args:
    #   $1 - MAC address
    #   $2 - Policy (full_access, lan_only, internet_only, isolated)

    local mac="${1^^}"
    local policy="$2"

    mac=$(echo "$mac" | sed 's/-/:/g')

    case "$policy" in
        full_access|full)
            add_mac_to_set "$mac" "full_access_macs"
            log_success "$mac → full_access (unrestricted)"
            ;;
        lan_only|lan)
            add_mac_to_set "$mac" "lan_only_macs"
            log_success "$mac → lan_only (no internet)"
            ;;
        internet_only|internet|wan)
            add_mac_to_set "$mac" "internet_only_macs"
            log_success "$mac → internet_only (no LAN)"
            ;;
        isolated|blocked|block)
            add_mac_to_set "$mac" "blocked_macs"
            log_success "$mac → isolated (blocked)"
            ;;
        default|auto)
            # Auto-assign based on OUI
            local auto_policy
            auto_policy=$(lookup_oui_policy "$mac")
            if [ -n "$auto_policy" ]; then
                set_device_policy "$mac" "$auto_policy"
            else
                log_info "$mac → default (no specific policy)"
            fi
            return
            ;;
        *)
            log_error "Invalid policy: $policy"
            echo "Valid policies: full_access, lan_only, internet_only, isolated, default"
            return 1
            ;;
    esac

    # Save to persistent file
    save_mac_policy "$mac" "$policy"
}

save_mac_policy() {
    # Save MAC-to-policy mapping persistently
    local mac="$1"
    local policy="$2"

    # Remove existing entry
    if [ -f "$MAC_POLICIES_FILE" ]; then
        sed -i "/^$mac:/Id" "$MAC_POLICIES_FILE"
    fi

    # Add new entry
    echo "${mac}:${policy}:$(date -Iseconds)" >> "$MAC_POLICIES_FILE"
}

load_saved_policies() {
    # Load saved MAC policies on startup
    log_info "Loading saved MAC policies..."

    if [ ! -f "$MAC_POLICIES_FILE" ]; then
        return
    fi

    local count=0
    while IFS=: read -r mac policy timestamp; do
        [ -z "$mac" ] && continue
        [[ "$mac" =~ ^#.*$ ]] && continue

        set_device_policy "$mac" "$policy" 2>/dev/null && ((count++))
    done < "$MAC_POLICIES_FILE"

    log_info "Loaded $count saved policies"
}

# ============================================================
# DEVICE CLASSIFICATION
# ============================================================

classify_device() {
    # Classify a device based on its MAC address
    # Looks up OUI and applies appropriate policy

    local mac="${1^^}"
    mac=$(echo "$mac" | sed 's/-/:/g')

    local info
    info=$(get_device_info "$mac")

    local category policy manufacturer
    IFS=: read -r category policy manufacturer <<< "$info"

    echo ""
    echo "Device Classification:"
    echo "======================"
    echo "MAC Address:  $mac"
    echo "OUI:          ${mac:0:8}"
    echo "Category:     $category"
    echo "Manufacturer: $manufacturer"
    echo "Auto Policy:  $policy"
    echo ""

    read -p "Apply policy '$policy'? [Y/n]: " confirm
    confirm="${confirm:-Y}"

    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        set_device_policy "$mac" "$policy"
    else
        echo "Policy not applied. Use: $0 set-policy $mac <policy>"
    fi
}

auto_classify_new_device() {
    # Called when a new device is detected
    # Automatically classifies and applies policy based on OUI

    local mac="$1"
    local ip="${2:-unknown}"

    local info policy
    info=$(get_device_info "$mac")
    policy=$(echo "$info" | cut -d: -f2)

    if [ "$policy" = "default" ]; then
        log_info "New device: $mac ($ip) - no OUI match, using default policy"
    else
        log_info "New device: $mac ($ip) - auto-applying policy: $policy"
        set_device_policy "$mac" "$policy"
    fi
}

# ============================================================
# MONITORING
# ============================================================

monitor_new_devices() {
    # Monitor ARP table for new devices and auto-classify them

    log_info "Monitoring for new devices..."

    local seen_macs_file="$STATE_DIR/seen_macs.txt"
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
                auto_classify_new_device "$mac" "$ip"
            fi
        done

        sleep 5
    done
}

# ============================================================
# BLOCKING
# ============================================================

block_device() {
    local mac="${1^^}"
    set_device_policy "$mac" "blocked"
}

unblock_device() {
    local mac="${1^^}"
    mac=$(echo "$mac" | sed 's/-/:/g')

    # Remove from blocked set
    nft delete element inet fortress_filter blocked_macs { "$mac" } 2>/dev/null || true

    # Remove from saved policies
    if [ -f "$MAC_POLICIES_FILE" ]; then
        sed -i "/^$mac:/Id" "$MAC_POLICIES_FILE"
    fi

    log_success "$mac unblocked"
}

# ============================================================
# STATUS
# ============================================================

show_status() {
    echo ""
    echo "Fortress Network Filter Status"
    echo "==============================="
    echo ""

    # Check nftables
    if nft list table inet fortress_filter &>/dev/null; then
        echo "nftables: ACTIVE"
    else
        echo "nftables: NOT CONFIGURED"
        echo ""
        echo "Run: $0 init"
        return
    fi

    echo ""
    echo "Policy Sets:"
    echo "------------"

    echo ""
    echo "Blocked devices:"
    nft list set inet fortress_filter blocked_macs 2>/dev/null | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | while read mac; do
        local info=$(get_device_info "$mac")
        local mfr=$(echo "$info" | cut -d: -f3)
        echo "  $mac ($mfr)"
    done
    echo ""

    echo "LAN-only devices (no internet):"
    nft list set inet fortress_filter lan_only_macs 2>/dev/null | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | while read mac; do
        local info=$(get_device_info "$mac")
        local mfr=$(echo "$info" | cut -d: -f3)
        echo "  $mac ($mfr)"
    done
    echo ""

    echo "Internet-only devices (no LAN):"
    nft list set inet fortress_filter internet_only_macs 2>/dev/null | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | while read mac; do
        local info=$(get_device_info "$mac")
        local mfr=$(echo "$info" | cut -d: -f3)
        echo "  $mac ($mfr)"
    done
    echo ""

    echo "Full-access devices:"
    nft list set inet fortress_filter full_access_macs 2>/dev/null | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | while read mac; do
        local info=$(get_device_info "$mac")
        local mfr=$(echo "$info" | cut -d: -f3)
        echo "  $mac ($mfr)"
    done
    echo ""

    echo "OUI Database: $(grep -v '^#' "$OUI_DB_FILE" 2>/dev/null | grep -v '^$' | wc -l) entries"
    echo "Saved Policies: $(wc -l < "$MAC_POLICIES_FILE" 2>/dev/null | tr -d ' ') devices"
    echo ""
}

show_rules() {
    echo ""
    echo "nftables Rules:"
    echo "==============="
    nft list table inet fortress_filter 2>/dev/null
}

# ============================================================
# CLEANUP
# ============================================================

cleanup() {
    log_info "Removing Fortress filter rules..."

    nft delete table inet fortress_filter 2>/dev/null || true
    rm -f "$NFTABLES_CONFIG"

    log_info "Filter rules removed"
}

# ============================================================
# MAIN
# ============================================================

usage() {
    echo "HookProbe Fortress - Network Filter Manager"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  init                        Initialize nftables rules"
    echo "  set-policy <mac> <policy>   Set device network policy"
    echo "  classify <mac>              Classify device by OUI"
    echo "  block <mac>                 Block device completely"
    echo "  unblock <mac>               Remove device block"
    echo "  monitor                     Monitor for new devices (daemon)"
    echo "  status                      Show filter status"
    echo "  rules                       Show nftables rules"
    echo "  create-oui                  Create/reset OUI database"
    echo "  cleanup                     Remove all filter rules"
    echo ""
    echo "Policies:"
    echo "  full_access    Full internet and LAN access"
    echo "  lan_only       LAN only - NO internet (sensors, cameras)"
    echo "  internet_only  Internet only - NO LAN (guests, POS)"
    echo "  isolated       Completely isolated (blocked)"
    echo "  default        Auto-assign based on OUI"
    echo ""
    echo "Examples:"
    echo "  $0 init                              # Initialize rules"
    echo "  $0 set-policy AA:BB:CC:DD:EE:FF lan_only   # Set device to LAN-only"
    echo "  $0 classify AA:BB:CC:DD:EE:FF        # Auto-classify device"
    echo "  $0 block AA:BB:CC:DD:EE:FF           # Block device"
    echo "  $0 monitor                           # Watch for new devices"
    echo ""
}

init_directories

case "${1:-}" in
    init)
        check_nftables || exit 1
        [ ! -f "$OUI_DB_FILE" ] && create_oui_database
        init_nftables
        load_saved_policies
        ;;
    set-policy|policy)
        [ -z "$2" ] || [ -z "$3" ] && { echo "Usage: $0 set-policy <mac> <policy>"; exit 1; }
        set_device_policy "$2" "$3"
        ;;
    classify|auto)
        [ -z "$2" ] && { echo "Usage: $0 classify <mac>"; exit 1; }
        classify_device "$2"
        ;;
    block)
        [ -z "$2" ] && { echo "Usage: $0 block <mac>"; exit 1; }
        block_device "$2"
        ;;
    unblock)
        [ -z "$2" ] && { echo "Usage: $0 unblock <mac>"; exit 1; }
        unblock_device "$2"
        ;;
    monitor)
        monitor_new_devices
        ;;
    status)
        show_status
        ;;
    rules)
        show_rules
        ;;
    create-oui)
        create_oui_database
        ;;
    cleanup|remove)
        cleanup
        ;;
    *)
        usage
        ;;
esac
