#!/bin/bash
#
# HookProbe Fortress - NAC Policy Sync Script
#
# Syncs device NAC policies from SQLite database to OpenFlow rules.
# Should be called after OVS is configured and ready.
#
# Usage:
#   nac-policy-sync.sh              # Sync all policies
#   nac-policy-sync.sh --status     # Show sync status
#
# Boot sequence:
#   1. fortress-vlan.service creates base OpenFlow rules (priority 500)
#   2. fortress.service starts containers
#   3. fts-ovs-connect.sh calls this script to apply per-device rules
#
# Policy Priority Hierarchy (AIOCHI Bubble Integration):
#   - Priority 900-1001: Device-specific policy overrides
#   - Priority 600-850:  Bubble default policies
#   - Priority 500:      Base ALLOW rules (fallback)
#   - Priority 450:      D2D bubble rules (intra-bubble traffic)
#   - Priority 100:      Default isolation
#
# Policy Types:
#   - QUARANTINE: Priority 999-1001 (drop all except DHCP/DNS/ARP)
#   - LAN_ONLY: Priority 600-750 (allow LAN, block internet)
#   - INTERNET_ONLY: Priority 650-850 (internet only, no LAN/mDNS)
#   - SMART_HOME: Priority 500 (full local access, base allow)
#   - FULL_ACCESS: Priority 500 (no restrictions)
#

set -e

LOG_TAG="fts-nac"
OVS_BRIDGE="${OVS_BRIDGE:-FTS}"

# FLAT BRIDGE ARCHITECTURE
# All devices share the same Layer 2 segment (no VLANs)
# Segmentation is via OpenFlow rules, not VLAN tagging
LAN_NETWORK="${LAN_NETWORK:-10.200.0.0/16}"
GATEWAY_IP="${GATEWAY_IP:-10.200.0.1}"
CONTAINER_NETWORK="172.20.0.0/16"

# Trigger file from container for real-time policy application
POLICY_TRIGGER_FILE="/opt/hookprobe/fortress/data/.nac_policy_sync"

# Ecosystem Bubble trigger file for bubble-based OpenFlow rules
# Written by shared/aiochi/bubble/manager.py, consumed here to apply bubble rules
BUBBLE_TRIGGER_FILE="/opt/hookprobe/fortress/data/.bubble_sdn_sync"

# Policy resolution trigger file for device-specific overrides
# Written by shared/aiochi/bubble/policy_resolver.py
POLICY_RESOLUTION_FILE="/opt/hookprobe/fortress/data/.policy_resolutions"

# Database paths
# Primary: SDN Autopilot database (device_identity table)
AUTOPILOT_DB="/var/lib/hookprobe/autopilot.db"
# Legacy: Old devices database
DEVICES_DB="/var/lib/hookprobe/devices.db"
DEVICE_REGISTRY="/opt/hookprobe/fortress/data/device_registry.json"

log_info() { logger -t "$LOG_TAG" "$1" 2>/dev/null || true; echo "[INFO] $1"; }
log_warn() { logger -t "$LOG_TAG" -p warning "$1" 2>/dev/null || true; echo "[WARN] $1"; }
log_error() { logger -t "$LOG_TAG" -p err "$1" 2>/dev/null || true; echo "[ERROR] $1"; }

# Check for policy trigger file from container
check_policy_trigger() {
    if [ -f "$POLICY_TRIGGER_FILE" ]; then
        local mac policy
        # Parse JSON trigger file using Python
        read -r mac policy < <(python3 -c "
import json
import sys
try:
    with open('$POLICY_TRIGGER_FILE') as f:
        data = json.load(f)
    print(data.get('mac', ''), data.get('policy', ''))
except Exception as e:
    print('', '', file=sys.stderr)
" 2>/dev/null || echo "")

        if [ -n "$mac" ] && [ -n "$policy" ]; then
            log_info "Processing policy trigger: $mac -> $policy"
            apply_policy "$mac" "$policy"
        fi

        # Remove the trigger file
        rm -f "$POLICY_TRIGGER_FILE"
    fi
}

# Check for ecosystem bubble trigger file from container
# Bubble rules allow intra-bubble traffic for same-user device groups
# Priority 450 (below base allow 500, above drop rules)
check_bubble_trigger() {
    if [ ! -f "$BUBBLE_TRIGGER_FILE" ]; then
        return 0
    fi

    log_info "Processing ecosystem bubble trigger..."

    # Parse bubble rules JSON using Python
    local rules_json
    rules_json=$(python3 -c "
import json
import sys
try:
    with open('$BUBBLE_TRIGGER_FILE') as f:
        data = json.load(f)
    # Output each rule as a single line for bash processing
    for rule in data.get('rules', []):
        match = rule.get('match', {})
        eth_src = match.get('eth_src', '')
        eth_dst = match.get('eth_dst', '')
        priority = rule.get('priority', 450)
        bubble_id = rule.get('bubble_id', 'unknown')
        if eth_src and eth_dst:
            print(f'{eth_src}|{eth_dst}|{priority}|{bubble_id}')
except Exception as e:
    print(f'ERROR:{e}', file=sys.stderr)
" 2>&1)

    if echo "$rules_json" | grep -q "^ERROR:"; then
        log_error "Failed to parse bubble trigger: $(echo "$rules_json" | grep '^ERROR:')"
        rm -f "$BUBBLE_TRIGGER_FILE"
        return 1
    fi

    local applied=0
    local bubble_ids=()

    # First, clear old bubble rules (priority 450)
    ovs-ofctl del-flows "$OVS_BRIDGE" "priority=450" 2>/dev/null || true

    # Apply each bubble rule
    while IFS='|' read -r eth_src eth_dst priority bubble_id; do
        [ -z "$eth_src" ] && continue
        [ -z "$eth_dst" ] && continue

        # Allow traffic between bubble devices (bidirectional)
        if add_flow "priority=${priority:-450},dl_src=$eth_src,dl_dst=$eth_dst,actions=NORMAL"; then
            ((applied++)) || true
        fi

        # Track unique bubble IDs
        if [[ ! " ${bubble_ids[*]} " =~ " ${bubble_id} " ]]; then
            bubble_ids+=("$bubble_id")
        fi
    done <<< "$rules_json"

    if [ "$applied" -gt 0 ]; then
        log_info "Applied $applied bubble OpenFlow rules for ${#bubble_ids[@]} bubble(s)"
    fi

    # Keep the trigger file for debugging (with .processed suffix)
    mv "$BUBBLE_TRIGGER_FILE" "${BUBBLE_TRIGGER_FILE}.processed" 2>/dev/null || true
}

# Apply OpenFlow rule
add_flow() {
    local flow_spec="$1"
    if ovs-ofctl add-flow "$OVS_BRIDGE" "$flow_spec" 2>/dev/null; then
        return 0
    else
        log_warn "Failed to add flow: $flow_spec"
        return 1
    fi
}

# Remove existing per-device rules for a MAC
remove_device_rules() {
    local mac="$1"
    ovs-ofctl del-flows "$OVS_BRIDGE" "dl_src=$mac" 2>/dev/null || true
    ovs-ofctl del-flows "$OVS_BRIDGE" "dl_dst=$mac" 2>/dev/null || true
}

# Apply policy rules for a device
# Args:
#   $1: MAC address
#   $2: Policy name (quarantine, lan_only, internet_only, smart_home, full_access)
#   $3: Priority mode ('override' for device-specific, 'default' for bubble default)
#
# Priority offsets:
#   - override: +300 (e.g., INTERNET_ONLY becomes 950-1100 instead of 650-800)
#   - default: +0 (standard priorities)
apply_policy() {
    local mac="$1"
    local policy="$2"
    local priority_mode="${3:-default}"
    local priority_offset=0

    # Device-specific overrides get higher priority
    if [ "$priority_mode" = "override" ]; then
        priority_offset=300
    fi

    # Normalize MAC: uppercase and colons (OVS expects XX:XX:XX:XX:XX:XX format)
    mac=$(echo "$mac" | tr '[:lower:]' '[:upper:]' | tr '-' ':')

    # Remove existing rules first
    remove_device_rules "$mac"

    case "$policy" in
        isolated|quarantine)
            # QUARANTINE: Block all traffic except DHCP and DNS to gateway
            # NOTE: Quarantine is ALWAYS highest priority regardless of override mode
            # Priority 1001: Allow DHCP (so device can get/renew IP)
            add_flow "priority=1001,udp,dl_src=$mac,tp_dst=67,actions=NORMAL"
            add_flow "priority=1001,udp,dl_dst=$mac,tp_src=67,actions=NORMAL"
            # Priority 1001: Allow DNS to gateway only (for captive portal)
            add_flow "priority=1001,udp,dl_src=$mac,nw_dst=$GATEWAY_IP,tp_dst=53,actions=NORMAL"
            add_flow "priority=1001,udp,dl_dst=$mac,nw_src=$GATEWAY_IP,tp_src=53,actions=NORMAL"
            # Priority 1001: Allow ARP (needed for basic connectivity)
            add_flow "priority=1001,arp,dl_src=$mac,actions=NORMAL"
            add_flow "priority=1001,arp,dl_dst=$mac,actions=NORMAL"
            # Priority 1000: Drop all IP traffic (explicit)
            add_flow "priority=1000,ip,dl_src=$mac,actions=drop"
            add_flow "priority=1000,ip,dl_dst=$mac,actions=drop"
            # Priority 999: Drop any other Ethernet frames
            add_flow "priority=999,dl_src=$mac,actions=drop"
            add_flow "priority=999,dl_dst=$mac,actions=drop"
            log_info "Applied QUARANTINE policy for $mac (blocks all except DHCP/DNS)"
            ;;

        lan_only)
            # LAN_ONLY: Device-to-device communication ONLY (IoT/IIoT, HomeKit lights)
            # NO dashboard, NO containers, NO internet - just talk to other devices
            # ALLOWS mDNS for discovery (HomeKit, AirPlay on LAN)
            #
            # Priority offset: +300 for device overrides (e.g., 750 -> 1050)
            #
            # Priority 475: mDNS/SSDP discovery (allows HomeKit/AirPlay on LAN)
            add_flow "priority=475,udp,dl_src=$mac,tp_dst=5353,actions=NORMAL"
            add_flow "priority=475,udp6,dl_src=$mac,tp_dst=5353,actions=NORMAL"
            add_flow "priority=475,udp,dl_dst=$mac,tp_src=5353,actions=NORMAL"
            add_flow "priority=475,udp6,dl_dst=$mac,tp_src=5353,actions=NORMAL"
            add_flow "priority=475,udp,dl_src=$mac,nw_dst=239.255.255.250,tp_dst=1900,actions=NORMAL"
            add_flow "priority=475,udp,dl_dst=$mac,nw_src=239.255.255.250,tp_src=1900,actions=NORMAL"
            # Allow gateway for DHCP/DNS only
            add_flow "priority=$((750 + priority_offset)),ip,dl_src=$mac,nw_dst=$GATEWAY_IP,actions=NORMAL"
            add_flow "priority=$((740 + priority_offset)),ip,dl_dst=$mac,nw_src=$GATEWAY_IP,actions=NORMAL"
            # Block containers - IoT shouldn't talk to infrastructure
            add_flow "priority=$((730 + priority_offset)),ip,dl_src=$mac,nw_dst=$CONTAINER_NETWORK,actions=drop"
            add_flow "priority=$((730 + priority_offset)),ip,dl_dst=$mac,nw_src=$CONTAINER_NETWORK,actions=drop"
            # Allow device-to-device on LAN network only
            add_flow "priority=$((720 + priority_offset)),ip,dl_src=$mac,nw_dst=$LAN_NETWORK,actions=NORMAL"
            add_flow "priority=$((710 + priority_offset)),ip,dl_dst=$mac,nw_src=$LAN_NETWORK,actions=NORMAL"
            # Block everything else (internet)
            add_flow "priority=$((600 + priority_offset)),ip,dl_src=$mac,actions=drop"
            add_flow "priority=$((600 + priority_offset)),ip,dl_dst=$mac,actions=drop"
            local mode_str="bubble default"
            [ "$priority_mode" = "override" ] && mode_str="device override"
            log_info "Applied LAN_ONLY policy for $mac ($mode_str, D2D + mDNS discovery)"
            ;;

        internet_only)
            # INTERNET_ONLY: Internet access ONLY (voice assistants, BYOD, corporate devices)
            # NO dashboard, NO LAN devices, NO containers, NO gateway ping - just internet
            # NO mDNS/Bonjour - cannot discover or be discovered by HomeKit/AirPlay devices
            #
            # For internet routing: packets go THROUGH gateway (L2) but IP dst is internet host
            # So we don't need to allow IP traffic TO gateway IP - only DHCP and DNS
            #
            # Priority offset: +300 for device overrides (e.g., 850 -> 1150)
            # Block mDNS/Bonjour (no HomeKit/AirPlay discovery)
            # This prevents internet_only devices from seeing or being seen by smart home devices
            add_flow "priority=$((850 + priority_offset)),udp,dl_src=$mac,tp_dst=5353,actions=drop"
            add_flow "priority=$((850 + priority_offset)),udp,dl_dst=$mac,tp_src=5353,actions=drop"
            # Also block IPv6 mDNS (HomeKit uses IPv6 heavily)
            add_flow "priority=$((850 + priority_offset)),udp6,dl_src=$mac,tp_dst=5353,actions=drop"
            add_flow "priority=$((850 + priority_offset)),udp6,dl_dst=$mac,tp_src=5353,actions=drop"
            # Allow DHCP (essential for IP assignment)
            add_flow "priority=$((800 + priority_offset)),udp,dl_src=$mac,tp_dst=67,actions=NORMAL"
            add_flow "priority=$((800 + priority_offset)),udp,dl_dst=$mac,tp_src=67,actions=NORMAL"
            # Allow DNS to gateway only (for name resolution)
            add_flow "priority=$((800 + priority_offset)),udp,dl_src=$mac,nw_dst=$GATEWAY_IP,tp_dst=53,actions=NORMAL"
            add_flow "priority=$((800 + priority_offset)),udp,dl_dst=$mac,nw_src=$GATEWAY_IP,tp_src=53,actions=NORMAL"
            add_flow "priority=$((800 + priority_offset)),tcp,dl_src=$mac,nw_dst=$GATEWAY_IP,tp_dst=53,actions=NORMAL"
            add_flow "priority=$((800 + priority_offset)),tcp,dl_dst=$mac,nw_src=$GATEWAY_IP,tp_src=53,actions=NORMAL"
            # Allow ARP (needed for gateway MAC resolution)
            add_flow "priority=$((800 + priority_offset)),arp,dl_src=$mac,actions=NORMAL"
            add_flow "priority=$((800 + priority_offset)),arp,dl_dst=$mac,actions=NORMAL"
            # Block containers - no access to infrastructure
            add_flow "priority=$((750 + priority_offset)),ip,dl_src=$mac,nw_dst=$CONTAINER_NETWORK,actions=drop"
            add_flow "priority=$((750 + priority_offset)),ip,dl_dst=$mac,nw_src=$CONTAINER_NETWORK,actions=drop"
            # Block ALL LAN traffic (including gateway - no ping allowed)
            # This blocks: other devices, dashboard, gateway ICMP/ping
            add_flow "priority=$((700 + priority_offset)),ip,dl_src=$mac,nw_dst=$LAN_NETWORK,actions=drop"
            add_flow "priority=$((700 + priority_offset)),ip,dl_dst=$mac,nw_src=$LAN_NETWORK,actions=drop"
            # Allow internet (non-LAN destinations)
            # Internet traffic has nw_dst=internet_host (e.g., 8.8.8.8), not gateway IP
            add_flow "priority=$((650 + priority_offset)),ip,dl_src=$mac,actions=NORMAL"
            add_flow "priority=$((650 + priority_offset)),ip,dl_dst=$mac,actions=NORMAL"
            local mode_str="bubble default"
            [ "$priority_mode" = "override" ] && mode_str="device override"
            log_info "Applied INTERNET_ONLY policy for $mac ($mode_str, no LAN/mDNS access)"
            ;;

        smart_home)
            # SMART_HOME: Full LAN access + explicit mDNS allow rules
            # Priority 475: Ensures SMART_HOME devices can discover each other
            # even if they're in different ecosystem bubbles
            #
            # This is between INTERNET_ONLY mDNS block (850) and base allow (800)
            # Without this, SMART_HOME devices rely on base mDNS allow which works,
            # but explicit rules make policy intent clearer and enable future filtering
            #
            # SECURITY: Block access to container infrastructure (172.20.0.0/16)
            # IoT devices should NOT interact with Fortress containers
            add_flow "priority=720,ip,dl_src=$mac,nw_dst=$CONTAINER_NETWORK,actions=drop"
            add_flow "priority=720,ip,dl_dst=$mac,nw_src=$CONTAINER_NETWORK,actions=drop"
            #
            # Allow mDNS queries FROM this device
            add_flow "priority=475,udp,dl_src=$mac,tp_dst=5353,actions=NORMAL"
            add_flow "priority=475,udp6,dl_src=$mac,tp_dst=5353,actions=NORMAL"
            # Allow mDNS responses TO this device
            add_flow "priority=475,udp,dl_dst=$mac,tp_src=5353,actions=NORMAL"
            add_flow "priority=475,udp6,dl_dst=$mac,tp_src=5353,actions=NORMAL"
            # Allow SSDP/UPnP (239.255.255.250:1900)
            add_flow "priority=475,udp,dl_src=$mac,nw_dst=239.255.255.250,tp_dst=1900,actions=NORMAL"
            add_flow "priority=475,udp,dl_dst=$mac,nw_src=239.255.255.250,tp_src=1900,actions=NORMAL"
            log_info "Applied SMART_HOME policy for $mac (LAN access + mDNS/SSDP, containers blocked)"
            ;;

        full_access|normal|default|"")
            # No per-device rules needed - base priority 500 rules allow all
            log_info "Applied FULL_ACCESS policy for $mac (no restrictions)"
            ;;

        *)
            log_warn "Unknown policy '$policy' for $mac - skipping"
            ;;
    esac
}

# Sync all policies from SDN Autopilot database (PRIMARY)
sync_from_autopilot() {
    if [ ! -f "$AUTOPILOT_DB" ]; then
        log_info "No autopilot database found at $AUTOPILOT_DB"
        return 1
    fi

    if ! command -v sqlite3 &>/dev/null; then
        log_warn "sqlite3 not found - cannot sync policies"
        return 1
    fi

    local synced=0
    local failed=0

    # Query device_identity table for devices with policies
    # Only sync devices that have restrictive policies (not normal/full_access)
    while IFS='|' read -r mac policy ip; do
        if [ -n "$mac" ] && [ -n "$policy" ]; then
            if apply_policy "$mac" "$policy"; then
                synced=$((synced + 1))
            else
                failed=$((failed + 1))
            fi
        fi
    done < <(sqlite3 "$AUTOPILOT_DB" "SELECT mac, policy, ip FROM device_identity WHERE policy IS NOT NULL AND policy != '' AND policy NOT IN ('smart_home', 'full_access')" 2>/dev/null || true)

    log_info "NAC autopilot sync complete: $synced synced, $failed failed"
    return 0
}

# Sync all policies from legacy SQLite database (FALLBACK)
sync_from_sqlite() {
    if [ ! -f "$DEVICES_DB" ]; then
        log_info "No legacy devices database found at $DEVICES_DB"
        return 1
    fi

    if ! command -v sqlite3 &>/dev/null; then
        log_warn "sqlite3 not found - cannot sync policies"
        return 1
    fi

    local synced=0
    local failed=0

    # Query all devices with policies
    while IFS='|' read -r mac policy; do
        if [ -n "$mac" ] && [ -n "$policy" ]; then
            if apply_policy "$mac" "$policy"; then
                synced=$((synced + 1))
            else
                failed=$((failed + 1))
            fi
        fi
    done < <(sqlite3 "$DEVICES_DB" "SELECT mac_address, policy FROM devices WHERE policy IS NOT NULL AND policy != ''" 2>/dev/null || true)

    log_info "NAC legacy sync complete: $synced synced, $failed failed"
    return 0
}

# Sync from JSON registry (fallback)
sync_from_json() {
    if [ ! -f "$DEVICE_REGISTRY" ]; then
        log_info "No device registry found at $DEVICE_REGISTRY"
        return 0
    fi

    if ! command -v python3 &>/dev/null; then
        log_warn "python3 not found - cannot parse JSON registry"
        return 1
    fi

    local synced=0

    # Parse JSON and extract MAC + policy
    while IFS='|' read -r mac policy; do
        if [ -n "$mac" ] && [ -n "$policy" ]; then
            if apply_policy "$mac" "$policy"; then
                synced=$((synced + 1))
            fi
        fi
    done < <(python3 -c "
import json
import sys
try:
    with open('$DEVICE_REGISTRY') as f:
        data = json.load(f)
    for mac, info in data.items():
        if isinstance(info, dict):
            policy = info.get('policy', '')
            if policy:
                print(f'{mac}|{policy}')
except Exception as e:
    print(f'Error: {e}', file=sys.stderr)
" 2>/dev/null || true)

    log_info "NAC JSON sync complete: $synced policies applied"
    return 0
}

# Show sync status
show_status() {
    echo "=== NAC Policy Sync Status ==="
    echo ""

    # Check SDN Autopilot database (primary)
    if [ -f "$AUTOPILOT_DB" ]; then
        echo "SDN Autopilot Database: $AUTOPILOT_DB"
        if command -v sqlite3 &>/dev/null; then
            local count
            count=$(sqlite3 "$AUTOPILOT_DB" "SELECT COUNT(*) FROM device_identity WHERE policy IS NOT NULL" 2>/dev/null || echo "0")
            echo "  Devices with policies: $count"
            echo ""
            echo "  Policies breakdown:"
            sqlite3 "$AUTOPILOT_DB" "SELECT policy, COUNT(*) FROM device_identity WHERE policy IS NOT NULL GROUP BY policy" 2>/dev/null | \
                while IFS='|' read -r policy cnt; do
                    printf "    %-15s %s\n" "$policy" "$cnt"
                done
            echo ""
            echo "  Quarantine devices:"
            sqlite3 "$AUTOPILOT_DB" "SELECT mac, ip, hostname FROM device_identity WHERE policy = 'quarantine'" 2>/dev/null | \
                while IFS='|' read -r mac ip hostname; do
                    printf "    %s (%s) %s\n" "$mac" "${ip:-no-ip}" "${hostname:-no-hostname}"
                done
        fi
    else
        echo "SDN Autopilot Database: Not found"
    fi

    echo ""

    # Check legacy database
    if [ -f "$DEVICES_DB" ]; then
        echo "Legacy Database: $DEVICES_DB (fallback)"
        if command -v sqlite3 &>/dev/null; then
            local count
            count=$(sqlite3 "$DEVICES_DB" "SELECT COUNT(*) FROM devices WHERE policy IS NOT NULL" 2>/dev/null || echo "0")
            echo "  Devices with policies: $count"
        fi
    else
        echo "Legacy Database: Not found"
    fi

    echo ""
    echo "OVS Bridge: $OVS_BRIDGE"

    if ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
        echo "  Status: Active"
        echo ""
        echo "  Per-device flows (priority >= 600):"
        ovs-ofctl dump-flows "$OVS_BRIDGE" 2>/dev/null | grep -E "priority=(6[0-9]{2}|7[0-9]{2}|1000|1001)" | head -20 || echo "    None"
        echo ""
        echo "  Ecosystem bubble flows (priority 450):"
        ovs-ofctl dump-flows "$OVS_BRIDGE" 2>/dev/null | grep -E "priority=450" | head -20 || echo "    None"
    else
        echo "  Status: Bridge not found"
    fi

    echo ""
    echo "=== Ecosystem Bubble Status ==="

    # Check bubble database
    local bubble_db="/var/lib/hookprobe/bubbles.db"
    if [ -f "$bubble_db" ]; then
        echo "Bubble Database: $bubble_db"
        if command -v sqlite3 &>/dev/null; then
            local bubble_count
            bubble_count=$(sqlite3 "$bubble_db" "SELECT COUNT(*) FROM bubbles WHERE state = 'active'" 2>/dev/null || echo "0")
            echo "  Active bubbles: $bubble_count"
            echo ""
            if [ "$bubble_count" -gt 0 ]; then
                echo "  Bubbles:"
                sqlite3 "$bubble_db" "SELECT bubble_id, ecosystem, confidence FROM bubbles WHERE state = 'active'" 2>/dev/null | \
                    while IFS='|' read -r bid eco conf; do
                        printf "    %s (%s) confidence=%.2f\n" "$bid" "$eco" "$conf"
                    done
            fi
        fi
    else
        echo "Bubble Database: Not found"
    fi

    # Check last trigger file
    if [ -f "${BUBBLE_TRIGGER_FILE}.processed" ]; then
        echo ""
        echo "Last bubble sync: $(stat -c '%y' "${BUBBLE_TRIGGER_FILE}.processed" 2>/dev/null | cut -d. -f1)"
    fi
}

# Main
main() {
    case "${1:-}" in
        --status)
            show_status
            ;;
        --trigger)
            # Check trigger file AND sync from database
            # This ensures policies persist even after OVS restarts
            if ! ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
                log_error "OVS bridge $OVS_BRIDGE not found"
                exit 1
            fi
            # First check for any pending trigger from container
            check_policy_trigger
            # Check for ecosystem bubble rules from container
            check_bubble_trigger
            # Then sync all restrictive policies from database
            # This is fast since we only sync quarantine/internet_only/lan_only
            if [ -f "$AUTOPILOT_DB" ]; then
                sync_from_autopilot
            fi
            ;;
        --help|-h)
            echo "Usage: $0 [--status|--trigger|--help]"
            echo ""
            echo "Syncs NAC device policies from database to OpenFlow rules."
            echo ""
            echo "Options:"
            echo "  --status    Show current sync status"
            echo "  --trigger   Only check for container trigger file (fast path)"
            echo "  --help      Show this help"
            ;;
        *)
            # Check if OVS bridge exists
            if ! ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
                log_error "OVS bridge $OVS_BRIDGE not found"
                exit 1
            fi

            # First check for any pending policy trigger from container
            check_policy_trigger
            # Check for ecosystem bubble rules from container
            check_bubble_trigger

            log_info "Starting NAC policy sync..."

            # Try SDN Autopilot database first (PRIMARY), then legacy, then JSON
            if [ -f "$AUTOPILOT_DB" ]; then
                sync_from_autopilot
            elif [ -f "$DEVICES_DB" ]; then
                sync_from_sqlite
            elif [ -f "$DEVICE_REGISTRY" ]; then
                sync_from_json
            else
                log_info "No policy databases found - nothing to sync"
            fi
            ;;
    esac
}

main "$@"
