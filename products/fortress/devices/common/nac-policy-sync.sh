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
#   3. fts-ovs-connect.sh calls this script to apply per-device rules (priority 600-750)
#
# Per-device policies override base rules with higher priority:
#   - QUARANTINE: Priority 1000-1001 (drop all except DHCP/DNS)
#   - LAN_ONLY: Priority 600-750 (allow LAN, block internet)
#   - INTERNET_ONLY: Priority 650-750 (block LAN, allow internet)
#   - FULL_ACCESS/NORMAL/SMART_HOME: No rules needed (use base priority 500)
#

set -e

LOG_TAG="fts-nac"
OVS_BRIDGE="${OVS_BRIDGE:-FTS}"
LAN_NETWORK="${LAN_NETWORK:-10.200.0.0/16}"
GATEWAY_IP="${GATEWAY_IP:-10.200.0.1}"
CONTAINER_NETWORK="172.20.0.0/16"

# Trigger file from container for real-time policy application
POLICY_TRIGGER_FILE="/opt/hookprobe/fortress/data/.nac_policy_sync"

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
apply_policy() {
    local mac="$1"
    local policy="$2"

    mac=$(echo "$mac" | tr '[:lower:]' '[:upper:]')

    # Remove existing rules first
    remove_device_rules "$mac"

    case "$policy" in
        isolated|quarantine)
            # QUARANTINE: Block all traffic except DHCP and DNS to gateway
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
            # Allow gateway
            add_flow "priority=750,ip,dl_src=$mac,nw_dst=$GATEWAY_IP,actions=NORMAL"
            # Allow LAN
            add_flow "priority=740,ip,dl_src=$mac,nw_dst=$LAN_NETWORK,actions=NORMAL"
            # Allow return from LAN
            add_flow "priority=730,ip,dl_dst=$mac,nw_src=$LAN_NETWORK,actions=NORMAL"
            # Allow container network
            add_flow "priority=720,ip,dl_src=$mac,nw_dst=$CONTAINER_NETWORK,actions=NORMAL"
            # Block internet
            add_flow "priority=600,ip,dl_src=$mac,actions=drop"
            log_info "Applied LAN_ONLY policy for $mac"
            ;;

        internet_only)
            # Allow gateway
            add_flow "priority=750,ip,dl_src=$mac,nw_dst=$GATEWAY_IP,actions=NORMAL"
            add_flow "priority=740,ip,dl_dst=$mac,nw_src=$GATEWAY_IP,actions=NORMAL"
            # Block LAN (except gateway above)
            add_flow "priority=700,ip,dl_src=$mac,nw_dst=$LAN_NETWORK,actions=drop"
            add_flow "priority=700,ip,dl_dst=$mac,nw_src=$LAN_NETWORK,actions=drop"
            # Allow internet
            add_flow "priority=650,ip,dl_src=$mac,actions=NORMAL"
            add_flow "priority=650,ip,dl_dst=$mac,actions=NORMAL"
            log_info "Applied INTERNET_ONLY policy for $mac"
            ;;

        full_access|normal|smart_home|default|"")
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
    done < <(sqlite3 "$AUTOPILOT_DB" "SELECT mac, policy, ip FROM device_identity WHERE policy IS NOT NULL AND policy != '' AND policy NOT IN ('normal', 'smart_home', 'full_access')" 2>/dev/null || true)

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
    else
        echo "  Status: Bridge not found"
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
