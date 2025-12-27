#!/bin/bash
#
# HookProbe Fortress - SDN Configuration Update Script
#
# Updates existing installations to include network state in fortress-state.json
# This allows the Python config.py to load the actual network configuration.
#
# Usage: sudo ./update-sdn-state.sh [--dry-run]
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
CONFIG_DIR="/etc/hookprobe"
STATE_FILE="$CONFIG_DIR/fortress-state.json"
OVS_BRIDGE="${OVS_BRIDGE:-FTS}"

# Flags
DRY_RUN=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--dry-run]"
            echo ""
            echo "Updates fortress-state.json with network configuration."
            echo "This allows config.py to load the actual network settings."
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
if [ "$EUID" -ne 0 ] && [ "$DRY_RUN" = false ]; then
    log_error "Please run as root (sudo)"
    exit 1
fi

echo ""
echo -e "${CYAN}╔═════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     HookProbe Fortress - SDN State Update                   ║${NC}"
echo -e "${CYAN}╚═════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if state file exists
if [ ! -f "$STATE_FILE" ]; then
    log_error "State file not found: $STATE_FILE"
    log_error "Is Fortress installed?"
    exit 1
fi

log_info "Found state file: $STATE_FILE"

# Detect current network configuration
log_info "Detecting network configuration..."

# Detect bridge name
DETECTED_BRIDGE=""
for bridge in FTS fortress br-fortress; do
    if ovs-vsctl br-exists "$bridge" 2>/dev/null; then
        DETECTED_BRIDGE="$bridge"
        break
    fi
done

if [ -z "$DETECTED_BRIDGE" ]; then
    log_warn "No OVS bridge found, using default: FTS"
    DETECTED_BRIDGE="FTS"
else
    log_success "Detected OVS bridge: $DETECTED_BRIDGE"
fi

# Detect LAN gateway IP
DETECTED_GATEWAY=""
DETECTED_SUBNET=""

# VLAN mode: Get IP from vlan100 interface
if ip addr show vlan100 2>/dev/null | grep -q "inet "; then
    DETECTED_GATEWAY=$(ip addr show vlan100 | grep -oP 'inet \K[\d.]+' | head -1)
    DETECTED_SUBNET=$(ip addr show vlan100 | grep -oP 'inet \K[\d./]+' | head -1)
    log_success "VLAN mode: vlan100 = $DETECTED_SUBNET"
fi

if [ -z "$DETECTED_GATEWAY" ]; then
    log_warn "Could not detect gateway IP, using default: 10.200.0.1/24"
    DETECTED_GATEWAY="10.200.0.1"
    DETECTED_SUBNET="10.200.0.0/24"
fi

# Extract subnet from CIDR
if [[ "$DETECTED_SUBNET" == *"/"* ]]; then
    # Has CIDR notation - extract network
    GATEWAY_IP="${DETECTED_SUBNET%/*}"
    SUBNET_MASK="${DETECTED_SUBNET#*/}"
    # Calculate network address (simple: assume .1 gateway means .0 network)
    NETWORK_ADDR="${GATEWAY_IP%.*}.0"
    LAN_SUBNET="${NETWORK_ADDR}/${SUBNET_MASK}"
else
    LAN_SUBNET="10.200.0.0/24"
fi

log_info "LAN subnet: $LAN_SUBNET"
log_info "LAN gateway: $DETECTED_GATEWAY"

# Always VLAN mode (filter mode removed)
NETWORK_MODE="vlan"
log_info "Network mode: VLAN"

# Detect DHCP range from dnsmasq config
DHCP_START="10.200.0.100"
DHCP_END="10.200.0.200"

for conf in /etc/dnsmasq.d/fortress*.conf /etc/dnsmasq.d/fts*.conf; do
    if [ -f "$conf" ]; then
        DHCP_RANGE=$(grep -oP 'dhcp-range=\K[^,]+,[^,]+' "$conf" 2>/dev/null | head -1)
        if [ -n "$DHCP_RANGE" ]; then
            DHCP_START="${DHCP_RANGE%,*}"
            DHCP_END="${DHCP_RANGE#*,}"
            log_info "DHCP range: $DHCP_START - $DHCP_END"
            break
        fi
    fi
done

# Read existing state
EXISTING_STATE=$(cat "$STATE_FILE")

# Check if network config already exists
if echo "$EXISTING_STATE" | grep -q '"lan_subnet"'; then
    log_info "Network configuration already exists in state file"

    # Show current values
    CURRENT_SUBNET=$(echo "$EXISTING_STATE" | grep -oP '"lan_subnet":\s*"\K[^"]+')
    CURRENT_GATEWAY=$(echo "$EXISTING_STATE" | grep -oP '"lan_gateway":\s*"\K[^"]+')

    log_info "  Current: subnet=$CURRENT_SUBNET, gateway=$CURRENT_GATEWAY"
    log_info "  Detected: subnet=$LAN_SUBNET, gateway=$DETECTED_GATEWAY"

    if [ "$CURRENT_SUBNET" = "$LAN_SUBNET" ] && [ "$CURRENT_GATEWAY" = "$DETECTED_GATEWAY" ]; then
        log_success "Configuration is up to date!"
        exit 0
    fi
fi

echo ""
log_info "Will update state file with:"
echo "  lan_subnet: $LAN_SUBNET"
echo "  lan_gateway: $DETECTED_GATEWAY"
echo "  ovs_bridge: $DETECTED_BRIDGE"
echo "  network_mode: $NETWORK_MODE"
echo "  dhcp_start: $DHCP_START"
echo "  dhcp_end: $DHCP_END"
echo ""

if [ "$DRY_RUN" = true ]; then
    log_info "Dry run complete. Use without --dry-run to apply changes."
    exit 0
fi

# Backup existing state
cp "$STATE_FILE" "${STATE_FILE}.bak"
log_info "Backed up state file to ${STATE_FILE}.bak"

# Update state file using Python for proper JSON handling
python3 << EOF
import json
import sys

try:
    with open('$STATE_FILE', 'r') as f:
        state = json.load(f)
except json.JSONDecodeError:
    print("Error: Invalid JSON in state file", file=sys.stderr)
    sys.exit(1)

# Update network configuration
state['lan_subnet'] = '$LAN_SUBNET'
state['lan_gateway'] = '$DETECTED_GATEWAY'
state['ovs_bridge'] = '$DETECTED_BRIDGE'
state['network_mode'] = '$NETWORK_MODE'
state['lan_dhcp_start'] = '$DHCP_START'
state['lan_dhcp_end'] = '$DHCP_END'

with open('$STATE_FILE', 'w') as f:
    json.dump(state, f, indent=4)

print("State file updated successfully")
EOF

if [ $? -eq 0 ]; then
    log_success "State file updated!"
    echo ""
    echo "The Python config.py will now load these network settings."
    echo "Restart the web container to apply: systemctl restart fortress"
else
    log_error "Failed to update state file"
    log_info "Restoring backup..."
    cp "${STATE_FILE}.bak" "$STATE_FILE"
    exit 1
fi
