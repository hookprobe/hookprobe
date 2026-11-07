#!/bin/bash
#
# HookProbe Fortress - SDN Configuration Migration Script
#
# DEPRECATED: This script was for VLAN-based architecture which is no longer used.
# Fortress now uses a flat OVS bridge with OpenFlow-based micro-segmentation.
#
# Migrates existing installations to the unified SDN architecture:
# - LAN: 10.200.0.0/24 - All WiFi/LAN clients on OVS bridge
# - Segments: Logical isolation via OpenFlow rules (no VLAN tagging)
#
# Usage: sudo ./migrate-sdn-config.sh [--dry-run] [--force]
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
OVS_BRIDGE="${OVS_BRIDGE:-FTS}"
CONFIG_DIR="/etc/hookprobe"
FORTRESS_CONF="$CONFIG_DIR/fortress.conf"
DNSMASQ_CONF="/etc/dnsmasq.d/fortress.conf"
BACKUP_DIR="/var/backups/hookprobe/migration-$(date +%Y%m%d-%H%M%S)"

# Network configuration (aligned with install scripts)
# NOTE: VLANs no longer used - flat bridge with OpenFlow segmentation
LAN_SEGMENT=100   # Legacy - kept for migration compatibility
MGMT_SEGMENT=200  # Legacy - kept for migration compatibility
LAN_SUBNET="10.200.0.0/24"
LAN_GATEWAY="10.200.0.1"
DHCP_START="10.200.0.100"
DHCP_END="10.200.0.200"

# Flags
DRY_RUN=false
FORCE=false
VERBOSE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--dry-run] [--force] [--verbose]"
            echo ""
            echo "Options:"
            echo "  --dry-run    Show what would be changed without making changes"
            echo "  --force      Skip confirmation prompts"
            echo "  --verbose    Show detailed output"
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
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }

# Check if running as root
if [ "$EUID" -ne 0 ] && [ "$DRY_RUN" = false ]; then
    log_error "Please run as root (sudo)"
    exit 1
fi

echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     HookProbe Fortress - SDN Configuration Migration          ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$DRY_RUN" = true ]; then
    log_warn "DRY RUN MODE - No changes will be made"
    echo ""
fi

# ============================================================
# STEP 1: Detect Current Configuration
# ============================================================

log_step "Step 1: Detecting current configuration..."

# Check if Fortress is installed
if ! command -v ovs-vsctl &>/dev/null; then
    log_error "Open vSwitch not installed. Is Fortress installed?"
    exit 1
fi

# Check OVS bridge
if ! ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
    log_error "OVS bridge '$OVS_BRIDGE' not found"
    exit 1
fi

log_success "OVS bridge '$OVS_BRIDGE' found"

# Detect current network mode
CURRENT_MODE="unknown"
if ip link show FTS &>/dev/null; then
    CURRENT_MODE="vlan"
    log_info "Current mode: VLAN (FTS/FTS interfaces detected)"
elif ip addr show "$OVS_BRIDGE" 2>/dev/null | grep -q "10.200.0.1"; then
    CURRENT_MODE="filter"
    log_info "Current mode: Filter (IP on bridge)"
elif ip addr show "$OVS_BRIDGE" 2>/dev/null | grep -q "10.250."; then
    CURRENT_MODE="legacy"
    log_warn "Current mode: Legacy (10.250.x.x subnet detected - needs migration)"
else
    log_warn "Current mode: Unknown"
fi

# Check current DHCP configuration
CURRENT_DHCP_SUBNET="unknown"
if [ -f "$DNSMASQ_CONF" ]; then
    if grep -q "10.200.0" "$DNSMASQ_CONF" 2>/dev/null; then
        CURRENT_DHCP_SUBNET="10.200.0.x"
        log_success "DHCP subnet: 10.200.0.x (correct)"
    elif grep -q "10.250.0" "$DNSMASQ_CONF" 2>/dev/null; then
        CURRENT_DHCP_SUBNET="10.250.0.x"
        log_warn "DHCP subnet: 10.250.0.x (needs migration)"
    fi
elif [ -f "/etc/dnsmasq.d/fortress-bridge.conf" ]; then
    DNSMASQ_CONF="/etc/dnsmasq.d/fortress-bridge.conf"
    if grep -q "10.200.0" "$DNSMASQ_CONF" 2>/dev/null; then
        CURRENT_DHCP_SUBNET="10.200.0.x"
        log_success "DHCP subnet: 10.200.0.x (correct)"
    elif grep -q "10.250.0" "$DNSMASQ_CONF" 2>/dev/null; then
        CURRENT_DHCP_SUBNET="10.250.0.x"
        log_warn "DHCP subnet: 10.250.0.x (needs migration)"
    fi
fi

# Check Python config
PYTHON_CONFIG_NEEDS_UPDATE=false
if [ -f "$FORTRESS_CONF" ]; then
    log_info "Fortress config file found: $FORTRESS_CONF"
else
    log_info "No fortress.conf found (using Python defaults)"
fi

echo ""

# ============================================================
# STEP 2: Determine Required Changes
# ============================================================

log_step "Step 2: Determining required changes..."

CHANGES_NEEDED=()

# Check if DHCP needs update
if [ "$CURRENT_DHCP_SUBNET" = "10.250.0.x" ]; then
    CHANGES_NEEDED+=("Update DHCP from 10.250.x.x to 10.200.x.x")
fi

# Check if VLAN interfaces need creation (filter mode → VLAN mode upgrade)
if [ "$CURRENT_MODE" = "filter" ] || [ "$CURRENT_MODE" = "legacy" ]; then
    if ! ip link show FTS &>/dev/null; then
        CHANGES_NEEDED+=("Create FTS interface (LAN)")
    fi
    if ! ip link show FTS &>/dev/null; then
        CHANGES_NEEDED+=("Create FTS interface (MGMT)")
    fi
fi

# Check OpenFlow rules for segments
SEGMENT_RULES_EXIST=false
if ovs-ofctl dump-flows "$OVS_BRIDGE" 2>/dev/null | grep -q "priority=200"; then
    SEGMENT_RULES_EXIST=true
    log_info "Segment OpenFlow rules found"
else
    CHANGES_NEEDED+=("Install segment OpenFlow rules")
fi

# Check IP configuration
CURRENT_LAN_IP=$(ip addr show FTS 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
if [ -z "$CURRENT_LAN_IP" ]; then
    CURRENT_LAN_IP=$(ip addr show "$OVS_BRIDGE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
fi

if [ "$CURRENT_LAN_IP" != "10.200.0.1" ] && [ -n "$CURRENT_LAN_IP" ]; then
    CHANGES_NEEDED+=("Update LAN gateway IP to 10.200.0.1")
fi

if [ ${#CHANGES_NEEDED[@]} -eq 0 ]; then
    log_success "No migration needed - configuration is already aligned!"
    echo ""
    echo "Current configuration:"
    echo "  - Network mode: $CURRENT_MODE"
    echo "  - DHCP subnet: $CURRENT_DHCP_SUBNET"
    echo "  - LAN Gateway: ${CURRENT_LAN_IP:-N/A}"
    echo "  - Segment rules: $SEGMENT_RULES_EXIST"
    exit 0
fi

echo ""
echo "The following changes are required:"
for change in "${CHANGES_NEEDED[@]}"; do
    echo -e "  ${YELLOW}→${NC} $change"
done
echo ""

# Confirm with user
if [ "$DRY_RUN" = true ]; then
    log_info "Dry run complete. Use without --dry-run to apply changes."
    exit 0
fi

if [ "$FORCE" = false ]; then
    read -p "Proceed with migration? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Migration cancelled"
        exit 0
    fi
fi

# ============================================================
# STEP 3: Create Backup
# ============================================================

log_step "Step 3: Creating backup..."

mkdir -p "$BACKUP_DIR"

# Backup dnsmasq config
if [ -f "$DNSMASQ_CONF" ]; then
    cp "$DNSMASQ_CONF" "$BACKUP_DIR/dnsmasq.conf.bak"
    log_info "Backed up: $DNSMASQ_CONF"
fi

# Backup OVS flows
ovs-ofctl dump-flows "$OVS_BRIDGE" > "$BACKUP_DIR/ovs-flows.bak" 2>/dev/null || true
log_info "Backed up: OVS flows"

# Backup fortress.conf if exists
if [ -f "$FORTRESS_CONF" ]; then
    cp "$FORTRESS_CONF" "$BACKUP_DIR/fortress.conf.bak"
    log_info "Backed up: $FORTRESS_CONF"
fi

log_success "Backup created at: $BACKUP_DIR"
echo ""

# ============================================================
# STEP 4: Update DHCP Configuration
# ============================================================

if [ "$CURRENT_DHCP_SUBNET" = "10.250.0.x" ]; then
    log_step "Step 4: Updating DHCP configuration..."

    # Determine interface to listen on
    DHCP_INTERFACE="$OVS_BRIDGE"
    if [ "$CURRENT_MODE" = "vlan" ] || ip link show FTS &>/dev/null; then
        DHCP_INTERFACE="FTS"
    fi

    cat > "$DNSMASQ_CONF" << EOF
# HookProbe Fortress - DHCP Configuration
# Migrated by migrate-sdn-config.sh on $(date)
# Previous config backed up to: $BACKUP_DIR

# Bind to LAN interface
interface=$DHCP_INTERFACE
bind-interfaces

# LAN DHCP range (10.200.0.0/24)
dhcp-range=$DHCP_START,$DHCP_END,255.255.255.0,12h

# Gateway
dhcp-option=3,$LAN_GATEWAY

# DNS (local dnsXai)
dhcp-option=6,$LAN_GATEWAY

# Domain
domain=hookprobe.local
local=/hookprobe.local/

# Logging
log-queries
log-dhcp

# Performance
cache-size=1000
EOF

    log_success "DHCP configuration updated"

    # Restart dnsmasq
    if systemctl is-active --quiet dnsmasq; then
        systemctl restart dnsmasq
        log_success "dnsmasq restarted"
    fi
fi

# ============================================================
# STEP 5: Create/Update VLAN Interfaces
# ============================================================

log_step "Step 5: Configuring VLAN interfaces..."

# Create FTS if needed
if ! ip link show FTS &>/dev/null; then
    log_info "Creating FTS (LAN) interface..."
    ovs-vsctl add-port "$OVS_BRIDGE" FTS -- set interface FTS type=internal
    ovs-vsctl set port FTS tag=$LAN_VLAN
    ip link set FTS up
    ip addr add "$LAN_GATEWAY/24" dev FTS 2>/dev/null || true
    log_success "FTS created with IP $LAN_GATEWAY"
else
    # Ensure correct IP
    if ! ip addr show FTS | grep -q "$LAN_GATEWAY"; then
        ip addr add "$LAN_GATEWAY/24" dev FTS 2>/dev/null || true
        log_info "Added $LAN_GATEWAY to FTS"
    fi
fi

# NOTE: FTS bridge interface setup is now handled by netplan/ovs-post-setup.sh
# This section is kept for legacy migration only
if ! ip link show FTS &>/dev/null; then
    log_info "FTS bridge not found - should be created by netplan"
    log_warn "Run install.sh to set up FTS bridge properly"
else
    # Verify FTS has correct IP
    if ! ip addr show FTS | grep -q "$LAN_GATEWAY"; then
        ip addr add "$LAN_GATEWAY/24" dev FTS 2>/dev/null || true
        log_info "Added $LAN_GATEWAY to FTS"
    fi
fi

echo ""

# ============================================================
# STEP 6: Install Segment OpenFlow Rules
# ============================================================

log_step "Step 6: Installing segment OpenFlow rules..."

# Base rules for LAN traffic
ovs-ofctl add-flow "$OVS_BRIDGE" "priority=500,ip,nw_src=10.200.0.0/16,actions=NORMAL" 2>/dev/null || true
ovs-ofctl add-flow "$OVS_BRIDGE" "priority=500,ip,nw_dst=10.200.0.0/16,actions=NORMAL" 2>/dev/null || true

# ARP handling
ovs-ofctl add-flow "$OVS_BRIDGE" "priority=400,arp,actions=NORMAL" 2>/dev/null || true

# DHCP handling
ovs-ofctl add-flow "$OVS_BRIDGE" "priority=450,udp,tp_src=68,tp_dst=67,actions=NORMAL" 2>/dev/null || true
ovs-ofctl add-flow "$OVS_BRIDGE" "priority=450,udp,tp_src=67,tp_dst=68,actions=NORMAL" 2>/dev/null || true

# Default rule
ovs-ofctl add-flow "$OVS_BRIDGE" "priority=0,actions=NORMAL" 2>/dev/null || true

log_success "Base OpenFlow rules installed"

# Segment isolation rules (Guest and Quarantine)
# Guest (VLAN 40) - Internet only, no LAN access
ovs-ofctl add-flow "$OVS_BRIDGE" "priority=300,dl_vlan=40,ip,nw_dst=10.200.0.0/16,actions=drop" 2>/dev/null || true

# Quarantine (VLAN 99) - No access
ovs-ofctl add-flow "$OVS_BRIDGE" "priority=300,dl_vlan=99,ip,actions=drop" 2>/dev/null || true

# POS (VLAN 20) - Isolated, internet only
ovs-ofctl add-flow "$OVS_BRIDGE" "priority=300,dl_vlan=20,ip,nw_dst=10.200.0.0/16,actions=drop" 2>/dev/null || true

log_success "Segment isolation rules installed"
echo ""

# ============================================================
# STEP 7: Update NAT Rules
# ============================================================

log_step "Step 7: Updating NAT rules..."

# Get WAN interface
WAN_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)

if [ -n "$WAN_INTERFACE" ]; then
    # Remove old NAT rule if exists
    iptables -t nat -D POSTROUTING -s 10.250.0.0/24 -o "$WAN_INTERFACE" -j MASQUERADE 2>/dev/null || true

    # Add new NAT rule
    if ! iptables -t nat -C POSTROUTING -s 10.200.0.0/24 -o "$WAN_INTERFACE" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s 10.200.0.0/24 -o "$WAN_INTERFACE" -j MASQUERADE
        log_success "NAT rule added for 10.200.0.0/24 → $WAN_INTERFACE"
    else
        log_info "NAT rule already exists"
    fi
else
    log_warn "Could not detect WAN interface - NAT not updated"
fi

echo ""

# ============================================================
# STEP 8: Verify Configuration
# ============================================================

log_step "Step 8: Verifying configuration..."

ERRORS=0

# Check FTS
if ip addr show FTS 2>/dev/null | grep -q "$LAN_GATEWAY"; then
    log_success "FTS: $LAN_GATEWAY ✓"
else
    log_error "FTS: IP not configured"
    ((ERRORS++))
fi

# Check FTS
if ip addr show FTS 2>/dev/null | grep -q "$MGMT_GATEWAY"; then
    log_success "FTS: $MGMT_GATEWAY ✓"
else
    log_error "FTS: IP not configured"
    ((ERRORS++))
fi

# Check dnsmasq
if systemctl is-active --quiet dnsmasq; then
    log_success "dnsmasq: running ✓"
else
    log_warn "dnsmasq: not running"
fi

# Check OVS flows
FLOW_COUNT=$(ovs-ofctl dump-flows "$OVS_BRIDGE" 2>/dev/null | grep -c "priority=" || echo 0)
log_info "OVS flows: $FLOW_COUNT rules installed"

echo ""

# ============================================================
# Summary
# ============================================================

echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo ""

if [ $ERRORS -eq 0 ]; then
    log_success "Migration completed successfully!"
else
    log_warn "Migration completed with $ERRORS errors"
fi

echo ""
echo "Configuration Summary:"
echo "  FTS Bridge:     10.200.0.0/24 → Gateway: 10.200.0.1"
echo "  DHCP Range:      $DHCP_START - $DHCP_END"
echo ""
echo "Backup location: $BACKUP_DIR"
echo ""

if [ $ERRORS -gt 0 ]; then
    echo "To restore from backup:"
    echo "  cp $BACKUP_DIR/dnsmasq.conf.bak $DNSMASQ_CONF"
    echo "  systemctl restart dnsmasq"
fi

echo ""
echo "Next steps:"
echo "  1. Verify network connectivity from a client device"
echo "  2. Check DHCP leases: cat /var/lib/misc/dnsmasq.leases"
echo "  3. Access dashboard: https://10.200.0.1:8443 or https://10.200.100.1:8443"
echo ""
