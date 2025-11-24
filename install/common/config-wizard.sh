#!/bin/bash
#
# config-wizard.sh - Interactive Configuration Wizard
# Version: 5.0
# License: MIT
#
# Provides interactive configuration for HookProbe deployment
#

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration variables
DEPLOYMENT_TYPE=""
CONFIG_FILE=""

# Network configuration
DETECTED_INTERFACES=()
WAN_INTERFACE=""
LAN_INTERFACE=""
HOST_IP=""
BRIDGE_NAME="qsec-bridge"
BRIDGE_IP="10.200.0.1"

# POD Network Configuration
POD_001_NETWORK="10.200.1.0/24"
POD_002_NETWORK="10.200.2.0/24"
POD_003_NETWORK="10.200.3.0/24"
POD_004_NETWORK="10.200.4.0/24"
POD_005_NETWORK="10.200.5.0/24"
POD_006_NETWORK="10.200.6.0/24"
POD_007_NETWORK="10.200.7.0/24"
POD_008_NETWORK="10.200.8.0/24"

# VNI Configuration
VNI_001=201
VNI_002=202
VNI_003=203
VNI_004=204
VNI_005=205
VNI_006=206
VNI_007=207
VNI_008=208

# VXLAN Configuration
VXLAN_PSK=""
VXLAN_PORT=4789

# Service Passwords
GRAFANA_PASSWORD="admin"
POSTGRES_PASSWORD=""
REDIS_PASSWORD=""
KEYCLOAK_PASSWORD=""
N8N_PASSWORD=""

# Feature Flags
ENABLE_CLOUDFLARE=false
ENABLE_XDP=true
ENABLE_GDPR=true

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Utility Functions
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

print_header() {
    clear
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}   HookProbe Configuration Wizard${NC}"
    echo -e "${BLUE}   $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

print_info() {
    echo -e "${CYAN}ℹ ${NC}$1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

prompt_input() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"

    if [ -n "$default" ]; then
        read -p "$(echo -e ${CYAN}${prompt}${NC} [${GREEN}${default}${NC}]: )" input
        eval $var_name="${input:-$default}"
    else
        read -p "$(echo -e ${CYAN}${prompt}${NC}: )" input
        eval $var_name="$input"
    fi
}

prompt_password() {
    local prompt="$1"
    local var_name="$2"
    local password1=""
    local password2=""

    while true; do
        read -sp "$(echo -e ${CYAN}${prompt}${NC}: )" password1
        echo ""
        read -sp "$(echo -e ${CYAN}Confirm password${NC}: )" password2
        echo ""

        if [ "$password1" = "$password2" ]; then
            if [ ${#password1} -ge 8 ]; then
                eval $var_name="$password1"
                break
            else
                print_error "Password must be at least 8 characters"
            fi
        else
            print_error "Passwords do not match. Try again."
        fi
    done
}

prompt_yesno() {
    local prompt="$1"
    local default="$2"

    if [ "$default" = "y" ]; then
        read -p "$(echo -e ${CYAN}${prompt}${NC} [${GREEN}Y${NC}/n]: )" answer
        answer=${answer:-y}
    else
        read -p "$(echo -e ${CYAN}${prompt}${NC} [y/${GREEN}N${NC}]: )" answer
        answer=${answer:-n}
    fi

    [[ "$answer" =~ ^[Yy] ]]
}

generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-24
}

generate_psk() {
    openssl rand -base64 32
}

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Network Detection
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

detect_network_interfaces() {
    print_header "Detecting Network Interfaces"

    print_info "Scanning network interfaces..."

    # Get all physical network interfaces (exclude virtual, loopback, docker, etc.)
    DETECTED_INTERFACES=()
    while IFS= read -r iface; do
        # Skip loopback, docker, veth, br-, vxlan, etc.
        if [[ ! "$iface" =~ ^(lo|docker|veth|br-|vxlan|virbr) ]]; then
            DETECTED_INTERFACES+=("$iface")
        fi
    done < <(ip -o link show | awk -F': ' '{print $2}' | grep -v '@')

    if [ ${#DETECTED_INTERFACES[@]} -eq 0 ]; then
        print_error "No suitable network interfaces found"
        exit 1
    fi

    echo ""
    print_success "Detected ${#DETECTED_INTERFACES[@]} network interface(s):"
    echo ""

    local idx=1
    for iface in "${DETECTED_INTERFACES[@]}"; do
        local ip_addr=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | head -1)
        local status=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo "unknown")
        local speed=$(cat "/sys/class/net/$iface/speed" 2>/dev/null || echo "?")

        printf "  ${YELLOW}%d${NC}) %-12s " "$idx" "$iface"
        printf "IP: %-15s " "${ip_addr:-none}"
        printf "Status: %-8s " "$status"
        printf "Speed: %s Mbps\n" "$speed"
        ((idx++))
    done
    echo ""
}

select_wan_interface() {
    print_header "WAN Interface Selection"

    print_info "Select the WAN (Internet-facing) interface"
    echo ""

    local idx=1
    for iface in "${DETECTED_INTERFACES[@]}"; do
        echo "  ${YELLOW}$idx${NC}) $iface"
        ((idx++))
    done
    echo ""

    while true; do
        read -p "$(echo -e ${CYAN}Select WAN interface${NC} [1-${#DETECTED_INTERFACES[@]}]: )" selection

        if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "${#DETECTED_INTERFACES[@]}" ]; then
            WAN_INTERFACE="${DETECTED_INTERFACES[$((selection-1))]}"
            print_success "Selected WAN interface: $WAN_INTERFACE"
            sleep 1
            break
        else
            print_error "Invalid selection"
        fi
    done
}

configure_host_network() {
    print_header "Host Network Configuration"

    # Detect current IP on WAN interface
    local current_ip=$(ip -4 addr show "$WAN_INTERFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | head -1)

    if [ -n "$current_ip" ]; then
        print_info "Current IP on $WAN_INTERFACE: $current_ip"
        if prompt_yesno "Use this IP address?" "y"; then
            HOST_IP="$current_ip"
        fi
    fi

    if [ -z "$HOST_IP" ]; then
        prompt_input "Enter host IP address" "192.168.1.100" HOST_IP
    fi

    echo ""
    prompt_input "Bridge name" "$BRIDGE_NAME" BRIDGE_NAME
    prompt_input "Bridge IP address" "$BRIDGE_IP" BRIDGE_IP

    print_success "Network configuration set"
    sleep 1
}

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# POD Network Configuration
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

configure_pod_networks() {
    print_header "POD Network Configuration"

    print_info "Configure POD networks and VNI numbers"
    echo ""
    print_warning "Press Enter to use defaults or customize each POD"
    echo ""

    if ! prompt_yesno "Use default POD networks (10.200.x.0/24)?" "y"; then
        echo ""
        prompt_input "POD 001 (Web DMZ) network" "$POD_001_NETWORK" POD_001_NETWORK
        prompt_input "POD 002 (IAM) network" "$POD_002_NETWORK" POD_002_NETWORK
        prompt_input "POD 003 (Database) network" "$POD_003_NETWORK" POD_003_NETWORK
        prompt_input "POD 004 (Cache) network" "$POD_004_NETWORK" POD_004_NETWORK
        prompt_input "POD 005 (Monitoring) network" "$POD_005_NETWORK" POD_005_NETWORK
        prompt_input "POD 006 (Security) network" "$POD_006_NETWORK" POD_006_NETWORK
        prompt_input "POD 007 (Response) network" "$POD_007_NETWORK" POD_007_NETWORK
    fi

    echo ""
    if ! prompt_yesno "Use default VNI numbers (201-208)?" "y"; then
        echo ""
        prompt_input "VNI for POD 001" "$VNI_001" VNI_001
        prompt_input "VNI for POD 002" "$VNI_002" VNI_002
        prompt_input "VNI for POD 003" "$VNI_003" VNI_003
        prompt_input "VNI for POD 004" "$VNI_004" VNI_004
        prompt_input "VNI for POD 005" "$VNI_005" VNI_005
        prompt_input "VNI for POD 006" "$VNI_006" VNI_006
        prompt_input "VNI for POD 007" "$VNI_007" VNI_007
    fi

    print_success "POD networks configured"
    sleep 1
}

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Security Configuration
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

configure_vxlan_security() {
    print_header "VXLAN Security Configuration"

    print_info "VXLAN tunnels use PSK (Pre-Shared Key) encryption"
    echo ""

    if prompt_yesno "Generate random PSK?" "y"; then
        VXLAN_PSK=$(generate_psk)
        print_success "Generated secure PSK"
    else
        prompt_password "Enter VXLAN PSK (min 32 characters)" VXLAN_PSK
    fi

    echo ""
    prompt_input "VXLAN port" "$VXLAN_PORT" VXLAN_PORT

    print_success "VXLAN security configured"
    sleep 1
}

configure_passwords() {
    print_header "Service Password Configuration"

    print_info "Configure passwords for all services"
    print_warning "Passwords must be at least 8 characters"
    echo ""

    if prompt_yesno "Generate random passwords for all services?" "y"; then
        GRAFANA_PASSWORD=$(generate_password)
        POSTGRES_PASSWORD=$(generate_password)
        REDIS_PASSWORD=$(generate_password)
        KEYCLOAK_PASSWORD=$(generate_password)
        N8N_PASSWORD=$(generate_password)
        print_success "Generated secure random passwords"
    else
        echo ""
        prompt_password "Grafana admin password" GRAFANA_PASSWORD
        prompt_password "PostgreSQL password" POSTGRES_PASSWORD
        prompt_password "Redis password" REDIS_PASSWORD
        prompt_password "Keycloak admin password" KEYCLOAK_PASSWORD

        if [ "$DEPLOYMENT_TYPE" = "edge" ]; then
            if prompt_yesno "Install n8n (POD 008)?" "n"; then
                prompt_password "n8n admin password" N8N_PASSWORD
            fi
        fi
    fi

    print_success "Passwords configured"
    sleep 1
}

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Feature Configuration
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

configure_features() {
    print_header "Feature Configuration"

    print_info "Enable or disable optional features"
    echo ""

    if prompt_yesno "Enable Cloudflare Tunnel?" "n"; then
        ENABLE_CLOUDFLARE=true
    fi

    if prompt_yesno "Enable XDP/eBPF DDoS protection?" "y"; then
        ENABLE_XDP=true
    fi

    if prompt_yesno "Enable GDPR compliance (automatic data retention)?" "y"; then
        ENABLE_GDPR=true
    fi

    print_success "Features configured"
    sleep 1
}

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Configuration Summary
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

show_configuration_summary() {
    print_header "Configuration Summary"

    echo -e "${CYAN}Deployment Type:${NC} $DEPLOYMENT_TYPE"
    echo ""
    echo -e "${CYAN}Network Configuration:${NC}"
    echo "  WAN Interface:  $WAN_INTERFACE"
    echo "  Host IP:        $HOST_IP"
    echo "  Bridge Name:    $BRIDGE_NAME"
    echo "  Bridge IP:      $BRIDGE_IP"
    echo ""
    echo -e "${CYAN}POD Networks:${NC}"
    echo "  POD 001 (Web):  $POD_001_NETWORK (VNI: $VNI_001)"
    echo "  POD 002 (IAM):  $POD_002_NETWORK (VNI: $VNI_002)"
    echo "  POD 003 (DB):   $POD_003_NETWORK (VNI: $VNI_003)"
    echo "  POD 004 (Cache):$POD_004_NETWORK (VNI: $VNI_004)"
    echo "  POD 005 (Mon):  $POD_005_NETWORK (VNI: $VNI_005)"
    echo "  POD 006 (Sec):  $POD_006_NETWORK (VNI: $VNI_006)"
    echo "  POD 007 (Resp): $POD_007_NETWORK (VNI: $VNI_007)"
    echo ""
    echo -e "${CYAN}Security:${NC}"
    echo "  VXLAN PSK:      [configured]"
    echo "  VXLAN Port:     $VXLAN_PORT"
    echo "  Passwords:      [configured]"
    echo ""
    echo -e "${CYAN}Features:${NC}"
    echo "  Cloudflare:     $([ "$ENABLE_CLOUDFLARE" = true ] && echo enabled || echo disabled)"
    echo "  XDP/eBPF:       $([ "$ENABLE_XDP" = true ] && echo enabled || echo disabled)"
    echo "  GDPR:           $([ "$ENABLE_GDPR" = true ] && echo enabled || echo disabled)"
    echo ""

    if ! prompt_yesno "Save this configuration?" "y"; then
        echo ""
        print_warning "Configuration cancelled"
        return 1
    fi

    return 0
}

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Save Configuration
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

save_configuration() {
    print_header "Saving Configuration"

    cat > "$CONFIG_FILE" << EOF
#!/bin/bash
#
# HookProbe Configuration
# Generated: $(date)
# Deployment: $DEPLOYMENT_TYPE
#

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Network Configuration
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WAN_INTERFACE="$WAN_INTERFACE"
LAN_INTERFACE="$LAN_INTERFACE"
HOST_IP="$HOST_IP"
BRIDGE_NAME="$BRIDGE_NAME"
BRIDGE_IP="$BRIDGE_IP"

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# POD Network Configuration
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

POD_001_NETWORK="$POD_001_NETWORK"
POD_002_NETWORK="$POD_002_NETWORK"
POD_003_NETWORK="$POD_003_NETWORK"
POD_004_NETWORK="$POD_004_NETWORK"
POD_005_NETWORK="$POD_005_NETWORK"
POD_006_NETWORK="$POD_006_NETWORK"
POD_007_NETWORK="$POD_007_NETWORK"
POD_008_NETWORK="$POD_008_NETWORK"

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# VNI Configuration
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VNI_001=$VNI_001
VNI_002=$VNI_002
VNI_003=$VNI_003
VNI_004=$VNI_004
VNI_005=$VNI_005
VNI_006=$VNI_006
VNI_007=$VNI_007
VNI_008=$VNI_008

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# VXLAN Security
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VXLAN_PSK="$VXLAN_PSK"
VXLAN_PORT=$VXLAN_PORT

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Service Passwords
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

GRAFANA_PASSWORD="$GRAFANA_PASSWORD"
POSTGRES_PASSWORD="$POSTGRES_PASSWORD"
REDIS_PASSWORD="$REDIS_PASSWORD"
KEYCLOAK_PASSWORD="$KEYCLOAK_PASSWORD"
N8N_PASSWORD="$N8N_PASSWORD"

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Feature Flags
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ENABLE_CLOUDFLARE=$ENABLE_CLOUDFLARE
ENABLE_XDP=$ENABLE_XDP
ENABLE_GDPR=$ENABLE_GDPR
EOF

    chmod 600 "$CONFIG_FILE"

    print_success "Configuration saved to: $CONFIG_FILE"
    echo ""
    print_warning "⚠ Keep this file secure - it contains passwords!"
    sleep 2
}

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Main Wizard Flow
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

run_configuration_wizard() {
    local deployment_type="$1"
    local config_file="$2"

    DEPLOYMENT_TYPE="$deployment_type"
    CONFIG_FILE="$config_file"

    # Welcome
    print_header "Welcome"
    echo "This wizard will help you configure HookProbe deployment."
    echo ""
    print_info "Deployment type: $DEPLOYMENT_TYPE"
    echo ""
    read -p "Press Enter to continue..."

    # Run configuration steps
    detect_network_interfaces
    select_wan_interface
    configure_host_network
    configure_pod_networks
    configure_vxlan_security
    configure_passwords
    configure_features

    # Show summary and save
    if show_configuration_summary; then
        save_configuration
        print_success "Configuration wizard completed!"
        return 0
    else
        print_error "Configuration cancelled"
        return 1
    fi
}
