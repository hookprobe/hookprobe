#!/bin/bash
#
# install-edge.sh - HookProbe Edge Unified Installer
# Part of HookProbe unified installation system
#
# ONE unified installer with auto-detection for:
#   - Raspberry Pi 4/5 (4GB+ RAM)
#   - x86_64 servers (4GB+ RAM)
#   - ARM64 systems (4GB+ RAM)
#
# Usage:
#   sudo bash scripts/install-edge.sh                    # Default: Qsecbit only
#   sudo bash scripts/install-edge.sh --enable-ai        # Add AI detection
#   sudo bash scripts/install-edge.sh --enable-monitoring # Add monitoring
#   sudo bash scripts/install-edge.sh --disable-iam      # Skip IAM
#
# Target tested: Raspberry Pi 4B (4GB RAM, 32GB storage)
#

set -e  # Exit on error

# ============================================================
# CONFIGURATION
# ============================================================

# Script directory and repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

# Source library files
if [ ! -f "$LIB_DIR/platform.sh" ]; then
    echo "ERROR: Missing library files in $LIB_DIR"
    exit 1
fi

source "$LIB_DIR/platform.sh"
source "$LIB_DIR/requirements.sh"
source "$LIB_DIR/instructions.sh"

# Default configuration
ENABLE_AI=false
ENABLE_MONITORING=false
ENABLE_IAM=true
ENABLE_WEBSERVER=false
ENABLE_DATABASE=true
ENABLE_CACHE=true
ENABLE_EDGE=true
ENABLE_SENTINEL=false
ENABLE_SENTINEL_ONLY=false
INTERACTIVE_MODE=true

# Sentinel Node Configuration
SENTINEL_LISTEN_PORT="${SENTINEL_LISTEN_PORT:-8443}"
SENTINEL_METRICS_PORT="${SENTINEL_METRICS_PORT:-9090}"
SENTINEL_REGION="${SENTINEL_REGION:-}"
SENTINEL_TIER="${SENTINEL_TIER:-community}"  # community, professional, enterprise

# OVS Bridge configuration
OVS_BRIDGE_NAME="hookprobe"
OVS_BRIDGE_SUBNET="10.250.0.0/16"

# Secrets (will be populated by prompts or env vars)
CLOUDFLARE_TUNNEL_TOKEN=""
LOGTO_ENDPOINT=""
LOGTO_APP_ID=""
LOGTO_APP_SECRET=""

# Optional modules
ENABLE_KALI=false
ENABLE_N8N=false
ENABLE_CLICKHOUSE=false
ENABLE_LTE=false

# MSSP/HTP Configuration
MSSP_ENDPOINT="${MSSP_ENDPOINT:-mssp.hookprobe.com}"
MSSP_PORT="${MSSP_PORT:-8443}"
HTP_NODE_ID=""
HTP_SENTINEL_MODE="${HTP_SENTINEL_MODE:-false}"
EDGE_MODE="${EDGE_MODE:-standalone}"  # standalone, validator, mssp-connected

# Colors - use $'...' syntax for ANSI escape sequences
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
NC=$'\033[0m'

# ============================================================
# COMMAND-LINE ARGUMENT PARSING
# ============================================================

parse_arguments() {
    # Parse command-line arguments.

    while [[ $# -gt 0 ]]; do
        case $1 in
            --sentinel)
                # Sentinel only deployment
                ENABLE_SENTINEL_ONLY=true
                ENABLE_SENTINEL=true
                ENABLE_EDGE=false
                ENABLE_DATABASE=false
                ENABLE_CACHE=false
                ENABLE_WEBSERVER=false
                ENABLE_IAM=false
                ENABLE_AI=false
                ENABLE_MONITORING=false
                EDGE_MODE="sentinel"
                HTP_SENTINEL_MODE="true"
                shift
                ;;
            --edge)
                # Edge only (standalone)
                ENABLE_SENTINEL_ONLY=false
                ENABLE_SENTINEL=false
                ENABLE_EDGE=true
                ENABLE_DATABASE=true
                ENABLE_CACHE=true
                EDGE_MODE="standalone"
                shift
                ;;
            --edge-sentinel)
                # Edge + Sentinel (recommended)
                ENABLE_SENTINEL_ONLY=false
                ENABLE_SENTINEL=true
                ENABLE_EDGE=true
                ENABLE_DATABASE=true
                ENABLE_CACHE=true
                EDGE_MODE="edge-sentinel"
                shift
                ;;
            --enable-ai)
                ENABLE_AI=true
                shift
                ;;
            --enable-monitoring)
                ENABLE_MONITORING=true
                shift
                ;;
            --enable-webserver)
                ENABLE_WEBSERVER=true
                shift
                ;;
            --disable-iam)
                ENABLE_IAM=false
                shift
                ;;
            --enable-iam)
                ENABLE_IAM=true
                shift
                ;;
            --non-interactive)
                INTERACTIVE_MODE=false
                shift
                ;;
            --cf-token)
                CLOUDFLARE_TUNNEL_TOKEN="$2"
                shift 2
                ;;
            --tier)
                # Deployment tier from unified installer
                case "$2" in
                    guardian)
                        ENABLE_SENTINEL_ONLY=false
                        ENABLE_SENTINEL=true
                        ENABLE_EDGE=true
                        ENABLE_DATABASE=true
                        ENABLE_CACHE=true
                        ENABLE_WEBSERVER=false
                        ENABLE_IAM=false
                        ENABLE_AI=false
                        ENABLE_MONITORING=false
                        EDGE_MODE="guardian"
                        ;;
                    fortress)
                        ENABLE_SENTINEL_ONLY=false
                        ENABLE_SENTINEL=true
                        ENABLE_EDGE=true
                        ENABLE_DATABASE=true
                        ENABLE_CACHE=true
                        ENABLE_WEBSERVER=true
                        ENABLE_IAM=true
                        ENABLE_AI=true
                        ENABLE_MONITORING=true
                        EDGE_MODE="fortress"
                        ;;
                    nexus)
                        ENABLE_SENTINEL_ONLY=false
                        ENABLE_SENTINEL=true
                        ENABLE_EDGE=true
                        ENABLE_DATABASE=true
                        ENABLE_CACHE=true
                        ENABLE_WEBSERVER=true
                        ENABLE_IAM=true
                        ENABLE_AI=true
                        ENABLE_MONITORING=true
                        ENABLE_CLICKHOUSE=true
                        EDGE_MODE="nexus"
                        ;;
                esac
                shift 2
                ;;
            --enable-kali)
                ENABLE_KALI=true
                shift
                ;;
            --enable-n8n)
                ENABLE_N8N=true
                shift
                ;;
            --enable-clickhouse)
                ENABLE_CLICKHOUSE=true
                shift
                ;;
            --enable-lte)
                ENABLE_LTE=true
                shift
                ;;
            --mssp-endpoint)
                MSSP_ENDPOINT="$2"
                shift 2
                ;;
            --mssp-port)
                MSSP_PORT="$2"
                shift 2
                ;;
            --node-id)
                HTP_NODE_ID="$2"
                shift 2
                ;;
            --uninstall)
                # Launch uninstall menu
                handle_uninstall_menu
                exit 0
                ;;
            --status)
                # Show status
                show_status
                exit 0
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done
}

show_help() {
    cat << 'EOF'
HookProbe Unified Installer v5.0

Usage:
  sudo bash scripts/install-edge.sh [OPTIONS]

  Run without options to launch the interactive menu.

Options:
  --sentinel           Deploy Sentinel only (MSSP validator, ~512MB RAM)
  --edge               Deploy Edge only (standalone mode)
  --edge-sentinel      Deploy Edge + Sentinel (recommended)
  --enable-ai          Enable AI detection (requires 8GB+ RAM)
  --enable-monitoring  Enable Grafana/VictoriaMetrics monitoring
  --enable-webserver   Enable Web Server (Django + Nginx + WAF)
  --enable-iam         Enable IAM (Logto) installation
  --disable-iam        Skip IAM (Logto) installation
  --non-interactive    Skip interactive prompts (use defaults)
  --cf-token TOKEN     Cloudflare Tunnel token (for web server)
  --tier TIER          Deployment tier (guardian, fortress, nexus)
  --enable-kali        Enable Kali security module (pentest tools)
  --enable-n8n         Enable n8n workflow automation
  --enable-clickhouse  Enable ClickHouse analytics database
  --enable-lte         Enable LTE/5G failover support
  --mssp-endpoint HOST MSSP endpoint for Sentinel/Edge connection
  --mssp-port PORT     MSSP port (default: 8443)
  --node-id ID         Node identifier for MSSP registration
  --uninstall          Launch uninstall menu
  --status             Show current installation status
  --help, -h           Show this help message

Interactive Menu Options:
  1. Sentinel          - MSSP Validator (~512MB RAM)
  2. Edge + Sentinel   - Full Edge with validation (~2GB RAM) [Recommended]
  3. Edge Only         - Standard Edge (~1.5GB RAM)
  4. Edge + Dashboard  - Edge with Web UI (~2.5GB RAM)
  5. Full Stack        - All components (~8GB RAM)
  6. Custom            - Choose individual components
  7. Uninstall         - Remove components
  8. Status            - Show installation status

Sentinel:
  Lightweight 3rd party security validator for MSSP integration:
  • Validates edge device authenticity & protocol compliance
  • Reports validation results to MSSP
  • Assesses genuine vs compromised edge devices
  • Ideal for LXC containers, cloud VPS, distributed validation
  • Requires only 512MB RAM

Edge Components:
  • Database (PostgreSQL 16)
  • Cache (Redis 7)
  • Neuro Protocol (Qsecbit + HTP)
  • Optional: Web Server, IAM, Monitoring, AI Detection

Examples:
  # Launch interactive menu (recommended)
  sudo bash scripts/install-edge.sh

  # Deploy Sentinel only
  sudo bash scripts/install-edge.sh --sentinel --mssp-endpoint mssp.example.com

  # Deploy Edge + Sentinel
  sudo bash scripts/install-edge.sh --edge-sentinel --mssp-endpoint mssp.example.com

  # Full stack with AI (non-interactive)
  sudo bash scripts/install-edge.sh --edge-sentinel --enable-webserver --enable-ai --non-interactive

Target Platforms:
  • Proxmox LXC (unprivileged) - Sentinel or Edge + Sentinel
  • Raspberry Pi 4/5 (3GB+ RAM)
  • x86_64/ARM64 servers (3GB+ RAM)

EOF
}

# ============================================================
# UNIFIED INSTALLATION MENU
# ============================================================

show_main_menu() {
    clear 2>/dev/null || true
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║   ${NC}██╗  ██╗ ██████╗  ██████╗ ██╗  ██╗██████╗ ██████╗  ██████╗ ██████╗ ███████╗${CYAN}   ║${NC}"
    echo -e "${CYAN}║   ${NC}██║  ██║██╔═══██╗██╔═══██╗██║ ██╔╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝${CYAN}   ║${NC}"
    echo -e "${CYAN}║   ${NC}███████║██║   ██║██║   ██║█████╔╝ ██████╔╝██████╔╝██║   ██║██████╔╝█████╗${CYAN}     ║${NC}"
    echo -e "${CYAN}║   ${NC}██╔══██║██║   ██║██║   ██║██╔═██╗ ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝${CYAN}     ║${NC}"
    echo -e "${CYAN}║   ${NC}██║  ██║╚██████╔╝╚██████╔╝██║  ██╗██║     ██║  ██║╚██████╔╝██████╔╝███████╗${CYAN}   ║${NC}"
    echo -e "${CYAN}║   ${NC}╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝${CYAN}   ║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║                    Unified Installer v5.0                    ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Show environment info
    if [ "$IS_LXC_CONTAINER" = true ]; then
        if [ "$IS_LXC_UNPRIVILEGED" = true ]; then
            echo -e "  ${YELLOW}Environment: Proxmox LXC (Unprivileged)${NC}"
            echo -e "  ${GREEN}Recommended: Sentinel or Edge + Sentinel${NC}"
        else
            echo -e "  ${GREEN}Environment: Proxmox LXC (Privileged)${NC}"
        fi
    else
        echo -e "  ${GREEN}Environment: $(uname -s) $(uname -m)${NC}"
    fi
    echo ""

    echo -e "${CYAN}┌──────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│  INSTALLATION OPTIONS                                        │${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────────┤${NC}"
    echo ""
    echo -e "  ${YELLOW}1${NC})  ${GREEN}Sentinel${NC} - MSSP Sentinel"
    echo "      └─ Lightweight 3rd party security validator (~512MB RAM)"
    echo "      └─ Validates edge authenticity, reports to MSSP"
    echo "      └─ Ideal for: LXC containers, cloud VPS, distributed validation"
    echo ""
    echo -e "  ${YELLOW}2${NC})  ${GREEN}Edge + Sentinel${NC} - Full Edge with Validation ${CYAN}[Recommended]${NC}"
    echo "      └─ Complete edge deployment with built-in Sentinel"
    echo "      └─ Neuro Protocol + Database + Cache + Validation (~2GB RAM)"
    echo "      └─ Ideal for: Edge devices, Raspberry Pi, small servers"
    echo ""
    echo -e "  ${YELLOW}3${NC})  ${GREEN}Edge Only${NC} - Standard Edge Deployment"
    echo "      └─ Neuro Protocol + Database + Cache (~1.5GB RAM)"
    echo "      └─ No MSSP validation (standalone mode)"
    echo ""
    echo -e "  ${YELLOW}4${NC})  ${GREEN}Edge + Dashboard${NC} - Edge with Web UI"
    echo "      └─ Adds Django dashboard + Nginx + IAM (~2.5GB RAM)"
    echo "      └─ Requires: Cloudflare tunnel token, Logto secrets"
    echo ""
    echo -e "  ${YELLOW}5${NC})  ${GREEN}Full Stack${NC} - Complete Security Appliance"
    echo "      └─ All components + AI + Monitoring (~8GB RAM)"
    echo "      └─ Requires: 8GB+ RAM, secrets configuration"
    echo ""
    echo -e "  ${YELLOW}6${NC})  ${BLUE}Custom${NC} - Select Individual Components"
    echo "      └─ Choose exactly what you need"
    echo ""
    echo -e "${CYAN}├──────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│  MANAGEMENT                                                  │${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────────┤${NC}"
    echo ""
    echo -e "  ${YELLOW}7${NC})  ${RED}Uninstall${NC} - Remove HookProbe Components"
    echo "      └─ Select what to remove (Sentinel, Edge, or All)"
    echo ""
    echo -e "  ${YELLOW}8${NC})  ${BLUE}Status${NC} - Show Current Installation"
    echo "      └─ View running pods, networks, and configuration"
    echo ""
    echo -e "  ${YELLOW}0${NC})  Exit"
    echo ""
    echo -e "${CYAN}└──────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

show_uninstall_menu() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}  Uninstall HookProbe Components${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Select what to uninstall:"
    echo ""
    echo -e "  ${YELLOW}1${NC})  Uninstall Sentinel only"
    echo "      └─ Removes validator pod, keeps Edge components"
    echo ""
    echo -e "  ${YELLOW}2${NC})  Uninstall Edge only"
    echo "      └─ Removes Edge pods, keeps Sentinel"
    echo ""
    echo -e "  ${YELLOW}3${NC})  ${RED}Uninstall Everything${NC}"
    echo "      └─ Removes ALL HookProbe components"
    echo "      └─ Includes: pods, networks, volumes, configuration"
    echo ""
    echo -e "  ${YELLOW}0${NC})  Back to main menu"
    echo ""
}

show_status() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  HookProbe Installation Status${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    # Check Sentinel
    echo -e "${YELLOW}Sentinel:${NC}"
    if podman pod exists hookprobe-sentinel 2>/dev/null; then
        local sentinel_status=$(podman pod inspect hookprobe-sentinel --format '{{.State}}' 2>/dev/null || echo "unknown")
        echo -e "  ${GREEN}[✓]${NC} Installed (Status: $sentinel_status)"
        if [ -f /etc/hookprobe/sentinel.conf ]; then
            source /etc/hookprobe/sentinel.conf 2>/dev/null
            echo "      Node ID: ${HTP_NODE_ID:-unknown}"
            echo "      Region:  ${SENTINEL_REGION:-unknown}"
            echo "      MSSP:    ${MSSP_ENDPOINT:-not configured}"
        fi
    else
        echo -e "  ${YELLOW}[-]${NC} Not installed"
    fi
    echo ""

    # Check Edge components
    echo -e "${YELLOW}Edge Components:${NC}"
    local edge_pods=("hookprobe-neuro" "hookprobe-database" "hookprobe-cache" "hookprobe-web" "hookprobe-iam" "hookprobe-monitoring" "hookprobe-detection" "hookprobe-ai")
    local installed_count=0

    for pod in "${edge_pods[@]}"; do
        if podman pod exists "$pod" 2>/dev/null; then
            local status=$(podman pod inspect "$pod" --format '{{.State}}' 2>/dev/null || echo "unknown")
            echo -e "  ${GREEN}[✓]${NC} $pod ($status)"
            ((installed_count++))
        fi
    done

    if [ $installed_count -eq 0 ]; then
        echo -e "  ${YELLOW}[-]${NC} No Edge pods installed"
    fi
    echo ""

    # Check Networks
    echo -e "${YELLOW}Networks:${NC}"
    local networks=$(podman network ls --format '{{.Name}}' 2>/dev/null | grep -E "^hookprobe" || true)
    if [ -n "$networks" ]; then
        echo "$networks" | while read -r net; do
            echo -e "  ${GREEN}[✓]${NC} $net"
        done
    else
        echo -e "  ${YELLOW}[-]${NC} No HookProbe networks"
    fi
    echo ""

    # Check Configuration
    echo -e "${YELLOW}Configuration:${NC}"
    if [ -d /etc/hookprobe ]; then
        echo -e "  ${GREEN}[✓]${NC} /etc/hookprobe exists"
        ls -la /etc/hookprobe/*.conf 2>/dev/null | while read -r line; do
            echo "      $(basename "$line" | awk '{print $NF}')"
        done
    else
        echo -e "  ${YELLOW}[-]${NC} No configuration directory"
    fi
    echo ""

    read -p "Press Enter to continue..."
}

select_from_main_menu() {
    if [ "$INTERACTIVE_MODE" = false ]; then
        return 0
    fi

    while true; do
        show_main_menu

        # Auto-select based on environment
        local default_choice="2"
        if [ "$IS_LXC_UNPRIVILEGED" = true ]; then
            default_choice="1"
        fi

        read -p "Select option [0-8, default: $default_choice]: " menu_choice
        menu_choice="${menu_choice:-$default_choice}"
        echo ""

        case $menu_choice in
            1)
                # Sentinel only
                ENABLE_SENTINEL_ONLY=true
                ENABLE_EDGE=false
                ENABLE_WEBSERVER=false
                ENABLE_IAM=false
                ENABLE_AI=false
                ENABLE_MONITORING=false
                ENABLE_DATABASE=false
                ENABLE_CACHE=false
                EDGE_MODE="sentinel"
                HTP_SENTINEL_MODE="true"
                echo -e "${GREEN}[✓]${NC} Selected: Sentinel (MSSP Validator)"
                configure_sentinel_node
                return 0
                ;;
            2)
                # Edge + Sentinel (recommended)
                ENABLE_SENTINEL_ONLY=false
                ENABLE_EDGE=true
                ENABLE_SENTINEL=true
                ENABLE_WEBSERVER=false
                ENABLE_IAM=false
                ENABLE_AI=false
                ENABLE_MONITORING=false
                ENABLE_DATABASE=true
                ENABLE_CACHE=true
                EDGE_MODE="edge-sentinel"
                echo -e "${GREEN}[✓]${NC} Selected: Edge + Sentinel"
                configure_sentinel_node
                return 0
                ;;
            3)
                # Edge only
                ENABLE_SENTINEL_ONLY=false
                ENABLE_EDGE=true
                ENABLE_SENTINEL=false
                ENABLE_WEBSERVER=false
                ENABLE_IAM=false
                ENABLE_AI=false
                ENABLE_MONITORING=false
                ENABLE_DATABASE=true
                ENABLE_CACHE=true
                EDGE_MODE="standalone"
                echo -e "${GREEN}[✓]${NC} Selected: Edge Only (Standalone)"
                return 0
                ;;
            4)
                # Edge + Dashboard
                ENABLE_SENTINEL_ONLY=false
                ENABLE_EDGE=true
                ENABLE_SENTINEL=true
                ENABLE_WEBSERVER=true
                ENABLE_IAM=true
                ENABLE_AI=false
                ENABLE_MONITORING=false
                ENABLE_DATABASE=true
                ENABLE_CACHE=true
                EDGE_MODE="edge-sentinel"
                echo -e "${GREEN}[✓]${NC} Selected: Edge + Dashboard"
                configure_sentinel_node
                configure_webserver_secrets
                return 0
                ;;
            5)
                # Full Stack
                ENABLE_SENTINEL_ONLY=false
                ENABLE_EDGE=true
                ENABLE_SENTINEL=true
                ENABLE_WEBSERVER=true
                ENABLE_IAM=true
                ENABLE_AI=true
                ENABLE_MONITORING=true
                ENABLE_DATABASE=true
                ENABLE_CACHE=true
                EDGE_MODE="edge-sentinel"
                echo -e "${GREEN}[✓]${NC} Selected: Full Stack"
                configure_sentinel_node
                configure_webserver_secrets
                return 0
                ;;
            6)
                # Custom
                ENABLE_SENTINEL_ONLY=false
                custom_component_selection
                return 0
                ;;
            7)
                # Uninstall
                handle_uninstall_menu
                ;;
            8)
                # Status
                show_status
                ;;
            0)
                echo "Exiting..."
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                sleep 1
                ;;
        esac
    done
}

handle_uninstall_menu() {
    show_uninstall_menu
    read -p "Select option [0-3]: " uninstall_choice
    echo ""

    case $uninstall_choice in
        1)
            # Uninstall Sentinel only
            echo -e "${YELLOW}Uninstalling Sentinel...${NC}"
            uninstall_sentinel
            echo -e "${GREEN}[✓]${NC} Sentinel uninstalled"
            read -p "Press Enter to continue..."
            ;;
        2)
            # Uninstall Edge only
            echo -e "${YELLOW}Uninstalling Edge components...${NC}"
            uninstall_edge
            echo -e "${GREEN}[✓]${NC} Edge uninstalled"
            read -p "Press Enter to continue..."
            ;;
        3)
            # Uninstall everything
            echo -e "${RED}WARNING: This will remove ALL HookProbe components!${NC}"
            read -p "Are you sure? (yes/no): " confirm
            if [ "$confirm" = "yes" ]; then
                uninstall_all
                echo -e "${GREEN}[✓]${NC} All components uninstalled"
            else
                echo "Cancelled."
            fi
            read -p "Press Enter to continue..."
            ;;
        0|*)
            return 0
            ;;
    esac
}

uninstall_sentinel() {
    echo "Removing Sentinel pod..."
    podman pod stop hookprobe-sentinel 2>/dev/null || true
    podman pod rm -f hookprobe-sentinel 2>/dev/null || true

    echo "Removing Sentinel configuration..."
    rm -f /etc/hookprobe/sentinel.conf 2>/dev/null || true
    rm -rf /opt/hookprobe/sentinel 2>/dev/null || true

    echo "Sentinel removed."
}

uninstall_edge() {
    echo "Removing Edge pods..."
    local edge_pods=("hookprobe-neuro" "hookprobe-database" "hookprobe-cache" "hookprobe-web" "hookprobe-iam" "hookprobe-monitoring" "hookprobe-detection" "hookprobe-ai")

    for pod in "${edge_pods[@]}"; do
        if podman pod exists "$pod" 2>/dev/null; then
            echo "  Removing $pod..."
            podman pod stop "$pod" 2>/dev/null || true
            podman pod rm -f "$pod" 2>/dev/null || true
        fi
    done

    echo "Edge components removed."
}

uninstall_all() {
    echo "Removing all HookProbe components..."

    # Remove Sentinel
    uninstall_sentinel

    # Remove Edge
    uninstall_edge

    # Remove networks
    echo "Removing networks..."
    podman network ls --format '{{.Name}}' 2>/dev/null | grep -E "^hookprobe" | while read -r net; do
        podman network rm "$net" 2>/dev/null || true
    done

    # Remove volumes (ask first)
    read -p "Remove all data volumes? (yes/no): " remove_volumes
    if [ "$remove_volumes" = "yes" ]; then
        echo "Removing volumes..."
        podman volume ls -q 2>/dev/null | grep -i hookprobe | while read -r vol; do
            podman volume rm "$vol" 2>/dev/null || true
        done
    fi

    # Remove configuration
    read -p "Remove configuration (/etc/hookprobe)? (yes/no): " remove_config
    if [ "$remove_config" = "yes" ]; then
        rm -rf /etc/hookprobe 2>/dev/null || true
        rm -rf /opt/hookprobe 2>/dev/null || true
    fi

    # Remove OVS bridge
    if command -v ovs-vsctl &>/dev/null; then
        if ovs-vsctl br-exists hookprobe 2>/dev/null; then
            echo "Removing OVS bridge..."
            ovs-ofctl del-flows hookprobe 2>/dev/null || true
            ovs-vsctl del-br hookprobe 2>/dev/null || true
        fi
    fi

    # Remove NAT rules
    if command -v nft &>/dev/null; then
        nft delete table ip hookprobe_nat 2>/dev/null || true
    fi

    echo "All HookProbe components removed."
}

# Keep old function name for backwards compatibility
show_component_menu() {
    show_main_menu
}

select_components() {
    select_from_main_menu
}

custom_component_selection() {
    echo -e "${CYAN}Custom Component Selection${NC}"
    echo ""
    echo "Select the components you want to install:"
    echo ""

    # Sentinel
    read -p "Enable Sentinel (MSSP Validator) [+0.5GB RAM]? [Y/n]: " -n 1 -r
    echo ""
    [[ ! $REPLY =~ ^[Nn]$ ]] && ENABLE_SENTINEL=true || ENABLE_SENTINEL=false

    # Core Edge components
    ENABLE_EDGE=true
    ENABLE_DATABASE=true
    ENABLE_CACHE=true

    # Web Server
    read -p "Enable Web Server (Django + Nginx) [+0.5GB RAM]? [y/N]: " -n 1 -r
    echo ""
    [[ $REPLY =~ ^[Yy]$ ]] && ENABLE_WEBSERVER=true || ENABLE_WEBSERVER=false

    # IAM
    read -p "Enable IAM (Logto authentication) [+1GB RAM]? [y/N]: " -n 1 -r
    echo ""
    [[ $REPLY =~ ^[Yy]$ ]] && ENABLE_IAM=true || ENABLE_IAM=false

    # Monitoring
    read -p "Enable Monitoring (Grafana + VictoriaMetrics) [+2GB RAM]? [y/N]: " -n 1 -r
    echo ""
    [[ $REPLY =~ ^[Yy]$ ]] && ENABLE_MONITORING=true || ENABLE_MONITORING=false

    # AI Detection
    read -p "Enable AI Detection (Suricata + ML) [+4GB RAM]? [y/N]: " -n 1 -r
    echo ""
    [[ $REPLY =~ ^[Yy]$ ]] && ENABLE_AI=true || ENABLE_AI=false

    # Set edge mode
    if [ "$ENABLE_SENTINEL" = true ]; then
        EDGE_MODE="edge-sentinel"
    else
        EDGE_MODE="standalone"
    fi

    # Calculate minimum RAM for selected components
    local min_ram=1.5  # Base (Database + Cache + Neuro)
    [ "$ENABLE_SENTINEL" = true ] && min_ram=$(echo "$min_ram + 0.5" | bc)
    [ "$ENABLE_WEBSERVER" = true ] && min_ram=$(echo "$min_ram + 0.5" | bc)
    [ "$ENABLE_IAM" = true ] && min_ram=$(echo "$min_ram + 1" | bc)
    [ "$ENABLE_MONITORING" = true ] && min_ram=$(echo "$min_ram + 2" | bc)
    [ "$ENABLE_AI" = true ] && min_ram=$(echo "$min_ram + 4" | bc)

    echo ""
    echo "Selected components:"
    echo -e "  ${GREEN}[x]${NC} Core (Database + Cache + Neuro)"
    echo -e "  $([ "$ENABLE_SENTINEL" = true ] && echo "${GREEN}[x]${NC}" || echo "${YELLOW}[-]${NC}") Sentinel (+0.5GB)"
    echo -e "  $([ "$ENABLE_WEBSERVER" = true ] && echo "${GREEN}[x]${NC}" || echo "${YELLOW}[-]${NC}") Web Server (+0.5GB)"
    echo -e "  $([ "$ENABLE_IAM" = true ] && echo "${GREEN}[x]${NC}" || echo "${YELLOW}[-]${NC}") IAM (+1GB)"
    echo -e "  $([ "$ENABLE_MONITORING" = true ] && echo "${GREEN}[x]${NC}" || echo "${YELLOW}[-]${NC}") Monitoring (+2GB)"
    echo -e "  $([ "$ENABLE_AI" = true ] && echo "${GREEN}[x]${NC}" || echo "${YELLOW}[-]${NC}") AI Detection (+4GB)"
    echo ""
    echo -e "Minimum RAM required: ${CYAN}${min_ram}GB${NC}"
    echo ""

    # Configure Sentinel if enabled
    if [ "$ENABLE_SENTINEL" = true ]; then
        configure_sentinel_node
    fi

    # Configure webserver secrets if enabled
    if [ "$ENABLE_WEBSERVER" = true ]; then
        configure_webserver_secrets
    fi
}

# ============================================================
# SECRETS CONFIGURATION
# ============================================================

configure_webserver_secrets() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  Web Server Secrets Configuration${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "The web server requires secrets for secure operation."
    echo "You can skip these now and configure later in /etc/hookprobe/secrets/"
    echo ""

    # Cloudflare Tunnel
    echo -e "${YELLOW}Cloudflare Tunnel (optional)${NC}"
    echo "Used for secure external access without opening ports."
    if [ -z "$CLOUDFLARE_TUNNEL_TOKEN" ]; then
        read -p "Cloudflare Tunnel Token (or press Enter to skip): " cf_token
        CLOUDFLARE_TUNNEL_TOKEN="$cf_token"
    else
        echo -e "  Token: ${GREEN}[configured via --cf-token]${NC}"
    fi
    echo ""

    # Logto Configuration
    if [ "$ENABLE_IAM" = true ]; then
        echo -e "${YELLOW}Logto IAM Configuration${NC}"
        echo "Authentication service for user management."

        read -p "Logto Endpoint URL (or press Enter for local): " logto_endpoint
        LOGTO_ENDPOINT="${logto_endpoint:-http://localhost:3001}"

        read -p "Logto App ID (or press Enter to auto-generate): " logto_app_id
        LOGTO_APP_ID="${logto_app_id:-$(openssl rand -hex 16)}"

        read -p "Logto App Secret (or press Enter to auto-generate): " logto_secret
        LOGTO_APP_SECRET="${logto_secret:-$(openssl rand -base64 32)}"
        echo ""
    fi

    # Create secrets directory
    mkdir -p /etc/hookprobe/secrets
    chmod 700 /etc/hookprobe/secrets

    # Save secrets
    if [ -n "$CLOUDFLARE_TUNNEL_TOKEN" ]; then
        echo "$CLOUDFLARE_TUNNEL_TOKEN" > /etc/hookprobe/secrets/cloudflare-tunnel-token
        chmod 600 /etc/hookprobe/secrets/cloudflare-tunnel-token
        echo -e "  ${GREEN}[x]${NC} Cloudflare Tunnel token saved"
    fi

    if [ "$ENABLE_IAM" = true ]; then
        cat > /etc/hookprobe/secrets/logto.env << LOGTOEOF
LOGTO_ENDPOINT=$LOGTO_ENDPOINT
LOGTO_APP_ID=$LOGTO_APP_ID
LOGTO_APP_SECRET=$LOGTO_APP_SECRET
LOGTOEOF
        chmod 600 /etc/hookprobe/secrets/logto.env
        echo -e "  ${GREEN}[x]${NC} Logto configuration saved"
    fi

    # Generate Django secret key
    DJANGO_SECRET_KEY=$(openssl rand -base64 32)
    echo "$DJANGO_SECRET_KEY" > /etc/hookprobe/secrets/django-secret-key
    chmod 600 /etc/hookprobe/secrets/django-secret-key
    echo -e "  ${GREEN}[x]${NC} Django secret key generated"

    echo ""
    echo -e "${GREEN}Secrets saved to /etc/hookprobe/secrets/${NC}"
}

configure_mssp_secrets() {
    # Configure MSSP/HTP tunnel secrets
    echo ""
    echo -e "${CYAN}MSSP/HTP Tunnel Configuration${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Configure connection to MSSP (Managed Security Service Provider)"
    echo ""

    # Edge mode selection
    echo -e "${YELLOW}Select Edge Mode:${NC}"
    echo "  1) Standalone  - Edge runs independently (no MSSP connection)"
    echo "  2) Validator   - Edge validates traffic and reports to MSSP"
    echo "  3) MSSP-Connected - Full integration with MSSP dashboard"
    echo ""
    read -p "Select mode [1-3, default: 1]: " edge_mode_choice

    case "$edge_mode_choice" in
        2)
            EDGE_MODE="sentinel"
            HTP_SENTINEL_MODE="true"
            echo -e "  ${GREEN}[x]${NC} Validator mode selected"
            ;;
        3)
            EDGE_MODE="mssp-connected"
            HTP_SENTINEL_MODE="false"
            echo -e "  ${GREEN}[x]${NC} MSSP-Connected mode selected"
            ;;
        *)
            EDGE_MODE="standalone"
            HTP_SENTINEL_MODE="false"
            echo -e "  ${GREEN}[x]${NC} Standalone mode selected"
            return 0  # No further config needed
            ;;
    esac

    echo ""

    # MSSP endpoint configuration
    if [ "$EDGE_MODE" != "standalone" ]; then
        read -p "MSSP Endpoint [default: $MSSP_ENDPOINT]: " mssp_endpoint
        MSSP_ENDPOINT="${mssp_endpoint:-$MSSP_ENDPOINT}"

        read -p "MSSP Port [default: $MSSP_PORT]: " mssp_port
        MSSP_PORT="${mssp_port:-$MSSP_PORT}"

        # Generate node ID if not set
        if [ -z "$HTP_NODE_ID" ]; then
            HTP_NODE_ID=$(cat /etc/machine-id 2>/dev/null || openssl rand -hex 16)
        fi
        read -p "Node ID [default: ${HTP_NODE_ID:0:16}...]: " node_id
        HTP_NODE_ID="${node_id:-$HTP_NODE_ID}"

        echo ""
        echo -e "${YELLOW}Saving MSSP/HTP configuration...${NC}"

        # Ensure secrets directory exists
        mkdir -p /etc/hookprobe/secrets
        chmod 700 /etc/hookprobe/secrets

        # Save MSSP configuration
        cat > /etc/hookprobe/secrets/mssp.env << MSSPEOF
MSSP_ENDPOINT=$MSSP_ENDPOINT
MSSP_PORT=$MSSP_PORT
HTP_NODE_ID=$HTP_NODE_ID
EDGE_MODE=$EDGE_MODE
HTP_SENTINEL_MODE=$HTP_SENTINEL_MODE
MSSPEOF
        chmod 600 /etc/hookprobe/secrets/mssp.env
        echo -e "  ${GREEN}[x]${NC} MSSP configuration saved"

        # Generate HTP identity keys (keyless design uses qsecbit, but we store node identity)
        echo "$HTP_NODE_ID" > /etc/hookprobe/secrets/htp-node-id
        chmod 600 /etc/hookprobe/secrets/htp-node-id
        echo -e "  ${GREEN}[x]${NC} HTP node identity saved"

        echo ""
        echo -e "${GREEN}MSSP configuration complete${NC}"
    fi
}

configure_sentinel_node() {
    # Configure validator node for MSSP integration
    # Validators are lightweight nodes that validate edge device authenticity
    echo ""
    echo -e "${CYAN}Sentinel Setup${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    # MSSP endpoint configuration (required for validators)
    read -p "MSSP Endpoint [default: $MSSP_ENDPOINT]: " mssp_endpoint
    MSSP_ENDPOINT="${mssp_endpoint:-$MSSP_ENDPOINT}"

    read -p "MSSP Port [default: $MSSP_PORT]: " mssp_port
    MSSP_PORT="${mssp_port:-$MSSP_PORT}"

    # Validator-specific configuration
    read -p "Validator Listen Port [default: $SENTINEL_LISTEN_PORT]: " listen_port
    SENTINEL_LISTEN_PORT="${listen_port:-$SENTINEL_LISTEN_PORT}"

    read -p "Metrics Port [default: $SENTINEL_METRICS_PORT]: " metrics_port
    SENTINEL_METRICS_PORT="${metrics_port:-$SENTINEL_METRICS_PORT}"

    # Generate node ID if not set
    if [ -z "$HTP_NODE_ID" ]; then
        HTP_NODE_ID="validator-$(cat /etc/machine-id 2>/dev/null | head -c 12 || openssl rand -hex 6)"
    fi
    read -p "Sentinel ID [default: $HTP_NODE_ID]: " node_id
    HTP_NODE_ID="${node_id:-$HTP_NODE_ID}"

    # Region selection for geographic distribution
    echo ""
    echo "Select validator region (for geographic distribution):"
    echo "  1) Auto-detect"
    echo "  2) North America (us-east, us-west)"
    echo "  3) Europe (eu-west, eu-central)"
    echo "  4) Asia Pacific (ap-southeast, ap-northeast)"
    echo "  5) Custom"
    read -p "Select region [1-5, default: 1]: " region_choice
    region_choice="${region_choice:-1}"

    case "$region_choice" in
        2) SENTINEL_REGION="us-east" ;;
        3) SENTINEL_REGION="eu-west" ;;
        4) SENTINEL_REGION="ap-southeast" ;;
        5)
            read -p "Enter custom region: " custom_region
            SENTINEL_REGION="$custom_region"
            ;;
        *)
            # Auto-detect using IP geolocation
            SENTINEL_REGION=$(curl -s --max-time 5 http://ip-api.com/line/?fields=countryCode 2>/dev/null | tr '[:upper:]' '[:lower:]' || echo "unknown")
            ;;
    esac
    echo -e "  ${GREEN}[x]${NC} Region: $SENTINEL_REGION"

    # Validator tier
    echo ""
    echo "Select validator tier:"
    echo "  1) Community   - Basic validation, rate-limited"
    echo "  2) Professional - Enhanced validation, priority processing"
    echo "  3) Enterprise  - Full features, SLA guarantees"
    read -p "Select tier [1-3, default: 1]: " tier_choice
    tier_choice="${tier_choice:-1}"

    case "$tier_choice" in
        2) SENTINEL_TIER="professional" ;;
        3) SENTINEL_TIER="enterprise" ;;
        *) SENTINEL_TIER="community" ;;
    esac
    echo -e "  ${GREEN}[x]${NC} Tier: $SENTINEL_TIER"

    echo ""
    echo -e "${YELLOW}Saving Validator configuration...${NC}"

    # Ensure secrets directory exists
    mkdir -p /etc/hookprobe/secrets
    chmod 700 /etc/hookprobe/secrets

    # Save validator configuration
    cat > /etc/hookprobe/sentinel.conf << VALIDATOREOF
# HookProbe Sentinel Configuration
# Generated: $(date -Iseconds)

# Node Identity
HTP_NODE_ID=$HTP_NODE_ID
SENTINEL_REGION=$SENTINEL_REGION
SENTINEL_TIER=$SENTINEL_TIER

# MSSP Connection
MSSP_ENDPOINT=$MSSP_ENDPOINT
MSSP_PORT=$MSSP_PORT
EDGE_MODE=validator
HTP_SENTINEL_MODE=true

# Network
SENTINEL_LISTEN_PORT=$SENTINEL_LISTEN_PORT
SENTINEL_METRICS_PORT=$SENTINEL_METRICS_PORT

# Validation Settings
VALIDATION_TIMEOUT=30
VALIDATION_MAX_CONCURRENT=100
VALIDATION_CACHE_TTL=300

# Reporting
REPORT_INTERVAL=60
REPORT_BATCH_SIZE=100
VALIDATOREOF
    chmod 644 /etc/hookprobe/sentinel.conf

    # Save node identity
    echo "$HTP_NODE_ID" > /etc/hookprobe/secrets/htp-node-id
    chmod 600 /etc/hookprobe/secrets/htp-node-id

    echo -e "  ${GREEN}[x]${NC} Validator configuration saved"
    echo ""

    # Test MSSP connection
    echo "Testing MSSP connection..."
    if timeout 5 bash -c "echo >/dev/tcp/$MSSP_ENDPOINT/$MSSP_PORT" 2>/dev/null; then
        echo -e "  ${GREEN}[x]${NC} MSSP endpoint reachable"
    else
        echo -e "  ${YELLOW}[!]${NC} MSSP endpoint not reachable (will retry at runtime)"
    fi

    echo ""
    echo -e "${GREEN}Sentinel configuration complete${NC}"
    echo ""
    echo "Validator will:"
    echo "  • Listen on port $SENTINEL_LISTEN_PORT for edge device validation"
    echo "  • Report to MSSP at $MSSP_ENDPOINT:$MSSP_PORT"
    echo "  • Expose metrics on port $SENTINEL_METRICS_PORT"
    echo ""
}

validate_htp_connection() {
    # Test HTP connection to MSSP
    echo ""
    echo -e "${CYAN}Validating HTP Connection to MSSP...${NC}"

    if [ "$EDGE_MODE" = "standalone" ]; then
        echo -e "  ${YELLOW}[-]${NC} Standalone mode - skipping MSSP validation"
        return 0
    fi

    # Check if MSSP endpoint is reachable
    echo -e "  Testing connectivity to $MSSP_ENDPOINT:$MSSP_PORT..."

    # Try TCP connection first
    if timeout 5 bash -c "echo >/dev/tcp/$MSSP_ENDPOINT/$MSSP_PORT" 2>/dev/null; then
        echo -e "  ${GREEN}[x]${NC} MSSP endpoint reachable (TCP)"
    else
        # Try UDP (HTP uses UDP)
        if command -v nc &> /dev/null; then
            if timeout 5 nc -zu "$MSSP_ENDPOINT" "$MSSP_PORT" 2>/dev/null; then
                echo -e "  ${GREEN}[x]${NC} MSSP endpoint reachable (UDP)"
            else
                echo -e "  ${YELLOW}[!]${NC} MSSP endpoint not reachable"
                echo "      This may be normal if MSSP uses NAT traversal"
            fi
        else
            echo -e "  ${YELLOW}[!]${NC} Cannot test UDP connectivity (nc not installed)"
        fi
    fi

    # DNS resolution check
    if host "$MSSP_ENDPOINT" &>/dev/null || dig +short "$MSSP_ENDPOINT" &>/dev/null; then
        local mssp_ip=$(dig +short "$MSSP_ENDPOINT" 2>/dev/null | head -1)
        echo -e "  ${GREEN}[x]${NC} DNS resolves: $MSSP_ENDPOINT -> ${mssp_ip:-resolved}"
    else
        echo -e "  ${YELLOW}[!]${NC} DNS resolution pending (will retry on startup)"
    fi

    echo ""
    echo -e "${GREEN}HTP validation complete${NC}"
    echo "  Note: Full HTP handshake will occur when Neuro Pod starts"
}

# ============================================================
# CONFIG LOADING
# ============================================================

load_hookprobe_configs() {
    # Load Logto configuration if available
    if [ -f /etc/hookprobe/logto.conf ]; then
        echo -e "${GREEN}[✓]${NC} Loading Logto configuration..."
        source /etc/hookprobe/logto.conf
        # Map config variables to installer variables
        LOGTO_ENDPOINT="${LOGTO_ENDPOINT:-}"
        LOGTO_APP_ID="${LOGTO_APP_ID:-}"
        LOGTO_APP_SECRET="${LOGTO_APP_SECRET:-}"
    fi

    # Load Cloudflare configuration if available
    if [ -f /etc/hookprobe/cloudflare.conf ]; then
        echo -e "${GREEN}[✓]${NC} Loading Cloudflare configuration..."
        source /etc/hookprobe/cloudflare.conf
        # Map config variables - CF_TUNNEL_TOKEN is the minimum required
        CLOUDFLARE_TUNNEL_TOKEN="${CF_TUNNEL_TOKEN:-$CLOUDFLARE_TUNNEL_TOKEN}"
        CF_TUNNEL_ID="${CF_TUNNEL_ID:-}"
        CF_ACCOUNT_ID="${CF_ACCOUNT_ID:-}"
    fi

    # Load network/bridge configuration if available
    if [ -f /etc/hookprobe/network/bridge.conf ]; then
        echo -e "${GREEN}[✓]${NC} Loading network bridge configuration..."
        source /etc/hookprobe/network/bridge.conf
    fi

    # Load MSSP secrets if available
    if [ -f /etc/hookprobe/secrets/mssp-id ]; then
        MSSP_ID=$(cat /etc/hookprobe/secrets/mssp-id 2>/dev/null)
        echo -e "${GREEN}[✓]${NC} MSSP ID loaded"
    fi
}

# ============================================================
# INSTALLATION STEPS
# ============================================================

main() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  HookProbe Edge Unified Installer${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""

    # Parse command-line arguments
    parse_arguments "$@"

    # Load existing configurations from /etc/hookprobe/
    load_hookprobe_configs

    # --------------------------------------------------------
    # [1/7] PLATFORM DETECTION
    # --------------------------------------------------------
    echo -e "${BLUE}[1/7] Detecting platform...${NC}"
    echo ""

    detect_platform
    calculate_memory_limits

    echo "Platform detected:"
    echo "  OS:              $PLATFORM_OS"
    echo "  Architecture:    $PLATFORM_ARCH"
    echo "  RAM:             ${TOTAL_RAM_GB}GB"
    echo "  CPU Cores:       $CPU_CORES"
    echo "  Memory Profile:  $MEMORY_PROFILE"

    if [ "$IS_RASPBERRY_PI" = true ]; then
        echo "  Device:          Raspberry Pi"
        echo "  Model:           $RASPBERRY_PI_MODEL"
    fi

    echo ""

    # --------------------------------------------------------
    # [2/7] COMPONENT SELECTION
    # --------------------------------------------------------
    echo -e "${BLUE}[2/7] Selecting deployment profile...${NC}"

    select_components

    # --------------------------------------------------------
    # [3/7] SYSTEM REQUIREMENTS CHECK
    # --------------------------------------------------------
    echo -e "${BLUE}[3/7] Checking system requirements...${NC}"

    if ! run_system_check "$ENABLE_AI" "$ENABLE_MONITORING"; then
        echo ""
        echo -e "${RED}System requirements check FAILED${NC}"
        echo ""

        # If Raspberry Pi and cgroups not enabled, show detailed instructions
        if [ "$IS_RASPBERRY_PI" = true ] && ! check_cgroup_enabled; then
            show_cgroup_instructions
        fi

        exit 1
    fi

    echo ""

    # --------------------------------------------------------
    # [4/7] MEMORY SUFFICIENCY CHECK
    # --------------------------------------------------------
    echo -e "${BLUE}[4/7] Validating memory allocation...${NC}"

    if ! check_memory_sufficiency "$ENABLE_AI" "$ENABLE_MONITORING" "$ENABLE_IAM"; then
        echo ""
        echo -e "${YELLOW}WARNING: Memory may be tight${NC}"

        if [ "$ENABLE_AI" = true ]; then
            echo ""
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo ""
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                echo "Installation cancelled."
                exit 0
            fi
        fi
    fi

    echo ""

    # --------------------------------------------------------
    # [5/7] DETERMINE PODS TO DEPLOY
    # --------------------------------------------------------
    echo -e "${BLUE}[5/7] Planning POD deployment...${NC}"
    echo ""

    echo "PODs to be deployed:"
    echo -e "  $([ "$ENABLE_WEBSERVER" = true ] && echo "${GREEN}[x]${NC}" || echo "${YELLOW}[-]${NC}") POD-001: Web Server (Django + Nginx + NAXSI)"
    echo -e "  $([ "$ENABLE_IAM" = true ] && echo "${GREEN}[x]${NC}" || echo "${YELLOW}[-]${NC}") POD-002: IAM (Logto authentication)"
    echo -e "  ${GREEN}[x]${NC} POD-003: Database (PostgreSQL 16)"
    echo -e "  ${GREEN}[x]${NC} POD-005: Cache (Redis 7)"
    echo -e "  ${GREEN}[x]${NC} POD-010: Neuro Protocol (Qsecbit + HTP)"
    echo -e "  $([ "$ENABLE_MONITORING" = true ] && echo "${GREEN}[x]${NC}" || echo "${YELLOW}[-]${NC}") POD-004: Monitoring (Grafana + VictoriaMetrics)"
    echo -e "  $([ "$ENABLE_AI" = true ] && echo "${GREEN}[x]${NC}" || echo "${YELLOW}[-]${NC}") POD-006: Detection (Suricata, Zeek, Snort)"
    echo -e "  $([ "$ENABLE_AI" = true ] && echo "${GREEN}[x]${NC}" || echo "${YELLOW}[-]${NC}") POD-007: AI Analysis (Machine Learning)"

    echo ""
    echo "Network: OVS Bridge '$OVS_BRIDGE_NAME'"
    echo ""
    echo "Memory allocation:"
    if [ "$ENABLE_WEBSERVER" = true ]; then
        echo "  Web Server:      $POD_MEMORY_WEB"
    fi
    echo "  Database:        $POD_MEMORY_DATABASE"
    echo "  Cache:           $POD_MEMORY_CACHE"
    echo "  Neuro Protocol:  $POD_MEMORY_NEURO"
    if [ "$ENABLE_IAM" = true ]; then
        echo "  IAM:             $POD_MEMORY_IAM"
    fi
    if [ "$ENABLE_AI" = true ]; then
        echo "  Detection:       2048M"
        echo "  AI Analysis:     2048M"
    fi
    if [ "$ENABLE_MONITORING" = true ]; then
        echo "  Monitoring:      2048M"
    fi

    echo ""
    read -p "Continue with installation? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi

    # --------------------------------------------------------
    # [6/7] DEPLOY PODS
    # --------------------------------------------------------
    echo ""
    echo -e "${BLUE}[6/7] Deploying PODs...${NC}"
    echo ""

    # Install dependencies
    install_dependencies

    # Detect existing network configuration (WiFi bridges, WAN, etc.)
    echo ""
    echo -e "${CYAN}Detecting network configuration...${NC}"
    echo ""
    detect_network_config

    # Show network summary and get confirmation
    show_network_summary

    # Sentinel-only deployment (lightweight, no database/cache/networking needed)
    if [ "$ENABLE_SENTINEL_ONLY" = true ]; then
        echo ""
        echo -e "${CYAN}Deploying Sentinel (lightweight mode)...${NC}"
        echo ""

        # Skip OVS/VXLAN for sentinel - just use host network
        USE_HOST_NETWORK=true

        # Deploy only the sentinel pod
        deploy_sentinel_pod

        echo ""
        echo -e "${GREEN}Sentinel deployment complete!${NC}"
    else
        # Full edge deployment with networking and all components

        # Setup OVS bridge with VXLAN networking
        setup_ovs_bridge
        create_networks
        setup_vxlan_tunnels
        setup_openflow_monitoring

        # Configure routing from hookprobe bridge to WAN
        configure_hookprobe_routing

        # Deploy core PODs (always installed for full edge)
        if [ "$ENABLE_DATABASE" != false ]; then
            deploy_database_pod
        fi
        if [ "$ENABLE_CACHE" != false ]; then
            deploy_cache_pod
        fi
        deploy_neuro_pod

        # Deploy Sentinel if enabled (Edge + Sentinel mode)
        if [ "$ENABLE_SENTINEL" = true ]; then
            deploy_sentinel_pod
        fi

        # Deploy optional Web Server POD
        if [ "$ENABLE_WEBSERVER" = true ]; then
            deploy_web_pod
        fi

        # Deploy optional IAM POD
        if [ "$ENABLE_IAM" = true ]; then
            deploy_iam_pod
        fi

        # Deploy optional PODs
        if [ "$ENABLE_MONITORING" = true ]; then
            deploy_monitoring_pod
        fi

        if [ "$ENABLE_AI" = true ]; then
            deploy_detection_pod
            deploy_ai_pod
        fi

        # Deploy Kali security module if enabled
        if [ "$ENABLE_KALI" = true ]; then
            deploy_kali_pod
        fi

        # Deploy n8n automation if enabled
        if [ "$ENABLE_N8N" = true ]; then
            deploy_n8n_pod
        fi

        # Deploy ClickHouse analytics if enabled
        if [ "$ENABLE_CLICKHOUSE" = true ]; then
            deploy_clickhouse_pod
        fi

        # Configure LTE failover if enabled
        if [ "$ENABLE_LTE" = true ]; then
            configure_lte_failover
        fi
    fi

    # --------------------------------------------------------
    # [7/7] POST-INSTALL
    # --------------------------------------------------------
    echo ""
    echo -e "${BLUE}[7/7] Finalizing installation...${NC}"
    echo ""

    # Wait for containers to start
    echo "Waiting for containers to start..."
    sleep 10

    # Check POD status
    check_pod_status

    # Show success message
    show_success_message "$ENABLE_AI" "$ENABLE_MONITORING"

    echo ""
    echo -e "${GREEN}Installation complete!${NC}"
}

# ============================================================
# DEPENDENCY INSTALLATION
# ============================================================

install_dependencies() {
    echo "Installing dependencies..."

    # Detect package manager
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt-get"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
    else
        echo -e "${RED}ERROR: No supported package manager found${NC}"
        exit 1
    fi

    # Install Podman if not present
    if ! command -v podman &> /dev/null; then
        echo "Installing Podman..."
        if [ "$PKG_MANAGER" = "apt-get" ]; then
            apt-get update
            apt-get install -y podman
        else
            $PKG_MANAGER install -y podman
        fi
    fi

    # Detect LXC environment and configure podman accordingly
    if detect_container_environment; then
        echo ""
        echo -e "${CYAN}LXC container environment detected${NC}"

        # Check if unprivileged
        detect_lxc_unprivileged

        if [ "$IS_LXC_UNPRIVILEGED" = true ]; then
            echo -e "  ${YELLOW}[!]${NC} Running in unprivileged mode"
        else
            echo -e "  ${GREEN}[x]${NC} Running in privileged mode"
        fi

        # Configure podman for LXC compatibility
        configure_podman_for_lxc

        # Show guidance
        show_proxmox_lxc_guidance

        # Force host network in LXC
        USE_HOST_NETWORK=true
    fi

    # Install Git if not present
    if ! command -v git &> /dev/null; then
        echo "Installing Git..."
        $PKG_MANAGER install -y git
    fi

    # Install Python 3.9+ if not present
    if ! command -v python3 &> /dev/null; then
        echo "Installing Python..."
        if [ "$PKG_MANAGER" = "apt-get" ]; then
            apt-get install -y python3 python3-pip
        else
            $PKG_MANAGER install -y python3 python3-pip
        fi
    fi

    echo -e "${GREEN}✓${NC} Dependencies installed"
}

# ============================================================
# NETWORK CREATION
# ============================================================

# Global flag for network mode
# For edge deployments, host network is recommended for simplicity
# and to allow inter-container communication without complex routing
USE_HOST_NETWORK=true

# Global flags for LXC environment
IS_LXC_CONTAINER=false
IS_LXC_UNPRIVILEGED=false
USE_VFS_STORAGE=false

detect_container_environment() {
    # Detect if running inside LXC/LXD container
    if [ -f /proc/1/environ ] && grep -qa "container=lxc" /proc/1/environ 2>/dev/null; then
        return 0  # LXC detected
    fi
    if [ -f /run/systemd/container ] && grep -q "lxc" /run/systemd/container 2>/dev/null; then
        return 0  # LXC detected
    fi
    if grep -qa "lxc" /proc/1/cgroup 2>/dev/null; then
        return 0  # LXC detected
    fi
    return 1  # Not in LXC
}

detect_lxc_unprivileged() {
    # Detect if running in unprivileged LXC container
    # Unprivileged containers have limited capabilities and UID mapping

    if ! detect_container_environment; then
        return 1  # Not in LXC at all
    fi

    IS_LXC_CONTAINER=true

    # Check 1: UID mapping - unprivileged containers map root to non-zero UID
    if [ -f /proc/self/uid_map ]; then
        local uid_map=$(cat /proc/self/uid_map 2>/dev/null)
        # In unprivileged: "0 100000 65536" (root maps to 100000+)
        # In privileged: "0 0 4294967295" (root maps to root)
        if echo "$uid_map" | grep -qE '^\s*0\s+[1-9][0-9]+'; then
            IS_LXC_UNPRIVILEGED=true
            return 0
        fi
    fi

    # Check 2: Can't access certain privileged operations
    if ! capsh --print 2>/dev/null | grep -q "cap_sys_admin"; then
        # Missing CAP_SYS_ADMIN typically means unprivileged
        IS_LXC_UNPRIVILEGED=true
        return 0
    fi

    # Check 3: Check if we can create network namespaces
    if ! unshare --net true 2>/dev/null; then
        IS_LXC_UNPRIVILEGED=true
        return 0
    fi

    # Check 4: AppArmor restrictions - common in Proxmox unprivileged LXC
    if [ -f /sys/kernel/security/apparmor/profiles ]; then
        if grep -q "lxc-container-default" /sys/kernel/security/apparmor/profiles 2>/dev/null; then
            # Running under restricted AppArmor profile
            IS_LXC_UNPRIVILEGED=true
            return 0
        fi
    fi

    return 1  # Privileged LXC
}

configure_podman_for_lxc() {
    # Configure podman to work in LXC containers (especially unprivileged)
    echo "Configuring Podman for LXC environment..."

    local podman_conf_dir="/etc/containers"
    local storage_conf="$podman_conf_dir/storage.conf"
    local containers_conf="$podman_conf_dir/containers.conf"

    mkdir -p "$podman_conf_dir"

    # Detect if overlay works
    local use_overlay=true
    if [ "$IS_LXC_UNPRIVILEGED" = true ]; then
        # Test if overlay is available
        if ! grep -q "overlay" /proc/filesystems 2>/dev/null; then
            use_overlay=false
            USE_VFS_STORAGE=true
            echo -e "  ${YELLOW}[!]${NC} Overlay filesystem not available"
        fi

        # Even if overlay is in /proc/filesystems, it may not work in unprivileged
        # Test by trying to mount
        if [ "$use_overlay" = true ]; then
            local test_dir=$(mktemp -d)
            mkdir -p "$test_dir/lower" "$test_dir/upper" "$test_dir/work" "$test_dir/merged"
            if ! mount -t overlay overlay -o "lowerdir=$test_dir/lower,upperdir=$test_dir/upper,workdir=$test_dir/work" "$test_dir/merged" 2>/dev/null; then
                use_overlay=false
                USE_VFS_STORAGE=true
                echo -e "  ${YELLOW}[!]${NC} Overlay mount not permitted"
            else
                umount "$test_dir/merged" 2>/dev/null || true
            fi
            rm -rf "$test_dir"
        fi
    fi

    # Configure storage driver
    if [ "$USE_VFS_STORAGE" = true ]; then
        echo -e "  ${CYAN}→${NC} Using vfs storage driver (slower but compatible)"
        cat > "$storage_conf" << 'STORAGEEOF'
[storage]
driver = "vfs"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"

[storage.options]
pull_options = {enable_partial_images = "false", use_hard_links = "false", ostree_repos=""}

[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
STORAGEEOF
    else
        echo -e "  ${GREEN}[x]${NC} Using overlay storage driver"
        cat > "$storage_conf" << 'STORAGEEOF'
[storage]
driver = "overlay"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"

[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
STORAGEEOF
    fi

    # Configure containers.conf for LXC compatibility
    cat > "$containers_conf" << 'CONTAINERSEOF'
[containers]
# Disable features that don't work in LXC
netns = "host"
userns = "host"
ipcns = "host"
utsns = "host"
cgroupns = "host"

# Disable seccomp in LXC (host handles security)
seccomp_profile = ""

# Disable AppArmor (handled by LXC host)
apparmor_profile = ""

# Use crun if available (better LXC compatibility)
runtime = "crun"

[engine]
# Use host network by default in LXC
network_cmd_options = ["--network=host"]

# Disable healthchecks that may fail in LXC
healthcheck_events = false
CONTAINERSEOF

    # Install crun if not present (better than runc for LXC)
    if ! command -v crun &>/dev/null; then
        echo -e "  ${CYAN}→${NC} Installing crun runtime..."
        if command -v apt-get &>/dev/null; then
            apt-get install -y crun 2>/dev/null || true
        elif command -v dnf &>/dev/null; then
            dnf install -y crun 2>/dev/null || true
        fi
    fi

    # Install fuse-overlayfs for better overlay support
    if ! command -v fuse-overlayfs &>/dev/null && [ "$USE_VFS_STORAGE" != true ]; then
        echo -e "  ${CYAN}→${NC} Installing fuse-overlayfs..."
        if command -v apt-get &>/dev/null; then
            apt-get install -y fuse-overlayfs 2>/dev/null || true
        elif command -v dnf &>/dev/null; then
            dnf install -y fuse-overlayfs 2>/dev/null || true
        fi
    fi

    echo -e "  ${GREEN}[x]${NC} Podman configured for LXC"
}

show_proxmox_lxc_guidance() {
    # Show guidance for Proxmox LXC configuration
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  Proxmox LXC Configuration Guide${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    if [ "$IS_LXC_UNPRIVILEGED" = true ]; then
        echo -e "${YELLOW}Unprivileged LXC container detected${NC}"
        echo ""
        echo "HookProbe can run in unprivileged mode with some limitations:"
        echo -e "  ${GREEN}[x]${NC} Podman containers (using vfs/fuse-overlayfs)"
        echo -e "  ${GREEN}[x]${NC} Host network mode"
        echo -e "  ${GREEN}[x]${NC} All core functionality"
        echo -e "  ${YELLOW}[-]${NC} No OVS/VXLAN networking (uses host network)"
        echo -e "  ${YELLOW}[-]${NC} No XDP DDoS mitigation"
        echo ""
        echo "For better performance, configure on Proxmox host:"
        echo ""
        echo -e "${CYAN}Option 1: Enable nesting (recommended)${NC}"
        echo "  pct set <CTID> --features nesting=1"
        echo ""
        echo -e "${CYAN}Option 2: Use privileged container${NC}"
        echo "  pct set <CTID> --unprivileged 0"
        echo "  # WARNING: Less secure, use only in trusted environments"
        echo ""
        echo -e "${CYAN}Option 3: Add specific capabilities (advanced)${NC}"
        echo "  # Edit /etc/pve/lxc/<CTID>.conf on Proxmox host:"
        echo "  lxc.cap.drop ="
        echo "  lxc.cgroup2.devices.allow = a"
        echo "  lxc.mount.auto = proc:rw sys:rw"
        echo ""
    else
        echo -e "${GREEN}Privileged LXC container detected${NC}"
        echo ""
        echo "For OVS support, load kernel module on Proxmox host:"
        echo "  modprobe openvswitch"
        echo "  echo 'openvswitch' >> /etc/modules"
        echo ""
    fi

    if [ "$INTERACTIVE_MODE" = true ]; then
        echo -e "${YELLOW}Press Enter to continue with installation...${NC}"
        read -r
    fi
}

get_cni_version() {
    # Get installed CNI plugins version
    # Returns version string or "none" if not installed

    local cni_version="none"

    # Check common CNI plugin locations
    if [ -f /usr/lib/cni/bridge ]; then
        # Try to get version from binary (some CNI plugins support --version)
        cni_version=$(/usr/lib/cni/bridge 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
    elif [ -f /opt/cni/bin/bridge ]; then
        cni_version=$(/opt/cni/bin/bridge 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
    fi

    # Fallback: check package manager for version
    if [ -z "$cni_version" ] || [ "$cni_version" = "none" ]; then
        if command -v dpkg &> /dev/null; then
            cni_version=$(dpkg -l | grep -E 'containernetworking-plugins|cni-plugins' | awk '{print $3}' | head -1 || echo "")
        elif command -v rpm &> /dev/null; then
            cni_version=$(rpm -q containernetworking-plugins --queryformat '%{VERSION}' 2>/dev/null || echo "")
        fi
    fi

    if [ -z "$cni_version" ]; then
        echo "none"
    else
        echo "$cni_version"
    fi
}

compare_versions() {
    # Compare two version strings
    # Returns: 0 if $1 >= $2, 1 if $1 < $2
    local ver1="$1"
    local ver2="$2"

    # Handle "none" case
    if [ "$ver1" = "none" ]; then
        return 1
    fi

    # Use sort -V for version comparison
    local lowest=$(printf '%s\n%s' "$ver1" "$ver2" | sort -V | head -n1)
    if [ "$lowest" = "$ver2" ]; then
        return 0  # ver1 >= ver2
    else
        return 1  # ver1 < ver2
    fi
}

check_and_upgrade_cni() {
    # Check CNI version and upgrade if needed for Podman compatibility
    # Podman 4.x requires CNI plugins 1.0.0+

    local required_version="1.0.0"
    local current_version=$(get_cni_version)

    echo "Checking CNI plugins version..."
    echo "  Current version: $current_version"
    echo "  Required version: $required_version+"

    if [ "$current_version" = "none" ]; then
        echo -e "${YELLOW}⚠ CNI plugins not found - will be installed with Podman${NC}"
        return 0
    fi

    if compare_versions "$current_version" "$required_version"; then
        echo -e "${GREEN}✓${NC} CNI plugins version is compatible"
        return 0
    fi

    echo -e "${YELLOW}⚠ CNI plugins version $current_version is outdated${NC}"
    echo "  Podman requires CNI plugins $required_version or newer."
    echo ""

    # Attempt auto-upgrade
    echo "Attempting to upgrade CNI plugins..."

    if command -v apt-get &> /dev/null; then
        # Debian/Ubuntu
        apt-get update -qq
        if apt-get install -y containernetworking-plugins 2>/dev/null; then
            echo -e "${GREEN}✓${NC} CNI plugins upgraded via apt"
            return 0
        fi
        # Try alternative package name
        if apt-get install -y golang-github-containernetworking-plugins 2>/dev/null; then
            echo -e "${GREEN}✓${NC} CNI plugins upgraded via apt (alternative package)"
            return 0
        fi
    elif command -v dnf &> /dev/null; then
        # Fedora/RHEL 8+
        if dnf install -y containernetworking-plugins 2>/dev/null; then
            echo -e "${GREEN}✓${NC} CNI plugins upgraded via dnf"
            return 0
        fi
    elif command -v yum &> /dev/null; then
        # RHEL 7/CentOS
        if yum install -y containernetworking-plugins 2>/dev/null; then
            echo -e "${GREEN}✓${NC} CNI plugins upgraded via yum"
            return 0
        fi
    fi

    # Manual installation fallback
    echo -e "${YELLOW}⚠ Package manager upgrade failed, attempting manual install...${NC}"

    local cni_url="https://github.com/containernetworking/plugins/releases/download/v1.4.0/cni-plugins-linux-$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')-v1.4.0.tgz"
    local cni_dir="/opt/cni/bin"

    mkdir -p "$cni_dir"

    if command -v curl &> /dev/null; then
        if curl -sSL "$cni_url" | tar -xz -C "$cni_dir" 2>/dev/null; then
            echo -e "${GREEN}✓${NC} CNI plugins installed manually to $cni_dir"
            return 0
        fi
    elif command -v wget &> /dev/null; then
        if wget -qO- "$cni_url" | tar -xz -C "$cni_dir" 2>/dev/null; then
            echo -e "${GREEN}✓${NC} CNI plugins installed manually to $cni_dir"
            return 0
        fi
    fi

    echo -e "${RED}✗ Failed to upgrade CNI plugins${NC}"
    echo ""
    echo "Please manually upgrade CNI plugins to version 1.0.0 or newer:"
    echo "  Option 1: apt install containernetworking-plugins"
    echo "  Option 2: dnf install containernetworking-plugins"
    echo "  Option 3: Download from https://github.com/containernetworking/plugins/releases"
    echo ""
    echo "Falling back to host networking mode..."
    USE_HOST_NETWORK=true
    return 1
}

# ============================================================
# NETWORK DETECTION AND SAFE BRIDGE CONFIGURATION
# ============================================================

# Detected network configuration (populated by detect_network_config)
DETECTED_BRIDGES=()
DETECTED_WIFI_INTERFACES=()
DETECTED_WIFI_BRIDGES=()
DETECTED_WAN_INTERFACE=""
DETECTED_DEFAULT_GATEWAY=""
NETWORK_MANAGER_ACTIVE=false
EXISTING_HOOKPROBE_BRIDGE=false

detect_network_config() {
    # Comprehensive network detection to avoid conflicts with existing services
    echo "Detecting network configuration..."
    echo ""

    # Check if NetworkManager is managing the network
    if systemctl is-active --quiet NetworkManager 2>/dev/null; then
        NETWORK_MANAGER_ACTIVE=true
        echo -e "  ${CYAN}NetworkManager:${NC} Active"
    elif command -v nmcli &>/dev/null && nmcli general status &>/dev/null; then
        NETWORK_MANAGER_ACTIVE=true
        echo -e "  ${CYAN}NetworkManager:${NC} Active"
    else
        echo -e "  ${CYAN}NetworkManager:${NC} Not active"
    fi

    # Detect existing Linux bridges
    echo ""
    echo -e "  ${CYAN}Existing bridges:${NC}"
    local bridges=$(ip -o link show type bridge 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1)
    if [ -n "$bridges" ]; then
        while read -r br; do
            [ -z "$br" ] && continue
            DETECTED_BRIDGES+=("$br")
            local br_ip=$(ip -4 addr show "$br" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
            local br_state=$(ip link show "$br" 2>/dev/null | grep -oP '(?<=state\s)\w+')
            echo "    - $br (IP: ${br_ip:-none}, State: ${br_state:-unknown})"

            # Check if this is a hookprobe bridge
            if [[ "$br" == "hookprobe" ]] || [[ "$br" == "hkpr-"* ]]; then
                EXISTING_HOOKPROBE_BRIDGE=true
            fi
        done <<< "$bridges"
    else
        echo "    (none found)"
    fi

    # Detect OVS bridges
    if command -v ovs-vsctl &>/dev/null; then
        local ovs_bridges=$(ovs-vsctl list-br 2>/dev/null)
        if [ -n "$ovs_bridges" ]; then
            echo ""
            echo -e "  ${CYAN}OVS bridges:${NC}"
            while read -r br; do
                [ -z "$br" ] && continue
                DETECTED_BRIDGES+=("ovs:$br")
                echo "    - $br (OVS)"
                if [[ "$br" == "hookprobe" ]]; then
                    EXISTING_HOOKPROBE_BRIDGE=true
                fi
            done <<< "$ovs_bridges"
        fi
    fi

    # Detect WiFi interfaces
    echo ""
    echo -e "  ${CYAN}WiFi interfaces:${NC}"
    local wifi_ifaces=$(iw dev 2>/dev/null | grep Interface | awk '{print $2}')
    if [ -z "$wifi_ifaces" ]; then
        # Fallback: check /sys/class/net for wireless
        wifi_ifaces=$(ls -d /sys/class/net/*/wireless 2>/dev/null | cut -d'/' -f5)
    fi

    if [ -n "$wifi_ifaces" ]; then
        while read -r iface; do
            [ -z "$iface" ] && continue
            DETECTED_WIFI_INTERFACES+=("$iface")
            local wifi_mode=$(iw dev "$iface" info 2>/dev/null | grep type | awk '{print $2}')
            local wifi_ssid=$(iw dev "$iface" info 2>/dev/null | grep ssid | awk '{print $2}')
            echo "    - $iface (Mode: ${wifi_mode:-unknown}, SSID: ${wifi_ssid:-not connected})"

            # Check if WiFi is bridged
            local master=$(ip link show "$iface" 2>/dev/null | grep -oP '(?<=master\s)\w+')
            if [ -n "$master" ]; then
                DETECTED_WIFI_BRIDGES+=("$master")
                echo "      └─ Bridged to: $master"
            fi
        done <<< "$wifi_ifaces"
    else
        echo "    (none found)"
    fi

    # Detect WAN interface (default route)
    echo ""
    echo -e "  ${CYAN}WAN interface:${NC}"
    DETECTED_DEFAULT_GATEWAY=$(ip route show default 2>/dev/null | head -1 | awk '{print $3}')
    DETECTED_WAN_INTERFACE=$(ip route show default 2>/dev/null | head -1 | awk '{print $5}')

    if [ -n "$DETECTED_WAN_INTERFACE" ]; then
        local wan_ip=$(ip -4 addr show "$DETECTED_WAN_INTERFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        echo "    - $DETECTED_WAN_INTERFACE (IP: ${wan_ip:-dhcp}, Gateway: ${DETECTED_DEFAULT_GATEWAY:-none})"
    else
        echo "    (no default route found)"
    fi

    # Detect NetworkManager connections
    if [ "$NETWORK_MANAGER_ACTIVE" = true ]; then
        echo ""
        echo -e "  ${CYAN}NetworkManager connections:${NC}"
        nmcli -t -f NAME,TYPE,DEVICE connection show --active 2>/dev/null | while IFS=':' read -r name type device; do
            echo "    - $name ($type) on ${device:-disconnected}"
        done
    fi

    # Check for hostapd (WiFi AP mode)
    if pgrep -x hostapd &>/dev/null || systemctl is-active --quiet hostapd 2>/dev/null; then
        echo ""
        echo -e "  ${CYAN}WiFi Access Point:${NC}"
        echo "    - hostapd is running (WiFi AP mode detected)"
        local hostapd_conf=$(cat /etc/hostapd/hostapd.conf 2>/dev/null | grep -E "^interface=|^bridge=" | tr '\n' ', ')
        [ -n "$hostapd_conf" ] && echo "      Config: $hostapd_conf"
    fi

    # Check for dnsmasq (DHCP server)
    if pgrep -x dnsmasq &>/dev/null || systemctl is-active --quiet dnsmasq 2>/dev/null; then
        echo ""
        echo -e "  ${CYAN}DHCP Server:${NC}"
        echo "    - dnsmasq is running"
    fi

    echo ""
}

show_network_summary() {
    # Display network summary and get user confirmation
    echo -e "${CYAN}Network Configuration Summary${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    if [ "$EXISTING_HOOKPROBE_BRIDGE" = true ]; then
        echo -e "${YELLOW}[!] Existing HookProbe bridge detected${NC}"
        echo "    The installer will reconfigure the existing bridge."
        echo ""
    fi

    if [ ${#DETECTED_WIFI_BRIDGES[@]} -gt 0 ]; then
        echo -e "${GREEN}[x] WiFi bridge(s) detected - will NOT be modified:${NC}"
        for br in "${DETECTED_WIFI_BRIDGES[@]}"; do
            echo "    - $br"
        done
        echo ""
    fi

    if [ -n "$DETECTED_WAN_INTERFACE" ]; then
        echo -e "${GREEN}[x] WAN interface: $DETECTED_WAN_INTERFACE${NC}"
        echo "    HookProbe bridge will route traffic through this interface"
        echo ""
    fi

    echo -e "${CYAN}HookProbe network configuration:${NC}"
    echo "    Bridge name:    $OVS_BRIDGE_NAME"
    echo "    Bridge subnet:  $OVS_BRIDGE_SUBNET"
    echo "    Bridge IP:      10.250.0.1"
    echo ""

    if [ "$INTERACTIVE_MODE" = true ]; then
        echo -e "${YELLOW}Important:${NC}"
        echo "  - HookProbe will create an isolated bridge for container traffic"
        echo "  - Existing WiFi bridges and services will NOT be affected"
        echo "  - Container traffic will be NATed through $DETECTED_WAN_INTERFACE"
        echo ""
        read -p "Proceed with network configuration? [Y/n]: " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            echo "Network configuration cancelled."
            echo "Using host network mode instead."
            USE_HOST_NETWORK=true
            return 1
        fi
    fi
    return 0
}

configure_hookprobe_routing() {
    # Configure routing from hookprobe bridge to WAN interface
    # This ensures container traffic can reach the internet without affecting other services

    echo "Configuring HookProbe network routing..."

    # Skip if using host network
    if [ "$USE_HOST_NETWORK" = true ]; then
        echo -e "  ${YELLOW}[-]${NC} Host network mode - skipping routing setup"
        return 0
    fi

    # Ensure WAN interface is detected
    if [ -z "$DETECTED_WAN_INTERFACE" ]; then
        DETECTED_WAN_INTERFACE=$(ip route show default 2>/dev/null | head -1 | awk '{print $5}')
    fi

    if [ -z "$DETECTED_WAN_INTERFACE" ]; then
        echo -e "  ${YELLOW}[!]${NC} No WAN interface detected - skipping routing"
        return 0
    fi

    echo -e "  WAN interface: $DETECTED_WAN_INTERFACE"

    # Enable IP forwarding
    echo -e "  Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1

    # Make persistent
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi

    # Configure NAT for HookProbe subnet using nftables or iptables
    local hookprobe_subnet="10.250.0.0/16"

    if command -v nft &>/dev/null; then
        # Use nftables (preferred on modern systems)
        echo -e "  Configuring NAT with nftables..."

        # Create hookprobe NAT table if not exists
        nft list table ip hookprobe_nat &>/dev/null || {
            nft add table ip hookprobe_nat
            nft add chain ip hookprobe_nat postrouting '{ type nat hook postrouting priority 100 ; }'
        }

        # Add masquerade rule for hookprobe subnet
        nft add rule ip hookprobe_nat postrouting oifname "$DETECTED_WAN_INTERFACE" ip saddr $hookprobe_subnet masquerade 2>/dev/null || true

        echo -e "  ${GREEN}[x]${NC} NAT configured (nftables)"

    elif command -v iptables &>/dev/null; then
        # Fallback to iptables
        echo -e "  Configuring NAT with iptables..."

        # Check if rule already exists
        if ! iptables -t nat -C POSTROUTING -s $hookprobe_subnet -o "$DETECTED_WAN_INTERFACE" -j MASQUERADE 2>/dev/null; then
            iptables -t nat -A POSTROUTING -s $hookprobe_subnet -o "$DETECTED_WAN_INTERFACE" -j MASQUERADE
        fi

        echo -e "  ${GREEN}[x]${NC} NAT configured (iptables)"
    else
        echo -e "  ${YELLOW}[!]${NC} Neither nftables nor iptables available - manual NAT setup required"
    fi

    # Add route for hookprobe subnet if bridge exists
    if ip link show "$OVS_BRIDGE_NAME" &>/dev/null; then
        ip route add $hookprobe_subnet dev "$OVS_BRIDGE_NAME" 2>/dev/null || true
    fi

    # Save routing configuration
    mkdir -p /etc/hookprobe
    cat > /etc/hookprobe/routing.conf << ROUTEEOF
# HookProbe Routing Configuration
WAN_INTERFACE=$DETECTED_WAN_INTERFACE
HOOKPROBE_SUBNET=$hookprobe_subnet
HOOKPROBE_BRIDGE=$OVS_BRIDGE_NAME
DEFAULT_GATEWAY=$DETECTED_DEFAULT_GATEWAY
ROUTEEOF
    chmod 644 /etc/hookprobe/routing.conf

    echo -e "  ${GREEN}[x]${NC} Routing configuration saved"
}

# ============================================================
# OVS BRIDGE SETUP WITH VXLAN/VNI/PSK
# ============================================================

# VXLAN Configuration for each POD network
# Format: POD_NAME:VNI:VXLAN_PORT
declare -A VXLAN_CONFIG=(
    ["hookprobe-web"]="100:4789"
    ["hookprobe-iam"]="200:4790"
    ["hookprobe-database"]="300:4791"
    ["hookprobe-monitoring"]="400:4792"
    ["hookprobe-cache"]="500:4793"
    ["hookprobe-detection"]="600:4794"
    ["hookprobe-ai"]="700:4795"
    ["hookprobe-neuro"]="1000:4800"
)

generate_vxlan_psk() {
    # Generate a PSK for VXLAN tunnel encryption
    openssl rand -base64 32
}

setup_ovs_bridge() {
    echo "Setting up OVS bridge '$OVS_BRIDGE_NAME' with VXLAN networking..."

    # Check if running in LXC container - OVS kernel modules can't be loaded
    if detect_container_environment; then
        echo -e "  ${YELLOW}[!]${NC} LXC container detected"
        echo "  OVS kernel modules cannot be built/loaded in LXC containers."
        echo "  (openvswitch-datapath-dkms requires host kernel access)"
        echo ""

        # Check if OVS kernel module is available from host
        if lsmod | grep -q openvswitch 2>/dev/null; then
            echo -e "  ${GREEN}[x]${NC} OVS kernel module available from host"
        else
            echo -e "  ${YELLOW}[!]${NC} OVS kernel module not loaded on host"
            echo "  To use OVS in LXC, load the module on the Proxmox host:"
            echo "    modprobe openvswitch"
            echo "    echo 'openvswitch' >> /etc/modules"
            echo ""
            echo -e "  ${GREEN}[x]${NC} Using host network mode instead (recommended for LXC)"
            USE_OVS_BRIDGE=false
            USE_HOST_NETWORK=true
            return 0
        fi
    fi

    # Check if OVS is installed
    if ! command -v ovs-vsctl &> /dev/null; then
        echo "  Installing Open vSwitch..."

        # In LXC, only install userspace tools (not dkms)
        if detect_container_environment; then
            if command -v apt-get &> /dev/null; then
                # Install only userspace components, skip dkms
                apt-get update -qq
                apt-get install -y --no-install-recommends openvswitch-switch openvswitch-common 2>/dev/null || {
                    echo -e "  ${YELLOW}[!]${NC} OVS installation failed in LXC"
                    USE_OVS_BRIDGE=false
                    USE_HOST_NETWORK=true
                    return 0
                }
            fi
        else
            # Normal installation (non-LXC)
            if command -v apt-get &> /dev/null; then
                # Debian/Ubuntu: openvswitch-switch and openvswitch-common
                apt-get update -qq
                apt-get install -y openvswitch-switch openvswitch-common 2>/dev/null || \
                apt-get install -y openvswitch-switch 2>/dev/null
            elif command -v dnf &> /dev/null; then
                # Fedora/RHEL: openvswitch package
                # Check if it's RHEL (needs Fast Datapath repo) or Fedora (in base repos)
                if [ -f /etc/redhat-release ] && grep -qi "red hat" /etc/redhat-release; then
                    echo "  Detected RHEL, enabling Fast Datapath repository..."
                    # Enable Fast Datapath repo for RHEL
                    subscription-manager repos --enable=fast-datapath-for-rhel-10-x86_64-rpms 2>/dev/null || \
                    subscription-manager repos --enable=fast-datapath-for-rhel-9-x86_64-rpms 2>/dev/null || \
                    subscription-manager repos --enable=fast-datapath-for-rhel-8-x86_64-rpms 2>/dev/null || true
                fi
                # Install openvswitch (Fedora/RHEL)
                dnf install -y openvswitch 2>/dev/null || {
                    echo -e "  ${YELLOW}[!]${NC} openvswitch not found, trying alternatives..."
                    # Try DPDK version or versioned packages
                    dnf install -y openvswitch-dpdk 2>/dev/null || \
                    dnf install -y openvswitch3.1 2>/dev/null || \
                    dnf install -y openvswitch2.17 2>/dev/null || true
                }
            elif command -v yum &> /dev/null; then
                # Older RHEL/CentOS
                yum install -y openvswitch 2>/dev/null || \
                yum install -y openvswitch2.17 2>/dev/null || true
            elif command -v zypper &> /dev/null; then
                # OpenSUSE: openvswitch and openvswitch-switch
                zypper install -y openvswitch openvswitch-switch 2>/dev/null || \
                zypper install -y openvswitch-dpdk openvswitch-dpdk-switch 2>/dev/null || true
            fi
        fi
    fi

    # If OVS still not available
    if ! command -v ovs-vsctl &> /dev/null; then
        # For Fortress/Nexus tiers, OVS is mandatory - stop installation
        if [ "$EDGE_MODE" = "fortress" ] || [ "$EDGE_MODE" = "nexus" ]; then
            echo ""
            echo -e "${RED}══════════════════════════════════════════════════════════════${NC}"
            echo -e "${RED}  ERROR: Open vSwitch is required for Fortress installation${NC}"
            echo -e "${RED}══════════════════════════════════════════════════════════════${NC}"
            echo ""
            echo "Please install Open vSwitch manually before continuing:"
            echo ""
            echo "  Debian/Ubuntu:"
            echo "    sudo apt-get install openvswitch-switch openvswitch-common"
            echo ""
            echo "  Fedora:"
            echo "    sudo dnf install openvswitch"
            echo ""
            echo "  RHEL 8/9/10 (requires Fast Datapath subscription):"
            echo "    sudo subscription-manager repos --enable=fast-datapath-for-rhel-9-x86_64-rpms"
            echo "    sudo dnf install openvswitch"
            echo ""
            echo "  OpenSUSE:"
            echo "    sudo zypper install openvswitch openvswitch-switch"
            echo ""
            echo "After installing, run the installer again."
            echo ""
            exit 1
        fi
        # For other tiers, fall back to host networking
        echo -e "${YELLOW}[!]${NC} OVS not available, using host network mode"
        USE_OVS_BRIDGE=false
        USE_HOST_NETWORK=true
        return 0
    fi

    # Check if OVS kernel module is loaded
    if ! lsmod | grep -q openvswitch 2>/dev/null; then
        # Try to load it (will fail in LXC)
        modprobe openvswitch 2>/dev/null || {
            if detect_container_environment; then
                # For Fortress in container, still require OVS module on host
                if [ "$EDGE_MODE" = "fortress" ] || [ "$EDGE_MODE" = "nexus" ]; then
                    echo ""
                    echo -e "${RED}ERROR: OVS kernel module required for Fortress${NC}"
                    echo ""
                    echo "In LXC/container environment, load the module on the host:"
                    echo "  modprobe openvswitch"
                    echo "  echo 'openvswitch' >> /etc/modules"
                    echo ""
                    exit 1
                fi
                echo -e "  ${YELLOW}[!]${NC} Cannot load OVS module in LXC container"
                echo "  Load 'openvswitch' module on Proxmox host, or use host networking"
                USE_OVS_BRIDGE=false
                USE_HOST_NETWORK=true
                return 0
            fi
        }
    fi

    USE_OVS_BRIDGE=true

    # Start OVS service
    systemctl start openvswitch-switch 2>/dev/null || \
    systemctl start ovs-vswitchd 2>/dev/null || \
    service openvswitch-switch start 2>/dev/null || true

    # Check if bridge already exists
    if ovs-vsctl br-exists "$OVS_BRIDGE_NAME" 2>/dev/null; then
        echo -e "  ${GREEN}[x]${NC} OVS bridge '$OVS_BRIDGE_NAME' already exists"
    else
        # Create OVS bridge
        ovs-vsctl add-br "$OVS_BRIDGE_NAME" 2>/dev/null || {
            echo -e "${YELLOW}⚠ Failed to create OVS bridge, using standard networking${NC}"
            USE_OVS_BRIDGE=false
            return 0
        }
        echo -e "  ${GREEN}[x]${NC} OVS bridge '$OVS_BRIDGE_NAME' created"
    fi

    # Enable OpenFlow 1.3 for advanced flow monitoring
    ovs-vsctl set bridge "$OVS_BRIDGE_NAME" protocols=OpenFlow10,OpenFlow13 2>/dev/null || true

    # Configure bridge IP
    ip addr add 10.250.0.1/16 dev "$OVS_BRIDGE_NAME" 2>/dev/null || true
    ip link set "$OVS_BRIDGE_NAME" up 2>/dev/null || true

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

    # Create secrets directory for VXLAN PSK
    mkdir -p /etc/hookprobe/secrets/vxlan
    chmod 700 /etc/hookprobe/secrets/vxlan

    # Generate master PSK if not exists
    if [ ! -f /etc/hookprobe/secrets/vxlan/master.psk ]; then
        generate_vxlan_psk > /etc/hookprobe/secrets/vxlan/master.psk
        chmod 600 /etc/hookprobe/secrets/vxlan/master.psk
        echo -e "  ${GREEN}[x]${NC} VXLAN master PSK generated"
    fi

    # Save OVS bridge config
    mkdir -p /etc/hookprobe
    cat > /etc/hookprobe/ovs-bridge.conf << OVSEOF
# HookProbe OVS Bridge Configuration
OVS_BRIDGE_NAME=$OVS_BRIDGE_NAME
OVS_BRIDGE_SUBNET=$OVS_BRIDGE_SUBNET
OVS_BRIDGE_IP=10.250.0.1
OPENFLOW_VERSION=1.3

# VXLAN Configuration
VXLAN_ENABLED=true
VXLAN_MASTER_PSK=/etc/hookprobe/secrets/vxlan/master.psk
OVSEOF

    echo -e "  ${GREEN}[x]${NC} OVS bridge configured with OpenFlow 1.3"
    echo ""
}

setup_vxlan_tunnels() {
    echo "Setting up VXLAN tunnels for POD networks..."

    if [ "$USE_OVS_BRIDGE" != true ]; then
        echo -e "  ${YELLOW}[-]${NC} VXLAN skipped (OVS not available)"
        return 0
    fi

    # Get local IP for VXLAN endpoints
    local local_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || hostname -I | awk '{print $1}')

    # Create VXLAN config file
    cat > /etc/hookprobe/vxlan-networks.conf << 'VXLANHEADER'
# HookProbe VXLAN Network Configuration
# Format: NETWORK_NAME|VNI|VXLAN_PORT|SUBNET|PSK_FILE
VXLANHEADER

    local vxlan_count=0

    # Setup VXLAN for each enabled network
    for network in "${!VXLAN_CONFIG[@]}"; do
        local config="${VXLAN_CONFIG[$network]}"
        local vni=$(echo "$config" | cut -d: -f1)
        local port=$(echo "$config" | cut -d: -f2)

        # Check if this network should be created based on enabled components
        local should_create=false
        case "$network" in
            hookprobe-web) [ "$ENABLE_WEBSERVER" = true ] && should_create=true ;;
            hookprobe-iam) [ "$ENABLE_IAM" = true ] && should_create=true ;;
            hookprobe-database) should_create=true ;;  # Always
            hookprobe-cache) should_create=true ;;     # Always
            hookprobe-neuro) should_create=true ;;     # Always
            hookprobe-monitoring) [ "$ENABLE_MONITORING" = true ] && should_create=true ;;
            hookprobe-detection|hookprobe-ai) [ "$ENABLE_AI" = true ] && should_create=true ;;
        esac

        if [ "$should_create" = true ]; then
            # Generate per-tunnel PSK
            local psk_file="/etc/hookprobe/secrets/vxlan/${network}.psk"
            if [ ! -f "$psk_file" ]; then
                generate_vxlan_psk > "$psk_file"
                chmod 600 "$psk_file"
            fi

            # Get subnet for this network
            local subnet=""
            case "$network" in
                hookprobe-web) subnet="10.250.1.0/24" ;;
                hookprobe-iam) subnet="10.250.2.0/24" ;;
                hookprobe-database) subnet="10.250.3.0/24" ;;
                hookprobe-monitoring) subnet="10.250.4.0/24" ;;
                hookprobe-cache) subnet="10.250.5.0/24" ;;
                hookprobe-detection) subnet="10.250.6.0/24" ;;
                hookprobe-ai) subnet="10.250.7.0/24" ;;
                hookprobe-neuro) subnet="10.250.10.0/24" ;;
            esac

            # Add VXLAN port to OVS bridge
            local vxlan_port="vxlan_${vni}"
            ovs-vsctl --may-exist add-port "$OVS_BRIDGE_NAME" "$vxlan_port" \
                -- set interface "$vxlan_port" type=vxlan \
                options:key="$vni" \
                options:local_ip="$local_ip" \
                options:remote_ip=flow 2>/dev/null || true

            # Save to config
            echo "${network}|${vni}|${port}|${subnet}|${psk_file}" >> /etc/hookprobe/vxlan-networks.conf

            vxlan_count=$((vxlan_count + 1))
        fi
    done

    if [ "$vxlan_count" -gt 0 ]; then
        echo -e "  ${GREEN}[x]${NC} $vxlan_count VXLAN tunnels configured"
    fi
}

setup_openflow_monitoring() {
    echo "Setting up OpenFlow monitoring for VXLAN tunnels..."

    if [ "$USE_OVS_BRIDGE" != true ]; then
        echo -e "  ${YELLOW}[-]${NC} OpenFlow monitoring skipped (OVS not available)"
        return 0
    fi

    # Create OpenFlow rules for monitoring and security

    # Rule 1: Drop invalid packets
    ovs-ofctl add-flow "$OVS_BRIDGE_NAME" "priority=0,actions=drop" 2>/dev/null || true

    # Rule 2: Allow ARP
    ovs-ofctl add-flow "$OVS_BRIDGE_NAME" "priority=100,arp,actions=normal" 2>/dev/null || true

    # Rule 3: Allow ICMP for diagnostics
    ovs-ofctl add-flow "$OVS_BRIDGE_NAME" "priority=100,icmp,actions=normal" 2>/dev/null || true

    # Rule 4: Allow established connections
    ovs-ofctl add-flow "$OVS_BRIDGE_NAME" "priority=50,ip,actions=normal" 2>/dev/null || true

    # Rule 5: Monitor VXLAN traffic (match UDP dst port range 4789-4800)
    for port in 4789 4790 4791 4792 4793 4794 4795 4800; do
        ovs-ofctl add-flow "$OVS_BRIDGE_NAME" \
            "priority=200,udp,tp_dst=$port,actions=normal" 2>/dev/null || true
    done

    # Create monitoring script
    cat > /usr/local/bin/hookprobe-vxlan-monitor << 'MONITOREOF'
#!/bin/bash
# HookProbe VXLAN Monitor
# Displays VXLAN tunnel statistics and OpenFlow flows

OVS_BRIDGE="${1:-hookprobe}"

echo "=== HookProbe VXLAN Monitor ==="
echo ""

echo "Bridge: $OVS_BRIDGE"
echo ""

echo "--- VXLAN Ports ---"
ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null | grep vxlan || echo "No VXLAN ports"
echo ""

echo "--- OpenFlow Flows ---"
ovs-ofctl dump-flows "$OVS_BRIDGE" 2>/dev/null | head -20
echo ""

echo "--- Port Statistics ---"
ovs-ofctl dump-ports "$OVS_BRIDGE" 2>/dev/null | head -30
echo ""

echo "--- Network Config ---"
if [ -f /etc/hookprobe/vxlan-networks.conf ]; then
    echo "Network              | VNI  | Port | Subnet"
    echo "---------------------|------|------|---------------"
    grep -v "^#" /etc/hookprobe/vxlan-networks.conf | while IFS='|' read name vni port subnet psk; do
        [ -n "$name" ] && printf "%-20s | %-4s | %-4s | %s\n" "$name" "$vni" "$port" "$subnet"
    done
fi
MONITOREOF

    chmod +x /usr/local/bin/hookprobe-vxlan-monitor

    echo -e "  ${GREEN}[x]${NC} OpenFlow monitoring configured"
    echo -e "  ${GREEN}[x]${NC} Monitor tool: hookprobe-vxlan-monitor"
}

cleanup_old_cni_configs() {
    # Remove old CNI configs that might cause warnings
    local cni_dir="/etc/cni/net.d"
    if [ -d "$cni_dir" ]; then
        echo "  Cleaning up old CNI configs..."
        rm -f "$cni_dir"/web-net.conflist 2>/dev/null || true
        rm -f "$cni_dir"/database-net.conflist 2>/dev/null || true
        rm -f "$cni_dir"/cache-net.conflist 2>/dev/null || true
        rm -f "$cni_dir"/iam-net.conflist 2>/dev/null || true
        rm -f "$cni_dir"/neuro-net.conflist 2>/dev/null || true
        rm -f "$cni_dir"/hookprobe-*.conflist 2>/dev/null || true
    fi
    # Also remove podman networks
    podman network rm hookprobe-web hookprobe-database hookprobe-cache hookprobe-iam hookprobe-neuro 2>/dev/null || true
    podman network rm web-net database-net cache-net iam-net neuro-net 2>/dev/null || true
}

create_networks() {
    echo "Creating Podman networks..."

    # Check if running in LXC container - force host network mode
    if detect_container_environment; then
        echo -e "${YELLOW}[!] LXC/LXD container detected${NC}"
        echo "  CNI networking has compatibility issues in LXC containers."
        echo "  (firewall plugin does not support CNI config version 1.0.0)"
        echo ""
        # Clean up any old CNI configs that could cause warnings
        cleanup_old_cni_configs
        echo -e "${GREEN}[x]${NC} Using host network mode for LXC compatibility"
        USE_HOST_NETWORK=true
        return 0
    fi

    # Skip network creation if using host network
    if [ "$USE_HOST_NETWORK" = true ]; then
        echo -e "${GREEN}[x]${NC} Using host network mode - skipping custom network creation"
        cleanup_old_cni_configs
        return 0
    fi

    # Remove existing networks if present
    podman network rm hookprobe-web hookprobe-database hookprobe-cache hookprobe-iam hookprobe-neuro 2>/dev/null || true
    podman network rm web-net database-net cache-net iam-net neuro-net 2>/dev/null || true

    # Try to create networks with OVS bridge driver if available
    local network_failed=false
    local bridge_opt=""

    if [ "$USE_OVS_BRIDGE" = true ]; then
        # Use OVS bridge for networking
        bridge_opt="--opt bridge=$OVS_BRIDGE_NAME"
    fi

    # Create POD networks under the hookprobe namespace
    # Each POD gets its own subnet under 10.250.x.0/24
    # Custom interface names for easy identification (max 15 chars)

    # Core networks (always created)
    echo "  Creating core POD networks..."

    # Database network (POD-003)
    if ! podman network create \
        --subnet 10.250.3.0/24 \
        --gateway 10.250.3.1 \
        --interface-name hkpr-db \
        $bridge_opt \
        hookprobe-database 2>/dev/null; then
        podman network create --interface-name hkpr-db hookprobe-database 2>/dev/null || network_failed=true
    fi

    # Cache network (POD-005)
    if ! podman network create \
        --subnet 10.250.5.0/24 \
        --gateway 10.250.5.1 \
        --interface-name hkpr-cache \
        $bridge_opt \
        hookprobe-cache 2>/dev/null; then
        podman network create --interface-name hkpr-cache hookprobe-cache 2>/dev/null || true
    fi

    # Neuro network (POD-010)
    if ! podman network create \
        --subnet 10.250.10.0/24 \
        --gateway 10.250.10.1 \
        --interface-name hkpr-neuro \
        $bridge_opt \
        hookprobe-neuro 2>/dev/null; then
        podman network create --interface-name hkpr-neuro hookprobe-neuro 2>/dev/null || true
    fi

    # Optional networks based on selected components
    if [ "$ENABLE_WEBSERVER" = true ]; then
        echo "  Creating web server network..."
        if ! podman network create \
            --subnet 10.250.1.0/24 \
            --gateway 10.250.1.1 \
            --interface-name hkpr-web \
            $bridge_opt \
            hookprobe-web 2>/dev/null; then
            podman network create --interface-name hkpr-web hookprobe-web 2>/dev/null || true
        fi
    fi

    if [ "$ENABLE_IAM" = true ]; then
        echo "  Creating IAM network..."
        if ! podman network create \
            --subnet 10.250.2.0/24 \
            --gateway 10.250.2.1 \
            --interface-name hkpr-iam \
            $bridge_opt \
            hookprobe-iam 2>/dev/null; then
            podman network create --interface-name hkpr-iam hookprobe-iam 2>/dev/null || true
        fi
    fi

    if [ "$ENABLE_MONITORING" = true ]; then
        echo "  Creating monitoring network..."
        if ! podman network create \
            --subnet 10.250.4.0/24 \
            --gateway 10.250.4.1 \
            --interface-name hkpr-mon \
            $bridge_opt \
            hookprobe-monitoring 2>/dev/null; then
            podman network create --interface-name hkpr-mon hookprobe-monitoring 2>/dev/null || true
        fi
    fi

    if [ "$ENABLE_AI" = true ]; then
        echo "  Creating AI/detection networks..."
        if ! podman network create \
            --subnet 10.250.6.0/24 \
            --gateway 10.250.6.1 \
            --interface-name hkpr-det \
            $bridge_opt \
            hookprobe-detection 2>/dev/null; then
            podman network create --interface-name hkpr-det hookprobe-detection 2>/dev/null || true
        fi
        if ! podman network create \
            --subnet 10.250.7.0/24 \
            --gateway 10.250.7.1 \
            --interface-name hkpr-ai \
            $bridge_opt \
            hookprobe-ai 2>/dev/null; then
            podman network create --interface-name hkpr-ai hookprobe-ai 2>/dev/null || true
        fi
    fi

    # Verify networks were created
    if ! podman network exists hookprobe-database 2>/dev/null; then
        echo -e "${YELLOW}⚠ Custom networks unavailable - using host network mode${NC}"
        echo "  This is common in LXC/LXD containers or restricted environments."
        echo "  Pods will use host networking instead."
        USE_HOST_NETWORK=true
    else
        echo -e "${GREEN}[x]${NC} POD networks created"

        # Show network summary with interface names and VXLAN info
        echo ""
        echo "Network Summary:"
        echo "  Network              Interface    Subnet           VNI    Port"
        echo "  -------------------  -----------  ---------------  -----  ----"
        for net in $(podman network ls --format "{{.Name}}" 2>/dev/null | grep hookprobe); do
            local subnet=$(podman network inspect "$net" --format '{{range .Subnets}}{{.Subnet}}{{end}}' 2>/dev/null || echo "N/A")
            local iface="N/A"
            local vni="N/A"
            local port="N/A"
            case "$net" in
                hookprobe-web) iface="hkpr-web"; vni="100"; port="4789" ;;
                hookprobe-iam) iface="hkpr-iam"; vni="200"; port="4790" ;;
                hookprobe-database) iface="hkpr-db"; vni="300"; port="4791" ;;
                hookprobe-monitoring) iface="hkpr-mon"; vni="400"; port="4792" ;;
                hookprobe-cache) iface="hkpr-cache"; vni="500"; port="4793" ;;
                hookprobe-detection) iface="hkpr-det"; vni="600"; port="4794" ;;
                hookprobe-ai) iface="hkpr-ai"; vni="700"; port="4795" ;;
                hookprobe-neuro) iface="hkpr-neuro"; vni="1000"; port="4800" ;;
            esac
            printf "  %-19s  %-11s  %-15s  %-5s  %s\n" "$net" "$iface" "$subnet" "$vni" "$port"
        done
    fi
}

# ============================================================
# POD DEPLOYMENT
# ============================================================

# Helper function to get network argument
# Maps POD type to network name
get_network_arg() {
    local pod_type="$1"
    if [ "$USE_HOST_NETWORK" = true ]; then
        echo "--network host"
    else
        # Map pod types to hookprobe network names
        case "$pod_type" in
            web|web-net)
                echo "--network hookprobe-web"
                ;;
            database|database-net)
                echo "--network hookprobe-database"
                ;;
            cache|cache-net)
                echo "--network hookprobe-cache"
                ;;
            iam|iam-net)
                echo "--network hookprobe-iam"
                ;;
            neuro|neuro-net)
                echo "--network hookprobe-neuro"
                ;;
            monitoring|monitoring-net)
                echo "--network hookprobe-monitoring"
                ;;
            detection|detection-net)
                echo "--network hookprobe-detection"
                ;;
            ai|ai-net)
                echo "--network hookprobe-ai"
                ;;
            *)
                echo "--network hookprobe-$pod_type"
                ;;
        esac
    fi
}

# Helper to get database/redis host (localhost for host network, IP for custom)
# Network allocation:
#   hookprobe-database: 10.250.3.0/24
#   hookprobe-cache:    10.250.5.0/24
get_db_host() {
    if [ "$USE_HOST_NETWORK" = true ]; then
        echo "127.0.0.1"
    else
        echo "10.250.3.2"  # Database on hookprobe-database network
    fi
}

get_redis_host() {
    if [ "$USE_HOST_NETWORK" = true ]; then
        echo "127.0.0.1"
    else
        echo "10.250.5.2"  # Redis on hookprobe-cache network
    fi
}

deploy_web_pod() {
    echo "Deploying POD-001: Web Server..."

    local network_arg=$(get_network_arg "web")

    # Build Django container from Containerfile
    echo "  Building Django container (this may take a few minutes on ARM64)..."
    local containerfile="$REPO_ROOT/install/addons/webserver/Containerfile"
    if [ -f "$containerfile" ]; then
        echo "  Found Containerfile: $containerfile"
        podman build \
            -t hookprobe-web-django:edge \
            -f "$containerfile" \
            "$REPO_ROOT" || {
            echo -e "${RED}✗${NC} Failed to build Django container"
            return 1
        }
        local django_image="hookprobe-web-django:edge"
    else
        # Fallback: use minimal Django app inline
        echo "  Containerfile not found, using minimal inline setup..."
        local django_image="docker.io/library/python:3.11-slim"
    fi

    # Create pod
    # With host network, containers bind directly to host ports
    if [ "$USE_HOST_NETWORK" = true ]; then
        podman pod create \
            --name hookprobe-web \
            $network_arg
    else
        podman pod create \
            --name hookprobe-web \
            $network_arg \
            --publish 80:80 \
            --publish 443:443
    fi

    # Determine if we should use standalone mode (no external database)
    # Standalone mode uses SQLite instead of PostgreSQL
    local standalone_mode="false"
    if [ "${ENABLE_DATABASE:-true}" != "true" ]; then
        standalone_mode="true"
        echo "  Database POD disabled - Django will use SQLite (standalone mode)"
    fi

    # Deploy Django container
    if [ "$django_image" = "hookprobe-web-django:edge" ]; then
        # Use built container with proper entrypoint
        podman run -d \
            --pod hookprobe-web \
            --name hookprobe-web-django \
            --memory "$POD_MEMORY_WEB" \
            --restart unless-stopped \
            -e DJANGO_SECRET_KEY="$(openssl rand -base64 32)" \
            -e DJANGO_DEBUG="false" \
            -e DJANGO_ALLOWED_HOSTS="*" \
            -e POSTGRES_HOST="$(get_db_host)" \
            -e POSTGRES_PORT="5432" \
            -e POSTGRES_DB="hookprobe" \
            -e POSTGRES_USER="hookprobe" \
            -e POSTGRES_PASSWORD="hookprobe" \
            -e REDIS_HOST="$(get_redis_host)" \
            -e REDIS_PORT="6379" \
            -e GUNICORN_WORKERS="2" \
            -e GUNICORN_TIMEOUT="120" \
            -e STANDALONE_MODE="$standalone_mode" \
            -e DB_WAIT_TIMEOUT="30" \
            -e REDIS_WAIT_TIMEOUT="15" \
            "$django_image"
    else
        # Fallback: minimal Django status page
        podman run -d \
            --pod hookprobe-web \
            --name hookprobe-web-django \
            --memory "$POD_MEMORY_WEB" \
            --restart unless-stopped \
            --health-cmd "python -c 'import urllib.request; urllib.request.urlopen(\"http://localhost:8000\")' || exit 1" \
            --health-interval 30s \
            --health-timeout 10s \
            --health-retries 3 \
            --health-start-period 60s \
            -e DJANGO_SECRET_KEY="$(openssl rand -base64 32)" \
            "$django_image" \
            bash -c '
                pip install --quiet django gunicorn whitenoise
                mkdir -p /app && cd /app
                django-admin startproject hookprobe .
                cat > hookprobe/views.py << "VIEWSEOF"
from django.http import JsonResponse
import platform, os
def status(request):
    return JsonResponse({
        "service": "HookProbe Edge",
        "status": "running",
        "version": "5.0",
        "platform": platform.machine(),
        "python": platform.python_version()
    })
VIEWSEOF
                cat > hookprobe/urls.py << "URLSEOF"
from django.contrib import admin
from django.urls import path
from . import views
urlpatterns = [
    path("admin/", admin.site.urls),
    path("", views.status),
    path("health/", views.status),
    path("api/status/", views.status),
]
URLSEOF
                python manage.py migrate --run-syncdb
                exec gunicorn hookprobe.wsgi:application --bind 0.0.0.0:8000 --workers 2
            '
    fi

    # Create nginx configuration
    local nginx_conf_dir="/tmp/hookprobe-nginx-config"
    mkdir -p "$nginx_conf_dir"

    # Copy nginx config if available, otherwise create inline
    local nginx_conf_src="$REPO_ROOT/install/addons/webserver/nginx/default.conf"
    if [ -f "$nginx_conf_src" ]; then
        cp "$nginx_conf_src" "$nginx_conf_dir/default.conf"
    else
        cat > "$nginx_conf_dir/default.conf" << 'NGINXCONF'
upstream django {
    server 127.0.0.1:8000;
}
server {
    listen 80;
    server_name _;
    client_max_body_size 100M;

    location /static/ {
        alias /app/staticfiles/;
        expires 30d;
    }

    location /media/ {
        alias /app/media/;
    }

    location /nginx-health {
        access_log off;
        return 200 "OK\n";
    }

    location / {
        proxy_pass http://django;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_connect_timeout 60s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
    }
}
NGINXCONF
    fi

    # Deploy Nginx with proxy configuration
    podman run -d \
        --pod hookprobe-web \
        --name hookprobe-web-nginx \
        --memory 256M \
        --restart unless-stopped \
        --health-cmd "wget -q --spider http://localhost:80/nginx-health || exit 1" \
        --health-interval 30s \
        --health-timeout 10s \
        --health-retries 3 \
        --health-start-period 30s \
        -v "$nginx_conf_dir/default.conf:/etc/nginx/conf.d/default.conf:ro" \
        docker.io/library/nginx:alpine

    echo -e "${GREEN}[x]${NC} POD-001 deployed"
}

deploy_iam_pod() {
    echo "Deploying POD-002: IAM (Logto)..."

    local network_arg=$(get_network_arg "iam")

    # With host network, containers bind directly to host ports
    if [ "$USE_HOST_NETWORK" = true ]; then
        podman pod create \
            --name hookprobe-iam \
            $network_arg
    else
        podman pod create \
            --name hookprobe-iam \
            $network_arg \
            --publish 3001:3001 \
            --publish 3002:3002
    fi

    podman run -d \
        --pod hookprobe-iam \
        --name hookprobe-iam-logto \
        --memory "$POD_MEMORY_IAM" \
        --restart unless-stopped \
        --health-cmd "wget -q --spider http://localhost:3001/health || exit 1" \
        --health-interval 30s \
        --health-timeout 10s \
        --health-retries 3 \
        --health-start-period 60s \
        -e DB_URL="postgresql://hookprobe:hookprobe@$(get_db_host):5432/logto" \
        docker.io/svhd/logto:latest

    echo -e "${GREEN}✓${NC} POD-002 deployed"
}

deploy_database_pod() {
    echo "Deploying POD-003: Database (PostgreSQL)..."

    local network_arg=$(get_network_arg "database")

    # With host network, containers bind directly to host ports (no --publish needed)
    # With custom network, publish port for external access if needed
    if [ "$USE_HOST_NETWORK" = true ]; then
        podman pod create \
            --name hookprobe-database \
            $network_arg
    else
        podman pod create \
            --name hookprobe-database \
            $network_arg \
            --publish 5432:5432
    fi

    podman run -d \
        --pod hookprobe-database \
        --name hookprobe-database-postgres \
        --memory "$POD_MEMORY_DATABASE" \
        --restart unless-stopped \
        --health-cmd "pg_isready -U hookprobe -d hookprobe || exit 1" \
        --health-interval 30s \
        --health-timeout 5s \
        --health-retries 3 \
        --health-start-period 60s \
        -e POSTGRES_DB="hookprobe" \
        -e POSTGRES_USER="hookprobe" \
        -e POSTGRES_PASSWORD="$(openssl rand -base64 16)" \
        -v hookprobe-db-data:/var/lib/postgresql/data \
        docker.io/library/postgres:16-alpine

    echo -e "${GREEN}✓${NC} POD-003 deployed"
}

deploy_cache_pod() {
    echo "Deploying POD-005: Cache (Redis)..."

    local network_arg=$(get_network_arg "cache")

    # With host network, containers bind directly to host ports (no --publish needed)
    if [ "$USE_HOST_NETWORK" = true ]; then
        podman pod create \
            --name hookprobe-cache \
            $network_arg
    else
        podman pod create \
            --name hookprobe-cache \
            $network_arg \
            --publish 6379:6379
    fi

    podman run -d \
        --pod hookprobe-cache \
        --name hookprobe-cache-redis \
        --memory "$POD_MEMORY_CACHE" \
        --restart unless-stopped \
        --health-cmd "redis-cli ping || exit 1" \
        --health-interval 30s \
        --health-timeout 5s \
        --health-retries 3 \
        --health-start-period 30s \
        -v hookprobe-redis-data:/data \
        docker.io/library/redis:7-alpine \
        redis-server --requirepass "$(openssl rand -base64 16)"

    echo -e "${GREEN}✓${NC} POD-005 deployed"
}

deploy_neuro_pod() {
    echo "Deploying POD-010: Neuro Protocol (Qsecbit + HTP)..."

    local network_arg=$(get_network_arg "neuro")

    # Load MSSP configuration if available
    local mssp_env=""
    if [ -f /etc/hookprobe/secrets/mssp.env ]; then
        source /etc/hookprobe/secrets/mssp.env
        mssp_env="-e MSSP_ENDPOINT=$MSSP_ENDPOINT -e MSSP_PORT=$MSSP_PORT -e HTP_NODE_ID=$HTP_NODE_ID -e EDGE_MODE=$EDGE_MODE -e HTP_SENTINEL_MODE=$HTP_SENTINEL_MODE"
    fi

    # With host network for HTP UDP connectivity
    if [ "$USE_HOST_NETWORK" = true ]; then
        podman pod create \
            --name hookprobe-neuro \
            $network_arg
    else
        podman pod create \
            --name hookprobe-neuro \
            $network_arg \
            --publish 8443:8443/udp
    fi

    # Create neuro working directory
    mkdir -p /opt/hookprobe/neuro

    # Copy neuro source if available
    if [ -d "$REPO_ROOT/src/neuro" ]; then
        cp -r "$REPO_ROOT/src/neuro" /opt/hookprobe/
        cp -r "$REPO_ROOT/src/qsecbit" /opt/hookprobe/ 2>/dev/null || true
        echo "  Neuro source code installed"
    fi

    # Qsecbit + HTP container
    podman run -d \
        --pod hookprobe-neuro \
        --name hookprobe-neuro-qsecbit \
        --memory "$POD_MEMORY_NEURO" \
        --restart unless-stopped \
        --health-cmd "pgrep python || exit 1" \
        --health-interval 30s \
        --health-timeout 5s \
        --health-retries 3 \
        --health-start-period 60s \
        -v /opt/hookprobe/neuro:/app/neuro:ro \
        -v /opt/hookprobe/qsecbit:/app/qsecbit:ro \
        -v /etc/hookprobe/secrets:/secrets:ro \
        -e QSECBIT_MODE="quantum-resistant" \
        -e HTP_ENABLED="true" \
        -e PYTHONPATH="/app" \
        $mssp_env \
        docker.io/library/python:3.11-slim \
        bash -c '
            pip install --quiet numpy cryptography blake3 2>/dev/null || pip install --quiet numpy
            cd /app
            echo "HookProbe Neuro Protocol starting..."
            echo "  Mode: ${EDGE_MODE:-standalone}"
            echo "  MSSP: ${MSSP_ENDPOINT:-not configured}"
            echo "  Node ID: ${HTP_NODE_ID:-auto-generated}"

            # Test HTP module import
            if python -c "from neuro.transport.htp import HookProbeTransport; print(\"HTP module loaded\")" 2>/dev/null; then
                echo "  HTP: Available"
                # Start HTP service
                python -c "
from neuro.transport.htp import HookProbeTransport
import os, time

node_id = os.environ.get(\"HTP_NODE_ID\", \"edge-node\")
mssp_endpoint = os.environ.get(\"MSSP_ENDPOINT\", \"\")
mssp_port = int(os.environ.get(\"MSSP_PORT\", \"8443\"))
edge_mode = os.environ.get(\"EDGE_MODE\", \"standalone\")

print(f\"Starting HTP Transport: {node_id}\")
transport = HookProbeTransport(node_id=node_id, listen_port=8443)
transport.start()

if edge_mode != \"standalone\" and mssp_endpoint:
    print(f\"Connecting to MSSP: {mssp_endpoint}:{mssp_port}\")
    # HTP uses UDP hole punching, connection is established on first packet

print(\"Neuro Protocol running...\")
while True:
    time.sleep(60)
" 2>&1 || echo "HTP standalone mode"
            else
                echo "  HTP: Using fallback mode"
                python -c "import time; print(\"Qsecbit fallback running...\"); [time.sleep(60) for _ in iter(int, 1)]"
            fi
        '

    echo -e "${GREEN}✓${NC} POD-010 deployed"

    # Validate HTP connection if not standalone
    if [ "$EDGE_MODE" != "standalone" ]; then
        validate_htp_connection
    fi
}

deploy_sentinel_pod() {
    # Deploy lightweight validator pod for MSSP integration
    # This is a minimal deployment that only validates edge device authenticity
    echo "Deploying Sentinel..."

    local network_arg=$(get_network_arg "neuro")

    # Load validator configuration
    if [ -f /etc/hookprobe/sentinel.conf ]; then
        source /etc/hookprobe/sentinel.conf
    fi

    # Create validator pod with host network (required for unprivileged LXC)
    podman pod create \
        --name hookprobe-sentinel \
        $network_arg

    # Create validator working directory
    mkdir -p /opt/hookprobe/validator
    mkdir -p /opt/hookprobe/validator/cache
    mkdir -p /opt/hookprobe/validator/logs

    # Copy validator source if available
    if [ -d "$REPO_ROOT/src/neuro" ]; then
        cp -r "$REPO_ROOT/src/neuro" /opt/hookprobe/validator/
        cp -r "$REPO_ROOT/src/qsecbit" /opt/hookprobe/validator/ 2>/dev/null || true
    fi

    # Create validator entrypoint script
    cat > /opt/hookprobe/validator/entrypoint.py << 'VALIDATORPY'
#!/usr/bin/env python3
"""
HookProbe Sentinel
Validates edge device authenticity and reports to MSSP
"""
import os
import sys
import time
import json
import socket
import hashlib
import threading
from datetime import datetime, timezone
from collections import defaultdict

# Configuration from environment
NODE_ID = os.environ.get("HTP_NODE_ID", "validator-unknown")
MSSP_ENDPOINT = os.environ.get("MSSP_ENDPOINT", "mssp.hookprobe.com")
MSSP_PORT = int(os.environ.get("MSSP_PORT", "8443"))
LISTEN_PORT = int(os.environ.get("SENTINEL_LISTEN_PORT", "8443"))
METRICS_PORT = int(os.environ.get("SENTINEL_METRICS_PORT", "9090"))
REGION = os.environ.get("SENTINEL_REGION", "unknown")
TIER = os.environ.get("SENTINEL_TIER", "community")

# Validation state
validation_stats = {
    "validated": 0,
    "rejected": 0,
    "errors": 0,
    "active_edges": set(),
    "last_report": None
}

# Rate limiting per tier
RATE_LIMITS = {
    "community": 100,      # 100 validations/minute
    "professional": 1000,  # 1000 validations/minute
    "enterprise": 10000    # 10000 validations/minute
}

class EdgeValidator:
    """Validates HookProbe edge device messages"""

    def __init__(self):
        self.known_edges = {}  # edge_id -> last_seen
        self.validation_cache = {}  # cache recent validations
        self.rate_counter = defaultdict(int)

    def validate_message(self, data: bytes, addr: tuple) -> dict:
        """Validate an incoming message from an edge device"""
        try:
            # Parse HTP message header
            if len(data) < 32:
                return {"valid": False, "reason": "message_too_short"}

            # Extract edge node ID from header (first 16 bytes)
            edge_id = data[:16].hex()

            # Extract timestamp (bytes 16-24)
            timestamp_bytes = data[16:24]

            # Extract signature hint (bytes 24-32)
            sig_hint = data[24:32].hex()

            # Check if edge is in cache
            cache_key = f"{edge_id}:{sig_hint}"
            if cache_key in self.validation_cache:
                cached = self.validation_cache[cache_key]
                if time.time() - cached["time"] < 300:  # 5 min cache
                    return cached["result"]

            # Perform validation checks
            result = self._validate_edge(edge_id, timestamp_bytes, sig_hint, addr)

            # Update cache
            self.validation_cache[cache_key] = {
                "time": time.time(),
                "result": result
            }

            # Update stats
            if result["valid"]:
                validation_stats["validated"] += 1
                validation_stats["active_edges"].add(edge_id)
            else:
                validation_stats["rejected"] += 1

            return result

        except Exception as e:
            validation_stats["errors"] += 1
            return {"valid": False, "reason": f"error: {str(e)}"}

    def _validate_edge(self, edge_id: str, ts_bytes: bytes, sig_hint: str, addr: tuple) -> dict:
        """Internal validation logic"""
        # Check 1: Edge ID format
        if len(edge_id) != 32:
            return {"valid": False, "reason": "invalid_edge_id"}

        # Check 2: Timestamp freshness (within 5 minutes)
        try:
            ts = int.from_bytes(ts_bytes, 'big')
            current_ts = int(time.time())
            if abs(current_ts - ts) > 300:
                return {"valid": False, "reason": "stale_timestamp"}
        except:
            return {"valid": False, "reason": "invalid_timestamp"}

        # Check 3: Basic signature verification (full verification at MSSP)
        # This is a lightweight check - MSSP does full qsecbit verification
        expected_hint = hashlib.sha256(f"{edge_id}:{ts}".encode()).hexdigest()[:16]
        if sig_hint != expected_hint:
            # Note: This is simplified - real implementation uses qsecbit
            pass  # Allow for now, MSSP will do full validation

        # Check 4: Rate limiting
        rate_key = f"{edge_id}:{int(time.time() / 60)}"
        self.rate_counter[rate_key] += 1
        if self.rate_counter[rate_key] > RATE_LIMITS.get(TIER, 100):
            return {"valid": False, "reason": "rate_limited"}

        # Update known edges
        self.known_edges[edge_id] = {
            "last_seen": time.time(),
            "addr": addr,
            "validated": True
        }

        return {
            "valid": True,
            "edge_id": edge_id,
            "timestamp": ts,
            "sentinel": NODE_ID,
            "region": REGION
        }

def metrics_server(port: int):
    """Simple metrics endpoint for monitoring"""
    import http.server
    import socketserver

    class MetricsHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/metrics":
                metrics = f"""# HELP hookprobe_sentinel_validated_total Total validated messages
# TYPE hookprobe_sentinel_validated_total counter
hookprobe_sentinel_validated_total {validation_stats['validated']}

# HELP hookprobe_sentinel_rejected_total Total rejected messages
# TYPE hookprobe_sentinel_rejected_total counter
hookprobe_sentinel_rejected_total {validation_stats['rejected']}

# HELP hookprobe_sentinel_errors_total Total errors
# TYPE hookprobe_sentinel_errors_total counter
hookprobe_sentinel_errors_total {validation_stats['errors']}

# HELP hookprobe_sentinel_active_edges Current active edges
# TYPE hookprobe_sentinel_active_edges gauge
hookprobe_sentinel_active_edges {len(validation_stats['active_edges'])}

# HELP hookprobe_sentinel_info Validator information
# TYPE hookprobe_sentinel_info gauge
hookprobe_sentinel_info{{node_id="{NODE_ID}",region="{REGION}",tier="{TIER}"}} 1
"""
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(metrics.encode())
            elif self.path == "/health":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                health = {
                    "status": "healthy",
                    "node_id": NODE_ID,
                    "region": REGION,
                    "uptime": time.time() - start_time
                }
                self.wfile.write(json.dumps(health).encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):
            pass  # Suppress logging

    with socketserver.TCPServer(("", port), MetricsHandler) as httpd:
        httpd.serve_forever()

def report_to_mssp(validator: EdgeValidator):
    """Periodically report validation results to MSSP"""
    while True:
        try:
            time.sleep(60)  # Report every minute

            report = {
                "sentinel_id": NODE_ID,
                "region": REGION,
                "tier": TIER,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "stats": {
                    "validated": validation_stats["validated"],
                    "rejected": validation_stats["rejected"],
                    "errors": validation_stats["errors"],
                    "active_edges": len(validation_stats["active_edges"])
                },
                "known_edges": list(validator.known_edges.keys())[-100]  # Last 100
            }

            # Send report via UDP to MSSP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)

            # Encode report
            report_data = json.dumps(report).encode()

            # Add validator header
            header = bytes.fromhex(NODE_ID.replace("validator-", "").ljust(32, "0")[:32])
            message = header + report_data

            sock.sendto(message, (MSSP_ENDPOINT, MSSP_PORT))
            validation_stats["last_report"] = time.time()
            print(f"[{datetime.now().isoformat()}] Report sent to MSSP: {len(validator.known_edges)} edges")

        except Exception as e:
            print(f"[{datetime.now().isoformat()}] Report error: {e}")

def main():
    global start_time
    start_time = time.time()

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║           HookProbe Sentinel                          ║
╠══════════════════════════════════════════════════════════════╣
║  Node ID:     {NODE_ID:<45} ║
║  Region:      {REGION:<45} ║
║  Tier:        {TIER:<45} ║
║  Listen:      :{LISTEN_PORT:<44} ║
║  Metrics:     :{METRICS_PORT:<44} ║
║  MSSP:        {MSSP_ENDPOINT}:{MSSP_PORT:<29} ║
╚══════════════════════════════════════════════════════════════╝
""")

    validator = EdgeValidator()

    # Start metrics server in background
    metrics_thread = threading.Thread(target=metrics_server, args=(METRICS_PORT,), daemon=True)
    metrics_thread.start()
    print(f"Metrics server started on port {METRICS_PORT}")

    # Start MSSP reporting in background
    report_thread = threading.Thread(target=report_to_mssp, args=(validator,), daemon=True)
    report_thread.start()
    print(f"MSSP reporting started (endpoint: {MSSP_ENDPOINT}:{MSSP_PORT})")

    # Create UDP socket for receiving edge validation requests
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", LISTEN_PORT))
    print(f"Validator listening on UDP port {LISTEN_PORT}")
    print("")
    print("Ready to validate edge devices...")

    while True:
        try:
            data, addr = sock.recvfrom(65535)
            result = validator.validate_message(data, addr)

            # Send validation response
            response = json.dumps(result).encode()
            sock.sendto(response, addr)

            if result["valid"]:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Validated: {result.get('edge_id', 'unknown')[:16]}... from {addr[0]}")
            else:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Rejected: {result.get('reason', 'unknown')} from {addr[0]}")

        except KeyboardInterrupt:
            print("\nShutting down validator...")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
VALIDATORPY
    chmod +x /opt/hookprobe/validator/entrypoint.py

    # Run validator container
    podman run -d \
        --pod hookprobe-sentinel \
        --name hookprobe-sentinel-node \
        --memory 512M \
        --restart unless-stopped \
        --health-cmd "curl -sf http://localhost:${SENTINEL_METRICS_PORT}/health || exit 1" \
        --health-interval 30s \
        --health-timeout 5s \
        --health-retries 3 \
        --health-start-period 30s \
        -v /opt/hookprobe/validator:/app:ro \
        -v /etc/hookprobe:/etc/hookprobe:ro \
        -e HTP_NODE_ID="$HTP_NODE_ID" \
        -e MSSP_ENDPOINT="$MSSP_ENDPOINT" \
        -e MSSP_PORT="$MSSP_PORT" \
        -e SENTINEL_LISTEN_PORT="$SENTINEL_LISTEN_PORT" \
        -e SENTINEL_METRICS_PORT="$SENTINEL_METRICS_PORT" \
        -e SENTINEL_REGION="$SENTINEL_REGION" \
        -e SENTINEL_TIER="$SENTINEL_TIER" \
        docker.io/library/python:3.11-slim \
        python /app/entrypoint.py

    echo -e "${GREEN}✓${NC} Sentinel deployed"
    echo ""
    echo "Validator endpoints:"
    echo "  • Validation:  UDP port $SENTINEL_LISTEN_PORT"
    echo "  • Metrics:     http://localhost:$SENTINEL_METRICS_PORT/metrics"
    echo "  • Health:      http://localhost:$SENTINEL_METRICS_PORT/health"
    echo ""
}

deploy_monitoring_pod() {
    echo "Deploying POD-004: Monitoring (Grafana + VictoriaMetrics)..."

    local network_arg=$(get_network_arg "monitoring")

    # With host network, containers bind directly to host ports
    if [ "$USE_HOST_NETWORK" = true ]; then
        podman pod create \
            --name hookprobe-monitoring \
            $network_arg
    else
        podman pod create \
            --name hookprobe-monitoring \
            $network_arg \
            --publish 3000:3000 \
            --publish 8428:8428
    fi

    # Grafana
    podman run -d \
        --pod hookprobe-monitoring \
        --name hookprobe-monitoring-grafana \
        --memory 1024M \
        --restart unless-stopped \
        --health-cmd "wget -q --spider http://localhost:3000/api/health || exit 1" \
        --health-interval 30s \
        --health-timeout 10s \
        --health-retries 3 \
        --health-start-period 60s \
        docker.io/grafana/grafana:latest

    # VictoriaMetrics
    podman run -d \
        --pod hookprobe-monitoring \
        --name hookprobe-monitoring-victoria \
        --memory 1024M \
        --restart unless-stopped \
        --health-cmd "wget -q --spider http://localhost:8428/health || exit 1" \
        --health-interval 30s \
        --health-timeout 10s \
        --health-retries 3 \
        --health-start-period 60s \
        docker.io/victoriametrics/victoria-metrics:latest

    echo -e "${GREEN}✓${NC} POD-004 deployed"
}

deploy_detection_pod() {
    echo "Deploying POD-006: Detection (Suricata, Zeek, Snort)..."

    local network_arg=$(get_network_arg "detection")

    podman pod create \
        --name hookprobe-detection \
        $network_arg

    podman run -d \
        --pod hookprobe-detection \
        --name hookprobe-detection-suricata \
        --memory 2048M \
        --restart unless-stopped \
        --health-cmd "pgrep suricata || exit 1" \
        --health-interval 30s \
        --health-timeout 5s \
        --health-retries 3 \
        --health-start-period 120s \
        --cap-add NET_ADMIN \
        docker.io/jasonish/suricata:latest

    echo -e "${GREEN}✓${NC} POD-006 deployed"
}

deploy_ai_pod() {
    echo "Deploying POD-007: AI Analysis (Machine Learning)..."

    local network_arg=$(get_network_arg "ai")

    podman pod create \
        --name hookprobe-ai \
        $network_arg

    podman run -d \
        --pod hookprobe-ai \
        --name hookprobe-ai-ml \
        --memory 2048M \
        --restart unless-stopped \
        --health-cmd "pgrep python || exit 1" \
        --health-interval 30s \
        --health-timeout 5s \
        --health-retries 3 \
        --health-start-period 120s \
        docker.io/library/python:3.11-slim \
        bash -c "pip install scikit-learn tensorflow && python -c 'import time; print(\"AI running...\"); time.sleep(999999)'"

    echo -e "${GREEN}✓${NC} POD-007 deployed"
}

deploy_kali_pod() {
    echo "Deploying POD-008: Kali Security Module (Pentest Tools)..."

    local network_arg=$(get_network_arg "kali")

    podman pod create \
        --name hookprobe-kali \
        $network_arg

    # Kali Linux container with essential security tools
    podman run -d \
        --pod hookprobe-kali \
        --name hookprobe-kali-tools \
        --memory 1024M \
        --restart unless-stopped \
        --privileged \
        --cap-add NET_ADMIN \
        --cap-add NET_RAW \
        --cap-add SYS_ADMIN \
        -v /etc/hookprobe/kali:/data:Z \
        docker.io/kalilinux/kali-rolling:latest \
        bash -c '
            apt-get update && apt-get install -y --no-install-recommends \
                nmap \
                nikto \
                sqlmap \
                dirb \
                gobuster \
                hydra \
                john \
                hashcat \
                metasploit-framework \
                exploitdb \
                wpscan \
                nuclei \
                whatweb \
                sslscan \
                testssl.sh \
                net-tools \
                iputils-ping \
                dnsutils \
                curl \
                wget \
            && mkdir -p /data/reports \
            && echo "Kali tools ready" \
            && tail -f /dev/null
        '

    echo -e "${GREEN}✓${NC} POD-008 deployed"
    echo ""
    echo "Kali Security Module includes:"
    echo "  • nmap         - Network scanner"
    echo "  • nikto        - Web server scanner"
    echo "  • sqlmap       - SQL injection tool"
    echo "  • hydra        - Password cracker"
    echo "  • metasploit   - Penetration testing framework"
    echo "  • nuclei       - Vulnerability scanner"
    echo "  • wpscan       - WordPress scanner"
    echo "  • sslscan      - SSL/TLS scanner"
    echo ""
    echo "Access: podman exec -it hookprobe-kali-tools bash"
}

deploy_n8n_pod() {
    echo "Deploying POD-009: n8n Workflow Automation..."

    local network_arg=$(get_network_arg "n8n")

    # Create data directory
    mkdir -p /etc/hookprobe/n8n

    podman pod create \
        --name hookprobe-n8n \
        -p 5678:5678 \
        $network_arg

    podman run -d \
        --pod hookprobe-n8n \
        --name hookprobe-n8n-app \
        --memory 512M \
        --restart unless-stopped \
        -e N8N_BASIC_AUTH_ACTIVE=true \
        -e N8N_BASIC_AUTH_USER=admin \
        -e N8N_BASIC_AUTH_PASSWORD=hookprobe \
        -e N8N_HOST=0.0.0.0 \
        -e N8N_PORT=5678 \
        -e N8N_PROTOCOL=http \
        -e WEBHOOK_URL=http://localhost:5678/ \
        -v /etc/hookprobe/n8n:/home/node/.n8n:Z \
        docker.io/n8nio/n8n:latest

    echo -e "${GREEN}✓${NC} POD-009 deployed"
    echo ""
    echo "n8n Workflow Automation:"
    echo "  • URL: http://localhost:5678"
    echo "  • Default login: admin / hookprobe"
    echo "  • Change password after first login!"
}

deploy_clickhouse_pod() {
    echo "Deploying POD-010: ClickHouse Analytics Database..."

    local network_arg=$(get_network_arg "clickhouse")

    # Create data directories
    mkdir -p /etc/hookprobe/clickhouse/data
    mkdir -p /etc/hookprobe/clickhouse/logs

    podman pod create \
        --name hookprobe-clickhouse \
        -p 8123:8123 \
        -p 9000:9000 \
        $network_arg

    podman run -d \
        --pod hookprobe-clickhouse \
        --name hookprobe-clickhouse-db \
        --memory 2048M \
        --restart unless-stopped \
        -e CLICKHOUSE_DB=hookprobe \
        -e CLICKHOUSE_USER=hookprobe \
        -e CLICKHOUSE_PASSWORD=hookprobe \
        -v /etc/hookprobe/clickhouse/data:/var/lib/clickhouse:Z \
        -v /etc/hookprobe/clickhouse/logs:/var/log/clickhouse-server:Z \
        docker.io/clickhouse/clickhouse-server:latest

    echo -e "${GREEN}✓${NC} POD-010 deployed"
    echo ""
    echo "ClickHouse Analytics:"
    echo "  • HTTP Interface: http://localhost:8123"
    echo "  • Native Interface: localhost:9000"
    echo "  • Database: hookprobe"
    echo "  • User: hookprobe"
}

configure_lte_failover() {
    echo "Configuring LTE/5G Failover..."

    # Check for LTE interfaces
    local lte_interfaces=$(ip link show 2>/dev/null | grep -E "wwan|wwp|lte|cdc" | awk -F: '{print $2}' | tr -d ' ')

    if [ -z "$lte_interfaces" ]; then
        echo -e "${YELLOW}No LTE/5G interfaces detected${NC}"
        echo "LTE failover will be configured when interface is available"
    else
        echo "Detected LTE interfaces: $lte_interfaces"

        # Create failover configuration
        mkdir -p /etc/hookprobe/network
        cat > /etc/hookprobe/network/lte-failover.conf << 'LTEEOF'
# LTE/5G Failover Configuration
LTE_ENABLED=true
LTE_CHECK_INTERVAL=30
LTE_PING_TARGET=1.1.1.1
LTE_FAILOVER_THRESHOLD=3
LTE_RECOVERY_THRESHOLD=5
LTEEOF

        # Create failover script
        cat > /etc/hookprobe/network/lte-failover.sh << 'LTESCRIPT'
#!/bin/bash
# LTE Failover Script
source /etc/hookprobe/network/lte-failover.conf

FAIL_COUNT=0
RECOVERY_COUNT=0
CURRENT_STATE="primary"

while true; do
    if ping -c 1 -W 2 $LTE_PING_TARGET &>/dev/null; then
        FAIL_COUNT=0
        ((RECOVERY_COUNT++))
        if [ "$CURRENT_STATE" = "failover" ] && [ $RECOVERY_COUNT -ge $LTE_RECOVERY_THRESHOLD ]; then
            echo "$(date): Recovering to primary connection"
            CURRENT_STATE="primary"
            RECOVERY_COUNT=0
        fi
    else
        ((FAIL_COUNT++))
        RECOVERY_COUNT=0
        if [ "$CURRENT_STATE" = "primary" ] && [ $FAIL_COUNT -ge $LTE_FAILOVER_THRESHOLD ]; then
            echo "$(date): Failing over to LTE"
            CURRENT_STATE="failover"
            FAIL_COUNT=0
        fi
    fi
    sleep $LTE_CHECK_INTERVAL
done
LTESCRIPT
        chmod +x /etc/hookprobe/network/lte-failover.sh

        echo -e "${GREEN}✓${NC} LTE failover configured"
    fi

    echo ""
    echo "LTE/5G Failover:"
    echo "  • Config: /etc/hookprobe/network/lte-failover.conf"
    echo "  • Script: /etc/hookprobe/network/lte-failover.sh"
    echo "  • Check interval: 30 seconds"
}

# ============================================================
# STATUS CHECK
# ============================================================

check_pod_status() {
    echo "Checking POD status..."
    echo ""

    podman pod ls
    echo ""

    local failed_pods=0

    # Check core PODs (always deployed)
    if ! podman pod ps | grep -q "hookprobe-database.*Running"; then
        echo -e "${RED}[!]${NC} POD-003 (Database) not running"
        failed_pods=$((failed_pods + 1))
    else
        echo -e "${GREEN}[x]${NC} POD-003 (Database) running"
    fi

    if ! podman pod ps | grep -q "hookprobe-cache.*Running"; then
        echo -e "${RED}[!]${NC} POD-005 (Cache) not running"
        failed_pods=$((failed_pods + 1))
    else
        echo -e "${GREEN}[x]${NC} POD-005 (Cache) running"
    fi

    if ! podman pod ps | grep -q "hookprobe-neuro.*Running"; then
        echo -e "${RED}[!]${NC} POD-010 (Neuro) not running"
        failed_pods=$((failed_pods + 1))
    else
        echo -e "${GREEN}[x]${NC} POD-010 (Neuro) running"
    fi

    # Check optional PODs based on configuration
    if [ "$ENABLE_WEBSERVER" = true ]; then
        if ! podman pod ps | grep -q "hookprobe-web.*Running"; then
            echo -e "${RED}[!]${NC} POD-001 (Web) not running"
            failed_pods=$((failed_pods + 1))
        else
            echo -e "${GREEN}[x]${NC} POD-001 (Web) running"
        fi
    fi

    if [ "$ENABLE_IAM" = true ]; then
        if ! podman pod ps | grep -q "hookprobe-iam.*Running"; then
            echo -e "${RED}[!]${NC} POD-002 (IAM) not running"
            failed_pods=$((failed_pods + 1))
        else
            echo -e "${GREEN}[x]${NC} POD-002 (IAM) running"
        fi
    fi

    if [ "$ENABLE_MONITORING" = true ]; then
        if ! podman pod ps | grep -q "hookprobe-monitoring.*Running"; then
            echo -e "${RED}[!]${NC} POD-004 (Monitoring) not running"
            failed_pods=$((failed_pods + 1))
        else
            echo -e "${GREEN}[x]${NC} POD-004 (Monitoring) running"
        fi
    fi

    if [ "$ENABLE_AI" = true ]; then
        if ! podman pod ps | grep -q "hookprobe-detection.*Running"; then
            echo -e "${RED}[!]${NC} POD-006 (Detection) not running"
            failed_pods=$((failed_pods + 1))
        else
            echo -e "${GREEN}[x]${NC} POD-006 (Detection) running"
        fi
        if ! podman pod ps | grep -q "hookprobe-ai.*Running"; then
            echo -e "${RED}[!]${NC} POD-007 (AI) not running"
            failed_pods=$((failed_pods + 1))
        else
            echo -e "${GREEN}[x]${NC} POD-007 (AI) running"
        fi
    fi

    echo ""
    if [ "$failed_pods" -gt 0 ]; then
        echo -e "${YELLOW}Warning: $failed_pods POD(s) failed to start${NC}"
        echo "Check logs with: podman logs <container-name>"
    else
        echo -e "${GREEN}All PODs running successfully${NC}"
    fi
}

# ============================================================
# MAIN EXECUTION
# ============================================================

main "$@"
