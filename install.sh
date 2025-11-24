#!/bin/bash
#
# install.sh - HookProbe Installation Menu
# Version: 5.0
# License: MIT
#
# Main entry point for HookProbe deployment
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

show_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
    ╦ ╦╔═╗╔═╗╦╔═╔═╗╦═╗╔═╗╔╗ ╔═╗
    ╠═╣║ ║║ ║╠╩╗╠═╝╠╦╝║ ║╠╩╗║╣
    ╩ ╩╚═╝╚═╝╩ ╩╩  ╩╚═╚═╝╚═╝╚═╝

    Cyber Resilience at the Edge
    Version 5.0
EOF
    echo -e "${NC}"
}

show_menu() {
    echo -e "${GREEN}HookProbe Installer${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Main Deployments:"
    echo -e "  ${YELLOW}1${NC}) Edge Deployment (SBC/Intel N100/Raspberry Pi)"
    echo -e "  ${YELLOW}2${NC}) Cloud Backend (MSSP Multi-Tenant)"
    echo ""
    echo "Optional Add-ons:"
    echo -e "  ${YELLOW}3${NC}) Install n8n Workflow Automation (POD 008)"
    echo -e "  ${YELLOW}4${NC}) Install LTE/5G Connectivity"
    echo -e "  ${YELLOW}5${NC}) Install ClickHouse Analytics"
    echo ""
    echo "Maintenance:"
    echo -e "  ${YELLOW}6${NC}) Uninstall HookProbe"
    echo -e "  ${YELLOW}7${NC}) Update Containers"
    echo ""
    echo -e "  ${YELLOW}q${NC}) Quit"
    echo ""
}

run_installer() {
    local script_path="$1"
    local description="$2"

    if [ ! -f "$script_path" ]; then
        echo -e "${RED}ERROR: Installer not found: $script_path${NC}"
        return 1
    fi

    echo -e "${GREEN}Starting: $description${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if bash "$script_path"; then
        echo -e "${GREEN}✓ $description completed successfully${NC}"
    else
        echo -e "${RED}✗ $description failed${NC}"
        return 1
    fi
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}ERROR: This script must be run as root${NC}"
        echo "Please run: sudo $0"
        exit 1
    fi
}

main() {
    check_root

    while true; do
        clear
        show_banner
        show_menu

        read -p "Select option: " choice
        echo ""

        case $choice in
            1)
                run_installer "$SCRIPT_DIR/install/edge/setup.sh" "Edge Deployment"
                ;;
            2)
                run_installer "$SCRIPT_DIR/install/cloud/setup.sh" "Cloud Backend Deployment"
                ;;
            3)
                run_installer "$SCRIPT_DIR/install/addons/n8n/setup.sh" "n8n Workflow Automation"
                ;;
            4)
                echo -e "${BLUE}LTE/5G Setup${NC}"
                echo "Please see: install/addons/lte/README.md for manual setup instructions"
                ;;
            5)
                echo -e "${BLUE}ClickHouse Setup${NC}"
                echo "Please see: docs/guides/clickhouse-quick-start.md for setup instructions"
                ;;
            6)
                echo -e "${YELLOW}Uninstall Options:${NC}"
                echo "1) Uninstall Edge Deployment"
                echo "2) Uninstall Cloud Backend"
                echo "3) Uninstall n8n Only"
                read -p "Select: " uninstall_choice

                case $uninstall_choice in
                    1) run_installer "$SCRIPT_DIR/install/edge/uninstall.sh" "Edge Uninstall" ;;
                    2) run_installer "$SCRIPT_DIR/install/cloud/uninstall.sh" "Cloud Uninstall" ;;
                    3) run_installer "$SCRIPT_DIR/install/addons/n8n/uninstall.sh" "n8n Uninstall" ;;
                    *) echo -e "${RED}Invalid option${NC}" ;;
                esac
                ;;
            7)
                run_installer "$SCRIPT_DIR/install/edge/update.sh" "Container Update"
                ;;
            q|Q)
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                ;;
        esac

        echo ""
        read -p "Press Enter to continue..."
    done
}

main
