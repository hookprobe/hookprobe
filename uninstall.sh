#!/bin/bash
#
# uninstall.sh - HookProbe Uninstallation Menu
# Version: 5.0
# License: MIT
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}ERROR: This script must be run as root${NC}"
        exit 1
    fi
}

show_menu() {
    echo -e "${YELLOW}HookProbe Uninstaller${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "1) Uninstall Edge Deployment (PODs 001-007)"
    echo "2) Uninstall Cloud Backend"
    echo "3) Uninstall n8n Only (POD 008)"
    echo "4) Uninstall Everything"
    echo ""
    echo "q) Cancel"
    echo ""
}

main() {
    check_root

    show_menu
    read -p "Select option: " choice

    case $choice in
        1)
            echo -e "${YELLOW}Uninstalling Edge Deployment...${NC}"
            bash "$SCRIPT_DIR/deploy/edge/uninstall.sh"
            ;;
        2)
            echo -e "${YELLOW}Uninstalling Cloud Backend...${NC}"
            bash "$SCRIPT_DIR/deploy/cloud/uninstall.sh"
            ;;
        3)
            echo -e "${YELLOW}Uninstalling n8n...${NC}"
            bash "$SCRIPT_DIR/deploy/addons/n8n/uninstall.sh"
            ;;
        4)
            echo -e "${RED}WARNING: This will remove EVERYTHING${NC}"
            read -p "Are you sure? (type 'yes'): " confirm
            if [ "$confirm" = "yes" ]; then
                bash "$SCRIPT_DIR/deploy/edge/uninstall.sh" 2>/dev/null || true
                bash "$SCRIPT_DIR/deploy/addons/n8n/uninstall.sh" 2>/dev/null || true
                bash "$SCRIPT_DIR/deploy/cloud/uninstall.sh" 2>/dev/null || true
                echo -e "${GREEN}✓ Complete uninstall finished${NC}"
            else
                echo "Cancelled."
            fi
            ;;
        q|Q)
            echo "Cancelled."
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            exit 1
            ;;
    esac
}

main
