#!/bin/bash
#
# instructions.sh - User Instructions Library
# Part of HookProbe unified installation system
#
# Shows clear, actionable instructions when manual configuration is needed
#

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================
# RASPBERRY PI CGROUP INSTRUCTIONS
# ============================================================

show_cgroup_instructions() {
    # Show detailed instructions for enabling cgroups on Raspberry Pi.

    #

    # Uses platform detection to show exact file path.

    local boot_config=$(get_boot_config_path)

    echo -e "${CYAN}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│ RASPBERRY PI CGROUP CONFIGURATION REQUIRED                 │${NC}"
    echo -e "${CYAN}└────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo "Raspberry Pi requires cgroup configuration for containers (Podman)."
    echo ""

    # STEP 1: Detect and show correct boot config path
    echo -e "${YELLOW}STEP 1: Edit boot configuration${NC}"
    echo ""

    if [ -n "$boot_config" ]; then
        echo -e "  Your system uses: ${GREEN}$boot_config${NC}"
        echo ""
        echo "  Edit the file:"
        echo -e "    ${BLUE}sudo nano $boot_config${NC}"
    else
        echo -e "  ${YELLOW}⚠ Could not auto-detect boot config file.${NC}"
        echo ""
        echo "  Try one of these:"
        echo -e "    ${BLUE}sudo nano /boot/firmware/cmdline.txt${NC}  # Raspberry Pi OS Bookworm (Debian 12+)"
        echo -e "    ${BLUE}sudo nano /boot/cmdline.txt${NC}           # Older Raspberry Pi OS"
    fi

    echo ""

    # STEP 2: Show parameters to add
    echo -e "${YELLOW}STEP 2: Add these parameters to the EXISTING line${NC}"
    echo -e "        ${RED}⚠ Do NOT create a new line!${NC}"
    echo ""
    echo "  Add at the end of the existing line:"
    echo ""
    echo -e "    ${GREEN}cgroup_enable=cpuset cgroup_enable=memory cgroup_memory=1${NC}"
    echo ""

    # STEP 3: Show example
    echo -e "${YELLOW}STEP 3: Example (before and after)${NC}"
    echo ""
    echo "  ${BLUE}Before:${NC}"
    echo "  console=serial0,115200 console=tty1 root=PARTUUID=12345-02 rootfstype=ext4 rootwait"
    echo ""
    echo "  ${GREEN}After:${NC}"
    echo "  console=serial0,115200 console=tty1 root=PARTUUID=12345-02 rootfstype=ext4 rootwait ${GREEN}cgroup_enable=cpuset cgroup_enable=memory cgroup_memory=1${NC}"
    echo ""

    # STEP 4: Save and reboot
    echo -e "${YELLOW}STEP 4: Save and reboot${NC}"
    echo ""
    echo "  Save the file (Ctrl+X, then Y, then Enter in nano)"
    echo ""
    echo "  Reboot your Raspberry Pi:"
    echo -e "    ${BLUE}sudo reboot${NC}"
    echo ""

    # STEP 5: Verify
    echo -e "${YELLOW}STEP 5: Verify (after reboot)${NC}"
    echo ""
    echo "  Check if cgroup memory is enabled:"
    echo -e "    ${BLUE}cat /proc/cgroups | grep memory${NC}"
    echo "  Should show: ${GREEN}memory ... 1${NC} (last column = 1)"
    echo ""
    echo "  Check if cgroup filesystem is mounted:"
    echo -e "    ${BLUE}ls /sys/fs/cgroup/memory.max${NC}"
    echo "  Should exist without errors"
    echo ""

    # STEP 6: Re-run installer
    echo -e "${YELLOW}STEP 6: Re-run installer${NC}"
    echo ""
    echo "  After rebooting and verifying, re-run this installer:"
    echo -e "    ${BLUE}sudo bash $(readlink -f "$0")${NC}"
    echo ""

    echo -e "${CYAN}────────────────────────────────────────────────────────────${NC}"
}

# ============================================================
# RAM WARNING INSTRUCTIONS
# ============================================================

show_low_ram_warning() {
    # Show warning when RAM is below minimum requirements.

    #

    # Args:

    # $1 - detected RAM in GB

    # $2 - minimum required RAM in GB

    local detected=$1
    local required=$2

    echo -e "${RED}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${RED}│ INSUFFICIENT RAM                                           │${NC}"
    echo -e "${RED}└────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "Your system has ${RED}${detected}GB${NC} RAM"
    echo -e "Minimum required: ${GREEN}${required}GB${NC} RAM"
    echo ""
    echo "HookProbe Edge requires at least 4GB RAM for:"
    echo "  • Web Server + Database + Cache: ~1.5GB"
    echo "  • Neuro Protocol (Qsecbit + HTP): ~512MB"
    echo "  • Operating System overhead: ~2GB"
    echo ""
    echo "Recommendations:"
    echo "  1. Upgrade to Raspberry Pi 4/5 with 4GB+ RAM"
    echo "  2. Or use x86_64 system with 4GB+ RAM"
    echo "  3. Close other applications to free up memory"
    echo ""
}

# ============================================================
# DISK SPACE WARNING INSTRUCTIONS
# ============================================================

show_low_disk_warning() {
    # Show warning when disk space is below minimum.

    #

    # Args:

    # $1 - detected free space in GB

    # $2 - minimum required space in GB

    local detected=$1
    local required=$2

    echo -e "${RED}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${RED}│ INSUFFICIENT DISK SPACE                                    │${NC}"
    echo -e "${RED}└────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "Free disk space: ${RED}${detected}GB${NC}"
    echo -e "Minimum required: ${GREEN}${required}GB${NC}"
    echo ""
    echo "HookProbe Edge requires disk space for:"
    echo "  • Container images: ~5GB"
    echo "  • Database storage: ~10GB"
    echo "  • Log files: ~3GB"
    echo "  • System overhead: ~2GB"
    echo ""
    echo "Recommendations:"
    echo "  1. Use larger SD card (64GB+ recommended for Raspberry Pi)"
    echo -e "  2. Clean up unnecessary files: ${BLUE}sudo apt clean && sudo apt autoremove${NC}"
    echo "  3. Use external USB storage for data volumes"
    echo ""
}

# ============================================================
# AI ENABLE WARNING
# ============================================================

show_ai_enable_warning() {
    # Show warning when trying to enable AI on low-RAM system.

    #

    # Args:

    # $1 - total RAM in GB

    # $2 - estimated total memory usage in MB

    local ram_gb=$1
    local usage_mb=$2

    echo -e "${YELLOW}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│ AI FEATURES ON LOW-RAM SYSTEM                              │${NC}"
    echo -e "${YELLOW}└────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo "You have enabled ${YELLOW}--enable-ai${NC} on a ${YELLOW}${ram_gb}GB${NC} RAM system"
    echo ""
    echo "Memory usage estimate:"
    echo "  • Core PODs (Web, DB, Cache, Neuro): ~2GB"
    echo "  • AI PODs (Detection + Analysis): ~4GB"
    echo "  • Total: ~$(awk "BEGIN {printf \"%.1f\", $usage_mb/1024}")GB"
    echo ""
    echo -e "${YELLOW}⚠ WARNING:${NC} This may cause:"
    echo "  • Out-of-memory (OOM) errors"
    echo "  • System slowdown / freezing"
    echo "  • Container crashes"
    echo ""
    echo -e "${GREEN}Recommended:${NC} AI features work best with 16GB+ RAM"
    echo ""
    echo "Options:"
    echo "  1. Continue anyway (may be unstable)"
    echo "  2. Cancel and install without AI (stable on 4GB)"
    echo "  3. Upgrade RAM to 8GB+ for better performance"
    echo ""
}

# ============================================================
# POST-INSTALL SUCCESS MESSAGE
# ============================================================

show_success_message() {
    # Show success message after installation.

    #

    # Args:

    # $1 - enable_ai (true/false)

    # $2 - enable_monitoring (true/false)

    local enable_ai=$1
    local enable_monitoring=$2

    echo ""
    echo -e "${GREEN}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${GREEN}│ ✓ HOOKPROBE EDGE NODE INSTALLED SUCCESSFULLY              │${NC}"
    echo -e "${GREEN}└────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "${CYAN}Configuration Summary:${NC}"
    echo "  Platform:    $PLATFORM_ARCH on $PLATFORM_OS"
    echo "  RAM:         ${TOTAL_RAM_GB}GB (Profile: $MEMORY_PROFILE)"
    echo "  CPU Cores:   $CPU_CORES"
    echo ""
    echo -e "${CYAN}Installed Components:${NC}"
    echo "  ${GREEN}✓${NC} POD-001: Web Server (Django + Nginx + NAXSI WAF)"
    echo "  ${GREEN}✓${NC} POD-002: IAM (Logto authentication)"
    echo "  ${GREEN}✓${NC} POD-003: Database (PostgreSQL 16)"
    echo "  ${GREEN}✓${NC} POD-005: Cache (Redis 7)"
    echo "  ${GREEN}✓${NC} POD-010: Neuro Protocol (Qsecbit + HTP)"

    if [ "$enable_ai" = true ]; then
        echo "  ${GREEN}✓${NC} POD-006: Detection (Suricata, Zeek, Snort)"
        echo "  ${GREEN}✓${NC} POD-007: AI Analysis (Machine Learning)"
    fi

    if [ "$enable_monitoring" = true ]; then
        echo "  ${GREEN}✓${NC} POD-004: Monitoring (Grafana, VictoriaMetrics)"
    fi

    echo ""
    echo -e "${CYAN}Security Features:${NC}"
    echo "  ${GREEN}✓${NC} Qsecbit:     Enabled (quantum-resistant crypto)"
    echo "  ${GREEN}✓${NC} HTP:         Enabled (adaptive transport)"
    echo "  ${GREEN}✓${NC} P2 Adaptive: RTT, bandwidth, stress monitoring"
    echo "  $([ "$enable_ai" = true ] && echo "${GREEN}✓${NC} AI Detection: Enabled" || echo "${YELLOW}✗${NC} AI Detection: Disabled (use --enable-ai)")"
    echo ""

    echo -e "${CYAN}Next Steps:${NC}"
    echo ""
    echo "  1. Check POD status:"
    echo -e "     ${BLUE}podman pod ls${NC}"
    echo ""
    echo "  2. View container logs:"
    echo -e "     ${BLUE}podman logs -f hookprobe-web-django${NC}"
    echo ""
    echo "  3. Access web interface:"
    echo -e "     ${BLUE}http://localhost${NC} or ${BLUE}http://$(hostname -I | awk '{print $1}')${NC}"
    echo ""
    echo "  4. Check Qsecbit status:"
    echo -e "     ${BLUE}podman logs -f hookprobe-neuro-qsecbit${NC}"
    echo ""

    if [ "$enable_ai" = false ]; then
        echo -e "${YELLOW}To enable AI later:${NC}"
        echo -e "  ${BLUE}sudo bash $(readlink -f "$0") --enable-ai${NC}"
        echo ""
    fi

    if [ "$enable_monitoring" = false ]; then
        echo -e "${YELLOW}To enable monitoring later:${NC}"
        echo -e "  ${BLUE}sudo bash $(readlink -f "$0") --enable-monitoring${NC}"
        echo ""
    fi

    echo -e "${CYAN}────────────────────────────────────────────────────────────${NC}"
    echo ""
    echo -e "${GREEN}HookProbe Edge is now protecting your network!${NC}"
    echo ""
}

# ============================================================
# QUICK REFERENCE
# ============================================================

show_quick_reference() {
    # Show quick reference card for HookProbe commands.

    echo -e "${CYAN}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│ HOOKPROBE QUICK REFERENCE                                  │${NC}"
    echo -e "${CYAN}└────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "${YELLOW}Container Management:${NC}"
    echo -e "  ${BLUE}podman pod ls${NC}                    # List all PODs"
    echo -e "  ${BLUE}podman ps${NC}                        # List all containers"
    echo -e "  ${BLUE}podman logs -f <container>${NC}       # View container logs"
    echo -e "  ${BLUE}podman pod restart <pod>${NC}         # Restart a POD"
    echo ""
    echo -e "${YELLOW}System Status:${NC}"
    echo -e "  ${BLUE}systemctl status hookprobe-edge${NC}  # Check edge service"
    echo -e "  ${BLUE}free -h${NC}                          # Check RAM usage"
    echo -e "  ${BLUE}df -h${NC}                            # Check disk usage"
    echo ""
    echo -e "${YELLOW}Neuro Protocol (Qsecbit + HTP):${NC}"
    echo -e "  ${BLUE}podman logs -f hookprobe-neuro-qsecbit${NC}  # Qsecbit logs"
    echo -e "  ${BLUE}podman logs -f hookprobe-neuro-htp${NC}      # HTP transport logs"
    echo ""
    echo -e "${YELLOW}Troubleshooting:${NC}"
    echo -e "  ${BLUE}podman pod stop <pod>${NC}            # Stop a POD"
    echo -e "  ${BLUE}podman pod rm <pod>${NC}              # Remove a POD"
    echo -e "  ${BLUE}journalctl -xe${NC}                   # System logs"
    echo ""
}
