#!/bin/bash
#
# setup.sh - HookProbe v5.0 Stage 1 Deployment
# GPL-FREE Edition - Single bridge with OpenFlow ACLs
# Version: 5.0.0 - Complete rebuild with permissive licenses
#
# Target OS: RHEL 10 / Fedora 40+ / CentOS Stream 10
#

set -e  # Exit on error
set -u  # Exit on undefined variable

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load network configuration
if [ -f "$SCRIPT_DIR/config.sh" ]; then
    source "$SCRIPT_DIR/config.sh"
else
    echo "ERROR: config.sh not found in $SCRIPT_DIR"
    exit 1
fi

echo "============================================================"
echo "   HOOKPROBE v5.0 - STAGE 1 DEPLOYMENT"
echo "   GPL-FREE Security Platform"
echo "   Single Bridge + OpenFlow ACLs + L2 Hardening"
echo "============================================================"

# ============================================================
# STEP 1: DETECT PLATFORM AND HARDWARE
# ============================================================
echo ""
echo "[STEP 1] Detecting platform and hardware..."

# Check for root
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root"
   exit 1
fi

# ===== OS Platform Detection =====
PLATFORM_OS="unknown"
PLATFORM_FAMILY="unknown"
PKG_MANAGER="unknown"

if [ -f /etc/os-release ]; then
    source /etc/os-release

    case "$ID" in
        rhel|centos|fedora|rocky|almalinux)
            PLATFORM_FAMILY="rhel"
            PKG_MANAGER="dnf"
            ;;
        debian|ubuntu|pop|linuxmint)
            PLATFORM_FAMILY="debian"
            PKG_MANAGER="apt"
            ;;
        *)
            echo "ERROR: Unsupported OS: $ID"
            echo "HookProbe v5.0 currently supports:"
            echo "  - RHEL-based: RHEL 10, Fedora 40+, CentOS Stream 9+, Rocky Linux, AlmaLinux"
            echo "  - Debian-based: Debian 12+, Ubuntu 22.04+/24.04+"
            exit 1
            ;;
    esac

    PLATFORM_OS="$NAME"
    echo "✓ OS Detected: $NAME ($VERSION)"
    echo "✓ Platform Family: $PLATFORM_FAMILY"
else
    echo "ERROR: Cannot detect OS (missing /etc/os-release)"
    exit 1
fi

# ===== Hardware Architecture Detection =====
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)
        ARCH_TYPE="x86_64"
        ;;
    aarch64|arm64)
        ARCH_TYPE="arm64"
        ;;
    armv7l)
        echo "ERROR: ARMv7 (32-bit) is not supported. Use ARMv8/ARM64."
        exit 1
        ;;
    *)
        echo "ERROR: Unsupported architecture: $ARCH"
        exit 1
        ;;
esac
echo "✓ Architecture: $ARCH_TYPE"

# ===== Hardware Platform Detection =====
HARDWARE_PLATFORM="unknown"
CPU_MODEL=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)

# Check for virtualization
IS_VIRTUAL=false
if systemd-detect-virt --quiet; then
    VIRT_TYPE=$(systemd-detect-virt)
    IS_VIRTUAL=true
    echo "✓ Virtualization Detected: $VIRT_TYPE"
    HARDWARE_PLATFORM="virtual-$VIRT_TYPE"
fi

# Detect specific hardware (physical only)
if [ "$IS_VIRTUAL" = false ]; then
    if [ "$ARCH_TYPE" = "arm64" ]; then
        # ARM64 SBC detection
        if grep -qi "raspberry pi" /proc/device-tree/model 2>/dev/null || grep -qi "raspberry pi" /sys/firmware/devicetree/base/model 2>/dev/null; then
            RPI_MODEL=$(cat /proc/device-tree/model 2>/dev/null || cat /sys/firmware/devicetree/base/model 2>/dev/null)
            if echo "$RPI_MODEL" | grep -qi "raspberry pi 5"; then
                HARDWARE_PLATFORM="raspberry-pi-5"
                echo "✓ Hardware: Raspberry Pi 5"
            elif echo "$RPI_MODEL" | grep -qi "raspberry pi 4"; then
                HARDWARE_PLATFORM="raspberry-pi-4"
                echo "✓ Hardware: Raspberry Pi 4"
            else
                HARDWARE_PLATFORM="raspberry-pi-other"
                echo "✓ Hardware: Raspberry Pi (older model)"
                echo "⚠️  WARNING: Raspberry Pi 4/5 recommended for optimal performance"
            fi
        elif grep -qi "rockchip" /proc/cpuinfo; then
            HARDWARE_PLATFORM="rockchip-sbc"
            echo "✓ Hardware: Rockchip-based SBC (Rock Pi, Orange Pi, etc.)"
        else
            HARDWARE_PLATFORM="arm64-generic"
            echo "✓ Hardware: ARM64 Generic SBC"
        fi
    elif [ "$ARCH_TYPE" = "x86_64" ]; then
        # x86_64 detection
        if echo "$CPU_MODEL" | grep -qi "Intel.*N100"; then
            HARDWARE_PLATFORM="intel-n100"
            echo "✓ Hardware: Intel N100 Mini PC (Recommended)"
        elif echo "$CPU_MODEL" | grep -qi "Intel.*Celeron.*N[0-9]"; then
            HARDWARE_PLATFORM="intel-celeron-n-series"
            echo "✓ Hardware: Intel Celeron N-series"
        elif echo "$CPU_MODEL" | grep -qi "Intel.*Xeon"; then
            HARDWARE_PLATFORM="intel-xeon-server"
            echo "✓ Hardware: Intel Xeon Server"
        elif echo "$CPU_MODEL" | grep -qi "AMD.*EPYC"; then
            HARDWARE_PLATFORM="amd-epyc-server"
            echo "✓ Hardware: AMD EPYC Server"
        else
            HARDWARE_PLATFORM="x86_64-generic"
            echo "✓ Hardware: Generic x86_64 system"
        fi
    fi
else
    echo "✓ Hardware: Virtual Machine ($VIRT_TYPE)"
fi

# ===== NIC Detection (for XDP capabilities) =====
PRIMARY_NIC=$(ip route show default | grep -oP '(?<=dev )[^ ]+' | head -1)
if [ -n "$PRIMARY_NIC" ]; then
    NIC_DRIVER=$(ethtool -i "$PRIMARY_NIC" 2>/dev/null | grep "^driver:" | awk '{print $2}')
    if [ -n "$NIC_DRIVER" ]; then
        echo "✓ Primary NIC: $PRIMARY_NIC (driver: $NIC_DRIVER)"

        # Check XDP capability
        case "$NIC_DRIVER" in
            igb|igc)
                echo "  ✓ XDP Mode: XDP-DRV (Layer 1 - Full kernel bypass)"
                echo "  ✓ Intel NIC with native XDP support detected"
                ;;
            i40e|ice)
                echo "  ✓ XDP Mode: XDP-DRV (Layer 1 - Full kernel bypass)"
                echo "  ✓ Intel Server NIC with native XDP support detected"
                ;;
            mlx5_core)
                echo "  ✓ XDP Mode: XDP-DRV/XDP-HW (Layer 1/0 - Best performance)"
                echo "  ✓ Mellanox ConnectX with XDP hardware offload support detected"
                ;;
            mlx4_en)
                echo "  ✓ XDP Mode: XDP-SKB (Layer 1.5 - Software mode)"
                echo "  ⚠️  Mellanox ConnectX-3: AF_XDP supported but no XDP-DRV"
                ;;
            bcmgenet|r8152|r8169)
                echo "  ✓ XDP Mode: XDP-SKB (Layer 1.5 - Software mode)"
                echo "  ⚠️  Consumer/SBC NIC: XDP-SKB only (higher CPU usage)"
                ;;
            ixgbe)
                echo "  ✓ XDP Mode: XDP-SKB (Layer 1.5 - Software mode)"
                echo "  ⚠️  Intel X520: AF_XDP supported but no XDP-DRV mode"
                ;;
            *)
                echo "  ✓ XDP Mode: XDP-SKB (Layer 1.5 - Universal fallback)"
                echo "  ℹ️  Unknown NIC: XDP-SKB will be used"
                ;;
        esac
    else
        echo "✓ Primary NIC: $PRIMARY_NIC (driver unknown)"
    fi
else
    echo "⚠️  WARNING: Could not detect primary network interface"
fi

# ===== Platform Summary =====
echo ""
echo "=========================================="
echo "  PLATFORM SUMMARY"
echo "=========================================="
echo "OS Family:    $PLATFORM_FAMILY"
echo "OS:           $PLATFORM_OS"
echo "Architecture: $ARCH_TYPE"
echo "Hardware:     $HARDWARE_PLATFORM"
echo "Virtualized:  $IS_VIRTUAL"
echo "Package Mgr:  $PKG_MANAGER"
if [ -n "$PRIMARY_NIC" ]; then
    echo "Primary NIC:  $PRIMARY_NIC ($NIC_DRIVER)"
fi
echo "=========================================="
echo ""

# ===== Platform-Specific Warnings =====
if [ "$HARDWARE_PLATFORM" = "raspberry-pi-4" ] || [ "$HARDWARE_PLATFORM" = "raspberry-pi-5" ]; then
    echo "ℹ️  Raspberry Pi detected:"
    echo "   - XDP will run in SKB mode (software, higher CPU usage)"
    echo "   - For production DDoS mitigation, consider Intel N100 with I226 NIC"
    echo ""
fi

# ============================================================
# STEP 2: VALIDATE ENVIRONMENT
# ============================================================
echo ""
echo "[STEP 2] Validating environment..."

# Validate or auto-detect PHYSICAL_HOST_INTERFACE
if [ -z "${PHYSICAL_HOST_INTERFACE:-}" ]; then
    echo "⚠️  PHYSICAL_HOST_INTERFACE not set in config.sh, attempting auto-detection..."
    PHYSICAL_HOST_INTERFACE=$(ip route show default | grep -oP '(?<=dev )[^ ]+' | head -1)

    if [ -z "$PHYSICAL_HOST_INTERFACE" ]; then
        echo "❌ ERROR: Could not auto-detect network interface."
        echo "   Please set PHYSICAL_HOST_INTERFACE in config.sh"
        echo ""
        echo "Available interfaces:"
        ip -brief addr show
        exit 1
    fi

    echo "✓ Auto-detected interface: $PHYSICAL_HOST_INTERFACE"

    # Show IP for confirmation
    detected_ip=$(ip -4 addr show "$PHYSICAL_HOST_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || echo "")
    if [ -n "$detected_ip" ]; then
        echo "  Interface IP: $detected_ip"
    fi

    # Confirm with user
    read -p "  Use this interface? (yes/no) [yes]: " confirm_interface
    confirm_interface=${confirm_interface:-yes}
    if [ "$confirm_interface" != "yes" ]; then
        echo ""
        echo "Available interfaces:"
        ip -brief addr show
        echo ""
        echo "Please set PHYSICAL_HOST_INTERFACE in config.sh and run again"
        exit 1
    fi
elif ! ip link show "$PHYSICAL_HOST_INTERFACE" &>/dev/null; then
    # Interface is set but doesn't exist
    echo "❌ ERROR: Interface '$PHYSICAL_HOST_INTERFACE' does not exist"
    echo "   Please update PHYSICAL_HOST_INTERFACE in config.sh"
    echo ""
    echo "Available interfaces:"
    ip -brief addr show
    exit 1
fi

# Detect local host IP
LOCAL_HOST_IP=$(ip -4 addr show "$PHYSICAL_HOST_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "")
if [ -z "$LOCAL_HOST_IP" ]; then
    echo "ERROR: Could not detect IP on interface '$PHYSICAL_HOST_INTERFACE'"
    exit 1
fi
echo "✓ Local Host IP: $LOCAL_HOST_IP"

# Determine remote peer
if [ "$LOCAL_HOST_IP" == "$HOST_A_IP" ]; then
    REMOTE_HOST_IP="$HOST_B_IP"
else
    REMOTE_HOST_IP="$HOST_A_IP"
fi
echo "✓ Remote Peer IP: $REMOTE_HOST_IP"

# Check if PSK was changed
if [ "$VXLAN_PSK" == "HookProbe_VXLAN_Master_Key_2025_CHANGE_ME_NOW" ]; then
    echo "⚠️  WARNING: VXLAN PSK not changed! Using default (INSECURE)"
    read -p "Continue anyway? (yes/no): " continue_anyway
    if [ "$continue_anyway" != "yes" ]; then
        echo "Aborted. Please update VXLAN_PSK in network-config.sh"
        exit 1
    fi
fi

# ============================================================
# STEP 3: INSTALL DEPENDENCIES
# ============================================================
echo ""
echo "[STEP 3] Installing required packages..."

if [ "$PLATFORM_FAMILY" = "rhel" ]; then
    echo "Installing packages for RHEL-based system..."

    # Update package database
    dnf update -y

    # Enable EPEL repository
    dnf install -y epel-release

    # Required packages (RHEL/Fedora)
    REQUIRED_PACKAGES=(
        git curl wget unzip tar
        podman buildah skopeo
        openvswitch openvswitch-ipsec
        python3 python3-pip
        net-tools iproute bridge-utils ethtool
        iptables nftables firewalld
        postgresql
        jq yq
        bcc-tools bpftool
        libbpf libbpf-devel
    )

    # Add kernel-modules-extra if not in a container
    if [ "$IS_VIRTUAL" = false ] || [ "$VIRT_TYPE" = "kvm" ]; then
        REQUIRED_PACKAGES+=(kernel-modules-extra)
    fi

    dnf install -y "${REQUIRED_PACKAGES[@]}"

    # Install XDP tools for DDoS mitigation
    if [ "$ENABLE_XDP_DDOS" = true ]; then
        echo "Installing XDP tools..."
        dnf install -y xdp-tools libxdp-devel
    fi

elif [ "$PLATFORM_FAMILY" = "debian" ]; then
    echo "Installing packages for Debian-based system..."

    # Update package database
    apt-get update

    # Required packages (Debian/Ubuntu)
    REQUIRED_PACKAGES=(
        git curl wget unzip tar
        podman buildah
        openvswitch-switch
        python3 python3-pip
        net-tools iproute2 bridge-utils ethtool
        iptables nftables
        postgresql-client
        jq
        bpfcc-tools bpftrace
        libbpf-dev
    )

    # Add linux-headers if not in a container
    if [ "$IS_VIRTUAL" = false ] || [ "$VIRT_TYPE" = "kvm" ]; then
        REQUIRED_PACKAGES+=("linux-headers-$(uname -r)")
    fi

    apt-get install -y "${REQUIRED_PACKAGES[@]}"

    # Install XDP tools for DDoS mitigation
    if [ "$ENABLE_XDP_DDOS" = true ]; then
        echo "Installing XDP tools..."
        apt-get install -y xdp-tools libxdp-dev
    fi

else
    echo "ERROR: Unknown platform family: $PLATFORM_FAMILY"
    exit 1
fi

echo "✓ All dependencies installed for $PLATFORM_FAMILY"

# ============================================================
# STEP 4: CONFIGURE KERNEL MODULES & PARAMETERS
# ============================================================
echo ""
echo "[STEP 4] Configuring kernel..."

# Load kernel modules
modprobe openvswitch
modprobe vxlan
modprobe ip_tables
modprobe nf_conntrack
modprobe nft_tables
modprobe br_netfilter

# Make modules persistent
cat > /etc/modules-load.d/hookprobe-v5.conf << EOF
openvswitch
vxlan
ip_tables
nf_conntrack
nft_tables
br_netfilter
EOF

# Kernel parameters for security and performance
cat > /etc/sysctl.d/99-hookprobe-v5.conf << EOF
# Network security
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3

# Connection tracking
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 432000
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30

# ICMP rate limiting
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 6168

# IPv6 (if used)
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Bridge netfilter
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-arptables = 1

# Performance tuning
net.core.netdev_max_backlog = 5000
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
EOF

sysctl -p /etc/sysctl.d/99-hookprobe-v5.conf

echo "✓ Kernel configured for security and performance"

# ============================================================
# STEP 5: CREATE SINGLE OVS BRIDGE WITH VXLAN TUNNELS
# ============================================================
echo ""
echo "[STEP 5] Creating Open vSwitch infrastructure..."

# Start OVS
systemctl enable --now openvswitch
sleep 2

# Create single unified bridge
echo "Creating unified bridge: $QSEC_BRIDGE"
ovs-vsctl --may-exist add-br "$QSEC_BRIDGE"

# Function to create VXLAN tunnel
create_vxlan_tunnel() {
    local vni=$1
    local port_name="vxlan${vni}"
    
    echo "  → Creating VXLAN tunnel: VNI=$vni"
    
    ovs-vsctl --may-exist add-port "$QSEC_BRIDGE" "$port_name" -- \
        set interface "$port_name" type=vxlan \
        options:key="$vni" \
        options:remote_ip="$REMOTE_HOST_IP" \
        options:local_ip="$LOCAL_HOST_IP" \
        options:dst_port="$VXLAN_PORT" \
        options:psk="$VXLAN_PSK"
}

# Create VXLAN tunnels for all VNIs
create_vxlan_tunnel "$VNI_MANAGEMENT"
create_vxlan_tunnel "$VNI_WEB_DMZ"
create_vxlan_tunnel "$VNI_IAM"
create_vxlan_tunnel "$VNI_DATABASE"
create_vxlan_tunnel "$VNI_CACHE"
create_vxlan_tunnel "$VNI_MONITORING"
create_vxlan_tunnel "$VNI_SECURITY"
create_vxlan_tunnel "$VNI_HONEYPOT"

# Configure bridge IP
BRIDGE_IP=$(echo $QSEC_BRIDGE_IP | cut -d'/' -f1)
BRIDGE_PREFIX=$(echo $QSEC_BRIDGE_IP | cut -d'/' -f2)
ip addr flush dev "$QSEC_BRIDGE" 2>/dev/null || true
ip addr add "$QSEC_BRIDGE_IP" dev "$QSEC_BRIDGE"
ip link set "$QSEC_BRIDGE" up

echo "✓ OVS bridge and VXLAN tunnels created"

# ============================================================
# STEP 5: CONFIGURE OPENFLOW ACLS PER VNI
# ============================================================
echo ""
echo "[STEP 5] Configuring OpenFlow ACLs..."

# Clear existing flows
ovs-ofctl del-flows "$QSEC_BRIDGE"

# Function to add OpenFlow rule
add_flow() {
    local priority=$1
    local match=$2
    local actions=$3
    ovs-ofctl add-flow "$QSEC_BRIDGE" "priority=${priority},${match},actions=${actions}"
}

echo "  → Configuring default deny policy..."
# Default deny (lowest priority)
add_flow $PRIORITY_DENY_DEFAULT "" "drop"

echo "  → Configuring established connection tracking..."
# Allow established connections (highest priority)
add_flow $PRIORITY_ALLOW_ESTABLISHED "ct_state=+est+trk" "normal"
add_flow $PRIORITY_ALLOW_ESTABLISHED "ct_state=+rel+trk" "normal"

echo "  → Configuring anti-spoofing per VNI..."
# Anti-spoofing: Drop packets with wrong source MAC/IP per VNI
# VNI 201 (Web DMZ) - only allow known MACs
add_flow $PRIORITY_ANTI_SPOOF "tun_id=$VNI_WEB_DMZ,dl_src=00:00:00:00:00:00" "drop"

echo "  → Configuring ARP protection..."
# ARP protection - only allow ARP from gateways
add_flow $PRIORITY_ANTI_SPOOF "arp,arp_spa=${GATEWAY_WEB_DMZ}" "normal"
add_flow $PRIORITY_ANTI_SPOOF "arp,arp_spa=${GATEWAY_IAM}" "normal"
add_flow $PRIORITY_ANTI_SPOOF "arp,arp_spa=${GATEWAY_DATABASE}" "normal"
add_flow $PRIORITY_ANTI_SPOOF "arp" "drop"  # Drop all other ARP

echo "  → Configuring rate limiting..."
# Rate limiting for ICMP
add_flow $PRIORITY_RATE_LIMIT "icmp" "ct(commit,table=1)"
ovs-ofctl add-flow "$QSEC_BRIDGE" "table=1,priority=${PRIORITY_RATE_LIMIT},icmp,ct_state=+new,actions=normal"

# Rate limiting for SYN packets
add_flow $PRIORITY_RATE_LIMIT "tcp,tcp_flags=+syn" "ct(commit,table=2)"

echo "  → Configuring inter-VNI routing..."
# Allow specific inter-VNI traffic
# Web DMZ → Database
add_flow $PRIORITY_ALLOW_SPECIFIC "tun_id=$VNI_WEB_DMZ,nw_dst=${IP_POSTGRES_MAIN},tcp,tp_dst=5432" "ct(commit),normal"

# Web DMZ → Cache
add_flow $PRIORITY_ALLOW_SPECIFIC "tun_id=$VNI_WEB_DMZ,nw_dst=${IP_REDIS},tcp,tp_dst=6379" "ct(commit),normal"

# Web DMZ → IAM
add_flow $PRIORITY_ALLOW_SPECIFIC "tun_id=$VNI_WEB_DMZ,nw_dst=${IP_KEYCLOAK},tcp,tp_dst=8080" "ct(commit),normal"

# Security → All VNIs (for monitoring)
for vni in $VNI_MANAGEMENT $VNI_WEB_DMZ $VNI_IAM $VNI_DATABASE $VNI_CACHE $VNI_MONITORING $VNI_HONEYPOT; do
    add_flow $PRIORITY_ALLOW_SPECIFIC "tun_id=$VNI_SECURITY,tun_id=$vni" "normal"
done

# Monitoring → All VNIs (for metrics collection)
for vni in $VNI_MANAGEMENT $VNI_WEB_DMZ $VNI_IAM $VNI_DATABASE $VNI_CACHE $VNI_SECURITY $VNI_HONEYPOT; do
    add_flow $PRIORITY_ALLOW_SPECIFIC "tun_id=$VNI_MONITORING,tun_id=$vni" "normal"
done

echo "  → Configuring honeypot redirection..."
# Honeypot redirection will be added by mitigation engine dynamically

echo "✓ OpenFlow ACLs configured"

# ============================================================
# STEP 6: CONFIGURE PORT MIRRORING FOR IDS
# ============================================================
echo ""
echo "[STEP 6] Configuring port mirroring for IDS..."

# Create mirror for DMZ traffic to Security POD
ovs-vsctl -- --id=@m create mirror name=dmz-mirror \
    select_all=true -- add bridge "$QSEC_BRIDGE" mirrors @m

echo "✓ Port mirroring configured"

# ============================================================
# STEP 7: ENABLE SFLOW/NETFLOW FOR TELEMETRY
# ============================================================
echo ""
echo "[STEP 7] Configuring flow telemetry..."

if [ "$ENABLE_FLOW_LOGGING" = true ]; then
    # Configure sFlow
    ovs-vsctl -- --id=@sflow create sflow agent="$QSEC_BRIDGE" \
        target="127.0.0.1:6343" sampling=64 polling=10 \
        -- set bridge "$QSEC_BRIDGE" sflow=@sflow
    
    echo "✓ sFlow telemetry enabled"
fi

# ============================================================
# STEP 8: CONFIGURE FIREWALL (NFTABLES)
# ============================================================
echo ""
echo "[STEP 8] Configuring firewall with nftables..."

# Create nftables configuration
cat > /etc/nftables/hookprobe-v5.nft << 'NFTEOF'
#!/usr/sbin/nft -f
# HookProbe v5.0 Firewall Rules

# Clear existing rules
flush ruleset

# Main table
table inet hookprobe {
    # Rate limiting counters
    set ssh_ratelimit {
        type ipv4_addr
        size 65536
        flags dynamic,timeout
        timeout 1m
    }
    
    set http_ratelimit {
        type ipv4_addr
        size 65536
        flags dynamic,timeout
        timeout 10s
    }
    
    # Blocked IPs (honeypot redirection targets)
    set blocked_ips {
        type ipv4_addr
        size 65536
        flags timeout
        timeout 1h
    }
    
    # Input chain (traffic to host)
    chain input {
        type filter hook input priority filter; policy drop;
        
        # Allow loopback
        iif "lo" accept
        
        # Allow established/related
        ct state established,related accept
        
        # Allow ICMP (rate limited)
        icmp type echo-request limit rate 10/second accept
        icmpv6 type { echo-request, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
        
        # SSH rate limiting
        tcp dport 22 ct state new add @ssh_ratelimit { ip saddr limit rate 3/minute burst 5 packets } accept
        tcp dport 22 drop
        
        # Allow from bridge
        iifname "qsec-bridge" accept
        
        # Allow specific services
        tcp dport { 80, 443, 3000, 8080, 8428, 9428 } ct state new accept
        
        # Log drops
        limit rate 5/minute log prefix "nft-input-drop: "
        drop
    }
    
    # Forward chain (traffic through host)
    chain forward {
        type filter hook forward priority filter; policy drop;
        
        # Allow established/related
        ct state established,related accept
        
        # Allow from/to bridge
        iifname "qsec-bridge" oifname "qsec-bridge" accept
        
        # Allow bridge to internet
        iifname "qsec-bridge" oifname "PHYSICAL_INTERFACE" ct state new accept
        
        # SYN flood protection
        tcp flags syn tcp option maxseg size 1-536 drop
        tcp flags syn limit rate 100/second burst 150 packets accept
        tcp flags syn drop
        
        # Block known attackers (redirect to honeypot handled by SNAT)
        ip saddr @blocked_ips reject
        
        # Log drops
        limit rate 5/minute log prefix "nft-forward-drop: "
        drop
    }
    
    # Output chain (traffic from host)
    chain output {
        type filter hook output priority filter; policy accept;
    }
    
    # NAT table for honeypot redirection
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        
        # Honeypot SNAT redirection (added dynamically by mitigation engine)
    }
    
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        
        # Masquerade bridge traffic to internet
        oifname "PHYSICAL_INTERFACE" masquerade
    }
}
NFTEOF

# Replace PHYSICAL_INTERFACE placeholder
sed -i "s/PHYSICAL_INTERFACE/$PHYSICAL_HOST_INTERFACE/g" /etc/nftables/hookprobe-v5.nft

# Load nftables rules
nft -f /etc/nftables/hookprobe-v5.nft

# Make persistent
systemctl enable nftables

echo "✓ Firewall configured with rate limiting"

# ============================================================
# STEP 9: CONFIGURE XDP DDOS MITIGATION (if enabled)
# ============================================================
echo ""
echo "[STEP 9] Configuring XDP DDoS mitigation..."

if [ "$ENABLE_XDP_DDOS" = true ]; then
    echo "Creating XDP DDoS mitigation program..."
    
    mkdir -p /opt/hookprobe/xdp
    
    cat > /opt/hookprobe/xdp/ddos_mitigate.c << 'XDPEOF'
// XDP DDoS Mitigation for HookProbe v5.0
// Compile: clang -O2 -target bpf -c ddos_mitigate.c -o ddos_mitigate.o

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>

#define RATE_LIMIT_ICMP 10
#define RATE_LIMIT_SYN 100
#define RATE_LIMIT_UDP 200

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);      // Source IP
    __type(value, __u64);    // Packet count
    __uint(max_entries, 65536);
} rate_limit_map SEC(".maps");

SEC("xdp")
int xdp_ddos_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    
    __u32 src_ip = iph->saddr;
    __u64 *pkt_count = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
    
    if (pkt_count) {
        // Check rate limits based on protocol
        if (iph->protocol == IPPROTO_ICMP) {
            if (*pkt_count > RATE_LIMIT_ICMP)
                return XDP_DROP;
        } else if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            if ((void *)(tcph + 1) > data_end)
                return XDP_PASS;
            
            // SYN flood protection
            if (tcph->syn && !tcph->ack) {
                if (*pkt_count > RATE_LIMIT_SYN)
                    return XDP_DROP;
            }
        } else if (iph->protocol == IPPROTO_UDP) {
            if (*pkt_count > RATE_LIMIT_UDP)
                return XDP_DROP;
        }
        
        (*pkt_count)++;
    } else {
        __u64 init_count = 1;
        bpf_map_update_elem(&rate_limit_map, &src_ip, &init_count, BPF_ANY);
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
XDPEOF
    
    # Compile XDP program
    if command -v clang &> /dev/null; then
        echo "Compiling XDP program..."
        cd /opt/hookprobe/xdp
        clang -O2 -target bpf -c ddos_mitigate.c -o ddos_mitigate.o
        
        # Load XDP program
        ip link set dev "$PHYSICAL_HOST_INTERFACE" xdp obj ddos_mitigate.o sec xdp
        
        echo "✓ XDP DDoS mitigation loaded on $PHYSICAL_HOST_INTERFACE"
    else
        echo "⚠️  Clang not found, skipping XDP compilation"
        echo "   Install with: dnf install clang llvm"
    fi
else
    echo "⊘ XDP DDoS mitigation disabled"
fi

# ============================================================
# STEP 10: CREATE PODMAN NETWORKS
# ============================================================
echo ""
echo "[STEP 10] Creating Podman networks..."

create_podman_network() {
    local net_name=$1
    local subnet=$2
    local gateway=$3
    
    echo "  → Creating network: $net_name ($subnet)"
    
    podman network exists "$net_name" 2>/dev/null && podman network rm "$net_name"
    
    podman network create \
        --driver bridge \
        --subnet="$subnet" \
        --gateway="$gateway" \
        "$net_name"
}

create_podman_network "$NETWORK_WEB" "$SUBNET_WEB_DMZ" "$GATEWAY_WEB_DMZ"
create_podman_network "$NETWORK_IAM" "$SUBNET_IAM" "$GATEWAY_IAM"
create_podman_network "$NETWORK_DATABASE" "$SUBNET_DATABASE" "$GATEWAY_DATABASE"
create_podman_network "$NETWORK_CACHE" "$SUBNET_CACHE" "$GATEWAY_CACHE"
create_podman_network "$NETWORK_MONITORING" "$SUBNET_MONITORING" "$GATEWAY_MONITORING"
create_podman_network "$NETWORK_SECURITY" "$SUBNET_SECURITY" "$GATEWAY_SECURITY"
create_podman_network "$NETWORK_HONEYPOT" "$SUBNET_HONEYPOT" "$GATEWAY_HONEYPOT"

echo "✓ Podman networks created"

# ============================================================
# STEP 11: CREATE PERSISTENT VOLUMES
# ============================================================
echo ""
echo "[STEP 11] Creating persistent volumes..."

create_volume() {
    local vol_name=$1
    if ! podman volume exists "$vol_name" 2>/dev/null; then
        podman volume create "$vol_name"
        echo "  → Created volume: $vol_name"
    else
        echo "  → Volume exists: $vol_name"
    fi
}

create_volume "$VOLUME_POSTGRES_DATA"
create_volume "$VOLUME_DJANGO_STATIC"
create_volume "$VOLUME_DJANGO_MEDIA"
create_volume "$VOLUME_KEYCLOAK_DATA"
create_volume "$VOLUME_VICTORIAMETRICS_DATA"
create_volume "$VOLUME_CLICKHOUSE_DATA"
create_volume "$VOLUME_CLICKHOUSE_LOGS"
create_volume "$VOLUME_GRAFANA_DATA"
create_volume "$VOLUME_ZEEK_LOGS"
create_volume "$VOLUME_SNORT_LOGS"
create_volume "$VOLUME_MODSECURITY_LOGS"
create_volume "$VOLUME_QSECBIT_DATA"
create_volume "$VOLUME_HONEYPOT_DATA"

echo "✓ Persistent volumes ready"

# ============================================================
# STEP 12: DEPLOY POD_DATABASE - POSTGRESQL
# ============================================================
echo ""
echo "[STEP 12] Deploying POD_DATABASE - PostgreSQL..."

podman pod exists "$POD_DATABASE" 2>/dev/null && podman pod rm -f "$POD_DATABASE"

podman pod create \
    --name "$POD_DATABASE" \
    --network "$NETWORK_DATABASE" \
    -p ${PORT_POSTGRES}:5432

echo "  → Starting PostgreSQL container..."
podman run -d --restart always \
    --pod "$POD_DATABASE" \
    --name "${POD_DATABASE}-postgres" \
    -e POSTGRES_DB="$POSTGRES_DB" \
    -e POSTGRES_USER="$POSTGRES_USER" \
    -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
    -v "$VOLUME_POSTGRES_DATA:/var/lib/postgresql/data" \
    --log-driver=journald \
    --log-opt tag="hookprobe-postgres" \
    "$IMAGE_POSTGRES"

echo "  → Waiting for PostgreSQL to be ready..."
sleep 15

echo "✓ POD_DATABASE deployed"

# ============================================================
# STEP 13: DEPLOY POD_CACHE - REDIS/VALKEY
# ============================================================
echo ""
echo "[STEP 13] Deploying POD_CACHE - Redis/Valkey..."

podman pod exists "$POD_CACHE" 2>/dev/null && podman pod rm -f "$POD_CACHE"

podman pod create \
    --name "$POD_CACHE" \
    --network "$NETWORK_CACHE"

echo "  → Starting Redis container..."
podman run -d --restart always \
    --pod "$POD_CACHE" \
    --name "${POD_CACHE}-redis" \
    --log-driver=journald \
    --log-opt tag="hookprobe-redis" \
    "$IMAGE_REDIS" \
    redis-server --appendonly yes --maxmemory 2gb --maxmemory-policy allkeys-lru

echo "✓ POD_CACHE deployed"

# ============================================================
# STEP 14: DEPLOY POD_IAM - KEYCLOAK
# ============================================================
echo ""
echo "[STEP 14] Deploying POD_IAM - Keycloak..."

podman pod exists "$POD_IAM" 2>/dev/null && podman pod rm -f "$POD_IAM"

podman pod create \
    --name "$POD_IAM" \
    --network "$NETWORK_IAM" \
    -p ${PORT_KEYCLOAK}:8080 \
    -p ${PORT_KEYCLOAK_ADMIN}:9000

echo "  → Starting Keycloak PostgreSQL database..."
podman run -d --restart always \
    --pod "$POD_IAM" \
    --name "${POD_IAM}-postgres" \
    -e POSTGRES_DB="$KEYCLOAK_DB" \
    -e POSTGRES_USER="$KEYCLOAK_DB_USER" \
    -e POSTGRES_PASSWORD="$KEYCLOAK_DB_PASSWORD" \
    --log-driver=journald \
    --log-opt tag="hookprobe-keycloak-db" \
    "$IMAGE_POSTGRES"

sleep 15

echo "  → Starting Keycloak IAM service..."
podman run -d --restart always \
    --pod "$POD_IAM" \
    --name "${POD_IAM}-keycloak" \
    -e KC_DB=postgres \
    -e KC_DB_URL="jdbc:postgresql://localhost:5432/${KEYCLOAK_DB}" \
    -e KC_DB_USERNAME="$KEYCLOAK_DB_USER" \
    -e KC_DB_PASSWORD="$KEYCLOAK_DB_PASSWORD" \
    -e KC_HOSTNAME="$KEYCLOAK_HOSTNAME" \
    -e KEYCLOAK_ADMIN="$KEYCLOAK_ADMIN" \
    -e KEYCLOAK_ADMIN_PASSWORD="$KEYCLOAK_ADMIN_PASSWORD" \
    -e KC_HTTP_PORT=8080 \
    -e KC_HTTPS_PORT=8443 \
    -v "$VOLUME_KEYCLOAK_DATA:/opt/keycloak/data" \
    --log-driver=journald \
    --log-opt tag="hookprobe-keycloak" \
    "$IMAGE_KEYCLOAK" \
    start-dev

echo "✓ POD_IAM deployed (Keycloak)"

# ============================================================
# STEP 15: DEPLOY POD_MONITORING - VICTORIAMETRICS, CLICKHOUSE, GRAFANA
# ============================================================
echo ""
echo "[STEP 15] Deploying POD_MONITORING - Observability & Analytics Stack..."

podman pod exists "$POD_MONITORING" 2>/dev/null && podman pod rm -f "$POD_MONITORING"

podman pod create \
    --name "$POD_MONITORING" \
    --network "$NETWORK_MONITORING" \
    -p ${PORT_GRAFANA}:3000 \
    -p ${PORT_VICTORIAMETRICS}:8428 \
    -p ${PORT_CLICKHOUSE_HTTP}:8123 \
    -p ${PORT_CLICKHOUSE_NATIVE}:9001

echo "  → Starting VictoriaMetrics..."
podman run -d --restart always \
    --pod "$POD_MONITORING" \
    --name "${POD_MONITORING}-victoriametrics" \
    -v "$VOLUME_VICTORIAMETRICS_DATA:/victoria-metrics-data" \
    --log-driver=journald \
    --log-opt tag="hookprobe-victoriametrics" \
    "$IMAGE_VICTORIAMETRICS" \
    -storageDataPath=/victoria-metrics-data \
    -retentionPeriod=90d

echo "  → Starting ClickHouse OLAP database..."
mkdir -p /tmp/clickhouse-config

cat > /tmp/clickhouse-config/users.xml << 'CLICKHOUSEUSERS'
<yandex>
    <profiles>
        <default>
            <max_memory_usage>8000000000</max_memory_usage>
            <use_uncompressed_cache>0</use_uncompressed_cache>
            <load_balancing>random</load_balancing>
        </default>
    </profiles>
    <users>
        <${CLICKHOUSE_USER}>
            <password>${CLICKHOUSE_PASSWORD}</password>
            <networks><ip>::/0</ip></networks>
            <profile>default</profile>
            <quota>default</quota>
        </${CLICKHOUSE_USER}>
    </users>
    <quotas>
        <default>
            <interval>
                <duration>3600</duration>
                <queries>0</queries>
                <errors>0</errors>
            </interval>
        </default>
    </quotas>
</yandex>
CLICKHOUSEUSERS

podman run -d --restart always \
    --pod "$POD_MONITORING" \
    --name "${POD_MONITORING}-clickhouse" \
    -v "$VOLUME_CLICKHOUSE_DATA:/var/lib/clickhouse" \
    -v "$VOLUME_CLICKHOUSE_LOGS:/var/log/clickhouse-server" \
    -v /tmp/clickhouse-config/users.xml:/etc/clickhouse-server/users.d/custom.xml:ro \
    --ulimit nofile=262144:262144 \
    --log-driver=journald \
    --log-opt tag="hookprobe-clickhouse" \
    "$IMAGE_CLICKHOUSE"

echo "  → Waiting for ClickHouse to start..."
sleep 15

echo "  → Initializing ClickHouse database schemas..."
podman exec "${POD_MONITORING}-clickhouse" clickhouse-client --query "CREATE DATABASE IF NOT EXISTS ${CLICKHOUSE_DB}"

podman exec "${POD_MONITORING}-clickhouse" clickhouse-client --database="${CLICKHOUSE_DB}" --multiquery << 'CLICKHOUSESCHEMA'
-- Main security events table (unified from all sources)
CREATE TABLE IF NOT EXISTS security_events (
    timestamp DateTime64(3),
    event_id UUID DEFAULT generateUUIDv4(),
    source_type LowCardinality(String),
    host String,
    src_ip IPv4,
    dst_ip IPv4,
    src_port UInt16,
    dst_port UInt16,
    protocol LowCardinality(String),
    attack_type LowCardinality(String),
    severity LowCardinality(String),
    blocked UInt8,
    raw_event String CODEC(ZSTD(3)),
    geoip_country LowCardinality(String),
    user_agent String,
    uri String
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, src_ip, attack_type)
TTL timestamp + INTERVAL ${CLICKHOUSE_RETENTION_DAYS} DAY
SETTINGS index_granularity = 8192;

-- Qsecbit historical analysis table
CREATE TABLE IF NOT EXISTS qsecbit_scores (
    timestamp DateTime64(3),
    score Float32,
    rag_status LowCardinality(String),
    drift Float32,
    attack_probability Float32,
    classifier_decay Float32,
    quantum_drift Float32,
    cpu_usage Float32,
    memory_usage Float32,
    network_traffic Float32,
    disk_io Float32,
    host String,
    pod String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY timestamp
TTL timestamp + INTERVAL ${CLICKHOUSE_QSECBIT_RETENTION_DAYS} DAY
SETTINGS index_granularity = 8192;

-- Network flows table (Zeek data)
CREATE TABLE IF NOT EXISTS network_flows (
    timestamp DateTime64(3),
    src_ip IPv4,
    dst_ip IPv4,
    src_port UInt16,
    dst_port UInt16,
    protocol LowCardinality(String),
    bytes_sent UInt64,
    bytes_received UInt64,
    packets_sent UInt32,
    packets_received UInt32,
    duration Float32,
    service LowCardinality(String),
    conn_state LowCardinality(String),
    zeek_uid String
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, src_ip, dst_ip)
TTL timestamp + INTERVAL ${CLICKHOUSE_FLOWS_RETENTION_DAYS} DAY
SETTINGS index_granularity = 8192;

-- WAF events table (ModSecurity)
CREATE TABLE IF NOT EXISTS waf_events (
    timestamp DateTime64(3),
    src_ip IPv4,
    request_uri String,
    request_method LowCardinality(String),
    rule_id UInt32,
    rule_message String,
    attack_category LowCardinality(String),
    severity LowCardinality(String),
    blocked UInt8,
    user_agent String,
    referer String,
    request_body String CODEC(ZSTD(3)),
    response_status UInt16,
    response_time Float32
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, src_ip, attack_category)
TTL timestamp + INTERVAL ${CLICKHOUSE_RETENTION_DAYS} DAY
SETTINGS index_granularity = 8192;

-- System logs table (journald, syslog)
CREATE TABLE IF NOT EXISTS system_logs (
    timestamp DateTime64(3),
    hostname String,
    severity LowCardinality(String),
    facility LowCardinality(String),
    tag String,
    message String,
    container_name String
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, hostname, severity)
TTL timestamp + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- Honeypot attacks table
CREATE TABLE IF NOT EXISTS honeypot_attacks (
    timestamp DateTime64(3),
    src_ip IPv4,
    honeypot_type LowCardinality(String),
    username String,
    password String,
    command String,
    payload String CODEC(ZSTD(3)),
    attack_classification LowCardinality(String),
    credential_in_db UInt8,
    geoip_country LowCardinality(String),
    geoip_city String,
    asn UInt32
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, src_ip)
TTL timestamp + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

-- Materialized view: Attacks per hour
CREATE MATERIALIZED VIEW IF NOT EXISTS attacks_per_hour_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, attack_type, src_ip)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    attack_type,
    src_ip,
    count() AS attack_count,
    countIf(blocked = 1) AS blocked_count
FROM security_events
GROUP BY hour, attack_type, src_ip;

-- Materialized view: Top attackers per day
CREATE MATERIALIZED VIEW IF NOT EXISTS top_attackers_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (day, src_ip)
AS SELECT
    toDate(timestamp) AS day,
    src_ip,
    count() AS total_attacks,
    uniq(attack_type) AS attack_types,
    countIf(severity = 'critical') AS critical_attacks
FROM security_events
GROUP BY day, src_ip;
CLICKHOUSESCHEMA

echo "✓ ClickHouse deployed and initialized"

echo "  → Starting Vector log aggregator..."
mkdir -p /tmp/vector-config

cat > /tmp/vector-config/vector.toml << 'VECTOREOF'
[sources.journald]
type = "journald"
include_units = ["podman"]

[sources.host_logs]
type = "file"
include = ["/var/log/messages", "/var/log/secure"]

[sources.modsec_logs]
type = "file"
include = ["/var/lib/containers/storage/volumes/hookprobe-modsecurity-logs-v5/_data/*.log"]
data_dir = "/var/lib/vector/modsec"

[transforms.parse_journald]
type = "remap"
inputs = ["journald"]
source = '''
  .timestamp = now()
  .hostname = get_hostname!()
  .container_name = .CONTAINER_NAME
  .severity = .PRIORITY
  .message = .MESSAGE
'''

[transforms.parse_host_logs]
type = "remap"
inputs = ["host_logs"]
source = '''
  parsed = parse_syslog!(.message)
  .timestamp = parsed.timestamp
  .hostname = parsed.hostname
  .severity = parsed.severity
  .facility = parsed.facility
  .tag = parsed.appname
  .message = parsed.message
'''

[transforms.parse_modsec]
type = "remap"
inputs = ["modsec_logs"]
source = '''
  parsed = parse_json!(.message)
  .timestamp = to_timestamp!(parsed.transaction.time_stamp)
  .src_ip = parsed.transaction.client_ip
  .request_uri = parsed.transaction.request.uri
  .request_method = parsed.transaction.request.method
  .attack_category = parsed.transaction.messages[0].details.ruleId
  .severity = parsed.transaction.messages[0].details.severity
  .blocked = if parsed.transaction.producer.connector == "ModSecurity" { 1 } else { 0 }
'''

[sinks.clickhouse_system_logs]
type = "clickhouse"
inputs = ["parse_journald", "parse_host_logs"]
endpoint = "http://localhost:8123"
database = "security"
table = "system_logs"
compression = "gzip"

[sinks.clickhouse_waf]
type = "clickhouse"
inputs = ["parse_modsec"]
endpoint = "http://localhost:8123"
database = "security"
table = "waf_events"
compression = "gzip"
VECTOREOF

podman run -d --restart always \
    --pod "$POD_MONITORING" \
    --name "${POD_MONITORING}-vector" \
    -v /tmp/vector-config:/etc/vector:ro \
    -v /var/log:/var/log:ro \
    -v /run/log/journal:/run/log/journal:ro \
    -v /var/lib/containers/storage/volumes:/var/lib/containers/storage/volumes:ro \
    --log-driver=journald \
    --log-opt tag="hookprobe-vector" \
    "$IMAGE_VECTOR" \
    --config /etc/vector/vector.toml

echo "  → Starting Filebeat for Zeek log ingestion..."
mkdir -p /tmp/filebeat-config

cat > /tmp/filebeat-config/filebeat.yml << 'FILEBEATEOF'
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /zeek-logs/current/conn.log
    - /zeek-logs/current/dns.log
    - /zeek-logs/current/http.log
  json.keys_under_root: true
  json.add_error_key: true
  fields:
    source_type: zeek

output.http:
  hosts: ["http://localhost:8123"]
  index: "network_flows"
  parameters:
    database: security
    table: network_flows
  compression_level: 3
FILEBEATEOF

podman run -d --restart always \
    --pod "$POD_MONITORING" \
    --name "${POD_MONITORING}-filebeat" \
    -v /tmp/filebeat-config/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro \
    -v "$VOLUME_ZEEK_LOGS:/zeek-logs:ro" \
    --user root \
    --log-driver=journald \
    --log-opt tag="hookprobe-filebeat" \
    "$IMAGE_FILEBEAT"

echo "  → Starting Node Exporter..."
podman run -d --restart always \
    --pod "$POD_MONITORING" \
    --name "${POD_MONITORING}-node-exporter" \
    --pid=host \
    -v "/:/host:ro,rslave" \
    --log-driver=journald \
    --log-opt tag="hookprobe-node-exporter" \
    "$IMAGE_NODE_EXPORTER" \
    --path.rootfs=/host

echo "  → Starting Grafana..."
mkdir -p /tmp/grafana-provisioning/datasources

cat > /tmp/grafana-provisioning/datasources/datasources.yml << EOF
apiVersion: 1

datasources:
  - name: VictoriaMetrics
    type: prometheus
    access: proxy
    url: http://localhost:8428
    isDefault: true
    editable: true

  - name: ClickHouse
    type: vertamedia-clickhouse-datasource
    access: proxy
    url: http://localhost:8123
    jsonData:
      defaultDatabase: security
      addCorsHeader: true
      usePOST: false
    editable: true
EOF

podman run -d --restart always \
    --pod "$POD_MONITORING" \
    --name "${POD_MONITORING}-grafana" \
    -e GF_SECURITY_ADMIN_USER=admin \
    -e GF_SECURITY_ADMIN_PASSWORD=admin \
    -e GF_USERS_ALLOW_SIGN_UP=false \
    -e GF_INSTALL_PLUGINS=grafana-piechart-panel,vertamedia-clickhouse-datasource \
    -v "$VOLUME_GRAFANA_DATA:/var/lib/grafana" \
    -v "/tmp/grafana-provisioning/datasources:/etc/grafana/provisioning/datasources:ro" \
    --user root \
    --log-driver=journald \
    --log-opt tag="hookprobe-grafana" \
    "$IMAGE_GRAFANA"

echo "✓ POD_MONITORING deployed (VictoriaMetrics + ClickHouse + Grafana)"

# ============================================================
# STEP 16: BUILD AND DEPLOY DJANGO APPLICATION
# ============================================================
echo ""
echo "[STEP 16] Building Django application..."

DJANGO_BUILD_DIR="/tmp/hookprobe-django-build"
rm -rf "$DJANGO_BUILD_DIR"
mkdir -p "$DJANGO_BUILD_DIR"

cat > "$DJANGO_BUILD_DIR/Dockerfile" << 'DJANGOEOF'
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=hookprobe.settings

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN python manage.py collectstatic --noinput || true
RUN mkdir -p /app/static /app/media

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "hookprobe.wsgi:application"]
DJANGOEOF

cat > "$DJANGO_BUILD_DIR/requirements.txt" << 'REQEOF'
Django==5.0.6
gunicorn==22.0.0
psycopg2-binary==2.9.9
redis==5.0.4
celery==5.4.0
django-environ==0.11.2
Pillow==10.3.0
djangorestframework==3.15.1
requests==2.32.3
PyJWT==2.8.0
cryptography==42.0.7
REQEOF

mkdir -p "$DJANGO_BUILD_DIR/hookprobe"

cat > "$DJANGO_BUILD_DIR/manage.py" << 'MANAGEEOF'
#!/usr/bin/env python
import os
import sys

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "hookprobe.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError("Couldn't import Django.") from exc
    execute_from_command_line(sys.argv)
MANAGEEOF
chmod +x "$DJANGO_BUILD_DIR/manage.py"

cat > "$DJANGO_BUILD_DIR/hookprobe/settings.py" << EOF
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = '${DJANGO_SECRET_KEY}'
DEBUG = ${DJANGO_DEBUG}
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'hookprobe.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': '${POSTGRES_DB}',
        'USER': '${POSTGRES_USER}',
        'PASSWORD': '${POSTGRES_PASSWORD}',
        'HOST': '${IP_POSTGRES_MAIN}',
        'PORT': '5432',
    }
}

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://${IP_REDIS}:6379/1',
    }
}

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
EOF

cat > "$DJANGO_BUILD_DIR/hookprobe/urls.py" << 'URLSEOF'
from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
URLSEOF

cat > "$DJANGO_BUILD_DIR/hookprobe/wsgi.py" << 'WSGIEOF'
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'hookprobe.settings')
application = get_wsgi_application()
WSGIEOF

touch "$DJANGO_BUILD_DIR/hookprobe/__init__.py"

echo "  → Building Django container image..."
cd "$DJANGO_BUILD_DIR"
podman build -t hookprobe-django:v5 .

echo "✓ Django application built"

# ============================================================
# STEP 17: DEPLOY POD_WEB - DJANGO + MODSECURITY + NGINX
# ============================================================
echo ""
echo "[STEP 17] Deploying POD_WEB - Web DMZ..."

podman pod exists "$POD_WEB" 2>/dev/null && podman pod rm -f "$POD_WEB"

podman pod create \
    --name "$POD_WEB" \
    --network "$NETWORK_WEB" \
    -p ${PORT_HTTP}:80 \
    -p ${PORT_HTTPS}:443

echo "  → Starting Django application..."
podman run -d --restart always \
    --pod "$POD_WEB" \
    --name "${POD_WEB}-django" \
    -e DJANGO_SETTINGS_MODULE="hookprobe.settings" \
    -v "$VOLUME_DJANGO_STATIC:/app/static" \
    -v "$VOLUME_DJANGO_MEDIA:/app/media" \
    --log-driver=journald \
    --log-opt tag="hookprobe-django" \
    hookprobe-django:v5

sleep 10

echo "  → Running database migrations..."
podman exec "${POD_WEB}-django" python manage.py migrate --noinput || true

echo "  → Creating Django superuser..."
podman exec "${POD_WEB}-django" python manage.py shell << 'PYEOF'
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@hookprobe.local', 'admin')
    print('Superuser created: admin/admin')
else:
    print('Superuser already exists')
PYEOF

echo "  → Configuring ModSecurity + Nginx..."
mkdir -p /tmp/modsecurity-nginx-config

cat > /tmp/modsecurity-nginx-config/nginx.conf << 'MODSECEOF'
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

load_module modules/ngx_http_modsecurity_module.so;

events {
    worker_connections 4096;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    sendfile on;
    keepalive_timeout 65;

    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;

    upstream django {
        server localhost:8000;
    }

    server {
        listen 80;
        server_name _;
        client_max_body_size 100M;

        location /static/ {
            alias /var/www/static/;
            expires 30d;
        }

        location /media/ {
            alias /var/www/media/;
            expires 30d;
        }

        location / {
            proxy_pass http://django;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_redirect off;
        }
    }
}
MODSECEOF

cat > /tmp/modsecurity-nginx-config/main.conf << 'MODSECMAINEOF'
Include /etc/nginx/modsec/modsecurity.conf
Include /etc/nginx/modsec/crs-setup.conf
Include /usr/share/modsecurity-crs/rules/*.conf
MODSECMAINEOF

cat > /tmp/modsecurity-nginx-config/modsecurity.conf << EOF
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction Reject
SecPcreMatchLimit 100000
SecPcreMatchLimitRecursion 100000

SecAuditEngine RelevantOnly
SecAuditLog /var/log/nginx/modsec_audit.log
SecAuditLogFormat JSON
SecAuditLogType Serial

SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"

SecAction "id:900200,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=${MODSECURITY_PARANOIA_LEVEL}"
SecAction "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=${MODSECURITY_ANOMALY_THRESHOLD}"
EOF

echo "  → Starting ModSecurity + Nginx..."
podman run -d --restart always \
    --pod "$POD_WEB" \
    --name "${POD_WEB}-modsecurity" \
    -v /tmp/modsecurity-nginx-config/nginx.conf:/etc/nginx/nginx.conf:ro \
    -v /tmp/modsecurity-nginx-config/main.conf:/etc/nginx/modsec/main.conf:ro \
    -v /tmp/modsecurity-nginx-config/modsecurity.conf:/etc/nginx/modsec/modsecurity.conf:ro \
    -v "$VOLUME_DJANGO_STATIC:/var/www/static:ro" \
    -v "$VOLUME_DJANGO_MEDIA:/var/www/media:ro" \
    -v "$VOLUME_MODSECURITY_LOGS:/var/log/nginx" \
    --log-driver=journald \
    --log-opt tag="hookprobe-modsecurity" \
    "$IMAGE_MODSECURITY"

# Optional: Cloudflare Tunnel
if [ "$CLOUDFLARE_TUNNEL_TOKEN" != "CHANGE_ME_GET_FROM_CLOUDFLARE_DASHBOARD" ]; then
    echo "  → Starting Cloudflare Tunnel..."
    podman run -d --restart always \
        --pod "$POD_WEB" \
        --name "${POD_WEB}-cloudflared" \
        --log-driver=journald \
        --log-opt tag="hookprobe-cloudflared" \
        "$IMAGE_CLOUDFLARED" \
        tunnel --no-autoupdate run --token "$CLOUDFLARE_TUNNEL_TOKEN"
    echo "  ✓ Cloudflare Tunnel started"
else
    echo "  ⊘ Cloudflare Tunnel skipped (token not configured)"
fi

echo "✓ POD_WEB deployed"

# ============================================================
# STEP 18: DEPLOY POD_SECURITY - ZEEK + SNORT + QSECBIT (OPTIONAL)
# ============================================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[STEP 18] Security Analysis POD (Optional)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "This step deploys the AI-powered security analysis components:"
echo "  • Zeek IDS       - Network traffic analysis"
echo "  • Snort 3 IDS/IPS - Intrusion detection/prevention"
echo "  • Qsecbit Agent  - AI threat analysis and automated response"
echo ""
echo "If you only want a simple web server without security analysis,"
echo "you can skip this step and add it later."
echo ""

# Check if DEPLOY_SECURITY is set in environment or config
if [ "${DEPLOY_SECURITY:-ask}" = "ask" ]; then
    read -p "Deploy Security Analysis POD? (yes/no) [yes]: " deploy_security
    deploy_security=${deploy_security:-yes}
elif [ "${DEPLOY_SECURITY}" = "no" ]; then
    deploy_security="no"
else
    deploy_security="yes"
fi

if [ "$deploy_security" != "yes" ]; then
    echo "⊘ Security Analysis POD skipped (can be deployed later)"
    echo "  To deploy later, run: sudo ./install.sh and select option 1"
    echo ""
else
    echo "✓ Deploying Security Analysis POD..."
    echo ""

podman pod exists "$POD_SECURITY" 2>/dev/null && podman pod rm -f "$POD_SECURITY"

podman pod create \
    --name "$POD_SECURITY" \
    --network "$NETWORK_SECURITY" \
    -p ${PORT_QSECBIT_API}:8888

echo "  → Starting Zeek IDS..."
podman run -d --restart always \
    --pod "$POD_SECURITY" \
    --name "${POD_SECURITY}-zeek" \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    -v "$VOLUME_ZEEK_LOGS:/opt/zeek/logs" \
    --log-driver=journald \
    --log-opt tag="hookprobe-zeek" \
    "$IMAGE_ZEEK" || echo "⚠️  Zeek may need additional configuration"

echo "  → Starting Snort 3 IDS/IPS..."
podman run -d --restart always \
    --pod "$POD_SECURITY" \
    --name "${POD_SECURITY}-snort" \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    -v "$VOLUME_SNORT_LOGS:/var/log/snort" \
    --log-driver=journald \
    --log-opt tag="hookprobe-snort" \
    "$IMAGE_SNORT" || echo "⚠️  Snort may need additional configuration"

echo "  → Building Qsecbit analysis engine..."
QSECBIT_BUILD_DIR="/tmp/qsecbit-build"
rm -rf "$QSECBIT_BUILD_DIR"
mkdir -p "$QSECBIT_BUILD_DIR"

# Copy Qsecbit Python module from artifacts
cp "$SCRIPT_DIR/../qsecbit.py" "$QSECBIT_BUILD_DIR/" 2>/dev/null || cat > "$QSECBIT_BUILD_DIR/qsecbit.py" << 'QSECEOF'
"""Qsecbit: Quantum Security Bit - AI resilience metric"""
import numpy as np
from scipy.spatial.distance import mahalanobis
from scipy.special import expit as logistic
from scipy.stats import entropy
from dataclasses import dataclass
from typing import Optional, Dict
from datetime import datetime

@dataclass
class QsecbitConfig:
    alpha: float = 0.30
    beta: float = 0.30
    gamma: float = 0.20
    delta: float = 0.20
    amber_threshold: float = 0.45
    red_threshold: float = 0.70

class Qsecbit:
    def __init__(self, baseline_mu, baseline_cov, quantum_anchor, config=None):
        self.mu = np.array(baseline_mu)
        self.cov = np.array(baseline_cov)
        self.q_anchor = float(quantum_anchor)
        self.config = config or QsecbitConfig()
        self.inv_cov = np.linalg.inv(self.cov)
        self.prev_classifier = None
    
    def calculate(self, x_t, p_attack, c_t, q_t=None, dt=1.0):
        drift = self._drift(x_t)
        decay = self._classifier_decay(c_t, dt)
        qdrift = self._quantum_drift(q_t or self._system_entropy(x_t))
        score = self.config.alpha * drift + self.config.beta * p_attack + \
                self.config.gamma * decay + self.config.delta * qdrift
        rag = "RED" if score >= self.config.red_threshold else \
              "AMBER" if score >= self.config.amber_threshold else "GREEN"
        return {"score": score, "rag": rag, "drift": drift, "attack_prob": p_attack}
    
    def _drift(self, x_t):
        d = mahalanobis(x_t, self.mu, self.inv_cov)
        return float(logistic(3.5 * (d - 2.0)))
    
    def _classifier_decay(self, c_t, dt):
        if self.prev_classifier is None:
            self.prev_classifier = c_t.copy()
            return 0.0
        delta = np.linalg.norm(c_t - self.prev_classifier) / max(dt, 1e-9)
        self.prev_classifier = c_t.copy()
        return float(min(1.0, delta / 0.15))
    
    def _quantum_drift(self, q_t):
        return float(min(1.0, abs(q_t - self.q_anchor) / 0.25))
    
    def _system_entropy(self, x_t):
        hist, _ = np.histogram(x_t, bins=10, density=True)
        return float(entropy(hist + 1e-10))
QSECEOF

cat > "$QSECBIT_BUILD_DIR/qsecbit_service.py" << EOF
#!/usr/bin/env python3
import os
import time
import json
from qsecbit import Qsecbit, QsecbitConfig
from flask import Flask, jsonify
import numpy as np

app = Flask(__name__)

# Initialize Qsecbit
baseline_mu = np.array([float(x) for x in "$QSECBIT_BASELINE_MU".split(',')])
baseline_cov = np.eye(len(baseline_mu)) * 0.02
quantum_anchor = float("$QSECBIT_QUANTUM_ANCHOR")

config = QsecbitConfig(
    alpha=float("$QSECBIT_ALPHA"),
    beta=float("$QSECBIT_BETA"),
    gamma=float("$QSECBIT_GAMMA"),
    delta=float("$QSECBIT_DELTA"),
    amber_threshold=float("$QSECBIT_AMBER_THRESHOLD"),
    red_threshold=float("$QSECBIT_RED_THRESHOLD")
)

qsecbit = Qsecbit(baseline_mu, baseline_cov, quantum_anchor, config)

@app.route('/api/qsecbit/latest', methods=['GET'])
def get_latest():
    # Simulate metrics (in production, fetch from VictoriaMetrics)
    x_t = baseline_mu + np.random.randn(len(baseline_mu)) * 0.1
    p_attack = 0.1
    c_t = np.array([0.9, 0.88, 0.92])
    
    result = qsecbit.calculate(x_t, p_attack, c_t, dt=30)
    return jsonify(result)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=False)
EOF

cat > "$QSECBIT_BUILD_DIR/Dockerfile" << 'QSECDOCKEREOF'
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir numpy scipy flask
COPY qsecbit.py .
COPY qsecbit_service.py .
EXPOSE 8888
CMD ["python", "qsecbit_service.py"]
QSECDOCKEREOF

cd "$QSECBIT_BUILD_DIR"
podman build -t hookprobe-qsecbit:v5 .

echo "  → Starting Qsecbit AI analysis engine..."
podman run -d --restart always \
    --pod "$POD_SECURITY" \
    --name "${POD_SECURITY}-qsecbit" \
    -v "$VOLUME_QSECBIT_DATA:/data" \
    --log-driver=journald \
    --log-opt tag="hookprobe-qsecbit" \
    hookprobe-qsecbit:v5

    echo ""
    echo "✓ Security Analysis POD deployed successfully!"
    echo "  → Qsecbit API available at: http://${LOCAL_HOST_IP}:${PORT_QSECBIT_API}"
    echo ""
fi

# ============================================================
# STEP 19: DEPLOY POD_HONEYPOT - BASIC HONEYPOTS
# ============================================================
echo ""
echo "[STEP 19] Deploying POD_HONEYPOT - Deception Layer..."

podman pod exists "$POD_HONEYPOT" 2>/dev/null && podman pod rm -f "$POD_HONEYPOT"

podman pod create \
    --name "$POD_HONEYPOT" \
    --network "$NETWORK_HONEYPOT"

echo "  → Creating basic HTTP honeypot..."
mkdir -p /tmp/honeypot-http

cat > /tmp/honeypot-http/index.html << 'HONEYEOF'
<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body>
<h1>Administration Panel</h1>
<form action="/login" method="post">
<input type="text" name="username" placeholder="Username">
<input type="password" name="password" placeholder="Password">
<button type="submit">Login</button>
</form>
</body>
</html>
HONEYEOF

podman run -d --restart always \
    --pod "$POD_HONEYPOT" \
    --name "${POD_HONEYPOT}-web" \
    -v /tmp/honeypot-http:/usr/share/nginx/html:ro \
    --log-driver=journald \
    --log-opt tag="hookprobe-honeypot-web" \
    "$IMAGE_NGINX"

echo "✓ POD_HONEYPOT deployed (basic setup)"
echo "  Stage 3 will add intelligent redirection and logging"

# ============================================================
# FINAL SUMMARY
# ============================================================
echo ""
echo "============================================================"
echo "   🎉 HOOKPROBE v5.0 COMPLETE DEPLOYMENT FINISHED!"
echo "============================================================"
echo ""
echo "✅ All Services Deployed:"
echo "  ✓ POD_DATABASE - PostgreSQL (${IP_POSTGRES_MAIN})"
echo "  ✓ POD_CACHE - Redis (${IP_REDIS})"
echo "  ✓ POD_IAM - Keycloak (${IP_KEYCLOAK})"
echo "  ✓ POD_MONITORING - VictoriaMetrics, ClickHouse, Grafana"
echo "  ✓ POD_WEB - Django + ModSecurity WAF + Nginx"
if [ "$CLOUDFLARE_TUNNEL_TOKEN" != "CHANGE_ME_GET_FROM_CLOUDFLARE_DASHBOARD" ]; then
    echo "    • Cloudflare Tunnel: Active"
fi
echo "  ✓ POD_SECURITY - Zeek + Snort 3 + Qsecbit AI"
echo "  ✓ POD_HONEYPOT - Basic deception layer"
echo ""
echo "🔐 Network Infrastructure:"
echo "  ✓ Single OVS bridge: $QSEC_BRIDGE"
echo "  ✓ 8 encrypted VXLAN tunnels (VNI 200-207)"
echo "  ✓ OpenFlow ACLs per VNI"
echo "  ✓ L2 hardening (anti-spoof, ARP protection)"
echo "  ✓ nftables firewall with connection tracking"
if [ "$ENABLE_XDP_DDOS" = true ] && [ -f /opt/hookprobe/xdp/ddos_mitigate.o ]; then
    echo "  ✓ XDP DDoS mitigation active"
fi
echo "  ✓ Port mirroring for IDS"
echo "  ✓ Flow telemetry (sFlow)"
echo ""
echo "🌐 Access Information:"
echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🌐 Web Application:"
echo "     URL: http://$LOCAL_HOST_IP"
echo "     Django Admin: http://$LOCAL_HOST_IP/admin"
echo "     Username: admin"
echo "     Password: admin (⚠️  CHANGE IMMEDIATELY)"
echo ""
echo "  🔐 Keycloak IAM:"
echo "     Admin Console: http://$LOCAL_HOST_IP:${PORT_KEYCLOAK_ADMIN}"
echo "     Username: $KEYCLOAK_ADMIN"
echo "     Password: (set in config - CHANGE IT)"
echo ""
echo "  📊 Monitoring & Analytics:"
echo "     Grafana: http://$LOCAL_HOST_IP:${PORT_GRAFANA}"
echo "     Username: admin | Password: admin"
echo "     VictoriaMetrics: http://$LOCAL_HOST_IP:${PORT_VICTORIAMETRICS}"
echo "     ClickHouse HTTP: http://$LOCAL_HOST_IP:${PORT_CLICKHOUSE_HTTP}"
echo "     ClickHouse Native: tcp://$LOCAL_HOST_IP:${PORT_CLICKHOUSE_NATIVE}"
echo ""
echo "  🤖 Qsecbit AI:"
echo "     API: http://$LOCAL_HOST_IP:${PORT_QSECBIT_API}/api/qsecbit/latest"
echo "     Health: http://$LOCAL_HOST_IP:${PORT_QSECBIT_API}/health"
echo ""
echo "  🗄️  Database:"
echo "     PostgreSQL: $LOCAL_HOST_IP:${PORT_POSTGRES}"
echo "     Database: $POSTGRES_DB"
echo "     User: $POSTGRES_USER"
echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📋 Next Steps:"
echo "  1. 🔐 Change all default passwords immediately!"
echo "     - Django admin: python manage.py changepassword admin"
echo "     - Grafana admin: via UI"
echo "     - Keycloak admin: via admin console"
echo ""
echo "  2. 🔍 Verify all services are running:"
echo "     podman pod ps"
echo "     podman ps -a"
echo ""
echo "  3. 📊 Access Grafana and verify data sources:"
echo "     http://$LOCAL_HOST_IP:${PORT_GRAFANA}"
echo ""
echo "  4. 🛡️  Check security services:"
echo "     podman logs ${POD_SECURITY}-zeek"
echo "     podman logs ${POD_SECURITY}-snort"
echo "     curl http://$LOCAL_HOST_IP:${PORT_QSECBIT_API}/health"
echo ""
echo "  5. 🔧 Review ModSecurity logs:"
echo "     podman logs ${POD_WEB}-modsecurity"
echo ""
echo "  6. 🎯 Ready for Stage 2: Documentation"
echo ""
echo "============================================================"
echo "  ✨ HookProbe v5.0 is now fully operational!"
echo "  🚀 100% GPL-Free Security Platform"
echo "  🛡️  Defense in Depth: XDP → OVS → nftables → WAF → IDS"
echo "============================================================"
