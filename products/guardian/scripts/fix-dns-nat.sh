#!/bin/bash
#
# Guardian DNS/NAT Fix Script
# Fixes DNS resolution by properly configuring NAT with nftables
# Supports automatic WAN failover between eth0 and wlan0
#
# Run as root: sudo ./fix-dns-nat.sh
#
# Version: 5.1.0

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Guardian DNS/NAT Fix ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Please run as root (sudo $0)"
    exit 1
fi

# Detect available WAN interfaces
detect_wan() {
    local wan_iface=""

    # Check eth0 first (preferred)
    if [ -d "/sys/class/net/eth0" ]; then
        if ip addr show eth0 2>/dev/null | grep -q "inet "; then
            # Has IP, check connectivity
            if ping -c 1 -W 2 -I eth0 1.1.1.1 >/dev/null 2>&1; then
                wan_iface="eth0"
            fi
        fi
    fi

    # Fall back to wlan0 if eth0 not available
    if [ -z "$wan_iface" ] && [ -d "/sys/class/net/wlan0" ]; then
        if ip addr show wlan0 2>/dev/null | grep -q "inet "; then
            if ping -c 1 -W 2 -I wlan0 1.1.1.1 >/dev/null 2>&1; then
                wan_iface="wlan0"
            elif ip addr show wlan0 2>/dev/null | grep -q "inet "; then
                # Has IP but no connectivity - use anyway
                wan_iface="wlan0"
            fi
        fi
    fi

    # Last resort: use whatever has an IP
    if [ -z "$wan_iface" ]; then
        for iface in eth0 enp0s3 eno1 wlan0; do
            if [ -d "/sys/class/net/$iface" ]; then
                if ip addr show "$iface" 2>/dev/null | grep -q "inet "; then
                    wan_iface="$iface"
                    break
                fi
            fi
        done
    fi

    echo "$wan_iface"
}

# Detect active WAN interface
echo "[1/5] Detecting WAN interface..."
WAN_IFACE=$(detect_wan)

if [ -n "$WAN_IFACE" ]; then
    echo "  Active WAN: $WAN_IFACE"
else
    echo "  WARNING: No WAN interface detected"
    echo "  Will configure NAT for both eth0 and wlan0"
    WAN_IFACE="both"
fi

# Enable IP forwarding
echo "[2/5] Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
mkdir -p /etc/sysctl.d
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-guardian.conf
sysctl -p /etc/sysctl.d/99-guardian.conf 2>/dev/null || true

# Create proper nftables config with failover support
echo "[3/5] Creating nftables NAT configuration..."
mkdir -p /etc/nftables.d

if [ "$WAN_IFACE" = "both" ]; then
    # Configure for both interfaces (failover-ready)
    cat > /etc/nftables.d/guardian.nft << 'EOF'
#!/usr/sbin/nft -f
# HookProbe Guardian - NAT and Firewall Rules (Failover Mode)

# Delete old tables if they exist (clean slate)
table inet guardian
delete table inet guardian

table ip guardian_nat
delete table ip guardian_nat

# Filtering rules (inet family)
table inet guardian {
    chain input {
        type filter hook input priority 0; policy accept;
        ct state established,related accept
        tcp dport 22 accept
        tcp dport 8080 accept
        iifname "br0" udp dport 53 accept
        iifname "br0" tcp dport 53 accept
        iifname "wlan1" udp dport 53 accept
        iifname "wlan1" tcp dport 53 accept
    }

    chain forward {
        type filter hook forward priority 0; policy accept;
        ct state established,related accept
        iifname "br0" accept
        iifname "wlan1" accept
    }
}

# NAT rules - both WANs for automatic failover
table ip guardian_nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "eth0" masquerade
        oifname "wlan0" masquerade
    }
}
EOF
else
    # Configure for single WAN
    cat > /etc/nftables.d/guardian.nft << EOF
#!/usr/sbin/nft -f
# HookProbe Guardian - NAT and Firewall Rules (Single WAN: $WAN_IFACE)

# Delete old tables if they exist (clean slate)
table inet guardian
delete table inet guardian

table ip guardian_nat
delete table ip guardian_nat

# Filtering rules (inet family)
table inet guardian {
    chain input {
        type filter hook input priority 0; policy accept;
        ct state established,related accept
        tcp dport 22 accept
        tcp dport 8080 accept
        iifname "br0" udp dport 53 accept
        iifname "br0" tcp dport 53 accept
        iifname "wlan1" udp dport 53 accept
        iifname "wlan1" tcp dport 53 accept
    }

    chain forward {
        type filter hook forward priority 0; policy accept;
        ct state established,related accept
        iifname "br0" accept
        iifname "wlan1" accept
    }
}

# NAT rules for active WAN
table ip guardian_nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "$WAN_IFACE" masquerade
    }
}
EOF
fi

# Apply nftables rules
echo "[4/5] Applying nftables rules..."
if nft -f /etc/nftables.d/guardian.nft 2>/dev/null; then
    echo "  nftables rules applied successfully"
else
    echo "  nftables failed, using iptables fallback..."
    # Clear old NAT rules and add new ones
    iptables -t nat -F POSTROUTING 2>/dev/null || true
    if [ "$WAN_IFACE" = "both" ]; then
        iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || true
        iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE 2>/dev/null || true
    else
        iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null || true
    fi
    echo "  iptables MASQUERADE rules applied"
fi

# Restart dnsmasq to ensure it's running properly
echo "[5/5] Restarting dnsmasq..."
systemctl restart dnsmasq 2>/dev/null || {
    echo "  dnsmasq restart failed, trying manual start..."
    killall dnsmasq 2>/dev/null || true
    sleep 1
    dnsmasq 2>/dev/null || true
}

echo ""
echo "=== DNS/NAT Fix Complete ==="
echo ""

# Test connectivity
echo "Testing connectivity..."
if [ -n "$WAN_IFACE" ] && [ "$WAN_IFACE" != "both" ]; then
    if ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then
        echo "  ✓ Internet connectivity: OK"
    else
        echo "  ✗ Internet connectivity: FAILED"
    fi
fi

echo "Testing DNS resolution..."
if nslookup google.com 127.0.0.1 >/dev/null 2>&1; then
    echo "  ✓ DNS resolution: OK"
elif dig @127.0.0.1 google.com +short >/dev/null 2>&1; then
    echo "  ✓ DNS resolution: OK"
elif host google.com >/dev/null 2>&1; then
    echo "  ✓ DNS resolution: OK (via system resolver)"
else
    echo "  ✗ DNS resolution: FAILED"
    echo ""
    echo "  Troubleshooting:"
    echo "    - Check WAN connection: ping 1.1.1.1"
    echo "    - Check dnsmasq: systemctl status dnsmasq"
    echo "    - Check routing: ip route"
fi

echo ""
echo "Current Configuration:"
echo "  WAN Interface: $WAN_IFACE"
echo "  LAN Interface: br0"
echo ""

echo "NAT Rules:"
nft list table ip guardian_nat 2>/dev/null || iptables -t nat -L POSTROUTING -n 2>/dev/null || echo "  (no rules found)"

echo ""
echo "Routing Table:"
ip route show | head -5

# Hint about routing daemon
if [ -f "$SCRIPT_DIR/guardian-routing.sh" ] || [ -f "/usr/local/bin/guardian-routing.sh" ]; then
    echo ""
    echo "TIP: For automatic WAN failover, run: guardian-routing.sh start"
fi
