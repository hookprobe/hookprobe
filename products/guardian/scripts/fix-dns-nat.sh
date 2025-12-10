#!/bin/bash
#
# Guardian DNS/NAT Fix Script
# Fixes DNS resolution by properly configuring NAT with nftables
#
# Run as root: sudo ./fix-dns-nat.sh
#
# Version: 5.1.0

set -e

echo "=== Guardian DNS/NAT Fix ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Please run as root (sudo $0)"
    exit 1
fi

# Enable IP forwarding
echo "[1/4] Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-guardian.conf
sysctl -p /etc/sysctl.d/99-guardian.conf 2>/dev/null || true

# Create proper nftables config
echo "[2/4] Creating nftables NAT configuration..."
mkdir -p /etc/nftables.d
cat > /etc/nftables.d/guardian.nft << 'EOF'
#!/usr/sbin/nft -f
# HookProbe Guardian - NAT and Firewall Rules

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
    }

    chain forward {
        type filter hook forward priority 0; policy accept;
        ct state established,related accept
        iifname "br0" accept
    }
}

# NAT rules (MUST use ip family, not inet)
table ip guardian_nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "wlan0" masquerade
        oifname "eth0" masquerade
    }
}
EOF

# Apply nftables rules
echo "[3/4] Applying nftables rules..."
if nft -f /etc/nftables.d/guardian.nft 2>/dev/null; then
    echo "  nftables rules applied successfully"
else
    echo "  nftables failed, using iptables fallback..."
    # Clear old NAT rules and add new ones
    iptables -t nat -F POSTROUTING 2>/dev/null || true
    iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE 2>/dev/null || true
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || true
    echo "  iptables MASQUERADE rules applied"
fi

# Restart dnsmasq to ensure it's running properly
echo "[4/4] Restarting dnsmasq..."
systemctl restart dnsmasq 2>/dev/null || {
    echo "  dnsmasq restart failed, trying manual start..."
    killall dnsmasq 2>/dev/null || true
    sleep 1
    dnsmasq 2>/dev/null || true
}

echo ""
echo "=== DNS/NAT Fix Complete ==="
echo ""
echo "Testing DNS resolution..."
if nslookup google.com 127.0.0.1 >/dev/null 2>&1; then
    echo "  ✓ DNS resolution working!"
elif dig @127.0.0.1 google.com +short >/dev/null 2>&1; then
    echo "  ✓ DNS resolution working!"
else
    echo "  ✗ DNS test failed. Check:"
    echo "    - WAN connection (wlan0 or eth0)"
    echo "    - dnsmasq status: systemctl status dnsmasq"
    echo "    - Upstream DNS: ping 1.1.1.1"
fi

echo ""
echo "Current NAT rules:"
nft list table ip guardian_nat 2>/dev/null || iptables -t nat -L POSTROUTING -n 2>/dev/null || echo "  (no rules found)"
