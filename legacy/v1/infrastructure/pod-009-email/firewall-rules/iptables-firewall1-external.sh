#!/bin/bash
#
# Firewall 1 - External (Internet ↔ DMZ)
# HookProbe POD-009 Email System
#
# Purpose: Protect DMZ from internet threats
# Position: Between internet and DMZ (10.200.9.0/24)
#

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}[POD-009] Configuring Firewall 1 - External${NC}"

# ============================================
# VARIABLES
# ============================================
DMZ_NETWORK="10.200.9.0/24"
DMZ_MAIL_GATEWAY="10.200.9.10"
DMZ_IDS="10.200.9.11"
INTERNAL_NETWORK="10.200.1.0/24"

# External interface (facing internet)
EXT_IF="eth0"
# DMZ interface
DMZ_IF="eth1"

# ============================================
# FLUSH EXISTING RULES
# ============================================
echo -e "${YELLOW}Flushing existing rules...${NC}"
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# ============================================
# DEFAULT POLICIES (DENY ALL)
# ============================================
echo -e "${YELLOW}Setting default policies to DROP...${NC}"
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# ============================================
# LOOPBACK
# ============================================
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# ============================================
# ESTABLISHED CONNECTIONS
# ============================================
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ============================================
# INBOUND FROM INTERNET → DMZ
# ============================================
echo -e "${YELLOW}Configuring Internet → DMZ rules...${NC}"

# SMTP (port 25) - Rate limited
iptables -A FORWARD -i $EXT_IF -o $DMZ_IF \
    -d $DMZ_MAIL_GATEWAY -p tcp --dport 25 \
    -m conntrack --ctstate NEW \
    -m limit --limit 100/minute --limit-burst 200 \
    -j ACCEPT

# SMTP Submission (port 587) - STARTTLS
iptables -A FORWARD -i $EXT_IF -o $DMZ_IF \
    -d $DMZ_MAIL_GATEWAY -p tcp --dport 587 \
    -m conntrack --ctstate NEW \
    -m limit --limit 50/minute --limit-burst 100 \
    -j ACCEPT

# HTTPS (port 443) - Cloudflare Tunnel
iptables -A FORWARD -i $EXT_IF -o $DMZ_IF \
    -d $DMZ_MAIL_GATEWAY -p tcp --dport 443 \
    -m conntrack --ctstate NEW \
    -j ACCEPT

# Log dropped packets from internet
iptables -A FORWARD -i $EXT_IF -o $DMZ_IF \
    -m limit --limit 5/min \
    -j LOG --log-prefix "[FW1-DROP-IN] " --log-level 4

# Default deny internet → DMZ
iptables -A FORWARD -i $EXT_IF -o $DMZ_IF -j DROP

# ============================================
# OUTBOUND FROM DMZ → INTERNET
# ============================================
echo -e "${YELLOW}Configuring DMZ → Internet rules...${NC}"

# SMTP (port 25) - Outbound mail relay
iptables -A FORWARD -i $DMZ_IF -o $EXT_IF \
    -s $DMZ_MAIL_GATEWAY -p tcp --dport 25 \
    -m conntrack --ctstate NEW \
    -j ACCEPT

# DNS (port 53) - DNS queries
iptables -A FORWARD -i $DMZ_IF -o $EXT_IF \
    -s $DMZ_MAIL_GATEWAY -p udp --dport 53 \
    -m conntrack --ctstate NEW \
    -j ACCEPT

iptables -A FORWARD -i $DMZ_IF -o $EXT_IF \
    -s $DMZ_MAIL_GATEWAY -p tcp --dport 53 \
    -m conntrack --ctstate NEW \
    -j ACCEPT

# HTTP/HTTPS (ports 80, 443) - Updates, CRL checks
iptables -A FORWARD -i $DMZ_IF -o $EXT_IF \
    -s $DMZ_MAIL_GATEWAY -p tcp -m multiport --dports 80,443 \
    -m conntrack --ctstate NEW \
    -j ACCEPT

# NTP (port 123) - Time synchronization
iptables -A FORWARD -i $DMZ_IF -o $EXT_IF \
    -s $DMZ_MAIL_GATEWAY -p udp --dport 123 \
    -m conntrack --ctstate NEW \
    -j ACCEPT

# Log unexpected outbound traffic from DMZ
iptables -A FORWARD -i $DMZ_IF -o $EXT_IF \
    -m limit --limit 5/min \
    -j LOG --log-prefix "[FW1-DROP-OUT] " --log-level 4

# Default deny DMZ → Internet (all other traffic)
iptables -A FORWARD -i $DMZ_IF -o $EXT_IF -j DROP

# ============================================
# BLOCK DMZ → INTERNAL (Enforced at Firewall 2)
# ============================================
# This firewall should NOT see DMZ → Internal traffic
# Log and drop if somehow it arrives here
iptables -A FORWARD -s $DMZ_NETWORK -d $INTERNAL_NETWORK \
    -j LOG --log-prefix "[FW1-DMZ2INT-ALERT] " --log-level 2

iptables -A FORWARD -s $DMZ_NETWORK -d $INTERNAL_NETWORK -j DROP

# ============================================
# ICMP (Limited)
# ============================================
# Allow ping from internet to DMZ gateway (for monitoring)
iptables -A FORWARD -i $EXT_IF -o $DMZ_IF \
    -d $DMZ_MAIL_GATEWAY -p icmp --icmp-type echo-request \
    -m limit --limit 5/sec \
    -j ACCEPT

# Allow ping responses from DMZ
iptables -A FORWARD -i $DMZ_IF -o $EXT_IF \
    -s $DMZ_MAIL_GATEWAY -p icmp --icmp-type echo-reply \
    -j ACCEPT

# ============================================
# ANTI-SPOOFING
# ============================================
echo -e "${YELLOW}Enabling anti-spoofing protection...${NC}"

# Drop packets with invalid source addresses from internet
iptables -A FORWARD -i $EXT_IF -s 10.0.0.0/8 -j DROP
iptables -A FORWARD -i $EXT_IF -s 172.16.0.0/12 -j DROP
iptables -A FORWARD -i $EXT_IF -s 192.168.0.0/16 -j DROP
iptables -A FORWARD -i $EXT_IF -s 127.0.0.0/8 -j DROP
iptables -A FORWARD -i $EXT_IF -s 169.254.0.0/16 -j DROP
iptables -A FORWARD -i $EXT_IF -s 224.0.0.0/4 -j DROP
iptables -A FORWARD -i $EXT_IF -s 240.0.0.0/5 -j DROP

# ============================================
# DDOS PROTECTION
# ============================================
echo -e "${YELLOW}Enabling DDoS protection...${NC}"

# SYN flood protection
iptables -A FORWARD -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT
iptables -A FORWARD -p tcp --syn -j DROP

# Protect against port scanning
iptables -N port-scanning
iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
iptables -A port-scanning -j DROP

# ============================================
# INVALID PACKETS
# ============================================
iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP

# ============================================
# LOGGING (Rate Limited)
# ============================================
iptables -N LOGGING
iptables -A FORWARD -j LOGGING
iptables -A LOGGING -m limit --limit 5/min -j LOG --log-prefix "[FW1-FINAL-DROP] " --log-level 4
iptables -A LOGGING -j DROP

# ============================================
# SAVE RULES
# ============================================
echo -e "${YELLOW}Saving iptables rules...${NC}"
if command -v iptables-save >/dev/null 2>&1; then
    iptables-save > /etc/iptables/rules.v4
    echo -e "${GREEN}Rules saved to /etc/iptables/rules.v4${NC}"
fi

# ============================================
# DISPLAY SUMMARY
# ============================================
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Firewall 1 Configuration Complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Allowed Traffic:"
echo "  Internet → DMZ:"
echo "    - TCP/25 (SMTP) - Rate limited to 100/min"
echo "    - TCP/587 (Submission) - Rate limited to 50/min"
echo "    - TCP/443 (Cloudflare Tunnel)"
echo ""
echo "  DMZ → Internet:"
echo "    - TCP/25 (SMTP relay)"
echo "    - TCP/53, UDP/53 (DNS)"
echo "    - TCP/80, TCP/443 (Updates)"
echo "    - UDP/123 (NTP)"
echo ""
echo "Blocked Traffic:"
echo "  - All other Internet → DMZ"
echo "  - All other DMZ → Internet"
echo "  - All DMZ → Internal (handled by FW2)"
echo ""
echo -e "${YELLOW}Monitor logs with: tail -f /var/log/syslog | grep FW1${NC}"
echo ""
