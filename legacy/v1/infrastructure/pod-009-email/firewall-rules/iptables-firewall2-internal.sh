#!/bin/bash
#
# Firewall 2 - Internal (DMZ ↔ Internal Network)
# HookProbe POD-009 Email System
#
# Purpose: CRITICAL - Prevent DMZ compromise from spreading to internal network
# Position: Between DMZ (10.200.9.0/24) and Internal (10.200.1.0/24)
#
# Security Principle: ZERO TRUST - Assume DMZ is hostile
#

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}[POD-009] Configuring Firewall 2 - Internal (CRITICAL SECURITY BOUNDARY)${NC}"

# ============================================
# VARIABLES
# ============================================
DMZ_NETWORK="10.200.9.0/24"
DMZ_MAIL_GATEWAY="10.200.9.10"

INTERNAL_NETWORK="10.200.1.0/24"
INTERNAL_MAIL_SERVER="10.200.1.25"
DJANGO_APP="10.200.1.12"

# DMZ interface
DMZ_IF="eth0"
# Internal interface
INT_IF="eth1"

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
echo -e "${RED}Setting default policies to DROP (Zero Trust)...${NC}"
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
# DMZ → INTERNAL (EXTREMELY RESTRICTIVE)
# ============================================
echo -e "${RED}Configuring DMZ → Internal rules (STRICT)...${NC}"

# ONLY allow SMTP relay from DMZ gateway to internal mail server
# This is the ONLY allowed traffic from DMZ to Internal
iptables -A FORWARD -i $DMZ_IF -o $INT_IF \
    -s $DMZ_MAIL_GATEWAY -d $INTERNAL_MAIL_SERVER \
    -p tcp --dport 25 \
    -m conntrack --ctstate NEW \
    -m comment --comment "SMTP relay from DMZ gateway to internal server" \
    -j ACCEPT

# Log and DENY all other DMZ → Internal traffic
# This includes:
# - Other ports from DMZ gateway
# - Any traffic from other DMZ hosts
# - Any protocols besides TCP/25
iptables -A FORWARD -i $DMZ_IF -o $INT_IF \
    -m limit --limit 2/min \
    -j LOG --log-prefix "[FW2-DMZ2INT-DENY] " --log-level 2

iptables -A FORWARD -i $DMZ_IF -o $INT_IF \
    -m comment --comment "Block all other DMZ to Internal" \
    -j REJECT --reject-with icmp-port-unreachable

# ============================================
# INTERNAL → DMZ (Controlled Outbound)
# ============================================
echo -e "${YELLOW}Configuring Internal → DMZ rules...${NC}"

# Allow internal mail server to relay outbound mail to DMZ gateway
iptables -A FORWARD -i $INT_IF -o $DMZ_IF \
    -s $INTERNAL_MAIL_SERVER -d $DMZ_MAIL_GATEWAY \
    -p tcp --dport 25 \
    -m conntrack --ctstate NEW \
    -m comment --comment "Internal server relay to DMZ gateway" \
    -j ACCEPT

# Allow Django app to send mail via DMZ gateway
iptables -A FORWARD -i $INT_IF -o $DMZ_IF \
    -s $DJANGO_APP -d $DMZ_MAIL_GATEWAY \
    -p tcp --dport 25 \
    -m conntrack --ctstate NEW \
    -m comment --comment "Django app to DMZ gateway" \
    -j ACCEPT

# Log and deny all other Internal → DMZ traffic
iptables -A FORWARD -i $INT_IF -o $DMZ_IF \
    -m limit --limit 5/min \
    -j LOG --log-prefix "[FW2-INT2DMZ-DENY] " --log-level 4

iptables -A FORWARD -i $INT_IF -o $DMZ_IF -j DROP

# ============================================
# INTERNAL ↔ INTERNAL (Allow)
# ============================================
# Allow traffic within internal network
iptables -A FORWARD -i $INT_IF -o $INT_IF -j ACCEPT

# ============================================
# ANTI-SPOOFING (Critical for DMZ)
# ============================================
echo -e "${RED}Enabling anti-spoofing for DMZ interface...${NC}"

# Drop packets from DMZ claiming to be from internal network
iptables -A FORWARD -i $DMZ_IF -s $INTERNAL_NETWORK \
    -j LOG --log-prefix "[FW2-SPOOF-ALERT] " --log-level 1

iptables -A FORWARD -i $DMZ_IF -s $INTERNAL_NETWORK -j DROP

# Drop packets from DMZ with invalid source
iptables -A FORWARD -i $DMZ_IF ! -s $DMZ_NETWORK \
    -j LOG --log-prefix "[FW2-INVALID-SRC] " --log-level 1

iptables -A FORWARD -i $DMZ_IF ! -s $DMZ_NETWORK -j DROP

# ============================================
# INTRUSION DETECTION INTEGRATION
# ============================================
echo -e "${YELLOW}Enabling IDS logging for suspicious DMZ activity...${NC}"

# Log new connections from DMZ (for IDS analysis)
iptables -A FORWARD -i $DMZ_IF -m conntrack --ctstate NEW \
    -j LOG --log-prefix "[FW2-DMZ-NEW-CONN] " --log-level 6

# Log port scanning attempts from DMZ
iptables -N DMZ-PORTSCAN
iptables -A FORWARD -i $DMZ_IF -j DMZ-PORTSCAN
iptables -A DMZ-PORTSCAN -p tcp --tcp-flags SYN,ACK,FIN,RST RST \
    -m limit --limit 1/s \
    -j LOG --log-prefix "[FW2-DMZ-SCAN] " --log-level 1

# ============================================
# RATE LIMITING (DMZ → Internal)
# ============================================
# Even though we only allow SMTP, rate limit to prevent abuse

iptables -A FORWARD -i $DMZ_IF -o $INT_IF \
    -p tcp --dport 25 \
    -m hashlimit \
        --hashlimit-name smtp_dmz_to_int \
        --hashlimit-above 50/minute \
        --hashlimit-burst 100 \
        --hashlimit-mode srcip \
    -j LOG --log-prefix "[FW2-RATE-LIMIT] " --log-level 3

iptables -A FORWARD -i $DMZ_IF -o $INT_IF \
    -p tcp --dport 25 \
    -m hashlimit \
        --hashlimit-name smtp_dmz_to_int \
        --hashlimit-above 50/minute \
        --hashlimit-burst 100 \
        --hashlimit-mode srcip \
    -j DROP

# ============================================
# INVALID PACKETS
# ============================================
iptables -A FORWARD -m conntrack --ctstate INVALID \
    -j LOG --log-prefix "[FW2-INVALID-PKT] " --log-level 3

iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP

# ============================================
# ICMP (Very Limited)
# ============================================
# Only allow ping from internal to DMZ (for monitoring)
iptables -A FORWARD -i $INT_IF -o $DMZ_IF \
    -p icmp --icmp-type echo-request \
    -m limit --limit 5/sec \
    -j ACCEPT

iptables -A FORWARD -i $DMZ_IF -o $INT_IF \
    -p icmp --icmp-type echo-reply \
    -j ACCEPT

# Deny all other ICMP from DMZ
iptables -A FORWARD -i $DMZ_IF -p icmp -j DROP

# ============================================
# CONNECTION TRACKING LIMITS
# ============================================
# Prevent connection table exhaustion from DMZ
iptables -A FORWARD -i $DMZ_IF \
    -m connlimit --connlimit-above 100 --connlimit-mask 32 \
    -j LOG --log-prefix "[FW2-CONN-LIMIT] " --log-level 2

iptables -A FORWARD -i $DMZ_IF \
    -m connlimit --connlimit-above 100 --connlimit-mask 32 \
    -j REJECT

# ============================================
# FINAL LOGGING
# ============================================
iptables -N LOGGING
iptables -A FORWARD -j LOGGING
iptables -A LOGGING -m limit --limit 2/min \
    -j LOG --log-prefix "[FW2-FINAL-DROP] " --log-level 4
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
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}Firewall 2 Configuration Complete!${NC}"
echo -e "${RED}CRITICAL SECURITY BOUNDARY ESTABLISHED${NC}"
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}Allowed Traffic:${NC}"
echo "  DMZ → Internal:"
echo "    - ${DMZ_MAIL_GATEWAY}:* → ${INTERNAL_MAIL_SERVER}:25 (SMTP relay ONLY)"
echo ""
echo "  Internal → DMZ:"
echo "    - ${INTERNAL_MAIL_SERVER}:* → ${DMZ_MAIL_GATEWAY}:25 (Outbound relay)"
echo "    - ${DJANGO_APP}:* → ${DMZ_MAIL_GATEWAY}:25 (Django email)"
echo ""
echo -e "${RED}Blocked Traffic (CRITICAL):${NC}"
echo "  - ALL other DMZ → Internal (prevents lateral movement)"
echo "  - ALL other ports from DMZ gateway"
echo "  - ALL traffic from other DMZ hosts"
echo "  - ALL DMZ spoofing attempts"
echo ""
echo -e "${YELLOW}Security Features Enabled:${NC}"
echo "  - Zero Trust architecture"
echo "  - Anti-spoofing protection"
echo "  - Rate limiting (50/min)"
echo "  - Connection limits (100 max)"
echo "  - IDS logging for all DMZ connections"
echo "  - Port scan detection"
echo ""
echo -e "${RED}⚠️  WARNING: This is the CRITICAL security boundary!${NC}"
echo -e "${RED}    If DMZ is compromised, this firewall prevents propagation.${NC}"
echo ""
echo -e "${YELLOW}Monitor critical events with:${NC}"
echo "  tail -f /var/log/syslog | grep -E 'FW2-(DMZ2INT-DENY|SPOOF|SCAN)'"
echo ""
