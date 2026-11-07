#!/bin/bash
#
# DKIM (DomainKeys Identified Mail) Setup
# HookProbe POD-009 - DMZ Mail Gateway
#
# Purpose: Sign outbound emails to prevent spoofing
#

set -e

# Color output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}[POD-009] Setting up DKIM signing${NC}"

DOMAIN="hookprobe.com"
SELECTOR="default"
DKIM_DIR="/etc/postfix/dkim"
KEY_SIZE=2048

# ============================================
# INSTALL OPENDKIM
# ============================================
echo -e "${YELLOW}Installing OpenDKIM...${NC}"
apt-get update
apt-get install -y opendkim opendkim-tools

# ============================================
# CREATE DIRECTORIES
# ============================================
mkdir -p $DKIM_DIR/keys/$DOMAIN
chown -R opendkim:opendkim $DKIM_DIR

# ============================================
# GENERATE DKIM KEYS
# ============================================
echo -e "${YELLOW}Generating DKIM key pair (RSA ${KEY_SIZE})...${NC}"

opendkim-genkey \
    -b $KEY_SIZE \
    -d $DOMAIN \
    -s $SELECTOR \
    -D $DKIM_DIR/keys/$DOMAIN

# Set permissions
chown opendkim:opendkim $DKIM_DIR/keys/$DOMAIN/$SELECTOR.private
chmod 600 $DKIM_DIR/keys/$DOMAIN/$SELECTOR.private

# ============================================
# OPENDKIM CONFIGURATION
# ============================================
echo -e "${YELLOW}Configuring OpenDKIM...${NC}"

cat > /etc/opendkim.conf <<EOF
# OpenDKIM Configuration
# HookProbe POD-009

# Logging
Syslog yes
SyslogSuccess yes
LogWhy yes

# Common settings
Canonicalization relaxed/simple
Mode sv
SubDomains no

# Signing
Domain $DOMAIN
Selector $SELECTOR
KeyFile $DKIM_DIR/keys/$DOMAIN/$SELECTOR.private

# Socket for Postfix integration
Socket inet:8891@localhost

# User/Group
UserID opendkim:opendkim

# Trusted hosts (can relay without signing)
InternalHosts /etc/opendkim/TrustedHosts
ExternalIgnoreList /etc/opendkim/TrustedHosts

# Security
RequireSafeKeys yes

# Performance
SignatureAlgorithm rsa-sha256
MinimumKeyBits 1024
EOF

# ============================================
# TRUSTED HOSTS
# ============================================
mkdir -p /etc/opendkim
cat > /etc/opendkim/TrustedHosts <<EOF
# Trusted hosts that can send mail through this server
127.0.0.1
localhost
10.200.1.0/24
10.200.9.0/24
*.hookprobe.com
*.hookprobe.local
EOF

# ============================================
# POSTFIX INTEGRATION
# ============================================
echo -e "${YELLOW}Configuring Postfix integration...${NC}"

# Add to Postfix main.cf
cat >> /etc/postfix/main.cf <<EOF

# DKIM Signing via OpenDKIM
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:localhost:8891
non_smtpd_milters = \$smtpd_milters
EOF

# ============================================
# SYSTEMD SERVICE
# ============================================
systemctl enable opendkim
systemctl restart opendkim

echo -e "${GREEN}OpenDKIM started successfully${NC}"

# ============================================
# DNS RECORD OUTPUT
# ============================================
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}DKIM Setup Complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}⚠️  IMPORTANT: Add this DNS TXT record to your domain:${NC}"
echo ""
echo "Record Name:"
echo "  ${SELECTOR}._domainkey.${DOMAIN}"
echo ""
echo "Record Type:"
echo "  TXT"
echo ""
echo "Record Value:"
cat $DKIM_DIR/keys/$DOMAIN/$SELECTOR.txt
echo ""
echo -e "${YELLOW}Example DNS configuration:${NC}"
echo ""
cat $DKIM_DIR/keys/$DOMAIN/$SELECTOR.txt | sed 's/^/  /'
echo ""
echo -e "${GREEN}After adding the DNS record, verify with:${NC}"
echo "  opendkim-testkey -d $DOMAIN -s $SELECTOR -vvv"
echo ""
echo -e "${GREEN}Test DKIM signing:${NC}"
echo "  echo 'Test email' | mail -s 'DKIM Test' user@example.com"
echo "  # Check email headers for DKIM-Signature"
echo ""

# ============================================
# SAVE KEY INFO
# ============================================
cat > $DKIM_DIR/key-info.txt <<EOF
DKIM Configuration for $DOMAIN
================================

Selector: $SELECTOR
Key Size: $KEY_SIZE bits
Algorithm: RSA-SHA256

Private Key: $DKIM_DIR/keys/$DOMAIN/$SELECTOR.private
Public Key (DNS): $DKIM_DIR/keys/$DOMAIN/$SELECTOR.txt

DNS Record to Add:
------------------
$(cat $DKIM_DIR/keys/$DOMAIN/$SELECTOR.txt)

Verification Command:
---------------------
opendkim-testkey -d $DOMAIN -s $SELECTOR -vvv

Testing:
--------
Send a test email and check for DKIM-Signature header
Use online tools like mail-tester.com to verify DKIM

Created: $(date)
EOF

echo -e "${GREEN}Key information saved to: $DKIM_DIR/key-info.txt${NC}"
echo ""
