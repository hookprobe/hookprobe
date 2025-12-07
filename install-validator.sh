#!/bin/bash
#
# install-validator.sh - HookProbe Liberty Validator Installation
#
# CRITICAL: This script can ONLY be run AFTER MSSP Cloud is deployed.
# Validators require KYC verification and MSSP cloud infrastructure.
#
# Prerequisites:
# 1. MSSP Cloud must be deployed and operational
# 2. KYC documentation prepared
# 3. Hardware meets minimum requirements
#
# Usage:
#   sudo ./install-validator.sh --mssp-url https://mssp.hookprobe.com
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
MSSP_URL=""
VALIDATOR_ID=""
KYC_EMAIL=""
INSTALL_DIR="/opt/hookprobe"
CONFIG_DIR="/etc/hookprobe"
DATA_DIR="/var/lib/hookprobe"

# ============================================================
# BANNER
# ============================================================

show_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
    ╦ ╦╔═╗╔═╗╦╔═╔═╗╦═╗╔═╗╔╗ ╔═╗
    ╠═╣║ ║║ ║╠╩╗╠═╝╠╦╝║ ║╠╩╗║╣
    ╩ ╩╚═╝╚═╝╩ ╩╩  ╩╚═╚═╝╚═╝╚═╝

    LIBERTY VALIDATOR INSTALLATION
    Production-Ready Distributed Validation
EOF
    echo -e "${NC}"
}

# ============================================================
# PREREQUISITE CHECKS
# ============================================================

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}ERROR: This script must be run as root${NC}"
        echo "Please run: sudo $0"
        exit 1
    fi
}

check_mssp_url() {
    if [ -z "$MSSP_URL" ]; then
        echo -e "${RED}ERROR: MSSP URL not provided${NC}"
        echo "Usage: $0 --mssp-url https://mssp.hookprobe.com"
        exit 1
    fi
}

check_mssp_cloud_deployed() {
    echo -e "${YELLOW}Checking MSSP Cloud deployment...${NC}"

    # Try to connect to MSSP API
    if ! curl -f -s -o /dev/null --connect-timeout 10 "${MSSP_URL}/api/v1/health"; then
        echo -e "${RED}✗ CRITICAL ERROR: MSSP Cloud is NOT deployed or unreachable${NC}"
        echo ""
        echo "Validators CANNOT be installed without MSSP Cloud infrastructure."
        echo ""
        echo "Required steps:"
        echo "  1. Deploy MSSP Cloud first: sudo ./install.sh --role cloud"
        echo "  2. Verify MSSP is running: ${MSSP_URL}/api/v1/health"
        echo "  3. Then retry validator installation"
        echo ""
        exit 1
    fi

    echo -e "${GREEN}✓ MSSP Cloud is operational${NC}"

    # Get MSSP version
    MSSP_VERSION=$(curl -s "${MSSP_URL}/api/v1/version" | jq -r '.version' 2>/dev/null || echo "unknown")
    echo "  MSSP Version: ${MSSP_VERSION}"
}

check_hardware_requirements() {
    echo -e "${YELLOW}Checking hardware requirements...${NC}"

    # CPU cores
    CPU_CORES=$(nproc)
    if [ "$CPU_CORES" -lt 4 ]; then
        echo -e "${RED}✗ Insufficient CPU cores: ${CPU_CORES} (minimum: 4)${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ CPU: ${CPU_CORES} cores${NC}"

    # RAM
    RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$RAM_GB" -lt 8 ]; then
        echo -e "${RED}✗ Insufficient RAM: ${RAM_GB}GB (minimum: 8GB)${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ RAM: ${RAM_GB}GB${NC}"

    # Disk space
    DISK_GB=$(df / | tail -1 | awk '{print int($4/1024/1024)}')
    if [ "$DISK_GB" -lt 100 ]; then
        echo -e "${YELLOW}⚠ Low disk space: ${DISK_GB}GB (recommended: 100GB+)${NC}"
    else
        echo -e "${GREEN}✓ Disk: ${DISK_GB}GB available${NC}"
    fi
}

# ============================================================
# KYC COLLECTION
# ============================================================

collect_kyc_information() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  KYC VERIFICATION REQUIRED FOR VALIDATORS     ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Validators require KYC (Know Your Customer) verification to ensure"
    echo "network integrity and comply with security policies."
    echo ""

    read -p "Organization Name: " ORG_NAME
    read -p "Contact Email: " KYC_EMAIL
    read -p "Country: " COUNTRY
    read -p "Geographic Region (e.g., us-east, eu-west): " GEO_REGION

    echo ""
    echo -e "${YELLOW}KYC Documentation:${NC}"
    echo "  Organization: ${ORG_NAME}"
    echo "  Email: ${KYC_EMAIL}"
    echo "  Country: ${COUNTRY}"
    echo "  Region: ${GEO_REGION}"
    echo ""

    read -p "Is this information correct? (yes/no): " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        echo -e "${RED}KYC collection cancelled${NC}"
        exit 1
    fi
}

# ============================================================
# HARDWARE FINGERPRINT
# ============================================================

generate_hardware_fingerprint() {
    echo -e "${YELLOW}Generating hardware fingerprint...${NC}"

    # Create fingerprint script
    cat > /tmp/hw_fingerprint.py << 'HWFP_SCRIPT'
import sys
sys.path.insert(0, '/opt/hookprobe/src')

from neuro.identity.hardware_fingerprint import HardwareFingerprintGenerator
import json

generator = HardwareFingerprintGenerator()
fingerprint = generator.generate()

print(json.dumps({
    'fingerprint_id': fingerprint.fingerprint_id,
    'cpu_id': fingerprint.cpu_id,
    'mac_addresses': fingerprint.mac_addresses,
    'disk_serials': fingerprint.disk_serials,
    'dmi_uuid': fingerprint.dmi_uuid,
    'hostname': fingerprint.hostname
}))
HWFP_SCRIPT

    HW_FP_JSON=$(python3 /tmp/hw_fingerprint.py)
    HW_FINGERPRINT=$(echo "$HW_FP_JSON" | jq -r '.fingerprint_id')

    echo -e "${GREEN}✓ Hardware Fingerprint: ${HW_FINGERPRINT:0:32}...${NC}"

    rm -f /tmp/hw_fingerprint.py
}

# ============================================================
# REGISTRATION WITH MSSP
# ============================================================

register_with_mssp() {
    echo -e "${YELLOW}Registering validator with MSSP...${NC}"

    # Generate validator ID
    VALIDATOR_ID="validator-$(uuidgen | cut -d'-' -f1)"

    # Generate Ed25519 key pair
    python3 << KEYGEN
from cryptography.hazmat.primitives.asymmetric import ed25519
import json

private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Save keys
with open('$CONFIG_DIR/validator_private_key.pem', 'wb') as f:
    from cryptography.hazmat.primitives import serialization
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open('$CONFIG_DIR/validator_public_key.pem', 'wb') as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print(public_key.public_bytes_raw().hex())
KEYGEN

    PUBLIC_KEY=$(cat $CONFIG_DIR/validator_public_key.pem | grep -v "BEGIN\|END" | tr -d '\n')

    # Get IP address
    IP_ADDRESS=$(curl -s ifconfig.me)

    # Register with MSSP
    REGISTRATION_DATA=$(cat <<EOF
{
  "device_id": "${VALIDATOR_ID}",
  "device_type": "validator",
  "hardware_fingerprint": "${HW_FINGERPRINT}",
  "public_key_ed25519": "${PUBLIC_KEY}",
  "firmware_version": "1.0.0",
  "location": {
    "ip_address": "${IP_ADDRESS}",
    "country": "${COUNTRY}",
    "region": "${GEO_REGION}",
    "city": "",
    "latitude": 0.0,
    "longitude": 0.0,
    "asn": 0,
    "isp": ""
  },
  "kyc": {
    "organization": "${ORG_NAME}",
    "email": "${KYC_EMAIL}",
    "country": "${COUNTRY}"
  }
}
EOF
)

    RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$REGISTRATION_DATA" \
        "${MSSP_URL}/api/v1/devices/register")

    STATUS=$(echo "$RESPONSE" | jq -r '.status' 2>/dev/null || echo "error")

    if [ "$STATUS" != "pending" ]; then
        echo -e "${RED}✗ Registration failed${NC}"
        echo "Response: $RESPONSE"
        exit 1
    fi

    echo -e "${GREEN}✓ Validator registered (status: PENDING)${NC}"
    echo "  Validator ID: ${VALIDATOR_ID}"
    echo ""
    echo -e "${YELLOW}IMPORTANT: Your validator is pending KYC approval${NC}"
    echo "  1. MSSP admin will review your KYC documentation"
    echo "  2. You will receive email confirmation at: ${KYC_EMAIL}"
    echo "  3. Once approved, your validator will become ACTIVE"
    echo ""
}

# ============================================================
# INSTALLATION
# ============================================================

install_dependencies() {
    echo -e "${YELLOW}Installing dependencies...${NC}"

    apt-get update -qq
    apt-get install -y -qq \
        python3-pip \
        python3-dev \
        build-essential \
        libssl-dev \
        libffi-dev \
        sqlite3 \
        jq \
        curl \
        net-tools \
        uuid-runtime

    pip3 install -q \
        cryptography \
        chacha20poly1305 \
        maxminddb \
        geoip2

    echo -e "${GREEN}✓ Dependencies installed${NC}"
}

install_hookprobe_validator() {
    echo -e "${YELLOW}Installing HookProbe Liberty Validator...${NC}"

    # Create directories
    mkdir -p $INSTALL_DIR
    mkdir -p $CONFIG_DIR
    mkdir -p $DATA_DIR/validator
    mkdir -p $DATA_DIR/merkle-log

    # Copy source files (assume we're in hookprobe repo)
    if [ -d "core" ]; then
        cp -r core/* $INSTALL_DIR/
        cp -r shared/* $INSTALL_DIR/
        echo -e "${GREEN}✓ Source files installed${NC}"
    else
        echo -e "${RED}✗ Core directory not found${NC}"
        exit 1
    fi

    # Create validator configuration
    cat > $CONFIG_DIR/validator.conf << CONF
[validator]
validator_id = ${VALIDATOR_ID}
mssp_url = ${MSSP_URL}
listen_port = 4478

[hardware]
fingerprint = ${HW_FINGERPRINT}

[kyc]
organization = ${ORG_NAME}
email = ${KYC_EMAIL}
country = ${COUNTRY}
region = ${GEO_REGION}

[network]
heartbeat_interval = 30
session_timeout = 300

[paths]
data_dir = ${DATA_DIR}/validator
merkle_log = ${DATA_DIR}/merkle-log
keys_dir = ${CONFIG_DIR}
CONF

    echo -e "${GREEN}✓ Validator configured${NC}"
}

create_systemd_service() {
    echo -e "${YELLOW}Creating systemd service...${NC}"

    cat > /etc/systemd/system/hookprobe-validator.service << SERVICE
[Unit]
Description=HookProbe Liberty Validator
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/python3 -m neuro.validation.validator_service
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE

    systemctl daemon-reload
    systemctl enable hookprobe-validator.service

    echo -e "${GREEN}✓ Systemd service created${NC}"
}

# ============================================================
# POST-INSTALL
# ============================================================

show_post_install_instructions() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  VALIDATOR INSTALLATION COMPLETE               ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Validator ID:${NC} ${VALIDATOR_ID}"
    echo -e "${BLUE}Status:${NC} PENDING (awaiting KYC approval)"
    echo -e "${BLUE}Hardware FP:${NC} ${HW_FINGERPRINT:0:32}..."
    echo ""
    echo -e "${YELLOW}Next Steps:${NC}"
    echo ""
    echo "  1. Wait for KYC approval email at: ${KYC_EMAIL}"
    echo "  2. Once approved, start the validator:"
    echo "     ${GREEN}sudo systemctl start hookprobe-validator${NC}"
    echo "  3. Monitor logs:"
    echo "     ${GREEN}sudo journalctl -u hookprobe-validator -f${NC}"
    echo "  4. Check status:"
    echo "     ${GREEN}curl ${MSSP_URL}/api/v1/validators/${VALIDATOR_ID}${NC}"
    echo ""
    echo -e "${YELLOW}Configuration:${NC}"
    echo "  Config: ${CONFIG_DIR}/validator.conf"
    echo "  Keys: ${CONFIG_DIR}/validator_*.pem"
    echo "  Data: ${DATA_DIR}/validator"
    echo ""
    echo -e "${BLUE}HookProbe Liberty Validator - Production Ready${NC}"
    echo ""
}

# ============================================================
# MAIN
# ============================================================

main() {
    show_banner

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --mssp-url)
                MSSP_URL="$2"
                shift 2
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Run checks and installation
    check_root
    check_mssp_url
    check_mssp_cloud_deployed
    check_hardware_requirements
    collect_kyc_information
    install_dependencies
    generate_hardware_fingerprint
    install_hookprobe_validator
    register_with_mssp
    create_systemd_service
    show_post_install_instructions
}

main "$@"
