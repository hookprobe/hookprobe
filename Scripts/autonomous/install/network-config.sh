#!/bin/bash
#
# network-config.sh - HookProbe Network Configuration
# Version: 4.0 - Complete 7-POD Architecture with AI Response
#
# This file contains all network and service configuration for HookProbe
#

# ============================================================
# PHYSICAL HOST CONFIGURATION
# ============================================================
# (!!!) EDIT THESE TO MATCH YOUR ENVIRONMENT (!!!)
HOST_A_IP="192.168.1.100"              # Physical IP of Host A
HOST_B_IP="192.168.1.101"              # Physical IP of Host B (if multi-host)
PHYSICAL_HOST_INTERFACE="eth0"         # Physical network interface (use 'ip a' to find)
INTERNET_GATEWAY="192.168.1.1"         # Default gateway to internet

# ============================================================
# OVS BRIDGE CONFIGURATION
# ============================================================
OVS_MAIN_BRIDGE="ovs-br0"              # Main OVS bridge
OVS_DMZ_BRIDGE="ovs-br-dmz"            # DMZ bridge for POD 001
OVS_INTERNAL_BRIDGE="ovs-br-internal"  # Internal services bridge

# ============================================================
# VXLAN ENCRYPTION (PSK)
# ============================================================
# CRITICAL: Must be identical on all hosts in cluster
# Generate strong keys: openssl rand -base64 32
OVS_PSK_MAIN="HookProbe_Main_VXLAN_Key_2025_CHANGE_ME"
OVS_PSK_DMZ="HookProbe_DMZ_VXLAN_Key_2025_CHANGE_ME"
OVS_PSK_INTERNAL="HookProbe_Internal_VXLAN_Key_2025_CHANGE_ME"

# ============================================================
# VXLAN NETWORK IDENTIFIERS (VNI)
# ============================================================
VNI_MAIN=100                           # Main management network
VNI_DMZ=101                            # DMZ network (POD 001)
VNI_IAM=102                            # IAM network (POD 002)
VNI_DB_PERSISTENT=103                  # Persistent DB network (POD 003)
VNI_DB_TRANSIENT=104                   # Transient DB network (POD 004)
VNI_MONITORING=105                     # Monitoring network (POD 005)
VNI_SECURITY=106                       # Security/IDS network (POD 006)
VNI_AI_RESPONSE=107                    # AI Response network (POD 007)

VXLAN_PORT=4789                        # Standard VXLAN port

# ============================================================
# IP SUBNET ALLOCATION
# ============================================================
# Management Network
SUBNET_MAIN="10.100.0.0/24"
GATEWAY_MAIN="10.100.0.1"

# POD 001 - Web App/DMZ Network (Enhanced with WAF + Cloudflare)
SUBNET_POD001="10.101.0.0/24"
GATEWAY_POD001="10.101.0.1"
IP_POD001_NAXSI_WAF="10.101.0.9"        # NAXSI WAF (front-facing)
IP_POD001_DJANGO="10.101.0.10"          # Django application
IP_POD001_NGINX="10.101.0.11"           # Nginx reverse proxy
IP_POD001_CLOUDFLARED="10.101.0.12"     # Cloudflare Tunnel
IP_POD001_MODSECURITY="10.101.0.13"     # Alternative WAF (ModSecurity)
IP_POD001_RESERVED_1="10.101.0.20"      # Reserved for expansion
IP_POD001_RESERVED_2="10.101.0.21"
IP_POD001_RESERVED_3="10.101.0.22"

# POD 002 - IAM/Authentication Services Network
SUBNET_POD002="10.102.0.0/24"
GATEWAY_POD002="10.102.0.1"
IP_POD002_LOGTO="10.102.0.10"           # Logto IAM service
IP_POD002_LOGTO_DB="10.102.0.11"        # Logto PostgreSQL
IP_POD002_KEYCLOAK="10.102.0.12"        # Alternative IAM
IP_POD002_LDAP="10.102.0.13"            # LDAP for PAM integration
IP_POD002_RESERVED_1="10.102.0.20"      # Reserved for expansion
IP_POD002_RESERVED_2="10.102.0.21"
IP_POD002_RESERVED_3="10.102.0.22"

# POD 003 - Persistent Database Network
SUBNET_POD003="10.103.0.0/24"
GATEWAY_POD003="10.103.0.1"
IP_POD003_POSTGRES="10.103.0.10"        # Main PostgreSQL database
IP_POD003_NFS="10.103.0.11"             # NFS server
IP_POD003_RADIUS="10.103.0.12"          # RADIUS server
IP_POD003_RESERVED_1="10.103.0.20"      # Reserved for expansion
IP_POD003_RESERVED_2="10.103.0.21"

# POD 004 - Transient Database Network
SUBNET_POD004="10.104.0.0/24"
GATEWAY_POD004="10.104.0.1"
IP_POD004_REDIS="10.104.0.10"           # Redis cache
IP_POD004_TRANSIENT_DB="10.104.0.11"    # Transient database
IP_POD004_RESERVED_1="10.104.0.20"      # Reserved for expansion
IP_POD004_RESERVED_2="10.104.0.21"

# POD 005 - Monitoring/Development Network (Enhanced with rsyslog)
SUBNET_POD005="10.105.0.0/24"
GATEWAY_POD005="10.105.0.1"
IP_POD005_GRAFANA="10.105.0.10"         # Grafana dashboards
IP_POD005_PROMETHEUS="10.105.0.11"      # Prometheus metrics
IP_POD005_LOKI="10.105.0.12"            # Loki log storage
IP_POD005_PROMTAIL="10.105.0.13"        # Promtail log shipper
IP_POD005_ALERTMANAGER="10.105.0.14"    # Alertmanager
IP_POD005_NODE_EXPORTER="10.105.0.15"   # Node exporter (host metrics)
IP_POD005_CADVISOR="10.105.0.16"        # cAdvisor (container metrics)
IP_POD005_RSYSLOG="10.105.0.17"         # Centralized syslog server
IP_POD005_FLUENTD="10.105.0.18"         # Alternative log aggregator
IP_POD005_LEARNING="10.105.0.20"        # Development/Testing
IP_POD005_RESERVED_1="10.105.0.30"      # Reserved for expansion
IP_POD005_RESERVED_2="10.105.0.31"

# POD 006 - Security/IDS Network
SUBNET_POD006="10.106.0.0/24"
GATEWAY_POD006="10.106.0.1"
IP_POD006_IDS="10.106.0.10"             # Suricata IDS
IP_POD006_IPS="10.106.0.11"             # IPS engine
IP_POD006_FIREWALL="10.106.0.12"        # Advanced firewall
IP_POD006_RESERVED_1="10.106.0.20"      # Reserved for expansion
IP_POD006_RESERVED_2="10.106.0.21"

# POD 007 - AI Threat Response & Qsecbit Analysis
SUBNET_POD007="10.107.0.0/24"
GATEWAY_POD007="10.107.0.1"
IP_POD007_QSECBIT="10.107.0.10"         # Qsecbit analysis engine
IP_POD007_KALI="10.107.0.11"            # Kali Linux response container
IP_POD007_REDIS_CACHE="10.107.0.12"    # Redis for Qsecbit state
IP_POD007_API="10.107.0.13"             # API endpoint for Django integration
IP_POD007_RESERVED_1="10.107.0.20"      # Reserved for expansion
IP_POD007_RESERVED_2="10.107.0.21"

# ============================================================
# CONTAINER IMAGES
# ============================================================
IMAGE_DJANGO="docker.io/library/python:3.12-slim"
IMAGE_NGINX="docker.io/library/nginx:1.27-alpine"
IMAGE_POSTGRES="docker.io/library/postgres:16-alpine"
IMAGE_REDIS="docker.io/library/redis:7-alpine"
IMAGE_SURICATA="docker.io/jasonish/suricata:latest"
IMAGE_SNORT="docker.io/ciscotalos/snort3:latest"
IMAGE_LOGTO="docker.io/svhd/logto:latest"
IMAGE_GRAFANA="docker.io/grafana/grafana:latest"
IMAGE_PROMETHEUS="docker.io/prom/prometheus:latest"
IMAGE_LOKI="docker.io/grafana/loki:latest"
IMAGE_PROMTAIL="docker.io/grafana/promtail:latest"
IMAGE_ALERTMANAGER="docker.io/prom/alertmanager:latest"
IMAGE_NODE_EXPORTER="docker.io/prom/node-exporter:latest"
IMAGE_CADVISOR="gcr.io/cadvisor/cadvisor:latest"
IMAGE_CLOUDFLARED="docker.io/cloudflare/cloudflared:latest"
IMAGE_RSYSLOG="docker.io/rsyslog/syslog_appliance_alpine:latest"
IMAGE_FLUENTD="docker.io/fluent/fluentd:latest"
IMAGE_KALI="docker.io/kalilinux/kali-rolling:latest"
IMAGE_PYTHON="docker.io/library/python:3.12-slim"

# ============================================================
# DATABASE CREDENTIALS
# ============================================================
POSTGRES_DB="hookprobe_db"
POSTGRES_USER="hookprobe_admin"
POSTGRES_PASSWORD="CHANGE_ME_STRONG_PASSWORD_123"

# Logto IAM Database
LOGTO_DB="logto_db"
LOGTO_DB_USER="logto_admin"
LOGTO_DB_PASSWORD="CHANGE_ME_LOGTO_DB_PASSWORD"

# ============================================================
# DJANGO CONFIGURATION
# ============================================================
DJANGO_SECRET_KEY="CHANGE_ME_DJANGO_SECRET_KEY_LONG_RANDOM_STRING"
DJANGO_DEBUG="False"
DJANGO_ALLOWED_HOSTS="*"  # Change in production

# ============================================================
# LOGTO IAM CONFIGURATION
# ============================================================
LOGTO_ENDPOINT="http://10.102.0.10:3001"
LOGTO_ADMIN_ENDPOINT="http://10.102.0.10:3002"

# ============================================================
# CLOUDFLARE TUNNEL CONFIGURATION
# ============================================================
# (!!!) CHANGE THESE - Get from Cloudflare Zero Trust Dashboard (!!!)
CLOUDFLARE_TUNNEL_TOKEN="CHANGE_ME_GET_FROM_CLOUDFLARE_DASHBOARD"
CLOUDFLARE_TUNNEL_NAME="hookprobe-tunnel"
CLOUDFLARE_DOMAIN="your-domain.com"  # Your Cloudflare domain

# ============================================================
# RSYSLOG CONFIGURATION
# ============================================================
RSYSLOG_PORT=514                        # Standard syslog port
RSYSLOG_TLS_PORT=6514                   # TLS syslog port

# ============================================================
# WAF CONFIGURATION
# ============================================================
# NAXSI WAF Rules
NAXSI_LEARNING_MODE="0"                 # 0=blocking, 1=learning
NAXSI_EXTENSIVE_LOG="1"                 # Detailed logging

# ============================================================
# QSECBIT AI RESPONSE CONFIGURATION
# ============================================================
# Qsecbit thresholds (matches Python script)
QSECBIT_ALPHA=0.30                     # System drift weight
QSECBIT_BETA=0.30                      # Attack probability weight
QSECBIT_GAMMA=0.20                     # Classifier decay weight
QSECBIT_DELTA=0.20                     # Quantum drift weight
QSECBIT_AMBER_THRESHOLD=0.45           # Amber alert threshold
QSECBIT_RED_THRESHOLD=0.70             # Red alert threshold

# Qsecbit baseline (adjust based on your environment)
QSECBIT_BASELINE_MU="0.1,0.2,0.15,0.33"  # CPU, Memory, Network, Disk I/O
QSECBIT_QUANTUM_ANCHOR=6.144           # Baseline entropy

# AI Response configuration
QSECBIT_CHECK_INTERVAL=30              # Seconds between Qsecbit calculations
KALI_AUTO_RESPONSE=true                # Enable automated countermeasures
KALI_REQUIRE_APPROVAL=false            # Require human approval for responses

# Kali Linux On-Demand Configuration
KALI_ON_DEMAND=true                    # Spin up Kali only when needed
KALI_SPIN_UP_THRESHOLD="AMBER"         # Spin up on AMBER or RED
KALI_COOLDOWN_MINUTES=30               # Keep Kali running for X minutes after last alert
KALI_AUTO_SHUTDOWN=true                # Automatically shutdown after cooldown

# Attack Response Configuration
ENABLE_ANTI_XSS=true                   # Enable XSS attack mitigation
ENABLE_ANTI_SQLI=true                  # Enable SQL injection mitigation
ENABLE_MEMORY_PROTECTION=true          # Enable memory attack protection
AUTO_UPDATE_WAF_RULES=true             # Automatically update WAF rules
AUTO_BLOCK_ATTACKER_IP=true            # Automatically block attacker IPs
CREATE_DB_SNAPSHOTS=true               # Create DB snapshots before mitigation

# API Configuration
QSECBIT_API_PORT=8888                  # API port for Django integration

# ============================================================
# VOLUME NAMES
# ============================================================
VOLUME_POSTGRES_DATA="hookprobe-postgres-data"
VOLUME_DJANGO_STATIC="hookprobe-django-static"
VOLUME_DJANGO_MEDIA="hookprobe-django-media"
VOLUME_NGINX_CONF="hookprobe-nginx-conf"
VOLUME_MONITORING_DATA="hookprobe-monitoring-data"
VOLUME_IDS_LOGS="hookprobe-ids-logs"
VOLUME_LOGTO_DB="hookprobe-logto-db"
VOLUME_GRAFANA_DATA="hookprobe-grafana-data"
VOLUME_PROMETHEUS_DATA="hookprobe-prometheus-data"
VOLUME_LOKI_DATA="hookprobe-loki-data"
VOLUME_ALERTMANAGER_DATA="hookprobe-alertmanager-data"
VOLUME_RSYSLOG_DATA="hookprobe-rsyslog-data"
VOLUME_WAF_LOGS="hookprobe-waf-logs"
VOLUME_CLOUDFLARED_CREDS="hookprobe-cloudflared-creds"
VOLUME_QSECBIT_DATA="hookprobe-qsecbit-data"
VOLUME_QSECBIT_MODELS="hookprobe-qsecbit-models"
VOLUME_KALI_TOOLS="hookprobe-kali-tools"
VOLUME_KALI_REPORTS="hookprobe-kali-reports"

# ============================================================
# POD NAMES
# ============================================================
POD_001_NAME="hookprobe-pod-001-web-dmz"
POD_002_NAME="hookprobe-pod-002-iam"
POD_003_NAME="hookprobe-pod-003-db-persistent"
POD_004_NAME="hookprobe-pod-004-db-transient"
POD_005_NAME="hookprobe-pod-005-monitoring"
POD_006_NAME="hookprobe-pod-006-security"
POD_007_NAME="hookprobe-pod-007-ai-response"

# ============================================================
# NETWORK NAMES (PODMAN)
# ============================================================
NETWORK_POD001="pod001-dmz-net"
NETWORK_POD002="pod002-iam-net"
NETWORK_POD003="pod003-db-persistent-net"
NETWORK_POD004="pod004-db-transient-net"
NETWORK_POD005="pod005-monitoring-net"
NETWORK_POD006="pod006-security-net"
NETWORK_POD007="pod007-ai-response-net"

# ============================================================
# PORT MAPPINGS (Host -> Container)
# ============================================================
# POD 001 - Web/DMZ
PORT_HTTP=80
PORT_HTTPS=443
PORT_WAF=8080                           # NAXSI WAF management

# POD 002 - IAM
PORT_LOGTO=3001
PORT_LOGTO_ADMIN=3002

# POD 003 - Databases
PORT_POSTGRES=5432
PORT_RADIUS=1812

# POD 005 - Monitoring
PORT_GRAFANA=3000
PORT_PROMETHEUS=9090
PORT_ALERTMANAGER=9093
PORT_LOKI=3100
PORT_RSYSLOG=514
PORT_RSYSLOG_TLS=6514

# POD 007 - AI Response
PORT_QSECBIT_API=8888

# ============================================================
# HELPER FUNCTIONS
# ============================================================

# Function to validate IP address format
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        echo "ERROR: Invalid IP address format: $ip"
        return 1
    fi
}

# Function to check if subnet is valid
validate_subnet() {
    local subnet=$1
    if [[ $subnet =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        return 0
    else
        echo "ERROR: Invalid subnet format: $subnet"
        return 1
    fi
}

# Export all variables
export HOST_A_IP HOST_B_IP PHYSICAL_HOST_INTERFACE INTERNET_GATEWAY
export OVS_MAIN_BRIDGE OVS_DMZ_BRIDGE OVS_INTERNAL_BRIDGE
export OVS_PSK_MAIN OVS_PSK_DMZ OVS_PSK_INTERNAL
export VNI_MAIN VNI_DMZ VNI_IAM VNI_DB_PERSISTENT VNI_DB_TRANSIENT VNI_MONITORING VNI_SECURITY VNI_AI_RESPONSE
export VXLAN_PORT
export SUBNET_MAIN GATEWAY_MAIN
export SUBNET_POD001 GATEWAY_POD001 IP_POD001_NAXSI_WAF IP_POD001_DJANGO IP_POD001_NGINX IP_POD001_CLOUDFLARED
export SUBNET_POD002 GATEWAY_POD002 IP_POD002_LOGTO IP_POD002_LOGTO_DB IP_POD002_KEYCLOAK IP_POD002_LDAP
export SUBNET_POD003 GATEWAY_POD003 IP_POD003_POSTGRES IP_POD003_NFS IP_POD003_RADIUS
export SUBNET_POD004 GATEWAY_POD004 IP_POD004_REDIS IP_POD004_TRANSIENT_DB
export SUBNET_POD005 GATEWAY_POD005 IP_POD005_GRAFANA IP_POD005_PROMETHEUS IP_POD005_LOKI IP_POD005_PROMTAIL IP_POD005_ALERTMANAGER IP_POD005_RSYSLOG
export SUBNET_POD006 GATEWAY_POD006 IP_POD006_IDS IP_POD006_IPS IP_POD006_FIREWALL
export SUBNET_POD007 GATEWAY_POD007 IP_POD007_QSECBIT IP_POD007_KALI IP_POD007_REDIS_CACHE IP_POD007_API
export POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD
export LOGTO_DB LOGTO_DB_USER LOGTO_DB_PASSWORD
export LOGTO_ENDPOINT LOGTO_ADMIN_ENDPOINT
export DJANGO_SECRET_KEY DJANGO_DEBUG DJANGO_ALLOWED_HOSTS
export CLOUDFLARE_TUNNEL_TOKEN CLOUDFLARE_TUNNEL_NAME CLOUDFLARE_DOMAIN
export RSYSLOG_PORT RSYSLOG_TLS_PORT
export NAXSI_LEARNING_MODE NAXSI_EXTENSIVE_LOG
export QSECBIT_ALPHA QSECBIT_BETA QSECBIT_GAMMA QSECBIT_DELTA
export QSECBIT_AMBER_THRESHOLD QSECBIT_RED_THRESHOLD
export QSECBIT_BASELINE_MU QSECBIT_QUANTUM_ANCHOR
export QSECBIT_CHECK_INTERVAL KALI_AUTO_RESPONSE KALI_REQUIRE_APPROVAL
export QSECBIT_API_PORT

echo "============================================================"
echo "   HOOKPROBE NETWORK CONFIGURATION LOADED - v4.0"
echo "============================================================"
echo "Network Topology:"
echo "  Main Management: $SUBNET_MAIN"
echo "  POD 001 (Web DMZ + WAF): $SUBNET_POD001"
echo "  POD 002 (IAM): $SUBNET_POD002"
echo "  POD 003 (DB Persistent): $SUBNET_POD003"
echo "  POD 004 (DB Transient): $SUBNET_POD004"
echo "  POD 005 (Monitoring + Logging): $SUBNET_POD005"
echo "  POD 006 (Security): $SUBNET_POD006"
echo "  POD 007 (AI Response): $SUBNET_POD007"
echo ""
echo "VXLAN Configuration:"
echo "  VNI 100: Management"
echo "  VNI 101: DMZ (PSK: DMZ)"
echo "  VNI 102: IAM (PSK: Main)"
echo "  VNI 103: DB Persistent (PSK: Internal)"
echo "  VNI 104: DB Transient (PSK: Internal)"
echo "  VNI 105: Monitoring (PSK: Main)"
echo "  VNI 106: Security (PSK: Internal)"
echo "  VNI 107: AI Response (PSK: Internal)"
echo ""
echo "Key Services:"
echo "  NAXSI WAF: ${IP_POD001_NAXSI_WAF}"
echo "  Django CMS: ${IP_POD001_DJANGO}"
echo "  Cloudflare Tunnel: ${IP_POD001_CLOUDFLARED}"
echo "  Logto IAM: ${IP_POD002_LOGTO}"
echo "  PostgreSQL: ${IP_POD003_POSTGRES}"
echo "  Redis: ${IP_POD004_REDIS}"
echo "  Grafana: ${IP_POD005_GRAFANA}"
echo "  Prometheus: ${IP_POD005_PROMETHEUS}"
echo "  Loki: ${IP_POD005_LOKI}"
echo "  Rsyslog: ${IP_POD005_RSYSLOG}"
echo "  Qsecbit AI: ${IP_POD007_QSECBIT}"
echo "  Kali Linux: ${IP_POD007_KALI}"
echo ""
echo "Security Features:"
echo "  ✓ NAXSI WAF (Web Application Firewall)"
echo "  ✓ Cloudflare Tunnel (Zero Trust Access)"
echo "  ✓ Centralized Syslog Server"
echo "  ✓ Enhanced Log Aggregation"
echo "  ✓ PSK-Encrypted VXLAN Tunnels"
echo "  ✓ Qsecbit AI Analysis"
echo "  ✓ Automated Kali Linux Response"
echo "============================================================"
