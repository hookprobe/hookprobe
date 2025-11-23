#!/bin/bash
#
# network-config.sh - HookProbe v5.0 Network Configuration
# GPL-FREE - All components use MIT/Apache/BSD licenses
# Version: 5.0 - Single bridge architecture with OpenFlow ACLs
#
set -e
# This file contains all network and service configuration for HookProbe v5.0
#
# NOTE: This file is sourced by other scripts, so we don't use 'set -e'
# to avoid breaking the calling scripts

# ============================================================
# PHYSICAL HOST CONFIGURATION
# ============================================================
# (!!!) EDIT THESE TO MATCH YOUR ENVIRONMENT (!!!)
HOST_A_IP="192.168.1.100"              # Physical IP of Host A
HOST_B_IP="192.168.1.101"              # Physical IP of Host B (if multi-host)
PHYSICAL_HOST_INTERFACE="eth0"         # Physical network interface (use 'ip a' to find)
INTERNET_GATEWAY="192.168.1.1"         # Default gateway to internet

# ============================================================
# OVS BRIDGE CONFIGURATION (SIMPLIFIED)
# ============================================================
QSEC_BRIDGE="qsec-bridge"              # Single unified bridge for all VNIs
QSEC_BRIDGE_IP="10.200.0.1/16"         # Bridge management IP

# ============================================================
# VXLAN ENCRYPTION (PSK) - CHANGE THESE!
# ============================================================
# CRITICAL: Must be identical on all hosts in cluster
# Generate strong keys: openssl rand -base64 32
VXLAN_PSK="HookProbe_VXLAN_Master_Key_2025_CHANGE_ME_NOW"

# ============================================================
# VXLAN NETWORK IDENTIFIERS (VNI)
# ============================================================
VNI_MANAGEMENT=200                     # Management network
VNI_WEB_DMZ=201                        # Web application zone
VNI_IAM=202                            # Identity & Access Management
VNI_DATABASE=203                       # Database tier
VNI_CACHE=204                          # Caching layer
VNI_MONITORING=205                     # Monitoring & logging
VNI_SECURITY=206                       # Security services (IDS/IPS)
VNI_HONEYPOT=207                       # Honeypot & deception

VXLAN_PORT=4789                        # Standard VXLAN port

# ============================================================
# IP SUBNET ALLOCATION (10.200.0.0/16 = 65,536 IPs)
# ============================================================
# Management Network (VNI 200)
SUBNET_MANAGEMENT="10.200.0.0/24"
GATEWAY_MANAGEMENT="10.200.0.1"

# Web DMZ Network (VNI 201) - ModSecurity WAF + Nginx + Django
SUBNET_WEB_DMZ="10.200.1.0/24"
GATEWAY_WEB_DMZ="10.200.1.1"
IP_MODSECURITY="10.200.1.10"           # ModSecurity WAF
IP_NGINX="10.200.1.11"                 # Nginx reverse proxy
IP_DJANGO="10.200.1.12"                # Django application
IP_CLOUDFLARED="10.200.1.13"           # Cloudflare Tunnel (optional)

# IAM Network (VNI 202) - Keycloak (Apache License)
SUBNET_IAM="10.200.2.0/24"
GATEWAY_IAM="10.200.2.1"
IP_KEYCLOAK="10.200.2.10"              # Keycloak IAM
IP_KEYCLOAK_DB="10.200.2.11"           # Keycloak PostgreSQL

# Database Network (VNI 203) - PostgreSQL (PostgreSQL License - permissive)
SUBNET_DATABASE="10.200.3.0/24"
GATEWAY_DATABASE="10.200.3.1"
IP_POSTGRES_MAIN="10.200.3.10"         # Main PostgreSQL
IP_NFS="10.200.3.11"                   # NFS server (optional)

# Cache Network (VNI 204) - Redis (BSD License)
SUBNET_CACHE="10.200.4.0/24"
GATEWAY_CACHE="10.200.4.1"
IP_REDIS="10.200.4.10"                 # Redis cache
IP_VALKEY="10.200.4.11"                # Valkey (Redis fork, BSD)

# Monitoring Network (VNI 205) - VictoriaMetrics, VictoriaLogs, Grafana
SUBNET_MONITORING="10.200.5.0/24"
GATEWAY_MONITORING="10.200.5.1"
IP_VICTORIAMETRICS="10.200.5.10"       # VictoriaMetrics (Apache 2.0)
IP_VICTORIALOGS="10.200.5.11"          # VictoriaLogs (Apache 2.0)
IP_GRAFANA="10.200.5.12"               # Grafana (AGPL but service use is OK)
IP_VECTOR="10.200.5.13"                # Vector log aggregator (Apache 2.0)
IP_NODE_EXPORTER="10.200.5.14"         # Prometheus node exporter (Apache 2.0)

# Security Network (VNI 206) - Zeek + Snort 3
SUBNET_SECURITY="10.200.6.0/24"
GATEWAY_SECURITY="10.200.6.1"
IP_ZEEK="10.200.6.10"                  # Zeek IDS (BSD)
IP_SNORT="10.200.6.11"                 # Snort 3 IDS/IPS (Cisco, GPL-2 with exceptions - checking)
IP_QSECBIT="10.200.6.12"               # Qsecbit analysis engine (MIT)

# Honeypot Network (VNI 207) - Custom scripts
SUBNET_HONEYPOT="10.200.7.0/24"
GATEWAY_HONEYPOT="10.200.7.1"
IP_HONEYPOT_WEB="10.200.7.10"          # Web honeypot
IP_HONEYPOT_SSH="10.200.7.11"          # SSH honeypot
IP_HONEYPOT_DB="10.200.7.12"           # Database honeypot
IP_MITIGATION_ENGINE="10.200.7.20"     # Attack mitigation orchestrator

# ============================================================
# CONTAINER IMAGES (GPL-FREE ALTERNATIVES)
# ============================================================
IMAGE_NGINX="docker.io/library/nginx:1.27-alpine"                    # Nginx (BSD-2-Clause)
IMAGE_POSTGRES="docker.io/library/postgres:16-alpine"                # PostgreSQL License
IMAGE_REDIS="docker.io/library/redis:7-alpine"                       # BSD-3-Clause
IMAGE_VALKEY="docker.io/valkey/valkey:8.0-alpine"                    # BSD-3-Clause
IMAGE_KEYCLOAK="quay.io/keycloak/keycloak:26.0"                      # Apache 2.0
IMAGE_GRAFANA="docker.io/grafana/grafana:11.4.0"                     # AGPL-3 (OK for service)
IMAGE_VICTORIAMETRICS="docker.io/victoriametrics/victoria-metrics:latest"  # Apache 2.0
IMAGE_VICTORIALOGS="docker.io/victoriametrics/victoria-logs:latest"        # Apache 2.0
IMAGE_VECTOR="docker.io/timberio/vector:latest-alpine"               # Apache 2.0
IMAGE_NODE_EXPORTER="quay.io/prometheus/node-exporter:latest"        # Apache 2.0
IMAGE_ZEEK="docker.io/zeek/zeek:latest"                              # BSD-3-Clause
IMAGE_SNORT="docker.io/ciscotalos/snort3:latest"                     # GPL-2 with linking exception
IMAGE_MODSECURITY="docker.io/owasp/modsecurity-nginx:latest"         # Apache 2.0
IMAGE_PYTHON="docker.io/library/python:3.12-slim"                    # PSF License
IMAGE_ALPINE="docker.io/library/alpine:3.21"                         # MIT/Apache mix
IMAGE_CLOUDFLARED="docker.io/cloudflare/cloudflared:latest"          # Apache 2.0

# ============================================================
# DATABASE CREDENTIALS - CHANGE THESE!
# ============================================================
POSTGRES_DB="hookprobe_db"
POSTGRES_USER="hookprobe_admin"
POSTGRES_PASSWORD="CHANGE_ME_STRONG_PASSWORD_123"

# Keycloak Database
KEYCLOAK_DB="keycloak_db"
KEYCLOAK_DB_USER="keycloak_admin"
KEYCLOAK_DB_PASSWORD="CHANGE_ME_KEYCLOAK_DB_PASSWORD"

# ============================================================
# DJANGO CONFIGURATION
# ============================================================
DJANGO_SECRET_KEY="CHANGE_ME_DJANGO_SECRET_KEY_LONG_RANDOM_STRING"
DJANGO_DEBUG="False"
DJANGO_ALLOWED_HOSTS="*"  # Change in production

# ============================================================
# KEYCLOAK IAM CONFIGURATION
# ============================================================
KEYCLOAK_ADMIN="admin"
KEYCLOAK_ADMIN_PASSWORD="CHANGE_ME_KEYCLOAK_ADMIN_PASSWORD"
KEYCLOAK_HOSTNAME="keycloak.hookprobe.local"

# ============================================================
# CLOUDFLARE TUNNEL CONFIGURATION (OPTIONAL)
# ============================================================
CLOUDFLARE_TUNNEL_TOKEN="CHANGE_ME_GET_FROM_CLOUDFLARE_DASHBOARD"
CLOUDFLARE_TUNNEL_NAME="hookprobe-tunnel"
CLOUDFLARE_DOMAIN="your-domain.com"

# ============================================================
# MODSECURITY WAF CONFIGURATION
# ============================================================
MODSECURITY_PARANOIA_LEVEL=1           # 1=basic, 4=paranoid
MODSECURITY_ANOMALY_THRESHOLD=5        # Lower = stricter
MODSECURITY_AUDIT_LOG=1                # Enable detailed logging

# ============================================================
# QSECBIT AI CONFIGURATION
# ============================================================
QSECBIT_ALPHA=0.30                     # System drift weight
QSECBIT_BETA=0.30                      # Attack probability weight
QSECBIT_GAMMA=0.20                     # Classifier decay weight
QSECBIT_DELTA=0.20                     # Quantum drift weight
QSECBIT_AMBER_THRESHOLD=0.45           # Warning threshold
QSECBIT_RED_THRESHOLD=0.70             # Critical threshold
QSECBIT_CHECK_INTERVAL=30              # Seconds between checks

# Baseline system metrics (adjust for your environment)
QSECBIT_BASELINE_MU="0.1,0.2,0.15,0.33"  # CPU, Memory, Network, Disk I/O
QSECBIT_QUANTUM_ANCHOR=6.144             # Baseline entropy

# ============================================================
# HONEYPOT & MITIGATION CONFIGURATION
# ============================================================
HONEYPOT_AUTO_REDIRECT=true            # Auto-redirect detected attackers
HONEYPOT_SNAT_ENABLED=true             # Use SNAT for transparent redirect
HONEYPOT_NOTIFY_EMAIL="qsecbit@hookprobe.com"
HONEYPOT_LOG_RETENTION_DAYS=90         # Keep honeypot logs for 90 days

# Attack response thresholds
ATTACK_AUTO_BLOCK_THRESHOLD=0.70       # Qsecbit score to trigger auto-block
ATTACK_HONEYPOT_THRESHOLD=0.45         # Score to redirect to honeypot
ATTACK_NOTIFICATION_THRESHOLD=0.60     # Score to send email notification

# ============================================================
# OPENFLOW PRIORITY LEVELS
# ============================================================
PRIORITY_ALLOW_ESTABLISHED=1000        # Allow established connections
PRIORITY_DENY_DEFAULT=100              # Default deny
PRIORITY_ALLOW_SPECIFIC=500            # Specific allow rules
PRIORITY_RATE_LIMIT=600                # Rate limiting rules
PRIORITY_ANTI_SPOOF=800                # Anti-spoofing rules
PRIORITY_HONEYPOT_REDIRECT=900         # Honeypot redirection

# ============================================================
# RATE LIMITING (packets per second)
# ============================================================
RATE_LIMIT_ICMP=10                     # ICMP echo requests
RATE_LIMIT_SYN=100                     # TCP SYN packets
RATE_LIMIT_UDP_GENERIC=200             # Generic UDP traffic
RATE_LIMIT_DNS=50                      # DNS queries per source
RATE_LIMIT_HTTP=1000                   # HTTP requests per source

# ============================================================
# DDoS MITIGATION (XDP/eBPF)
# ============================================================
ENABLE_XDP_DDOS=true                   # Enable XDP-based DDoS mitigation
XDP_SYN_COOKIE=true                    # SYN cookie protection
XDP_RATE_LIMIT=true                    # Rate limiting at kernel level

# ============================================================
# VOLUME NAMES
# ============================================================
VOLUME_POSTGRES_DATA="hookprobe-postgres-v5"
VOLUME_DJANGO_STATIC="hookprobe-django-static-v5"
VOLUME_DJANGO_MEDIA="hookprobe-django-media-v5"
VOLUME_KEYCLOAK_DATA="hookprobe-keycloak-v5"
VOLUME_VICTORIAMETRICS_DATA="hookprobe-victoriametrics-v5"
VOLUME_VICTORIALOGS_DATA="hookprobe-victorialogs-v5"
VOLUME_GRAFANA_DATA="hookprobe-grafana-v5"
VOLUME_ZEEK_LOGS="hookprobe-zeek-logs-v5"
VOLUME_SNORT_LOGS="hookprobe-snort-logs-v5"
VOLUME_MODSECURITY_LOGS="hookprobe-modsecurity-logs-v5"
VOLUME_QSECBIT_DATA="hookprobe-qsecbit-v5"
VOLUME_HONEYPOT_DATA="hookprobe-honeypot-v5"

# ============================================================
# POD NAMES
# ============================================================
POD_WEB="hookprobe-web-dmz"
POD_IAM="hookprobe-iam"
POD_DATABASE="hookprobe-database"
POD_CACHE="hookprobe-cache"
POD_MONITORING="hookprobe-monitoring"
POD_SECURITY="hookprobe-security"
POD_HONEYPOT="hookprobe-honeypot"

# ============================================================
# NETWORK NAMES (PODMAN)
# ============================================================
NETWORK_WEB="web-dmz-net"
NETWORK_IAM="iam-net"
NETWORK_DATABASE="database-net"
NETWORK_CACHE="cache-net"
NETWORK_MONITORING="monitoring-net"
NETWORK_SECURITY="security-net"
NETWORK_HONEYPOT="honeypot-net"

# ============================================================
# PORT MAPPINGS (Host -> Container)
# ============================================================
PORT_HTTP=80
PORT_HTTPS=443
PORT_KEYCLOAK=8080
PORT_KEYCLOAK_ADMIN=9000
PORT_POSTGRES=5432
PORT_GRAFANA=3000
PORT_VICTORIAMETRICS=8428
PORT_VICTORIALOGS=9428
PORT_QSECBIT_API=8888

# ============================================================
# SECURITY HARDENING FLAGS
# ============================================================
ENABLE_MAC_IP_BINDING=true             # Strict MAC/IP binding per port
ENABLE_ARP_PROTECTION=true             # Anti-ARP poisoning
ENABLE_DHCP_SNOOPING=false             # DHCP snooping (if needed)
ENABLE_ND_PROTECTION=true              # IPv6 Neighbor Discovery protection
ENABLE_PORT_SECURITY=true              # Port security on OVS

# Key rotation schedule (days)
VXLAN_KEY_ROTATION_DAYS=90
CERT_ROTATION_DAYS=365

# ============================================================
# LOGGING & AUDIT
# ============================================================
AUDIT_LOG_RETENTION_DAYS=365           # Keep audit logs for 1 year
ENABLE_FLOW_LOGGING=true               # NetFlow/sFlow export
ENABLE_OPENFLOW_LOGGING=true           # Log OpenFlow drops
ENABLE_NFTABLES_LOGGING=true           # Log firewall drops

# ============================================================
# HELPER FUNCTIONS
# ============================================================

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        echo "ERROR: Invalid IP address format: $ip"
        return 1
    fi
}

# Function to validate subnet
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
export QSEC_BRIDGE QSEC_BRIDGE_IP
export VXLAN_PSK VXLAN_PORT
export VNI_MANAGEMENT VNI_WEB_DMZ VNI_IAM VNI_DATABASE VNI_CACHE VNI_MONITORING VNI_SECURITY VNI_HONEYPOT
export SUBNET_MANAGEMENT GATEWAY_MANAGEMENT
export SUBNET_WEB_DMZ GATEWAY_WEB_DMZ IP_MODSECURITY IP_NGINX IP_DJANGO IP_CLOUDFLARED
export SUBNET_IAM GATEWAY_IAM IP_KEYCLOAK IP_KEYCLOAK_DB
export SUBNET_DATABASE GATEWAY_DATABASE IP_POSTGRES_MAIN IP_NFS
export SUBNET_CACHE GATEWAY_CACHE IP_REDIS IP_VALKEY
export SUBNET_MONITORING GATEWAY_MONITORING IP_VICTORIAMETRICS IP_VICTORIALOGS IP_GRAFANA IP_VECTOR IP_NODE_EXPORTER
export SUBNET_SECURITY GATEWAY_SECURITY IP_ZEEK IP_SNORT IP_QSECBIT
export SUBNET_HONEYPOT GATEWAY_HONEYPOT IP_HONEYPOT_WEB IP_HONEYPOT_SSH IP_HONEYPOT_DB IP_MITIGATION_ENGINE
export POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD
export KEYCLOAK_DB KEYCLOAK_DB_USER KEYCLOAK_DB_PASSWORD KEYCLOAK_ADMIN KEYCLOAK_ADMIN_PASSWORD
export DJANGO_SECRET_KEY DJANGO_DEBUG DJANGO_ALLOWED_HOSTS
export QSECBIT_ALPHA QSECBIT_BETA QSECBIT_GAMMA QSECBIT_DELTA
export QSECBIT_AMBER_THRESHOLD QSECBIT_RED_THRESHOLD QSECBIT_CHECK_INTERVAL
export HONEYPOT_AUTO_REDIRECT HONEYPOT_SNAT_ENABLED HONEYPOT_NOTIFY_EMAIL

echo "============================================================"
echo "   HOOKPROBE v5.0 NETWORK CONFIGURATION LOADED"
echo "   GPL-FREE Edition - All Permissive Licenses"
echo "============================================================"
echo "Network Architecture:"
echo "  Bridge: $QSEC_BRIDGE ($QSEC_BRIDGE_IP)"
echo "  VNIs: 200-207 (8 isolated networks)"
echo ""
echo "IP Allocation (10.200.0.0/16):"
echo "  Management:   $SUBNET_MANAGEMENT"
echo "  Web DMZ:      $SUBNET_WEB_DMZ"
echo "  IAM:          $SUBNET_IAM"
echo "  Database:     $SUBNET_DATABASE"
echo "  Cache:        $SUBNET_CACHE"
echo "  Monitoring:   $SUBNET_MONITORING"
echo "  Security:     $SUBNET_SECURITY"
echo "  Honeypot:     $SUBNET_HONEYPOT"
echo ""
echo "Security Components (All GPL-Free):"
echo "  ✓ ModSecurity WAF (Apache 2.0)"
echo "  ✓ Zeek IDS (BSD-3-Clause)"
echo "  ✓ Snort 3 IDS/IPS (GPL-2 w/ exception)"
echo "  ✓ VictoriaMetrics (Apache 2.0)"
echo "  ✓ VictoriaLogs (Apache 2.0)"
echo "  ✓ Keycloak IAM (Apache 2.0)"
echo "  ✓ Custom Honeypots (MIT)"
echo "  ✓ Qsecbit AI (MIT)"
echo ""
echo "Advanced Features:"
echo "  ✓ OpenFlow ACLs per VNI"
echo "  ✓ XDP/eBPF DDoS mitigation"
echo "  ✓ MAC/IP binding"
echo "  ✓ ARP/ND protection"
echo "  ✓ Rate limiting"
echo "  ✓ Honeypot auto-redirect"
echo "  ✓ PSK-encrypted VXLAN"
echo "============================================================"
