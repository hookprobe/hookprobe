#!/bin/bash
#
# n8n_network-config.sh - HookProbe n8n Automation Network Configuration
# Version: 1.0 - POD 008 (OPTIONAL EXTENSION)
#
# ⚠️  IMPORTANT: This is an OPTIONAL extension to HookProbe
#    Requires main HookProbe (PODs 001-007) to be deployed first
#    This extends the existing architecture with workflow automation
#
# This configuration follows existing HookProbe patterns:
#  - VNI allocation (108, next after 107)
#  - IP allocation (10.108.0.0/24, matching existing pattern)
#  - PSK encryption (uses OVS_PSK_INTERNAL for internal services)
#  - Security hardening (OpenFlow rules, ARP protection)
#

# Source the main network config
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/network-config.sh" ]; then
    source "$SCRIPT_DIR/network-config.sh"
else
    echo "ERROR: Main network-config.sh not found"
    echo "Please ensure main HookProbe is deployed first"
    exit 1
fi

# ============================================================
# POD 008 - AUTOMATION & CONTENT GENERATION (OPTIONAL)
# ============================================================
# This POD is OPTIONAL and can be deployed independently
# Follows existing HookProbe architecture patterns

# VNI for Automation POD (next in sequence after POD 007)
VNI_AUTOMATION=208

# Subnet for POD 008 (follows 10.10X.0.0/24 pattern)
SUBNET_POD008="10.200.8.0/24"
GATEWAY_POD008="10.200.8.1"

# IP Allocations for POD 008 (follows existing IP allocation pattern)
IP_POD008_N8N="10.200.8.10"              # n8n workflow automation
IP_POD008_N8N_DB="10.200.8.11"           # n8n PostgreSQL database
IP_POD008_REDIS="10.200.8.12"            # Redis for queue management
IP_POD008_CHROMIUM="10.200.8.13"         # Headless Chromium for scraping
IP_POD008_MCP_SERVER="10.200.8.15"       # MCP server for AI integrations
IP_POD008_RESERVED_1="10.200.8.20"       # Reserved for expansion
IP_POD008_RESERVED_2="10.200.8.21"
IP_POD008_RESERVED_3="10.200.8.22"

# ============================================================
# N8N CONFIGURATION
# ============================================================

# n8n basic settings
N8N_PROTOCOL="http"
N8N_HOST="${IP_POD008_N8N}"
N8N_PORT="5678"
N8N_BASIC_AUTH_ACTIVE="true"
N8N_BASIC_AUTH_USER="admin"
N8N_BASIC_AUTH_PASSWORD="CHANGE_ME_N8N_PASSWORD"  # ⚠️ CHANGE THIS

# n8n database (uses existing PostgreSQL pattern)
N8N_DB_TYPE="postgresdb"
N8N_DB_POSTGRESDB_HOST="${IP_POD008_N8N_DB}"
N8N_DB_POSTGRESDB_PORT="5432"
N8N_DB_POSTGRESDB_DATABASE="n8n"
N8N_DB_POSTGRESDB_USER="n8n_admin"
N8N_DB_POSTGRESDB_PASSWORD="CHANGE_ME_N8N_DB_PASSWORD"  # ⚠️ CHANGE THIS

# n8n execution mode (queue-based like existing setup)
N8N_EXECUTIONS_MODE="queue"
N8N_EXECUTIONS_QUEUE_REDIS_HOST="${IP_POD008_REDIS}"
N8N_EXECUTIONS_QUEUE_REDIS_PORT="6379"

# n8n webhook URL (external access)
N8N_WEBHOOK_URL="http://${HOST_A_IP}:${N8N_PORT}"

# n8n timezone (follows existing config)
N8N_TIMEZONE="UTC"

# ============================================================
# DJANGO CMS INTEGRATION
# ============================================================

# Django CMS API endpoint (from POD 001)
DJANGO_CMS_API_URL="http://${IP_POD001_DJANGO}:8000/api"
DJANGO_CMS_ADMIN_URL="http://${IP_POD001_DJANGO}:8000/admin"
DJANGO_CMS_USERNAME="admin"  # Use Django superuser
DJANGO_CMS_PASSWORD="${DJANGO_SECRET_KEY:0:20}"  # Derived from Django secret

# ============================================================
# QSECBIT API INTEGRATION
# ============================================================

# Qsecbit API (from POD 007)
QSECBIT_API_URL="http://${IP_POD007_QSECBIT}:${PORT_QSECBIT_API}"

# ============================================================
# WEB SCRAPING CONFIGURATION
# ============================================================

# Chromium/Puppeteer settings
CHROMIUM_EXTRA_ARGS="--no-sandbox --disable-setuid-sandbox --disable-dev-shm-usage"
PUPPETEER_SKIP_CHROMIUM_DOWNLOAD="false"
PUPPETEER_EXECUTABLE_PATH="/usr/bin/chromium-browser"

# Scraping rate limits
SCRAPING_MAX_CONCURRENT="3"
SCRAPING_DELAY_MS="2000"

# ============================================================
# MCP (Model Context Protocol) SERVER
# ============================================================

# MCP server for AI integrations
MCP_SERVER_PORT="8889"
MCP_SERVER_URL="http://${IP_POD008_MCP_SERVER}:${MCP_SERVER_PORT}"

# AI API keys (store in Vault in production)
OPENAI_API_KEY="CHANGE_ME_OPENAI_KEY"  # ⚠️ CHANGE THIS
ANTHROPIC_API_KEY="CHANGE_ME_ANTHROPIC_KEY"  # ⚠️ CHANGE THIS

# ============================================================
# CONTENT GENERATION SETTINGS
# ============================================================

# Blog posting schedule
BLOG_POST_SCHEDULE_CRON="0 9 * * *"  # Daily at 9 AM
BLOG_POST_CATEGORIES="Threat Intelligence,SBC Security,DevSecOps,Tutorials"

# Content quality thresholds
MIN_WORD_COUNT="800"
MAX_WORD_COUNT="2500"
MIN_SEO_SCORE="70"

# ============================================================
# CONTAINER IMAGES
# ============================================================

IMAGE_N8N="docker.io/n8nio/n8n:latest"
IMAGE_N8N_POSTGRES="docker.io/library/postgres:16-alpine"
IMAGE_N8N_REDIS="docker.io/library/redis:7-alpine"
IMAGE_CHROMIUM="docker.io/browserless/chrome:latest"
IMAGE_MCP_SERVER="docker.io/library/python:3.12-slim"

# ============================================================
# VOLUME NAMES
# ============================================================

VOLUME_N8N_DATA="hookprobe-n8n-data"
VOLUME_N8N_DB="hookprobe-n8n-db"
VOLUME_N8N_REDIS="hookprobe-n8n-redis"
VOLUME_MCP_DATA="hookprobe-mcp-data"
VOLUME_SCRAPING_CACHE="hookprobe-scraping-cache"

# ============================================================
# POD & NETWORK NAMES
# ============================================================

POD_008_NAME="hookprobe-pod-008-automation"
NETWORK_POD008="pod008-automation-net"

# ============================================================
# PORT MAPPINGS
# ============================================================

PORT_N8N=5678           # n8n web interface
PORT_MCP=8889           # MCP server

# ============================================================
# HELPER FUNCTIONS
# ============================================================

validate_n8n_config() {
    local errors=0
    
    if [ "$N8N_BASIC_AUTH_PASSWORD" == "CHANGE_ME_N8N_PASSWORD" ]; then
        echo "ERROR: Please change N8N_BASIC_AUTH_PASSWORD"
        errors=$((errors + 1))
    fi
    
    if [ "$N8N_DB_POSTGRESDB_PASSWORD" == "CHANGE_ME_N8N_DB_PASSWORD" ]; then
        echo "ERROR: Please change N8N_DB_POSTGRESDB_PASSWORD"
        errors=$((errors + 1))
    fi
    
    if [ "$OPENAI_API_KEY" == "CHANGE_ME_OPENAI_KEY" ]; then
        echo "WARNING: OPENAI_API_KEY not configured (AI features will be limited)"
    fi
    
    if [ "$ANTHROPIC_API_KEY" == "CHANGE_ME_ANTHROPIC_KEY" ]; then
        echo "WARNING: ANTHROPIC_API_KEY not configured (AI features will be limited)"
    fi
    
    return $errors
}

# Export all variables
export VNI_AUTOMATION
export SUBNET_POD008 GATEWAY_POD008
export IP_POD008_N8N IP_POD008_N8N_DB IP_POD008_REDIS IP_POD008_CHROMIUM IP_POD008_PUPPETEER IP_POD008_MCP_SERVER IP_POD008_API_PROXY
export N8N_PROTOCOL N8N_HOST N8N_PORT N8N_BASIC_AUTH_ACTIVE N8N_BASIC_AUTH_USER N8N_BASIC_AUTH_PASSWORD
export N8N_DB_TYPE N8N_DB_POSTGRESDB_HOST N8N_DB_POSTGRESDB_PORT N8N_DB_POSTGRESDB_DATABASE N8N_DB_POSTGRESDB_USER N8N_DB_POSTGRESDB_PASSWORD
export N8N_EXECUTIONS_MODE N8N_EXECUTIONS_QUEUE_REDIS_HOST N8N_EXECUTIONS_QUEUE_REDIS_PORT
export N8N_WEBHOOK_URL
export DJANGO_CMS_API_URL DJANGO_CMS_ADMIN_URL DJANGO_CMS_USERNAME DJANGO_CMS_PASSWORD
export QSECBIT_API_URL
export CHROMIUM_EXTRA_ARGS PUPPETEER_SKIP_CHROMIUM_DOWNLOAD PUPPETEER_EXECUTABLE_PATH
export SCRAPING_MAX_CONCURRENT SCRAPING_DELAY_MS
export MCP_SERVER_PORT MCP_SERVER_URL
export OPENAI_API_KEY ANTHROPIC_API_KEY
export BLOG_POST_SCHEDULE_CRON BLOG_POST_CATEGORIES
export MIN_WORD_COUNT MAX_WORD_COUNT MIN_SEO_SCORE
export IMAGE_N8N IMAGE_N8N_POSTGRES IMAGE_N8N_REDIS IMAGE_CHROMIUM IMAGE_MCP_SERVER
export VOLUME_N8N_DATA VOLUME_N8N_DB VOLUME_N8N_REDIS VOLUME_MCP_DATA VOLUME_SCRAPING_CACHE
export POD_008_NAME NETWORK_POD008
export PORT_N8N PORT_MCP

echo "============================================================"
echo "   N8N AUTOMATION CONFIGURATION LOADED - v1.0"
echo "   OPTIONAL EXTENSION - Requires main HookProbe (PODs 001-007)"
echo "============================================================"
echo "POD 008 - Automation & Content Generation (OPTIONAL)"
echo "  Network: ${SUBNET_POD008}"
echo "  VNI: ${VNI_AUTOMATION} (Internal - encrypted with OVS_PSK_INTERNAL)"
echo ""
echo "Integration with main HookProbe:"
echo "  ✓ Inherits all base configuration from network-config.sh"
echo "  ✓ Follows established VNI/IP allocation patterns"
echo "  ✓ Uses same PSK encryption scheme (INTERNAL)"
echo "  ✓ Applies same security hardening (L2 anti-spoof)"
echo ""
echo "Key Services:"
echo "  n8n:           ${IP_POD008_N8N}:${N8N_PORT}"
echo "  MCP Server:    ${IP_POD008_MCP_SERVER}:${MCP_SERVER_PORT}"
echo "  PostgreSQL:    ${IP_POD008_N8N_DB}"
echo "  Redis Queue:   ${IP_POD008_REDIS}"
echo "  Chromium:      ${IP_POD008_CHROMIUM}"
echo ""
echo "Integrations:"
echo "  Django CMS:    ${DJANGO_CMS_API_URL}"
echo "  Qsecbit API:   ${QSECBIT_API_URL}"
echo ""
echo "Access URL (after deployment):"
echo "  n8n UI:        http://${HOST_A_IP}:${PORT_N8N}"
echo "  Credentials:   ${N8N_BASIC_AUTH_USER} / [configured]"
echo ""
echo "Deploy with:   sudo ./n8n_setup.sh"
echo "Remove with:   sudo ./n8n_uninstall.sh"
echo "============================================================"
