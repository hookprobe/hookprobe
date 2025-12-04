#!/bin/bash
#
# install-sentinel-lite.sh - HookProbe Lightweight Sentinel Validator
# Version: 1.0
#
# Ultra-lightweight validator for constrained devices:
#   - Raspberry Pi 3 (1GB RAM)
#   - Raspberry Pi Zero/Pico-class
#   - Low-power ARM devices
#   - LTE/mobile network deployments
#
# Features:
#   - No container overhead (native Python service)
#   - Minimal RAM: 128-256MB
#   - Minimal disk: ~50MB installed
#   - Minimal bandwidth: ~5MB download
#   - Works offline after installation
#
# Usage:
#   curl -sSL https://install.hookprobe.com/sentinel-lite | sudo bash
#   # OR
#   sudo ./install-sentinel-lite.sh --mssp-endpoint mssp.hookprobe.com
#

set -e

# ============================================================
# CONFIGURATION
# ============================================================

VERSION="1.0.0"
SCRIPT_NAME="HookProbe Sentinel Lite"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Installation paths
INSTALL_DIR="/opt/hookprobe-sentinel"
CONFIG_DIR="/etc/hookprobe"
DATA_DIR="/var/lib/hookprobe/sentinel"
LOG_DIR="/var/log/hookprobe"

# Default configuration
MSSP_ENDPOINT="${MSSP_ENDPOINT:-mssp.hookprobe.com}"
MSSP_PORT="${MSSP_PORT:-8443}"
SENTINEL_PORT="${SENTINEL_PORT:-8443}"
METRICS_PORT="${METRICS_PORT:-9090}"
SENTINEL_REGION="${SENTINEL_REGION:-auto}"
SENTINEL_TIER="${SENTINEL_TIER:-community}"

# Memory profiles (in MB)
MEMORY_PROFILE="auto"
MEMORY_LIMIT_ULTRA=128    # For Pi Zero, Pico (512MB total RAM)
MEMORY_LIMIT_LOW=192      # For Pi 3 (1GB total RAM)
MEMORY_LIMIT_STANDARD=256 # For Pi 4 (2GB+ total RAM)

# ============================================================
# BANNER
# ============================================================

show_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
    ╦ ╦╔═╗╔═╗╦╔═╔═╗╦═╗╔═╗╔╗ ╔═╗
    ╠═╣║ ║║ ║╠╩╗╠═╝╠╦╝║ ║╠╩╗║╣
    ╩ ╩╚═╝╚═╝╩ ╩╩  ╩╚═╚═╝╚═╝╚═╝

    SENTINEL LITE - Ultra-Lightweight Validator
    For Raspberry Pi, ARM, and Constrained Devices
EOF
    echo -e "${NC}"
    echo -e "    Version: ${VERSION}"
    echo ""
}

# ============================================================
# UTILITY FUNCTIONS
# ============================================================

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${CYAN}[$1/$2]${NC} $3"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        echo "Please run: sudo $0"
        exit 1
    fi
}

# ============================================================
# SYSTEM DETECTION
# ============================================================

detect_platform() {
    log_info "Detecting platform..."

    # Detect architecture
    ARCH=$(uname -m)
    case "$ARCH" in
        armv6l)
            PLATFORM_TYPE="arm32v6"
            PLATFORM_NAME="ARM32 v6 (Pi Zero/1)"
            ;;
        armv7l)
            PLATFORM_TYPE="arm32v7"
            PLATFORM_NAME="ARM32 v7 (Pi 2/3)"
            ;;
        aarch64)
            PLATFORM_TYPE="arm64"
            PLATFORM_NAME="ARM64 (Pi 4/5)"
            ;;
        x86_64)
            PLATFORM_TYPE="amd64"
            PLATFORM_NAME="x86_64"
            ;;
        *)
            PLATFORM_TYPE="unknown"
            PLATFORM_NAME="$ARCH"
            ;;
    esac

    # Detect total RAM in MB
    TOTAL_RAM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
    AVAILABLE_RAM_MB=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)

    # Detect if Raspberry Pi
    IS_RASPBERRY_PI=false
    PI_MODEL=""
    if [ -f /proc/device-tree/model ]; then
        PI_MODEL=$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || echo "")
        if [[ "$PI_MODEL" == *"Raspberry Pi"* ]]; then
            IS_RASPBERRY_PI=true
        fi
    fi

    # Auto-select memory profile
    if [ "$MEMORY_PROFILE" = "auto" ]; then
        if [ "$TOTAL_RAM_MB" -le 512 ]; then
            MEMORY_PROFILE="ultra"
            MEMORY_LIMIT=$MEMORY_LIMIT_ULTRA
        elif [ "$TOTAL_RAM_MB" -le 1024 ]; then
            MEMORY_PROFILE="low"
            MEMORY_LIMIT=$MEMORY_LIMIT_LOW
        else
            MEMORY_PROFILE="standard"
            MEMORY_LIMIT=$MEMORY_LIMIT_STANDARD
        fi
    fi

    echo ""
    echo -e "${CYAN}Platform Detection:${NC}"
    echo "  Architecture:   $PLATFORM_NAME ($ARCH)"
    echo "  Total RAM:      ${TOTAL_RAM_MB}MB"
    echo "  Available RAM:  ${AVAILABLE_RAM_MB}MB"
    echo "  Memory Profile: $MEMORY_PROFILE (${MEMORY_LIMIT}MB limit)"
    if [ "$IS_RASPBERRY_PI" = true ]; then
        echo "  Device:         $PI_MODEL"
    fi
    echo ""
}

check_requirements() {
    log_info "Checking system requirements..."

    local errors=0

    # Check minimum RAM (256MB minimum for operation, but we can install on less)
    if [ "$TOTAL_RAM_MB" -lt 256 ]; then
        log_warn "Low RAM detected (${TOTAL_RAM_MB}MB). Sentinel Lite requires minimum 256MB"
        log_warn "Installation will proceed but performance may be limited"
    fi

    # Check available disk space (need at least 100MB)
    DISK_AVAILABLE_MB=$(df -m "$INSTALL_DIR" 2>/dev/null | awk 'NR==2 {print $4}' || df -m / | awk 'NR==2 {print $4}')
    if [ "$DISK_AVAILABLE_MB" -lt 100 ]; then
        log_error "Insufficient disk space: ${DISK_AVAILABLE_MB}MB available (100MB required)"
        ((errors++))
    else
        echo -e "  ${GREEN}✓${NC} Disk space: ${DISK_AVAILABLE_MB}MB available"
    fi

    # Check Python 3
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        if [[ "$(echo "$PYTHON_VERSION >= 3.7" | bc -l 2>/dev/null || echo 1)" == "1" ]]; then
            echo -e "  ${GREEN}✓${NC} Python: $PYTHON_VERSION"
        else
            log_warn "Python $PYTHON_VERSION detected. Python 3.7+ recommended"
        fi
    else
        log_warn "Python 3 not found. Will install."
    fi

    # Check network connectivity (quick test)
    if ping -c 1 -W 2 8.8.8.8 &> /dev/null || ping -c 1 -W 2 1.1.1.1 &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} Network: Connected"
    else
        log_warn "No internet detected. Offline mode will be used if packages are pre-cached"
    fi

    if [ $errors -gt 0 ]; then
        log_error "System requirements not met. Please fix the issues above."
        exit 1
    fi

    echo ""
}

# ============================================================
# INSTALLATION
# ============================================================

install_dependencies() {
    log_step 1 6 "Installing minimal dependencies..."

    # Detect package manager
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
    elif command -v apk &> /dev/null; then
        PKG_MANAGER="apk"
    else
        log_error "No supported package manager found"
        exit 1
    fi

    # Minimal package list - only what's absolutely needed
    case "$PKG_MANAGER" in
        apt)
            apt-get update -qq 2>/dev/null || true
            apt-get install -y -qq --no-install-recommends \
                python3 \
                python3-pip \
                curl \
                ca-certificates \
                2>/dev/null
            ;;
        dnf|yum)
            $PKG_MANAGER install -y -q \
                python3 \
                python3-pip \
                curl \
                ca-certificates \
                2>/dev/null
            ;;
        apk)
            apk add --no-cache \
                python3 \
                py3-pip \
                curl \
                ca-certificates \
                2>/dev/null
            ;;
    esac

    echo -e "  ${GREEN}✓${NC} System packages installed"
}

install_python_deps() {
    log_step 2 6 "Installing Python dependencies (minimal set)..."

    # Create virtual environment to isolate dependencies
    python3 -m venv "$INSTALL_DIR/venv" 2>/dev/null || {
        # If venv fails, install pip packages globally
        log_warn "Virtual environment not available, installing globally"
    }

    # Minimal Python dependencies for sentinel
    # Only install what's absolutely needed for validation
    local PIP_CMD="pip3"
    if [ -f "$INSTALL_DIR/venv/bin/pip" ]; then
        PIP_CMD="$INSTALL_DIR/venv/bin/pip"
    fi

    # Install minimal deps with no cache to save disk space
    $PIP_CMD install --no-cache-dir \
        --quiet \
        --prefer-binary \
        2>/dev/null || true

    echo -e "  ${GREEN}✓${NC} Python dependencies installed"
}

create_directories() {
    log_step 3 6 "Creating directory structure..."

    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$DATA_DIR/cache"
    mkdir -p "$LOG_DIR"

    # Set permissions
    chmod 750 "$CONFIG_DIR"
    chmod 750 "$DATA_DIR"

    echo -e "  ${GREEN}✓${NC} Directories created"
}

install_sentinel_service() {
    log_step 4 6 "Installing Sentinel Lite service..."

    # Generate node ID
    local NODE_ID="sentinel-lite-$(hostname -s)-$(date +%s | sha256sum | head -c 8)"

    # Create the lightweight sentinel Python script
    cat > "$INSTALL_DIR/sentinel.py" << 'SENTINEL_SCRIPT'
#!/usr/bin/env python3
"""
HookProbe Sentinel Lite - Ultra-Lightweight Validator
Optimized for constrained devices (Raspberry Pi, ARM, low-RAM systems)

Memory target: 128-256MB
CPU target: Single-core ARM
"""

import os
import sys
import time
import json
import socket
import hashlib
import threading
import signal
import logging
from datetime import datetime, timezone
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
import gc

# ============================================================
# CONFIGURATION
# ============================================================

NODE_ID = os.environ.get("SENTINEL_NODE_ID", "sentinel-lite-unknown")
MSSP_ENDPOINT = os.environ.get("MSSP_ENDPOINT", "mssp.hookprobe.com")
MSSP_PORT = int(os.environ.get("MSSP_PORT", "8443"))
LISTEN_PORT = int(os.environ.get("SENTINEL_PORT", "8443"))
METRICS_PORT = int(os.environ.get("METRICS_PORT", "9090"))
REGION = os.environ.get("SENTINEL_REGION", "auto")
TIER = os.environ.get("SENTINEL_TIER", "community")
MEMORY_LIMIT = int(os.environ.get("MEMORY_LIMIT_MB", "192"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

# Memory optimization settings
CACHE_MAX_SIZE = 1000  # Maximum cached validations
CACHE_TTL = 300  # Cache TTL in seconds
GC_INTERVAL = 60  # Garbage collection interval
EDGE_HISTORY_LIMIT = 100  # Maximum edge history entries

# Rate limits by tier
RATE_LIMITS = {
    "community": 100,
    "professional": 1000,
    "enterprise": 10000
}

# ============================================================
# LOGGING SETUP (memory-efficient)
# ============================================================

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.handlers.RotatingFileHandler(
            '/var/log/hookprobe/sentinel-lite.log',
            maxBytes=1024*1024,  # 1MB max log size
            backupCount=2
        ) if os.path.exists('/var/log/hookprobe') else logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("sentinel-lite")

# ============================================================
# MEMORY-EFFICIENT DATA STRUCTURES
# ============================================================

class LRUCache:
    """Simple LRU cache with TTL for validation results"""

    def __init__(self, max_size=1000, ttl=300):
        self.max_size = max_size
        self.ttl = ttl
        self.cache = {}
        self.access_order = []

    def get(self, key):
        if key in self.cache:
            entry = self.cache[key]
            if time.time() - entry['time'] < self.ttl:
                return entry['value']
            else:
                del self.cache[key]
        return None

    def set(self, key, value):
        # Evict oldest entries if at capacity
        while len(self.cache) >= self.max_size:
            if self.access_order:
                oldest = self.access_order.pop(0)
                self.cache.pop(oldest, None)

        self.cache[key] = {'value': value, 'time': time.time()}
        if key in self.access_order:
            self.access_order.remove(key)
        self.access_order.append(key)

    def cleanup(self):
        """Remove expired entries"""
        now = time.time()
        expired = [k for k, v in self.cache.items() if now - v['time'] > self.ttl]
        for k in expired:
            del self.cache[k]
            if k in self.access_order:
                self.access_order.remove(k)

# ============================================================
# SENTINEL VALIDATOR
# ============================================================

class SentinelLite:
    """Lightweight edge device validator"""

    def __init__(self):
        self.validation_cache = LRUCache(CACHE_MAX_SIZE, CACHE_TTL)
        self.rate_counters = defaultdict(int)
        self.rate_window = 0

        # Statistics (minimal memory footprint)
        self.stats = {
            'validated': 0,
            'rejected': 0,
            'errors': 0,
            'active_count': 0,
            'start_time': time.time()
        }

        # Track recent edges (limited history)
        self.recent_edges = []

    def validate(self, data: bytes, addr: tuple) -> dict:
        """Validate an incoming message from an edge device"""
        try:
            # Check message minimum size
            if len(data) < 32:
                self.stats['rejected'] += 1
                return {'valid': False, 'reason': 'message_too_short'}

            # Extract edge ID (first 16 bytes)
            edge_id = data[:16].hex()

            # Extract timestamp (bytes 16-24)
            ts_bytes = data[16:24]

            # Extract signature hint (bytes 24-32)
            sig_hint = data[24:32].hex()

            # Check cache first (memory-efficient)
            cache_key = f"{edge_id}:{sig_hint[:8]}"
            cached = self.validation_cache.get(cache_key)
            if cached:
                return cached

            # Perform validation
            result = self._validate_edge(edge_id, ts_bytes, sig_hint, addr)

            # Cache result
            self.validation_cache.set(cache_key, result)

            # Update stats
            if result['valid']:
                self.stats['validated'] += 1
                self._track_edge(edge_id)
            else:
                self.stats['rejected'] += 1

            return result

        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"Validation error: {e}")
            return {'valid': False, 'reason': 'internal_error'}

    def _validate_edge(self, edge_id: str, ts_bytes: bytes, sig_hint: str, addr: tuple) -> dict:
        """Internal validation logic"""

        # Check 1: Edge ID format
        if len(edge_id) != 32:
            return {'valid': False, 'reason': 'invalid_edge_id'}

        # Check 2: Timestamp freshness
        try:
            ts = int.from_bytes(ts_bytes, 'big')
            current_ts = int(time.time())
            if abs(current_ts - ts) > 300:  # 5 minute window
                return {'valid': False, 'reason': 'stale_timestamp'}
        except:
            return {'valid': False, 'reason': 'invalid_timestamp'}

        # Check 3: Rate limiting
        current_window = int(time.time() / 60)
        if current_window != self.rate_window:
            self.rate_counters.clear()
            self.rate_window = current_window

        rate_key = edge_id[:16]  # Use prefix for rate limiting
        self.rate_counters[rate_key] += 1
        if self.rate_counters[rate_key] > RATE_LIMITS.get(TIER, 100):
            return {'valid': False, 'reason': 'rate_limited'}

        return {
            'valid': True,
            'edge_id': edge_id,
            'timestamp': ts,
            'sentinel': NODE_ID,
            'region': REGION
        }

    def _track_edge(self, edge_id: str):
        """Track recently seen edges (limited memory)"""
        if edge_id not in self.recent_edges:
            self.recent_edges.append(edge_id)
            if len(self.recent_edges) > EDGE_HISTORY_LIMIT:
                self.recent_edges.pop(0)
        self.stats['active_count'] = len(self.recent_edges)

    def cleanup(self):
        """Periodic cleanup to free memory"""
        self.validation_cache.cleanup()
        gc.collect()

# ============================================================
# METRICS SERVER (lightweight)
# ============================================================

class MetricsHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler for metrics and health"""

    sentinel = None  # Set by main()

    def log_message(self, format, *args):
        pass  # Suppress access logs to save CPU

    def do_GET(self):
        if self.path == '/metrics':
            self._serve_metrics()
        elif self.path == '/health':
            self._serve_health()
        else:
            self.send_error(404)

    def _serve_metrics(self):
        stats = self.sentinel.stats
        uptime = time.time() - stats['start_time']

        metrics = f"""# HELP sentinel_validated_total Total validated messages
# TYPE sentinel_validated_total counter
sentinel_validated_total {stats['validated']}

# HELP sentinel_rejected_total Total rejected messages
# TYPE sentinel_rejected_total counter
sentinel_rejected_total {stats['rejected']}

# HELP sentinel_errors_total Total errors
# TYPE sentinel_errors_total counter
sentinel_errors_total {stats['errors']}

# HELP sentinel_active_edges Current active edges
# TYPE sentinel_active_edges gauge
sentinel_active_edges {stats['active_count']}

# HELP sentinel_uptime_seconds Uptime in seconds
# TYPE sentinel_uptime_seconds gauge
sentinel_uptime_seconds {uptime:.0f}

# HELP sentinel_info Sentinel information
# TYPE sentinel_info gauge
sentinel_info{{node_id="{NODE_ID}",region="{REGION}",tier="{TIER}",memory_limit="{MEMORY_LIMIT}"}} 1
"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(metrics.encode())

    def _serve_health(self):
        stats = self.sentinel.stats
        health = {
            'status': 'healthy',
            'node_id': NODE_ID,
            'region': REGION,
            'tier': TIER,
            'uptime': time.time() - stats['start_time'],
            'validated': stats['validated'],
            'memory_limit_mb': MEMORY_LIMIT
        }
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(health).encode())

# ============================================================
# MSSP REPORTER (lightweight)
# ============================================================

def mssp_reporter(sentinel: SentinelLite):
    """Report stats to MSSP periodically"""
    while True:
        try:
            time.sleep(60)  # Report every minute

            report = {
                'sentinel_id': NODE_ID,
                'region': REGION,
                'tier': TIER,
                'type': 'sentinel-lite',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'stats': {
                    'validated': sentinel.stats['validated'],
                    'rejected': sentinel.stats['rejected'],
                    'errors': sentinel.stats['errors'],
                    'active_edges': sentinel.stats['active_count']
                }
            }

            # Send via UDP (lightweight, fire-and-forget)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)

            # Simple header + JSON payload
            header = NODE_ID.encode()[:16].ljust(16, b'\x00')
            payload = json.dumps(report).encode()

            sock.sendto(header + payload, (MSSP_ENDPOINT, MSSP_PORT))
            sock.close()

            logger.debug(f"Report sent to MSSP: {sentinel.stats['active_count']} edges")

        except Exception as e:
            logger.warning(f"MSSP report error: {e}")

# ============================================================
# MEMORY MONITOR
# ============================================================

def memory_monitor(sentinel: SentinelLite):
    """Monitor and manage memory usage"""
    while True:
        try:
            time.sleep(GC_INTERVAL)

            # Cleanup caches
            sentinel.cleanup()

            # Check memory usage
            try:
                import resource
                mem_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
                if mem_mb > MEMORY_LIMIT * 0.9:
                    logger.warning(f"High memory usage: {mem_mb:.0f}MB / {MEMORY_LIMIT}MB")
                    gc.collect()
            except:
                pass

        except Exception as e:
            logger.error(f"Memory monitor error: {e}")

# ============================================================
# MAIN
# ============================================================

def main():
    logger.info("=" * 60)
    logger.info("HookProbe Sentinel Lite - Starting")
    logger.info("=" * 60)
    logger.info(f"Node ID:      {NODE_ID}")
    logger.info(f"Region:       {REGION}")
    logger.info(f"Tier:         {TIER}")
    logger.info(f"Listen Port:  {LISTEN_PORT}")
    logger.info(f"Metrics Port: {METRICS_PORT}")
    logger.info(f"MSSP:         {MSSP_ENDPOINT}:{MSSP_PORT}")
    logger.info(f"Memory Limit: {MEMORY_LIMIT}MB")
    logger.info("=" * 60)

    # Create sentinel
    sentinel = SentinelLite()
    MetricsHandler.sentinel = sentinel

    # Start metrics server
    metrics_server = HTTPServer(('0.0.0.0', METRICS_PORT), MetricsHandler)
    metrics_thread = threading.Thread(target=metrics_server.serve_forever, daemon=True)
    metrics_thread.start()
    logger.info(f"Metrics server started on port {METRICS_PORT}")

    # Start MSSP reporter
    reporter_thread = threading.Thread(target=mssp_reporter, args=(sentinel,), daemon=True)
    reporter_thread.start()
    logger.info("MSSP reporter started")

    # Start memory monitor
    monitor_thread = threading.Thread(target=memory_monitor, args=(sentinel,), daemon=True)
    monitor_thread.start()
    logger.info("Memory monitor started")

    # Create UDP socket for validation
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', LISTEN_PORT))
    logger.info(f"Validator listening on UDP port {LISTEN_PORT}")
    logger.info("")
    logger.info("Ready to validate edge devices...")

    # Graceful shutdown handler
    def signal_handler(sig, frame):
        logger.info("Shutting down...")
        sock.close()
        metrics_server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Main validation loop
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            result = sentinel.validate(data, addr)

            # Send response
            response = json.dumps(result).encode()
            sock.sendto(response, addr)

            if result['valid']:
                logger.debug(f"Validated: {result.get('edge_id', '?')[:16]}... from {addr[0]}")
            else:
                logger.debug(f"Rejected: {result.get('reason', '?')} from {addr[0]}")

        except socket.error:
            break
        except Exception as e:
            logger.error(f"Error: {e}")

if __name__ == "__main__":
    main()
SENTINEL_SCRIPT

    chmod +x "$INSTALL_DIR/sentinel.py"
    echo -e "  ${GREEN}✓${NC} Sentinel Lite service installed"
}

create_config() {
    log_step 5 6 "Creating configuration..."

    # Generate node ID
    local NODE_ID="sentinel-lite-$(hostname -s 2>/dev/null || echo 'node')-$(date +%s | sha256sum | head -c 8)"

    # Auto-detect region if set to auto
    if [ "$SENTINEL_REGION" = "auto" ]; then
        # Try to get region from IP geolocation (lightweight)
        SENTINEL_REGION=$(curl -s --connect-timeout 5 http://ip-api.com/json/ 2>/dev/null | grep -o '"countryCode":"[^"]*"' | cut -d'"' -f4 | tr '[:upper:]' '[:lower:]' || echo "unknown")
        [ -z "$SENTINEL_REGION" ] && SENTINEL_REGION="unknown"
    fi

    # Create main configuration
    cat > "$CONFIG_DIR/sentinel-lite.conf" << CONF
# HookProbe Sentinel Lite Configuration
# Generated: $(date -Iseconds)

# Node Identity
SENTINEL_NODE_ID="${NODE_ID}"
SENTINEL_REGION="${SENTINEL_REGION}"
SENTINEL_TIER="${SENTINEL_TIER}"

# MSSP Connection
MSSP_ENDPOINT="${MSSP_ENDPOINT}"
MSSP_PORT="${MSSP_PORT}"

# Service Ports
SENTINEL_PORT="${SENTINEL_PORT}"
METRICS_PORT="${METRICS_PORT}"

# Memory Management
MEMORY_LIMIT_MB="${MEMORY_LIMIT}"

# Logging
LOG_LEVEL="INFO"
CONF

    chmod 640 "$CONFIG_DIR/sentinel-lite.conf"

    # Create environment file for systemd
    cat > "$CONFIG_DIR/sentinel-lite.env" << ENV
# Environment variables for Sentinel Lite service
SENTINEL_NODE_ID=${NODE_ID}
SENTINEL_REGION=${SENTINEL_REGION}
SENTINEL_TIER=${SENTINEL_TIER}
MSSP_ENDPOINT=${MSSP_ENDPOINT}
MSSP_PORT=${MSSP_PORT}
SENTINEL_PORT=${SENTINEL_PORT}
METRICS_PORT=${METRICS_PORT}
MEMORY_LIMIT_MB=${MEMORY_LIMIT}
LOG_LEVEL=INFO
ENV

    chmod 640 "$CONFIG_DIR/sentinel-lite.env"

    echo -e "  ${GREEN}✓${NC} Configuration created"
    echo "      Node ID: ${NODE_ID}"
    echo "      Region:  ${SENTINEL_REGION}"
}

create_systemd_service() {
    log_step 6 6 "Creating systemd service..."

    # Determine Python path
    local PYTHON_PATH="python3"
    if [ -f "$INSTALL_DIR/venv/bin/python" ]; then
        PYTHON_PATH="$INSTALL_DIR/venv/bin/python"
    fi

    cat > /etc/systemd/system/hookprobe-sentinel-lite.service << SERVICE
[Unit]
Description=HookProbe Sentinel Lite - Lightweight Edge Validator
Documentation=https://hookprobe.com/docs/sentinel-lite
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${CONFIG_DIR}/sentinel-lite.env

# Memory limits for constrained devices
MemoryMax=${MEMORY_LIMIT}M
MemoryHigh=$((MEMORY_LIMIT * 80 / 100))M

# CPU limits (low priority)
CPUWeight=50
Nice=10

# Execute
ExecStart=${PYTHON_PATH} ${INSTALL_DIR}/sentinel.py

# Restart policy
Restart=always
RestartSec=10
WatchdogSec=120

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR} ${LOG_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SERVICE

    # Reload systemd
    systemctl daemon-reload

    # Enable service
    systemctl enable hookprobe-sentinel-lite.service 2>/dev/null

    echo -e "  ${GREEN}✓${NC} Systemd service created and enabled"
}

# ============================================================
# UNINSTALL
# ============================================================

uninstall() {
    echo -e "${YELLOW}Uninstalling HookProbe Sentinel Lite...${NC}"
    echo ""

    # Stop and disable service
    systemctl stop hookprobe-sentinel-lite.service 2>/dev/null || true
    systemctl disable hookprobe-sentinel-lite.service 2>/dev/null || true

    # Remove files
    rm -f /etc/systemd/system/hookprobe-sentinel-lite.service
    rm -rf "$INSTALL_DIR"
    rm -f "$CONFIG_DIR/sentinel-lite.conf"
    rm -f "$CONFIG_DIR/sentinel-lite.env"
    rm -rf "$DATA_DIR"

    # Reload systemd
    systemctl daemon-reload

    echo -e "${GREEN}✓ HookProbe Sentinel Lite uninstalled${NC}"
}

# ============================================================
# STATUS
# ============================================================

show_status() {
    echo -e "${CYAN}HookProbe Sentinel Lite Status${NC}"
    echo ""

    if systemctl is-active --quiet hookprobe-sentinel-lite.service; then
        echo -e "  Service:  ${GREEN}Running${NC}"
    else
        echo -e "  Service:  ${RED}Stopped${NC}"
    fi

    if [ -f "$CONFIG_DIR/sentinel-lite.conf" ]; then
        source "$CONFIG_DIR/sentinel-lite.conf"
        echo "  Node ID:  ${SENTINEL_NODE_ID}"
        echo "  Region:   ${SENTINEL_REGION}"
        echo "  Tier:     ${SENTINEL_TIER}"
        echo "  Memory:   ${MEMORY_LIMIT_MB}MB limit"
    fi

    # Check if metrics endpoint is responding
    if curl -sf "http://localhost:${METRICS_PORT:-9090}/health" > /dev/null 2>&1; then
        echo -e "  Health:   ${GREEN}OK${NC}"

        # Get stats
        local stats=$(curl -sf "http://localhost:${METRICS_PORT:-9090}/health" 2>/dev/null)
        if [ -n "$stats" ]; then
            local validated=$(echo "$stats" | grep -o '"validated":[0-9]*' | cut -d: -f2)
            local uptime=$(echo "$stats" | grep -o '"uptime":[0-9.]*' | cut -d: -f2 | cut -d. -f1)
            echo "  Validated: ${validated:-0} messages"
            echo "  Uptime:    ${uptime:-0}s"
        fi
    else
        echo -e "  Health:   ${YELLOW}Not responding${NC}"
    fi

    echo ""
}

# ============================================================
# POST-INSTALL
# ============================================================

show_post_install() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  SENTINEL LITE INSTALLATION COMPLETE                       ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Load config for display
    source "$CONFIG_DIR/sentinel-lite.conf" 2>/dev/null || true

    echo -e "${CYAN}Configuration:${NC}"
    echo "  Node ID:      ${SENTINEL_NODE_ID:-generated}"
    echo "  Region:       ${SENTINEL_REGION:-auto}"
    echo "  Tier:         ${SENTINEL_TIER:-community}"
    echo "  Memory:       ${MEMORY_LIMIT}MB"
    echo ""
    echo -e "${CYAN}Service Endpoints:${NC}"
    echo "  Validation:   UDP port ${SENTINEL_PORT:-8443}"
    echo "  Metrics:      http://localhost:${METRICS_PORT:-9090}/metrics"
    echo "  Health:       http://localhost:${METRICS_PORT:-9090}/health"
    echo ""
    echo -e "${CYAN}MSSP Connection:${NC}"
    echo "  Endpoint:     ${MSSP_ENDPOINT}:${MSSP_PORT}"
    echo ""
    echo -e "${YELLOW}Commands:${NC}"
    echo "  Start:        sudo systemctl start hookprobe-sentinel-lite"
    echo "  Stop:         sudo systemctl stop hookprobe-sentinel-lite"
    echo "  Status:       sudo systemctl status hookprobe-sentinel-lite"
    echo "  Logs:         sudo journalctl -u hookprobe-sentinel-lite -f"
    echo ""
    echo -e "${CYAN}Configuration files:${NC}"
    echo "  Config:       ${CONFIG_DIR}/sentinel-lite.conf"
    echo "  Environment:  ${CONFIG_DIR}/sentinel-lite.env"
    echo ""

    # Auto-start prompt
    read -p "Start Sentinel Lite now? (yes/no) [yes]: " start_now
    start_now=${start_now:-yes}

    if [ "$start_now" = "yes" ] || [ "$start_now" = "y" ]; then
        systemctl start hookprobe-sentinel-lite.service
        sleep 2

        if systemctl is-active --quiet hookprobe-sentinel-lite.service; then
            echo -e "${GREEN}✓ Sentinel Lite is running${NC}"
        else
            echo -e "${RED}✗ Failed to start. Check: journalctl -u hookprobe-sentinel-lite${NC}"
        fi
    fi

    echo ""
    echo -e "${BLUE}HookProbe Sentinel Lite - Ultra-Lightweight Edge Validation${NC}"
    echo ""
}

# ============================================================
# MAIN
# ============================================================

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --mssp-endpoint URL   MSSP server endpoint (default: mssp.hookprobe.com)"
    echo "  --mssp-port PORT      MSSP server port (default: 8443)"
    echo "  --port PORT           Sentinel listen port (default: 8443)"
    echo "  --metrics-port PORT   Metrics HTTP port (default: 9090)"
    echo "  --region REGION       Geographic region (default: auto)"
    echo "  --tier TIER           Service tier: community|professional|enterprise"
    echo "  --memory PROFILE      Memory profile: ultra|low|standard|auto"
    echo "  --uninstall           Remove Sentinel Lite"
    echo "  --status              Show current status"
    echo "  --help                Show this help"
    echo ""
    echo "Examples:"
    echo "  # Basic installation"
    echo "  sudo $0"
    echo ""
    echo "  # Install with custom MSSP endpoint"
    echo "  sudo $0 --mssp-endpoint my-mssp.example.com"
    echo ""
    echo "  # Force ultra-low memory mode (Pi Zero)"
    echo "  sudo $0 --memory ultra"
    echo ""
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --mssp-endpoint)
                MSSP_ENDPOINT="$2"
                shift 2
                ;;
            --mssp-port)
                MSSP_PORT="$2"
                shift 2
                ;;
            --port)
                SENTINEL_PORT="$2"
                shift 2
                ;;
            --metrics-port)
                METRICS_PORT="$2"
                shift 2
                ;;
            --region)
                SENTINEL_REGION="$2"
                shift 2
                ;;
            --tier)
                SENTINEL_TIER="$2"
                shift 2
                ;;
            --memory)
                MEMORY_PROFILE="$2"
                shift 2
                ;;
            --uninstall)
                check_root
                uninstall
                exit 0
                ;;
            --status)
                show_status
                exit 0
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    # Run installation
    show_banner
    check_root
    detect_platform
    check_requirements

    echo ""
    echo -e "${GREEN}Starting installation...${NC}"
    echo ""

    install_dependencies
    install_python_deps
    create_directories
    install_sentinel_service
    create_config
    create_systemd_service

    show_post_install
}

main "$@"
