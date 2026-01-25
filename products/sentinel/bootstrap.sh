#!/bin/bash
#
# HookProbe Sentinel Bootstrap
# "The Watchful Eye" - Secure, lightweight validator for edge devices
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/hookprobe/hookprobe/main/products/sentinel/bootstrap.sh | sudo bash
#   # OR with options:
#   curl -sSL ... | sudo bash -s -- --mesh-endpoint my-mesh.example.com
#
# Requirements:
#   - Linux (Debian/Ubuntu/Raspbian, RHEL/Fedora, Alpine)
#   - Python 3.7+
#   - 256MB+ RAM
#   - Root access
#   - Internet connectivity
#
# Security Features:
#   - HTP (HookProbe Transport Protocol) for mesh communication
#   - Rate limiting / DDoS protection
#   - Process sandboxing (seccomp, capabilities)
#   - Automatic firewall rules
#   - Integrity verification
#   - Fail2ban integration
#

set -e

VERSION="2.0.0"
GITHUB_REPO="https://github.com/hookprobe/hookprobe.git"
GITHUB_RAW="https://raw.githubusercontent.com/hookprobe/hookprobe/main/products/sentinel"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Installation paths
INSTALL_DIR="/opt/hookprobe/sentinel"
HOOKPROBE_DIR="/opt/hookprobe"
CONFIG_DIR="/etc/hookprobe"
SECRETS_DIR="/etc/hookprobe/secrets"
DATA_DIR="/var/lib/hookprobe/sentinel"
KEYS_DIR="/var/lib/hookprobe/keys"
LOG_DIR="/var/log/hookprobe"
RUN_DIR="/run/hookprobe"

# Defaults
MESH_ENDPOINT="${MESH_ENDPOINT:-mesh.hookprobe.com}"
MESH_PORT="${MESH_PORT:-8443}"
HEALTH_PORT="${HEALTH_PORT:-9090}"
SENTINEL_REGION="${SENTINEL_REGION:-auto}"
ENABLE_FIREWALL="${ENABLE_FIREWALL:-yes}"
ENABLE_FAIL2BAN="${ENABLE_FAIL2BAN:-yes}"
ENABLE_MESH="${ENABLE_MESH:-yes}"
MSSP_URL="${MSSP_URL:-https://mssp.hookprobe.com}"

# Security: Validate port number (CWE-78 prevention)
validate_port() {
    local port="$1"
    local name="$2"
    # Port must be numeric and in valid range
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        log_error "Invalid $name: must be numeric 1-65535"
        exit 1
    fi
}

# Security: Validate hostname/endpoint (CWE-78 prevention)
validate_hostname() {
    local hostname="$1"
    # Only allow alphanumeric, dots, and hyphens
    if ! [[ "$hostname" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]]; then
        log_error "Invalid hostname format: $hostname"
        exit 1
    fi
}

# ============================================================
# LOGGING
# ============================================================

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_security() { echo -e "${CYAN}[SECURITY]${NC} $1"; }

# ============================================================
# BANNER
# ============================================================

show_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
     ___ ___ _  _ _____ ___ _  _ ___ _
    / __| __| \| |_   _|_ _| \| | __| |
    \__ \ _|| .` | | |  | || .` | _|| |__
    |___/___|_|\_| |_| |___|_|\_|___|____|

            "The Watchful Eye"
EOF
    echo -e "${NC}"
    echo "  HookProbe Sentinel v${VERSION}"
    echo "  Secure edge validator with HTP protocol"
    echo ""
}

# ============================================================
# CHECKS
# ============================================================

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        echo "Usage: curl -sSL $GITHUB_RAW/bootstrap.sh | sudo bash"
        exit 1
    fi
}

check_internet() {
    log_info "Checking internet connectivity..."
    if ! ping -c 1 -W 5 8.8.8.8 &>/dev/null && ! ping -c 1 -W 5 1.1.1.1 &>/dev/null; then
        log_error "No internet connectivity. Sentinel requires internet access."
        exit 1
    fi
    log_info "Internet: Connected"
}

detect_platform() {
    ARCH=$(uname -m)
    OS_ID=$(grep -E "^ID=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "unknown")
    TOTAL_RAM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo "512")

    # Detect package manager
    if command -v apt-get &>/dev/null; then
        PKG_MANAGER="apt"
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
    elif command -v apk &>/dev/null; then
        PKG_MANAGER="apk"
    else
        PKG_MANAGER="unknown"
    fi

    # Auto-select memory limit based on available RAM
    if [ "$TOTAL_RAM_MB" -le 512 ]; then
        MEMORY_LIMIT=128
    elif [ "$TOTAL_RAM_MB" -le 1024 ]; then
        MEMORY_LIMIT=192
    elif [ "$TOTAL_RAM_MB" -le 2048 ]; then
        MEMORY_LIMIT=256
    else
        MEMORY_LIMIT=384
    fi

    log_info "Platform: $ARCH | OS: $OS_ID | RAM: ${TOTAL_RAM_MB}MB | Limit: ${MEMORY_LIMIT}MB"
}

# ============================================================
# DEPENDENCIES
# ============================================================

install_deps() {
    log_info "Installing dependencies..."

    case "$PKG_MANAGER" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq 2>/dev/null || true
            apt-get install -y -qq --no-install-recommends \
                python3 python3-pip python3-venv \
                curl wget ca-certificates \
                git iptables \
                2>/dev/null || true
            ;;
        dnf)
            dnf install -y -q \
                python3 python3-pip \
                curl wget ca-certificates \
                git iptables \
                2>/dev/null || true
            ;;
        yum)
            yum install -y -q \
                python3 python3-pip \
                curl wget ca-certificates \
                git iptables \
                2>/dev/null || true
            ;;
        apk)
            apk add --no-cache \
                python3 py3-pip \
                curl wget ca-certificates \
                git iptables \
                2>/dev/null || true
            ;;
    esac

    # Install fail2ban if enabled
    if [ "$ENABLE_FAIL2BAN" = "yes" ]; then
        log_info "Installing fail2ban..."
        case "$PKG_MANAGER" in
            apt) apt-get install -y -qq fail2ban 2>/dev/null || true ;;
            dnf|yum) dnf install -y -q fail2ban 2>/dev/null || yum install -y -q fail2ban 2>/dev/null || true ;;
            apk) apk add --no-cache fail2ban 2>/dev/null || true ;;
        esac
    fi
}

# ============================================================
# DOWNLOAD & INSTALL
# ============================================================

download_sentinel() {
    log_info "Downloading Sentinel components..."

    # Create directories with secure permissions
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$SECRETS_DIR" "$DATA_DIR" "$LOG_DIR" "$RUN_DIR"
    chmod 755 "$INSTALL_DIR"
    chmod 750 "$CONFIG_DIR"
    chmod 700 "$SECRETS_DIR"
    chmod 750 "$DATA_DIR"
    chmod 755 "$LOG_DIR"
    chmod 755 "$RUN_DIR"

    # Download main sentinel script
    log_info "Downloading sentinel.py..."
    if ! curl -sSfL "$GITHUB_RAW/sentinel.py" -o "$INSTALL_DIR/sentinel.py"; then
        log_error "Failed to download sentinel.py"
        exit 1
    fi

    # CWE-494: Download checksum file and verify integrity
    log_security "Verifying download integrity..."
    if curl -sSfL "$GITHUB_RAW/checksums.sha256" -o "$INSTALL_DIR/checksums.sha256" 2>/dev/null; then
        # Extract expected checksum for sentinel.py
        local expected_checksum=$(grep "sentinel.py" "$INSTALL_DIR/checksums.sha256" 2>/dev/null | awk '{print $1}')
        if [ -n "$expected_checksum" ]; then
            local actual_checksum=$(sha256sum "$INSTALL_DIR/sentinel.py" | awk '{print $1}')
            if [ "$expected_checksum" != "$actual_checksum" ]; then
                log_error "SECURITY: Checksum mismatch for sentinel.py!"
                log_error "Expected: $expected_checksum"
                log_error "Actual:   $actual_checksum"
                log_error "Download may have been tampered with. Aborting."
                rm -f "$INSTALL_DIR/sentinel.py"
                exit 1
            fi
            log_security "Checksum verified for sentinel.py"
        else
            log_warn "No checksum available for sentinel.py, skipping verification"
        fi
        rm -f "$INSTALL_DIR/checksums.sha256"
    else
        log_warn "Checksum file not available, proceeding without verification"
    fi

    # Download security module
    log_info "Downloading security module..."
    if ! curl -sSfL "$GITHUB_RAW/sentinel_security.py" -o "$INSTALL_DIR/sentinel_security.py"; then
        log_warn "Security module not found, creating default..."
        create_security_module
    fi

    # Download lib directory (mesh integration)
    log_info "Downloading mesh integration module..."
    mkdir -p "$INSTALL_DIR/lib"
    touch "$INSTALL_DIR/lib/__init__.py"
    curl -sSfL "$GITHUB_RAW/lib/mesh_integration.py" -o "$INSTALL_DIR/lib/mesh_integration.py" 2>/dev/null || \
        log_warn "Mesh integration module not available"

    # Download signatures (lightweight ruleset)
    log_info "Downloading threat signatures..."
    mkdir -p "$DATA_DIR/signatures"
    curl -sSfL "$GITHUB_RAW/signatures/basic.rules" -o "$DATA_DIR/signatures/basic.rules" 2>/dev/null || \
        create_basic_signatures

    # Set permissions
    chmod 755 "$INSTALL_DIR/sentinel.py"
    chmod 644 "$INSTALL_DIR/sentinel_security.py" 2>/dev/null || true

    # Verify download integrity (basic size check as fallback)
    local size=$(wc -c < "$INSTALL_DIR/sentinel.py" 2>/dev/null || echo "0")
    if [ "$size" -lt 1000 ]; then
        log_error "Downloaded file appears incomplete (${size} bytes)"
        exit 1
    fi

    log_info "Downloaded sentinel.py (${size} bytes)"
}

# ============================================================
# HOOKPROBE CORE MODULES (for Mesh/DSM/NEURO support)
# ============================================================

download_core_modules() {
    if [ "$ENABLE_MESH" != "yes" ]; then
        log_warn "Mesh support disabled, skipping core modules"
        return
    fi

    log_info "Downloading HookProbe core modules for mesh support..."

    # Create core directory structure
    mkdir -p "$HOOKPROBE_DIR/shared/mesh"
    mkdir -p "$HOOKPROBE_DIR/shared/dsm"
    mkdir -p "$HOOKPROBE_DIR/core/htp/transport"
    mkdir -p "$HOOKPROBE_DIR/core/htp/crypto"
    mkdir -p "$HOOKPROBE_DIR/core/neuro/core"
    mkdir -p "$HOOKPROBE_DIR/core/neuro/identity"
    mkdir -p "$HOOKPROBE_DIR/core/neuro/network"

    # Base URL for core modules
    local CORE_RAW="https://raw.githubusercontent.com/hookprobe/hookprobe/main"

    # Download shared mesh modules
    log_info "Downloading mesh modules..."
    local MESH_FILES=(
        "shared/mesh/__init__.py"
        "shared/mesh/tunnel.py"
        "shared/mesh/resilient_channel.py"
        "shared/mesh/consciousness.py"
        "shared/mesh/nat_traversal.py"
        "shared/mesh/unified_transport.py"
        "shared/mesh/port_manager.py"
        "shared/mesh/relay.py"
        "shared/mesh/channel_selector.py"
        "shared/mesh/neuro_encoder.py"
    )
    for f in "${MESH_FILES[@]}"; do
        curl -sSfL "$CORE_RAW/$f" -o "$HOOKPROBE_DIR/$f" 2>/dev/null || \
            log_warn "Failed to download $f"
    done

    # Download DSM modules
    log_info "Downloading DSM modules..."
    local DSM_FILES=(
        "shared/dsm/__init__.py"
        "shared/dsm/gossip.py"
        "shared/dsm/merkle.py"
        "shared/dsm/microblock.py"
    )
    for f in "${DSM_FILES[@]}"; do
        curl -sSfL "$CORE_RAW/$f" -o "$HOOKPROBE_DIR/$f" 2>/dev/null || \
            log_warn "Failed to download $f"
    done

    # Download HTP transport modules
    log_info "Downloading HTP modules..."
    local HTP_FILES=(
        "core/htp/__init__.py"
        "core/htp/transport/__init__.py"
        "core/htp/transport/htp.py"
        "core/htp/crypto/__init__.py"
        "core/htp/crypto/transport.py"
        "core/htp/crypto/transport_v2.py"
    )
    for f in "${HTP_FILES[@]}"; do
        curl -sSfL "$CORE_RAW/$f" -o "$HOOKPROBE_DIR/$f" 2>/dev/null || \
            log_warn "Failed to download $f"
    done

    # Download NEURO modules
    log_info "Downloading NEURO modules..."
    local NEURO_FILES=(
        "core/neuro/__init__.py"
        "core/neuro/core/__init__.py"
        "core/neuro/core/posf.py"
        "core/neuro/identity/__init__.py"
        "core/neuro/identity/hardware_fingerprint.py"
        "core/neuro/network/__init__.py"
        "core/neuro/network/nat_traversal.py"
    )
    for f in "${NEURO_FILES[@]}"; do
        curl -sSfL "$CORE_RAW/$f" -o "$HOOKPROBE_DIR/$f" 2>/dev/null || \
            log_warn "Failed to download $f"
    done

    # Create __init__.py files for package structure
    touch "$HOOKPROBE_DIR/shared/__init__.py"
    touch "$HOOKPROBE_DIR/core/__init__.py"

    # Set permissions
    chmod -R 755 "$HOOKPROBE_DIR/shared" "$HOOKPROBE_DIR/core" 2>/dev/null || true
    find "$HOOKPROBE_DIR" -name "*.py" -exec chmod 644 {} \; 2>/dev/null || true

    log_info "Core modules downloaded for mesh support"
}

# ============================================================
# KEYS DIRECTORY (for hardware fingerprint and identity)
# ============================================================

create_keys_directory() {
    log_info "Creating keys directory for device identity..."

    # Create keys directory with strict permissions
    mkdir -p "$KEYS_DIR"
    chmod 700 "$KEYS_DIR"

    # Generate hardware fingerprint on first install
    if [ ! -f "$KEYS_DIR/hardware_fingerprint" ]; then
        log_security "Generating hardware fingerprint..."

        # Collect hardware identifiers
        local cpu_info=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2 | tr -d ' ' || echo "unknown")
        local machine_id=$(cat /etc/machine-id 2>/dev/null || echo "unknown")
        local mac_addr=$(ip link show 2>/dev/null | grep -m1 "link/ether" | awk '{print $2}' || echo "00:00:00:00:00:00")
        local hostname=$(hostname -f 2>/dev/null || hostname || echo "unknown")

        # Create fingerprint hash
        local fingerprint_data="${cpu_info}:${machine_id}:${mac_addr}:${hostname}"
        local fingerprint=$(echo -n "$fingerprint_data" | sha256sum | cut -d' ' -f1)

        # Store fingerprint
        echo "$fingerprint" > "$KEYS_DIR/hardware_fingerprint"
        chmod 600 "$KEYS_DIR/hardware_fingerprint"

        log_security "Hardware fingerprint: ${fingerprint:0:16}..."
    fi

    # Generate HMAC signing key if not exists
    if [ ! -f "$KEYS_DIR/signing_key" ]; then
        log_security "Generating HMAC signing key..."
        # Use od (POSIX standard) instead of xxd for portability
        head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n' > "$KEYS_DIR/signing_key"
        chmod 600 "$KEYS_DIR/signing_key"
    fi

    log_info "Keys directory initialized"
}

create_security_module() {
    cat > "$INSTALL_DIR/sentinel_security.py" << 'SECMOD'
#!/usr/bin/env python3
"""
HookProbe Sentinel Security Module
Lightweight protection for edge validators
"""

import os
import sys
import json
import time
import hashlib
import logging
import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Set, Optional, Tuple

logger = logging.getLogger("sentinel.security")

class RateLimiter:
    """Token bucket rate limiter for DDoS protection"""

    def __init__(self, rate: int = 100, burst: int = 200):
        self.rate = rate  # requests per second
        self.burst = burst
        self.tokens: Dict[str, float] = defaultdict(lambda: burst)
        self.last_update: Dict[str, float] = defaultdict(time.time)

    def allow(self, client_ip: str) -> bool:
        now = time.time()
        elapsed = now - self.last_update[client_ip]
        self.last_update[client_ip] = now

        # Add tokens based on elapsed time
        self.tokens[client_ip] = min(
            self.burst,
            self.tokens[client_ip] + elapsed * self.rate
        )

        if self.tokens[client_ip] >= 1:
            self.tokens[client_ip] -= 1
            return True
        return False

    def cleanup(self, max_age: int = 3600):
        """Remove old entries"""
        now = time.time()
        expired = [ip for ip, ts in self.last_update.items() if now - ts > max_age]
        for ip in expired:
            del self.tokens[ip]
            del self.last_update[ip]


class ThreatDetector:
    """Lightweight threat detection"""

    # Known malicious patterns
    SUSPICIOUS_PATTERNS = [
        b"../",  # Path traversal
        b"<script",  # XSS attempt
        b"SELECT ",  # SQL injection
        b"UNION ",
        b"; DROP",
        b"eval(",
        b"exec(",
        b"/etc/passwd",
        b"/etc/shadow",
        b"cmd.exe",
        b"powershell",
    ]

    # Rate thresholds
    THRESHOLD_REQUESTS_PER_MIN = 300
    THRESHOLD_ERRORS_PER_MIN = 50
    THRESHOLD_UNIQUE_PATHS = 100

    def __init__(self):
        self.blocked_ips: Set[str] = set()
        self.request_counts: Dict[str, int] = defaultdict(int)
        self.error_counts: Dict[str, int] = defaultdict(int)
        self.path_counts: Dict[str, Set[str]] = defaultdict(set)
        self.last_reset = time.time()
        self.alert_callback = None

    def check_request(self, client_ip: str, path: str, body: bytes = b"") -> Tuple[bool, str]:
        """
        Check if request should be allowed.
        Returns (allowed, reason)
        """
        # Check if IP is blocked
        if client_ip in self.blocked_ips:
            return False, "IP blocked"

        # Reset counters every minute
        now = time.time()
        if now - self.last_reset > 60:
            self.request_counts.clear()
            self.error_counts.clear()
            self.path_counts.clear()
            self.last_reset = now

        # Check rate limits
        self.request_counts[client_ip] += 1
        if self.request_counts[client_ip] > self.THRESHOLD_REQUESTS_PER_MIN:
            self._block_ip(client_ip, "Rate limit exceeded")
            return False, "Rate limit"

        # Check path scanning
        self.path_counts[client_ip].add(path)
        if len(self.path_counts[client_ip]) > self.THRESHOLD_UNIQUE_PATHS:
            self._block_ip(client_ip, "Path scanning detected")
            return False, "Path scanning"

        # Check for malicious patterns
        combined = path.encode() + body
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern.lower() in combined.lower():
                self._block_ip(client_ip, f"Malicious pattern: {pattern.decode(errors='ignore')}")
                return False, "Malicious pattern"

        return True, "OK"

    def record_error(self, client_ip: str):
        """Record an error from this IP"""
        self.error_counts[client_ip] += 1
        if self.error_counts[client_ip] > self.THRESHOLD_ERRORS_PER_MIN:
            self._block_ip(client_ip, "Too many errors")

    def _block_ip(self, ip: str, reason: str):
        """Block an IP address"""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            logger.warning(f"Blocked IP {ip}: {reason}")
            if self.alert_callback:
                self.alert_callback("ip_blocked", {"ip": ip, "reason": reason})

    def unblock_ip(self, ip: str):
        """Unblock an IP address"""
        self.blocked_ips.discard(ip)

    def get_blocked_ips(self) -> Set[str]:
        """Get set of blocked IPs"""
        return self.blocked_ips.copy()


class IntegrityChecker:
    """File integrity monitoring"""

    def __init__(self, watch_paths: list = None):
        self.watch_paths = watch_paths or [
            "/opt/hookprobe/sentinel/sentinel.py",
            "/etc/hookprobe/sentinel.env",
        ]
        self.hashes: Dict[str, str] = {}
        self._compute_initial_hashes()

    def _compute_initial_hashes(self):
        """Compute initial file hashes"""
        for path in self.watch_paths:
            if os.path.exists(path):
                self.hashes[path] = self._hash_file(path)

    def _hash_file(self, path: str) -> str:
        """Compute SHA256 hash of file"""
        hasher = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ""

    def check_integrity(self) -> list:
        """Check if any watched files have changed"""
        changes = []
        for path in self.watch_paths:
            if os.path.exists(path):
                current_hash = self._hash_file(path)
                if path in self.hashes and current_hash != self.hashes[path]:
                    changes.append({
                        "path": path,
                        "old_hash": self.hashes[path][:16],
                        "new_hash": current_hash[:16],
                    })
        return changes


class FirewallManager:
    """Manage iptables rules for protection"""

    @staticmethod
    def _run_iptables(rule: str) -> bool:
        """Run iptables safely using subprocess (CWE-78 prevention)"""
        import subprocess
        try:
            cmd_parts = ["iptables"] + rule.split()
            result = subprocess.run(cmd_parts, capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False

    @staticmethod
    def setup_basic_rules(health_port: int = 9090):
        """Setup basic firewall protection"""
        # Validate port to prevent command injection
        if not isinstance(health_port, int) or health_port < 1 or health_port > 65535:
            return
        rules = [
            "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "-A INPUT -i lo -j ACCEPT",
            f"-A INPUT -p tcp --dport {health_port} -j ACCEPT",
            "-A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT",
            "-A INPUT -m state --state INVALID -j DROP",
        ]
        for rule in rules:
            FirewallManager._run_iptables(rule)

    @staticmethod
    def block_ip(ip: str):
        """Block an IP address"""
        # Validate IP to prevent injection
        try:
            ipaddress.ip_address(ip)
            FirewallManager._run_iptables(f"-I INPUT -s {ip} -j DROP")
        except ValueError:
            pass

    @staticmethod
    def unblock_ip(ip: str):
        """Unblock an IP address"""
        try:
            ipaddress.ip_address(ip)
            FirewallManager._run_iptables(f"-D INPUT -s {ip} -j DROP")
        except ValueError:
            pass


class SecurityManager:
    """Main security manager combining all components"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.rate_limiter = RateLimiter(
            rate=self.config.get("rate_limit", 100),
            burst=self.config.get("rate_burst", 200)
        )
        self.threat_detector = ThreatDetector()
        self.integrity_checker = IntegrityChecker()
        self.firewall_enabled = self.config.get("firewall_enabled", True)
        self.stats = {
            "requests_total": 0,
            "requests_blocked": 0,
            "attacks_detected": 0,
            "ips_blocked": 0,
        }

    def check_request(self, client_ip: str, path: str = "/", body: bytes = b"") -> Tuple[bool, str]:
        """Check if a request should be allowed"""
        self.stats["requests_total"] += 1

        # Rate limiting
        if not self.rate_limiter.allow(client_ip):
            self.stats["requests_blocked"] += 1
            return False, "Rate limited"

        # Threat detection
        allowed, reason = self.threat_detector.check_request(client_ip, path, body)
        if not allowed:
            self.stats["requests_blocked"] += 1
            self.stats["attacks_detected"] += 1
            if self.firewall_enabled:
                FirewallManager.block_ip(client_ip)
            return False, reason

        return True, "OK"

    def get_stats(self) -> dict:
        """Get security statistics"""
        return {
            **self.stats,
            "blocked_ips": list(self.threat_detector.get_blocked_ips()),
            "integrity_changes": self.integrity_checker.check_integrity(),
        }

    def periodic_cleanup(self):
        """Periodic cleanup tasks"""
        self.rate_limiter.cleanup()


# Export main class
__all__ = ["SecurityManager", "RateLimiter", "ThreatDetector", "IntegrityChecker", "FirewallManager"]
SECMOD
    chmod 644 "$INSTALL_DIR/sentinel_security.py"
    log_info "Created security module"
}

create_basic_signatures() {
    cat > "$DATA_DIR/signatures/basic.rules" << 'SIGS'
# HookProbe Sentinel Basic Signatures
# Format: type|pattern|severity|description

# Path traversal
path|../|high|Path traversal attempt
path|..%2f|high|Encoded path traversal
path|%2e%2e/|high|Double-encoded path traversal

# SQL Injection
body|union.*select|high|SQL injection UNION SELECT
body|or.*1.*=.*1|medium|SQL injection OR 1=1
body|drop.*table|critical|SQL DROP TABLE attempt
body|insert.*into|high|SQL INSERT attempt

# XSS
body|<script|high|XSS script tag
body|javascript:|high|XSS javascript protocol
body|onerror=|medium|XSS event handler

# Command injection
body|;.*cat.*|high|Command injection cat
body|;.*ls.*|medium|Command injection ls
body|\|.*sh|high|Pipe to shell

# Sensitive files
path|/etc/passwd|critical|Access to passwd
path|/etc/shadow|critical|Access to shadow
path|.env|high|Access to environment file
path|.git/|high|Access to git directory

# Scanner signatures
header|nikto|medium|Nikto scanner
header|sqlmap|high|SQLMap scanner
header|nmap|medium|Nmap scanner
SIGS
    chmod 644 "$DATA_DIR/signatures/basic.rules"
    log_info "Created basic signatures"
}

# ============================================================
# CONFIGURATION
# ============================================================

create_config() {
    log_info "Creating configuration..."

    # Generate secure node ID (use od for portability instead of xxd)
    local NODE_ID="sentinel-$(hostname -s 2>/dev/null || echo 'node')-$(head -c 8 /dev/urandom | od -A n -t x1 | tr -d ' \n')"

    # Auto-detect region (CWE-319: Use HTTPS instead of HTTP)
    if [ "$SENTINEL_REGION" = "auto" ]; then
        # SECURITY: Use HTTPS to prevent MITM attacks
        SENTINEL_REGION=$(curl -sf --connect-timeout 3 https://ipapi.co/country_code/ 2>/dev/null | \
            tr '[:upper:]' '[:lower:]' || echo "unknown")
        # Validate region format (2-letter country code only)
        if ! [[ "$SENTINEL_REGION" =~ ^[a-z]{2}$ ]]; then
            SENTINEL_REGION="unknown"
        fi
    fi

    # Create main configuration
    cat > "$CONFIG_DIR/sentinel.env" << ENV
# HookProbe Sentinel Configuration
# Generated: $(date -Iseconds)

# Node Identity
SENTINEL_NODE_ID=${NODE_ID}
SENTINEL_REGION=${SENTINEL_REGION}
SENTINEL_VERSION=${VERSION}

# Mesh Backend (HTP - HookProbe Transport Protocol)
MESH_ENDPOINT=${MESH_ENDPOINT}
MESH_PORT=${MESH_PORT}
MESH_PROTOCOL=htp
MESH_HTP_VERSION=1.0
ENABLE_MESH=${ENABLE_MESH}

# MSSP Integration
MSSP_URL=${MSSP_URL}
MSSP_ENABLED=true

# Health Endpoint
HEALTH_PORT=${HEALTH_PORT}
HEALTH_BIND=0.0.0.0

# HookProbe Core Paths (for mesh/dsm/htp/neuro)
HOOKPROBE_DIR=${HOOKPROBE_DIR}
HOOKPROBE_KEYS_DIR=${KEYS_DIR}

# Security Settings
ENABLE_RATE_LIMITING=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_BURST=200
ENABLE_THREAT_DETECTION=true
ENABLE_INTEGRITY_CHECK=true
BLOCK_ON_ATTACK=true

# QSecBit - Quantum-Safe Security Capabilities
QSECBIT_ENABLED=true
QSECBIT_ENTROPY_SOURCE=/dev/urandom
QSECBIT_KEY_ROTATION_HOURS=24
QSECBIT_HMAC_ALGO=sha3-256
QSECBIT_SESSION_TIMEOUT=3600

# Resource Limits
MEMORY_LIMIT_MB=${MEMORY_LIMIT}

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/hookprobe/sentinel.log
LOG_MAX_SIZE_MB=10
LOG_BACKUP_COUNT=3

# Paths
DATA_DIR=${DATA_DIR}
SIGNATURES_DIR=${DATA_DIR}/signatures
ENV
    chmod 640 "$CONFIG_DIR/sentinel.env"

    # Create secrets file for mesh token (if provided)
    if [ -n "$MESH_TOKEN" ]; then
        echo "$MESH_TOKEN" > "$SECRETS_DIR/mesh-token"
        chmod 600 "$SECRETS_DIR/mesh-token"
    fi

    log_info "Node ID: ${NODE_ID}"
    log_info "Region: ${SENTINEL_REGION}"
}

# ============================================================
# FIREWALL SETUP
# ============================================================

setup_firewall() {
    if [ "$ENABLE_FIREWALL" != "yes" ]; then
        log_warn "Firewall setup skipped"
        return
    fi

    log_security "Configuring firewall rules..."

    # CWE-78: Validate HEALTH_PORT before using in iptables command
    validate_port "$HEALTH_PORT" "HEALTH_PORT"

    # Check for iptables
    if ! command -v iptables &>/dev/null; then
        log_warn "iptables not found, skipping firewall setup"
        return
    fi

    # Create HookProbe chain if it doesn't exist
    iptables -N HOOKPROBE 2>/dev/null || true

    # Flush existing rules in our chain
    iptables -F HOOKPROBE 2>/dev/null || true

    # Basic protection rules
    # Rate limit incoming connections
    iptables -A HOOKPROBE -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT

    # Allow health check port (HEALTH_PORT validated above)
    iptables -A HOOKPROBE -p tcp --dport "$HEALTH_PORT" -j ACCEPT

    # Drop invalid packets
    iptables -A HOOKPROBE -m state --state INVALID -j DROP

    # Insert our chain into INPUT
    iptables -I INPUT -j HOOKPROBE 2>/dev/null || true

    # Save rules (distribution-specific)
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null || true
    elif [ -f /etc/redhat-release ]; then
        iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
    fi

    log_security "Firewall configured"
}

# ============================================================
# FAIL2BAN SETUP
# ============================================================

setup_fail2ban() {
    if [ "$ENABLE_FAIL2BAN" != "yes" ]; then
        return
    fi

    if ! command -v fail2ban-client &>/dev/null; then
        log_warn "fail2ban not installed, skipping"
        return
    fi

    log_security "Configuring fail2ban..."

    # Create sentinel jail
    cat > /etc/fail2ban/jail.d/hookprobe-sentinel.conf << 'F2B'
[hookprobe-sentinel]
enabled = true
port = 9090
filter = hookprobe-sentinel
logpath = /var/log/hookprobe/sentinel.log
maxretry = 5
findtime = 300
bantime = 3600
action = iptables-multiport[name=hookprobe, port="9090"]
F2B

    # Create filter
    cat > /etc/fail2ban/filter.d/hookprobe-sentinel.conf << 'F2BF'
[Definition]
failregex = ^.*\[SECURITY\].*Blocked IP <HOST>.*$
            ^.*\[WARNING\].*Attack detected from <HOST>.*$
            ^.*\[ERROR\].*Rate limit exceeded: <HOST>.*$
ignoreregex =
F2BF

    # Restart fail2ban
    systemctl restart fail2ban 2>/dev/null || true
    log_security "fail2ban configured"
}

# ============================================================
# SYSTEMD SERVICE
# ============================================================

create_service() {
    log_info "Creating systemd service..."

    cat > /etc/systemd/system/hookprobe-sentinel.service << 'SERVICE'
[Unit]
Description=HookProbe Sentinel - The Watchful Eye
Documentation=https://github.com/hookprobe/hookprobe
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root

# Working directory
WorkingDirectory=/opt/hookprobe/sentinel

# Environment
EnvironmentFile=/etc/hookprobe/sentinel.env

# PYTHONPATH for HookProbe core modules (mesh, dsm, htp, neuro)
Environment="PYTHONPATH=/opt/hookprobe"
Environment="HOOKPROBE_KEYS_DIR=/var/lib/hookprobe/keys"

# Resource limits
MemoryMax=384M
MemoryHigh=256M
CPUWeight=50
TasksMax=50
Nice=10

# Start command
ExecStart=/usr/bin/python3 /opt/hookprobe/sentinel/sentinel.py
ExecReload=/bin/kill -HUP $MAINPID

# Restart policy
Restart=always
RestartSec=10
WatchdogSec=60

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true

# Allow necessary paths
ReadWritePaths=/var/lib/hookprobe /var/log/hookprobe /run/hookprobe

# Capabilities
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Seccomp filter
SystemCallFilter=@system-service
SystemCallFilter=~@mount @reboot @swap @privileged

[Install]
WantedBy=multi-user.target
SERVICE

    # Reload and enable
    systemctl daemon-reload
    systemctl enable hookprobe-sentinel.service 2>/dev/null

    log_info "Service created and enabled"
}

# ============================================================
# UNINSTALL COMMAND
# ============================================================

create_uninstall_command() {
    log_info "Creating uninstall command..."

    # Create simple uninstall wrapper in /usr/local/bin
    cat > /usr/local/bin/sentinel-uninstall << 'UNINSTALL'
#!/bin/bash
#
# HookProbe Sentinel Uninstaller
# Run: sudo sentinel-uninstall
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root: sudo sentinel-uninstall${NC}"
    exit 1
fi

echo -e "${YELLOW}HookProbe Sentinel Uninstaller${NC}"
echo ""
read -p "Are you sure you want to uninstall Sentinel? [y/N]: " confirm
if [ "${confirm,,}" != "y" ]; then
    echo "Cancelled."
    exit 0
fi

echo -e "${YELLOW}Stopping service...${NC}"
systemctl stop hookprobe-sentinel.service 2>/dev/null || true
systemctl disable hookprobe-sentinel.service 2>/dev/null || true

echo -e "${YELLOW}Removing service file...${NC}"
rm -f /etc/systemd/system/hookprobe-sentinel.service
systemctl daemon-reload

echo -e "${YELLOW}Removing firewall rules...${NC}"
iptables -D INPUT -j HOOKPROBE 2>/dev/null || true
iptables -F HOOKPROBE 2>/dev/null || true
iptables -X HOOKPROBE 2>/dev/null || true

echo -e "${YELLOW}Removing fail2ban config...${NC}"
rm -f /etc/fail2ban/jail.d/hookprobe-sentinel.conf 2>/dev/null
rm -f /etc/fail2ban/filter.d/hookprobe-sentinel.conf 2>/dev/null
systemctl restart fail2ban 2>/dev/null || true

echo -e "${YELLOW}Removing installation files...${NC}"
rm -rf /opt/hookprobe/sentinel
rm -f /etc/hookprobe/sentinel.env
rm -rf /var/lib/hookprobe/sentinel

echo -e "${YELLOW}Removing uninstall command...${NC}"
rm -f /usr/local/bin/sentinel-uninstall

echo ""
echo -e "${GREEN}Sentinel has been uninstalled successfully.${NC}"
echo "Log files preserved in: /var/log/hookprobe/"
UNINSTALL

    chmod 755 /usr/local/bin/sentinel-uninstall
    log_info "Uninstall command created: sentinel-uninstall"
}

# ============================================================
# VERIFICATION
# ============================================================

verify_installation() {
    log_info "Verifying installation..."

    local errors=0

    # Check files
    [ -f "$INSTALL_DIR/sentinel.py" ] || { log_error "sentinel.py missing"; errors=$((errors+1)); }
    [ -f "$CONFIG_DIR/sentinel.env" ] || { log_error "sentinel.env missing"; errors=$((errors+1)); }
    [ -d "$DATA_DIR" ] || { log_error "data directory missing"; errors=$((errors+1)); }

    # Check Python
    python3 --version &>/dev/null || { log_error "Python3 not found"; errors=$((errors+1)); }

    # Check service
    systemctl is-enabled hookprobe-sentinel.service &>/dev/null || { log_warn "Service not enabled"; }

    if [ $errors -gt 0 ]; then
        log_error "Installation verification failed with $errors errors"
        return 1
    fi

    log_info "Installation verified successfully"
    return 0
}

# ============================================================
# COMPLETION
# ============================================================

show_complete() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  SENTINEL INSTALLED SUCCESSFULLY                           ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    source "$CONFIG_DIR/sentinel.env" 2>/dev/null

    echo -e "${CYAN}Configuration:${NC}"
    echo "  Node ID:      ${SENTINEL_NODE_ID:-generated}"
    echo "  Region:       ${SENTINEL_REGION:-auto}"
    echo "  Memory Limit: ${MEMORY_LIMIT}MB"
    echo "  Health Port:  ${HEALTH_PORT}"
    echo ""

    echo -e "${CYAN}Mesh Backend:${NC}"
    echo "  Endpoint:     ${MESH_ENDPOINT}:${MESH_PORT}"
    echo "  Protocol:     HTP (HookProbe Transport Protocol)"
    if [ "$ENABLE_MESH" = "yes" ]; then
        echo "  Mesh Modules: Installed (DSM, HTP, NEURO)"
        echo "  PYTHONPATH:   /opt/hookprobe"
    else
        echo "  Mesh Modules: Disabled"
    fi
    echo ""

    echo -e "${CYAN}MSSP Integration:${NC}"
    echo "  Dashboard:    ${MSSP_URL}"
    echo "  Heartbeat:    Enabled"
    echo "  Fingerprint:  $(cat $KEYS_DIR/hardware_fingerprint 2>/dev/null | head -c 16)..."
    echo ""

    echo -e "${CYAN}Security Features:${NC}"
    echo "  Rate Limiting:     Enabled"
    echo "  Threat Detection:  Enabled"
    echo "  Integrity Check:   Enabled"
    echo "  QSecBit:           Enabled (SHA3-256, 24h key rotation)"
    echo "  Device Identity:   Hardware fingerprint bound"
    [ "$ENABLE_FIREWALL" = "yes" ] && echo "  Firewall Rules:    Configured"
    [ "$ENABLE_FAIL2BAN" = "yes" ] && echo "  Fail2ban:          Configured"
    echo ""

    echo -e "${YELLOW}Commands:${NC}"
    echo "  sudo systemctl start hookprobe-sentinel    # Start service"
    echo "  sudo systemctl status hookprobe-sentinel   # Check status"
    echo "  sudo journalctl -u hookprobe-sentinel -f   # View logs"
    echo "  curl http://localhost:${HEALTH_PORT}/health  # Health check"
    echo "  sudo sentinel-uninstall                    # Uninstall"
    echo ""

    echo -e "${CYAN}Files:${NC}"
    echo "  Install:   $INSTALL_DIR"
    echo "  Config:    $CONFIG_DIR/sentinel.env"
    echo "  Keys:      $KEYS_DIR"
    echo "  Logs:      $LOG_DIR/sentinel.log"
    echo "  Data:      $DATA_DIR"
    echo ""
}

# ============================================================
# UNINSTALL
# ============================================================

uninstall() {
    log_warn "Uninstalling HookProbe Sentinel..."

    # Stop service
    systemctl stop hookprobe-sentinel.service 2>/dev/null || true
    systemctl disable hookprobe-sentinel.service 2>/dev/null || true

    # Remove service file
    rm -f /etc/systemd/system/hookprobe-sentinel.service
    systemctl daemon-reload

    # Remove firewall rules
    iptables -D INPUT -j HOOKPROBE 2>/dev/null || true
    iptables -F HOOKPROBE 2>/dev/null || true
    iptables -X HOOKPROBE 2>/dev/null || true

    # Remove fail2ban config
    rm -f /etc/fail2ban/jail.d/hookprobe-sentinel.conf
    rm -f /etc/fail2ban/filter.d/hookprobe-sentinel.conf
    systemctl restart fail2ban 2>/dev/null || true

    # Remove files
    rm -rf "$INSTALL_DIR"
    rm -rf "$HOOKPROBE_DIR/shared" "$HOOKPROBE_DIR/core"
    rm -f "$CONFIG_DIR/sentinel.env"
    rm -rf "$DATA_DIR"
    rm -rf "$KEYS_DIR"

    log_info "Uninstalled successfully"
    exit 0
}

# ============================================================
# HELP
# ============================================================

show_help() {
    cat << HELP
HookProbe Sentinel Bootstrap v${VERSION}
"The Watchful Eye" - Secure edge validator

Usage:
  curl -sSL $GITHUB_RAW/bootstrap.sh | sudo bash
  curl -sSL ... | sudo bash -s -- [OPTIONS]

Options:
  --mesh-endpoint URL   Mesh backend server (default: mesh.hookprobe.com)
  --mesh-port PORT      Mesh port (default: 8443)
  --mesh-token TOKEN    Mesh authentication token
  --mssp-url URL        MSSP dashboard URL (default: https://mssp.hookprobe.com)
  --health-port PORT    Health endpoint port (default: 9090)
  --region REGION       Region code (default: auto-detect)
  --no-firewall         Skip firewall configuration
  --no-fail2ban         Skip fail2ban configuration
  --no-mesh             Skip mesh/DSM/HTP module installation
  --uninstall           Remove Sentinel completely
  --help                Show this help

Security Features:
  • HTP (HookProbe Transport Protocol) for mesh
  • Rate limiting / DDoS protection
  • Threat pattern detection
  • File integrity monitoring
  • Process sandboxing (seccomp)
  • Automatic firewall rules
  • Fail2ban integration

Examples:
  # Basic install
  curl -sSL ... | sudo bash

  # Custom mesh endpoint
  curl -sSL ... | sudo bash -s -- --mesh-endpoint security.mycompany.com

  # Minimal install (no firewall/fail2ban)
  curl -sSL ... | sudo bash -s -- --no-firewall --no-fail2ban

HELP
    exit 0
}

# ============================================================
# MAIN
# ============================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --mesh-endpoint) MESH_ENDPOINT="$2"; shift 2 ;;
            --mesh-port) MESH_PORT="$2"; shift 2 ;;
            --mesh-token) MESH_TOKEN="$2"; shift 2 ;;
            --mssp-url) MSSP_URL="$2"; shift 2 ;;
            --health-port) HEALTH_PORT="$2"; shift 2 ;;
            --region) SENTINEL_REGION="$2"; shift 2 ;;
            --no-firewall) ENABLE_FIREWALL="no"; shift ;;
            --no-fail2ban) ENABLE_FAIL2BAN="no"; shift ;;
            --no-mesh) ENABLE_MESH="no"; shift ;;
            --uninstall) uninstall ;;
            --help|-h) show_help ;;
            *) log_error "Unknown option: $1"; show_help ;;
        esac
    done

    show_banner
    check_root
    check_internet
    detect_platform
    install_deps
    download_sentinel
    download_core_modules
    create_keys_directory
    create_config
    setup_firewall
    setup_fail2ban
    create_service
    create_uninstall_command
    verify_installation
    show_complete

    # Auto-start prompt
    echo ""
    read -p "Start Sentinel now? [Y/n]: " start_now
    if [ "${start_now:-y}" != "n" ] && [ "${start_now:-Y}" != "N" ]; then
        systemctl start hookprobe-sentinel.service
        sleep 2
        if systemctl is-active --quiet hookprobe-sentinel.service; then
            echo -e "${GREEN}✓ Sentinel is running${NC}"
            echo ""
            echo "Health check: curl http://localhost:${HEALTH_PORT}/health"
        else
            echo -e "${RED}✗ Failed to start. Check: journalctl -u hookprobe-sentinel -e${NC}"
        fi
    fi
}

main "$@"
