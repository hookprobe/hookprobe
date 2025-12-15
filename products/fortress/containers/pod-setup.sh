#!/bin/bash
#
# HookProbe Fortress - Container Pod Infrastructure
# Creates the Fortress pod with VXLAN networking and container services
#
# Pod Architecture:
#   fortress-pod
#   ├── fortress-postgres     (Database)
#   ├── fortress-web          (Admin Portal)
#   ├── fortress-agent        (QSecBit Agent)
#   └── fortress-redis        (Cache/Sessions)
#
# Network Architecture:
#   - Internal pod network: 10.250.100.0/24
#   - VXLAN VNI 1000 for core services
#   - VXLAN VNI 2000 for MSSP uplink
#
# Version: 5.0.0
# License: AGPL-3.0

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/container_utils.sh" 2>/dev/null || true

# ============================================================
# CONFIGURATION
# ============================================================
POD_NAME="fortress-pod"
POD_NETWORK="10.250.100.0/24"
POD_GATEWAY="10.250.100.1"

# Container images
POSTGRES_IMAGE="docker.io/library/postgres:15-alpine"
REDIS_IMAGE="docker.io/library/redis:7-alpine"
VICTORIAMETRICS_IMAGE="docker.io/victoriametrics/victoria-metrics:latest"
SURICATA_IMAGE="docker.io/jasonish/suricata:latest"
ZEEK_IMAGE="docker.io/zeek/zeek:latest"
PYTHON_IMAGE="docker.io/library/python:3.11-slim"

# Secrets directory
SECRETS_DIR="/etc/hookprobe/secrets"
DATA_DIR="/opt/hookprobe/fortress/data"

# VXLAN Configuration
VXLAN_CORE_VNI=1000
VXLAN_CORE_PORT=4800
VXLAN_MSSP_VNI=2000
VXLAN_MSSP_PORT=4900

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }

# ============================================================
# SECRETS MANAGEMENT
# ============================================================
generate_secret() {
    openssl rand -base64 32 | tr -d '/+=' | head -c 32
}

setup_secrets() {
    log_step "Setting up secrets..."

    mkdir -p "$SECRETS_DIR"/{database,vxlan,web}
    chmod 700 "$SECRETS_DIR"

    # PostgreSQL secrets
    if [ ! -f "$SECRETS_DIR/database/postgres_password" ]; then
        generate_secret > "$SECRETS_DIR/database/postgres_password"
        chmod 600 "$SECRETS_DIR/database/postgres_password"
        log_info "Generated PostgreSQL password"
    fi

    # Redis secret (optional auth)
    if [ ! -f "$SECRETS_DIR/database/redis_password" ]; then
        generate_secret > "$SECRETS_DIR/database/redis_password"
        chmod 600 "$SECRETS_DIR/database/redis_password"
        log_info "Generated Redis password"
    fi

    # Web secret key
    if [ ! -f "$SECRETS_DIR/web/secret_key" ]; then
        generate_secret > "$SECRETS_DIR/web/secret_key"
        chmod 600 "$SECRETS_DIR/web/secret_key"
        log_info "Generated web secret key"
    fi

    # VXLAN PSK
    if [ ! -f "$SECRETS_DIR/vxlan/core.psk" ]; then
        generate_secret > "$SECRETS_DIR/vxlan/core.psk"
        chmod 600 "$SECRETS_DIR/vxlan/core.psk"
        log_info "Generated VXLAN core PSK"
    fi

    if [ ! -f "$SECRETS_DIR/vxlan/mssp.psk" ]; then
        generate_secret > "$SECRETS_DIR/vxlan/mssp.psk"
        chmod 600 "$SECRETS_DIR/vxlan/mssp.psk"
        log_info "Generated VXLAN MSSP PSK"
    fi

    log_info "Secrets initialized"
}

# ============================================================
# DATA DIRECTORIES
# ============================================================
setup_data_dirs() {
    log_step "Setting up data directories..."

    mkdir -p "$DATA_DIR"/{postgres,redis,logs,reports}
    mkdir -p "$DATA_DIR"/{victoriametrics,suricata-logs,suricata-rules}
    mkdir -p "$DATA_DIR"/{zeek-logs,zeek-spool,ml-models,threat-intel}
    chmod 755 "$DATA_DIR"

    # PostgreSQL needs specific permissions
    mkdir -p "$DATA_DIR/postgres"
    # Note: PostgreSQL container will set correct ownership

    log_info "Data directories created"
}

# ============================================================
# VXLAN SETUP
# ============================================================
setup_vxlan() {
    log_step "Setting up VXLAN tunnels..."

    local LOCAL_IP=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || hostname -I | awk '{print $1}')

    # Create VXLAN interface for core services
    if ! ip link show vxlan${VXLAN_CORE_VNI} &>/dev/null; then
        ip link add vxlan${VXLAN_CORE_VNI} type vxlan \
            id ${VXLAN_CORE_VNI} \
            local ${LOCAL_IP} \
            dstport ${VXLAN_CORE_PORT} \
            nolearning 2>/dev/null || true
        ip link set vxlan${VXLAN_CORE_VNI} up 2>/dev/null || true
        log_info "Created VXLAN interface vxlan${VXLAN_CORE_VNI}"
    fi

    # Create VXLAN interface for MSSP uplink
    if ! ip link show vxlan${VXLAN_MSSP_VNI} &>/dev/null; then
        ip link add vxlan${VXLAN_MSSP_VNI} type vxlan \
            id ${VXLAN_MSSP_VNI} \
            local ${LOCAL_IP} \
            dstport ${VXLAN_MSSP_PORT} \
            nolearning 2>/dev/null || true
        ip link set vxlan${VXLAN_MSSP_VNI} up 2>/dev/null || true
        log_info "Created VXLAN interface vxlan${VXLAN_MSSP_VNI}"
    fi

    # Save VXLAN configuration
    cat > /etc/hookprobe/vxlan.conf << VXLANEOF
# HookProbe Fortress VXLAN Configuration
# Generated: $(date -Iseconds)

LOCAL_IP=${LOCAL_IP}

# Core Services VXLAN
VXLAN_CORE_VNI=${VXLAN_CORE_VNI}
VXLAN_CORE_PORT=${VXLAN_CORE_PORT}
VXLAN_CORE_PSK=${SECRETS_DIR}/vxlan/core.psk

# MSSP Uplink VXLAN
VXLAN_MSSP_VNI=${VXLAN_MSSP_VNI}
VXLAN_MSSP_PORT=${VXLAN_MSSP_PORT}
VXLAN_MSSP_PSK=${SECRETS_DIR}/vxlan/mssp.psk
VXLANEOF

    log_info "VXLAN configuration saved"
}

# ============================================================
# POD CREATION
# ============================================================
create_pod() {
    log_step "Creating Fortress pod..."

    # Remove existing pod if present
    podman pod exists "$POD_NAME" 2>/dev/null && {
        log_warn "Removing existing pod..."
        podman pod rm -f "$POD_NAME" 2>/dev/null || true
    }

    # Create pod with exposed ports
    podman pod create \
        --name "$POD_NAME" \
        --network bridge \
        --publish 8443:8443 \
        --publish 5432:5432 \
        --publish 6379:6379 \
        --publish 9090:9090 \
        --infra-name fortress-infra

    log_info "Pod '$POD_NAME' created"
}

# ============================================================
# POSTGRESQL CONTAINER
# ============================================================
create_postgres_container() {
    log_step "Creating PostgreSQL container..."

    local POSTGRES_PASSWORD=$(cat "$SECRETS_DIR/database/postgres_password")

    podman run -d \
        --pod "$POD_NAME" \
        --name fortress-postgres \
        --restart unless-stopped \
        -e POSTGRES_DB=fortress \
        -e POSTGRES_USER=fortress \
        -e POSTGRES_PASSWORD="${POSTGRES_PASSWORD}" \
        -e PGDATA=/var/lib/postgresql/data/pgdata \
        -v "$DATA_DIR/postgres:/var/lib/postgresql/data:Z" \
        "${POSTGRES_IMAGE}"

    log_info "PostgreSQL container created"

    # Wait for PostgreSQL to be ready
    log_info "Waiting for PostgreSQL to initialize..."
    sleep 5

    local retries=30
    while [ $retries -gt 0 ]; do
        if podman exec fortress-postgres pg_isready -U fortress &>/dev/null; then
            log_info "PostgreSQL is ready"
            break
        fi
        sleep 1
        ((retries--))
    done

    if [ $retries -eq 0 ]; then
        log_error "PostgreSQL failed to start"
        return 1
    fi

    # Initialize database schema
    init_database_schema
}

init_database_schema() {
    log_step "Initializing database schema..."

    local POSTGRES_PASSWORD=$(cat "$SECRETS_DIR/database/postgres_password")

    podman exec -i fortress-postgres psql -U fortress -d fortress << 'SCHEMA'
-- HookProbe Fortress Database Schema
-- Version: 5.0.0

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Devices table (connected clients)
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mac_address VARCHAR(17) UNIQUE NOT NULL,
    ip_address INET,
    hostname VARCHAR(255),
    device_type VARCHAR(50),
    manufacturer VARCHAR(255),
    vlan_id INTEGER DEFAULT 40,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_blocked BOOLEAN DEFAULT FALSE,
    is_known BOOLEAN DEFAULT FALSE,
    notes TEXT,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_vlan ON devices(vlan_id);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);

-- VLANs table
CREATE TABLE IF NOT EXISTS vlans (
    id SERIAL PRIMARY KEY,
    vlan_id INTEGER UNIQUE NOT NULL,
    name VARCHAR(50) NOT NULL,
    description TEXT,
    subnet CIDR NOT NULL,
    gateway INET,
    dhcp_enabled BOOLEAN DEFAULT TRUE,
    dhcp_range_start INET,
    dhcp_range_end INET,
    dns_policy VARCHAR(20) DEFAULT 'standard',
    bandwidth_limit_mbps INTEGER,
    is_isolated BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert default VLANs
INSERT INTO vlans (vlan_id, name, description, subnet, gateway, is_isolated)
VALUES
    (10, 'Management', 'Admin and management devices', '10.250.10.0/24', '10.250.10.1', false),
    (20, 'POS', 'Point of Sale terminals', '10.250.20.0/24', '10.250.20.1', true),
    (30, 'Staff', 'Staff devices', '10.250.30.0/24', '10.250.30.1', false),
    (40, 'Guest', 'Guest WiFi network', '10.250.40.0/24', '10.250.40.1', true),
    (99, 'IoT', 'IoT devices and sensors', '10.250.99.0/24', '10.250.99.1', true)
ON CONFLICT (vlan_id) DO NOTHING;

-- Threats table
CREATE TABLE IF NOT EXISTS threats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    threat_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    source_ip INET,
    source_mac VARCHAR(17),
    destination_ip INET,
    destination_port INTEGER,
    protocol VARCHAR(10),
    description TEXT,
    mitre_attack_id VARCHAR(20),
    is_blocked BOOLEAN DEFAULT FALSE,
    blocked_at TIMESTAMP WITH TIME ZONE,
    evidence JSONB DEFAULT '{}'::jsonb,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threats_type ON threats(threat_type);
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_detected ON threats(detected_at);
CREATE INDEX IF NOT EXISTS idx_threats_source ON threats(source_ip);

-- QSecBit scores history
CREATE TABLE IF NOT EXISTS qsecbit_history (
    id SERIAL PRIMARY KEY,
    score DECIMAL(5,4) NOT NULL,
    rag_status VARCHAR(10) NOT NULL,
    components JSONB NOT NULL,
    layer_stats JSONB,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_qsecbit_recorded ON qsecbit_history(recorded_at);

-- DNS queries log (for analytics)
CREATE TABLE IF NOT EXISTS dns_queries (
    id BIGSERIAL PRIMARY KEY,
    client_ip INET NOT NULL,
    client_mac VARCHAR(17),
    domain VARCHAR(255) NOT NULL,
    query_type VARCHAR(10),
    response_code VARCHAR(20),
    is_blocked BOOLEAN DEFAULT FALSE,
    block_reason VARCHAR(50),
    category VARCHAR(50),
    queried_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_queries USING gin(domain gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_dns_client ON dns_queries(client_ip);
CREATE INDEX IF NOT EXISTS idx_dns_blocked ON dns_queries(is_blocked) WHERE is_blocked = TRUE;
CREATE INDEX IF NOT EXISTS idx_dns_queried ON dns_queries(queried_at);

-- Audit log for admin actions
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    details JSONB,
    ip_address INET,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);

-- Reports table
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    report_type VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    parameters JSONB,
    file_path VARCHAR(500),
    file_size INTEGER,
    generated_by VARCHAR(50),
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Scheduled reports
CREATE TABLE IF NOT EXISTS scheduled_reports (
    id SERIAL PRIMARY KEY,
    report_type VARCHAR(50) NOT NULL,
    schedule VARCHAR(50) NOT NULL,
    parameters JSONB,
    email_recipients TEXT[],
    is_enabled BOOLEAN DEFAULT TRUE,
    last_run TIMESTAMP WITH TIME ZONE,
    next_run TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create views for common queries
CREATE OR REPLACE VIEW v_device_summary AS
SELECT
    vlan_id,
    COUNT(*) as device_count,
    COUNT(*) FILTER (WHERE last_seen > NOW() - INTERVAL '5 minutes') as active_count,
    COUNT(*) FILTER (WHERE is_blocked) as blocked_count
FROM devices
GROUP BY vlan_id;

CREATE OR REPLACE VIEW v_threat_summary AS
SELECT
    DATE_TRUNC('hour', detected_at) as hour,
    threat_type,
    severity,
    COUNT(*) as count
FROM threats
WHERE detected_at > NOW() - INTERVAL '24 hours'
GROUP BY DATE_TRUNC('hour', detected_at), threat_type, severity
ORDER BY hour DESC;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO fortress;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO fortress;

SCHEMA

    log_info "Database schema initialized"
}

# ============================================================
# REDIS CONTAINER
# ============================================================
create_redis_container() {
    log_step "Creating Redis container..."

    local REDIS_PASSWORD=$(cat "$SECRETS_DIR/database/redis_password")

    podman run -d \
        --pod "$POD_NAME" \
        --name fortress-redis \
        --restart unless-stopped \
        -v "$DATA_DIR/redis:/data:Z" \
        "${REDIS_IMAGE}" \
        redis-server --appendonly yes --requirepass "${REDIS_PASSWORD}"

    log_info "Redis container created"
}

# ============================================================
# VICTORIA METRICS CONTAINER (Time-series for ML training)
# ============================================================
create_victoriametrics_container() {
    log_step "Creating Victoria Metrics container..."

    podman run -d \
        --pod "$POD_NAME" \
        --name fortress-victoriametrics \
        --restart unless-stopped \
        -v "$DATA_DIR/victoriametrics:/victoria-metrics-data:Z" \
        "${VICTORIAMETRICS_IMAGE}" \
        -retentionPeriod=30d \
        -httpListenAddr=:8428

    log_info "Victoria Metrics container created (port 8428)"
}

# ============================================================
# SURICATA IDS CONTAINER
# ============================================================
create_suricata_container() {
    log_step "Creating Suricata IDS container..."

    # Determine interface to monitor (prefer wired interfaces)
    local MONITOR_IFACE=""
    if [ -e /sys/class/net/eth0 ]; then
        MONITOR_IFACE="eth0"
    elif [ -e /sys/class/net/br0 ]; then
        MONITOR_IFACE="br0"
    elif [ -e /sys/class/net/fortress ]; then
        MONITOR_IFACE="fortress"
    else
        log_warn "No suitable interface found for Suricata, using any"
        MONITOR_IFACE="any"
    fi

    log_info "Suricata will monitor interface: $MONITOR_IFACE"

    # Run Suricata with host network for traffic visibility
    podman run -d \
        --name fortress-suricata \
        --network host \
        --cap-add NET_ADMIN \
        --cap-add NET_RAW \
        --cap-add SYS_NICE \
        --restart unless-stopped \
        -v "$DATA_DIR/suricata-logs:/var/log/suricata:Z" \
        -v "$DATA_DIR/suricata-rules:/var/lib/suricata:Z" \
        "${SURICATA_IMAGE}" \
        -i "$MONITOR_IFACE"

    log_info "Suricata IDS container created"
}

# ============================================================
# ZEEK NETWORK ANALYZER CONTAINER
# ============================================================
create_zeek_container() {
    log_step "Creating Zeek Network Analyzer container..."

    # Determine interface to monitor
    local MONITOR_IFACE=""
    if [ -e /sys/class/net/eth0 ]; then
        MONITOR_IFACE="eth0"
    elif [ -e /sys/class/net/br0 ]; then
        MONITOR_IFACE="br0"
    elif [ -e /sys/class/net/fortress ]; then
        MONITOR_IFACE="fortress"
    else
        log_warn "No suitable interface found for Zeek"
        MONITOR_IFACE="eth0"
    fi

    log_info "Zeek will monitor interface: $MONITOR_IFACE"

    # Create Zeek configuration
    mkdir -p /opt/hookprobe/fortress/zeek
    cat > /opt/hookprobe/fortress/zeek/local.zeek << 'ZEEKEOF'
# Fortress Zeek Configuration - Threat Pattern Analysis
# Focus: HOW users are targeted, NOT what they browse

@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load policy/misc/detect-traceroute
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services

# Custom threat pattern detection
redef Notice::policy += {
    [$action = Notice::ACTION_LOG,
     $pred(n: Notice::Info) = {
        return n$note in set(
            Scan::Port_Scan,
            Scan::Address_Scan,
            SSL::Invalid_Server_Cert,
            DNS::External_Name
        );
     }]
};
ZEEKEOF

    # Run Zeek with host network
    podman run -d \
        --name fortress-zeek \
        --network host \
        --cap-add NET_ADMIN \
        --cap-add NET_RAW \
        --restart unless-stopped \
        --memory 512m \
        -v "$DATA_DIR/zeek-logs:/usr/local/zeek/logs:Z" \
        -v "$DATA_DIR/zeek-spool:/usr/local/zeek/spool:Z" \
        -v "/opt/hookprobe/fortress/zeek/local.zeek:/usr/local/zeek/share/zeek/site/local.zeek:ro" \
        "${ZEEK_IMAGE}" \
        zeek -i "$MONITOR_IFACE" local

    log_info "Zeek Network Analyzer container created"
}

# ============================================================
# ML THREAT AGGREGATOR SERVICE
# ============================================================
setup_ml_aggregator() {
    log_step "Setting up ML Threat Aggregator..."

    # Create ML aggregator Python script
    mkdir -p /opt/hookprobe/fortress/ml
    cat > /opt/hookprobe/fortress/ml/threat_aggregator.py << 'PYEOF'
#!/usr/bin/env python3
"""
Fortress ML Threat Aggregator

Aggregates threat data from Suricata, Zeek, and XDP for LSTM training.
Focus: HOW users are targeted (attack patterns), NOT what they browse.

Privacy-first design:
- No domain logging (handled by dnsXai separately, if enabled)
- No URL content storage
- Only attack signatures and patterns
- IP addresses anonymized after 24h
"""

import json
import time
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Any

# Data paths
SURICATA_LOG = Path("/opt/hookprobe/fortress/data/suricata-logs/eve.json")
ZEEK_LOG_DIR = Path("/opt/hookprobe/fortress/data/zeek-logs/current")
OUTPUT_DIR = Path("/opt/hookprobe/fortress/data/threat-intel")
ML_DATA_DIR = Path("/opt/hookprobe/fortress/data/ml-models")

class ThreatAggregator:
    """Aggregates threats for ML training - privacy preserving"""

    def __init__(self):
        self.threats = []
        self.patterns = defaultdict(int)
        self.attack_sequences = []
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        ML_DATA_DIR.mkdir(parents=True, exist_ok=True)

    def anonymize_ip(self, ip: str) -> str:
        """Anonymize IP for privacy - keep only network class"""
        if not ip:
            return "0.0.0.0"
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.0.0"
        return "0.0.0.0"

    def parse_suricata_alerts(self, limit: int = 1000) -> List[Dict]:
        """Parse Suricata alerts - extract attack patterns only"""
        alerts = []
        try:
            if not SURICATA_LOG.exists():
                return alerts

            with open(SURICATA_LOG, 'r') as f:
                # Read last N lines
                lines = f.readlines()[-limit:]

            for line in lines:
                try:
                    event = json.loads(line.strip())
                    if event.get("event_type") == "alert":
                        alert_data = event.get("alert", {})
                        # Extract ONLY attack pattern, not content
                        pattern = {
                            "timestamp": event.get("timestamp"),
                            "signature_id": alert_data.get("signature_id"),
                            "signature": alert_data.get("signature", ""),
                            "category": alert_data.get("category", ""),
                            "severity": alert_data.get("severity", 3),
                            "src_ip_anon": self.anonymize_ip(event.get("src_ip")),
                            "dest_port": event.get("dest_port"),
                            "protocol": event.get("proto", ""),
                            # NO: dest_ip (target), NO: HTTP content, NO: DNS queries
                        }
                        alerts.append(pattern)
                        self.patterns[alert_data.get("category", "unknown")] += 1
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            print(f"Error parsing Suricata: {e}")
        return alerts

    def parse_zeek_notices(self, limit: int = 500) -> List[Dict]:
        """Parse Zeek notices - extract attack indicators only"""
        notices = []
        try:
            notice_log = ZEEK_LOG_DIR / "notice.log"
            if not notice_log.exists():
                return notices

            with open(notice_log, 'r') as f:
                lines = f.readlines()[-limit:]

            for line in lines:
                if line.startswith('#'):
                    continue
                try:
                    event = json.loads(line.strip())
                    notice = {
                        "timestamp": event.get("ts"),
                        "note": event.get("note", ""),
                        "msg": event.get("msg", "")[:100],  # Truncate message
                        "src_ip_anon": self.anonymize_ip(event.get("src")),
                        "dest_port": event.get("p"),
                        # NO: full message content, NO: domain names
                    }
                    notices.append(notice)
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            print(f"Error parsing Zeek: {e}")
        return notices

    def extract_attack_sequences(self) -> List[Dict]:
        """Extract temporal attack sequences for LSTM training"""
        sequences = []

        # Group alerts by source (anonymized)
        source_events = defaultdict(list)

        for alert in self.threats:
            src = alert.get("src_ip_anon", "unknown")
            source_events[src].append({
                "time": alert.get("timestamp"),
                "category": alert.get("category", "unknown"),
                "severity": alert.get("severity", 3),
                "port": alert.get("dest_port", 0)
            })

        # Build sequences (attack chains)
        for src, events in source_events.items():
            if len(events) >= 3:  # Only sequences with 3+ events
                sequences.append({
                    "source_hash": hashlib.md5(src.encode()).hexdigest()[:8],
                    "event_count": len(events),
                    "categories": [e["category"] for e in events[:20]],
                    "severity_pattern": [e["severity"] for e in events[:20]],
                    "port_pattern": [e["port"] for e in events[:20]]
                })

        return sequences

    def aggregate(self) -> Dict:
        """Aggregate all threat data for ML training"""
        # Collect from sources
        suricata_alerts = self.parse_suricata_alerts()
        zeek_notices = self.parse_zeek_notices()

        self.threats = suricata_alerts + zeek_notices

        # Extract sequences for LSTM
        sequences = self.extract_attack_sequences()

        result = {
            "timestamp": datetime.now().isoformat(),
            "stats": {
                "suricata_alerts": len(suricata_alerts),
                "zeek_notices": len(zeek_notices),
                "unique_patterns": len(self.patterns),
                "attack_sequences": len(sequences)
            },
            "pattern_distribution": dict(self.patterns),
            "training_ready": len(sequences) >= 10
        }

        # Save for ML training
        self._save_training_data(sequences)

        # Save summary
        with open(OUTPUT_DIR / "aggregated.json", 'w') as f:
            json.dump(result, f, indent=2)

        return result

    def _save_training_data(self, sequences: List[Dict]):
        """Save training data for LSTM model"""
        training_file = ML_DATA_DIR / f"training_{datetime.now().strftime('%Y%m%d')}.jsonl"

        with open(training_file, 'a') as f:
            for seq in sequences:
                f.write(json.dumps(seq) + '\n')


def main():
    """Run aggregator continuously"""
    aggregator = ThreatAggregator()

    while True:
        try:
            result = aggregator.aggregate()
            print(f"[{datetime.now()}] Aggregated: "
                  f"Suricata={result['stats']['suricata_alerts']}, "
                  f"Zeek={result['stats']['zeek_notices']}, "
                  f"Sequences={result['stats']['attack_sequences']}")
        except Exception as e:
            print(f"Error: {e}")

        time.sleep(60)  # Run every minute


if __name__ == "__main__":
    main()
PYEOF

    chmod +x /opt/hookprobe/fortress/ml/threat_aggregator.py

    # Create systemd service for ML aggregator
    cat > /etc/systemd/system/fortress-ml-aggregator.service << 'EOF'
[Unit]
Description=Fortress ML Threat Aggregator
After=network.target fortress-suricata.service fortress-zeek.service

[Service]
Type=simple
Restart=always
RestartSec=30
ExecStart=/usr/bin/python3 /opt/hookprobe/fortress/ml/threat_aggregator.py
StandardOutput=append:/var/log/hookprobe/ml-aggregator.log
StandardError=append:/var/log/hookprobe/ml-aggregator.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable fortress-ml-aggregator 2>/dev/null || true

    log_info "ML Threat Aggregator service created"
}

# ============================================================
# LSTM DAILY TRAINING SERVICE
# ============================================================
setup_lstm_training() {
    log_step "Setting up LSTM daily training service..."

    # Create daily training service
    cat > /etc/systemd/system/fortress-lstm-train.service << 'EOF'
[Unit]
Description=Fortress LSTM Threat Model Training
After=network.target fortress-ml-aggregator.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/hookprobe/fortress/lib/lstm_threat_detector.py --train --epochs 100
StandardOutput=append:/var/log/hookprobe/lstm-training.log
StandardError=append:/var/log/hookprobe/lstm-training.log
EOF

    # Create daily training timer (runs at 3am to avoid 4am channel optimization)
    cat > /etc/systemd/system/fortress-lstm-train.timer << 'EOF'
[Unit]
Description=Daily LSTM Threat Model Training (3:00 AM)

[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=600
# DO NOT set Persistent=true - we don't want to run at boot

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable fortress-lstm-train.timer 2>/dev/null || true

    log_info "LSTM daily training timer created (runs at 3:00 AM)"
}

# ============================================================
# DNSXAI PRIVACY CONTROLS
# ============================================================
setup_dnsxai_privacy() {
    log_step "Setting up dnsXai privacy controls..."

    mkdir -p /etc/hookprobe/dnsxai

    # Create default privacy configuration
    cat > /etc/hookprobe/dnsxai/privacy.json << 'PRIVEOF'
{
    "version": "1.0",
    "description": "dnsXai Privacy Settings - Controls what data is collected",
    "settings": {
        "enable_query_logging": false,
        "enable_domain_tracking": false,
        "enable_ad_blocking_stats": true,
        "enable_threat_detection": true,
        "enable_ml_training_data": false,
        "anonymize_client_ips": true,
        "retention_days": 7,
        "export_allowed": false
    },
    "explanation": {
        "enable_query_logging": "Log individual DNS queries (PRIVACY IMPACT: HIGH). Disabled by default.",
        "enable_domain_tracking": "Track domain visit frequency per client (PRIVACY IMPACT: HIGH). Disabled by default.",
        "enable_ad_blocking_stats": "Count blocked ads/trackers (PRIVACY IMPACT: LOW). Enabled for statistics.",
        "enable_threat_detection": "Detect malicious domains (PRIVACY IMPACT: LOW). Essential for security.",
        "enable_ml_training_data": "Use anonymized query patterns for ML (PRIVACY IMPACT: MEDIUM). Disabled by default.",
        "anonymize_client_ips": "Replace client IPs with hashes (PRIVACY IMPACT: NONE). Always recommended.",
        "retention_days": "Days to keep logs before deletion. Shorter = more privacy.",
        "export_allowed": "Allow exporting DNS data. Disabled by default."
    }
}
PRIVEOF

    chmod 644 /etc/hookprobe/dnsxai/privacy.json

    # Create privacy management script
    cat > /usr/local/bin/fortress-dnsxai-privacy << 'PRIVSCRIPT'
#!/bin/bash
#
# Fortress dnsXai Privacy Control Tool
#
# Manages privacy settings for DNS query tracking
# Users can enable/disable tracking at any time

PRIVACY_FILE="/etc/hookprobe/dnsxai/privacy.json"

show_status() {
    echo "=== dnsXai Privacy Settings ==="
    echo ""
    if [ -f "$PRIVACY_FILE" ]; then
        python3 -c "
import json
with open('$PRIVACY_FILE') as f:
    data = json.load(f)
    settings = data.get('settings', {})
    explain = data.get('explanation', {})
    for key, value in settings.items():
        status = '✓ Enabled' if value else '✗ Disabled'
        if isinstance(value, int):
            status = str(value)
        print(f'  {key}: {status}')
        if key in explain:
            print(f'    → {explain[key]}')
        print()
"
    else
        echo "Privacy file not found!"
    fi
}

set_privacy() {
    local setting="$1"
    local value="$2"

    if [ -z "$setting" ] || [ -z "$value" ]; then
        echo "Usage: $0 set <setting> <true|false>"
        exit 1
    fi

    python3 -c "
import json
import sys

with open('$PRIVACY_FILE', 'r') as f:
    data = json.load(f)

setting = '$setting'
value_str = '$value'.lower()

if setting not in data.get('settings', {}):
    print(f'Unknown setting: {setting}')
    print('Available settings:', ', '.join(data.get('settings', {}).keys()))
    sys.exit(1)

if value_str in ('true', 'yes', '1', 'on'):
    value = True
elif value_str in ('false', 'no', '0', 'off'):
    value = False
elif value_str.isdigit():
    value = int(value_str)
else:
    print(f'Invalid value: {value_str}')
    sys.exit(1)

data['settings'][setting] = value

with open('$PRIVACY_FILE', 'w') as f:
    json.dump(data, f, indent=2)

print(f'Set {setting} = {value}')
"
}

maximum_privacy() {
    echo "Setting maximum privacy mode..."
    python3 -c "
import json

with open('$PRIVACY_FILE', 'r') as f:
    data = json.load(f)

data['settings'] = {
    'enable_query_logging': False,
    'enable_domain_tracking': False,
    'enable_ad_blocking_stats': False,
    'enable_threat_detection': True,
    'enable_ml_training_data': False,
    'anonymize_client_ips': True,
    'retention_days': 1,
    'export_allowed': False
}

with open('$PRIVACY_FILE', 'w') as f:
    json.dump(data, f, indent=2)

print('Maximum privacy mode enabled.')
print('Only essential threat detection remains active.')
"
}

balanced_mode() {
    echo "Setting balanced privacy mode..."
    python3 -c "
import json

with open('$PRIVACY_FILE', 'r') as f:
    data = json.load(f)

data['settings'] = {
    'enable_query_logging': False,
    'enable_domain_tracking': False,
    'enable_ad_blocking_stats': True,
    'enable_threat_detection': True,
    'enable_ml_training_data': False,
    'anonymize_client_ips': True,
    'retention_days': 7,
    'export_allowed': False
}

with open('$PRIVACY_FILE', 'w') as f:
    json.dump(data, f, indent=2)

print('Balanced privacy mode enabled.')
print('Threat detection + anonymous ad blocking stats.')
"
}

full_analytics() {
    echo "Setting full analytics mode..."
    echo "WARNING: This enables domain tracking!"
    read -p "Are you sure? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "Cancelled."
        exit 0
    fi

    python3 -c "
import json

with open('$PRIVACY_FILE', 'r') as f:
    data = json.load(f)

data['settings'] = {
    'enable_query_logging': True,
    'enable_domain_tracking': True,
    'enable_ad_blocking_stats': True,
    'enable_threat_detection': True,
    'enable_ml_training_data': True,
    'anonymize_client_ips': True,
    'retention_days': 30,
    'export_allowed': False
}

with open('$PRIVACY_FILE', 'w') as f:
    json.dump(data, f, indent=2)

print('Full analytics mode enabled.')
print('All tracking enabled with anonymized IPs.')
"
}

case "${1:-status}" in
    status|show)
        show_status
        ;;
    set)
        set_privacy "$2" "$3"
        ;;
    maximum|max)
        maximum_privacy
        ;;
    balanced|default)
        balanced_mode
        ;;
    full|analytics)
        full_analytics
        ;;
    help|*)
        echo "dnsXai Privacy Control Tool"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  status     - Show current privacy settings"
        echo "  set <key> <value> - Set a specific setting"
        echo "  maximum    - Maximum privacy (minimal tracking)"
        echo "  balanced   - Balanced mode (default)"
        echo "  full       - Full analytics (requires confirmation)"
        echo ""
        echo "Your privacy, your choice."
        ;;
esac
PRIVSCRIPT

    chmod +x /usr/local/bin/fortress-dnsxai-privacy

    log_info "dnsXai privacy controls installed"
    log_info "Use 'fortress-dnsxai-privacy status' to view settings"
    log_info "Use 'fortress-dnsxai-privacy maximum' for maximum privacy"
}

# ============================================================
# STATUS CHECK
# ============================================================
check_status() {
    echo ""
    echo "=== Fortress Pod Status ==="
    echo ""
    podman pod ps --filter name="$POD_NAME"
    echo ""
    echo "=== Container Status ==="
    podman ps --filter pod="$POD_NAME" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    echo ""
}

# ============================================================
# CLEANUP
# ============================================================
cleanup() {
    log_step "Cleaning up Fortress containers..."

    podman pod exists "$POD_NAME" 2>/dev/null && {
        podman pod stop "$POD_NAME" 2>/dev/null || true
        podman pod rm -f "$POD_NAME" 2>/dev/null || true
        log_info "Pod removed"
    }

    # Remove VXLAN interfaces
    ip link del vxlan${VXLAN_CORE_VNI} 2>/dev/null || true
    ip link del vxlan${VXLAN_MSSP_VNI} 2>/dev/null || true

    log_info "Cleanup complete"
}

# ============================================================
# MAIN
# ============================================================
main() {
    case "${1:-}" in
        start|up)
            setup_secrets
            setup_data_dirs
            setup_vxlan
            create_pod
            create_postgres_container
            create_redis_container
            create_victoriametrics_container
            create_suricata_container
            create_zeek_container
            setup_ml_aggregator
            setup_lstm_training
            setup_dnsxai_privacy
            check_status
            log_info "Fortress pod started successfully"
            log_info "PostgreSQL: localhost:5432 (user: fortress)"
            log_info "Redis: localhost:6379"
            log_info "Victoria Metrics: localhost:8428"
            log_info "Suricata IDS: monitoring network traffic"
            log_info "Zeek: analyzing network patterns"
            log_info "ML Aggregator: collecting threat data for LSTM training"
            log_info "Web Portal: https://localhost:8443"
            ;;
        stop|down)
            podman pod stop "$POD_NAME" 2>/dev/null || true
            log_info "Fortress pod stopped"
            ;;
        restart)
            podman pod restart "$POD_NAME" 2>/dev/null || {
                $0 stop
                $0 start
            }
            ;;
        status)
            check_status
            ;;
        logs)
            local container="${2:-fortress-postgres}"
            podman logs -f "$container"
            ;;
        shell)
            local container="${2:-fortress-postgres}"
            podman exec -it "$container" /bin/sh
            ;;
        psql)
            local POSTGRES_PASSWORD=$(cat "$SECRETS_DIR/database/postgres_password")
            podman exec -it fortress-postgres psql -U fortress -d fortress
            ;;
        cleanup|remove)
            cleanup
            ;;
        *)
            echo "Usage: $0 {start|stop|restart|status|logs|shell|psql|cleanup}"
            echo ""
            echo "Commands:"
            echo "  start    - Start Fortress pod and containers"
            echo "  stop     - Stop Fortress pod"
            echo "  restart  - Restart Fortress pod"
            echo "  status   - Show pod and container status"
            echo "  logs     - Show container logs (default: postgres)"
            echo "  shell    - Open shell in container"
            echo "  psql     - Open PostgreSQL shell"
            echo "  cleanup  - Remove all containers and data"
            exit 1
            ;;
    esac
}

main "$@"
