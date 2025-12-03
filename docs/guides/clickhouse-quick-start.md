# ClickHouse Quick Start Guide

**For HookProbe v5.0**
**Quick Reference**: Implementation steps for ClickHouse integration

---

## 🚀 Fast Track Implementation (30 minutes)

### Prerequisites

```bash
# Ensure HookProbe v5.0 is deployed
cd /home/user/hookprobe/Scripts/autonomous/install/
podman pod ps | grep hookprobe
```

### Step 1: Update Configuration (5 min)

**Edit `network-config.sh`:**

```bash
nano Scripts/autonomous/install/network-config.sh

# Add after line 88 (IP_NODE_EXPORTER):
IP_CLICKHOUSE="10.200.5.15"
IP_FILEBEAT="10.200.5.16"

# Add after line 122 (IMAGE_CLOUDFLARED):
IMAGE_CLICKHOUSE="docker.io/clickhouse/clickhouse-server:24.11"
IMAGE_FILEBEAT="docker.io/elastic/filebeat:8.11.0"

# Add after line 233 (VOLUME_HONEYPOT_DATA):
VOLUME_CLICKHOUSE_DATA="hookprobe-clickhouse-v5"
VOLUME_CLICKHOUSE_LOGS="hookprobe-clickhouse-logs-v5"

# Add after line 268 (PORT_QSECBIT_API):
PORT_CLICKHOUSE_HTTP=8123
PORT_CLICKHOUSE_NATIVE=9000

# Add new section before "SECURITY HARDENING FLAGS":
# ============================================================
# CLICKHOUSE CONFIGURATION
# ============================================================
CLICKHOUSE_DB="security"
CLICKHOUSE_USER="hookprobe"
CLICKHOUSE_PASSWORD="CHANGE_ME_CLICKHOUSE_STRONG_PASSWORD_123"
CLICKHOUSE_MAX_MEMORY_GB=8
CLICKHOUSE_RETENTION_DAYS=90
```

### Step 2: Deploy ClickHouse (10 min)

**Create deployment script:**

```bash
cat > /tmp/deploy-clickhouse.sh << 'EOF'
#!/bin/bash
set -e

source Scripts/autonomous/install/network-config.sh

echo "Creating ClickHouse volumes..."
podman volume create hookprobe-clickhouse-v5
podman volume create hookprobe-clickhouse-logs-v5

echo "Creating ClickHouse configuration..."
mkdir -p /tmp/clickhouse-config

cat > /tmp/clickhouse-config/users.xml << USEREOF
<yandex>
    <profiles>
        <default>
            <max_memory_usage>8000000000</max_memory_usage>
        </default>
    </profiles>
    <users>
        <${CLICKHOUSE_USER}>
            <password>${CLICKHOUSE_PASSWORD}</password>
            <networks><ip>::/0</ip></networks>
            <profile>default</profile>
            <quota>default</quota>
        </${CLICKHOUSE_USER}>
    </users>
    <quotas>
        <default>
            <interval>
                <duration>3600</duration>
                <queries>0</queries>
                <errors>0</errors>
            </interval>
        </default>
    </quotas>
</yandex>
USEREOF

echo "Deploying ClickHouse container..."
podman run -d --restart always \
    --pod hookprobe-monitoring \
    --name hookprobe-monitoring-clickhouse \
    --ip 10.200.5.15 \
    -v hookprobe-clickhouse-v5:/var/lib/clickhouse \
    -v hookprobe-clickhouse-logs-v5:/var/log/clickhouse-server \
    -v /tmp/clickhouse-config/users.xml:/etc/clickhouse-server/users.d/custom.xml:ro \
    --ulimit nofile=262144:262144 \
    --log-driver=journald \
    --log-opt tag="hookprobe-clickhouse" \
    docker.io/clickhouse/clickhouse-server:24.11

echo "Waiting for ClickHouse to start..."
sleep 15

echo "Testing ClickHouse..."
curl http://10.200.5.15:8123/ping

echo "✓ ClickHouse deployed successfully!"
EOF

chmod +x /tmp/deploy-clickhouse.sh
sudo /tmp/deploy-clickhouse.sh
```

### Step 3: Create Database Schema (5 min)

```bash
cat > /tmp/init-clickhouse.sql << 'EOF'
CREATE DATABASE IF NOT EXISTS security;

CREATE TABLE IF NOT EXISTS security.security_events (
    timestamp DateTime64(3),
    event_id UUID DEFAULT generateUUIDv4(),
    source_type LowCardinality(String),
    src_ip IPv4,
    dst_ip IPv4,
    attack_type LowCardinality(String),
    severity LowCardinality(String),
    blocked UInt8,
    raw_event String CODEC(ZSTD(3))
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, src_ip, attack_type)
TTL timestamp + INTERVAL 90 DAY;

CREATE TABLE IF NOT EXISTS security.qsecbit_scores (
    timestamp DateTime64(3),
    score Float32,
    rag_status LowCardinality(String),
    drift Float32,
    attack_probability Float32,
    classifier_decay Float32,
    quantum_drift Float32
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY timestamp
TTL timestamp + INTERVAL 1 YEAR;

CREATE TABLE IF NOT EXISTS security.waf_events (
    timestamp DateTime64(3),
    src_ip IPv4,
    request_uri String,
    rule_id UInt32,
    attack_category LowCardinality(String),
    blocked UInt8
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, src_ip)
TTL timestamp + INTERVAL 90 DAY;
EOF

podman exec -i hookprobe-monitoring-clickhouse \
    clickhouse-client --multiquery < /tmp/init-clickhouse.sql

echo "✓ Database schema created!"
```

### Step 4: Test Insert & Query (5 min)

```bash
# Test insert
podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "
INSERT INTO security.security_events VALUES
(now(), generateUUIDv4(), 'test', '1.2.3.4', '10.200.1.12', 'xss', 'high', 1, '{\"test\": true}')
"

# Test query
podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "
SELECT * FROM security.security_events FORMAT Pretty
"

# Check compression
podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "
SELECT
    table,
    formatReadableSize(sum(bytes_on_disk)) AS size,
    sum(rows) AS rows
FROM system.parts
WHERE database = 'security'
GROUP BY table
"
```

### Step 5: Add Grafana Data Source (5 min)

```bash
# Install ClickHouse plugin
podman exec hookprobe-monitoring-grafana \
    grafana-cli plugins install vertamedia-clickhouse-datasource

podman restart hookprobe-monitoring-grafana

echo "✓ Restart Grafana and add ClickHouse datasource via UI:"
echo "   URL: http://localhost:8123"
echo "   Server: localhost (since both in same pod)"
echo "   Database: security"
echo "   User: hookprobe"
echo "   Password: (from network-config.sh)"
```

---

## 📊 Example Queries

### Security Dashboard Queries

**1. Attack Trends (Last 24 Hours)**
```sql
SELECT
    toStartOfHour(timestamp) AS hour,
    count() AS attacks
FROM security.security_events
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY hour
ORDER BY hour
```

**2. Top 10 Attacking IPs**
```sql
SELECT
    src_ip,
    count() AS attacks,
    uniq(attack_type) AS attack_types,
    countIf(blocked = 1) AS blocked
FROM security.security_events
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY src_ip
ORDER BY attacks DESC
LIMIT 10
```

**3. Attack Types Distribution**
```sql
SELECT
    attack_type,
    count() AS count,
    round(count() * 100.0 / sum(count()) OVER (), 2) AS percentage
FROM security.security_events
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY attack_type
ORDER BY count DESC
```

**4. Qsecbit RAG Status**
```sql
SELECT
    rag_status,
    count() AS samples,
    round(avg(score), 4) AS avg_score
FROM security.qsecbit_scores
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY rag_status
```

**5. Critical Attacks**
```sql
SELECT
    timestamp,
    src_ip,
    attack_type,
    severity,
    raw_event
FROM security.security_events
WHERE severity = 'critical'
  AND timestamp >= now() - INTERVAL 7 DAY
ORDER BY timestamp DESC
LIMIT 100
```

---

## 🔧 Integration with Qsecbit

**Update `qsecbit.py`:**

```python
# Add at top
import os
from clickhouse_driver import Client

# In Qsecbit.__init__
def __init__(self, baseline_mu, baseline_cov, quantum_anchor, config=None):
    # ... existing code ...

    # ClickHouse integration
    self.ch_enabled = os.getenv('CLICKHOUSE_ENABLED', 'true').lower() == 'true'
    if self.ch_enabled:
        try:
            self.ch_client = Client(
                host=os.getenv('CLICKHOUSE_HOST', '10.200.5.15'),
                database='security',
                user=os.getenv('CLICKHOUSE_USER', 'hookprobe'),
                password=os.getenv('CLICKHOUSE_PASSWORD', '')
            )
        except Exception as e:
            print(f"Warning: ClickHouse not available: {e}")
            self.ch_enabled = False

# Add new method
def _save_to_clickhouse(self, sample):
    """Save qsecbit sample to ClickHouse"""
    if not self.ch_enabled:
        return

    try:
        self.ch_client.execute(
            'INSERT INTO qsecbit_scores VALUES',
            [{
                'timestamp': sample.timestamp,
                'score': float(sample.score),
                'rag_status': sample.rag_status,
                'drift': float(sample.components['drift']),
                'attack_probability': float(sample.components['attack_probability']),
                'classifier_decay': float(sample.components['classifier_decay']),
                'quantum_drift': float(sample.components['quantum_drift'])
            }]
        )
    except Exception as e:
        print(f"Warning: Failed to save to ClickHouse: {e}")

# In calculate() method, add at end before return:
def calculate(self, ...):
    # ... existing code ...

    self.history.append(sample)
    self._save_to_clickhouse(sample)  # ADD THIS LINE

    return sample
```

**Update `requirements.txt`:**
```txt
numpy>=1.24.0,<2.0.0
scipy>=1.10.0,<2.0.0
clickhouse-driver>=0.2.6
```

**Install dependency:**
```bash
podman exec hookprobe-security-qsecbit pip install clickhouse-driver
```

---

## 📈 Performance Tuning

### Memory Settings

**For 8GB System:**
```xml
<!-- In ClickHouse config -->
<max_server_memory_usage_to_ram_ratio>0.9</max_server_memory_usage_to_ram_ratio>
<max_concurrent_queries>50</max_concurrent_queries>
```

**For 16GB System:**
```xml
<max_server_memory_usage_to_ram_ratio>0.9</max_server_memory_usage_to_ram_ratio>
<max_concurrent_queries>100</max_concurrent_queries>
```

### Compression Tuning

**Maximum compression (slower writes, best for archives):**
```sql
ALTER TABLE security.security_events
MODIFY COLUMN raw_event String CODEC(ZSTD(9));
```

**Fast compression (faster writes, still good compression):**
```sql
ALTER TABLE security.security_events
MODIFY COLUMN raw_event String CODEC(LZ4);
```

### Query Performance

**Add indexes for common queries:**
```sql
-- Index for IP lookups
ALTER TABLE security.security_events
ADD INDEX idx_src_ip src_ip TYPE minmax GRANULARITY 4;

-- Index for attack type filtering
ALTER TABLE security.security_events
ADD INDEX idx_attack_type attack_type TYPE set(100) GRANULARITY 4;
```

---

## 🔍 Monitoring

### Check ClickHouse Health

```bash
# Status
podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "SELECT version()"

# Database size
podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "
SELECT
    database,
    formatReadableSize(sum(bytes_on_disk)) AS size
FROM system.parts
GROUP BY database
"

# Active queries
podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "
SELECT query, elapsed FROM system.processes
"

# Recent errors
podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "
SELECT * FROM system.errors WHERE value > 0
"
```

### Add to Grafana System Dashboard

**Memory usage:**
```sql
SELECT
    formatReadableSize(value) AS memory
FROM system.metrics
WHERE metric = 'MemoryTracking'
```

**Query performance:**
```sql
SELECT
    query_duration_ms,
    query
FROM system.query_log
WHERE type = 'QueryFinish'
  AND event_time >= now() - INTERVAL 1 HOUR
ORDER BY query_duration_ms DESC
LIMIT 10
```

---

## 🐛 Troubleshooting

### Issue: Container won't start

```bash
# Check logs
podman logs hookprobe-monitoring-clickhouse

# Common fix: ulimit too low
podman rm hookprobe-monitoring-clickhouse
podman run -d ... --ulimit nofile=262144:262144 ...
```

### Issue: Out of memory

```bash
# Reduce max memory
# Edit /etc/clickhouse-server/config.d/memory.xml
<max_server_memory_usage>4000000000</max_server_memory_usage>

podman restart hookprobe-monitoring-clickhouse
```

### Issue: Slow queries

```bash
# Check query log
podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "
SELECT
    query,
    query_duration_ms
FROM system.query_log
WHERE type = 'QueryFinish'
  AND query_duration_ms > 1000
ORDER BY event_time DESC
LIMIT 10
"

# Check if using indexes
EXPLAIN SELECT ... FROM security.security_events WHERE ...
```

### Issue: Can't connect from Grafana

```bash
# Check network
podman exec hookprobe-monitoring-grafana ping -c 1 localhost

# Check ClickHouse is listening
podman exec hookprobe-monitoring-clickhouse netstat -tlnp | grep 8123

# Check authentication
curl -u hookprobe:PASSWORD http://10.200.5.15:8123/?query=SELECT%201
```

---

## 🎯 Next Steps

1. ✅ Deploy ClickHouse (Done above)
2. ⬜ Configure Vector to send logs
3. ⬜ Set up Filebeat for Zeek logs
4. ⬜ Integrate Qsecbit
5. ⬜ Create Grafana dashboards
6. ⬜ Test with real traffic
7. ⬜ Document operational procedures

**See full guide**: [ClickHouse Integration Guide](./clickhouse-integration.md)

---

**Quick Support**:
- ClickHouse Docs: https://clickhouse.com/docs
- HookProbe Issues: https://github.com/hookprobe/hookprobe/issues
- Email: qsecbit@hookprobe.com
