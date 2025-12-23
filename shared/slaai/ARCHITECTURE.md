# HookProbe SLA AI - Intelligent Network Continuity

**Version**: 1.0.0
**Status**: Implementation Plan
**License**: Proprietary (HookProbe Commercial)

## Executive Summary

SLA AI is HookProbe's proprietary intelligent monitoring, fault prediction, and switching automation system designed to maximize Business Continuity while minimizing costs on metered backup connections.

**Core Philosophy**: *Feel, Sense, Adapt, Learn, Optimize*

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SLA AI - Intelligent Network Continuity             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐          │
│  │  Metrics Layer  │   │  Intelligence   │   │  Action Layer   │          │
│  │  (Collectors)   │──▶│  (LSTM + Rules) │──▶│  (Actuators)    │          │
│  └─────────────────┘   └─────────────────┘   └─────────────────┘          │
│          │                     │                     │                     │
│          ▼                     ▼                     ▼                     │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │                        State & Learning Store                        │  │
│  │  (SQLite: metrics history, predictions, model weights, cost data)   │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

Data Flow:
  Sensors → Metrics → Prediction → Decision → Action → Feedback → Learning
```

## Core Components

### 1. Metrics Collector (`metrics_collector.py`)

Collects real-time network health metrics from all WAN interfaces.

**Metrics Collected**:

| Metric | Source | Interval | Purpose |
|--------|--------|----------|---------|
| RTT (Round Trip Time) | ICMP ping | 5s | Latency baseline |
| Jitter | RTT variance | 5s | Connection stability |
| Packet Loss | ICMP sequence | 5s | Link quality |
| Bandwidth | iperf3 (optional) | 60s | Throughput capacity |
| Signal Strength (RSSI) | ModemManager | 10s | LTE radio quality |
| Signal Quality (RSRQ/RSRP) | ModemManager | 10s | LTE cell quality |
| Network Type | ModemManager | 30s | 4G/5G/3G detection |
| DNS Response Time | dig timing | 30s | DNS health |
| HTTP Response Time | curl timing | 60s | Full path latency |
| Interface Errors | /sys/class/net | 30s | Hardware issues |
| Gateway ARP Time | arping | 30s | L2 connectivity |

**Data Structure**:
```python
@dataclass
class WANMetrics:
    timestamp: datetime
    interface: str
    rtt_ms: float
    jitter_ms: float
    packet_loss_pct: float
    signal_rssi_dbm: Optional[int]  # LTE only
    signal_rsrp_dbm: Optional[int]  # LTE only
    signal_rsrq_db: Optional[int]   # LTE only
    network_type: str  # ethernet, lte-4g, lte-5g, etc.
    dns_response_ms: float
    http_response_ms: Optional[float]
    interface_errors: int
    gateway_arp_ms: float
    bytes_sent: int     # For cost tracking
    bytes_received: int
```

### 2. LSTM Predictor (`predictor.py`)

Neural network that learns patterns and predicts failures before they occur.

**Architecture**:
```
Input (24 features) → LSTM(64) → LSTM(32) → Dense(16) → Dense(3)
                                                          │
                                                          ▼
                                              [P(healthy), P(degraded), P(failure)]
```

**Training Data**:
- Historical metrics with labeled outcomes
- Sliding window of 12 samples (1 minute at 5s intervals)
- Outcomes labeled based on what happened 30-60 seconds later

**Prediction Outputs**:

| State | Probability | Action |
|-------|-------------|--------|
| HEALTHY | > 0.7 | Normal operation |
| DEGRADED | > 0.5 | Pre-emptive warning, prepare backup |
| FAILURE | > 0.6 | Immediate failover |

**Features for Prediction**:
1. Current RTT (normalized)
2. RTT trend (increasing/decreasing)
3. Jitter (normalized)
4. Packet loss rate
5. Signal strength (LTE)
6. Signal quality delta (improving/degrading)
7. Time of day (hour encoded)
8. Day of week (encoded)
9. Interface error rate
10. DNS response time
11. Gateway ARP success rate
12. Historical failure count (last 24h)

### 3. Failback Intelligence (`failback.py`)

Smart failback with cost awareness and hysteresis.

**Failback Criteria**:

```python
class FailbackPolicy:
    # Minimum time on backup before considering failback
    min_backup_duration_s: int = 120  # 2 minutes

    # Primary must be healthy for this long before failback
    primary_stable_duration_s: int = 60  # 1 minute

    # Number of successful health checks required
    primary_health_checks_required: int = 5

    # Metered connection awareness
    metered_failback_urgency: float = 1.5  # More aggressive when on metered

    # Time-based failback preference (failback faster during business hours)
    business_hours_multiplier: float = 1.2

    # LSTM prediction confidence for failback
    min_primary_health_confidence: float = 0.75
```

**Cost Tracking**:

```python
class CostTracker:
    # Track data usage on metered connections
    metered_interfaces: List[str]  # e.g., ["wwan0"]

    # Daily/monthly budgets (bytes)
    daily_budget_bytes: int
    monthly_budget_bytes: int

    # Current usage
    daily_usage_bytes: int
    monthly_usage_bytes: int

    # Cost per GB (for reporting)
    cost_per_gb: float
```

### 4. DNS Intelligence (`dns_intelligence.py`)

Adaptive DNS failover and optimization.

**DNS Provider Health Tracking**:

| Provider | Primary | Secondary | Health Check |
|----------|---------|-----------|--------------|
| Cloudflare | 1.1.1.1 | 1.0.0.1 | Active |
| Google | 8.8.8.8 | 8.8.4.4 | Active |
| Quad9 | 9.9.9.9 | 149.112.112.112 | Active |
| OpenDNS | 208.67.222.222 | 208.67.220.220 | Standby |
| Local ISP | Auto-discovered | - | Passive |

**Adaptive Selection**:
1. Monitor response times from all providers
2. Weight by reliability and response time
3. Automatically switch if primary degrades
4. Learn regional/ISP preferences over time

### 5. External Correlation (`correlation.py`)

Optional integration with external status APIs.

**Sources**:
- ISP status pages (scraping with permission)
- Downdetector API (if available)
- Cloud provider status (AWS, GCP, Azure)
- Regional internet exchange status

**Use Cases**:
- Known outage → Don't attempt failback
- Regional issue → Adjust predictions
- Planned maintenance → Pre-emptive failover

### 6. SLA Engine (`engine.py`)

Central coordinator that ties everything together.

```python
class SLAEngine:
    def __init__(self):
        self.metrics = MetricsCollector()
        self.predictor = LSTMPredictor()
        self.failback = FailbackIntelligence()
        self.dns = DNSIntelligence()
        self.cost = CostTracker()

    async def run(self):
        while True:
            # Collect metrics
            metrics = await self.metrics.collect()

            # Store for training
            self.store_metrics(metrics)

            # Get prediction
            prediction = self.predictor.predict(metrics)

            # Make decision
            action = self.decide(metrics, prediction)

            # Execute action
            await self.execute(action)

            # Record outcome for learning
            self.record_outcome(action)

            await asyncio.sleep(self.check_interval)
```

## State Machine

```
                    ┌──────────────────┐
                    │                  │
        ┌──────────▶│  PRIMARY_ACTIVE  │◀──────────┐
        │           │                  │           │
        │           └────────┬─────────┘           │
        │                    │                     │
        │         FAILURE DETECTED                 │
        │         or FAILURE PREDICTED             │
        │                    │                     │
        │                    ▼                     │
        │           ┌──────────────────┐           │
        │           │                  │           │
        │           │   FAILOVER_IN    │           │
        │           │   PROGRESS       │           │
        │           │                  │           │
        │           └────────┬─────────┘           │
        │                    │                     │
        │            BACKUP CONFIRMED              │
        │                    │                     │
        │                    ▼                     │
        │           ┌──────────────────┐           │
   FAILBACK         │                  │    PRIMARY
   COMPLETE         │  BACKUP_ACTIVE   │    RECOVERED
        │           │                  │    + STABLE
        │           └────────┬─────────┘           │
        │                    │                     │
        │                    ▼                     │
        │           ┌──────────────────┐           │
        │           │                  │           │
        └───────────│   FAILBACK_IN    │───────────┘
                    │   PROGRESS       │
                    │                  │
                    └──────────────────┘
```

## Database Schema

```sql
-- Metrics history (rolling 7 days)
CREATE TABLE wan_metrics (
    id INTEGER PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    interface TEXT NOT NULL,
    rtt_ms REAL,
    jitter_ms REAL,
    packet_loss_pct REAL,
    signal_rssi_dbm INTEGER,
    signal_rsrp_dbm INTEGER,
    signal_rsrq_db INTEGER,
    network_type TEXT,
    dns_response_ms REAL,
    http_response_ms REAL,
    interface_errors INTEGER,
    bytes_sent INTEGER,
    bytes_received INTEGER
);

-- Predictions and outcomes (for model training)
CREATE TABLE predictions (
    id INTEGER PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    interface TEXT NOT NULL,
    prediction TEXT NOT NULL,  -- healthy, degraded, failure
    confidence REAL NOT NULL,
    actual_outcome TEXT,  -- filled in after observation
    outcome_timestamp DATETIME
);

-- Failover events (for analysis)
CREATE TABLE failover_events (
    id INTEGER PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    from_interface TEXT NOT NULL,
    to_interface TEXT NOT NULL,
    trigger TEXT NOT NULL,  -- failure, prediction, manual
    prediction_lead_time_s REAL,  -- how early we predicted
    recovery_time_s REAL,
    data_loss_bytes INTEGER
);

-- Cost tracking
CREATE TABLE metered_usage (
    id INTEGER PRIMARY KEY,
    date DATE NOT NULL,
    interface TEXT NOT NULL,
    bytes_sent INTEGER NOT NULL,
    bytes_received INTEGER NOT NULL,
    estimated_cost REAL
);

-- LSTM model weights (binary blob)
CREATE TABLE model_weights (
    id INTEGER PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    interface TEXT NOT NULL,
    model_version TEXT NOT NULL,
    weights BLOB NOT NULL,
    training_samples INTEGER,
    accuracy REAL
);
```

## Configuration

```yaml
# /etc/hookprobe/slaai.conf

# General settings
enabled: true
check_interval_s: 5
prediction_interval_s: 30
database_path: /var/lib/hookprobe/slaai/metrics.db

# Interfaces
interfaces:
  primary:
    name: eth0
    type: ethernet
    metered: false
  backup:
    name: wwan0
    type: lte
    metered: true
    daily_budget_mb: 500
    monthly_budget_mb: 10000
    cost_per_gb: 0.50

# Failover settings
failover:
  prediction_threshold: 0.6
  immediate_threshold: 0.8
  min_failover_duration_s: 120

# Failback settings
failback:
  enabled: true
  min_primary_stable_s: 60
  health_checks_required: 5
  metered_urgency_multiplier: 1.5
  business_hours: "09:00-18:00"
  business_hours_multiplier: 1.2

# LSTM predictor
predictor:
  enabled: true
  model_path: /var/lib/hookprobe/slaai/model.pt
  retrain_interval_days: 7
  min_training_samples: 1000
  lookback_window: 12  # samples

# DNS intelligence
dns:
  enabled: true
  providers:
    - name: cloudflare
      primary: 1.1.1.1
      secondary: 1.0.0.1
      priority: 1
    - name: google
      primary: 8.8.8.8
      secondary: 8.8.4.4
      priority: 2
    - name: quad9
      primary: 9.9.9.9
      secondary: 149.112.112.112
      priority: 3
  health_check_interval_s: 60
  switch_threshold_ms: 100

# External correlation (optional)
correlation:
  enabled: false
  sources:
    - type: downdetector
      enabled: false
    - type: isp_status
      enabled: false

# Logging
logging:
  level: INFO
  file: /var/log/hookprobe/slaai.log
  max_size_mb: 50
  retention_days: 30
```

## Integration with PBR

SLA AI integrates with `wan-failover-pbr.sh` through:

1. **Shared State File**: `/run/fortress/slaai-recommendation.json`
2. **D-Bus Signals** (optional): For immediate failover triggers
3. **systemd Integration**: SLA AI runs as a service alongside PBR monitor

```python
# slaai_recommendation.json
{
    "timestamp": "2024-01-15T10:30:00Z",
    "recommendation": "failover",  # or "failback", "hold"
    "confidence": 0.85,
    "reason": "Primary degradation predicted in 30s",
    "primary_status": {
        "health": "degraded",
        "prediction": "failure",
        "rtt_ms": 150,
        "packet_loss_pct": 5.2
    },
    "backup_status": {
        "health": "healthy",
        "signal_rssi_dbm": -75,
        "network_type": "lte-4g"
    },
    "cost_status": {
        "daily_usage_mb": 45,
        "daily_budget_mb": 500,
        "monthly_usage_mb": 1200,
        "monthly_budget_mb": 10000
    }
}
```

## Metrics & Reporting

### SLA Metrics

| Metric | Target | Description |
|--------|--------|-------------|
| Uptime | 99.9% | Total connectivity uptime |
| MTTR | < 5s | Mean Time to Recovery |
| MTTD | < 30s | Mean Time to Detection (before failure) |
| False Positive Rate | < 5% | Unnecessary failovers |
| Cost Efficiency | 80% | Primary usage vs backup |
| Prediction Accuracy | > 80% | Correct failure predictions |

### Dashboard Metrics

```json
{
    "uptime_pct": 99.95,
    "failover_count_24h": 2,
    "avg_failover_duration_s": 45,
    "prediction_accuracy_pct": 85.5,
    "false_positive_rate_pct": 3.2,
    "backup_usage_mb_24h": 120,
    "estimated_cost_saved": 15.50,
    "current_state": "PRIMARY_ACTIVE",
    "primary_health_score": 0.92,
    "backup_health_score": 0.88
}
```

## Implementation Phases

### Phase 1: Core Metrics & Basic Failback (Week 1)
- Metrics collector with SQLite storage
- Basic failback logic with hysteresis
- Cost tracking for metered connections
- Integration with existing PBR

### Phase 2: LSTM Predictor (Week 2)
- LSTM model architecture
- Training pipeline from historical data
- Real-time prediction integration
- Model persistence and updates

### Phase 3: DNS Intelligence (Week 3)
- Multi-provider DNS health monitoring
- Adaptive DNS selection
- Integration with dnsmasq/dnsXai

### Phase 4: Advanced Features (Week 4)
- External correlation (optional)
- Dashboard metrics API
- Web UI integration
- Performance optimization

## Files Structure

```
shared/slaai/
├── __init__.py
├── ARCHITECTURE.md          # This file
├── engine.py                # Main SLA engine
├── metrics_collector.py     # Metrics collection
├── predictor.py             # LSTM predictor
├── failback.py              # Failback intelligence
├── dns_intelligence.py      # DNS adaptation
├── cost_tracker.py          # Metered usage tracking
├── database.py              # SQLite operations
├── config.py                # Configuration loading
├── models/
│   ├── __init__.py
│   └── lstm.py              # LSTM model definition
├── integrations/
│   ├── __init__.py
│   ├── pbr.py               # PBR integration
│   ├── dnsmasq.py           # dnsmasq integration
│   └── fortress.py          # Fortress-specific integration
└── tests/
    ├── __init__.py
    ├── test_metrics.py
    ├── test_predictor.py
    └── test_failback.py
```

## Security Considerations

1. **Data Privacy**: Metrics are stored locally, no cloud upload
2. **Model Integrity**: Model weights are signed and verified
3. **Access Control**: Only root can modify SLA AI configuration
4. **Rate Limiting**: Prevents excessive network probing

## Future Enhancements

1. **Mesh Intelligence**: Share learned patterns across HookProbe mesh
2. **Federated Learning**: Improve models without sharing raw data
3. **Multi-WAN (3+)**: Support for more than 2 WAN interfaces
4. **QoS Integration**: Priority-based failover for critical traffic
5. **Carrier Aggregation**: Simultaneous use of multiple WANs
