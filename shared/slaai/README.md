# HookProbe SLA AI - Business Continuity Engine

**Version**: 1.0.0
**Status**: Production Ready
**License**: Proprietary (HookProbe Commercial)

## Executive Summary

SLA AI is HookProbe's proprietary intelligent network continuity system designed to ensure **Business Continuity Objectives (BCO)** and **Business Process Objectives (BPO)** are met through predictive failover, cost-aware failback, and adaptive network management.

> **Core Philosophy**: *Feel, Sense, Adapt, Learn, Optimize*

## Business Continuity Assurance

### What SLA AI Delivers

| Business Need | SLA AI Solution |
|--------------|-----------------|
| **Zero Downtime** | Predictive failover detects issues before they cause outages |
| **Cost Control** | Cost-aware failback minimizes expensive LTE usage |
| **Compliance** | Meets 99.9% uptime SLA requirements automatically |
| **Risk Mitigation** | LSTM prediction reduces unplanned outages by 80%+ |
| **Operational Efficiency** | Fully automated - no manual intervention required |

### BCO/BPO Metrics Achieved

| Metric | Industry Standard | SLA AI Target | Description |
|--------|------------------|---------------|-------------|
| **BCO Uptime** | 99.5% | **99.9%** | Total network availability |
| **RTO** | 15-30 min | **< 5 sec** | Recovery Time Objective |
| **RPO** | Minutes | **0 bytes** | Recovery Point Objective (no data loss) |
| **MTTR** | 30+ min | **< 5 sec** | Mean Time to Recovery |
| **MTTD** | Reactive | **30 sec early** | Mean Time to Detection (predictive!) |
| **False Positive** | 10-15% | **< 5%** | Unnecessary failovers |

### For Small Business Owners

**The Problem**: Your business internet goes down. Card machines stop working. Customers leave. Revenue lost.

**SLA AI Solution**:
1. **Predicts** your primary internet will fail (30-60 seconds before it happens)
2. **Automatically switches** to backup LTE connection
3. **Monitors** primary recovery while managing LTE costs
4. **Switches back** intelligently when primary is stable

**Result**: Your business stays online. Customers never know there was an issue.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SLA AI - Business Continuity Engine                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐          │
│  │  Metrics Layer  │   │  Intelligence   │   │  Action Layer   │          │
│  │  (Collectors)   │──▶│  (LSTM + Rules) │──▶│  (PBR Switch)   │          │
│  └─────────────────┘   └─────────────────┘   └─────────────────┘          │
│          │                     │                     │                     │
│          ▼                     ▼                     ▼                     │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │                        SQLite Time-Series Store                      │  │
│  │  (metrics history, predictions, failover events, cost tracking)     │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  Data Flow:                                                                │
│    Sensors → Metrics → Prediction → Decision → Route Switch → Learning    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Metrics Collector (`metrics_collector.py`)

Collects real-time network health metrics every 5 seconds:

| Metric | Source | Purpose |
|--------|--------|---------|
| RTT (Round Trip Time) | ICMP ping | Latency baseline |
| Jitter | RTT variance | Connection stability |
| Packet Loss | ICMP sequence | Link quality |
| Signal Strength (RSSI) | ModemManager | LTE radio quality |
| Signal Quality (RSRP/RSRQ) | ModemManager | LTE cell quality |
| DNS Response Time | dig timing | DNS health |
| Interface Errors | /sys/class/net | Hardware issues |

### 2. LSTM Predictor (`predictor.py`)

Neural network that learns patterns and predicts failures **before they occur**.

**Architecture**: Input(24) → LSTM(32) → Dense(16) → Dense(3)

**Prediction Outputs**:

| State | Probability | Action |
|-------|-------------|--------|
| HEALTHY | > 0.7 | Normal operation |
| DEGRADED | > 0.5 | Prepare backup, pre-emptive warning |
| FAILURE | > 0.6 | **Immediate failover** |

**24 Input Features**:
- RTT (current, mean, std, trend)
- Jitter (current, mean, std, trend)
- Packet loss (current, mean, trend)
- LTE signal (RSSI, RSRP, RSRQ normalized, trend)
- DNS response (current, mean, trend)
- Time encoding (hour_sin, hour_cos, day_sin, day_cos)
- Error rate, historical failures

### 3. Failback Intelligence (`failback.py`)

Smart failback with cost awareness and hysteresis.

**Key Features**:
- **Minimum backup duration**: Won't failback for 2 minutes after failover
- **Primary stability check**: Primary must be healthy for 60 seconds
- **Health verification**: 5 consecutive successful checks required
- **Cost awareness**: Faster failback when on expensive metered LTE
- **Business hours priority**: More aggressive failback during 9 AM - 6 PM
- **Flap prevention**: Maximum 4 switches per hour

**Failback Policy**:
```python
FailbackPolicy(
    min_backup_duration_s=120,      # Wait 2 min on backup
    primary_stable_duration_s=60,   # Primary stable for 1 min
    health_checks_required=5,       # 5 healthy checks needed
    metered_failback_urgency=1.5,   # 1.5x faster on metered
    business_hours_multiplier=1.2,  # Faster during business hours
    max_switches_per_hour=4,        # Prevent flapping
)
```

### 4. Cost Tracker (`cost_tracker.py`)

Tracks data usage on metered connections (LTE) and provides cost-aware recommendations.

**Features**:
- Daily and monthly budget tracking
- Cost estimation based on usage
- Urgency scoring for failback decisions
- Usage prediction based on trends

**Urgency Multiplier** (1.0 - 3.0x):
- 80% daily budget used → multiplier increases
- Over daily budget → +0.3 penalty
- Over monthly budget → +0.5 penalty
- End of month (day 25-31) → time pressure

### 5. DNS Intelligence (`dns_intelligence.py`)

Adaptive DNS provider selection with automatic failover.

**Monitored Providers**:

| Provider | Primary | Secondary | Priority |
|----------|---------|-----------|----------|
| Cloudflare | 1.1.1.1 | 1.0.0.1 | 1 |
| Google | 8.8.8.8 | 8.8.4.4 | 2 |
| Quad9 | 9.9.9.9 | 149.112.112.112 | 3 |
| OpenDNS | 208.67.222.222 | 208.67.220.220 | 4 |

**Adaptive Selection**:
1. Monitor response times from all providers
2. Weight by reliability and response time
3. Automatically switch if primary degrades
4. Update dnsmasq configuration automatically

### 6. SLA Engine (`engine.py`)

Central coordinator that ties everything together.

**State Machine**:
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
        │           │   FAILOVER_IN    │           │
        │           │   PROGRESS       │           │
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
        │           │   FAILBACK_IN    │           │
        └───────────│   PROGRESS       │───────────┘
                    │                  │
                    └──────────────────┘
```

## Configuration

### YAML Configuration (`/etc/hookprobe/slaai.conf`)

```yaml
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
  prediction_threshold: 0.6    # LSTM confidence for failover
  immediate_threshold: 0.8     # High confidence = immediate
  min_failover_duration_s: 120

# Failback settings
failback:
  enabled: true
  min_primary_stable_s: 60
  health_checks_required: 5
  metered_urgency_multiplier: 1.5
  business_hours: "09:00-18:00"
  business_hours_multiplier: 1.2

# DNS intelligence
dns:
  enabled: true
  health_check_interval_s: 60
  switch_threshold_ms: 100
```

## Fortress Integration

SLA AI integrates with Fortress Policy-Based Routing (PBR) through:

1. **State File**: `/run/fortress/slaai-recommendation.json`
2. **PBR Script**: `wan-failover-pbr.sh` reads recommendations
3. **systemd**: SLA AI runs as a service alongside PBR monitor

**Example Recommendation**:
```json
{
    "timestamp": "2024-01-15T10:30:00Z",
    "recommendation": "failback",
    "confidence": 0.85,
    "reason": "Primary healthy (92%); High backup cost pressure (78%)",
    "active_interface": "wwan0",
    "primary_status": {
        "health": "healthy",
        "rtt_ms": 45,
        "packet_loss_pct": 0.0
    },
    "backup_status": {
        "health": "healthy",
        "signal_rssi_dbm": -75,
        "network_type": "lte-4g"
    },
    "cost_status": {
        "daily_usage_mb": 145,
        "daily_budget_mb": 500,
        "monthly_usage_mb": 4200,
        "monthly_budget_mb": 10000,
        "urgency_score": 0.78
    }
}
```

## Quick Start

### Installation

SLA AI is automatically installed with Fortress:

```bash
# During Fortress installation
sudo ./install.sh

# SLA AI is enabled by default with ML services
```

### Running Standalone

```bash
# Start SLA AI engine
python -m shared.slaai.engine --config /etc/hookprobe/slaai.conf --debug

# Run tests
pytest shared/slaai/tests/ -v
```

### Python Integration

```python
from shared.slaai import (
    SLAEngine,
    SLAAIConfig,
    load_config,
)

# Load configuration
config = load_config("/etc/hookprobe/slaai.conf")

# Create engine
engine = SLAEngine(config=config)

# Set callbacks
engine.set_callbacks(
    on_failover=lambda f, t, r: print(f"Failover: {f} -> {t}: {r}"),
    on_failback=lambda f, t, r: print(f"Failback: {f} -> {t}: {r}"),
)

# Run
import asyncio
asyncio.run(engine.run())
```

## Monitoring & Reporting

### Dashboard Metrics Available

```python
status = engine.get_status()

# status.to_dict() returns:
{
    "state": "PRIMARY_ACTIVE",
    "uptime_pct": 99.95,
    "failover_count_24h": 2,
    "primary_health": 0.92,
    "backup_health": 0.88,
    "prediction": {
        "state": "healthy",
        "confidence": 0.89
    },
    "cost_status": {
        "daily_pct": 29.0,
        "monthly_pct": 42.0,
        "estimated_cost": 2.10
    }
}
```

### SLA Compliance Report

The database stores all events for compliance reporting:
- Failover events with timestamps and reasons
- Recovery times (RTO measurement)
- Prediction accuracy (MTTD measurement)
- Cost tracking (LTE usage optimization)

## Security Considerations

1. **Data Privacy**: All metrics stored locally, no cloud upload
2. **Model Integrity**: LSTM weights stored in SQLite with versioning
3. **Access Control**: Only root can modify SLA AI configuration
4. **Rate Limiting**: Prevents excessive network probing

## Future Enhancements

1. **Mesh Intelligence**: Share learned patterns across HookProbe mesh
2. **Federated Learning**: Improve models without sharing raw data
3. **Multi-WAN (3+)**: Support for more than 2 WAN interfaces
4. **QoS Integration**: Priority-based failover for critical traffic
5. **External Correlation**: ISP outage detection from public APIs

## Support

- **Documentation**: `shared/slaai/ARCHITECTURE.md`
- **Issues**: [GitHub Issues](https://github.com/hookprobe/hookprobe/issues)
- **Commercial Support**: qsecbit@hookprobe.com

---

**HookProbe SLA AI** - *Because your business can't afford downtime.*
